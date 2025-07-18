---
title: "Emulated Fuzzing with AFL++ and QEMU"
categories: [Fuzzing, AFL++]
tags: [linux, fuzzing, qemu, iot]
---

AFL++ is an **advanced fork of AFL (American Fuzzy Lop)** that incorporates numerous improvements, including:

- **Better performance optimizations**
- **Support for QEMU, Unicorn, and FRIDA modes** (for binary-only fuzzing)
- **Enhanced mutation strategies**
- **Integration with other tools like LibFuzzer and Honggfuzz**


AFL++ uses **coverage-guided fuzzing**, meaning it:

1. **Instruments the target program** to track code execution.
2. **Generates mutated inputs** based on previous executions.
3. **Prioritizes inputs that trigger new code paths** (increasing bug discovery chances).

### Installation (Linux)

```bash
sudo apt update
sudo apt install git make build-essential clang ninja-build pkg-config libglib2.0-dev libpixman-1-dev
git clone https://github.com/AFLplusplus/AFLplusplus.git
cd AFLplusplus
make && sudo make install
```

### Fuzzing a Simple Program

Let’s test a vulnerable C program which reads data from a file:

```c
#include <stdio.h>
#include <string.h>
#include <unistd.h>

void vulnerable_function(FILE *fp) {
    char buffer[64];
    
    // Read file contents into buffer - UNSAFE!
    fread(buffer, 1, 128, fp);  // Deliberately reads more than buffer size
    
    printf("Read: %s\n", buffer);  // Print to verify fuzzing works
}

int main(int argc, char **argv) {
    if (argc != 2) {
        printf("Usage: %s <input_file>\n", argv[0]);
        return 1;
    }

    FILE *fp = fopen(argv[1], "rb");
    if (!fp) {
        perror("fopen failed");
        return 1;
    }

    vulnerable_function(fp);
    fclose(fp);
    return 0;
}
```

**Compilation and Instrumentation**

```bash
afl-gcc -o vuln_file vuln_file.c -fno-stack-protector -z execstack -D_FORTIFY_SOURCE=0
```

**Fuzzing**

```bash
# Create sample input directory
mkdir inputs
echo "AAAAAAAA" > inputs/testcase

# Run AFL++ fuzzer
afl-fuzz -i inputs -o findings -- ./vuln_file @@
```

### QEMU Mode

```shell
git clone https://github.com/AFLplusplus/AFLplusplus
cd AFLplusplus/
make all
cd qemu_mode
CPU_TARGET=arm ./build_qemu_support.sh
```

This will generate `afl-qemu-trace` in `AFLplusplus`. `afl-qemu-trace` is AFL++'s modified QEMU binary that serves as the core component for **binary-only instrumentation** when fuzzing with QEMU mode (`-Q` flag) 

AFL-QEMU-Trace is a specialized tool in **AFL++** (American Fuzzy Lop++) that allows **tracing program execution** in QEMU mode without full fuzzing. It's useful for debugging, analyzing coverage, and understanding how AFL++ interacts with a binary during emulation.

**Run AFL-QEMU-Trace on a Binary**

```bash
afl-qemu-trace --help
afl-qemu-trace [options] /path/to/target_binary < input_file
```

### Fuzzing Cross-Compiled Vulnerable Binary

Let's cross compile it for `arm` architecture.

```bash
arm-linux-gnueabi-gcc -z execstack -fno-stack-protector vuln_file.c -o vuln_file
```

**Corpus**

```bash
mkdir inputs
echo "AAAA" > inputs/test1
echo "BBBB" > inputs/test2
```

```bash
./AFLplusplus/afl-fuzz -Q -i inputs/ -o outputs/ -- ./vuln_file @@
```

You will get error and `afl-fuzz` suggests using `AFL_DEBUG=1`.

```bash
AFL_DEBUG=1 ./AFLplusplus/afl-fuzz -Q -i inputs/ -o outputs/ -- ./vuln_file @@
```
If you look at the error carefully you will see -

```txt
...
AFL forkserver entrypoint: 0x103f0
afl-qemu-trace: Could not open '/lib/ld-linux.so.3': No such file or directory
...
```

It means `afl-qemu-trace` was not able to get the libraries needed to run the target binary. You can provide the path in `QEMU_LD_PREFIX`. Note that it is prefix so no need to specify full path.

```bash
QEMU_LD_PREFIX=/usr/arm-linux-gnueabi ./AFLplusplus/afl-fuzz -Q -i inputs/ -o outputs/ -- ./vuln_file @@
```
For getting more about AFL variables, check [this](https://aflplus.plus/docs/env_variables/)

By looking at it I found out we can use the variable `AFL_BENCH_UNTIL_CRASH` to exit `afl-fuzz` after getting first crash.

So after using the following command and waiting for few seconds I got the crash.

```bash
QEMU_LD_PREFIX=/usr/arm-linux-gnueabi AFL_BENCH_UNTIL_CRASH=1 ./AFLplusplus/afl-fuzz -Q -i inputs/ -o outputs/ -- ./vuln_file @@
```
The crashes are saved in `./output/default/crashes/`.

```bash
$ ls output/default/crashes/
id:000000,sig:11,src:000000,time:160,execs:337,op:havoc,rep:12  README.txt
id:000001,sig:11,src:000000,time:170,execs:359,op:havoc,rep:10
```

You can view the hexdump of the file which crashed our target using `xxd`. 

We can now verify our crash by running the binary in `gdb-multiarch` and providing the file which crashed it as argument.

On one terminal run the binary using `qemu-arm` and in other terminal we will connect to the binary.

```bash
# Terminal 1
# For simplicity I renamed the crash file to `crashfile`
$ qemu-arm -L /usr/arm-linux-gnueabi -g 1234 ./vuln_file crashfile

# Terminal 2
$ gdb-multiarch  ./vuln_file
(gdb) set sysroot /usr/arm-linux-gnueabi
(gdb) target remote :1234

# You can `stepi` and ananlyze but I decided to `continue`
(gdb) continue
```
And we can see we get SEGFAULT!

```bash
#...
Continuing.

Program received signal SIGSEGV, Segmentation fault.
0x05050504 in ?? ()

*R11  0x5050505
#...
*PC   0x5050504
───────────────────────────[ DISASM / arm / thumb mode / set emulate on ]───────────────────────────
Invalid address 0x5050504

```

You can check my ARM assembly series for more into ARM!
We can see R11 is FP (Frame Pointer) is overwritten with 0x5050505. We can try to find this in our input where it lies at which offset.

```bash
$ xxd crashfile 
00000000: 4141 bc05 0605 2000 0000 1505 0506 0520  AA.... ........ 
00000010: 0000 0015 0505 0a05 0505 0505 0505 0505  ................
00000020: 0505 0505 0505 0505 0505 0541 410a 0506  ...........AA...
00000030: 0520 0000 0015 0505 0a05 0505 0505 0505  . ..............
00000040: 0505 0505 0505 0505 0505 0505 0541 41    .............AA
```

We are seeing `05 05 05 05` ;)


