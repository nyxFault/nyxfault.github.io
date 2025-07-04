---
title: "Mastering Honggfuzz: From Basics to Advanced"
categories: [Fuzzing, honggfuzz]
tags: [honggfuzz, fuzzing]
---

Fuzzing is a powerful technique for uncovering software vulnerabilities by feeding unexpected, malformed, or random inputs into a program. Among the many fuzzing tools available, Honggfuzz stands out for its efficiency, flexibility, and advanced features. In this blog post, we’ll take a deep dive into **Honggfuzz**, exploring its architecture, key features, usage, and how it compares to other fuzzers like AFL and libFuzzer.

**Honggfuzz**
Honggfuzz is an open-source, security-oriented, feedback-driven fuzzer developed by Google engineer Robert Swiecki. It is designed to find bugs and vulnerabilities in software by mutating inputs and monitoring program execution for crashes, hangs, or other anomalies.


### How Honggfuzz Works

Honggfuzz follows a feedback-driven fuzzing approach, where it:
1. Generates Inputs – Starts with a seed corpus and mutates inputs.
2. Executes Target – Runs the target program with the mutated input.
3. Monitors Execution – Uses sanitizers or hardware features (Intel PT) to detect crashes, hangs, or coverage changes.
4. Adjusts Strategy – Prioritizes inputs that trigger new code paths or crashes.

### Installation

```bash
sudo apt-get install binutils-dev libunwind-dev libblocksruntime-dev clang make
git clone https://github.com/google/honggfuzz
cd honggfuzz
make
sudo make install
```

You'll have `hfuzz-cc`, `hfuzz-clang`, `hfuzz-clang++`, `hfuzz-g++`, `hfuzz-gcc`. 
Honggfuzz supports multiple instrumentation methods to track code coverage. *Instrumentation* refers to the process of modifying the target program—typically at compile time—to insert additional code that tracks code coverage and other execution metrics during fuzzing. This inserted code enables honggfuzz to observe which parts of the program are exercised by each test input, allowing it to guide mutations toward unexplored code paths and thus increase the likelihood of finding bugs. By default, honggfuzz uses compile-time instrumentation with flags such as `-fsanitize-coverage=trace-pc-guard,indirect-calls,trace-cmp` (for clang) or `-finstrument-functions` (for gcc/clang). This code tracks which parts of the program are executed by each input.


## Basic Fuzzing Example

Let's write a simple C program with a classic stack-based buffer overflow vulnerability.
Our program will:
- Take a filename as input (passed via command line).
- Read its content into a small buffer.
- Trigger a buffer overflow if the file is too large.

*vulnerable.c*
```c
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define BUFFER_SIZE 16  // Intentionally small to force an overflow

void vulnerable_function(const char *filename) {
    char buffer[BUFFER_SIZE];  // Small fixed-size buffer
    FILE *file = fopen(filename, "rb");  // Open file in binary mode

    if (!file) {
        perror("Failed to open file");
        return;
    }

    // Danger! No bounds checking → Potential buffer overflow!
    fread(buffer, 1, BUFFER_SIZE * 10, file);  // Read way more than buffer can hold
    fclose(file);

    printf("Buffer content: %.*s\n", BUFFER_SIZE, buffer);  // Print (may be corrupted)
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <input_file>\n", argv[0]);
        return 1;
    }

    vulnerable_function(argv[1]);
    return 0;
}
```

Now, let's fuzz this program to find the crash.

**Compile with Honggfuzz Instrumentation**

```bash
hfuzz-clang -o vulnerable vulnerable.c
```
(Or use hfuzz-gcc if you prefer GCC.)

**Create a Seed Corpus**

```bash
mkdir inputs DIR
echo "AAAA" > inputs/seed.txt
```

These are **non-crashing** inputs.
Honggfuzz will **mutate** them to find crashes.

To get help:
```bash
honggfuzz -h
```

**Essential Options**

- **`-i DIR`** – Path to a directory containing initial file corpus
- **`-o DIR`** – Output data (new dynamic coverage corpus, or the minimized coverage corpus) is written to this directory (default: input directory is re-used)
- **`-P`** – Enable persistent fuzzing (use hfuzz_cc/hfuzz-clang to compile code).
- **`-s`** – Feed input via **stdin** instead of `___FILE___`
- **`-n N`** – Number of concurrent fuzzing threads (default: number of CPUs / 2)
- **`-t SEC`** – Timeout per run (default: 1 sec)
- **`-w FILE`** – Dictionary file. Format:http://llvm.org/docs/LibFuzzer.html#dictionaries

**Crash Handling**

- **`--crashdir DIR`** – Explicitly set crash directory
- **`--exit_upon_crash`** – Stop after first crash
- **`--verifier`** – Re-test crashes to avoid duplicates

**Advanced Modes**

- **`-x`** – Static mode only, disable instrumentation (binary-only fuzzing)
- **`-z`** – Force compile-time instrumentation (default)
- **`--only_printable`** – Only generate printable inputs

Let's learn about corpus. 
A **corpus** is a collection of input files used to guide fuzzing. Honggfuzz mutates these files to find new code paths and crashes.

- **`-i DIR`** → Input corpus directory (seed files)
- **`-o DIR`** → Save new/mutated inputs (avoids modifying originals)
- **`-M`** → Minimize corpus (removes redundant files)


**Example Commands**

```bash
# Basic fuzzing (file input)
honggfuzz -i seeds -o crashes -- ./target ___FILE___

# STDIN input mode
honggfuzz -i seeds -s -- ./target

# Persistent mode (faster)
honggfuzz -i seeds -P -- ./persistent_target
```

**Run Honggfuzz**

```bash
honggfuzz --verifier -i inputs -o cov --crashdir crash -- ./vulnerable ___FILE___
```

- `-i inputs`: Input corpus directory.
- `-o cov`: Where new/mutated inputs will be saved.
- `___FILE___`: Honggfuzz replaces this with the mutated input file.

By specifying `--crashdir crash`, crashes will be saved in a dedicated directory. Otherwise, all `.fuzz` files will clutter your current working directory.

Honggfuzz will quickly find that long inputs (>16 bytes) crash the program.

We will stop **honggfuzz** after getting enough crashes by hitting `Ctrl + C`.

```txt
------------------------[  0 days 00 hrs 00 mins 02 secs ]----------------------
  Iterations : 2,429 [2.43k]
  Mode [3/3] : Feedback Driven Mode
      Target : ./vulnerable ___FILE___
     Threads : 12, CPUs: 24, CPU%: 1857% [77%/CPU]
       Speed : 778/sec [avg: 1,214]
     Crashes : 24 [unique: 23, blocklist: 0, verified: 0]
    Timeouts : 12 [1 sec]
 Corpus Size : 8, max: 8,192 bytes, init: 1 files
  Cov Update : 0 days 00 hrs 00 mins 02 secs ago
    Coverage : edge: 4/7 [57%] pc: 0 cmp: 60
---------------------------------- [ LOGS ] ------------------/ honggfuzz 2.6 /-

```

**Analyze the Crash**

Check the coverage saved in `cov/` directory:

```bash
$ ls cov/
0e8f69c4e77001ea6de310801d61ea00.00000014.honggfuzz.cov  6dddddddddddb0006dddddddddddb000.00000006.honggfuzz.cov  fb8dddddddddddddefddddddddddddbe.00000008.honggfuzz.cov
6dddddb0000000000000006dddddb000.00000006.honggfuzz.cov  a4b87b8ddddddddd248addddddddddbe.0000000a.honggfuzz.cov
```

`.cov` files in Honggfuzz store code coverage data collected during fuzzing. They help Honggfuzz track which parts of your program have been executed, allowing it to intelligently guide mutations toward unexplored code paths.

**Understanding Crash Filenames**

When Honggfuzz finds a crash, it saves the triggering input as a `.fuzz` file. Let's examine how to work with these crash files.

```bash
$ ls crash/
'SIGBUS.PC.555555583534.STACK.0.CODE.128.ADDR.0.INSTR.movl___$0x0,-0x4(%rbp).2025-07-04.18:25:46.1067732.fuzz'
'SIGBUS.PC.555555583534.STACK.0.CODE.128.ADDR.0.INSTR.movl___$0x0,-0x4(%rbp).2025-07-04.18:25:46.1067827.fuzz'
#...
```

```txt
SIG[signal].PC.[address].STACK.[stack_hash].CODE.[code].ADDR.[addr].INSTR.[instruction].[timestamp].fuzz
```

We can change the `.fuzz` extension.

```txt
 --extension|-e VALUE
	Input file extension (e.g. 'swf'), (default: 'fuzz')
```

We can view the hex contents of a crash file using `xxd`:

```bash
xxd SIGSEGV.PC.0.STACK.0.CODE.1.ADDR.0.INSTR.\[NOT_MMAPED\].2025-07-04.18\:25\:48.1069771.fuzz 
00000000: 4124 4141 4102 0000 0000 0000 0000 0000  A$AAA...........
00000010: 0000 0000 0000 0000 0000 0000 0000 0000  ................
#...
```

This shows the exact input that triggered the crash - in this case, a malformed string starting with `A$AAA`.

**Reproducing the Crash**

To verify the crash:

```bash
./vulnerable ./crash/SIGSEGV.PC.0.STACK.0.CODE.1.ADDR.0.INSTR.\[NOT_MMAPED\].2025-07-04.18\:25\:48.1069771.fuzz 
Buffer content: A$AAA
UndefinedBehaviorSanitizer:DEADLYSIGNAL
==1074633==ERROR: UndefinedBehaviorSanitizer: SEGV on unknown address 0x000000000000 (pc 0x000000000000 bp 0x000000000000 sp 0x7ffefbf24050 T1074633)
==1074633==Hint: pc points to the zero page.
==1074633==The signal is caused by a READ memory access.
==1074633==Hint: address points to the zero page.
#...
```

The crash confirms our vulnerability:
- The program reads the malformed input
- A segmentation fault occurs (SEGV)
- The sanitizer detects illegal memory access


Happy Fuzzing! 🎉

For more hands on practice you can checkout [Fuzzing101](https://github.com/antonio-morales/Fuzzing101)
