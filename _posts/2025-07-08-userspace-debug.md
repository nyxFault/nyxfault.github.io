---
title: "Linux User Space Debugging"
categories: [Linux, Debugging]
tags: [debug, gdb, radare2, pwndbg]
---



Debugging is an essential skill for any software developer, and when it comes to Linux systems, it becomes even more critical. In Linux, the operating system is broadly divided into **kernel space** and **user space**. While kernel-space debugging involves low-level diagnostics of the OS internals, **user space debugging** focuses on applications and processes running outside the kernel — in a more controlled and less privileged environment.

User space debugging is particularly important because most Linux applications, services, and daemons operate in user space.

In this blog, we’ll dive into Linux User Space Debugging techniques and tools.

## 🐞 GDB (GNU Debugger)

**GDB** is the GNU Project Debugger, used to debug programs written in **C, C++, Fortran, and more**. It allows you to:

- Inspect what’s happening inside a program while it runs.
- Analyze what caused a crash.
- Modify variables at runtime.
- Step through code interactively.


```bash
# Compile with Debug Symbols
gcc -g program.c -o program

# Produce debugging information for use by GDB.
gcc -ggdb program.c -o program
```

> Tip
{: .prompt-tip }

While **plain GDB** is powerful and widely used, its default interface isn't very user-friendly and can feel quite minimal. It doesn’t provide results in a well-structured or visually clear manner, which can slow down the debugging process, especially when dealing with complex programs or low-level issues.

That’s why I prefer using **Pwndbg** — an enhanced GDB plugin designed for modern debugging.

**Installation**

```bash
sudo apt update
sudo apt install -y git gdb python3 python3-pip python3-dev
git clone https://github.com/pwndbg/pwndbg
cd pwndbg
./setup.sh
```
[pwndbg cheatsheet](https://pwndbg.re/CheatSheet.pdf)

**Basic GDB Commands**

```bash
# Starting GDB
$ gdb ./program

```



| **Command**   | **Description**                       |
| ------------- | ------------------------------------- |
| `run` or `r`  | Start the program                     |
| `quit` or `q` | Exit GDB                              |
| `help`        | Show help                             |
| `file`        | Load a new binary                     |
| `start`       | Begin execution and break at `main()` |

**⛔ Breakpoints and Execution Control**

```bash
# Set Breakpoints
break main                 # Break at function
break 25                   # Break at line number
break file.c:18            # Break at line in a specific file

# Manage Breakpoints
info breakpoints           # List breakpoints
delete [num]               # Delete breakpoints
disable [num]              # Disable
enable [num]               # Enable

# Execution Flow
run                        # Run from start
continue                   # Continue after a breakpoint
next                       # Step over function (source line)
step                       # Step into function
finish                     # Run until function returns
until [line]               # Continue until reaching line
```


**Inspecting State**

```bash
# Variables and Memory
print x                    # Print variable value
print/x x                  # Hex
print/d x                  # Decimal
print/t x                  # Binary
display x                  # Print after every step
set variable x=5           # Change variable value

# Registers
info registers             # Show CPU registers
x/4xb &var                 # Examine memory

# Memory Display (`x`)
# x/FMT ADDRESS
# FMT = [N][FORMAT][SIZE]
# [N][F][U] ;)
# Example:
x/4xb &arr                 # 4 bytes, hex format
x/4i $pc                   # 4 instructions from PC

# Stack, Frames, and Function Calls
backtrace (bt)             # Show call stack
frame 1                    # Switch to frame
info frame                 # Info about current frame
info locals                # Local vars in current frame
info args                  # Arguments to current function
```


**Advanced: Conditional & Watchpoints**

```bash
# Conditional Breakpoints
break foo if x == 5

# Watchpoints (break on value change)
watch x                   # Break if x is written to
rwatch x                  # Break if x is read
awatch x                  # Break if x is read or written

# Debugging Core Dumps
# Generate a core dump
ulimit -c unlimited
./program

# Load core file
gdb ./program core
gdb -core core

# Then use:
bt                          # Backtrace
info locals                 # Inspect variables
```

**Attach to a Running Process**

```bash
gdb -p <pid>
# OR
attach <pid>
detach
```

**Useful GDB Settings**

```bash
set disassembly-flavor intel     # Intel syntax (easier for many devs)
set pagination off               # Avoid --More-- in outputs
set print pretty on              # Pretty-print C++ containers
```

**GDB Shortcuts and TUI**

TUI Mode (Visual Interface)
```bash
gdb -tui ./program
```

Inside GDB:
```bash
layout src                     # Show source
layout asm                     # Assembly view
layout regs                    # Registers
Ctrl+L                         # Refresh screen
```


**Extra Tips**

```bash
set disassemble-next-line on
set follow-fork-mode child
```

`set follow-fork-mode child`

When debugging programs that create new processes (using `fork()`), this option tells GDB to automatically follow the **child process** instead of the parent.

**Security Features**

```bash
canary                   # Show stack canary
checksec                 # Show binary protections (NX, PIE, etc.)
```

**GDB Scripting (for automation)**

```bash
$ gdb -x script.gdb ./program

$ cat script.gdb
break main
run
print x
quit
```


Here’s the C program we’ll debug:

```c
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

void greet(const char *name) {
    printf("Hello, %s!\n", name);
}

int sum(int a, int b) {
    return a + b;
}

int main() {
    char *name = malloc(20);
    if (!name) {
        perror("malloc failed");
        return 1;
    }

    strcpy(name, "GDB_User");

    greet(name);

    int x = 10;
    int y = 20;
    int result = sum(x, y);

    printf("Sum of %d and %d is %d\n", x, y, result);

    int *ptr = NULL;
    *ptr = 5; // 💥 Intentional segfault

    free(name);
    return 0;
}

```


The program :
- Allocates memory for a name and greets the user.
- Computes the sum of two numbers.
- Intentionally crashes with a **segmentation fault** (`*ptr = 5`).

```bash
# Compile
gcc -ggdb demo.c -o demo
gdb ./demo 
pwndbg> break demo.c:22 # Line where greet(name) is called
pwndbg> run
pwndbg> print name # Inspect argument passed
$1 = 0x5555555592a0 "GDB_User"
pwndbg> break demo.c:26 # Store result in result
pwndbg> continue
pwndbg> next # Next line
pwndbg> p result
$2 = 30
pwndbg> p x 
$3 = 10
pwndbg> p y
$4 = 20
pwndbg> continue # The program will crash
pwndbg> backtrace
#0  0x0000555555555295 in main () at demo.c:31
#...
```

You can see at line 31 in `demo.c` we called `*ptr = 5`.

GDB’s **TUI mode** gives a **visual layout** in the terminal that includes:

- Source code
- Assembly
- Register contents
- Disassembly
- Navigation pane

**Starting TUI Mode**

```bash
# Option 1: From the start
gdb -tui ./demo

# Option 2: Inside GDB
(gdb) tui enable
(gdb) layout src     # show source
```

But pwndbg offers much more beautiful `TUI`. Use `layout pwndbg`

```bash
$ gdb ./program
layout pwndbg
```

Switch CLI & TUI mode
`Ctrl + X + A`

Use layout:
```bash
pwndbg> layout [NAME]
```

*NAME:*
- asm
- next
- prev
- pwndbg
- pwndbg_code
- regs
- split
- src


# Pwndbg Commands

## [Breakpoint](https://pwndbg.re/pwndbg/commands/#breakpoint "Permanent link")

- [breakrva](https://pwndbg.re/pwndbg/commands/breakpoint/breakrva/) - Break at RVA from PIE base.
- [ignore](https://pwndbg.re/pwndbg/commands/breakpoint/ignore/) - Set ignore-count of breakpoint number N to COUNT.

## [Context](https://pwndbg.re/pwndbg/commands/#context "Permanent link")

- [context](https://pwndbg.re/pwndbg/commands/context/context/) - Print out the current register, instruction, and stack context.
- [contextnext](https://pwndbg.re/pwndbg/commands/context/contextnext/) - Select next entry in context history.
- [contextoutput](https://pwndbg.re/pwndbg/commands/context/contextoutput/) - Sets the output of a context section.
- [contextprev](https://pwndbg.re/pwndbg/commands/context/contextprev/) - Select previous entry in context history.
- [contextsearch](https://pwndbg.re/pwndbg/commands/context/contextsearch/) - Search for a string in the context history and select that entry.
- [contextunwatch](https://pwndbg.re/pwndbg/commands/context/contextunwatch/) - Removes an expression previously added to be watched.
- [contextwatch](https://pwndbg.re/pwndbg/commands/context/contextwatch/) - Adds an expression to be shown on context.
- [regs](https://pwndbg.re/pwndbg/commands/context/regs/) - Print out all registers and enhance the information.

## [Developer](https://pwndbg.re/pwndbg/commands/#developer "Permanent link")

- [dev_dump_instruction](https://pwndbg.re/pwndbg/commands/developer/dev_dump_instruction/) - Dump internal PwndbgInstruction attributes.
- [log_level](https://pwndbg.re/pwndbg/commands/developer/log_level/) - Set the log level.

## [Disassemble](https://pwndbg.re/pwndbg/commands/#disassemble "Permanent link")

- [emulate](https://pwndbg.re/pwndbg/commands/disassemble/emulate/) - Like nearpc, but will emulate instructions from the current $PC forward.
- [nearpc](https://pwndbg.re/pwndbg/commands/disassemble/nearpc/) - Disassemble near a specified address.

## [GLibc ptmalloc2 Heap](https://pwndbg.re/pwndbg/commands/#glibc-ptmalloc2-heap "Permanent link")

- [arena](https://pwndbg.re/pwndbg/commands/glibc_ptmalloc2_heap/arena/) - Print the contents of an arena.
- [arenas](https://pwndbg.re/pwndbg/commands/glibc_ptmalloc2_heap/arenas/) - List this process's arenas.
- [bins](https://pwndbg.re/pwndbg/commands/glibc_ptmalloc2_heap/bins/) - Print the contents of all an arena's bins and a thread's tcache.
- [fastbins](https://pwndbg.re/pwndbg/commands/glibc_ptmalloc2_heap/fastbins/) - Print the contents of an arena's fastbins.
- [find_fake_fast](https://pwndbg.re/pwndbg/commands/glibc_ptmalloc2_heap/find_fake_fast/) - Find candidate fake fast or tcache chunks overlapping the specified address.
- [heap](https://pwndbg.re/pwndbg/commands/glibc_ptmalloc2_heap/heap/) - Iteratively print chunks on a heap.
- [heap_config](https://pwndbg.re/pwndbg/commands/glibc_ptmalloc2_heap/heap_config/) - Shows heap related configuration.
- [hi](https://pwndbg.re/pwndbg/commands/glibc_ptmalloc2_heap/hi/) - Searches all heaps to find if an address belongs to a chunk. If yes, prints the chunk.
- [largebins](https://pwndbg.re/pwndbg/commands/glibc_ptmalloc2_heap/largebins/) - Print the contents of an arena's largebins.
- [malloc_chunk](https://pwndbg.re/pwndbg/commands/glibc_ptmalloc2_heap/malloc_chunk/) - Print a chunk.
- [mp](https://pwndbg.re/pwndbg/commands/glibc_ptmalloc2_heap/mp/) - Print the mp_ struct's contents.
- [smallbins](https://pwndbg.re/pwndbg/commands/glibc_ptmalloc2_heap/smallbins/) - Print the contents of an arena's smallbins.
- [tcache](https://pwndbg.re/pwndbg/commands/glibc_ptmalloc2_heap/tcache/) - Print a thread's tcache contents.
- [tcachebins](https://pwndbg.re/pwndbg/commands/glibc_ptmalloc2_heap/tcachebins/) - Print the contents of a tcache.
- [top_chunk](https://pwndbg.re/pwndbg/commands/glibc_ptmalloc2_heap/top_chunk/) - Print relevant information about an arena's top chunk.
- [try_free](https://pwndbg.re/pwndbg/commands/glibc_ptmalloc2_heap/try_free/) - Check what would happen if free was called with given address.
- [unsortedbin](https://pwndbg.re/pwndbg/commands/glibc_ptmalloc2_heap/unsortedbin/) - Print the contents of an arena's unsortedbin.
- [vis_heap_chunks](https://pwndbg.re/pwndbg/commands/glibc_ptmalloc2_heap/vis_heap_chunks/) - Visualize chunks on a heap.

## [Integrations](https://pwndbg.re/pwndbg/commands/#integrations "Permanent link")

- [ai](https://pwndbg.re/pwndbg/commands/integrations/ai/) - Ask GPT-3 a question about the current debugging context.
- [bn-sync](https://pwndbg.re/pwndbg/commands/integrations/bn-sync/) - Synchronize Binary Ninja's cursor with GDB.
- [decomp](https://pwndbg.re/pwndbg/commands/integrations/decomp/) - Use the current integration to decompile code near an address.
- [j](https://pwndbg.re/pwndbg/commands/integrations/j/) - Synchronize IDA's cursor with GDB.
- [r2](https://pwndbg.re/pwndbg/commands/integrations/r2/) - Launches radare2.
- [r2pipe](https://pwndbg.re/pwndbg/commands/integrations/r2pipe/) - Execute stateful radare2 commands through r2pipe.
- [rop](https://pwndbg.re/pwndbg/commands/integrations/rop/) - Dump ROP gadgets with Jon Salwan's ROPgadget tool.
- [ropper](https://pwndbg.re/pwndbg/commands/integrations/ropper/) - ROP gadget search with ropper.
- [rz](https://pwndbg.re/pwndbg/commands/integrations/rz/) - Launches rizin.
- [rzpipe](https://pwndbg.re/pwndbg/commands/integrations/rzpipe/) - Execute stateful rizin commands through rzpipe.
- [save_ida](https://pwndbg.re/pwndbg/commands/integrations/save_ida/) - Save the ida database.

## [Kernel](https://pwndbg.re/pwndbg/commands/#kernel "Permanent link")

- [binder](https://pwndbg.re/pwndbg/commands/kernel/binder/) - Show Android Binder information
- [kbase](https://pwndbg.re/pwndbg/commands/kernel/kbase/) - Finds the kernel virtual base address.
- [kchecksec](https://pwndbg.re/pwndbg/commands/kernel/kchecksec/) - Checks for kernel hardening configuration options.
- [kcmdline](https://pwndbg.re/pwndbg/commands/kernel/kcmdline/) - Return the kernel commandline (/proc/cmdline).
- [kconfig](https://pwndbg.re/pwndbg/commands/kernel/kconfig/) - Outputs the kernel config (requires CONFIG_IKCONFIG).
- [klookup](https://pwndbg.re/pwndbg/commands/kernel/klookup/) - Lookup kernel symbols
- [knft_dump](https://pwndbg.re/pwndbg/commands/kernel/knft_dump/) - Dump all nftables: tables, chains, rules, expressions
- [knft_list_chains](https://pwndbg.re/pwndbg/commands/kernel/knft_list_chains/) - Dump netfilter chains form a specific table
- [knft_list_exprs](https://pwndbg.re/pwndbg/commands/kernel/knft_list_exprs/) - Dump only expressions from specific rule
- [knft_list_flowtables](https://pwndbg.re/pwndbg/commands/kernel/knft_list_flowtables/) - Dump netfilter flowtables from a specific table
- [knft_list_objects](https://pwndbg.re/pwndbg/commands/kernel/knft_list_objects/) - Dump netfilter objects from a specific table
- [knft_list_rules](https://pwndbg.re/pwndbg/commands/kernel/knft_list_rules/) - Dump netfilter rules form a specific chain
- [knft_list_sets](https://pwndbg.re/pwndbg/commands/kernel/knft_list_sets/) - Dump netfilter sets from a specific table
- [knft_list_tables](https://pwndbg.re/pwndbg/commands/kernel/knft_list_tables/) - Dump netfliter tables from a specific network namespace
- [kversion](https://pwndbg.re/pwndbg/commands/kernel/kversion/) - Outputs the kernel version (/proc/version).
- [pcplist](https://pwndbg.re/pwndbg/commands/kernel/pcplist/) - Print Per-CPU page list
- [slab](https://pwndbg.re/pwndbg/commands/kernel/slab/) - Prints information about the slab allocator

## [Linux/libc/ELF](https://pwndbg.re/pwndbg/commands/#linuxlibcelf "Permanent link")

- [argc](https://pwndbg.re/pwndbg/commands/linux_libc_elf/argc/) - Prints out the number of arguments.
- [argv](https://pwndbg.re/pwndbg/commands/linux_libc_elf/argv/) - Prints out the contents of argv.
- [aslr](https://pwndbg.re/pwndbg/commands/linux_libc_elf/aslr/) - Check the current ASLR status, or turn it on/off.
- [auxv](https://pwndbg.re/pwndbg/commands/linux_libc_elf/auxv/) - Print information from the Auxiliary ELF Vector.
- [auxv_explore](https://pwndbg.re/pwndbg/commands/linux_libc_elf/auxv_explore/) - Explore and print information from the Auxiliary ELF Vector.
- [elfsections](https://pwndbg.re/pwndbg/commands/linux_libc_elf/elfsections/) - Prints the section mappings contained in the ELF header.
- [envp](https://pwndbg.re/pwndbg/commands/linux_libc_elf/envp/) - Prints out the contents of the environment.
- [errno](https://pwndbg.re/pwndbg/commands/linux_libc_elf/errno/) - Converts errno (or argument) to its string representation.
- [got](https://pwndbg.re/pwndbg/commands/linux_libc_elf/got/) - Show the state of the Global Offset Table.
- [gotplt](https://pwndbg.re/pwndbg/commands/linux_libc_elf/gotplt/) - Prints any symbols found in the .got.plt section if it exists.
- [libcinfo](https://pwndbg.re/pwndbg/commands/linux_libc_elf/libcinfo/) - Show libc version and link to its sources
- [linkmap](https://pwndbg.re/pwndbg/commands/linux_libc_elf/linkmap/) - Show the state of the Link Map
- [onegadget](https://pwndbg.re/pwndbg/commands/linux_libc_elf/onegadget/) - Show onegadget
- [piebase](https://pwndbg.re/pwndbg/commands/linux_libc_elf/piebase/) - Calculate VA of RVA from PIE base.
- [plt](https://pwndbg.re/pwndbg/commands/linux_libc_elf/plt/) - Prints any symbols found in the .plt section if it exists.
- [strings](https://pwndbg.re/pwndbg/commands/linux_libc_elf/strings/) - Extracts and displays ASCII strings from readable memory pages of the debugged process.
- [threads](https://pwndbg.re/pwndbg/commands/linux_libc_elf/threads/) - List all threads belonging to the selected inferior.
- [tls](https://pwndbg.re/pwndbg/commands/linux_libc_elf/tls/) - Print out base address of the current Thread Local Storage (TLS).
- [track-got](https://pwndbg.re/pwndbg/commands/linux_libc_elf/track-got/) - Controls GOT tracking
- [track-heap](https://pwndbg.re/pwndbg/commands/linux_libc_elf/track-heap/) - Manages the heap tracker.

## [Memory](https://pwndbg.re/pwndbg/commands/#memory "Permanent link")

- [distance](https://pwndbg.re/pwndbg/commands/memory/distance/) - Print the distance between the two arguments, or print the offset to the address's page base.
- [gdt](https://pwndbg.re/pwndbg/commands/memory/gdt/) - Decode X86-64 GDT entries at address
- [go-dump](https://pwndbg.re/pwndbg/commands/memory/go-dump/) - Dumps a Go value of a given type at a specified address.
- [go-type](https://pwndbg.re/pwndbg/commands/memory/go-type/) - Dumps a Go runtime reflection type at a specified address.
- [hexdump](https://pwndbg.re/pwndbg/commands/memory/hexdump/) - Hexdumps data at the specified address or module name.
- [leakfind](https://pwndbg.re/pwndbg/commands/memory/leakfind/) - Attempt to find a leak chain given a starting address.
- [memfrob](https://pwndbg.re/pwndbg/commands/memory/memfrob/) - Memfrobs a region of memory (xor with '*').
- [mmap](https://pwndbg.re/pwndbg/commands/memory/mmap/) - Calls the mmap syscall and prints its resulting address.
- [mprotect](https://pwndbg.re/pwndbg/commands/memory/mprotect/) - Calls the mprotect syscall and prints its result value.
- [p2p](https://pwndbg.re/pwndbg/commands/memory/p2p/) - Pointer to pointer chain search. Searches given mapping for all pointers that point to specified mapping.
- [probeleak](https://pwndbg.re/pwndbg/commands/memory/probeleak/) - Pointer scan for possible offset leaks.
- [search](https://pwndbg.re/pwndbg/commands/memory/search/) - Search memory for byte sequences, strings, pointers, and integer values.
- [telescope](https://pwndbg.re/pwndbg/commands/memory/telescope/) - Recursively dereferences pointers starting at the specified address.
- [telescope](https://pwndbg.re/pwndbg/commands/memory/telescope/) - Recursively dereferences pointers starting at the specified address.
- [vmmap](https://pwndbg.re/pwndbg/commands/memory/vmmap/) - Print virtual memory map pages.
- [vmmap_add](https://pwndbg.re/pwndbg/commands/memory/vmmap_add/) - Add virtual memory map page.
- [vmmap_clear](https://pwndbg.re/pwndbg/commands/memory/vmmap_clear/) - Clear the vmmap cache.
- [vmmap_explore](https://pwndbg.re/pwndbg/commands/memory/vmmap_explore/) - Explore a page, trying to guess permissions.
- [xinfo](https://pwndbg.re/pwndbg/commands/memory/xinfo/) - Shows offsets of the specified address from various useful locations.
- [xor](https://pwndbg.re/pwndbg/commands/memory/xor/) - XOR `count` bytes at `address` with the key `key`.

## [Misc](https://pwndbg.re/pwndbg/commands/#misc "Permanent link")

- [asm](https://pwndbg.re/pwndbg/commands/misc/asm/) - Assemble shellcode into bytes
- [break-if-not-taken](https://pwndbg.re/pwndbg/commands/misc/break-if-not-taken/) - Breaks on a branch if it is not taken.
- [break-if-taken](https://pwndbg.re/pwndbg/commands/misc/break-if-taken/) - Breaks on a branch if it is taken.
- [checksec](https://pwndbg.re/pwndbg/commands/misc/checksec/) - Prints out the binary security settings using `checksec`.
- [comm](https://pwndbg.re/pwndbg/commands/misc/comm/) - Put comments in assembly code.
- [cyclic](https://pwndbg.re/pwndbg/commands/misc/cyclic/) - Cyclic pattern creator/finder.
- [cymbol](https://pwndbg.re/pwndbg/commands/misc/cymbol/) - Add, show, load, edit, or delete custom structures in plain C.
- [down](https://pwndbg.re/pwndbg/commands/misc/down/) - Select and print stack frame called by this one.
- [dt](https://pwndbg.re/pwndbg/commands/misc/dt/) - Dump out information on a type (e.g. ucontext_t).
- [dumpargs](https://pwndbg.re/pwndbg/commands/misc/dumpargs/) - Prints determined arguments for call instruction.
- [getfile](https://pwndbg.re/pwndbg/commands/misc/getfile/) - Gets the current file.
- [hex2ptr](https://pwndbg.re/pwndbg/commands/misc/hex2ptr/) - Converts a space-separated hex string to a little-endian address.
- [hijack-fd](https://pwndbg.re/pwndbg/commands/misc/hijack-fd/) - Replace a file descriptor of a debugged process.
- [ipi](https://pwndbg.re/pwndbg/commands/misc/ipi/) - Start an interactive IPython prompt.
- [patch](https://pwndbg.re/pwndbg/commands/misc/patch/) - Patches given instruction with given code or bytes.
- [patch_list](https://pwndbg.re/pwndbg/commands/misc/patch_list/) - List all patches.
- [patch_revert](https://pwndbg.re/pwndbg/commands/misc/patch_revert/) - Revert patch at given address.
- [plist](https://pwndbg.re/pwndbg/commands/misc/plist/) - Dumps the elements of a linked list.
- [sigreturn](https://pwndbg.re/pwndbg/commands/misc/sigreturn/) - Display the SigreturnFrame at the specific address
- [spray](https://pwndbg.re/pwndbg/commands/misc/spray/) - Spray memory with cyclic() generated values
- [tips](https://pwndbg.re/pwndbg/commands/misc/tips/) - Shows tips.
- [up](https://pwndbg.re/pwndbg/commands/misc/up/) - Select and print stack frame that called this one.
- [valist](https://pwndbg.re/pwndbg/commands/misc/valist/) - Dumps the arguments of a va_list.
- [vmmap_load](https://pwndbg.re/pwndbg/commands/misc/vmmap_load/) - Load virtual memory map pages from ELF file.

## [Process](https://pwndbg.re/pwndbg/commands/#process "Permanent link")

- [killthreads](https://pwndbg.re/pwndbg/commands/process/killthreads/) - Kill all or given threads.
- [pid](https://pwndbg.re/pwndbg/commands/process/pid/) - Gets the pid.
- [procinfo](https://pwndbg.re/pwndbg/commands/process/procinfo/) - Display information about the running process.

## [Register](https://pwndbg.re/pwndbg/commands/#register "Permanent link")

- [cpsr](https://pwndbg.re/pwndbg/commands/register/cpsr/) - Print out ARM CPSR or xPSR register.
- [fsbase](https://pwndbg.re/pwndbg/commands/register/fsbase/) - Prints out the FS base address. See also $fsbase.
- [gsbase](https://pwndbg.re/pwndbg/commands/register/gsbase/) - Prints out the GS base address. See also $gsbase.
- [setflag](https://pwndbg.re/pwndbg/commands/register/setflag/) - Modify the flags register.

## [Stack](https://pwndbg.re/pwndbg/commands/#stack "Permanent link")

- [canary](https://pwndbg.re/pwndbg/commands/stack/canary/) - Print out the current stack canary.
- [retaddr](https://pwndbg.re/pwndbg/commands/stack/retaddr/) - Print out the stack addresses that contain return addresses.
- [stack](https://pwndbg.re/pwndbg/commands/stack/stack/) - Dereferences on stack data with specified count and offset.
- [stack_explore](https://pwndbg.re/pwndbg/commands/stack/stack_explore/) - Explore stack from all threads.
- [stackf](https://pwndbg.re/pwndbg/commands/stack/stackf/) - Dereferences on stack data, printing the entire stack frame with specified count and offset .

## [Start](https://pwndbg.re/pwndbg/commands/#start "Permanent link")

- [attachp](https://pwndbg.re/pwndbg/commands/start/attachp/) - Attaches to a given pid, process name, process found with partial argv match or to a device file.
- [entry](https://pwndbg.re/pwndbg/commands/start/entry/) - Start the debugged program stopping at its entrypoint address.
- [sstart](https://pwndbg.re/pwndbg/commands/start/sstart/) - Alias for 'tbreak __libc_start_main; run'.
- [start](https://pwndbg.re/pwndbg/commands/start/start/) - Start the debugged program stopping at the first convenient location

## [Step/Next/Continue](https://pwndbg.re/pwndbg/commands/#stepnextcontinue "Permanent link")

- [nextcall](https://pwndbg.re/pwndbg/commands/step_next_continue/nextcall/) - Breaks at the next call instruction.
- [nextjmp](https://pwndbg.re/pwndbg/commands/step_next_continue/nextjmp/) - Breaks at the next jump instruction.
- [nextproginstr](https://pwndbg.re/pwndbg/commands/step_next_continue/nextproginstr/) - Breaks at the next instruction that belongs to the running program.
- [nextret](https://pwndbg.re/pwndbg/commands/step_next_continue/nextret/) - Breaks at next return-like instruction.
- [nextsyscall](https://pwndbg.re/pwndbg/commands/step_next_continue/nextsyscall/) - Breaks at the next syscall not taking branches.
- [stepover](https://pwndbg.re/pwndbg/commands/step_next_continue/stepover/) - Breaks on the instruction after this one.
- [stepret](https://pwndbg.re/pwndbg/commands/step_next_continue/stepret/) - Breaks at next return-like instruction by 'stepping' to it.
- [stepsyscall](https://pwndbg.re/pwndbg/commands/step_next_continue/stepsyscall/) - Breaks at the next syscall by taking branches.
- [stepuntilasm](https://pwndbg.re/pwndbg/commands/step_next_continue/stepuntilasm/) - Breaks on the next matching instruction.
- [xuntil](https://pwndbg.re/pwndbg/commands/step_next_continue/xuntil/) - Continue execution until an address or expression.

## [WinDbg](https://pwndbg.re/pwndbg/commands/#windbg "Permanent link")

- [bc](https://pwndbg.re/pwndbg/commands/windbg/bc/) - Clear the breakpoint with the specified index.
- [bd](https://pwndbg.re/pwndbg/commands/windbg/bd/) - Disable the breakpoint with the specified index.
- [be](https://pwndbg.re/pwndbg/commands/windbg/be/) - Enable the breakpoint with the specified index.
- [bl](https://pwndbg.re/pwndbg/commands/windbg/bl/) - List breakpoints.
- [bp](https://pwndbg.re/pwndbg/commands/windbg/bp/) - Set a breakpoint at the specified address.
- [da](https://pwndbg.re/pwndbg/commands/windbg/da/) - Dump a string at the specified address.
- [db](https://pwndbg.re/pwndbg/commands/windbg/db/) - Starting at the specified address, dump N bytes.
- [dc](https://pwndbg.re/pwndbg/commands/windbg/dc/) - Starting at the specified address, hexdump.
- [dd](https://pwndbg.re/pwndbg/commands/windbg/dd/) - Starting at the specified address, dump N dwords.
- [dds](https://pwndbg.re/pwndbg/commands/windbg/dds/) - Dump pointers and symbols at the specified address.
- [dq](https://pwndbg.re/pwndbg/commands/windbg/dq/) - Starting at the specified address, dump N qwords.
- [ds](https://pwndbg.re/pwndbg/commands/windbg/ds/) - Dump a string at the specified address.
- [dw](https://pwndbg.re/pwndbg/commands/windbg/dw/) - Starting at the specified address, dump N words.
- [eb](https://pwndbg.re/pwndbg/commands/windbg/eb/) - Write hex bytes at the specified address.
- [ed](https://pwndbg.re/pwndbg/commands/windbg/ed/) - Write hex dwords at the specified address.
- [eq](https://pwndbg.re/pwndbg/commands/windbg/eq/) - Write hex qwords at the specified address.
- [ew](https://pwndbg.re/pwndbg/commands/windbg/ew/) - Write hex words at the specified address.
- [ez](https://pwndbg.re/pwndbg/commands/windbg/ez/) - Write a string at the specified address.
- [eza](https://pwndbg.re/pwndbg/commands/windbg/eza/) - Write a string at the specified address.
- [go](https://pwndbg.re/pwndbg/commands/windbg/go/) - Windbg compatibility alias for 'continue' command.
- [k](https://pwndbg.re/pwndbg/commands/windbg/k/) - Print a backtrace (alias 'bt').
- [ln](https://pwndbg.re/pwndbg/commands/windbg/ln/) - List the symbols nearest to the provided value.
- [pc](https://pwndbg.re/pwndbg/commands/windbg/pc/) - Windbg compatibility alias for 'nextcall' command.
- [peb](https://pwndbg.re/pwndbg/commands/windbg/peb/) - Not be windows.

## [jemalloc Heap](https://pwndbg.re/pwndbg/commands/#jemalloc-heap "Permanent link")

- [jemalloc_extent_info](https://pwndbg.re/pwndbg/commands/jemalloc_heap/jemalloc_extent_info/) - Prints extent information for the given address
- [jemalloc_find_extent](https://pwndbg.re/pwndbg/commands/jemalloc_heap/jemalloc_find_extent/) - Returns extent information for pointer address allocated by jemalloc
- [jemalloc_heap](https://pwndbg.re/pwndbg/commands/jemalloc_heap/jemalloc_heap/) - Prints all extents information

## [pwndbg](https://pwndbg.re/pwndbg/commands/#pwndbg "Permanent link")

- [bugreport](https://pwndbg.re/pwndbg/commands/pwndbg/bugreport/) - Generate a bug report.
- [config](https://pwndbg.re/pwndbg/commands/pwndbg/config/) - Shows pwndbg-specific configuration.
- [configfile](https://pwndbg.re/pwndbg/commands/pwndbg/configfile/) - Generates a configuration file for the current pwndbg options.
- [memoize](https://pwndbg.re/pwndbg/commands/pwndbg/memoize/) - Toggles memoization (caching).
- [profiler](https://pwndbg.re/pwndbg/commands/pwndbg/profiler/) - Utilities for profiling pwndbg.
- [pwndbg](https://pwndbg.re/pwndbg/commands/pwndbg/pwndbg/) - Prints out a list of all pwndbg commands.
- [reinit_pwndbg](https://pwndbg.re/pwndbg/commands/pwndbg/reinit_pwndbg/) - Makes pwndbg reinitialize all state.
- [reload](https://pwndbg.re/pwndbg/commands/pwndbg/reload/) - Reload pwndbg.
- [theme](https://pwndbg.re/pwndbg/commands/pwndbg/theme/) - Shows pwndbg-specific theme configuration.
- [themefile](https://pwndbg.re/pwndbg/commands/pwndbg/themefile/) - Generates a configuration file for the current pwndbg theme options.
- [version](https://pwndbg.re/pwndbg/commands/pwndbg/version/) - Displays Pwndbg and its important deps versions.


---

## Radare2

While GDB is excellent for debugging, Radare2 goes much deeper — enabling disassembly, binary patching, and advanced analysis of compiled programs.
Radare2 (`r2`) is a powerful open-source framework for:

- Reverse engineering binaries (ELF, PE, Mach-O)
- Static and dynamic analysis
- Exploit development
- Binary patching
- Scripting & automation


#### Installation

You can install it using:
```bash
git clone https://github.com/radareorg/radare2.git
cd radare2
./sys/install.sh
```

Alternatively, install via your distro’s package manager:
```bash
sudo apt install radare2
```

```c
#include <stdio.h>
#include <string.h>

void greet() {
    printf("Welcome to GDB & Radare2 Demo!\n");
}

int vulnerable_function() {
    char name[32];
    printf("Enter your name: ");
    fgets(name, sizeof(name), stdin);
    printf("Hello, %s", name);
    return 0;
}

int main() {
    greet();
    vulnerable_function();
    printf("Program finished.\n");
    return 0;
}
```

> Tip
{: .prompt-tip }

Whenever you're stuck or unsure about a command in Radare2, just type `?` to open the **main help menu**, which lists all command categories.  
If you want help for a specific category, simply add `?` after the command prefix.

For example:
```bash
p?
```
This shows help for all **print-related** commands (`p` stands for **print** in Radare2).

**Basic Startup Commands**

| **Command**      | **Description**             |
| ---------------- | --------------------------- |
| `r2 ./binary`    | Open binary in r2           |
| `r2 -d ./binary` | Debug Mode                  |
| `r2 -A ./binary` | Analyze all automatically   |
| `aaa`            | Analyze everything manually |
| `aa`             | Analyze functions           |
| `afl`            | List Functions              |
| `pdf @main`      | Disassemble Function        |
| `s main`         | Seek to main                |
| `s <addr>`       | Seek to any address         |

**Navigation and Inspection**

| **Command**       | **Purpose**                             |
| ----------------- | --------------------------------------- |
| `s`               | Seek to address/function                |
| `afl`             | List all functions                      |
| `i`               | Show binary info                        |
| `ii`              | Show imported functions                 |
| `is`              | Show symbols                            |
| `iz`              | Show strings                            |
| `px <n> @ <addr>` | Hexdump (n bytes) at addr               |
| `pd <n> @ <addr>` | Disassemble n instructions at addr      |
| `VV`              | Visual mode with graph view (Capital V) |
| `V`               | Visual Mode (flat view)                 |
| `q`               | Quit Visual                             |

**Debugging with Radare2**

Start in Debug Mode:

```bash
r2 -d ./binary
```

| **Command**  | **Description**                |
| ------------ | ------------------------------ |
| `doo pargs]` | Reopen in debug mode with args |
| `dc`         | Continue                       |
| `ds`         | Step one instruction           |
| `dso <num>`  | step `<num>` source lines      |
| `db <addr>`  | Set breakpoint                 |
| `db main`    | Break at main                  |
| `dr`         | Show registers                 |
| `dr eax=0`   | Set register value             |
| `dmm`        | List Memory Maps               |
| `dpt`        | Show threads                   |

**Stack**

| **Command**     | **Description**                               |
| --------------- | --------------------------------------------- |
| `pxq <N> @ rsp` | Dump **N bytes** at the current stack pointer |
| `pxw <N> @ rsp` | Print N bytes Hex words dump (32-bit)         |
| `pxq <N> @ rsp` | Print N bytes Hex quad-words dump (64-bit)    |

**Disassembly and Analysis**

```bash
aaa              # Analyze all
s main           # Seek to main
pdf              # Print disassembly function
pdf @ sym.main   # Same as above
```

**Graph View (Visual Mode)**

```bash
V                # Visual flat mode
VV               # Visual Graph mode
```

Use arrow keys to move around. Press:

- `Enter` to follow function
- `q` to exit


**Stack, Memory, and Registers**

| **Command**   | **Description**                  |
| ------------- | -------------------------------- |
| `dr`          | Show register values             |
| `px 64 @ rsp` | Show stack contents              |
| `afvd`        | Show local variables             |
| `afcf`        | Show function calling convention |
| `agf`         | Show function graph (non-visual) |
| `axt <addr>`  | Find XRefs to addr               |

**Radare2** also has ability to find **cross-references (xrefs)** inside binaries.

**Cross-references** (or **xrefs**) are places in the binary where:

- A **function** is called.
- A **variable** or **string** is accessed.
- A memory address is referenced.

Use command `ax?`

| Command       | Description                                   |
| ------------- | --------------------------------------------- |
| `axt <addr>`  | Find xrefs to an address or symbol            |
| `axtj <addr>` | Same as above, but JSON output                |
| `axf <addr>`  | Find xrefs from a function (calls made by it) |

In our demo, we can find references to `greet` and `sum` functions.

```bash
[0x70306a9c9290]> axt @ sym.greet 
main 0x642b0a960245 [CALL:--x] call sym.greet
[0x70306a9c9290]> axt @ sym.sum
main 0x642b0a960262 [CALL:--x] call sym.sum
```


One of Radare2’s most powerful features is **binary patching** — the ability to modify compiled programs directly at the binary level.

Let’s modify a binary to **bypass a condition** and force it to print the flag.

Here’s our sample C program (`flag_demo.c`), which asks for a password and prints whether it’s correct:

```c
#include <stdio.h>
#include <string.h>

int main() {
    char password[20];
    printf("Enter password: ");
    scanf("%19s", password);

    if (strcmp(password, "letmein") == 0) {
        printf("Correct password!\n");
    } else {
        printf("Incorrect password.\n");
    }

    return 0;
}
```


```bash
gcc -g flag_demo.c -o flag_demo
```

Load the binary in radare2 with `-d` (Open in Debug mode)

```bash
r2 -w ./flag_demo
[0x000010e0]> aaa # Analyze everything (same as -A)
[0x000010e0]> afl # List all functions
```

Disassemble the `main` function to locate the password check:

```bash
# Look for the call to `strcmp`
[0x000010e0]> pdf @ sym.main
#...
|           0x00001224      e897feffff     call sym.imp.strcmp
#...
```

Set a breakpoint at the `strcmp` function:

```bash
[0x000010e0]> db sym.imp.strcmp
```

Run the program until it hits the breakpoint:

```bash
[0x720a0e5a3290]> dc
Enter password: AAAA
```

Now, the program stops right before comparing the password.

We can inspect registers and display the content **at the memory address stored in a register**

**NOTE**

In **x86-64 Linux**, the first function arguments are passed via registers:

- `rdi` → 1st argument
- `rsi` → 2nd argument

Inspect the strings in those registers using Radare2’s `psz` command (prints null-terminated strings):

```
# Inspect registers
[0x566dd71800c0]> psz @ rdi
AAAA
[0x566dd71800c0]> psz @ rsi
letmein
```

The password is `letmein`

We can go a step further and **patch the binary** to **always print the flag**, regardless of the user’s input.

Bypass the password check by modifying the binary, so it always prints correct password!

In your earlier disassembly of `main`:

```txt
call sym.imp.strcmp
test eax, eax
jne 0x5ce1794b523e  ; jumps to "Incorrect password" if wrong
```

The program compares the return value of `strcmp` and jumps to the "Incorrect password" message if they don’t match.

We’ll **NOP out** (disable) the conditional jump (`jne`) so it always prints "Correct password!" without checking.

Open binary in **write mode**:

```bash
r2 -w -A ./flag_demo
```

```bash
[0x000010e0]> pd 1 @ 0x0000122b
|       ,=< 0x0000122b      7511           jne 0x123e
[0x000010e0]> s 0x0000122b
[0x0000122b]> pd 1
|       ,=< 0x0000122b      7511           jne 0x123e
[0x0000122b]> wx?
Usage: wx[f] [arg]
| wx 3.       write the left nibble of the current byte
| wx .5       write the right nibble of the current byte
| wx+ 9090    write hexpairs and seek forward
| wxf -|file  write contents of hexpairs file here
[0x0000122b]> wx 9090
[0x0000122b]> pd 1
|           0x0000122b      90             nop
[0x0000122b]> pd 2
|           0x0000122b      90             nop
|           0x0000122c      90             nop
[0x0000122b]> q
```

Run the patched binary:

```bash
./flag_demo 
Enter password: AAAA
Correct password!
```

By NOP-ing out the conditional jump, we’ve forced the program to ignore the result of `strcmp` and always run the success block.


When you install **Radare2**, you also get several additional tools that are extremely useful for reverse engineering, binary analysis, hashing, patching, and more.

|Tool|Purpose|
|---|---|
|**rabin2**|ELF/PE/Mach-O binary analysis tool (inspect headers, imports, etc.)|
|**ragg2**|Generate shellcode and exploit payloads|
|**rahash2**|Calculate various hashes (MD5, SHA1, etc.) of files or strings|
|**rax2**|Convert numbers between bases (hex, dec, bin, etc.)|
|**rasm2**|Assembler and disassembler (standalone)|
|**radiff2**|Binary diffing tool to compare two binaries (very useful for patch analysis)|
|**rapatch2**|Binary patching tool (for scripting or quick patches)|
|**rafind2**|Search for patterns or signatures inside files or memory dumps|
|**rarun2**|Runtime loader to run binaries with custom arguments, environment, etc. (often used for emulation/sandboxing)|

You can read more about them [here](https://www.radare.org/get/RadareAZ-NN2015.pdf)

Radare2 includes a **built-in web interface** that provides a graphical view for:

- Disassembly
- Functions
- Graphs
- Hex dumps
- Stack, registers, and much more!

It’s great for **visual analysis** and works directly inside your browser.

Refer this [radare2-webui](https://github.com/radareorg/radare2-webui)


### Conclusion 

In this blog, we explored **GDB** and **Radare2**—two powerful tools for reverse engineering and debugging. This was just the beginning! In the **next blog**, I’ll take things further by solving some **real-world crackmes** to demonstrate more advanced, hands-on reverse engineering techniques using these tools.