---
title: "Shared Memory"
categories: [Linux, Programming]
tags: [linux, sys-programming]
---

**Shared Memory** is one of the fastest IPC (Inter-Process Communication) mechanisms on UNIX-like systems, allowing **multiple processes** to access the **same memory region**.

Unlike pipes or message queues, shared memory enables **direct memory access**, making it ideal for high-performance communication between processes. However, because multiple processes can access it simultaneously, you usually need **synchronization mechanisms** (like semaphores) to avoid race conditions.


#### SysV Shared Memory Functions

| Function   | Purpose                                                      |
| ---------- | ------------------------------------------------------------ |
| `shmget()` | Creates or gets a shared memory segment.                     |
| `shmat()`  | Attaches the shared memory to the process’s address space.   |
| `shmdt()`  | Detaches the shared memory from the process’s address space. |
| `shmctl()` | Controls or removes the shared memory segment.               |

#### Basic Working Flow

1. Generate a key using `ftok()`.
2. Create or access a shared memory segment with `shmget()`.
3. Attach to the segment with `shmat()`.
4. Read/write data in the shared memory.
5. Detach with `shmdt()` after use.
6. Delete the memory segment using `shmctl()` (if needed).


Below is a C program that demonstrates:

- Writing to shared memory.
- Reading from shared memory.
- Cleaning up the segment.

```c
#include <stdio.h>
#include <stdlib.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <string.h>
#include <unistd.h>

#define SHM_SIZE 1024  // 1 KB shared memory segment

int main() {
    key_t key;
    int shmid;
    char *data;

    // Generate a unique key
    key = ftok("shmfile", 65);
    if (key == -1) {
        perror("ftok");
        exit(1);
    }

    // Create shared memory segment
    shmid = shmget(key, SHM_SIZE, 0666 | IPC_CREAT);
    if (shmid == -1) {
        perror("shmget");
        exit(1);
    }

    // Attach to the shared memory
    data = (char *)shmat(shmid, (void *)0, 0);
    if (data == (char *)(-1)) {
        perror("shmat");
        exit(1);
    }

    // Write to shared memory
    printf("Writing to shared memory...\n");
    strcpy(data, "Hello from shared memory!");

    // Simulate some delay (optional)
    sleep(2);

    // Read from shared memory
    printf("Data read from shared memory: %s\n", data);

    // Detach from shared memory
    if (shmdt(data) == -1) {
        perror("shmdt");
        exit(1);
    }

    // Destroy the shared memory segment
    if (shmctl(shmid, IPC_RMID, NULL) == -1) {
        perror("shmctl");
        exit(1);
    }

    printf("Shared memory removed.\n");
    return 0;
}

```

**Compile & Run**

```bash
touch shmfile  # Required for ftok
gcc -o shm_example shm_example.c
./shm_example
```

**Summary** -

- `ftok()` generates a unique key.
- `shmget()` creates a shared memory segment (or accesses it if it already exists).
- `shmat()` attaches the segment to the process’s address space.
- `shmdt()` detaches the memory.
- `shmctl()` with `IPC_RMID` deletes the segment from the system.
- Memory persists even after the process exits **until explicitly deleted** with `shmctl`.