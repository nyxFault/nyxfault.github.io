---
title: "System Programming Concepts"
categories: [Linux, Programming]
tags: [linux, sys-programming]
---

_"System programming involves developing software that provides core services to the operating system and hardware, enabling user applications to interact with system resources efficiently. It focuses on low-level operations like process management, memory allocation, file systems, device drivers, and system calls—often written in languages like C or Rust for performance and direct hardware access."_

**System programming** focuses on software that interacts with hardware or system resources, like operating systems or drivers, while **application programming** creates software for end users to perform specific tasks.

## User Mode vs Kernel Mode

Modern operating systems like Linux operate in different **modes** to ensure security, stability, and efficient resource management. The two primary modes are **User Mode** and **Kernel Mode**.


### 1. Kernel Mode

- **Definition:**  
    Kernel mode is a privileged mode where the operating system has **full access** to all hardware and system resources.
    
- **Who Runs in Kernel Mode:**  
    The **Linux kernel** and **device drivers**.
    
- **Capabilities:**
    
    - Direct access to hardware (CPU, memory, I/O devices).
    - Can execute privileged instructions.
    - Can crash the entire system if errors occur.

### 2. User Mode

- **Definition:**  
    User mode is a restricted mode in which **user applications** run with limited access to system resources.
    
- **Who Runs in User Mode:**  
    User programs like web browsers, text editors, etc.
    
- **Capabilities:**
    
    - Cannot directly access hardware or kernel memory.
    - Must use **system calls** to request kernel services.
    - Crashes or errors affect only the specific application, not the entire system.

User mode programs rely on **system calls** (such as `open()`, `read()`, `write()`) to interact with the kernel and request services like file operations, networking, and process control.


Now, you must be wondering—**what exactly are system calls (syscalls)?**

A syscall is a request from a user program to the kernel to perform a privileged operation (e.g., `read()`, `write()`, `fork()`). Since user programs run in **unprivileged mode** (CPU ring 3), they can’t directly access hardware or kernel memory. The kernel (ring 0) handles these requests.

### How System Calls Work (Simple Flow):

1. **User Program Makes Request**  
    Program calls a library function (like `open()`, `read()`, or `write()`).
    
2. **System Call Invoked**  
    The library function triggers the corresponding system call.
    
3. **Mode Switch to Kernel Mode**  
    The CPU switches from user mode to kernel mode to safely execute the request.
    
4. **Kernel Performs Operation**  
    The Linux kernel processes the request (e.g., reading a file).
    
5. **Return to User Mode**  
    Once done, the system switches back to user mode and returns the result to the program.


**Refer** - [System calls in Operating System](https://www.scaler.com/topics/operating-system/system-calls-in-operating-system/)


![System Call](https://scaler.com/topics/images/intro_system_call.webp)

### Types of System Calls

System calls (syscalls) can be categorized based on the services they provide. Here are the most common types of system calls in Linux:

### 1. Process Control

These system calls manage processes, allowing programs to create, execute, and terminate processes.

**Examples:**

- `fork()` – Create a new process.
- `exec()` – Execute a new program.
- `exit()` – Terminate a process.
- `wait()` – Wait for a child process to finish.    


### 2. File Management

These system calls handle file operations like opening, reading, writing, and closing files.

**Examples:**

- `open()` – Open a file.
- `read()` – Read from a file.
- `write()` – Write to a file.
- `close()` – Close a file.
- `lseek()` – Reposition file offset.    


### 3. Device Management

These system calls manage hardware devices through device drivers.

**Examples:**

- `ioctl()` – Control device operations.
- `read()` / `write()` – For device I/O.
- `open()` / `close()` – To open/close device files.    



### 4. Information Maintenance

These system calls gather or set system information such as time, user ID, and system limits.

**Examples:**

- `getpid()` – Get process ID.
- `alarm()` – Set a timer.
- `sleep()` – Pause execution for a specified time.  
- `getuid()` – Get user ID.
   


### 5. Communication (Inter-Process Communication or IPC)

These system calls enable data exchange between processes using techniques like pipes, message queues, shared memory, and sockets.

**Examples:**

- `pipe()` – Create a pipe for data transfer.
- `shmget()` / `shmat()` – Shared memory.
- `msgget()` / `msgsnd()` – Message queues.
- `socket()` / `bind()` / `sendto()` – Network communication.

### C Library as a Wrapper for System Calls:

The C library provides high-level functions that abstract away the complexities of system calls.  
Developers generally use these functions instead of making system calls directly because they are easier to use and more portable across different systems.  
Internally, these C library functions are implemented using the corresponding system calls.

Functions like `open`, `read`, etc., are provided by the C library (libc).  
These functions have the same names as system calls, making them easy to remember and use.

When a C library function is called in a user program, it internally makes a system call to the kernel.  
For example, when you call `open("file.txt", O_RDONLY)`, the C library function `open` internally translates this to a `open` system call provided by the kernel.

The C library function prepares the arguments for the system call and sets up the CPU registers appropriately.  
It then triggers the CPU to switch to kernel mode, where the actual system call code executes.

The kernel receives the system call request from the user program.  
It validates the request, performs the necessary operations (like opening a file), and then returns control back to the C library function.

The C library function receives the result from the kernel and returns it to the user program.  
If an error occurred during the system call, the C library function translates the kernel error code (`errno`) into a meaningful error code or message that the user program can handle.

**libc**, short for "C Standard Library" or "Standard C Library," is a core library in the C programming language. It provides a set of functions, macros, and types that programmers can use to perform common operations, such as input/output (I/O), string manipulation, memory allocation, mathematical computations, and more. 


Here’s a simple C program that directly uses the C standard library (glibc) provided wrapper function to get the process ID:

```c
#include <unistd.h>
#include <stdio.h>

int main() {
    pid_t pid = getpid();  // Direct call to libc function
    printf("Process ID: %d\n", pid);
    return 0;
}
```

To use system calls directly in a C program, you can utilize the **syscall** function provided by the GNU C Library. 

Following is a simple C program that directly uses a system call to get the process ID:

```c
#include <unistd.h>
#include <sys/syscall.h>
#include <stdio.h>
#include <errno.h>

int main() {
    long pid = syscall(SYS_getpid); // Get process ID
    if (pid == -1) {
        perror("syscall failed");
        return 1;
    }
    printf("Process ID: %ld\n", pid);
    return 0;
}
```

Every system call has a unique syscall number that may vary across architectures. You can check syscall numbers in the Linux source code (`/usr/include/asm/unistd.h`).

I personally prefer this [site](https://syscall.sh/) for quick system call lookup.

