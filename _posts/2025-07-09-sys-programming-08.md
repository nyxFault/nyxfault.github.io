---
title: "8. Process Programming"
categories: [Linux, Programming]
tags: [linux, sys-programming]
---

We have already covered about what is process. Let's recall it -

A **process** is a running instance of a program. It has:

- Its own memory space (stack, heap, data, and text segments)
- File descriptors
- Process ID (PID)
- Execution context (registers, program counter, etc.)

Linux provides a set of system calls for process management:

### 1. `fork()`

`fork()` is used to create a **new process** by duplicating the current process. The new process is called the **child process**, while the original one is the **parent**.

```c
#include <unistd.h>
#include <stdio.h>

int main() {
    pid_t pid = fork();

    if (pid < 0) {
        perror("fork failed");
        return 1;
    } else if (pid == 0) {
        printf("This is the child process.\n");
    } else {
        printf("This is the parent process. Child PID: %d\n", pid);
    }

    return 0;
}

```

After `fork()`, both parent and child continue executing from the same point in the code, but they have different PIDs and independent memory spaces.

### 2. `exec()` Family


The `exec` family of functions are is used to execute a program, replacing the current process image with a new process image. These functions are defined in the `unistd.h` header file and are crucial for process control in Unix-like operating systems.

**Overview of exec Functions**

The exec family includes several functions, each with different ways to pass arguments and search for executables. Here’s a brief overview:
- **execl()**: Takes a variable number of arguments, ending with a NULL pointer.
- **execle()**: Similar to execl(), but allows passing an environment variable list.
- **execlp()**: Like execl(), but searches for the executable in the directories listed in the PATH environment variable.
- **execv()**: Takes an array of arguments instead of a variable list.
- **execvp()**: Similar to execv(), but searches for the executable in the PATH.
- **execve()**: The most general form, allowing both argument and environment variable lists.

They all execute `execve` system call under the hood.


The **execve** syscall in Unix-like operating systems (such as Linux) is a critical system call used to **replace the current process image** with a new program. This is central to process management, particularly when spawning new programs or executing external commands within a program.

The provided code demonstrates the usage of the execve system call, which replaces the current process image with a new one (in this case, /bin/ls). After execve is called, the current process is replaced, so the second printf will not be executed.
```c
#include <unistd.h>
#include <stdio.h>

int main() {
    pid_t pid = getpid();
    printf("Before execve: Process ID = %d\n", pid);

    // Arguments for execve ("/bin/ls" with argument "-l" and NULL terminator)
    char *args[] = {"/bin/ls", "-l", NULL};
    char *envp[] = {NULL};  // No environment variables

    // Call execve
    if (execve(args[0], args, envp) == -1) {
        perror("execve failed");
        return 1;
    }

    // This line won't be executed since execve replaces the process
    printf("This will never be printed\n");
    return 0;
}

```

The second printf will not execute because execve replaces the current process image, so everything after execve will not be executed unless execve fails.


**Behavior:**
*Process Replacement:* 
When execve is called, it replaces the current process (the process that called execve) with the new program. This means:
- The current process’s memory, including its code, data, and stack, is replaced with that of the new program.
- The process ID (PID) remains the same, but the program itself (the instructions and data) changes.
- If the new program is successfully executed, none of the code following execve in the calling process is executed because the calling process no longer exists in its original form.

*No Return on Success:*
If execve successfully loads the new program, it does not return to the calling program. The new program takes control of the process. Therefore, any code written after the execve call in the original process is never executed (unless there’s an error).


### Process Table and Process Control Block



In Linux, the Process Control Block (PCB) is a critical data structure used by the operating system to manage information about a running process. The `task_struct` structure in Linux represents this PCB. It holds all the essential information needed to track and manage processes, such as process state, scheduling information, memory management, and more.

The Process Table is a collection of all the `task_struct` structures in the system. Each entry in the process table corresponds to a single process running in the system. This structure is defined in `<linux/sched.h>` and includes various fields to manage the process's lifecycle, scheduling, and memory.

![Structure of PCB](https://scaler.com/topics/images/structure-of-process-control-block.webp)

**Refer**
[scaler](https://www.scaler.com/topics/operating-system/process-control-block-in-os/)


### 3. `wait()` and `waitpid()`

The `wait()` system call allows a parent process to wait for its child to finish execution.

```c
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <stdio.h>

int main() {
    pid_t pid = fork();

    if (pid == 0) {
        printf("Child process running\n");
        _exit(0);
    } else {
        wait(NULL);
        printf("Child process has finished\n");
    }

    return 0;
}

```

This ensures **proper cleanup** of the child process (prevents zombie processes).

**NOTE**

- **Zombie process**: A terminated child that hasn't been `wait()`ed for.
- **Orphan process**: A child whose parent has terminated — inherited by `init` (PID 1).

### 4. `exit()` and `_exit()`

- `exit()` is used to terminate a process **cleanly**, flushing I/O buffers.    
- `_exit()` is a **low-level** version that exits immediately, used mostly by child processes after `fork()`.

