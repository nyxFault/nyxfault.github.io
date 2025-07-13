---
title: "9. Signals"
categories: [Linux, Programming]
tags: [linux, sys-programming]
---

In Linux, signals are a fundamental mechanism for inter-process communication (IPC) and process control. They allow processes to send notifications to each other or to themselves about specific events, like the need to stop, terminate, or handle an error. Signals can also be sent by the kernel in response to events such as hardware interrupts or software exceptions.

Signals are **software interrupt**s delivered to a process to notify it of events like illegal memory access, a request to terminate, or user-defined conditions.

When a process receives a signal:

- It can **ignore** it (except for a few critical ones).
- It can **catch** it by defining a **signal handler** function.
- It can let the **default action** occur (usually termination).

Think of signals like asynchronous messages telling a process that "something just happened."

Here are some widely used signals in Linux:

| Signal Name | Signal Number | Description                                   | Default Action        |
| ----------- | ------------- | --------------------------------------------- | --------------------- |
| `SIGINT`    | 2             | Interrupt from keyboard (Ctrl+C)              | Terminate             |
| `SIGTERM`   | 15            | Termination request                           | Terminate             |
| `SIGKILL`   | 9             | Kill signal (cannot be caught or ignored)     | Terminate             |
| `SIGSEGV`   | 11            | Invalid memory reference (Segmentation fault) | Terminate + core dump |
| `SIGSTOP`   | 19            | Stop process (cannot be caught/ignored)       | Stop                  |
| `SIGCONT`   | 18            | Continue a stopped process                    | Continue              |
| `SIGHUP`    | 1             | Hangup detected on controlling terminal       | Terminate             |
| `SIGALRM`   | 14            | Alarm clock (timer expiration)                | Terminate             |
| `SIGUSR1`   | 10            | User-defined signal 1                         | Terminate             |
| `SIGUSR2`   | 12            | User-defined signal 2                         | Terminate             |


**Handling Signals in C**

```c
#include <stdio.h>
#include <signal.h>
#include <unistd.h>

void handler(int signum) {
    write(STDOUT_FILENO, "Signal caught!\n", 15);
}

int main() {
    struct sigaction sa;
    sa.sa_handler = handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;

    sigaction(SIGINT, &sa, NULL);

    while (1) {
        printf("Working...\n");
        sleep(1);
    }
}

```

You can send signals to processes using `kill` command. It also lists all available signal names along with their corresponding numbers.

```bash
kill -l
# Send signal to PID
kill -9 1234   # Sends SIGKILL to process with PID 1234
kill -SIGTERM 1234  # Sends SIGTERM explicitly
```


You remember those classic **buffer overflows**, right?  
You write beyond an array’s boundary and—boom!—your program crashes with a **Segmentation Fault** (`SIGSEGV` — the **Segmentation Violation** signal).

But wait… what exactly is that **SIGSEGV**?

It’s a _signal_ sent by the operating system when your program tries to access memory it’s not allowed to. 

Now here’s the fun part:

We can **catch** that segmentation fault using a signal handler!


```c
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <unistd.h>

void segfault_handler(int signum) {
    printf("You overflowed me!\n");
    exit(1);
}

void vuln() {
    char buffer[16];
    gets(buffer);
}

int main() {
    struct sigaction sa;
    sa.sa_handler = segfault_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGSEGV, &sa, NULL);
    vuln();
    return 0;
}
```
Compile and run -

```bash
$ gcc overflow.c -fno-stack-protector -z execstack -o overflow
# Send lots of A's 
$ printf "%0.sA" {1..100} | ./overflow 
You overflowed me!
```

### SIGUSR1 and SIGUSR2 Signals
SIGUSR1 and SIGUSR2 are user-defined signals in Unix-like operating systems, including Linux. They are part of the set of signals reserved for **user-defined purposes**, allowing programs to define custom signal-handling behaviors for specific events or conditions.

These signals are **not predefined by the operating system** (like SIGINT or SIGTERM), but rather are intended for use by applications or programs to signal each other or themselves. As a result, these signals have no default action — they are designed to be used with custom signal handlers defined by the programmer.

Here is an example of how to use SIGUSR1 and SIGUSR2 in a C program. This program defines signal handlers for both signals and prints a message when each signal is received.

```c
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>

// Signal handler for SIGUSR1
void handle_usr1(int sig) {
    printf("Received SIGUSR1\n");
}

// Signal handler for SIGUSR2
void handle_usr2(int sig) {
    printf("Received SIGUSR2\n");
}

int main() {
    // Set up the signal handler for SIGUSR1
    if (signal(SIGUSR1, handle_usr1) == SIG_ERR) {
        perror("Error setting signal handler for SIGUSR1");
        return 1;
    }

    // Set up the signal handler for SIGUSR2
    if (signal(SIGUSR2, handle_usr2) == SIG_ERR) {
        perror("Error setting signal handler for SIGUSR2");
        return 1;
    }

    // Print the process ID (PID) so that the user can send signals to this process
    printf("Process ID: %d\n", getpid());
    printf("Send SIGUSR1 or SIGUSR2 to this process (use kill -10 <pid> or kill -12 <pid>)\n");

    // Infinite loop to keep the program running and waiting for signals
    while (1) {
        sleep(1);
    }

    return 0;
}
```

Unlike signals like `SIGINT` (Ctrl+C), `SIGUSR1` and `SIGUSR2` have no default behavior. The program needs to define a handler to take any action when these signals are received.

**Use Cases for SIGUSR1 and SIGUSR2:**
- Inter-process Communication (IPC)
- Debugging and Monitoring
- Custom Actions


