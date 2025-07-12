---
title: "PIPES and FIFO - IPC"
categories: [Linux, Programming]
tags: [linux, sys-programming]
---

## **1. Pipes**

Pipes are one of the oldest and simplest IPC mechanisms in Unix-like systems. They provide a unidirectional (one-way) communication channel between two related processes (usually a parent and child).

### **Types of Pipes**

1. **Anonymous Pipes (`|` in shell)**
    
    - Created using the `pipe()` system call.
    - Data flows in one direction (read end and write end).    
    - Limited to communication between parent and child processes.

*Example*

```c
#include <unistd.h>
#include <stdio.h>

int main() {
    int fd[2];
    pipe(fd); // Creates a pipe

    if (fork() == 0) { // Child process
        close(fd[0]); // Close read end
        write(fd[1], "Hello, parent!", 15);
        close(fd[1]);
    } else { // Parent process
        close(fd[1]); // Close write end
        char buf[20];
        read(fd[0], buf, sizeof(buf));
        printf("Received: %s\n", buf);
        close(fd[0]);
    }
    return 0;
}
```


The `pipe()` system call creates a **unidirectional inter-process communication (IPC) channel** between two related processes (typically a parent and child). It provides two file descriptors:

- `fd[0]` → Read end (for receiving data).
- `fd[1]` → Write end (for sending data).

**Syntax**

```c
#include <unistd.h>
int pipe(int fd[2]);
```

- Returns `0` on success, `-1` on error.

#### How It Works

1. Data written to `fd[1]` can be read from `fd[0]`.
2. If a process tries to read from an empty pipe, it **blocks** until data is available.
3. If all write ends are closed, `read()` returns `0` (EOF).


#### SIGPIPE 

 The `SIGPIPE` signal is sent to a process by the operating system when it attempts to **write to a pipe or socket that has no readers**. This typically happens when the reading end of a pipe is closed, but the writing process continues to send data.
 
2. **Named Pipes (FIFO)**
   
- Created using `mkfifo()` and exist as a filesystem entry.
- Allows unrelated processes to communicate.

*Example*

```bash
mkfifo mypipe
# Process 1 writes to the pipe:
echo "Hello" > mypipe
# Process 2 reads from the pipe:
cat < mypipe
```

Here is an example program (**sender**) writes data to the FIFO, and the other (**receiver**) reads it.

*receiver*

This program creates a FIFO (if it doesn't exist) and waits for data from the sender.

```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>

#define FIFO_NAME "myfifo"

int main() {
    int fd;
    char buf[100];

    // Create FIFO (named pipe) if it doesn't exist
    mkfifo(FIFO_NAME, 0666);  // 0666 = Read/Write permissions

    printf("Waiting for sender...\n");
    fd = open(FIFO_NAME, O_RDONLY);  // Open FIFO in read-only mode
    read(fd, buf, sizeof(buf));      // Read data from FIFO
    printf("Received: %s\n", buf);

    close(fd);
    unlink(FIFO_NAME);  // Remove FIFO when done
    return 0;
}
```

*sender*

This program writes a message to the FIFO created by the receiver.

```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>

#define FIFO_NAME "myfifo"

int main() {
    int fd;
    char buf[] = "Hello from sender!";

    // Open FIFO (wait if receiver hasn't created it yet)
    fd = open(FIFO_NAME, O_WRONLY);  // Open FIFO in write-only mode
    write(fd, buf, sizeof(buf));     // Write data to FIFO
    printf("Message sent.\n");

    close(fd);
    return 0;
}
```
