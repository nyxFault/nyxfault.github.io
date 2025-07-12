---
title: "Advanced I/O"
categories: [Linux, Programming]
tags: [linux, sys-programming]
---

While basic I/O functions like read(), write(), and open() are sufficient for many tasks, high-performance or specialized applications often require advanced I/O techniques.

In this article, we’ll dive into key advanced I/O mechanisms provided by Linux:

- **Scatter/Gather I/O**
- **epoll (Advanced Multiplexing)**
- **Memory-Mapped I/O (mmap)**
- **File Advice (fadvise)**
- **Asynchronous I/O (AIO)**

## 1. Scatter/Gather I/O (readv() / writev())

Scatter/gather I/O allows performing a single I/O operation on multiple memory buffers at once.

- Scatter: Reads data from a file descriptor into multiple buffers.
- Gather: Writes data from multiple buffers into a file descriptor.

Imagine you have a complex structure split into multiple fields (e.g., header, payload, footer). Instead of copying them into a single buffer before writing to disk, you can use `writev()` to write them all in one system call.

**System Calls**

```c
#include <sys/uio.h>

ssize_t readv(int fd, const struct iovec *iov, int iovcnt);
ssize_t writev(int fd, const struct iovec *iov, int iovcnt);
```

The `iovec` structure is defined as:

```c
struct iovec {
    void *iov_base;  /* Starting address */
    size_t iov_len;  /* Number of bytes to transfer */
};
```

*Example: Writing multiple buffers*

```c
#include <sys/uio.h>
#include <fcntl.h>
#include <string.h>
#include <stdio.h>

int main() {
    int fd = open("output.txt", O_WRONLY | O_CREAT, 0644);
    if (fd == -1) {
        perror("open");
        return 1;
    }

    char header[] = "HEADER: ";
    char data1[] = "Data part 1";
    char data2[] = "Data part 2";
    char footer[] = "\nFOOTER\n";

    struct iovec iov[4];
    iov[0].iov_base = header;
    iov[0].iov_len = strlen(header);
    iov[1].iov_base = data1;
    iov[1].iov_len = strlen(data1);
    iov[2].iov_base = data2;
    iov[2].iov_len = strlen(data2);
    iov[3].iov_base = footer;
    iov[3].iov_len = strlen(footer);

    ssize_t nwritten = writev(fd, iov, 4);
    if (nwritten == -1) {
        perror("writev");
        return 1;
    }

    printf("Wrote %zd bytes\n", nwritten);
    close(fd);
    return 0;
}

```

## 2. Epoll — High-performance I/O Multiplexing

Evolution of I/O Multiplexing

- `select()`: The original POSIX solution (1983)
- `poll()`: Improved version of select (1997)
- `epoll()`: Linux's scalable event notification (2002)
- `io_uring`: The newest high-performance interface (2019)


`epoll` is a scalable I/O event notification mechanism in Linux, designed to efficiently monitor multiple file descriptors for read/write readiness. It overcomes the limitations of `select()` and `poll()` by using a **kernel-managed event queue**, making it ideal for high-performance servers handling thousands of connections.

Applications that need to handle **thousands of sockets** (e.g., web servers) need efficient ways to detect ready I/O without high CPU usage.

`epoll` uses three main system calls:

### **(1) `epoll_create1()` – Create an epoll Instance**

```c
#include <sys/epoll.h>

int epoll_create1(int flags);
```

- **Parameters**:
    
    - `flags`: Typically `0` or `EPOLL_CLOEXEC` (close-on-exec).
        
- **Returns**:
    
    - A file descriptor (`epfd`) referring to the new epoll instance.
    - `-1` on error (`errno` set).


*Example*

```c
int epfd = epoll_create1(0);
if (epfd == -1) {
    perror("epoll_create1");
    exit(EXIT_FAILURE);
}
```


### **(2) `epoll_ctl()` – Add/Modify/Remove FDs to Monitor**

```c
int epoll_ctl(int epfd, int op, int fd, struct epoll_event *event);
```

- **Parameters**:
    
    - `epfd`: The epoll instance (`epoll_create1` return value).
        
    - `op`: Operation type:
        
        - `EPOLL_CTL_ADD` – Add a new FD to monitor.
        - `EPOLL_CTL_MOD` – Modify an existing FD.
        - `EPOLL_CTL_DEL` – Remove an FD.
            
    - `fd`: The file descriptor to monitor.
        
    - `event`: Pointer to `struct epoll_event` (see below).

**`struct epoll_event`**:

```c
struct epoll_event {
    uint32_t     events;  // Epoll events (EPOLLIN, EPOLLOUT, etc.)
    epoll_data_t data;    // User data (often stores fd or pointer)
};

typedef union epoll_data {
    void    *ptr;
    int      fd;
    uint32_t u32;
    uint64_t u64;
} epoll_data_t;
```

*Example (Adding a Socket for Read Events):*

```c
struct epoll_event ev;
ev.events = EPOLLIN;  // Monitor for read readiness
ev.data.fd = sockfd;  // Store socket FD in event data

if (epoll_ctl(epfd, EPOLL_CTL_ADD, sockfd, &ev) == -1) {
    perror("epoll_ctl");
    exit(EXIT_FAILURE);
}
```


### **(3) `epoll_wait()` – Wait for Events**

```c
int epoll_wait(int epfd, struct epoll_event *events,
               int maxevents, int timeout);
```

- **Parameters**:
    
    - `epfd`: The epoll instance.
        
    - `events`: Array where events will be stored.
        
    - `maxevents`: Maximum number of events to return (size of `events` array).
        
    - `timeout`: Max wait time in milliseconds (`-1` = block indefinitely, `0` = return immediately).
        
- **Returns**:
    
    - Number of ready FDs (`>0`), `0` on timeout, `-1` on error.


*Example (Event Loop):*

```c
#define MAX_EVENTS 10

struct epoll_event events[MAX_EVENTS];
int nfds = epoll_wait(epfd, events, MAX_EVENTS, -1);

if (nfds == -1) {
    perror("epoll_wait");
    exit(EXIT_FAILURE);
}

for (int i = 0; i < nfds; i++) {
    if (events[i].events & EPOLLIN) {
        int fd = events[i].data.fd;
        handle_read(fd);  // Process incoming data
    }
}
```

*Example: TCP Echo Server Using epoll*

```c
#include <sys/epoll.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#define MAX_EVENTS 10
#define PORT 8080

void set_nonblocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

int main() {
    int listen_sock = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port = htons(PORT),
        .sin_addr.s_addr = INADDR_ANY
    };

    bind(listen_sock, (struct sockaddr*)&addr, sizeof(addr));
    listen(listen_sock, SOMAXCONN);

    int epfd = epoll_create1(0);
    struct epoll_event ev, events[MAX_EVENTS];
    ev.events = EPOLLIN;
    ev.data.fd = listen_sock;
    epoll_ctl(epfd, EPOLL_CTL_ADD, listen_sock, &ev);

    printf("Server running on port %d...\n", PORT);

    while (1) {
        int nfds = epoll_wait(epfd, events, MAX_EVENTS, -1);

        for (int i = 0; i < nfds; i++) {
            if (events[i].data.fd == listen_sock) {
                // New connection
                int conn_fd = accept(listen_sock, NULL, NULL);
                set_nonblocking(conn_fd);
                ev.events = EPOLLIN | EPOLLET;  // Edge-triggered
                ev.data.fd = conn_fd;
                epoll_ctl(epfd, EPOLL_CTL_ADD, conn_fd, &ev);
                printf("New client connected\n");
            } else {
                // Data from client
                char buf[1024];
                ssize_t n = read(events[i].data.fd, buf, sizeof(buf));

                if (n <= 0) {
                    if (n == 0 || errno == EAGAIN) {
                        close(events[i].data.fd);
                        printf("Client disconnected\n");
                    } else {
                        perror("read");
                    }
                } else {
                    write(events[i].data.fd, buf, n);  // Echo back
                }
            }
        }
    }

    close(epfd);
    close(listen_sock);
    return 0;
}
```

The main difference between `poll()`, `selet()` and `epoll()` I see -

**Notification Mechanism**:
    
- `select`/`poll`: Scan all FDs to find ready ones
- `epoll`: Only returns FDs that are actually ready


## 3. Memory-Mapped I/O (`mmap`)

Memory-mapped I/O maps a file or device directly into a process’s address space, enabling file access through memory operations rather than `read()`/`write()` system calls.

**System Calls**

```c
#include <sys/mman.h>

void *mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset);
int munmap(void *addr, size_t length);
```

*Example: File copy using mmap*

```c
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>

int main(int argc, char *argv[]) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <source> <destination>\n", argv[0]);
        return 1;
    }

    int src_fd = open(argv[1], O_RDONLY);
    if (src_fd == -1) {
        perror("open source");
        return 1;
    }

    struct stat sb;
    if (fstat(src_fd, &sb) == -1) {
        perror("fstat");
        return 1;
    }

    void *src = mmap(NULL, sb.st_size, PROT_READ, MAP_PRIVATE, src_fd, 0);
    if (src == MAP_FAILED) {
        perror("mmap source");
        return 1;
    }

    int dst_fd = open(argv[2], O_RDWR | O_CREAT | O_TRUNC, 0666);
    if (dst_fd == -1) {
        perror("open destination");
        return 1;
    }

    if (ftruncate(dst_fd, sb.st_size) == -1) {
        perror("ftruncate");
        return 1;
    }

    void *dst = mmap(NULL, sb.st_size, PROT_READ | PROT_WRITE, MAP_SHARED, dst_fd, 0);
    if (dst == MAP_FAILED) {
        perror("mmap destination");
        return 1;
    }

    memcpy(dst, src, sb.st_size);

    munmap(src, sb.st_size);
    munmap(dst, sb.st_size);
    close(src_fd);
    close(dst_fd);

    return 0;
}

```


## 4. File Advice (`posix_fadvise()`)

`posix_fadvise()` is a system call that allows programs to provide **hints** to the kernel about their intended access patterns for a file. This enables the kernel to optimize caching, read-ahead, and other I/O behaviors for better performance.

**Common Hints:**

- `POSIX_FADV_SEQUENTIAL` - Expect sequential access.
- `POSIX_FADV_RANDOM` - Random access, minimize readahead.
- `POSIX_FADV_WILLNEED` - Load into cache soon.
- `POSIX_FADV_DONTNEED` -	Drop cached data (free up memory).

**System Calls**

```c
#include <fcntl.h>

int posix_fadvise(int fd, off_t offset, off_t len, int advice);
```

| Parameter | Description                      |
|-----------|--------------------------------|
| fd        | File descriptor of the open file|
| offset    | Starting offset in the file      |
| len       | Length of the region (0 = until EOF) |
| advice    | Hint about the expected access pattern |


*Example: Optimizing a File Copy*

```c
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>

#define BUF_SIZE 4096

int main() {
    int src_fd = open("source.txt", O_RDONLY);
    int dst_fd = open("dest.txt", O_WRONLY | O_CREAT, 0644);

    // Advise sequential access for better read-ahead
    posix_fadvise(src_fd, 0, 0, POSIX_FADV_SEQUENTIAL);

    char buf[BUF_SIZE];
    ssize_t n;

    while ((n = read(src_fd, buf, BUF_SIZE)) > 0) {
        write(dst_fd, buf, n);
    }

    // Free cached data after copy
    posix_fadvise(src_fd, 0, 0, POSIX_FADV_DONTNEED);
    posix_fadvise(dst_fd, 0, 0, POSIX_FADV_DONTNEED);

    close(src_fd);
    close(dst_fd);
    return 0;
}

```

`POSIX_FADV_DONTNEED` is a particularly interesting file advice hint. It tells the kernel to discard cached pages associated with a file, making it useful for fine-tuning memory usage. Interestingly, this hint also played a role in the infamous **Dirty COW** exploit, where it was used to manipulate the page cache. I’ll be covering this exploit in detail in an upcoming blog post.

## 5. Asynchronous I/O (AIO)


Asynchronous I/O lets a program **initiate I/O operations** without blocking the calling thread, then get notified upon completion.

This contrasts with typical `read()` or `write()` calls that block until finished.

Before diving deeper, you might be wondering:  
**What exactly is the difference between synchronous (blocking) and asynchronous (non-blocking) I/O?**


### **Blocking I/O (Synchronous I/O)**

In **blocking I/O**, when your program makes an I/O request—like reading from a file or network—it **pauses** and waits for the operation to complete.

The thread is _blocked_ (paused) and can’t do anything else during that time.

#### Real-World Analogy:

Ordering coffee at a cafe:

- You place your order (I/O request).
- You stand at the counter and wait (your thread is blocked).
- You can’t do anything else until your coffee is ready.
- Only after you get your coffee can you continue with your day.    

That’s blocking I/O: the program stops until the I/O finishes.

### **Non-Blocking I/O (Asynchronous I/O)**

In **non-blocking I/O**, your program makes an I/O request but **does not wait**. It immediately continues executing other tasks.

You can later check whether the I/O has completed or get notified automatically when it’s done.

#### Real-World Analogy:

The same coffee order—but this time, the cafe gives you a buzzer:

- You place your order (I/O request).
- You get a buzzer and can sit down, check your phone, or work (your thread stays free).
- When your coffee is ready, the buzzer alerts you (notification/callback).
- You can keep doing other things while you wait.

That’s asynchronous I/O: the program stays responsive, handling other tasks while waiting for I/O to finish.


Polling is like checking your buzzer every few seconds instead of waiting for it to buzz.

In programming terms:

- **Polling** means periodically checking if I/O is ready.
- System calls like `select()`, `poll()`, and `epoll` implement this mechanism.
- They act like the cafe’s notification system, telling your program when I/O is ready.

#### POSIX Asynchronous I/O (AIO) System Calls

|System Call|Description|
|---|---|
|`aio_read()`|Initiates an asynchronous read operation.|
|`aio_write()`|Initiates an asynchronous write operation.|
|`aio_error()`|Checks whether a given AIO request has completed.|
|`aio_return()`|Retrieves the result of a completed AIO operation.|
|`aio_suspend()`|Suspends the calling thread until one or more AIO requests complete (optional timeout).|
|`lio_listio()`|Submits multiple AIO requests at once (batch I/O).|

Historically, Linux's POSIX AIO only supports **regular files**. This is it limitation.

#### io_uring (Modern Asynchronous I/O System Calls)

Introduced in **Linux 5.1**, `io_uring` is a powerful, modern asynchronous I/O framework designed for high performance and versatility.

I will explore this topic in greater detail in a future post.


*POSIX AIO Example: Asynchronous File Read in C*

```c
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <aio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>

int main() {
    const char *filename = "testfile.txt";
    int fd = open(filename, O_RDONLY);
    if (fd == -1) {
        perror("open");
        return EXIT_FAILURE;
    }

    char buffer[100] = {0};  // Buffer to hold file data

    struct aiocb cb;  // AIO control block
    memset(&cb, 0, sizeof(struct aiocb));
    cb.aio_fildes = fd;
    cb.aio_buf = buffer;
    cb.aio_nbytes = sizeof(buffer) - 1;
    cb.aio_offset = 0;  // Start at beginning of file

    // Start asynchronous read
    if (aio_read(&cb) == -1) {
        perror("aio_read");
        close(fd);
        return EXIT_FAILURE;
    }

    // Wait for I/O to complete
    while (aio_error(&cb) == EINPROGRESS) {
        printf("Reading in background...\n");
        sleep(1);  // Simulate doing other work
    }

    // Check final status
    int err = aio_error(&cb);
    ssize_t ret = aio_return(&cb);
    if (err != 0) {
        fprintf(stderr, "AIO error: %s\n", strerror(err));
    } else {
        printf("Read %zd bytes:\n%s\n", ret, buffer);
    }

    close(fd);
    return 0;
}

```


## Duplicating File Descriptor `dup()`

Whenever we open a file, socket, or even create a pipe, the kernel returns a file descriptor—an integer that uniquely identifies that resource in a process.

But sometimes, we need **duplicate** file descriptors—for example, to redirect output or manipulate files in advanced ways. That’s where the **`dup()`** and **`dup2()`** system calls come in.


The `dup()` system call duplicates an existing file descriptor. It creates a copy of the specified file descriptor, returning the **lowest-numbered unused descriptor**.

```c
#include <unistd.h>

int dup(int oldfd); //  oldfd: The file descriptor to be duplicated.
```

- oldfd: The file descriptor you want to duplicate.
- Return Value: New file descriptor on success, or `-1` on error (with `errno` set appropriately). On failure, it returns `-1`, and `errno` is set to indicate the error.

*NOTE*

Both descriptors (original and duplicate) share the same open file description. Operations like `read()`, `write()`, `lseek()` on one affect the other. They share file offset and file status flags (e.g., `O_APPEND`). However, file descriptor flags like `FD_CLOEXEC` are maintained per descriptor.

What if we close the `STDOUT_FILENO` a macro defined in `unistd.h` which represents the file descriptor associated with standard output, which is where data written by the `printf()` function and similar output functions is sent by default.
As we have closed the stdout file descriptor we will not be able to see any output on the screen.

```c
#include <unistd.h>
#include <stdio.h>
int main(){
	printf("Closing fd=%d\n", STDOUT_FILENO);
	close(STDOUT_FILENO); //STDOUT_FILENO = 1 so close(1) will also work!
	printf("Hello World\n");
}

```
On running -

```bash
$ ./demo 
Closing fd=1
```
As you can see we are not able to see the string.

Here’s a simple example demonstrating how `dup()` can redirect `stdout` to a file.

```c
#include <unistd.h>
#include <stdio.h>
#include <string.h>
int main() {
    pid_t pid = getpid();
    printf("My PID is: %d\n", pid);
    printf("Duplicating fd=%d\n", STDOUT_FILENO);
    int fd2 = dup(STDOUT_FILENO); // same as dup(1)
    printf("Closing fd=1\n");
    close(STDOUT_FILENO); //STDOUT_FILENO = 1 so close(1) will also work!
    getchar();
    char msg[]="Hello World\n";
    write(fd2,msg,strlen(msg));
}

```

```bash
$ ./dup 
My PID is: 245078
Duplicating fd=1
Closing fd=1
```

We can see in other terminal the `fd` in this process -

```bash
$ ls -la /proc/245078/fd
total 0
dr-x------ 2 fury fury  3 Jul 10 14:22 .
dr-xr-xr-x 9 fury fury  0 Jul 10 14:22 ..
lrwx------ 1 fury fury 64 Jul 10 14:22 0 -> /dev/pts/10
lrwx------ 1 fury fury 64 Jul 10 14:22 2 -> /dev/pts/10
lrwx------ 1 fury fury 64 Jul 10 14:22 3 -> /dev/pts/10

```

We can hit any key and the program continues and display the string.

```bash
Closing fd=1

Hello World
```

**`dup2()` system call**

`dup2()` is a function in C used for duplicating file descriptors. It allows you to copy one file descriptor to another, optionally closing the target file descriptor first if it's already in use. This can be very useful for redirecting input and output of programs, creating backups of file descriptors, and more.

```c
#include <unistd.h>
int dup2(int oldfd, int newfd);
```

On failure, it returns -1, and errno is set to indicate the error.

*Example*

```c
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>

int main() {
    int fd = open("output.txt", O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd == -1) {
        perror("open");
        return 1;
    }

    // Duplicate fd to STDOUT_FILENO (1)
    if (dup2(fd, STDOUT_FILENO) == -1) {
        perror("dup2");
        return 1;
    }

    // Now printf() will write to output.txt
    printf("This will go to output.txt\n");

    // Close the file descriptor
    close(fd);

    return 0;
}

```

We duplicated our `STDOUT` i.e 1 as `fd` which we get from opening the file so if we try to print on screen it will be redirected to the file pointed by fd.

