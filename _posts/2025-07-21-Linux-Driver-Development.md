---
title: "Linux Driver Development"
categories: [Linux, Internals]
tags: [linux, lkm, kernel, driver]
---

### Introduction

In the previous [blog](http://nyxfault.github.io/posts/Linux-Kernel-Programming/), we explored the basics of Linux kernel module development. We also examined the fundamental differences between a Linux kernel module and a device driver, as well as the various types of drivers available in Linux.

In this article, we’ll build on that foundation and dive into Linux driver development, with a particular focus on creating a basic character device driver. Character drivers are one of the simplest and most common types of Linux drivers, making them an excellent starting point for understanding how drivers interact with user space and the kernel.

Before diving into code, let’s revisit what exactly a Linux driver is and look at the different types of drivers.


### What is a Linux Driver?

A **Linux device driver** is a special type of kernel module that enables the operating system to communicate with hardware devices. It acts as a **bridge between hardware and the kernel**, translating generic OS calls (like read, write) into device-specific operations.

While all drivers are kernel modules, **not all kernel modules are drivers**. A kernel module can add any functionality to the kernel (e.g., a filesystem), whereas a driver’s main purpose is to manage hardware devices and expose them to user space.

### Types of Linux Device Drivers

1. **Character Drivers** – Transfer data as a stream of characters (byte by byte), e.g., serial ports, keyboards, and `/dev/null`.
    
2. **Block Drivers** – Handle data in fixed-size blocks, enabling random access, e.g., hard disks and SSDs.
    
3. **Network Drivers** – Manage network interfaces, handling packet transmission and reception.
    
4. **Other Drivers** –
    
    - **USB Drivers** – Handle USB devices like flash drives.
    - **PCI Drivers** – Manage devices connected via the PCI bus.
    - **Virtual Drivers** – Provide functionality without real hardware (e.g., loopback devices).

### Why Start with a Character Driver?

Character drivers are the simplest type of Linux drivers, making them ideal for beginners. They are:

- **Easy to implement and test** – No complex hardware setup is required.
    
- **Hardware-independent** – Can work with virtual devices, making development straightforward.
    
- **Great for learning** – Provide a clear way to understand essential file operations like `open()`, `read()`, `write()`, and `release()`.


**Install Kernel headers**

Ensure you have the necessary tools and libraries installed. You typically need the kernel headers and build tools.

```bash
$ sudo apt-get install build-essential linux-headers-$(uname -r)
```



## Anatomy of a Character Device Driver

A **character device driver** interacts with user space applications through file operations. It registers itself with the kernel and exposes a device file (usually in `/dev/`), which applications can use via standard system calls like `open()`, `read()`, `write()`, and `close()`.

The basic steps to implement a character driver include:

1. **Registering the device with the kernel.**
    
    - The driver must register itself with a unique major and minor number so that the kernel knows which driver handles which device file.
        
2. **Defining file operations.**
    
    - We implement callbacks like `open`, `read`, `write`, and `release` which are invoked when a user-space process interacts with the device file.
        
3. **Creating a device file in `/dev/`.**
    
    - This file acts as the interface between user space and the driver.
        
4. **Cleaning up during module removal.**
    
    - We must unregister the device and free any allocated resources.


### Major and Minor Numbers


Each device file is associated with a **major** number and a minor **number**.
- Major Number: Identifies the driver associated with the device.
- Minor Number: Identifies a specific device among several devices that the driver controls.

You can see the major and minor numbers using the `ls -l /dev` command.

```bash
$ ls -l /dev/null
crw-rw-rw- 1 root root 1, 3 Oct  1 12:34 /dev/null
```
Here, `1` is the **major** number, and `3` is the **minor** number.


## Understanding the Driver’s Anatomy

### 1. Registering the Driver

The `register_chrdev()` function is used to register our driver with the kernel:

```c
major_number = register_chrdev(0, DEVICE_NAME, &fops);
```

- Passing `0` tells the kernel to dynamically allocate a **major number**.
- `DEVICE_NAME` is the name that appears in `/proc/devices`.
- `&fops` points to the `file_operations` structure which defines how the driver handles `read`, `write`, `open`, and `release`.

When unloading the module, we clean up using:

```c
unregister_chrdev(major_number, DEVICE_NAME);
```


### File Operations in Character Drivers (`struct file_operations`)

The `file_operations` structure is the heart of a character device driver. It defines the operations that can be performed on the device. It's a table of function pointers, such as:

```c
static struct file_operations fops = {
    .owner = THIS_MODULE,
    .open = my_open,
    .release = my_release,
    .read = my_read,
    .write = my_write,
};
```

Here are some of the most commonly used members of the `file_operations` structure:

[Link](https://elixir.bootlin.com/linux/v5.11.22/source/include/linux/fs.h#L1820)


| Member            | Description                                                          |
| ----------------- | -------------------------------------------------------------------- |
| `.read`           | Called when a user-space program reads from the device.              |
| `.write`          | Called when a user-space program writes to the device.               |
| `.open`           | Called when the device is opened.                                    |
| `.release`        | Called when the device is closed.                                    |
| `.unlocked_ioctl` | Called for device-specific operations using the `ioctl` system call. |
| `.poll`           | Used to implement polling for I/O events.                            |
| `.mmap`           | Maps device memory into user-space.                                  |
| `.llseek`         | Implements seeking within the device file.                           |


Let's write a **simple character device driver** which can be loaded into the Linux kernel as a module, and provides **basic read and write operations** through a device file (e.g., `/dev/my_char_device`).

This driver will:

- Register itself with the kernel and obtain a **major number**.
- Create a buffer where data from the user can be stored.
- Implement `open`, `read`, `write`, and `release` file operations.
- Allow us to **read and write data from user space programs** using commands like `echo` and `cat`.


Before jumping into the code, let’s outline the minimal features our character driver will have:

1. **Driver Registration:**  
    It will register with the kernel using `register_chrdev()`.
    
2. **Device Buffer:**  
    We’ll use a simple static character array to store the data written by user space.
    
3. **File Operations:**
    
    - **`open()`** – Called when the device file is opened.
    - **`release()`** – Called when the device file is closed.
    - **`read()`** – Copies data from the driver buffer to user space.
    - **`write()`** – Copies data from user space into the driver buffer.
    
4. **Logging:**  
    Use `printk()` to log driver activity for debugging.


Here’s the complete source code of a **very basic character driver**:

```c
/*
my_char_device.c
*/
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/uaccess.h>

#define DEVICE_NAME "my_char_device"
#define BUFFER_SIZE 1024

static int major_number;
static char device_buffer[BUFFER_SIZE];
static int buffer_offset = 0;

// Function prototypes
static int device_open(struct inode *, struct file *);
static int device_release(struct inode *, struct file *);
static ssize_t device_read(struct file *, char *, size_t, loff_t *);
static ssize_t device_write(struct file *, const char *, size_t, loff_t *);

// File operations structure
static struct file_operations fops = {
    .read = device_read,
    .write = device_write,
    .open = device_open,
    .release = device_release,
};

// Open function
static int device_open(struct inode *inode, struct file *file) {
    printk(KERN_INFO "Device opened\n");
    return 0;
}

// Release function
static int device_release(struct inode *inode, struct file *file) {
    printk(KERN_INFO "Device closed\n");
    return 0;
}

// Read function
static ssize_t device_read(struct file *filp, char *buffer, size_t length, loff_t *offset) {
    if (*offset >= buffer_offset) {
        return 0; // EOF
    }
    if (*offset + length > buffer_offset) {
        length = buffer_offset - *offset;
    }
    if (copy_to_user(buffer, device_buffer + *offset, length)) {
        return -EFAULT;
    }
    *offset += length;
    return length;
}

// Write function
static ssize_t device_write(struct file *filp, const char *buffer, size_t length, loff_t *offset) {
    if (buffer_offset + length >= BUFFER_SIZE) {
        return -ENOMEM; // No space left
    }
    // buffer_offset = 0;  // Reset buffer for new data
    if (copy_from_user(device_buffer + buffer_offset, buffer, length)) {
        return -EFAULT;
    }
    // buffer_offset = length; // For resetting buffer 
    buffer_offset += length;
    return length;
}

// Module initialization
static int __init my_char_device_init(void) {
    // int register_chrdev(unsigned int major, const char *name, const struct file_operations *fops);
    major_number = register_chrdev(0, DEVICE_NAME, &fops);
    if (major_number < 0) {
        printk(KERN_ALERT "Failed to register a major number\n");
        return major_number;
    }
    printk(KERN_INFO "Registered character device with major number %d\n", major_number);
    return 0;
}

// Module exit
static void __exit my_char_device_exit(void) {
    unregister_chrdev(major_number, DEVICE_NAME);
    printk(KERN_INFO "Unregistered character device\n");
}

module_init(my_char_device_init);
module_exit(my_char_device_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("nyxFault");
MODULE_DESCRIPTION("A simple character device driver");

```

Once you save the code as `my_char_device.c`, follow these steps:

#### 1. Compile the Module

Create a simple `Makefile`:

```makefile
obj-m += my_char_device.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

```

Compile:

```bash
make
```

#### 2. Insert the Module

```bash
sudo insmod my_char_device.ko
```

Check kernel logs -

```bash
$ sudo dmesg -wH
[Jul21 07:02] Registered character device with major number 505

```
You’ll see a log message with the assigned major number.

#### 3. Create a Device File

```bash
# sudo mknod /dev/my_char_device c <major_number> 0
# In my case major_number = 505
sudo mknod /dev/my_char_device c 505 0
sudo chmod 666 /dev/my_char_device
```

#### 4. Test Read/Write

```bash
echo "Hello Driver" > /dev/my_char_device
cat /dev/my_char_device
```

#### 5. Remove the Module

```bash
sudo rmmod my_char_device
sudo rm /dev/my_char_device
```




## IOCTLs

So far, our driver lets user space **read** and **write** bytes like a simple buffer device. Real hardware drivers almost always need _extra_ control operations: reset the device, set a mode, query status, adjust configuration, fetch statistics, etc. Many of these operations don't map cleanly to the standard read/write byte stream model. That’s where **IOCTLs (I/O control requests)** come in. They provide a flexible, extensible, device-specific control channel that is invoked from user space with the `ioctl()` system call. 

### When to Use IOCTL (and When Not To)

Use an IOCTL when you need to send _structured commands_ or retrieve _device-specific information_ that doesn't fit naturally into the standard `read`/`write` model. Classic examples: setting baud rate, clearing a buffer, querying device registers, or triggering a firmware update.

### IOCTL Command Encoding (The `_IO*` Macros)


IOCTL commands are 32-bit numbers that encode four pieces of information:

| Field                 | Meaning                                                                                                    | Notes |
| --------------------- | ---------------------------------------------------------------------------------------------------------- | ----- |
| Direction             | Is data moving _into_ the kernel, _out_ to user space, both, or none? Encoded by which macro you use.      |       |
| Type (a.k.a. _magic_) | 8-bit “subsystem/driver” ID, often a character literal, chosen to be unique.                               |       |
| Command number        | 8-bit ordinal (sequence) ID within that magic.                                                             |       |
| Size                  | Size of the data structure exchanged (automatically encoded by the macros that take a data type argument). |       |

The kernel provides standard helper macros in `<linux/ioctl.h>` / `include/uapi/asm-generic/ioctl.h`:

- `_IO(type, nr)` – no data argument.
- `_IOR(type, nr, data_type)` – user expects data _read_ from kernel.
- `_IOW(type, nr, data_type)` – user _writes_ data into kernel.
- `_IOWR(type, nr, data_type)` – bidirectional.

“Read” and “write” are from the _user space_ point of view: a `GET_FOO` command that returns data to user space uses `_IOR`, even though the kernel is copying _to_ user space internally. Likewise, a `SET_FOO` command uses `_IOW`, even though the kernel copies _from_ user space.

**Gotcha:** Pass the **type name**, _not_ `sizeof(type)`, to `_IOR/_IOW/_IOWR`—the macros compute `sizeof(type)` themselves. Passing `sizeof(...)` causes you to encode the size of a size_t, which breaks things.


### Modern Kernel Hook: `.unlocked_ioctl`

Historically, `struct file_operations` had an `.ioctl` callback that took both `struct inode *` and `struct file *` and was protected by the Big Kernel Lock (BKL). The kernel moved away from the BKL years ago; new drivers should implement `.unlocked_ioctl(struct file *, unsigned int cmd, unsigned long arg)` instead. That’s the callback the VFS calls for` ioctl()` on your device.

**VFS (Virtual File System)** is an abstraction layer inside the Linux kernel that provides a **unified interface to all types of files and filesystems**, including devices.

When a user-space process calls functions like `open()`, `read()`, `write()`, or `ioctl()`, it doesn’t interact directly with the actual filesystem or device driver. Instead, it communicates with the **VFS**, which then delegates the request to the appropriate filesystem or device driver.

```txt
User Space
   |
   | open(), read(), write(), ioctl()
   v
+-------------------+
| VFS (Common Layer)|
+-------------------+
   |   Calls the driver
   v
Device Driver
   |
   v
Hardware (or virtual device)

```


To demonstrate how to pass _structured data_ between user space and the kernel, we’ll build a tiny “calculator” interface into our driver. User space fills in two numbers (`num1`, `num2`), calls an IOCTL such as **ADD**, and the driver returns the result in `num3`. This pattern—**copy a struct in, operate, copy the updated struct out**—is a common, simple way to use IOCTLs for device-specific operations that don’t map naturally onto read/write byte streams.

As user space both **passes data in** (the input operands) and **expects data back** (the result), the correct macro is `_IOWR`, which encodes a _bidirectional_ data transfer in the IOCTL command number.


Put the IOCTL definitions in a header that both the driver and user programs include. Keeping a single shared definition prevents ABI drift and type-size mismatches across architectures.

```c
/* my_char_calc_ioctl.h
 *
 * Shared header between kernel module and user programs.
 */
#ifndef MY_CHAR_CALC_IOCTL_H
#define MY_CHAR_CALC_IOCTL_H

#include <linux/ioctl.h>   /* for _IO*, Linux builds */
                           /* user space may map this via sys/ioctl.h */

#define MYCHAR_CALC_MAGIC 'k'  /* define magic number */

/* Structure passed in/out of IOCTLs. 
 * num1, num2: input operands
 * num3: kernel writes result here
 */
struct mychar_calc {
    int num1;
    int num2;
    int num3;
};

/* Bidirectional calculator commands */
#define MYCHAR_CALC_ADD _IOWR(MYCHAR_CALC_MAGIC, 0, struct mychar_calc)
#define MYCHAR_CALC_SUB _IOWR(MYCHAR_CALC_MAGIC, 1, struct mychar_calc)
#define MYCHAR_CALC_MUL _IOWR(MYCHAR_CALC_MAGIC, 2, struct mychar_calc)
#define MYCHAR_CALC_DIV _IOWR(MYCHAR_CALC_MAGIC, 3, struct mychar_calc)

#endif /* MY_CHAR_CALC_IOCTL_H */

```

**Magic Number**

```c
#define MYCHAR_CALC_MAGIC 'k'
```

is used to define a **"magic number" (or magic code)** for your device driver's IOCTL commands. This value uniquely identifies the set of IOCTL commands that belong to your driver.

**Reason for using Magic Number**

The Linux kernel uses **IOCTL command codes** to determine which operation should be performed when a user program calls `ioctl(fd, cmd, arg)`. These command codes are **32-bit integers**, built using macros like `_IO`, `_IOR`, `_IOW`, and `_IOWR`.

The magic number is an essential part of the command code. It prevents **collisions** between IOCTL commands of different drivers. Without it, if two drivers happened to define a command with the same number, the kernel wouldn't know which driver should handle it.

In production, you should avoid collisions by checking the **official list of assigned magic numbers**:

- Path: `Documentation/userspace-api/ioctl/ioctl-number.rst` in the Linux source tree.

##### How Magic Number is Used Internally

When you call `_IOWR(MYCHAR_CALC_MAGIC, 0, struct mychar_calc)`, it generates a unique integer code by combining:

- The **magic number** `'k'` (ASCII code 107).
- The **command number** (`0` in this case).
- The **data transfer direction** (read/write).
- The **size of the data type** (`sizeof(struct mychar_calc)`).


This way, each IOCTL command in Linux is unique and avoids accidental overlaps with commands from other drivers.

Below is an example of **very basic character driver** that adds an `.unlocked_ioctl` callback to implement the calculator commands.


```c
/*
my_char_device.c
*/
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include "my_char_calc_ioctl.h"

#define DEVICE_NAME "my_char_device"
#define BUFFER_SIZE 1024

static int major_number;
static char device_buffer[BUFFER_SIZE];
static int buffer_offset = 0;

// Prototypes
static int device_open(struct inode *, struct file *);
static int device_release(struct inode *, struct file *);
static ssize_t device_read(struct file *, char __user *, size_t, loff_t *);
static ssize_t device_write(struct file *, const char __user *, size_t, loff_t *);
static long device_ioctl(struct file *, unsigned int, unsigned long);

static struct file_operations fops = {
    .read           = device_read,
    .write          = device_write,
    .open           = device_open,
    .release        = device_release,
    .unlocked_ioctl = device_ioctl,
};

// Open
static int device_open(struct inode *inode, struct file *file)
{
    printk(KERN_INFO "%s: Device opened\n", DEVICE_NAME);
    return 0;
}

// Release
static int device_release(struct inode *inode, struct file *file)
{
    printk(KERN_INFO "%s: Device closed\n", DEVICE_NAME);
    return 0;
}

// Read
static ssize_t device_read(struct file *filp, char __user *buffer, size_t length, loff_t *offset)
{
    if (*offset >= buffer_offset)
        return 0; // EOF

    if (*offset + length > buffer_offset)
        length = buffer_offset - *offset;

    if (copy_to_user(buffer, device_buffer + *offset, length))
        return -EFAULT;

    *offset += length;
    return length;
}

// Write (overwrite old data)
static ssize_t device_write(struct file *filp, const char __user *buffer, size_t length, loff_t *offset)
{
    if (length >= BUFFER_SIZE)
        return -ENOMEM;

    buffer_offset = 0; // Clear old data
    if (copy_from_user(device_buffer, buffer, length))
        return -EFAULT;

    buffer_offset = length;
    return length;
}

// IOCTL - Calculator operations
static long device_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
    struct mychar_calc calc;

    if (copy_from_user(&calc, (void __user *)arg, sizeof(calc)))
        return -EFAULT;

    switch (cmd) {
    case MYCHAR_CALC_ADD:
        calc.num3 = calc.num1 + calc.num2;
        break;
    case MYCHAR_CALC_SUB:
        calc.num3 = calc.num1 - calc.num2;
        break;
    case MYCHAR_CALC_MUL:
        calc.num3 = calc.num1 * calc.num2;
        break;
    case MYCHAR_CALC_DIV:
        if (calc.num2 == 0)
            return -EINVAL;
        calc.num3 = calc.num1 / calc.num2;
        break;
    default:
        return -ENOTTY;
    }

    if (copy_to_user((void __user *)arg, &calc, sizeof(calc)))
        return -EFAULT;

    return 0;
}

// Module init
static int __init my_char_device_init(void)
{
    major_number = register_chrdev(0, DEVICE_NAME, &fops);
    if (major_number < 0) {
        printk(KERN_ALERT "%s: Failed to register major number\n", DEVICE_NAME);
        return major_number;
    }
    printk(KERN_INFO "%s: Registered with major number %d\n", DEVICE_NAME, major_number);
    return 0;
}

// Module exit
static void __exit my_char_device_exit(void)
{
    unregister_chrdev(major_number, DEVICE_NAME);
    printk(KERN_INFO "%s: Unregistered\n", DEVICE_NAME);
}

module_init(my_char_device_init);
module_exit(my_char_device_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("nyxFault");
MODULE_DESCRIPTION("A simple character device driver with calculator IOCTLs");

```

Compile the driver, insert the module and create device node. Give `RW` permissions to `/dev/my_char_device`.

Now, let’s write a user-space program that will communicate with our character device using the IOCTL commands we defined (ADD, SUB, MUL, DIV). This program will send two numbers to the driver and receive the result for each operation.

```c
/* userspace_calc.c */
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>

#include "my_char_calc_ioctl.h"   /* struct + IOCTL definitions */

/* Change these if you want different test numbers */
#define A 7
#define B 5

int main(void)
{
    int fd;
    struct mychar_calc calc;

    fd = open("/dev/my_char_device", O_RDWR);
    if (fd < 0) {
        perror("open");
        return 1;
    }

    /* ADD */
    calc.num1 = A; calc.num2 = B; calc.num3 = 0;
    if (ioctl(fd, MYCHAR_CALC_ADD, &calc) == -1) perror("ADD");
    else printf("%d + %d = %d\n", A, B, calc.num3);

    /* SUB */
    calc.num1 = A; calc.num2 = B; calc.num3 = 0;
    if (ioctl(fd, MYCHAR_CALC_SUB, &calc) == -1) perror("SUB");
    else printf("%d - %d = %d\n", A, B, calc.num3);

    /* MUL */
    calc.num1 = A; calc.num2 = B; calc.num3 = 0;
    if (ioctl(fd, MYCHAR_CALC_MUL, &calc) == -1) perror("MUL");
    else printf("%d * %d = %d\n", A, B, calc.num3);

    /* DIV */
    calc.num1 = A; calc.num2 = B; calc.num3 = 0;
    if (ioctl(fd, MYCHAR_CALC_DIV, &calc) == -1) perror("DIV");
    else printf("%d / %d = %d\n", A, B, calc.num3);

    close(fd);
    return 0;
}
```

```bash
$ gcc userspace_calc.c -o userspace_calc
$ ./userspace_calc 
7 + 5 = 12
7 - 5 = 2
7 * 5 = 35
7 / 5 = 1
```


In this article, we took our first real step into **Linux driver development** by building a simple **character device driver** and extending it with **IOCTL commands**. Linux driver development may seem daunting at first, but starting small (like with character devices) makes it much more approachable. Once you understand the concepts of **VFS**, **file operations**, and **IOCTLs**, you can easily build on these fundamentals.

