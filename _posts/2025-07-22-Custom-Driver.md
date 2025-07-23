---
title: "Building and Testing Custom Kernel Drivers: A Guide to In-Tree and Out-of-Tree Modules"
categories: [Linux, Internals]
tags: [linux, kernel, lkm, ldd, driver, qemu]
---


In our previous blogs, we explored the fundamentals of Linux kernel modules and even developed a basic kernel module along with a simple character device driver. This post is a follow-up to my previous [article](https://nyxfault.github.io/posts/Kernel-Crafting/), **“Kernel Crafting: Building, Running, and Debugging Your Custom Linux Kernel with Busybox and QEMU,”** where we built a minimal Linux kernel environment with Busybox. Here, we’ll extend that by adding and testing our own kernel driver using both methods.

**Quick revision** -

A kernel module is simply a piece of code that can be loaded into (and unloaded from) the kernel at runtime without recompiling the entire kernel. There are two types of Linux Kernel Modules -

- **In-Tree Modules** – integrating your driver directly into the Linux kernel source tree.
- **Out-of-Tree Modules** – building your driver as a separate module without touching the kernel source.


Let’s create a simple character device driver:

```c
/*
 hello_driver.c
*/
#include <linux/module.h>
#include <linux/kernel.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("nyxFault");
MODULE_DESCRIPTION("A simple Hello World LKM");

static int __init hello_init(void) {
    printk(KERN_INFO "Hello, World!\n");
    return 0;
}

static void __exit hello_exit(void) {
    printk(KERN_INFO "Goodbye, World!\n");
}

module_init(hello_init);
module_exit(hello_exit);
```


## Adding an In-Tree Driver

Inside the kernel source, there are directories like `drivers/`, `fs/`, and `net/`. We can place our driver in `drivers/misc/hello/`.

**Create Directory & Kbuild**

**NOTE**

We will be using the same kernel that we built in the previous [blog](https://nyxfault.github.io/posts/Kernel-Crafting/).


```bash
#cd linux-x.y.z/drivers/misc/
cd /home/fury/Desktop/Blog/Kernel_Lab/linux-5.11.4/drivers/misc
mkdir hello
cd hello
# Add the driver source file
nano hello_driver.c 
```

**Add Kconfig**

Create a `Kconfig` in the same directory i.e. `linux-5.11.4/drivers/misc/hello`:

```txt
config HELLO_DRIVER
    tristate "Hello World Driver"
    default m
    help
      A simple Hello World kernel driver for testing.

```

Add the following line to `drivers/misc/Kconfig`:


*In my case* 

```bash
#...
source "drivers/misc/uacce/Kconfig"
source "drivers/misc/hello/Kconfig"
endmenu
```

**Add Makefile**

Create a `Makefile` inside `hello/`:

```makefile
obj-$(CONFIG_HELLO_DRIVER) += hello_driver.o
```

Append in `drivers/misc/Makefile`:

*In my case*

```makefile
obj-$(CONFIG_HISI_HIKEY_USB)    += hisi_hikey_usb.o
obj-$(CONFIG_HELLO_DRIVER)      += hello/

```

**Build the Kernel**

Enable our "Hello" Driver and Rebuild the kernel:

```bash
make menuconfig
# Enable the driver: Device Drivers -> Misc Devices -> Hello World Driver
# You will see <M>. Change it to <*> by pressing `y`
make -j$(nproc)

# In case you want to install modules in your system
# make modules_install
```
Here’s what the symbols mean in `menuconfig`:

- **`< >`** — Feature/driver is disabled.
- **`<M>`** — Feature/driver will be compiled as a **module** (e.g., `hello_driver.ko`).
- **`<*>`** — Feature/driver will be **built into the kernel image** (statically linked).


```bash
$ make -j`nproc`
  SYNC    include/config/auto.conf.cmd
  DESCEND  objtool
  CALL    scripts/atomic/check-atomics.sh
  CALL    scripts/checksyscalls.sh
  CHK     include/generated/compile.h
  CC      drivers/misc/hello/hello_driver.o # <---- our driver
  AR      drivers/misc/hello/built-in.a
#...
  BUILD   arch/x86/boot/bzImage
Kernel: arch/x86/boot/bzImage is ready  (#2)

```
Finally the driver is part of the kernel build.

Check the compiled object in your driver folder:

```bash
$ ls drivers/misc/hello/
built-in.a  hello_driver.c  hello_driver.o  Kconfig  Makefile  modules.order
```
You might see `hello_driver.o` and `.mod.o` (temporary build files), but **no `.ko`** will exist because of `<*>`.

When you run the kernel with initramfs.

```bash
qemu-system-x86_64 -kernel ./linux-5.11.4/arch/x86/boot/bzImage -initrd ./busybox-1.36.1/initramfs.cpio.gz -append "root=/dev/ram rw console=ttyS0 quiet" -nographic
```

After few seconds you will see -

```bash
[+] Welcome to Minimal BusyBox Rootfs
H4ppy K3rnel H4cking!
~ # 

```

Now, as our module is automatically loaded into the kernel we can check the kernel logs

```bash
# dmesg | grep -i Hello
[    0.927940] Hello, World!
```

When you compile the driver with `<*>` (built-in), **there is no separate `.ko` file** on your filesystem. The code of `hello_driver` is **compiled directly into the kernel binary** (`bzImage`) and becomes part of the monolithic kernel.

You can see the kernel symbols (`/proc/kallsyms`)

```bash
$ cat /proc/kallsyms  | grep hello_
ffffffff9a973542 t hello_init
ffffffff9aa29e84 d __initcall_hello_init6
ffffffff9aa32550 t hello_exit
```

## Adding an Out-of-Tree Driver

An **out-of-tree driver** is a kernel module that is developed and built **outside the kernel source tree**. This is the preferred approach during development, as it allows you to compile and test your driver without recompiling the entire kernel.

The general workflow is straightforward:

1. Compile the kernel module (`.ko`) using the kernel headers or source tree.
2. Transfer the `.ko` file to the target system.
3. Load it dynamically using `insmod` or `modprobe`, and remove it using `rmmod`.


Let’s use the same `hello_driver.c` we wrote earlier. In a separate directory (outside the kernel source tree), create a `Makefile`:

```makefile
obj-m += hello_driver.o

#KDIR := /path/to/linux-source
KDIR := /home/fury/Desktop/Blog/Kernel_Lab/linux-5.11.4
PWD  := $(shell pwd)

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
```

**Build the Module**

```bash
make
```

This will produce a `hello_driver.ko` file.

Copy `hello_driver.ko` into your QEMU root filesystem (initramfs).

```bash
$ cp hello_driver.ko ../busybox-1.36.1/_install/
$ ../busybox-1.36.1/_install/
$ find . -print0 | cpio --null -ov --format=newc | gzip -9 > ../initramfs.cpio.gz

```

**Boot QEMU:**

```bash
qemu-system-x86_64 -kernel ./linux-5.11.4/arch/x86/boot/bzImage -initrd ./busybox-1.36.1/initramfs.cpio.gz -append "root=/dev/ram rw console=ttyS0 quiet" -nographic
```

**Inside QEMU:**

```bash
# ls
bin              init             root             usr
dev              linuxrc          sbin
hello_driver.ko  proc             sys
```
**Inserting Module**

```bash
# insmod hello_driver.ko
# lsmod
hello_driver 16384 0 - Live 0xffffffffc016c000 (O)
# 
```

Check Kernel Logs -

```bash
# dmesg 
#...
[  181.060398] hello_driver: loading out-of-tree module taints kernel.
[  181.067936] Hello, World!
```


In this post, we explored two different approaches to adding custom drivers to the Linux kernel — **in-tree** and **out-of-tree**.

- With **in-tree drivers**, your code becomes part of the kernel source and is built directly into the kernel image (`<*>`) or as a module (`<M>`).
- With **out-of-tree modules**, you can build your driver independently and dynamically load or remove it using `insmod`, `modprobe`, and `rmmod` without recompiling the kernel.


#### What’s Next?

The next step in our kernel exploration will be understanding **Syscalls** and **adding custom system calls** to the Linux kernel. This will allow us to expose new functionality directly to user-space programs