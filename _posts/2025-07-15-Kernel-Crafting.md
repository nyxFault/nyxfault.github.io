---
title: "Kernel Crafting: Building, Running, and Debugging Your Custom Linux Kernel with Busybox and QEMU"
categories: [Lab]
tags: [linux, kernel, debug, qemu]
---

In this step-by-step tutorial, we’ll walk through the entire process of building a Linux kernel, creating a minimal filesystem using Busybox, running it on QEMU, and debugging the kernel. Finally, we’ll wrap up by learning how to compile and add custom Linux kernel modules to enhance our kernel. I’m using a Linux system for this demonstration, specifically **Ubuntu 22.04.5 LTS x86_64** with kernel version **6.8.0-60-generic**. However, the steps should be similar for other Linux distributions. Let’s dive in!



Before we begin, ensure you have all the necessary tools and libraries installed on your system. This includes development tools, compilers, and libraries essential for building the kernel.

```bash
sudo apt update
sudo apt install build-essential libncurses5-dev bison flex libssl-dev libelf-dev qemu qemu-kvm 
```

## Downloading the Linux Kernel

First, let’s download the Linux kernel source code. We’ll choose version 5.11.4 for this example:


```bash
wget https://www.kernel.org/pub/linux/kernel/v5.x/linux-5.11.4.tar.xz
tar xvf linux-5.11.4.tar.xz
cd linux-5.11.4/
```

## Configuring and Compiling the Kernel

Next, we’ll configure the kernel. For simplicity, we’ll use the default configuration:

```bash
make defconfig
```

When configuring the Linux kernel, you might want to use the configuration file specific to your current Linux distribution. This can help ensure that the kernel configuration matches the settings and modules already in use on your system. To do this, you can copy one of the existing configuration files from `/boot/config-$(uname -r)` in the Linux kernel source root directory and name it `.config`.

Or else you can do -

```bash
make defconfig
```

The following command provides a text-based menu interface that allows us to configure various kernel options, including enabling or disabling features, selecting specific device drivers, and more.

```bash
make menuconfig
```

Before we compile the kernel, we need to enable some options for debug symbols, KASLR, and other useful features. 

**Kernel hacking ->**

- [x] **Kernel debugging**  
  `CONFIG_DEBUG_KERNEL`

- [x] **Compile the kernel with debug info**  
  `CONFIG_DEBUG_INFO`

- [x] **Generate DWARF version 4 debugging information**  
  `CONFIG_DEBUG_INFO_DWARF4`

- [x] **Enable GDB scripts** *(if available)*  
  `CONFIG_GDB_SCRIPTS`

- [x] **Debug slab memory allocations**  
  `CONFIG_SLUB_DEBUG` or `CONFIG_DEBUG_SLAB`

- [x] **Export All Kernel Symbols**  
  `CONFIG_KALLSYMS` or `CONFIG_KALLSYMS_ALL`


Check the `.config` file in a text editor and ensure these options are set:

```bash
CONFIG_DEBUG_KERNEL=y
CONFIG_DEBUG_INFO=y
CONFIG_GDB_SCRIPTS=y
CONFIG_SLUB_DEBUG_ON=y
CONFIG_KALLSYMS=y
CONFIG_KALLSYMS_ALL=y
```

Now, let’s compile the kernel. This process may take some time:

```bash
make -j$(nproc)
```

This will utilize all available CPU cores for faster compilation. On my system, it took roughly 3 minutes.

After a successful build, you should see the following output files:

- `arch/x86/boot/bzImage` → The compressed bootable kernel image.
- `vmlinux` → The uncompressed ELF image with full debug symbols. This is the file you’ll use with GDB.



### Creating a Minimal Filesystem with BusyBox

To boot a custom kernel with QEMU or use it for debugging, you'll often need a minimal root filesystem. The easiest way to build one is by using [BusyBox](https://busybox.net), a lightweight collection of Unix utilities in a single binary.


**Step 1: Download and Build BusyBox**

Start by downloading and building BusyBox:

```bash
wget https://busybox.net/downloads/busybox-1.36.1.tar.bz2
tar xvf busybox-1.36.1.tar.bz2
cd busybox-1.36.1/
make defconfig  # Use the default configuration
```

Now configure it for static linking (important for minimal rootfs without dynamic libraries):

```bash
make menuconfig
```

Set the following (Under Settings):

- `[*] Build BusyBox as a static binary (no shared libs)`
- You can leave everything else as default.

After selecting the `"Build static binary (no shared libs)"` option in the `make menuconfig` interface, exit the menu by selecting “Exit” or pressing ‘Esc’ repeatedly until prompted to save changes. Then, proceed to build the Busybox filesystem:

```bash
make -j$(nproc) # Ignore "Trying libraries: crypt m resolv" error
make install
```

This will install BusyBox into the `_install/` directory.

```bash
$ tree -d _install/
├── bin
├── sbin
└── usr
    ├── bin
    └── sbin
```

```bash
$ file busybox
busybox: ELF 64-bit LSB executable, x86-64, version 1 (GNU/Linux), statically linked, BuildID[sha1]=4a456612187a08793907e7565e1a41736f9adb43, for GNU/Linux 3.2.0, stripped
```

You now have a **statically linked BusyBox binary** — clean, minimal, and ready for use in your root filesystem (e.g. for QEMU, initramfs, or kernel debugging).


**Step 2: Add init Script**

BusyBox looks for `/init` or `/sbin/init` as the first process (PID 1). Create a basic init script:

```bash
cd _install
nano init
```

```bash
#!/bin/sh

# Create mount points 
mkdir -p /proc /sys /dev

mount -t devtmpfs none /dev
mount -t proc none /proc
mount -t sysfs none /sys

# clear the screen
clear

# Banner
echo " __________"
echo "< nyxFault >"
echo " ----------"
echo "        \   ^__^"
echo "         \  (oo)\_______"
echo "            (__)\       )\/\\"
echo "                ||----w |"
echo "                ||     ||"
echo ""

# Display boot time
echo -e "\nBoot took $(cut -d' ' -f1 /proc/uptime) seconds\n"

# Welcome message
echo -e "\n[+] Welcome to Minimal BusyBox Rootfs"
echo "H4ppy K3rnel H4cking!"

# Start the shell
setsid  cttyhack sh
exec /bin/sh
```

Make it executable:

```bash
chmod +x init
```

We’ve completed the setup for our custom Linux system using Busybox and a custom initialization script (init). Let’s summarize the steps we’ve taken:

- Busybox Compilation: We compiled Busybox, which provides a single executable capable of providing various Linux utilities such as `sh`, `echo`, `vi`, and more.
    
- Filesystem Creation: After compiling Busybox, we used make install to create a filesystem hierarchy (`_install` directory) containing these utilities as links to the Busybox executable. This filesystem structure resembles a basic Linux filesystem.
    
- Custom Initialization Script: We created a shell script named `init`. This script will be executed after the kernel loads during the boot process.
    
- Mounting Essential Directories: In the `init` script, we mounted essential special directories such as `/dev`, `/proc`, and `/sys`. These directories provide access to kernel information and system devices.


**Step 3: Create the initramfs**

To create the filesystem (initramfs) containing our custom Linux system, we’ll run the following commands inside the `_install` directory:

```bash
$ find . -print0 | cpio --null -ov --format=newc | gzip -9 > ../initramfs.cpio.gz
$ file ../initramfs.cpio.gz
initramfs.cpio.gz: gzip compressed data
```

**initramfs**

The initramfs (initial RAM filesystem) contains the files needed for the Linux kernel to mount the root filesystem and start the system. It’s used during the early stages of the boot process.

After running the command, the initramfs.cpio.gz file will be created in the parent directory. This file contains the entire filesystem structure that we created using Busybox and the init script.

We’re now ready to boot our custom Linux system using QEMU or another virtualization platform.

### Booting the Kernel with QEMU and Initramfs

Let’s proceed to boot our custom kernel with the minimal filesystem using QEMU:

```bash
$ qemu-system-x86_64 -kernel ../linux-5.11.4/arch/x86/boot/bzImage -initrd initramfs.cpio.gz -append "root=/dev/ram rw console=ttyS0 quiet" -nographic
```

```
-kernel: Path to your custom kernel image (bzImage).
-initrd: Path to the initramfs.cpio.gz file.
-append: Specifies kernel command-line parameters. Here, we specify:
    root=/dev/ram: Tells the kernel to use the RAM disk as the root filesystem.
    rw: Mount the root filesystem as read-write.
    console=ttyS0: Redirect kernel console output to the first serial port (ttyS0).
The -nographic option ensures that the output is displayed in the terminal.
```

If you don’t use the `-nographic` option, QEMU will open a graphical window to display the boot process of the kernel. We will use terminal to display as I have faced problems while debugging on QEMU Graphical Window.

### Debugging the Kernel with GDB

To enable debugging, we need to run QEMU with the `-s` option to enable debug mode. We’ll also add the `-S` option to freeze the CPU at startup:

```bash
$ qemu-system-x86_64 -kernel ../linux-5.11.4/arch/x86/boot/bzImage -initrd initramfs.cpio.gz -append "root=/dev/ram rw console=ttyS0 quiet nokaslr" -nographic -s -S
```

### GDB

In another terminal, start GDB:

```bash
gdb \
    -ex "add-auto-load-safe-path $(pwd)" \
    -ex "file vmlinux" \
    -ex 'target remote localhost:1234' \
    -ex 'continue' 
```

Now you can set breakpoints, inspect memory, and step through code in GDB.

To stop the execution press Ctrl+C in the gdb window.

If you don't see `vmlinux-gdb.py`. Make sure you have`CONFIG_GDB_SCRIPTS=y` in `.config`.

You can try `make scripts_gdb` command.

To add the `vmlinux-gdb.py` -

```bash
(gdb) source vmlinux-gdb.py
```

Type `lx-` and hit **TAB**. You will see following options -

```bash
(gdb) lx-
lx-clk-summary
lx-cpus
lx-lsmod 
lx-ps
#...
```

```bash
(gdb) lx-cmdline 
root=/dev/ram rw console=ttyS0 quiet nokaslr
```

Let's try to print some kernel symbols addresses -

```bash
pwndbg> p prepare_kernel_cred
$1 = {struct cred *(struct task_struct *)} 0xffffffff8108a4a0 <prepare_kernel_cred>
pwndbg> p commit_creds
$2 = {int (struct cred *)} 0xffffffff8108a270 <commit_creds>

```

Let's verify it in QEMU.

```bash
~ # cat /proc/kallsyms  | grep -w prepare_kernel_cred
ffffffff8108a4a0 T prepare_kernel_cred
~ # cat /proc/kallsyms  | grep -w commit_creds
ffffffff8108a270 T commit_creds
```

Till now we’ve successfully printed the addresses of `prepare_kernel_cred` and `commit_creds` and verified them in the `/proc/kallsyms` file.

Now, we will explore how to establish breakpoints at kernel functions and trigger them by initiating system calls. Here are several prevalent kernel functions where breakpoints can be set for effective debugging during development:

- `start_kernel`: This function is the entry point of the Linux kernel.
- `do_sys_open`: This function is responsible for handling the `open()` system call.
- `sys_read`: The `sys_read` system call is used by user-space programs to read data from a file descriptor (fd) into a buffer (buffer) for a specified number of bytes (count).
- `sys_write`: Writes data to a file descriptor.
- `sys_close`: Closes a file descriptor.
- `sys_execve`: Creates a new directory.
- `sys_rmdir`: Removes a directory.
- `sys_unlink`: Removes a file.
- `sys_chmod`: Changes file permissions.
- `sys_mmap`: Maps files or devices into memory.
- `sys_exit`: Handles process termination.


We will now setup a breakpoint on `__x64_sys_mkdir` as we are on `x64` architecture and continue `c`.

You can also view the source code of `__x64_sys_mkdir`.

*NOTE*

I am using **pwndbg** as GDB extension.

```bash
pwndbg> list __x64_sys_mkdir
3677		return do_mkdirat(dfd, pathname, mode);
3678	}
3679	
3680	SYSCALL_DEFINE2(mkdir, const char __user *, pathname, umode_t, mode)
3681	{
3682		return do_mkdirat(AT_FDCWD, pathname, mode);
3683	}
3684	
3685	int vfs_rmdir(struct inode *dir, struct dentry *dentry)
3686	{

pwndbg> c
Continuing.
```


Now, we will create a directory named AAAA in QEMU terminal.

```bash
~ # mkdir AAAA
```

In GDB, we can see that we hit the function `__x64_sys_mkdir()`.

```bash
In file: /tmp/linux-5.11.4/fs/namei.c:3680
   3675 SYSCALL_DEFINE3(mkdirat, int, dfd, const char __user *, pathname, umode_t, mode)
   3676 {
   3677         return do_mkdirat(dfd, pathname, mode);
   3678 }
   3679 
 ► 3680 SYSCALL_DEFINE2(mkdir, const char __user *, pathname, umode_t, mode)
   3681 {
   3682         return do_mkdirat(AT_FDCWD, pathname, mode);
   3683 }
   3684 
   3685 int vfs_rmdir(struct inode *dir, struct dentry *dentry)
```

We can use `next` to see what arguments are passed to `do_mkdirat` because this is function called.

Now, we will print the arguments passed to `do_mkdirat` -

```bash
   3650 static long do_mkdirat(int dfd, const char __user *pathname, umode_t mode)
 ► 3651 {


pwndbg> reg rdi rsi rdx
*RDI  0xffffc900001b7f58 ◂— 0xffffc900001b7f58
*RSI  0
*RDX  0xffffffffffffffff
```

We can also use the name of the arguments instead of registers in case you don't remember the calling convention ;)

```bash
pwndbg> p dfd
$3 = -100
pwndbg> p pathname
$4 = 0x7ffc41948fc8 "AAAA"
pwndbg> p mode
$5 = 511
```

We can see register RSI "AAAA". We can modify it… :)

```bash
pwndbg> x/c 0x7ffc41948fc8
0x7ffc41948fc8:	65 'A'
pwndbg> x/c 0x7ffc41948fc9
0x7ffc41948fc9:	65 'A'
pwndbg> x/c 0x7ffc41948fca
0x7ffc41948fca:	65 'A'
pwndbg> x/c 0x7ffc41948fcb
0x7ffc41948fcb:	65 'A'
pwndbg> x/c 0x7ffc41948fcc
0x7ffc41948fcc:	0 '\000'

```

```bash
pwndbg> set {char}0x7ffc41948fc8 = 'H'
pwndbg> set {char}0x7ffc41948fc9 = 'A'
pwndbg> set {char}0x7ffc41948fca = 'C'
pwndbg> set {char}0x7ffc41948fcb = 'K'
pwndbg> x/s 0x7ffc41948fc8 # Verify
0x7ffc41948fc8:	"HACK"
pwndbg> c
Continuing.

```

Now, let’s take a look at QEMU window.

```bash
~ # ls
HACK     dev      linuxrc  root     sys
bin      init     proc     sbin     usr
```

There you have it! By hitting a breakpoint at the `do_mkdirat()` kernel function, we were able to manipulate the memory content and change the directory name. Initially, we used `mkdir AAAA`, but through modifying the memory content, we ended up creating a directory named `HACK`.

**Congratulations!** You’ve successfully built a custom Linux kernel, created a minimal filesystem with Busybox, ran it on QEMU, and even debugged the kernel using GDB. This tutorial has given you a hands-on experience in kernel development and embedded system basics.

Feel free to explore more kernel configurations, Busybox features, and QEMU options to deepen your understanding.

Now you’re equipped with the knowledge to create and debug custom Linux kernels. 

**Happy kernel hacking!**

