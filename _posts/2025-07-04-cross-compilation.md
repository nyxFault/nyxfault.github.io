---
title: "The Art of Cross-Compilation and Emulation: Building and Testing Across Architectures"
categories: [Compilation, cross-compilation]
tags: [cross-compilation, qemu]
---

Welcome to **The Art of Cross-Compilation and Emulation: Building and Testing Across Architectures**, where we delve deep into the world of compiling code for systems and architectures beyond the familiar environment of your development machine.

In today's increasingly interconnected world of devices, the ability to develop software for platforms different from your own is a valuable asset. From embedded systems in IoT devices to powerful smartphones running different architectures, cross-compilation allows you to compile software on one machine and run it on another with ease.

But what exactly is cross-compilation, and why is it necessary? This blog explores the art of building software for systems with different processors and architectures - be it ARM, MIPS, or RISC-V - and testing your creations through emulation. In this post, we will cover the key concepts behind cross-compilation, how to set up the right toolchains, and even emulate target systems to test your code before deploying it.
Whether you're building firmware, kernels, or applications, cross-compilation allows you to be versatile and efficient in creating software that spans multiple platforms.

**Host Machine vs. Target Machine**

In the context of cross-compilation, it's important to differentiate between the host machine and the target machine:

-   Host Machine: This is the environment where you compile your code.
    It runs the cross-compiler toolchain and is typically the
    architecture of your development setup, such as x86_64.
-   Target Machine: This is the architecture for which you are compiling
    your code. It can be a different platform, such as ARM, MIPS, or any
    other architecture. The compiled binaries are intended to run on
    this machine.

## Setting Up Enviornment

To successfully perform cross-compilation and emulate target environments, you'll need to set up a few essential tools and toolchains on your development machine. This section will guide you through the installation of the necessary cross-compilers and emulation software to prepare your environment for building and testing code across different architectures. Cross-compilation requires specialized compilers that can generate binaries for architectures different from your host system. 
Below, I'll demonstrate how to install cross-compiler toolchains for ARM and MIPS architectures. The steps are similar for other architectures - simply install the corresponding toolchains for your target platform.

### 1. Installing Cross-Compiler Toolchains

A **toolchain** is a set of tools (compiler, assembler, linker, debugger) used to build code for a target architecture. 

**For ARM (32-bit and 64-bit)** 
To compile for ARM-based targets, such as embedded systems or mobile devices, you need to install ARM-specific GCC toolchain.

```bash
sudo apt update
# Install cross-compiler for ARM 32-bit
sudo apt install gcc-arm-linux-gnueabihf

# Install cross-compiler for ARM 64-bit
sudo apt install gcc-aarch64-linux-gnu
```

These compilers allow you to build applications that will run on ARM processors, both 32-bit and 64-bit.

**For MIPS (32-bit and 64-bit)**
MIPS architecture is commonly used in routers and other networking devices. To cross-compile for MIPS, install the following toolchain.

```bash
# Install cross-compiler for MIPS 32-bit (little-endian)
sudo apt install gcc-mipsel-linux-gnu

# Install cross-compiler for MIPS 64-bit
sudo apt install gcc-mips64-linux-gnuabi64
```

With the toolchains installed, you're now ready to build programs that will run on MIPS-based systems.

But wait - what if you don't have access to the actual hardware? No worries! That's where emulation comes in. Emulation allows you to run
and test your cross-compiled binaries as if they were running on the target architecture, all from the comfort of your current system.

### 2. Installing QEMU for Emulation 

To test the cross-compiled binaries without needing access to the physical target devices, we can use QEMU, an open-source emulator capable of simulating different architectures.

Let's first understand what QEMU is. QEMU stands for Quick Emulator and is a powerful open-source emulator that facilitates running software on
different hardware architectures. 

QEMU supports two main types of emulation:

1.  User-Mode Emulation: In this mode, QEMU allows you to run individual applications compiled for a different architecture on your host     system. This means that if you have a binary compiled for ARM, for example, you can execute it on your x86 machine without needing to boot into a complete ARM environment. This is particularly useful for developers who need to test applications quickly without setting up an entire operating system.
2.  Full System Emulation: This mode emulates an entire system, including the CPU, memory, and peripheral devices. It allows you to run complete operating systems, such as Linux distributions, as if they were running on the actual hardware.

In this case, we will only need User-Mode Emulation, as our focus is on compiling and testing small binaries. This allows us to quickly run and
validate our applications without the overhead of setting up a full system environment.

Install QEMU with support for ARM and MIPS as follows:

```bash
# Install QEMU for User-Mode Emulation
sudo apt install qemu-user qemu-user-static
```

### 3. Installing Build Tools

In addition to cross-compilers and emulators, you'll need some common build tools like `Make` and optionally `CMake` for projects using modern build systems.

```bash
# Optional
sudo apt install make cmake
```

### 4. Verifying Your Environment 

Once all tools and software are installed, it's a good idea to verify that everything is working as expected. You can check the installation of the cross-compilers by running:

```bash
# Check ARM 32-bit cross-compiler
arm-linux-gnueabihf-gcc --version

# Check ARM 64-bit cross-compiler
aarch64-linux-gnu-gcc --version

# Check MIPS 32-bit (little-endian) cross-compiler
mipsel-linux-gnu-gcc --version

# Check MIPS 64-bit cross-compiler
mips64-linux-gnuabi64-gcc --version
```

Now that we have everything installed, it's time to get our hands dirty and dive into some practical applications! Let's put our cross-compilation and emulation skills to the test by compiling and running some binaries.

## Compiling and Running Binaries

With our environment set up and ready, let's walk through the process of compiling a simple C program and running it using QEMU's User-Mode Emulation.

### 1. Writing the C Program 

First, create a simple C program that we will compile. For demonstration purposes, we'll write a program that prints "Hello World!".

```c
#include <stdio.h>
int main() {
    printf("Hello World!\n");
}
```
### 2. Cross-Compiling the Program 

Next, we'll compile this program for the ARM architecture. Use the following command to cross-compile it:

```bash
# For ARM 32-bit
arm-linux-gnueabihf-gcc hello.c -o hello_arm

# For ARM 64-bit
aarch64-linux-gnu-gcc hello.c -o hello_arm64

# For MIPS 32-bit (little-endian)
mipsel-linux-gnu-gcc hello.c -o hello_mipsel

# For MIPS 64-bit
mips64-linux-gnuabi64-gcc hello.c -o hello_mips64
```

### 3. Running the Compiled Binary with QEMU 

Once the binaries are compiled, you can run them using QEMU's User-Mode Emulation.

**Running the ARM 32-bit Binary:**

```bash
$ qemu-arm ./hello_arm
qemu-arm: Could not open '/lib/ld-linux-armhf.so.3': No such file or directory
```

Well, that's a surprise! 
To understand the problem, it's essential to grasp the difference between *static* and *dynamic* compilation. I know it might feel like a bit of theory, but stick with me; it'll help clarify our situation.

**Static Compilation** 

In static compilation, all the necessary libraries and dependencies are included directly within the executable at compile time. This means that when you run the compiled program, it doesn't rely on any external libraries. The advantage of static compilation is that it results in a self-contained binary that can run independently on any compatible system without worrying about whether the required libraries are installed. However, this can lead to larger executable sizes and can make updates more cumbersome, as you'll need to recompile the entire program when updating a library.

**Dynamic Compilation** 

On the other hand, dynamic compilation creates an executable that links to shared libraries at runtime. This means that the program depends on external libraries being present on the system where it runs. While dynamic compilation results in smaller executable sizes and allows for easier updates (as you can replace just the library without recompiling the entire program), it also introduces potential issues like the one we're experiencing with QEMU: if the required dynamic libraries are missing on the system, the program won't run.

In our case, QEMU is looking for the dynamic linker library `ld-linux-armhf.so.3`, which it can't find, leading to the error.

To determine whether your binary is statically or dynamically compiled, and to identify its dependencies, you can use a couple of command-line
tools.

Using the **file** Command: This command provides information about the binary file type

```bash
$ file ./hello_arm
./hello_arm: ELF 32-bit LSB pie executable, ARM, EABI5 version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux-armhf.so.3, BuildID[sha1]=881b47dada7aab1309bed2e7d792f032e58376f7, for GNU/Linux 3.2.0, not stripped
```

We can see in the output above that it is marked as `dynamically linked`, which means our binary is dynamically compiled.

For static compilation, we need to provide the `-static` flag to gcc during the compilation process. Use the following command:

```bash
arm-linux-gnueabihf-gcc -static hello.c -o hello_arm_static
```

Now, if we check the binary using the `file` command, we can see the output indicating its compilation type:

```bash
$ file hello_arm_static
hello_arm_static: ELF 32-bit LSB executable, ARM, EABI5 version 1 (GNU/Linux), statically linked, BuildID[sha1] 59512fea76527295359f453c545a480dcc128983, for GNU/Linux 3.2.0, not stripped
```

In this output, the phrase "statically linked" confirms that our binary has been compiled statically. This means all the necessary libraries are
included within the executable, allowing it to run independently of external library dependencies.

We can compare size of both statically and dynamically compiled binaries.

```bash
$ ls -lh hello_arm hello_arm_static
-rwxrwxr-x 1 kali kali 7.8K Oct 12 02:35 hello_arm
-rwxrwxr-x 1 kali kali 414K Oct 12 02:44 hello_arm_static
```

As we can see, our `hello_arm` binary is just 7.8KB, while the `hello_arm_static` binary is a whopping 414KB! 😲 Oh, that's a significant size increase for such a small piece of code! This illustrates one of the trade-offs of static compilation - while it provides independence from external libraries, it can lead to larger executable sizes.

Let's run our statically compiled binary now:

```bash
$ qemu-arm ./hello_arm_static 
Hello World!
```
Hurray! We successfully ran the statically compiled binary! 🎉 But what about our dynamically linked binary? 😟

Remember the toolchain we installed? It not only includes gcc but also other essential components, such as the linker and libraries needed for
building and running dynamically linked binaries.

We can find the necessary libraries and linkers for ARM 32-bit binaries in the `/usr/arm-linux-gnueabihf/` directory. Let's navigate to that
location:

```bash
$ cd /usr/arm-linux-gnueabihf/
$ ls 
bin  include  lib
```
Within this directory, you'll see several subdirectories: bin, include, and lib.

-   bin: This directory typically contains the binary executables for various tools, including the cross-compiler.
-   include: This directory holds header files that define the interfaces for the libraries used during compilation.
-   lib: This is where the shared libraries and dynamic linkers reside, which are crucial for executing dynamically linked binaries.

Now, let's take a look at the contents of the lib directory:

```bash
$ ls lib/
ld-linux-armhf.so.3
libc.so.6 
...
```

In the lib directory, you can find important files such as: 

-   ld-linux-armhf.so.3: This is the dynamic linker/loader for ARM
    32-bit binaries. It is responsible for loading the required shared
    libraries into memory when a dynamically linked executable is run.
-   libc.so.6: This is the GNU C Library (glibc), which provides
    essential functionalities for C programs, such as input/output
    operations, memory management, and string manipulation.

In QEMU, we can specify the path to the ELF interpreter using the `-L` flag or by setting the `QEMU_LD_PREFIX` environment variable. This allows QEMU to locate the required dynamic libraries needed to run our dynamically linked binaries.

**Using the `-L` flag**

```bash
$ qemu-arm -L /usr/arm-linux-gnueabihf ./hello_arm
Hello World!
```

**Using the `QEMU_LD_PREFIX` Environment Variable**

```bash
$ export QEMU_LD_PREFIX=/usr/arm-linux-gnueabihf
$ qemu-arm ./hello_arm
Hello World!
```
YAY! In both cases, we can finally run our dynamically compiled ARM 32-bit binary successfully! 🎉

You can follow the same process for compiling and running binaries for ARM 64, MIPS 32 (LE), and MIPS 64 architectures. The steps remain consistent: simply compile your code using appropriate toolchains, and use QEMU to run the binaries while ensuring that the required libraries are accessible. This versatility allows you to work seamlessly across different architectures, expanding your development capabilities!

- For ARM 64, you can find the libraries in: `/usr/aarch64-linux-gnu/`
- For MIPS 32 (Little Endian), the libraries are located in: `/usr/mipsel-linux-gnu/`
- For MIPS 64, you can find the libraries in: `/usr/mips64-linux-gnuabi64/`

## Conclusion

In this guide, we explored the fundamentals of cross-compilation and emulation using QEMU. We covered the differences between static and dynamic compilation, discussing how static binaries include all dependencies within the executable, while dynamic binaries rely on external libraries. We also learned how to set up toolchains, compile binaries for different architectures, and troubleshoot common issues.
With this knowledge, you can effectively develop and test applications across various platforms.

Well, I'll leave the rest as an exercise for you! I hope you enjoyed this guide on the art of cross-compilation and emulation. If you found
it helpful, be sure to follow for more insights and tutorials! 
Should you encounter any issues or have questions, please don't hesitate to reach out. I'm here to help!

Happy Compiling! 🚀

