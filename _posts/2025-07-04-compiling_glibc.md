---
title: "Compiling and Installing glibc x.y on Debian"
categories: [Compilation, glibc]
tags: [glibc, heap]

---

## Compiling and Installing glibc x.y on Debian

**Prerequisites**

```bash
sudo apt-get install automake autoconf libtool make gcc
```
If you're unsure of your system's host type, you can run the following command to check:

```bash
gcc -dumpmachine
```

For demo, we will use `libc 2.1`

Visit the GNU C Library (glibc) [website](https://www.gnu.org/software/libc/)

Find libc in https://ftp.gnu.org/gnu/glibc/



1. Download the Source Code:
```bash
wget https://ftp.gnu.org/gnu/glibc/glibc-2.1.3.tar.gz
tar -xvzf glibc-2.1.3.tar.gz
cd glibc-2.1.3
```

2. Prepare the Build Environment:
Create a separate build directory to keep your source directory clean:
```bash
mkdir build
cd build
```

3. Configure the Build
You need to specify the installation directory where the compiled glibc will be installed. For example, let's install it in `/opt/glibc-2.1.3`:
```bash
../configure --prefix=/opt/glibc-2.1.3 --enable-add-ons
```
Adjust the `--prefix` option to your preferred installation directory.
You can also specify other options like `--enable-debug` if you want to build a debug version.

4. Compile the Library
Compile the library using `make`:
```bash
make -j$(nproc)
```

5. Install the Library
After successful compilation, install the library:
```bash
sudo make install
```

6. Update Library Cache
Update the dynamic linker run-time bindings:
```bash
sudo ldconfig
```

7. Linking Against Your Custom glibc
To link your program with the specific glibc version, you need to specify the path to the glibc installation using the `-Wl`,`-rpath` and `-L` options:
```bash
gcc -Wl,-rpath=/opt/glibc-2.31/lib -L/opt/glibc-2.31/lib -I/opt/glibc-2.31/include hello.c -o hello
```
