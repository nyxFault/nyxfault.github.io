---
title: "Fuzzing Dynamically Linked Code"
categories: [Fuzzing]
tags: [fuzzing, afl++, afl-fuzz]
mermaid: true
---

Hey everyone — apologies for the delayed post. I got caught up with a few things and couldn’t publish as planned. Thanks for your patience and continued support.

Wishing you all a Happy New Year! 🎉 Looking forward to sharing more technical content and deep dives with you this year.

As we have already discussed about statically and dynamically linked libraries. We will again revise it here but if you want you can check it [here](https://nyxfault.github.io/posts/ELF-Internals/#creating--linking-libraries-in-linux-static--dynamic).

A **library** is a collection of precompiled code (functions, objects, symbols) that programs link against to reuse functionality instead of reimplementing it.

There are **two primary types** of libraries in Linux:

#### 1. Static Libraries

**File extension:** `.a`
**Linked at:** Compile time

**Characteristics**

- The library code is **copied into the final executable** at link time.
- The binary becomes **self-contained** (no dependency on the `.a` file at runtime).
- Larger executable size.
- No runtime symbol resolution.

#### 2. Shared (Dynamic) Libraries

**File extension:** `.so`  
**Linked at:** Runtime (via dynamic linker `ld-linux.so`)

**Characteristics**

- Code is **not embedded** in the executable.
- Loaded at runtime by the dynamic loader.
- Multiple processes can **share the same mapped memory pages**.
- Smaller executables.


This article focuses on dynamically linked libraries.
Both executables and shared libraries use the **ELF (Executable and Linkable Format)**.

Key ELF components involved in dynamic linking:

#### `.dynamic`

Contains metadata used by the loader:

- `DT_NEEDED` – required shared libraries
- `DT_SYMTAB` – symbol table
- `DT_STRTAB` – string table
- `DT_RELA` / `DT_REL` – relocation entries
- `DT_PLTGOT` – GOT address

#### `.dynsym`

Dynamic symbol table (exported/imported symbols).

#### `.got` (Global Offset Table)

Holds runtime-resolved addresses.

#### `.plt` (Procedure Linkage Table)

Trampoline stubs used for lazy binding.


### The Dynamic Loader

The interpreter is defined inside the ELF:

```bash
readelf -l /bin/ls | grep interpreter
      [Requesting program interpreter: /lib64/ld-linux-x86-64.so.2]
```

The dynamic loader:

1. Parses `.dynamic`
2. Loads required libraries (`DT_NEEDED`)
3. Performs relocations
4. Resolves symbols
5. Transfers control to `main`


### Symbol Resolution

When a function like `printf()` is called:

1. Execution jumps to a PLT stub.
2. The PLT consults the GOT.
3. If unresolved, control goes to the dynamic resolver.
4. The resolver finds the symbol in loaded libraries.
5. GOT is patched with the resolved address.
6. Subsequent calls go directly to the resolved function.

This mechanism is known as **lazy binding**.


You can disable it:

```bash
LD_BIND_NOW=1 /bin/ls
```

`LD_BIND_NOW` is an environment variable used in Linux and Unix-like systems that instructs the dynamic linker (`ld.so`) to resolve all symbols (function calls and variables) at program startup, rather than lazily (on-demand) when they are first called.


#### Lazy vs Immediate Binding

|Binding Type|Behavior|
|---|---|
|Lazy|Symbols resolved on first use|
|Immediate|All symbols resolved at startup|

Lazy binding improves startup performance but expands attack surface (e.g., GOT overwrite exploitation).

Dynamic linking introduces attack vectors:

- GOT overwrite
- `LD_PRELOAD` hijacking
- RPATH injection
- Symbol interposition
- PLT hooking
- ret2dlresolve


Let's create a vulnerable library which copies data to a buffer without checking size.

```c
// vuln.c
#include <stdio.h>
#include <string.h>

void overflow(char *str)
{
    char buffer[64];
    printf("[*] Copying user input...\n");
    // Vulnerable: no bounds checking
    strcpy(buffer, str);
    printf("[*] Done copying: %s\n", buffer);
}
```


Compile **without modern mitigations** to make exploitation easier:

```bash
gcc -z execstack -fPIC -shared -o libvuln.so vuln.c -fno-stack-protector 
```

```bash
checksec libvuln.so
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        PIE enabled
    RWX:        Has RWX segments
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No

```

Let's make a test program linked to this library.

```c
// test.c
#include <stdio.h>

void overflow(char *str);

int main(int argc, char *argv[])
{
    if (argc != 2) {
        printf("Usage: %s <input>\n", argv[0]);
        return 1;
    }

    overflow(argv[1]);
    return 0;
}
```

Compile and Link Against libvuln.so

```bash
gcc test.c -L. -lvuln -o test -fno-stack-protector -z execstack -no-pie
```

Run:

```bash
$ LD_LIBRARY_PATH=. ./test 
Usage: ./test <input>
$ LD_LIBRARY_PATH=. ./test AAAA
[*] Copying user input...
[*] Done copying: AAAA
```

**Trigger Overflow**

```bash
LD_LIBRARY_PATH=. ./test $(python3 -c 'print("A"*200)')
[*] Copying user input...
[*] Done copying: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
Segmentation fault (core dumped)
```

### Manual Shared Object Loading Using dlopen() and dlsym()

##### The dlopen() API Family

The `dlopen()` interface, part of the POSIX standard, consists of four primary functions:

```c
#include <dlfcn.h>

void *dlopen(const char *filename, int flags);
void *dlsym(void *handle, const char *symbol);
int dlclose(void *handle);
char *dlerror(void);
```

These functions form the foundation of manual dynamic linking in Unix-like systems.

##### `dlopen()`

```c
void *dlopen(const char *filename, int flags);
```

The `filename` parameter specifies which shared object to load:

- **NULL**: Returns handle to the main executable

`dlopen` returns an opaque "handle" that the program can then use to access the functions and data within that library.

### Flags and Their Implications

##### RTLD_LAZY vs RTLD_NOW

**RTLD_LAZY**: Performs lazy binding - symbols are resolved only when first referenced. This improves initial load time but risks runtime symbol resolution failures.

**RTLD_NOW**: Performs eager binding - all undefined symbols are resolved immediately during dlopen(). This provides immediate failure feedback but increases load time.


##### `dlsym()`

```c
void *dlsym(void *handle, const char *symbol);
```

`dlsym()` returns the address where a symbol (function or variable) is loaded in memory. The handle comes from dlopen(), and special handles exist for specific purposes:

```c
// Get symbol from currently loaded library
void (*func)(void) = dlsym(handle, "function_name");

// Search all loaded libraries
void *symbol = dlsym(RTLD_DEFAULT, "global_function");

// Search only the main executable
void *symbol = dlsym(RTLD_MAIN_ONLY, "main_function");
```

##### Error Handling with `dlerror()`

Proper error handling is crucial when working with dynamic loading:

```c
void *handle = dlopen("./mylib.so", RTLD_NOW);
if (!handle) {
    fprintf(stderr, "dlopen failed: %s\n", dlerror());
    return -1;
}

// Clear any existing error
dlerror();

void (*func)(void) = dlsym(handle, "my_function");
char *error = dlerror();
if (error != NULL) {
    fprintf(stderr, "dlsym failed: %s\n", error);
    dlclose(handle);
    return -1;
}
```

##### `dlclose()`

The `dlclose()` function is used in POSIX-compliant systems to inform the system that a dynamically loaded shared object (like a `.so` file or DLL) is no longer needed by the application.


Let's take our previous example where we created `libvuln.so` library.

```c
#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>

int main() {
    void *handle;
    void (*overflow)(char *str);
    char *error;
    
    // Step 1: Clear any existing errors
    dlerror();
    
    // Step 2: Load the shared library
    printf("[*] Loading libvuln.so...\n");
    handle = dlopen("./libvuln.so", RTLD_LAZY);
    
    if (!handle) {
        fprintf(stderr, "[!] Failed to load library: %s\n", dlerror());
        return EXIT_FAILURE;
    }
    printf("[+] Library loaded successfully at %p\n", handle);
    
    // Step 3: Get the symbol address
    printf("[*] Locating overflow() function...\n");
    overflow = (void (*)(char *)) dlsym(handle, "overflow");
    
    error = dlerror();
    if (error != NULL) {
        fprintf(stderr, "[!] Symbol lookup failed: %s\n", error);
        dlclose(handle);
        return EXIT_FAILURE;
    }
    printf("[+] overflow() found at address %p\n", overflow);
    
    // Step 4: Execute the function
    printf("[*] Executing overflow()...\n");
    char test_string[] = "Hello, vulnerable world!";
    overflow(test_string);
    
    // Step 5: Cleanup
    printf("[*] Cleaning up...\n");
    if (dlclose(handle) != 0) {
        fprintf(stderr, "[!] Failed to close library: %s\n", dlerror());
        return EXIT_FAILURE;
    }
    printf("[+] Library unloaded successfully\n");
    
    return EXIT_SUCCESS;
}
```

#### Compilation and Usage

```bash
# Step 1: Compile the loader
gcc -o loader loader.c -ldl

# Step 2: Run with library in current directory
./loader AAAA
[*] Loading libvuln.so...
[+] Library loaded successfully at 0x625dd25ba6d0
[*] Locating overflow() function...
[+] overflow() found at address 0x74c1c37c6159
[*] Executing overflow()...
[*] Copying user input...
[*] Done copying: AAAA
[*] Cleaning up...
[+] Library unloaded successfully

```


To fuzz this setup with **AFL++**, we need to address one key architectural detail:

> AFL only observes coverage in _instrumented code_.  
> Since the vulnerability lives in `libvuln.so`, the shared object must be instrumented — not just the loader.

Your current loader also hardcodes `"Hello, vulnerable world!"`, which prevents AFL from controlling input. We must modify it to consume file-based input (AFL model).

```c
#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>

#define MAX_INPUT 1024

int main(int argc, char *argv[]) {
    void *handle;
    void (*overflow)(char *str);
    char *error;

    if (argc < 2) {
        fprintf(stderr, "Usage: %s <input_file>\n", argv[0]);
        return EXIT_FAILURE;
    }

    FILE *f = fopen(argv[1], "rb");
    if (!f) {
        perror("fopen");
        return EXIT_FAILURE;
    }

    char buf[MAX_INPUT] = {0};
    size_t len = fread(buf, 1, sizeof(buf)-1, f);
    fclose(f);

    dlerror();

    handle = dlopen("./libvuln.so", RTLD_LAZY);
    if (!handle) {
        fprintf(stderr, "dlopen failed: %s\n", dlerror());
        return EXIT_FAILURE;
    }

    overflow = (void (*)(char *)) dlsym(handle, "overflow");
    if ((error = dlerror()) != NULL) {
        fprintf(stderr, "dlsym failed: %s\n", error);
        dlclose(handle);
        return EXIT_FAILURE;
    }

    overflow(buf);

    dlclose(handle);
    return EXIT_SUCCESS;
}

```

Now AFL controls input via file mutation.

```bash
# Build shared library with instrumentation
AFL_USE_ASAN=1 afl-clang-fast -shared -fPIC -o libvuln.so vuln.c

# Build loader with instrumentation
AFL_USE_ASAN=1 afl-clang-fast -o fuzz_libvuln loader.c -ldl
```

```bash
./fuzz_libvuln in/seed
[-] FATAL: forkserver is already up, but an instrumented dlopen() library loaded afterwards. You must AFL_PRELOAD such libraries to be able to fuzz them or LD_PRELOAD to run outside of afl-fuzz.
To ignore this set AFL_IGNORE_PROBLEMS=1.
Aborted
```


When fuzzing with AFL++, dynamically loaded libraries introduce a non-obvious constraint:

> All instrumented code must be loaded before the AFL forkserver starts.

If an instrumented `.so` is loaded later via `dlopen()`, AFL++ aborts with:

```txt
FATAL: forkserver is already up, but an instrumented dlopen() library loaded afterwards.
You must AFL_PRELOAD such libraries...
```

This article explains **why this happens**, and the **correct ways to handle it**, depending on your threat model and research goals.

AFL++ instrumentation works by:

- Inserting edge-coverage hooks at compile time.
- Registering a shared memory bitmap (`__afl_area_ptr`) at process start.
- Starting a forkserver early in `main()`.

When your program later calls:

```c
handle = dlopen("./libvuln.so", RTLD_LAZY);
```

and that `.so` was compiled with `afl-clang-fast`, the library:

- Contains its own instrumentation.
- Attempts to register coverage.
- Does so **after the forkserver has already initialized**.

That violates AFL's runtime assumptions. Result: abort.

**Run AFL with AFL_PRELOAD**

```bash
AFL_PRELOAD=./libvuln.so afl-fuzz -i in -o out -- ./fuzz_libvuln @@
```

After 20-25 seconds you'll find a crash.

```bash
$ xxd out/default/crashes/id\:000000\,sig\:06\,src\:000000\,time\:854\,execs\:2118\,op\:havoc\,rep\:8 
00000000: 3333 3333 3333 3333 3333 3333 3333 4133  33333333333333A3
00000010: 3333 3333 3333 4133 3333 3333 3333 3333  333333A333333333
00000020: 3333 3333 3333 3333 3345 3333 3333 3333  333333333E333333
00000030: 3333 4133 3333 3333 3333 3333 3333 3333  33A3333333333333
00000040: 3333 3333 3345 3333 3333 3333 3333 3333  33333E3333333333
00000050: 3333 6833 3341                           33h33A
```

If you want to run it manually (not under afl-fuzz):

```bash
# Normal File
LD_PRELOAD=./libvuln.so ./fuzz_libvuln in/seed 
[*] Copying user input...
[*] Done copying: AAAA

# Crash File
LD_PRELOAD=./libvuln.so ./fuzz_libvuln out/default/crashes/id\:000000\,sig\:06\,src\:000000\,time\:854\,execs\:2118\,op\:havoc\,rep\:8 
[*] Copying user input...
=================================================================
==644365==ERROR: AddressSanitizer: stack-buffer-overflow on address 0x7ffc5414c180 at pc 0x000000487b98 bp 0x7ffc5414c110 sp 0x7ffc5414b8d0
WRITE of size 87 at 0x7ffc5414c180 thread T0
/usr/bin/llvm-symbolizer-13: symbol lookup error: ./libvuln.so: undefined symbol: __afl_area_ptr
==644365==WARNING: external symbolizer didn't start up correctly!
```

That means:

- AFL found an input that overflows your stack buffer.
- ASAN correctly detected it.
- Your fuzzing setup worked.

Ignore the `__afl_area_ptr` warning. It is AFL’s global shared memory pointer for the coverage bitmap.

When you compile with:

```bash
afl-clang-fast
```

Instrumentation inserts references to:

```c
__afl_area_ptr
```

During fuzzing:

- afl-fuzz sets up shared memory
- Exports `__afl_area_ptr`
- Everything links correctly

But when you run manually with:

```bash
LD_PRELOAD=./libvuln.so ./fuzz_libvuln crashfile
```

You are **not running under afl-fuzz**.

Therefore:

- No AFL runtime
- No coverage shared memory
- No `__afl_area_ptr`
- The instrumented `.so` tries to resolve it
- Loader fails symbol resolution

Inside AFL:

```txt
afl-fuzz → forkserver → shared memory → __afl_area_ptr exists
```

Outside AFL:

```txt
./fuzz_libvuln → no forkserver → no shared memory → missing symbol
```

That’s the difference.

If you want I can do the same using **libfuzzer** as well.
#### Conclusion

In this blog, we looked at dynamically linked libraries, how to compile binaries against dynamically linked libraries. Then we tried instrumenting the target binary (SUT) using AFL++. AFL++ instrumentation must be present **before** the forkserver initializes. If an instrumented `.so` is loaded afterward, AFL aborts because coverage registration occurs too late, violating its shared-memory assumptions.
