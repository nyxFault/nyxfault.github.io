---
title: "Hijacking the puts Function in C"
# date: 2025-07-04 12:00:00 +0000  # Adjust to your actual date/time
categories: [Hijacking, glibc]
tags: [glibc]
# icon: fas fa-info-circle
# order: 4
# layout: home

---

Function hijacking is a technique used in programming to intercept calls to standard library functions and replace them with custom implementations. This report demonstrates how to hijack the puts function in C to print a custom message ("BYE BYE!") whenever puts is called. 

The implementation consists of two main components:
1. A Shared Library: This library contains the custom implementation of the puts function.
2. A Test Program: This program demonstrates the effect of the hijacking by calling puts.

Step 1: Create the Library Source File
```c
#define _GNU_SOURCE
#include <stdio.h>
#include <dlfcn.h>

// Define a pointer to the original puts function
static int (*original_puts)(const char *) = NULL;

// Our custom puts function
int puts(const char *str) {
    // Load the original puts function if not already done
    if (!original_puts) {
        original_puts = dlsym(RTLD_NEXT, "puts");
    } 

    // Call the original puts function with the provided string
    // return original_puts(str);
    //  Modify the behavior: add a prefix to the output
    char modified_str[1024];
    snprintf(modified_str, sizeof(modified_str), "[Hijacked] %s", str);

    // Call the original puts with the modified string
    return original_puts(modified_str);

	// return our custom message
	// return original_puts("BYE BYE!");
}

```

Step 2: Compile the Library:
```sh
gcc -shared -fPIC -o hook_puts.so hook_puts.c -ldl
```
- -shared: Creates a shared library.
- -fPIC: Generates position-independent code (required for shared libraries).
- -ldl: Links the dl library, which provides functions like dlsym.

Step 3: Create a Test Program
```c
#include <stdio.h>

int main() {
    puts("Hello World!\n");
    return 0;
}
```

Step 4: Compile the Test Program
```sh
gcc -o test test.c
```

Step 5: Run the Test Program with `LD_PRELOAD`
```sh
LD_PRELOAD=./hook_puts.so ./test
```

When you set `LD_PRELOAD=./hook_puts.so`, the dynamic linker loads your shared library before any other libraries (including libc). This allows your custom puts function to override the one in libc.

`dlsym(RTLD_NEXT, "puts")`: This function retrieves the address of the original puts function from libc. `RTLD_NEXT` tells the dynamic linker to find the next occurrence of the function in the search order (i.e., the original puts in libc).


**LD_PRELOAD:** 

This environment variable is used to specify shared libraries that should be loaded before others when running a program. By preloading our library, we ensure that our version of puts is used instead of the standard one.

The `#define _GNU_SOURCE` directive is used at the beginning of the source code to enable GNU-specific features and extensions in the C standard library.
Defining `_GNU_SOURCE` allows the use of various non-standard GNU extensions that are not available in the standard C library by default. This includes additional functions and features that enhance the capabilities of the library, such as strdup, memmem, and many others that are specific to GNU.


For getting function prototypes you can use `man` pages. Look for the `SYNOPSIS` section, which contains the function prototype. 

```bash
man puts | grep -A 3 "SYNOPSIS"
```

If you have `cppman` installed, you can use it to display the function prototype in a more user-friendly way.

```bash
cppman puts
```

You can use gcc to preprocess the header files and extract the function prototype.

1. Create a temporary C file (e.g., temp.c) with just the #include directive:
```c
#include <stdio.h>
```

2. Use gcc to preprocess the file and dump all macros and declarations:
```bash
gcc -E temp.c | grep -w puts
```


**Hooking `add` function**

```c
#include <stdio.h>

// Function to add two integers
int add(int a, int b) {
    return a + b;
}

// Function to print the result
void print_result(int result) {
    printf("The result is: %d\n", result);
}

int main() {
    int num1 = 10;
    int num2 = 20;
    int sum;

    // Call the add function
    sum = add(num1, num2);

    // Call the print_result function
    print_result(sum);

    return 0;
}
```


**Note:**
If the `add` function is statically linked into the executable, LD_PRELOAD will not work because it only affects dynamically linked functions.


**Hooking `strlen` function**


This is a simple C program that uses `strlen` function:

```c
#include <stdio.h>
#include <string.h> // For strlen() function

int main() {
    char input[100]; // Buffer to store the input string

    // Prompt the user for input
    printf("Enter a string: ");
    fgets(input, sizeof(input), stdin);

    // Remove the newline character added by fgets
    input[strcspn(input, "\n")] = '\0';

    // Calculate the length of the string
    int length = strlen(input);

    // Print the length of the string
    printf("The length of the string is: %d\n", length);

    return 0;
}
```


Write hook for `strlen`

```c
#define _GNU_SOURCE
#include <stdio.h>
#include <dlfcn.h>
#include <string.h>

// Function pointer to store the original `strlen` function
static size_t (*original_strlen)(const char *s) = NULL;

// Hooked `strlen` function
size_t strlen(const char *s) {
    // Load the original `strlen` function if not already loaded
    if (!original_strlen) {
        original_strlen = dlsym(RTLD_NEXT, "strlen");
        if (!original_strlen) {
            fprintf(stderr, "Error: Could not find original strlen function.\n");
            return 0; // Return 0 or handle the error appropriately
        }
    }

    // Print debug information (optional)
    printf("Hooked strlen called with string: %s\n", s);

    // Modify the behavior: always return 1337
    return 1337;
}
```


```bash
gcc -shared -fPIC -o hijack_strlen.so hijack_strlen.c -ldl
LD_PRELOAD=./hijack_strlen.so ./test_strlen
```


