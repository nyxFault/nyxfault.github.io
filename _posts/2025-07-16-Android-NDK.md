---
title: "Android NDK Tutorial: Compiling C/C++ Code with ndk-build"
categories: [Android, NDK]
tags: [android, ndk]
---

The Android Native Development Kit (NDK) is a toolset that allows you to implement parts of your Android app using native-code languages like C and C++. 

You can download the NDK from the official [Android Developer website](https://developer.android.com/ndk/downloads) or via the command line on Linux using:

```bash
# sdkmanager --install "ndk;version"
sudo sdkmanager --install "ndk;22.1.7171670"
```

### Step 1: Set Up Project Structure

Create a directory structure like this:

```bash
MyNativeProject/
│── jni/               # Native code goes here
│   ├── Android.mk     # Makefile for NDK
│   ├── Application.mk # (Optional) Build configurations
│   └── main.c         # Your C/C++ code
└── libs/              # (Auto-generated) Compiled libraries
```

### Step 2: Write a Simple C Program

Create `jni/main.c`:

```c
#include <stdio.h>
#include <android/log.h>

void hello_world() {
    printf("Hello from C!\n");
    __android_log_print(ANDROID_LOG_INFO, "NDK", "Hello from NDK!"); // Logcat output
}

int main() {
    hello_world();
    return 0;
}
```

### Step 3: Create `Android.mk`

This file tells `ndk-build` how to compile your code.  

Create `jni/Android.mk`:

```makefile
LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

# Name of your executable or library
LOCAL_MODULE    := my_program  

# List your C/C++ source files
LOCAL_SRC_FILES := main.c

# Link against Android-specific libraries (log, dl, etc.)
LOCAL_LDLIBS    := -llog -ldl  

# Build as an executable (use BUILD_SHARED_LIBRARY for .so)
include $(BUILD_EXECUTABLE)  
```

### Step 4: (Optional) Configure `Application.mk`

This file defines build settings like target ABI and API level.  

Create `jni/Application.mk`:

```makefile
# Target architectures (arm64-v8a, armeabi-v7a, x86, x86_64)
# APP_ABI := all  # Build for all ABIs, or specify like armeabi-v7a arm64-v8a x86 x86_64
APP_ABI := arm64-v8a armeabi-v7a  

# Minimum Android API level
APP_PLATFORM := android-21  

# Use Clang (recommended)
NDK_TOOLCHAIN_VERSION := clang  

# Enable C++ exceptions/RTTI (if using C++)
# APP_CPPFLAGS += -fexceptions -frtti
```

### Step 5: Run `ndk-build`

Open a terminal in `MyNativeProject/` and run:

```bash
# If NDK is in PATH:
$ ndk-build

# If NDK is not in PATH, specify full path:
# /opt/android-sdk/ndk/<version>/ndk-build
$ /opt/android-sdk/ndk/22.1.7171670/ndk-build 
[arm64-v8a] Compile        : my_program <= main.c
[arm64-v8a] Executable     : my_program
[arm64-v8a] Install        : my_program => libs/arm64-v8a/my_program
[armeabi-v7a] Compile thumb  : my_program <= main.c
[armeabi-v7a] Executable     : my_program
[armeabi-v7a] Install        : my_program => libs/armeabi-v7a/my_program

```

**Output:**

- Compiled binary: `./libs/<ABI>/my_program`  
- Debug symbols (if any): `./obj/local/<ABI>/`

**Common `ndk-build` Commands**

|Command|Description|
|---|---|
|`ndk-build`|Compile for all ABIs|
|`ndk-build clean`|Delete build artifacts|
|`ndk-build NDK_DEBUG=1`|Build with debug symbols|
|`ndk-build V=1`|Show detailed build logs|
|`ndk-build APP_ABI=arm64-v8a`|Build only for 64-bit ARM|

### Verify

```bash
$ adb shell getprop ro.product.cpu.abi
arm64-v8a
# Push the compiled binary 
$ adb push ../libs/arm64-v8a/my_program /data/local/tmp
$ adb shell
bonito:/ $ cd /data/local/tmp
bonito:/data/local/tmp $ ./my_program                                                              
Hello from C!
bonito:/data/local/tmp $

```

By creating standalone binaries that run in `/data/local/tmp`, we've explored one of the fundamental use cases of the NDK - executing native code directly on Android devices.

**Coming Up Next:** In my next blog post, I'll show you how to integrate native code directly into your Android applications using JNI (Java Native Interface). We'll explore this amazing bridge between Java and native code, covering everything from basic integration to fuzzing it.