---
title: "Fuzzing an Android JNI Socket App with AFL++ Frida (Real Device)"
categories: [Android, Fuzzing, AFL++]
tags: [android, jni, afl++, frida, fuzzing, ndk]
---

I wanted to fuzz an Android app **on-device** (not emulator fantasy mode), and I wanted the target to be a JNI `.so` with a socket parser.

So I built one:

- app listens on `4444`
- receives bytes
- JNI/native side has a `fuzzMe(...)` function
- crash trigger is `FuzzMe@123`

Then I fuzzed it the same way Quarkslab fuzzed `qb.blogfuzz`:

- AFL++ Frida mode on rooted phone
- external harness binary
- `afl.js` persistent hook
- corpus + crash triage

And yes, we got a crash file.

## App links

- Source code: [FuzzMeApp](https://github.com/nyxFault/FuzzMeApp)
- Direct APK download: [app-debug.apk (v1.0.0)](https://github.com/nyxFault/FuzzMeApp/releases/download/v1.0.0/app-debug.apk)

---

![this is fine](https://media.giphy.com/media/NTur7XlVDUdqM/giphy.gif)

*“I’ll just test one input manually…”*  
*five hours later: building harnesses and cursing forkserver handshakes*

---

## Target setup (what we fuzz)

Inside app native code (`native-lib.cpp`), we exposed:

```c
extern "C" void fuzzMe(const uint8_t *buffer, uint64_t length) {
    if (buffer == nullptr || length < 10) return;
    if (buffer[0]=='F')
      if (buffer[1]=='u')
        if (buffer[2]=='z')
          if (buffer[3]=='z')
            if (buffer[4]=='M')
              if (buffer[5]=='e')
                if (buffer[6]=='@')
                  if (buffer[7]=='1')
                    if (buffer[8]=='2')
                      if (buffer[9]=='3')
                        triggerCrash();   // intentional crash
}
```

This gives us:

1. a direct native fuzz target (`fuzzMe`)
2. deterministic crash condition
3. realistic Android deployment (`libfuzzme.so`)

---

## Environment

### Host

- Linux host
- Android NDK `r25c`
  - Download: [Android NDK r25c (official)](https://dl.google.com/android/repository/android-ndk-r25c-linux.zip)
- AFL++ `4.06c` built for Android (`afl-fuzz`, `afl-frida-trace.so`)
- `adb`

### Device

- rooted Android phone
- `su` available
- writable `/data/local/tmp`

---

## 1) Build the app and get `libfuzzme.so`

From Android Studio project:

```bash
git clone https://github.com/nyxFault/FuzzMeApp.git
cd /path/to/FuzzMeApp
printf "sdk.dir=%s\n" "$HOME/Android/Sdk" > local.properties
./gradlew :app:assembleDebug
```

Decode APK and inspect bundled arm64 library:

```bash
apktool d app/build/outputs/apk/debug/app-debug.apk -o app-debug
```

Optional: if you do not want to build locally, download the release APK and decode it:

```bash
wget -O app-debug.apk https://github.com/nyxFault/FuzzMeApp/releases/download/v1.0.0/app-debug.apk
apktool d app-debug.apk -o app-debug
```

Check exported symbols from extracted `.so`:

```bash
objdump -T "app-debug/lib/arm64-v8a/libfuzzme.so" | rg 'fuzzMe|Java_com_example_fuzzmeapp_MainActivity'
```

You should see `fuzzMe` exported.

---

## 2) Build external harness (Quarkslab style)

I used this tiny harness project:

```bash
git clone https://github.com/nyxFault/AndroidJNIFuzzing.git
cd AndroidJNIFuzzing/harness/
ls
```

```text
├── CMakeLists.txt
├── fuzz.c
└── afl.js
```

### `fuzz.c`

```c
#include <errno.h>
#include <stdint.h>
#include <stdio.h>

#define BUFFER_SIZE 1024
extern void fuzzMe(const uint8_t *buffer, uint64_t length);

void fuzz_one_input(const uint8_t *buf, int len) { fuzzMe(buf, (uint64_t)len); }

int main(void) {
  uint8_t buffer[BUFFER_SIZE];
  ssize_t rlength = fread((void *)buffer, 1, BUFFER_SIZE, stdin);
  if (rlength == -1) return errno;
  fuzz_one_input(buffer, (int)rlength);
  return 0;
}
```

### `CMakeLists.txt`

```cmake
project(FuzzMeAppHarness)
cmake_minimum_required(VERSION 3.8)

link_directories(${CMAKE_SOURCE_DIR}/lib)

add_executable(fuzz "fuzz.c")
set_property(TARGET fuzz APPEND_STRING PROPERTY LINK_FLAGS " -Wl,-rpath=$ORIGIN")
target_link_libraries(fuzz fuzzme)
```

### `afl.js` (persistent loop + include/exclude)

```javascript
const pStartAddr = DebugSymbol.fromName("fuzz_one_input").address;

const MODULE_WHITELIST = [
  "fuzz",
  "libfuzzme.so",
];

new ModuleMap().values().forEach(m => {
  if (!MODULE_WHITELIST.includes(m.name)) {
    Afl.addExcludedRange(m.base, m.size);
  }
});

const cm = new CModule(`
  #include <string.h>
  #include <gum/gumdefs.h>
  #define BUF_LEN 1024
  void afl_persistent_hook(GumCpuContext *regs, uint8_t *input_buf, uint32_t input_buf_len) {
    uint32_t length = (input_buf_len > BUF_LEN) ? BUF_LEN : input_buf_len;
    memcpy((void *)regs->x[0], input_buf, length);
    regs->x[1] = length;
  }
`, { memcpy: Module.getExportByName(null, "memcpy") });

Afl.setEntryPoint(pStartAddr);
Afl.setPersistentAddress(pStartAddr);
Afl.setPersistentHook(cm.afl_persistent_hook);
Afl.setPersistentCount(10000);
Afl.setInstrumentLibraries();
Afl.done();
```

### Build harness for Android arm64

```bash
cd /path/to/AndroidJNIFuzzing
mkdir -p harness/lib
cp "/path/to/FuzzMeApp/app-debug/lib/arm64-v8a/libfuzzme.so" harness/lib/

cmake -S harness \
      -B harness/build \
      -DANDROID_PLATFORM=31 \
      -DCMAKE_TOOLCHAIN_FILE=/path/to/android-ndk-r25c/build/cmake/android.toolchain.cmake \
      -DANDROID_ABI=arm64-v8a

cmake --build harness/build -j4
```

This step builds only the harness binary (`harness/build/fuzz`).
It does **not** build AFL++ binaries.

---

## 3) Build AFL++ binaries (`afl-fuzz` + `afl-frida-trace.so`)

```bash
cd /path/to/AndroidJNIFuzzing
git submodule update --init --recursive

cd AFLplusplus
curl -L https://raw.githubusercontent.com/quarkslab/android-fuzzing/main/AFLplusplus/CMakeLists.txt -o CMakeLists.txt

cmake -G "Unix Makefiles" \
      -DANDROID_PLATFORM=31 \
      -DCMAKE_TOOLCHAIN_FILE=/path/to/android-ndk-r25c/build/cmake/android.toolchain.cmake \
      -DANDROID_ABI=arm64-v8a \
      .
cmake --build . -- -j"$(nproc)"
```

After this, you should have:

```text
/path/to/AndroidJNIFuzzing/AFLplusplus/afl-fuzz
/path/to/AndroidJNIFuzzing/AFLplusplus/afl-frida-trace.so
```

---

## 4) Push artifacts to phone

```bash
adb shell "mkdir -p /data/local/tmp/fuzzme"
adb push /path/to/AndroidJNIFuzzing/AFLplusplus/afl-fuzz /data/local/tmp/fuzzme/
adb push /path/to/AndroidJNIFuzzing/AFLplusplus/afl-frida-trace.so /data/local/tmp/fuzzme/
adb push /path/to/AndroidJNIFuzzing/harness/build/fuzz /data/local/tmp/fuzzme/
adb push /path/to/AndroidJNIFuzzing/harness/afl.js /data/local/tmp/fuzzme/
adb push /path/to/AndroidJNIFuzzing/harness/lib/libfuzzme.so /data/local/tmp/fuzzme/
```

Prepare CPU governor + corpus:

Then prepare the environment on the device for our first fuzzing campaign (in root):

```bash
adb shell
# su
# cd /sys/devices/system/cpu
# echo performance | tee cpu*/cpufreq/scaling_governor

adb shell "sh -c \"cd /data/local/tmp/fuzzme && rm -rf in_fuzzme out_fuzzme && mkdir in_fuzzme out_fuzzme && dd if=/dev/urandom of=in_fuzzme/sample.bin bs=1 count=16\""
```

---

## 5) Run AFL++ Frida mode

Start fuzzing:

```bash
adb shell
# su
# cd /data/local/tmp/fuzzme

AFL_FRIDA_INST_NO_OPTIMIZE=1 AFL_FRIDA_INST_NO_PREFETCH=1 AFL_FRIDA_INST_NO_PREFETCH_BACKPATCH=1 ./afl-fuzz -O -G 1024 -i in_fuzzme -o out_fuzzme ./fuzz
```

Why these env vars?  
On newer devices we often hit Frida patching edge cases. These settings trade a bit of speed for stability.

Optional (if you face startup/handshake errors): add debug logs with `AFL_DEBUG=1`.

```bash
AFL_DEBUG=1 AFL_FRIDA_INST_NO_OPTIMIZE=1 AFL_FRIDA_INST_NO_PREFETCH=1 AFL_FRIDA_INST_NO_PREFETCH_BACKPATCH=1 \
./afl-fuzz -O -G 1024 -i in_fuzzme -o out_fuzzme ./fuzz
```

If `Ctrl+C` does not stop AFL, kill it from host:

```bash
adb shell "su -c 'pkill -INT afl-fuzz || pkill -TERM afl-fuzz || pkill -9 afl-fuzz'"
```

PID fallback:

```bash
adb shell "su -c 'ps -A | grep afl-fuzz'"
adb shell "su -c 'kill -INT <pid> || kill -TERM <pid> || kill -9 <pid>'"
```

---

## 6) Wait for crash, then triage

Monitor crash count:

```bash
adb shell "su -c 'sh -c \"cd /data/local/tmp/fuzzme && ls out_fuzzme/default/crashes/id:* 2>/dev/null | wc -l\"'"
```

Dump crash input:

```bash
adb shell "sh -c \"cd /data/local/tmp/fuzzme && xxd out_fuzzme/default/crashes/id:*\""
```

In my run:

```text
00000000: 4675 7a7a 4d65 4031 3233 e0e0 e0e0 e0e0  FuzzMe@123......
00000010: e0e0 3275                                ..2u
```

So AFL found an input beginning with `FuzzMe@123` and triggered SIGSEGV as expected.

---

## Common pain points (aka why your campaign dies in 3 seconds)

### 1) `Fork server handshake failed`

Usually one of:

- bad `afl.js` (forgot `Afl.done()`)
- too much instrumentation scope
- unstable Frida options on your ROM/device

### 2) No new coverage forever

This was interesting in my setup too.  
When `fuzzMe` was a simple `std::string::find`, coverage was boring.  
When switched to branch ladder checks, AFL got a much better gradient and improved path discovery.

### 3) “Works manually, not in AFL”

Remember AFL assumptions:

- target must behave deterministic enough
- harness must avoid external side effects
- all needed shared libs should be loaded before execution path enters target

---

![fuzzing speed](https://media.giphy.com/media/l3q2K5jinAlChoCLS/giphy.gif)

*When `exec/s` goes up and crashes are still 0, but you pretend this is fine.*

---

## Repro one-liner (compact)

If your files are already in `/data/local/tmp/fuzzme`:

```bash
adb shell "su -c 'sh -c \"cd /data/local/tmp/fuzzme && \
rm -rf out_fuzzme && mkdir out_fuzzme && \
AFL_FRIDA_INST_NO_OPTIMIZE=1 AFL_FRIDA_INST_NO_PREFETCH=1 AFL_FRIDA_INST_NO_PREFETCH_BACKPATCH=1 \
./afl-fuzz -O -G 1024 -i in_fuzzme -o out_fuzzme ./fuzz\"'"
```

Optional troubleshooting variant:

```bash
adb shell "su -c 'sh -c \"cd /data/local/tmp/fuzzme && \
rm -rf out_fuzzme && mkdir out_fuzzme && \
AFL_DEBUG=1 AFL_FRIDA_INST_NO_OPTIMIZE=1 AFL_FRIDA_INST_NO_PREFETCH=1 AFL_FRIDA_INST_NO_PREFETCH_BACKPATCH=1 \
./afl-fuzz -O -G 1024 -i in_fuzzme -o out_fuzzme ./fuzz\"'"
```

---

## Final thoughts

This workflow is very close to the Quarkslab `qb.blogfuzz` style, but adapted to a custom JNI-backed Android app:

- build target `.so`
- export a deterministic fuzz function
- external harness + Frida persistent hook
- run AFL on rooted phone
- triage crash corpus

Happy crashing 🍻

---

## Credits

Big shoutout to Quarkslab for the original inspiration and methodology:

- [Android greybox fuzzing with AFL++ Frida mode (Quarkslab)](https://blog.quarkslab.com/android-greybox-fuzzing-with-afl-frida-mode.html)
