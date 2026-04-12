---
title: "Fuzzing from Scratch with libFuzzer"
categories: [Fuzzing, LLVM]
tags: [fuzzing, libfuzzer, clang, llvm, sanitizers]
---

## What libFuzzer is

**libFuzzer** is LLVM’s **in-process**, **coverage-guided** fuzzer. You compile your target **with the fuzzer runtime** (`-fsanitize=fuzzer`), implement a single callback **`LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)`**, and the engine feeds your code **mutated byte buffers** at high speed. Instrumentation records **which edges** of the control-flow graph execute; inputs that reach **new coverage** are kept in a **corpus** and mutated further. That feedback loop is why it often finds bugs faster than blind random testing.

libFuzzer is **not** a separate daemon like AFL’s `afl-fuzz` talking to a forked process: the fuzzer **runs inside your binary** (it supplies `main` when you link with `-fsanitize=fuzzer`). You typically pair it with **sanitizers**, especially **AddressSanitizer** (`-fsanitize=address`), so heap/stack overflows, use-after-frees, and many other issues **abort with a report** the moment they happen.

![Keyboard smash / chaos energy](https://media.giphy.com/media/l3q2K5jinAlChoCLS/giphy.gif)

*Coverage-guided fuzzing: thousands of weird inputs per second and you get to watch.*

---

## Installing Clang (and libFuzzer support)

libFuzzer **ships with Clang** as part of LLVM’s **compiler-rt** runtimes. You do **not** install “libfuzzer” from PyPI or a separate tarball; you install a **recent Clang** and use **`clang -fsanitize=fuzzer`**.

### Debian / Ubuntu / Kali (apt)

```bash
sudo apt update
sudo apt install clang build-essential
```

That is enough for the examples in this post. Optional but useful for readable sanitizer stacks:

```bash
sudo apt install llvm
```

Ensure **`llvm-symbolizer`** is on your **`PATH`** (the `llvm` package often provides it). AddressSanitizer uses it to turn addresses into file/line in stack traces.

### Other platforms

- **Fedora / RHEL**: `sudo dnf install clang llvm`.
- **Arch**: `sudo pacman -S clang llvm`.
- **macOS** (Homebrew): `brew install llvm` and use **`$(brew --prefix llvm)/bin/clang`** if you want the latest LLVM; Apple’s **`clang`** on Xcode usually includes fuzzer support as well.

### Verify that fuzzing works

Check Clang:

```bash
clang --version
```

Compile a **minimal fuzz target** (empty input handler is enough):

```bash
printf '%s\n' \
'#include <stddef.h>
#include <stdint.h>
int LLVMFuzzerTestOneInput(const uint8_t *d, size_t s) { (void)d; (void)s; return 0; }' \
| clang -x c -fsanitize=fuzzer,address - -o /tmp/fuzz_smoke
```

If that succeeds, **libFuzzer and AddressSanitizer** are available. Run it once:

```bash
/tmp/fuzz_smoke -runs=1
```

You should see libFuzzer’s usual log lines (`INFO:`, `Running 1 inputs`, etc.). Remove **`/tmp/fuzz_smoke`** when done.

![Relief / thumbs up](https://media.giphy.com/media/111ebonMs90YLu/giphy.gif)

*Smoke test passed. Your toolchain actually has `fuzzer` + `address`.*

---

## Demo in one paragraph

The toy program only accepts inputs that start with the **four bytes of `0xDEADBEEF`** (big-endian: **`de ad be ef`**). It builds **`prefix || input`**, then **`memcpy`s** into **`buf[16]`** without checking length. Overflow when **`4 + size > 16`** (**`size > 12`**) after the prefix matches.

### `compare_target.h`

```c
#ifndef COMPARE_TARGET_H
#define COMPARE_TARGET_H

#include <stddef.h>
#include <stdint.h>

/* Input must start with the four bytes of 0xDEADBEEF (de ad be ef); then unsafe copy. */
void vulnerable_copy(const uint8_t *data, size_t size);

#endif
```

### `compare_target.c`

```c
#include "compare_target.h"

#include <stdint.h>
#include <string.h>

#define BUF_LEN 16

/*
 * Magic: 0xDEADBEEF. Bytes on the wire (big-endian order) are de ad be ef, the usual
 * way this constant is written in hex dumps and compared byte-for-byte.
 */
#define K_MAGIC_U32 0xDEADBEEFu

static const uint8_t k_prefix[] = {
    (uint8_t)((K_MAGIC_U32 >> 24) & 0xffu),
    (uint8_t)((K_MAGIC_U32 >> 16) & 0xffu),
    (uint8_t)((K_MAGIC_U32 >> 8) & 0xffu),
    (uint8_t)(K_MAGIC_U32 & 0xffu),
};
#define PREFIX_LEN (sizeof(k_prefix))

#define COMBINED_MAX 5000u

void vulnerable_copy(const uint8_t *data, size_t size) {
  char buf[BUF_LEN];
  char combined[COMBINED_MAX];

  if (size < PREFIX_LEN) {
    return;
  }
  if (memcmp(data, k_prefix, PREFIX_LEN) != 0) {
    return;
  }

  if (PREFIX_LEN + size > COMBINED_MAX) {
    return;
  }

  memcpy(combined, k_prefix, PREFIX_LEN);
  memcpy(combined + PREFIX_LEN, data, size);

  size_t total = PREFIX_LEN + size;
  /* BUG: copies full combined length into tiny buf */
  memcpy(buf, combined, total);
}
```

### `fuzz_harness.c`

```c
#include <stddef.h>
#include <stdint.h>

#include "compare_target.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  vulnerable_copy(data, size);
  return 0;
}
```

### `Makefile`

```makefile
# libFuzzer demo: clang with -fsanitize=address,fuzzer

CC     := clang
CFLAGS := -Wall -Wextra -g
SAN    := -fsanitize=address,fuzzer
TARGET := fuzz_compare
SRCS   := compare_target.c fuzz_harness.c

.PHONY: all clean run

all: $(TARGET)

$(TARGET): $(SRCS) compare_target.h
	$(CC) $(CFLAGS) $(SAN) -o $@ $(SRCS)

run: $(TARGET)
	./$(TARGET) -max_total_time=30 corpus/

clean:
	rm -f $(TARGET) crash-* oom-* timeout-* slow-*
```

---

### Build

```bash
make
# or:
# clang -Wall -Wextra -g -fsanitize=address,fuzzer \
#   -o fuzz_compare compare_target.c fuzz_harness.c
```

---

### Run

```bash
./fuzz_compare corpus/
```

Put one or more **seed files** under **`corpus/`** (they can be tiny). libFuzzer loads them, then mutates and merges interesting inputs; **`-max_total_time=N`** stops after N seconds for quick experiments.

---

### What a real run looks like

Coverage climbs until comparisons against the magic start succeeding. LLVM’s **compare instrumentation** can log a **persistent dictionary** token **`DE:`** with **octal escapes**. Those bytes are still **`0xDE` `0xAD` `0xBE` `0xEF`**:

```text
#211 REDUCE cov: 7 ft: 8 corp: 3/9b lim: 5 exec/s: 0 rss: 46Mb L: 4/4 MS: 1 CMP- DE: "\336\255\276\357"-
```

Shortly after, **AddressSanitizer** may abort on the final **`memcpy`** (example: **17-byte** write into **`buf[16]`**):

```text
==328828==ERROR: AddressSanitizer: stack-buffer-overflow on address ...
WRITE of size 17 at ...
    #1 0x... in vulnerable_copy .../compare_target.c:44:3
    #2 0x... in LLVMFuzzerTestOneInput .../fuzz_harness.c:7:3
```

libFuzzer writes a **reproducer** file (**`crash-*`**) and often prints **hex** and **Base64**:

```text
0xde,0xad,0xbe,0xef,0xad,0xde,0xad,0xde,0xad,0xbe,0xef,0xbe,0xef,
Base64: 3q2+763erd6tvu++7w==
```

The payload begins with **`deadbeef`**; extra bytes increase **`size`** so **`total`** exceeds **16**.

![Celebration / we have a file](https://media.giphy.com/media/26BRv0ThflsHCqDrG/giphy.gif)

*You wanted a crash artifact. The fuzzer delivered.*

### Read the crash file with **`xxd`**

```text
$ xxd ./crash-530a36203a3efc91fde624b2d8aa0dc828d0e1a3
00000000: dead beef adde adde adbe efbe ef         .............
```

---

### Fix (for a non-vulnerable binary)

Bound **`total`** before **`memcpy` to `buf`**, or allocate **`buf`** with size at least **`total`**.

![This is fine](https://media.giphy.com/media/NTur7XlVDUdqM/giphy.gif)

*Shipping without bounds checks. Totally fine. (No. Fix it.)*

---

### Further reading (official)

- LLVM **Fuzzing** docs: [LLVM libFuzzer](https://llvm.org/docs/LibFuzzer.html) (flags, dictionaries, merging corpora, custom mutators).
