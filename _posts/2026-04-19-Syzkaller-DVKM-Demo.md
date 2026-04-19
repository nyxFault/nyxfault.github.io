---
title: "Syzkaller Part 2: A Damn Vulnerable Kernel Module, Syzlang, and the Full Demo Pipeline"
categories: [Fuzzing, Syzkaller, Kernel]
tags: [linux, kernel, syzkaller, fuzzing, dvkm, syzlang, ioctl, kasan]
---

**Part 2** of the Syzkaller writeup. [Part 1]({% post_url 2025-07-22-Syzkaller %}) covered layout, install, and building a fuzzable **6.19** kernel for QEMU. Here I bolt on a deliberately broken driver, wire syzkaller to it with syzlang, run the manager, and follow crashes into reproducers and a tiny hand-written C program.

Lab and education only. Do not paste this into a product kernel unless you enjoy incident response.

![Production kernel deploy of demo-only code — this is fine](https://media1.giphy.com/media/v1.Y2lkPTc5MGI3NjExNjFkOWU2Mzh6N2V0aW12c3d4bjFyNjFsczQxdHg3djVubzRiY21lMSZlcD12MV9pbnRlcm5hbF9naWZfYnlfaWQmY3Q9Zw/iH2IldVkqeLuJ7eJ0L/giphy.gif)

---

## Pieces on the bench

| Piece | Purpose |
|------|---------|
| `DVKM` misc driver | `/dev/dvkm`, ioctls that botch sizes and lifetimes on purpose |
| `include/uapi/linux/dvkm.h` | Ioctl numbers + packed structs for userspace and tooling |
| `sys/linux/dev_dvkm.txt` | Syzlang: `openat$dvkm`, `ioctl$DVKM_*`, shapes for args |
| `make descriptions` | Regenerates syscall metadata so `openat$dvkm` exists in binaries |
| Manager JSON | Either full syscall set or a short `enable_syscalls` list for demos |

---

## What the driver does

Code lives at `drivers/misc/dvkm.c`, enabled with `CONFIG_DVKM=y`, registered as a misc device.

Three intentional patterns:

1. **Heap**: `kmalloc(32)`, then `copy_from_user` with a user-controlled length (too large).
2. **Stack**: 128-byte buffer on stack, same bad trust in length.
3. **UAF**: ioctl ops for alloc / free / use, but the pointer is not cleared after `kfree`.

With KASAN and hardened usercopy you tend to see either a sanitizer report or `__copy_overflow` with a stack that mentions `dvkm_ioctl`. Good enough for a live demo.

![Deliberately vulnerable code for the classroom](https://media0.giphy.com/media/v1.Y2lkPTc5MGI3NjExYXh1eTc3dGxsa244ajZhcTMyeGtmcjN3ZGVmc3Z1NHQ3YWIwdW12byZlcD12MV9pbnRlcm5hbF9naWZfYnlfaWQmY3Q9Zw/NuQKy3ydPtFVKggRCp/giphy.gif)

---

## UAPI header

Ioctl commands use `_IOWR` / `_IOW`. Structs are packed so the size baked into the ioctl number matches what userspace and the fuzzer send:

```c
#define DVKM_IOC_MAGIC 0xD8

struct dvkm_heap_overflow {
    __u64 user_ptr;
    __u32 len;
} __attribute__((packed));

#define DVKM_IOCTL_HEAP_OVERFLOW _IOWR(DVKM_IOC_MAGIC, 1, struct dvkm_heap_overflow)
```

Full file sits beside the kernel tree: `include/uapi/linux/dvkm.h`.

---

## Syzlang file

Descriptions are not C. You define a `fd_dvkm` resource, `openat$dvkm` pointing at `/dev/dvkm`, and per-ioctl lines. Command codes can be literal hex if you do not want to run header extraction yet:

```text
ioctl$DVKM_IOCTL_HEAP_OVERFLOW(fd fd_dvkm, cmd const[0xc00cd801], arg ptr[in, dvkm_heap_overflow])
```

After any edit under `sys/linux/`:

```bash
cd /path/to/syzkaller
rm -f .descriptions   # optional, forces a full regen
make descriptions
make manager target   # or plain make
```

Skip `make descriptions` and `openat$dvkm` never lands in `bin/syz-manager`. Configs that whitelist `openat$dvkm` in `enable_syscalls` then die with `unknown enabled syscall`. I hit that once with a stale build; rebuilding fixed it.

![Forgot `make descriptions` and the manager is mad](https://media0.giphy.com/media/v1.Y2lkPTc5MGI3NjExYndvdTJqeHo2aWh5bDZ1cGF5dGlxbGZicWpjcHdxNDZ4NzFkM2tpZCZlcD12MV9pbnRlcm5hbF9naWZfYnlfaWQmY3Q9Zw/TJawtKM6OCKkvwCIqX/giphy.gif)

---

## Adding DVKM to the kernel (step by step)

The driver is not in upstream Linux. You add a small set of files under your kernel tree, wire Kbuild, turn the option on, rebuild, and boot. Do this on a copy of the tree you already use for syzkaller (same version you intend to fuzz).

### 1. Files and where they live

| Path | Role |
|------|------|
| `include/uapi/linux/dvkm.h` | UAPI: ioctl numbers, packed structs, `enum` for UAF ops. Userspace and syzkaller include this by path. |
| `drivers/misc/dvkm.c` | The misc device driver: `/dev/dvkm`, `unlocked_ioctl`, the intentional bugs. |

`dvkm.c` includes `<uapi/linux/dvkm.h>` so the ioctl definitions match in one place.

### 2. Hook it into `drivers/misc`

**`drivers/misc/Makefile`** (append one line):

```make
obj-$(CONFIG_DVKM)		+= dvkm.o
```

**`drivers/misc/Kconfig`** (inside the `menu "Misc devices"` block, before `endmenu`):

```kconfig
config DVKM
	bool "Damn Vulnerable Kernel Module (fuzzing demo only)"
	default n
	help
	  Exposes /dev/dvkm with intentional bugs for research demos only.
	  Do not enable in production kernels.
```

Run `make menuconfig` later and you will find it under **Device Drivers** then **Misc devices**, or set the symbol from the command line (below).

### 3. Enable the option

Pick one approach.

**A. Kconfig fragment (good for automation)**  
If you already merge a syzkaller-oriented fragment (see Part 1), add:

```text
CONFIG_DVKM=y
```

Then:

```bash
./scripts/kconfig/merge_config.sh -m .config your-fragment.config
make olddefconfig
```

**B. Interactive**

```bash
make menuconfig
```

Navigate to **Device Drivers** → **Misc devices** → enable **Damn Vulnerable Kernel Module**. Save and exit.

**C. One-shot without menu**

```bash
./scripts/config --enable DVKM
make olddefconfig
```

### 4. Built-in (`y`) vs module (`m`)

| Choice | When to use |
|--------|-------------|
| **`CONFIG_DVKM=y`** | Simplest for QEMU demos. The driver is always there; `/dev/dvkm` exists as soon as the kernel boots. No `insmod`, no copying `dvkm.ko` into the disk image. |
| **`CONFIG_DVKM=m`** | You load it by hand or from an init script. You must install `drivers/misc/dvkm.ko` into the guest’s `/lib/modules/$(uname -r)/` (or `scp` it in and `insmod`). Easy to forget. |

For fewer surprises, use **`y`** unless you have a reason to keep it modular.

### 5. Build

From the kernel tree:

```bash
make olddefconfig
make -j"$(nproc)"
```

Fix compile errors before moving on. Typical first-time issues:

- **`misc_unregister` vs `misc_deregister`**: older examples use `misc_unregister`; current trees expose **`misc_deregister`** (see `include/linux/miscdevice.h`). If the compiler complains about an implicit declaration, fix the name to match your kernel version.
- **Missing header**: `dvkm.c` must see `include/uapi/linux/dvkm.h`. It should if the file is under `include/uapi/linux/`.

Outputs you need for syzkaller unchanged: **`vmlinux`**, **`arch/x86/boot/bzImage`**.

### 6. Sanity check after boot

On the guest (or QEMU serial shell):

```bash
ls -l /dev/dvkm
```

You want a char device (misc creates it with the name `dvkm`). If it is missing:

- Confirm you booted **this** `bzImage` (not an old kernel).
- For **`=m`**, run `lsmod | grep dvkm` and load the module if needed.
- Check `dmesg` for registration errors.

Optional quick test (as root):

```bash
python3 -c "import os,fcntl; f=os.open('/dev/dvkm',os.O_RDWR); print('ok', f)"
```

If that opens, the node and permissions are fine.

### 7. VM image and permissions

The syzkaller image usually runs fuzzing as **root**, so `0666` on the misc device (if you set that in code) or root-only access both work. If you tighten permissions later, keep syzkaller’s executor able to open the device.

### 8. Checklist before you fuzz

- [ ] `include/uapi/linux/dvkm.h` present  
- [ ] `drivers/misc/dvkm.c` present  
- [ ] `drivers/misc/Makefile` has `obj-$(CONFIG_DVKM)`  
- [ ] `drivers/misc/Kconfig` has `config DVKM`  
- [ ] `CONFIG_DVKM=y` (or `m` + module installed in guest)  
- [ ] Full rebuild done, **`bzImage` copied or pointed to by syzkaller config**  
- [ ] Guest shows **`/dev/dvkm`** after boot  

Once that is green, wire syzkaller (`dev_dvkm.txt`, `make descriptions`, manager config) as in the sections above.

---

## Two config styles

**Full fuzz:** point `kernel_obj`, `image`, `sshkey`, and `vm.kernel` at your `bzImage` and disk. Leave `enable_syscalls` out so everything in the description set can fire.

**Narrow demo:** set `enable_syscalls` to `openat$dvkm`, the `ioctl$DVKM_*` names, plus helpers like `mmap`, `close`, `munmap`. Logs get easier to read for a talk; coverage numbers shrink. Use a separate workdir (e.g. `workdir-dvkm`) so you do not mix corpora with a wide fuzz run.

---

## Crash output layout

![The guest oopsed and you get artifacts under `workdir/crashes/`](https://media.giphy.com/media/26BRv0ThflsHCqDrG/giphy.gif)

When the guest dies interestingly, `syz-manager` writes under:

```text
<workdir>/crashes/<hash>/
```

Useful names:

| File | What it is |
|------|------------|
| `logN` | Raw log from executor / kernel |
| `reportN` | Parsed report |
| `repro.prog` | Minimized syz program if repro succeeded |
| `repro.cprog` | C output only if that stage succeeded |
| `repro0` … `repro2` | Logs from failed automatic repro attempts, not a working PoC |

Do not assume you get `repro.cprog`. Often you stop at `repro.prog`. Upstream doc: [Reproducing crashes](https://github.com/google/syzkaller/blob/master/docs/reproducing_crashes.md).

---

## syz-repro

Same manager JSON as fuzzing, one argument: a **single** crash log file (e.g. `log0`), not the whole directory:

```bash
./bin/syz-repro -config=trixie-fuzz-dvkm.cfg \
  ./workdir-dvkm/crashes/<id>/log0
```

Remember: regenerate syscall descriptions and rebuild `syz-repro` after adding `dev_dvkm.txt`. Pass a file path. If `enable_syscalls` keeps biting you during repro, point at a config without that key but with the same QEMU/kernel/image.

---

## Hand-written C PoC

For a demo you sometimes want a twenty-line program: open `/dev/dvkm`, one ioctl with `len` bigger than the kmalloc, no dependency on syzkaller's C generator. Build it, `scp` to the guest, run, read `dmesg`. Boring but reliable when `repro.cprog` never appears.

---

## Wrap-up

You end up with: fuzzable kernel, silly driver in-tree, syzlang so the fuzzer reaches it, manager for continuous runs, optional `syz-repro` on a saved log, and a manual C file when you need a guaranteed slide.

![End-to-end demo pipeline complete](https://media.giphy.com/media/111ebonMs90YLu/giphy.gif)

**[Back to Part 1]({% post_url 2025-07-22-Syzkaller %})**

---

## References

- [Syscall descriptions](https://github.com/google/syzkaller/blob/master/docs/syscall_descriptions.md)
- [Syntax](https://github.com/google/syzkaller/blob/master/docs/syscall_descriptions_syntax.md)
- [Reproducing crashes](https://github.com/google/syzkaller/blob/master/docs/reproducing_crashes.md)
- [Kernel configs](https://github.com/google/syzkaller/blob/master/docs/linux/kernel_configs.md)
