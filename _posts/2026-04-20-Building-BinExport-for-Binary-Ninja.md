---
title: "How I Built BinExport for Binary Ninja (and Made It Actually Work)"
categories: [Reversing, Binary Ninja]
tags: [binary-ninja, binexport, reverse-engineering, plugin, linux]
---

I wanted a clean BinDiff workflow from Binary Ninja, which means one thing first: get reliable `.BinExport` files out of Binja.

I thought this would take 5 minutes. It did not.

I hit multiple issues:

- debugger plugin missing library
- BinExport plugin not showing in menu
- ABI mismatch errors
- one build that loaded but crashed when I clicked `BinExport`

This post is the exact path I used, in simple steps, with the commands I actually ran.

![Me after third plugin rebuild](https://media.giphy.com/media/v1.Y2lkPTc5MGI3NjExMnNob2ZqYXQwZW1hajJjd3R1Y2M1aXB2NWJ6Z2N4NWR5Y3Z4aW5sNiZlcD12MV9naWZzX3NlYXJjaCZjdD1n/3o7aD2saalBwwftBIY/giphy.gif)

---

## Goal

My end state here was:

- Binary Ninja shows `BinExport` in UI
- click works without crashing
- output file gets generated correctly (`something.BinExport`)

---

## Step 1: Fix Binary Ninja debugger/plugin runtime first

Before BinExport, I hit:

- `libdebuggercore.so` failed to load
- `libxml2.so.2: cannot open shared object file`

On my system, `libxml2.so.16` existed (Kali rolling), but Binary Ninja expected `.so.2`.

I fixed it by placing a compatibility symlink where BN loader paths already search:

```bash
ln -sf /usr/lib/x86_64-linux-gnu/libxml2.so.16.1.2 \
  /home/fury/binaryninja/plugins/lldb/lib/libxml2.so.2
```

After that, debugger plugins loaded cleanly.

Quick check command:

```bash
ldd /home/fury/binaryninja/plugins/libdebuggercore.so | rg "libxml2|not found"
```

If you still see `not found`, fix this first before touching BinExport.

![Dependency errors everywhere](https://media.giphy.com/media/v1.Y2lkPTc5MGI3NjExa2Q3d2x6aWw4dHh6bWQ0NWFlaW5wdHA0eDZlYnd4cTZ0aWdnMW40cCZlcD12MV9naWZzX3NlYXJjaCZjdD1n/l0IylOPCNkiqOgMyA/giphy.gif)

---

## Step 2: Install BinExport/BinDiff and verify load

I installed BinExport/BinDiff binaries, but BinExport still did not show in `Plugins`.

Initial checks:

- plugin file existed
- manual `dlopen` worked
- but no BinExport command registered in Binary Ninja UI

This means “file present” is not enough; Binary Ninja still rejects/ignores plugin registration for ABI/version reasons.

Useful checks:

```bash
ls -la /home/fury/binaryninja/plugins | rg binexport
ldd /home/fury/binaryninja/plugins/binexport12_binaryninja.so | rg "not found|libbinaryninjacore"
```

Also check user plugin folder because BN loads from there too:

```bash
ls -la ~/.binaryninja/plugins | rg binexport
```

---

## Step 3: Identify the real blocker: ABI mismatch

The key log was:

> This plugin was built for a newer version of Binary Ninja (100).  
> Please update Binary Ninja or rebuild the plugin with the matching API version (65).

That told me exactly what to do: rebuild for ABI 65.

I verified ABI directly from plugin symbols (`CorePluginABIVersion`) and stopped guessing.

Command I used to read plugin ABI:

```bash
LD_LIBRARY_PATH=/home/fury/binaryninja:/home/fury/binaryninja/plugins \
python3 - <<'PY'
import ctypes
so = ctypes.CDLL("/home/fury/.binaryninja/plugins/binexport12_binaryninja.so")
f = so.CorePluginABIVersion
f.restype = ctypes.c_uint32
print(f())
PY
```

If Binary Ninja says plugin needs API 65 and this prints 100, plugin will not load.

---

## Step 4: Rebuild BinExport from source

I rebuilt BinExport locally instead of using prebuilt plugin binaries.

High-level build flow:

```bash
git clone https://github.com/google/binexport.git
cd binexport
mkdir build && cd build
cmake .. -G Ninja \
  -DCMAKE_BUILD_TYPE=Release \
  -DBINEXPORT_ENABLE_BINARYNINJA=ON \
  -DBINEXPORT_ENABLE_IDAPRO=OFF \
  -DBINEXPORT_BUILD_TESTING=OFF
cmake --build . -j"$(nproc)"
```

Then I installed the built plugin into user plugin directory:

```bash
cp binaryninja/binexport12_binaryninja.so ~/.binaryninja/plugins/
cp binaryninja/binexport12_binaryninja.so ~/.binaryninja/plugins/libbinexport12_binaryninja.so
chmod 755 ~/.binaryninja/plugins/binexport12_binaryninja.so
```

I also removed stale disabled plugin files because they can shadow new builds:

```bash
rm -f ~/.binaryninja/plugins/binexport12_binaryninja.so.disabled
rm -f ~/.binaryninja/plugins/binexport12_binaryninja.so.abi-mismatch-disabled
rm -f ~/.binaryninja/plugins/binexport12_binaryninja.so.api100.disabled
```

![Rebuild again](https://media.giphy.com/media/v1.Y2lkPTc5MGI3NjExdGQ2b2YwNGQwazQxM3Ixb2oxbnRjY3Mzd2VxMm5idXZqY2szbWJvZiZlcD12MV9naWZzX3NlYXJjaCZjdD1n/26ufdipQqU2lhNA4g/giphy.gif)

---

## Step 5: Fix “loads but closes Binja on click”

One intermediate build loaded but clicking `BinExport` closed the window.

That was a runtime compatibility problem: load succeeded, execution path still not stable.

I switched to an older BinExport source tag that matched my Binary Ninja generation better:

```bash
git checkout v12-20220607-binaryninja_3.1
```

Then rebuilt and reinstalled. That removed the click-crash.

Main lesson: “plugin loads” is not the same as “plugin is runtime stable”.

---

## Step 6: Validate command registration

To confirm command registration in my Binary Ninja build:

```python
from binaryninjaui import UIContext
from binaryninja.plugin import PluginCommand, PluginCommandContext

ctx = UIContext.activeContext()
vf = ctx.getCurrentViewFrame()
bv_real = vf.getCurrentViewInterface().getData()
cmds = PluginCommand.get_valid_list(PluginCommandContext(bv_real))
print("\n".join(sorted([k for k in cmds.keys() if "export" in k.lower() or "bin" in k.lower()])))
```

When this prints `BinExport`, you’re good.

---


## Why it does not ask save location

This plugin build writes output non-interactively (no save dialog).

Example log:

```text
Writing to: "/path/to/old.BinExport"
... exported N functions with M instructions
```

Output path is derived from currently opened file/database name, with extension replaced by `.BinExport`.

So if you open:

`/home/fury/Desktop/DiffLab/binja_diff/old`

it writes:

`/home/fury/Desktop/DiffLab/binja_diff/old.BinExport`

---

## Final workflow

Now my working Binary Ninja loop is:

1. Open binary in Binary Ninja.
2. Run `BinExport`.
3. Get `target.BinExport` next to the binary/database.
4. Repeat for second binary.
5. Diff both `.BinExport` files in BinDiff.

Quick sanity checklist before diffing:

- both files exported from same architecture target
- both analyses finished in Binja before export
- both `.BinExport` files are non-empty

---

## Takeaways

- Check ABI first; don’t trust “it copied fine”.
- Remove stale disabled plugin files.
- “Loads” and “works when clicked” are separate checkpoints.
- If prebuilt plugins fight your environment, source build wins.

If you are on a rolling distro and mixed reverse-engineering toolchain, expect to do at least one local rebuild. Once aligned, it is stable.

![Finally works](https://media.giphy.com/media/v1.Y2lkPTc5MGI3NjExODRoM3NlbjB6eWlyOGN3aDN3Y2Q1N2ljdGF2aWUza2xwaGQ2eGRrbiZlcD12MV9naWZzX3NlYXJjaCZjdD1n/11sBLVxNs7v6WA/giphy.gif)

