---
title: "How I Fixed BinExport + BinDiff in Binary Ninja"
categories: [Reversing, Binary Ninja]
tags: [binary-ninja, binexport, bindiff, reverse-engineering, plugin, linux]
---

I wanted the usual workflow:

- open target in Binary Ninja
- export `.BinExport`
- compare in BinDiff
- not fight plugin errors at 2am

What I got instead:

```text
[Default] Plugin module '/home/fury/.binaryninja/plugins/binexport12_binaryninja.so' failed to load
[Default] This plugin was built for an outdated core ABI. Please rebuild the plugin with the latest API (65).
```

If you are seeing this exact thing: this post is your shortcut.

![Me after "quick plugin setup"](https://media.giphy.com/media/v1.Y2lkPTc5MGI3NjExMnNob2ZqYXQwZW1hajJjd3R1Y2M1aXB2NWJ6Z2N4NWR5Y3Z4aW5sNiZlcD12MV9naWZzX3NlYXJjaCZjdD1n/3o7aD2saalBwwftBIY/giphy.gif)

---

## The real problem

This was not a Binary Ninja core bug.  
It was a **stale user plugin symlink** pointing to an old BinDiff package plugin.

My bad symlink:

```bash
ls -la ~/.binaryninja/plugins | rg binexport
```

Output on my box:

```bash
/home/fury/.binaryninja/plugins/binexport12_binaryninja.so -> /opt/bindiff/plugins/binaryninja/binexport12_binaryninja.so
```

That `/opt/bindiff/...` one was built for an older Binary Ninja core API.

---

## Verify ABI instead of guessing

I checked the plugin ABI by disassembling `CorePluginABIVersion`:

```bash
objdump -d --disassemble=CorePluginABIVersion \
  ~/.binaryninja/plugins/libbinexport12_binaryninja.so
```

Look for:

```text
mov    $0x41,%eax
```

`0x41` hex = `65` decimal (the ABI my Binary Ninja wanted).

If you get a value lower than your current Binary Ninja API requirement, that plugin is too old.

---

## Fix (the 30-second version)

Replace the stale symlink and point it to the ABI 65 local library:

```bash
rm -f ~/.binaryninja/plugins/binexport12_binaryninja.so
ln -s ~/.binaryninja/plugins/libbinexport12_binaryninja.so \
  ~/.binaryninja/plugins/binexport12_binaryninja.so
```

Confirm:

```bash
ls -la ~/.binaryninja/plugins | rg binexport12_binaryninja
```

---

## What about the Binary Ninja install plugin dir?

You might also have another BinExport library under:

- `/home/fury/binaryninja/plugins/libbinexport12_binaryninja.so`

That is fine. The key is: the plugin Binary Ninja actually loads from your user plugin path must match your current ABI.

No need to overcomplicate this unless you are building from source on purpose.

---

## Verify in UI

After restart:

- open a binary
- run `BinExport`
- check output file exists next to your target (`*.BinExport`)

---

## Clean BinDiff workflow in Binja

Once fixed, this is all I do:

1. Open binary in Binary Ninja.
2. Run `BinExport`.
3. Get `target.BinExport`.
4. Repeat for second binary.
5. Diff both `.BinExport` files in BinDiff.

---

## Quick troubleshooting checklist

If BinExport still fails in Binary Ninja:

1. `ls -la ~/.binaryninja/plugins | rg binexport`
2. make sure `binexport12_binaryninja.so` does **not** point to `/opt/bindiff/...`
3. check ABI from `CorePluginABIVersion` (`0x41` for ABI 65)
4. restart Binary Ninja completely
5. test on a small binary first

The big lesson: **plugin path precedence matters more than people think**.  
One stale symlink can waste an entire afternoon.

![Finally works](https://media.giphy.com/media/v1.Y2lkPTc5MGI3NjExODRoM3NlbjB6eWlyOGN3aDN3Y2Q1N2ljdGF2aWUza2xwaGQ2eGRrbiZlcD12MV9naWZzX3NlYXJjaCZjdD1n/11sBLVxNs7v6WA/giphy.gif)