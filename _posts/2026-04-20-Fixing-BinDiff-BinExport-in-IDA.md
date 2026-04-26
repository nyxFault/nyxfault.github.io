---
title: "Installing BinDiff + BinExport on IDA Pro 9.1 (Linux, No Tears Edition)"
categories: [Reversing, IDA]
tags: [ida, ida-pro-9.1, bindiff, binexport, reverse-engineering, linux]
---

I wanted a simple thing:

- Open `ida64`
- Export with BinExport
- Diff with BinDiff
- Not get yelled at by plugin loader logs

Instead, I got this:

```text
/home/fury/.idapro/plugins/binexport12_ida.so: can't load file
BinExport 12 (@f2abe5a, Jul  4 2025), (c)2004-2011 zynamics GmbH, (c)2011-2025 Google LLC
```

Classic Linux RE setup moment.

![Me opening IDA after "just one quick plugin install"](https://media.giphy.com/media/v1.Y2lkPTc5MGI3NjExa3JzdnN2MHpwM3BvY3N4dDdzOHp5MzhxNW5uN2N4OWVnM3B6dW9wYSZlcD12MV9naWZzX3NlYXJjaCZjdD1n/11tTNkNy1SdXGg/giphy.gif)

---

## TL;DR fix

For IDA Pro 9.1 on Linux, use the **64-bit plugin only**:

- keep `binexport12_ida64.so`
- remove `binexport12_ida.so` (32-bit)

If `binexport12_ida.so` is present, IDA may try to load it and print noise/failures even though the 64-bit one is fine.

---

## My environment

- OS: Kali Linux
- IDA: `IDA Pro 9.1`
- IDA path: `/home/fury/ida-pro-9.1`
- User plugin path: `/home/fury/.idapro/plugins`
- BinDiff package: `bindiff_8_amd64.deb`

If your IDA is elsewhere, just swap paths in commands below.

---

## 1) Install BinDiff

```bash
cd ~/Downloads
sudo apt install -y ./bindiff_8_amd64.deb
bindiff --version
```

Expected:

```text
BinDiff 8 ...
```

If `bindiff --version` works, package install is good.

---

## 2) Install BinExport plugin for IDA

I used the Linux zip from BinExport releases and copied the IDA plugin to both plugin paths:

```bash
unzip -o ~/Downloads/BinExport-Linux.zip -d /tmp/binexport_linux
cp -f /tmp/binexport_linux/ida/binexport12_ida64.so /home/fury/ida-pro-9.1/plugins/
cp -f /tmp/binexport_linux/ida/binexport12_ida64.so /home/fury/.idapro/plugins/
```

You can check:

```bash
ls -la /home/fury/ida-pro-9.1/plugins | rg binexport12_ida
ls -la /home/fury/.idapro/plugins | rg binexport12_ida
```

---

## 3) The important cleanup (this is where most pain comes from)

Remove the 32-bit plugin file:

```bash
rm -f /home/fury/ida-pro-9.1/plugins/binexport12_ida.so
rm -f /home/fury/.idapro/plugins/binexport12_ida.so
```

Then verify only `ida64` remains:

```bash
ls -la /home/fury/ida-pro-9.1/plugins | rg binexport12_ida
ls -la /home/fury/.idapro/plugins | rg binexport12_ida
```

Expected output should show **only** `binexport12_ida64.so`.

---

## 4) Launch IDA the right way

Use `ida64`, not `ida`.

Inside IDA:

1. Open any sample binary
2. `Edit -> Plugins`
3. Confirm `BinExport 12` is present
4. Run BinExport once to confirm export dialog appears

If that works, you are done.

![When plugin list finally looks clean](https://media.giphy.com/media/v1.Y2lkPTc5MGI3NjExNm5nd3h4Y2xydWdkd2M0YTRzdjN0am95OWg3M3d5ODRqbzh6M3pjbiZlcD12MV9naWZzX3NlYXJjaCZjdD1n/3o7TKTDn976rzVgky4/giphy.gif)

---

## What tripped me up

- I had both `binexport12_ida.so` and `binexport12_ida64.so`.
- IDA reported a load error for `binexport12_ida.so`, which looked scary, but the 64-bit plugin was actually fine.

The fix was not "rebuild everything from source".  
The fix was: **clean plugin directory and keep only the correct architecture plugin**.

---

## Quick sanity checklist

```bash
# 1) BinDiff installed?
bindiff --version

# 2) Right plugin exists?
ls -l /home/fury/.idapro/plugins/binexport12_ida64.so

# 3) Wrong plugin removed?
ls -l /home/fury/.idapro/plugins/binexport12_ida.so
```

For #3, "No such file or directory" is a feature, not a bug.

---

## Final note

If IDA plugin loading ever gets weird, 80% of the time it is one of these:

1. wrong architecture (`ida.so` vs `ida64.so`)
2. duplicate plugin copies in multiple plugin paths
3. old symlink leftovers from previous installs

Clean paths, keep one correct plugin, launch `ida64`, move on with life.

