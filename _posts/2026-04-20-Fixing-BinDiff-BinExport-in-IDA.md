---
title: "How I Fixed BinDiff and BinExport in IDA Pro"
categories: [Reversing, IDA]
tags: [ida, bindiff, binexport, reverse-engineering, plugin, linux]
---

I ran into this in IDA:

```text
dlopen(.../bindiff8_ida.so): undefined symbol: root_node
dlopen(.../binexport12_ida.so): undefined symbol: root_node
```

Both plugins were present, but they were not built for my local IDA setup. This post is exactly how I fixed it.

I wanted this workflow:

- IDA opens with no plugin load errors
- BinExport works in `ida64`
- BinDiff plugin also loads in `ida64`

![Me seeing undefined symbols in plugin load logs](https://media.giphy.com/media/v1.Y2lkPTc5MGI3NjExa3JzdnN2MHpwM3BvY3N4dDdzOHp5MzhxNW5uN2N4OWVnM3B6dW9wYSZlcD12MV9naWZzX3NlYXJjaCZjdD1n/11tTNkNy1SdXGg/giphy.gif)

---

## What was broken

In my case `~/.idapro/plugins` had symlinks to old prebuilt binaries:

```bash
ls -la ~/.idapro/plugins
```

They pointed to `/opt/bindiff/plugins/idapro/*.so`.

Quick confirmation:

```bash
nm -D /opt/bindiff/plugins/idapro/bindiff8_ida.so | rg root_node
nm -D /opt/bindiff/plugins/idapro/binexport12_ida.so | rg root_node
```

If `root_node` shows as undefined, that plugin build is from an older API expectation and may fail on modern IDA.

I also confirmed those were old symlinked binaries from `/opt/bindiff/...`, not fresh local builds.

---

## My fix strategy

I rebuilt both plugins as native `ida64` plugins against my local SDK/toolchain:

- Rebuild `binexport12_ida64.so`
- Rebuild `bindiff8_ida64.so`
- Install into `~/.idapro/plugins`
- Remove stale `*_ida.so` (32-bit) entries

Important: I use `ida64`, so I only care about `*_ida64.so`.

Simple rule: if you use IDA 64-bit, avoid mixing random old `*_ida.so` files from old bundles.

---

## Rebuild BinExport IDA64

I used source build because prebuilt plugin was clearly mismatched.

Clone command pattern (template + real):

```bash
git clone https://github.com/google/binexport.git /tmp/binexport-src
cd /tmp/binexport-src
git checkout main
rm -rf build_ida93 && mkdir build_ida93 && cd build_ida93
cmake .. -G Ninja \
  -DCMAKE_BUILD_TYPE=Release \
  -DBINEXPORT_ENABLE_IDAPRO=ON \
  -DBINEXPORT_ENABLE_BINARYNINJA=OFF \
  -DBINEXPORT_BUILD_TESTING=OFF \
  -DBINEXPORT_IDASDK_OSS=OFF \
  -DIdaSdk_ROOT_DIR=/home/fury/ida-sdk/src
cmake --build . -j"$(nproc)"
```

Output:

- `build_ida93/ida/binexport12_ida64.so`

Quick check:

```bash
ls -la /tmp/binexport-src/build_ida93/ida | rg binexport12_ida64.so
```

![Compiling... waiting... compiling again](https://media.giphy.com/media/v1.Y2lkPTc5MGI3NjExM2doYzM5Mnh4b2J3aWZ4NHM2aHBhcGI5d2Q3NGE2eGZ0NHRrM3RwMSZlcD12MV9naWZzX3NlYXJjaCZjdD1n/l0HlBO7eyXzSZkJri/giphy.gif)

---

## Rebuild BinDiff IDA64

BinDiff expects a sibling `binexport` tree, so I built inside a temp workspace containing both repos:

```bash
rm -rf /tmp/bindiff-work
mkdir -p /tmp/bindiff-work
cp -a /home/fury/bindiff_build/bindiff /tmp/bindiff-work/bindiff
cp -a /home/fury/bindiff_build/binexport /tmp/bindiff-work/binexport

cd /tmp/bindiff-work/bindiff
rm -rf build_ida91 && mkdir build_ida91 && cd build_ida91
cmake .. -G Ninja \
  -DCMAKE_BUILD_TYPE=Release \
  -DBINDIFF_ENABLE_IDAPRO=ON \
  -DBINDIFF_ENABLE_BINARYNINJA=OFF \
  -DBINDIFF_ENABLE_TESTS=OFF \
  -DIdaSdk_ROOT_DIR=/home/fury/ida-pro-9.1
cmake --build . -j"$(nproc)"
```

Output:

- `build_ida91/ida/bindiff8_ida64.so`

Quick check:

```bash
ls -la /tmp/bindiff-work/bindiff/build_ida91/ida | rg bindiff8_ida64.so
```

---

## Install cleaned plugins

```bash
cp -f /tmp/bindiff-work/bindiff/build_ida91/ida/bindiff8_ida64.so ~/.idapro/plugins/
cp -f /tmp/binexport-src/build_ida93/ida/binexport12_ida64.so ~/.idapro/plugins/
rm -f ~/.idapro/plugins/bindiff8_ida.so ~/.idapro/plugins/binexport12_ida.so
```

I remove `*_ida.so` intentionally to avoid 32-bit loader noise and keep startup clean.

Then verify plugin folder:

```bash
ls -la ~/.idapro/plugins | rg "bindiff8_ida|binexport12_ida"
```

---

## Verify before launching IDA

No more `root_node` dependency:

```bash
nm -D ~/.idapro/plugins/bindiff8_ida64.so | rg root_node
nm -D ~/.idapro/plugins/binexport12_ida64.so | rg root_node
```

If both commands print nothing, that specific symbol mismatch is gone.

Then start `ida64`, not `ida`.

You can also quickly confirm plugin symbols are there:

```bash
nm -D ~/.idapro/plugins/bindiff8_ida64.so | rg "PLUGIN"
nm -D ~/.idapro/plugins/binexport12_ida64.so | rg "PLUGIN"
```

If IDA still shows old errors, check if there are duplicate plugin copies in another plugin path.

![When it finally loads cleanly](https://media.giphy.com/media/v1.Y2lkPTc5MGI3NjExNm5nd3h4Y2xydWdkd2M0YTRzdjN0am95OWg3M3d5ODRqbzh6M3pjbiZlcD12MV9naWZzX3NlYXJjaCZjdD1n/3o7TKTDn976rzVgky4/giphy.gif)

---

## Common mistakes I hit

- Building with wrong SDK path
- Keeping old symlinked plugin files in `~/.idapro/plugins`
- Running `ida` (32-bit path) instead of `ida64`
- Assuming “plugin file exists” means “plugin is compatible”

Quick debug checklist:

1. `ls -la ~/.idapro/plugins`
2. ensure only `*_ida64.so` are active
3. run `nm -D ... | rg root_node`
4. run `ida64`
5. re-check Output window lines

---

## Final note

Prebuilt plugin bundles are convenient, but if they were compiled against a different IDA SDK/runtime expectation, rebuilding locally is the fastest path to stability.

