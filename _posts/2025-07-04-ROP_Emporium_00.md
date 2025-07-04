---
title: "ROP Emporium challenges"
categories: [Binary, Exploitation]
tags: [x86, x86_64, ARMv5, ARM, MIPS]
---

## Table of Content

1. [ ] ret2win
2. [ ] split
3. [ ] callme
4. [ ] write4
5. [ ] badchars
6. [ ] fluff
7. [ ] pivot
8. [ ] ret2csu


## Calling Conventions

|Architecture|Function Args|Return Value|Calling Convention|Notes|
|---|---|---|---|---|---|
|**x86 (32-bit)**|Stack (right to left), pushed by caller|EAX|`cdecl`, `stdcall`, etc.|ESP-aligned, saved EBP common|
|**x86-64 (AMD64/Linux)**|RDI, RSI, RDX, RCX, R8, R9 → rest on stack|RAX|**System V AMD64**|Shadow space not required|
|**x86-64 (Windows)**|RCX, RDX, R8, R9 → rest on stack|RAX|**Microsoft x64**|Requires 32-byte shadow space|
|**ARM (32-bit)**|R0–R3, rest on stack|R0|`AAPCS`|Stack 8-byte aligned|
|**AArch64 (ARM 64-bit)**|X0–X7, rest on stack|X0|`AAPCS64`|Stack 16-byte aligned|

### x86 (32-bit)

- Most common: `cdecl`
    
    - Caller cleans up the stack.
    - Args pushed **right to left** 
    - Return: `EAX`
    - Callee saves: `EBP`, `EBX`, `ESI`, `EDI`
    
- Useful for stack smashing — return address is right after the buffer.


### x86-64 (Linux - System V)

- First six arguments in:
```txt
RDI, RSI, RDX, RCX, R8, R9
```

- Rest on stack
- Return value in `RAX`
- Stack must be **16-byte aligned before CALL** 
- Registers preserved across calls: `RBX`, `RBP`, `R12–R15`

Great for **ROP chains** — gadgets like `pop rdi; ret` help set args.

### x86-64 (Windows)

- First 4 args in: `RCX`, `RDX`, `R8`, `R9`
- **Shadow space**: 32 bytes reserved on stack by caller
- Callee cleans up shadow space
- Rest on stack
- Used mainly in Windows binary CTFs


### ARM (32-bit)

- Args: `R0–R3`, rest on stack
- Return: `R0`
- Callee saves: `R4–R11`
- Stack alignment: 8 bytes
- Used for mobile/embedded CTFs

### AArch64 (64-bit ARM)

- Args: `X0–X7`, rest on stack
- Return: `X0`
- Stack must be 16-byte aligned before a call
- Callee saves: `X19–X28`, FP (`X29`), LR (`X30`)
