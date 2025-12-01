---
title: "ROP Emporium challenges"
categories: [Binary, Exploitation]
tags: [x86, x86-64, ARMv5, ARM, MIPS]
---

## Table of Content

1. [x] ret2win
2. [ ] split
3. [ ] callme
4. [ ] write4
5. [ ] badchars
6. [ ] fluff
7. [ ] pivot
8. [ ] ret2csu

You can download the challenges from [ROP Emporium](https://ropemporium.com/).

It is essential to understand the calling conventions of different architectures before solving the challenges.

## Calling Conventions


| Architecture             | Function Args                              | Return Value | Calling Convention       |
| ------------------------ | ------------------------------------------ | ------------ | ------------------------ |
| **x86 (32-bit)**         | Stack (right to left), pushed by caller    | EAX          | `cdecl`, `stdcall`, etc. |
| **x86-64 (AMD64/Linux)** | RDI, RSI, RDX, RCX, R8, R9 → rest on stack | RAX          | **System V AMD64**       |
| **x86-64 (Windows)**     | RCX, RDX, R8, R9 → rest on stack           | RAX          | **Microsoft x64**        |
| **ARM (32-bit)**         | R0–R3, rest on stack                       | R0           | `AAPCS`                  |
| **AArch64 (ARM 64-bit)** | X0–X7, rest on stack                       | X0           | `AAPCS64`                |
| **MIPS (32-bit)**        | A0–A3, rest on stack                       | V0 (and V1)  | O32 / N32 ABI            |


### x86 (32-bit)

- Most common: `cdecl`
    - Caller cleans up the stack.
    - Args pushed **right to left** 
    - Return: `EAX`
    - Callee saves: `EBP`, `EBX`, `ESI`, `EDI`
    

### x86-64 (Linux - System V)

- First six arguments in:
```txt
RDI, RSI, RDX, RCX, R8, R9
```

- Rest on stack
- Return value in `RAX`
- Stack must be **16-byte aligned before CALL** 
- Registers preserved across calls: `RBX`, `RBP`, `R12–R15`


### x86-64 (Windows)

- First 4 args in: `RCX`, `RDX`, `R8`, `R9`
- **Shadow space**: 32 bytes reserved on stack by caller
- Callee cleans up shadow space
- Rest on stack

### ARM (32-bit)

- Args: `R0–R3`, rest on stack
- Return: `R0`
- Callee saves: `R4–R11`
- Stack alignment: 8 bytes

### AArch64 (64-bit ARM)

- Args: `X0–X7`, rest on stack
- Return: `X0`
- Stack must be 16-byte aligned before a call
- Callee saves: `X19–X28`, FP (`X29`), LR (`X30`)


### MIPS (32-bit)

- Args: `A0–A3`, rest on stack
- Return: `V0` (and `V1` for some cases, e.g., 64-bit returns)
- Callee saves: `S0–S7`, FP (`$fp`), RA (`$ra`)
- Stack alignment: 8 bytes (must be aligned before a call)