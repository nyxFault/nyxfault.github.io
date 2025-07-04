---
title: "ROP Emporium - callme"
categories: [Binary, Exploitation]
tags: [x86, x86_64, ARMv5, ARM, MIPS, callme]
---


## 1. Setting Up the Environment


If you are on an x86-based system (like a typical PC), you can use QEMU to emulate an ARM processor.

```bash
sudo apt update
sudo apt install qemu qemu-user qemu-system-arm gcc-arm-linux-gnueabi gdb-multiarch
```

**Running an ARM Linux System on QEMU**

To run an ARM Linux system, you can use a prebuilt image:

```bash
qemu-system-arm -M versatilepb -kernel vmlinuz-arm -hda rootfs.img -append "root=/dev/sda"
```

## **2. Introduction to ARM Architecture**

ARM (Advanced RISC Machine) is a RISC (Reduced Instruction Set Computing) architecture widely used in mobile devices, embedded systems, and IoT applications.

### **ARM vs. x86: Key Differences**

|Feature|ARM|x86|
|---|---|---|
|**Architecture Type**|RISC (Reduced Instruction Set Computing)|CISC (Complex Instruction Set Computing)|
|**Instruction Size**|Fixed (mostly 32-bit, some 16-bit Thumb)|Variable (1-15 bytes)|
|**Power Efficiency**|High (used in mobile devices)|Lower (used in PCs/servers)|
|**Instruction Execution**|Load-Store Architecture (separate memory & register operations)|Register-Memory Architecture|
|**Endianness**|Mostly Little-Endian (configurable)|Little-Endian (x86)|
|**Register Count**|More General-Purpose Registers|Fewer Registers|
|**Privilege Levels**|Multiple CPU Modes (User, Supervisor, etc.)|Ring Levels (Ring 0-3)|


### **ARM Processor Modes**

ARM CPUs operate in different modes based on privilege level and interrupt handling:

|Mode|Description|
|---|---|
|**User Mode**|Used by applications, limited system access|
|**Supervisor Mode**|Kernel mode for OS execution|
|**IRQ Mode**|Handles normal interrupts|
|**FIQ Mode**|Handles fast interrupts|
|**Abort Mode**|Used when a memory access fails|
|**Undef Mode**|Handles undefined instructions|
|**System Mode**|Like Supervisor mode but accessible from User Mode|

ARM switches modes using exceptions (interrupts, system calls).

### **Registers in ARM**

ARM has 16 general-purpose registers (`R0-R15`), plus special registers:

| Register   | Description                                                                                     |
|------------|-------------------------------------------------------------------------------------------------|
| R0-R3     | Used for function arguments and return values (up to 4 parameters).                            |
| R4-R7     | Callee-saved registers (used by functions but must be preserved across function calls).        |
| R8-R12    | General-purpose registers.                                                                       |
| R13 (SP)  | Stack Pointer. Points to the current top of the stack.                                         |
| R14 (LR)  | Link Register. Stores the return address from function calls.                                   |
| R15 (PC)  | Program Counter. Holds the address of the next instruction to execute.                          |
| CPSR      | Current Program Status Register. Contains flags like Zero, Negative, Overflow, Carry, Interrupts, etc. |
| SPSR      | Saved Program Status Register. Holds the CPSR during exception handling and mode switching.    |


### **Endianness in ARM**

- **Little-Endian**: Stores the least significant byte first (default in ARM).
- **Big-Endian**: Stores the most significant byte first.
- ARM processors support both, but most modern systems use **Little-Endian**.
    
The **AAPCS** (ARM Architecture Procedure Call Standard) defines the rules for how functions are called and how parameters are passed between functions in ARM-based systems. It's a key standard for ensuring consistent calling conventions across different ARM implementations.

### Key Points of AAPCS (ARM Procedure Call Standard):

1. **Function Arguments (Registers R0 - R3)**
	- The first four arguments to a function are passed using registers **R0 - R3**.
	- If a function requires more than four arguments, the additional parameters are passed on the stack.
        
2. **Return Values (R0 - R1)**
	- The return value of a function is usually stored in **R0**. **R0** for single return values, **R1** for multi-word returns.
        
3. **Registers for Local Variables:**
    - **R4 - R7**: Callee-saved registers (must be preserved by the function if modified).
    - **R8 - R12**: Additional registers that can be used freely by functions but must be saved if used across function calls.
        
4. **Link Register (LR):**
    - **LR (R14)**: Stores the return address when a function is called. The callee is responsible for saving it if necessary.
        
5. **Stack Pointer (SP) and Frame Pointer (FP):**
    - **SP (R13)**: The stack pointer points to the top of the stack.
    - **FP (R7/R11)**: The frame pointer points to the start of the current function’s stack frame (R7/R11 is used as the frame pointer in many ARM-based systems).
        
6. **Callee vs Caller-Saved Registers:**
    - **Callee-saved**: Registers that the called function must preserve if it modifies them (e.g., **R4 - R7**).
    - **Caller-saved**: Registers that the calling function must preserve if it needs their values after a function call (e.g., **R0 - R3**, **LR**).
        
7. **Stack Alignment:**
    - The stack must be aligned to 8-byte boundaries on function entry.

#### **Exception Handling**

- During an interrupt or exception, ARM saves the current state of the program (CPSR and registers) and switches to a special mode (like IRQ or FIQ mode). The stack is used to save and restore the program state when returning from an exception.

---

