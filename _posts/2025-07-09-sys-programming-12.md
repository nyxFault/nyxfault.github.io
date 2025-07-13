---
title: "12. IPC - Introduction"
categories: [Linux, Programming]
tags: [linux, sys-programming]
---

Inter-Process Communication (IPC) refers to the mechanisms that allow processes to exchange data and synchronize their execution. In Linux, multiple processes often need to communicate—whether they are cooperating on a task, sharing resources, or coordinating work.

Linux provides several IPC mechanisms, each with its own use cases, advantages, and trade-offs.

## Types of IPC Mechanisms in Linux

Linux provides multiple IPC techniques, which are generally divided into:

- Communication IPCs: For exchanging data.
- Synchronization IPCs: For coordinating process execution.

Linux provides several IPC mechanisms, which can be broadly categorized as follows:

|IPC Mechanism|Kernel Involvement|Communication Type|Synchronization Capability|
|---|---|---|---|
|**Pipes (Unnamed Pipes)**|Minimal (via file descriptors)|Unidirectional|No|
|**Named Pipes (FIFOs)**|Minimal (via filesystem)|Unidirectional (bidirectional with care)|No|
|**Message Queues**|Moderate (kernel-managed queue)|Bidirectional|Yes (ordering)|
|**Shared Memory**|Moderate (shared address space)|Bidirectional|Needs external synchronization (e.g., semaphores)|
|**Semaphores**|High (kernel-managed)|N/A|Yes (synchronization only)|
|**Sockets**|High (network stack)|Bidirectional|Yes (explicit)|
|**Signals**|Minimal|One-shot notification|Limited (basic notifications)|


