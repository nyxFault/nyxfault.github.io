---
title: "Practical Guide to Havoc C2: A Modern Command and Control Framework"
categories: [Windows, C2]
tags: [windows, c2, havoc, redteam]
mermaid: true
---

I’ve been diving deeper into Windows internals and red teaming over the past few days. While I already hold penetration testing certifications, I wanted to push beyond surface-level knowledge. That exploration led me to **Havoc C2**, a relatively new but fast-growing command and control framework widely adopted in offensive security research.

## Introduction

Command and Control (C2) frameworks are the backbone of advanced adversary operations. They provide the infrastructure for persistence, lateral movement, and data exfiltration. Havoc C2, an open-source post-exploitation framework, has gained significant traction due to its modularity, evasion techniques, and flexible architecture. Unlike older frameworks such as Cobalt Strike or Empire, Havoc is actively evolving and explicitly designed to bypass modern defensive controls.

This article breaks down Havoc C2’s architecture, components, operational workflow, evasion strategies, and implications for defenders.


## Background

Havoc C2 was released publicly in 2022 and has been under active development. It provides red teamers and adversaries with:

- An extensible C2 server and client.
- Cross-platform agent (“demon”) with advanced evasion.
- Rich operator UI for tasking and monitoring compromised systems.

Its design goals include bypassing EDR/AV, flexibility in payload staging, and modular post-exploitation tooling.

## Installation

Install Dependencies:

```bash
sudo apt install -y git build-essential apt-utils cmake libfontconfig1 libglu1-mesa-dev libgtest-dev libspdlog-dev libboost-all-dev libncurses5-dev libgdbm-dev libssl-dev libreadline-dev libffi-dev libsqlite3-dev libbz2-dev mesa-common-dev qtbase5-dev qtchooser qt5-qmake qtbase5-dev-tools libqt5websockets5 libqt5websockets5-dev qtdeclarative5-dev golang-go qtbase5-dev libqt5websockets5-dev python3-dev libboost-all-dev mingw-w64 nasm
```

```bash
git clone https://github.com/HavocFramework/Havoc.git
cd Havoc
```

#### Building the Teamserver

Install additional Go dependencies:

```bash
cd teamserver
go mod download golang.org/x/sys
go mod download github.com/ugorji/go
cd ..
```

Build and Run:

```bash
# Install musl Compiler & Build Binary (From Havoc Root Directory)
make ts-build

# Run the teamserver
./havoc server --profile ./profiles/havoc.yaotl -v --debug
```
The profile defines network settings and evasion parameters.

All files created during interaction with the Teamserver are stored within the `/Havoc/data/*` folder.

#### Building the Client

Now that we successfully compiled the teamserver we now should install the dependencies for the Client and compile it.

Build and Run:

```bash
# Build the client Binary (From Havoc Root Directory)
make client-build

# Run the client
./havoc client
```

Till now we have compiled:

- teamserver (server component)
- client (operator interface)


## Architecture Overview

Havoc C2 has three core components:

1. **Teamserver**
    
    - Central command infrastructure.
    - Manages agents (demons), operator sessions, and communication channels.
    - Written in C++ with performance in mind.
        
2. **Client/Operator Console**
    
    - GUI for red teamers.
    - Provides an interface for payload generation, tasking, and data visualization.
    
3. **Demon (Agent)**
    
    - The endpoint implant.    
    - Supports Windows (x64/x86) with ongoing Linux and cross-platform development.
    - Features in-memory execution, reflective loading, and evasion modules.

Compared to Cobalt Strike, Havoc is free and open source but less mature.

## Communication Model

- **Transport Flexibility**: HTTP/HTTPS, SMB, and custom transports.
- **Encrypted Channels**: Uses cryptographic key exchange (ChaCha20-Poly1305).
- **Staging**: Supports staged and stageless payloads, making detection harder.
- **Beaconing vs Interactive**: Default is beacon-style callback but configurable for interactive shells.


## BOF Development

A Beacon Object File is a **COFF object** that Beacon loads and calls at runtime. You write one function, `go`, which runs **in-process**, with **no CRT**, and only what you import or resolve yourself.

You can checkout my blog on BOF Development [here](https://nyxfault.github.io/posts/BOF-Guide/)
