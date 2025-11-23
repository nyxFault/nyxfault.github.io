---
title: "Mastering Binary Ninja Python API"
categories: [Reversing, Assembly]
tags: [reversing, binja]
mermaid: true
---

I’ve been away for a few weeks because I’ve been learning Windows Kernel Exploitation, and soon I’ll be posting my notes on it here. In this post, I’ll be sharing some tutorials on how to use the Binary Ninja (Binja) API. Binary Ninja already provides great examples and official tutorials, and I highly recommend checking them out. I’ve included all the references at the end of this post.

I’ve been using IDA for a long time and had only briefly looked at Binary Ninja before, but I was greatly impressed by its API. It’s elegant, well‑designed, and makes plugin development surprisingly easy. I’ve already created a few basic plugins, which you can find [here](https://github.com/nyxFault/nyxFault-Binja).

Before you can start using the Binary Ninja Python API, you need to run the `install_api.py` script to properly set up the API in your Python environment. This script adds the Binary Ninja Python API to your Python environment’s path, enabling you to import and use the API seamlessly.

### Steps to Install the API

- Locate the `install_api.py` script inside the `scripts` folder within your Binary Ninja installation directory. The path varies by platform:
  - **Windows:** `C:\Program Files\Vector35\BinaryNinja\scripts\install_api.py`    
  - **Linux:** `/opt/binaryninja/scripts/install_api.py` (or wherever Binary Ninja is installed)

- Run the script using your Python interpreter. For example: 

```bash
python3 /path/to/binaryninja/scripts/install_api.py
```

- The script will verify if the API is already installed, and if not, it will add the necessary paths by modifying your site-packages or Python path configurations.

Once completed, you can verify the installation by importing Binary Ninja in your Python code:

```python
import binaryninja
print(binaryninja.core_version())
```

If no errors occur and the version prints correctly, the API is successfully installed and ready to use.
## Table of Contents

1. Chapter 1: Getting Started
2. Chapter 2: Working with BinaryView
3. Chapter 3: Functions and Analysis
4. Chapter 4: Intermediate Language (IL) Systems
5. Chapter 5: Basic Blocks and Control Flow
6. Chapter 6: Data Variables and Types
7. Chapter 7: Cross-References and Analysis
8. Chapter 8: Symbols, Sections, and Segments


*NOTE*

For examples shown in this tutorial I will be using the following Hello World code compiled to an executable `hello.exe`.

```c
#include <stdio.h>

void sayHello()
{
    printf("Hello World!\n");
}

int main()
{
    sayHello();
}
```


## Chapter 1: Getting Started

### 1.1 Installation and Import

```bash
# Import Binary Ninja module
import binaryninja
# Or import like this
from binaryninja import *

# Check version
print(core_version())
print(f"Binary Ninja {core_version_info().major}.{core_version_info().minor}.{core_version_info().build}")

```

### 1.2 Opening a Binary File

```python
from binaryninja import *
# Open a file and get basic info
# Load a file with default options
with load("./hello.exe") as bv:
    if bv is not None:
        print(f"Opening {bv.file.filename} which has {len(list(bv.functions))} functions")

# `Without automatic analysis`
with load("./hello.exe", update_analysis=False) as bv:
    # Manually trigger analysis when needed
    bv.update_analysis_and_wait()
```

Open the Python console in Binary Ninja via `View > Python Console`. The `bv` variable is automatically available and represents your current binary.

```python
# Basic binary info
bv.file.filename
bv.arch.name
bv.platform.name
bv.start
bv.entry_point
```

### 1.3 BinaryView Types

```python
# List available BinaryView types
print(list(BinaryViewType))
# Output: [<view type: 'Raw'>, <view type: 'ELF'>, <view type: 'Mach-O'>, <view type: 'PE'>]

# Access specific view type
elf_view = BinaryViewType['ELF']
print(elf_view)
```

### 1.4 Essential Properties

```python
# Control Log Levels
from binaryninja.enums import LogLevel
binaryninja.log.log_to_stdout(LogLevel.AlertLog)

with load("/bin/ls") as bv:
    # Basic information
    print(f"Architecture: {bv.arch}")
    print(f"Platform: {bv.platform}")
    print(f"Entry point: {hex(bv.entry_point)}")
    print(f"Start address: {hex(bv.start)}")
    print(f"End address: {hex(bv.end)}")
    print(f"Length: {hex(len(bv))}")
    print(f"Executable: {bv.executable}")

```

## Chapter 2: Working with BinaryView

### 2.1 Analysis Control

```python
from binaryninja import *
with load("hello.exe") as bv:
    # Wait for analysis to complete (blocking)
    bv.update_analysis_and_wait()
    
    # Trigger analysis without waiting (non-blocking)
    bv.update_analysis()
    
    # Abort analysis
    bv.abort_analysis()
    
    # Check analysis state
    print(f"Analysis state: {bv.analysis_info.state}")
    print(f"Analysis time: {bv.analysis_info.analysis_time}ms")

```


### 2.2 Analysis Completion Callbacks

```python
def on_analysis_complete():
    print("Analysis completed!")

# Add completion event
with load("/bin/ls") as bv:
    event = bv.add_analysis_completion_event(on_analysis_complete)
    bv.update_analysis()
    # Callback will be triggered when analysis finishes

```

### 2.3 Reading Binary Data

We will try to read the string "Hello World!" at address 0x405064.

```txt
00405064  char const _.rdata[0xd] = "Hello World!", 0
```

```python
from binaryninja import *
with load("hello.exe") as bv:
    if bv.is_valid_offset(0x0405064): # Check if address is valid
        # Read bytes from address
        byte_data = bv.read(0x0405064, 16)
        print(byte_data)
        str_decoded = byte_data.decode('utf-8')
        print(str_decoded)
```

### 2.4 Writing Binary Data

Let's write "Bye World!" at address 0x0405064.

```python
from binaryninja import *
with load("hello.exe") as bv:
    if bv.is_valid_offset(0x0405064): # Check if address is valid
        data = b'Bye World!\x00\x00\x00\x00'
        # Insert bytes
        # bv.insert(0x0405064, b'\x90\x90')
        # Remove bytes
        # bv.remove(0x0405064, 2)
        # Write bytes to address
        bytes_written = bv.write(0x0405064, data)
        print(f"Modified {bytes_written} bytes in memory")
    
    # Save to a new executable file
    output_path = "hello_modified.exe"
    bv.save(output_path)
    print(f"Permanent changes saved to: {output_path}")
```

## Chapter 3: Functions and Analysis

Install Ariadne Plugin and Analyze the target. In webUI -

![[Pasted image 20251122233132.png]]


### 3.1 Listing and Iterating Functions

```python
from binaryninja import *
with load("hello.exe") as bv:
    # Get all functions
    functions = bv.functions
    print(f"Total functions: {len(functions)}")
    
    # Iterate through functions
    for func in bv.functions:
        print(f"{func.name} @ {hex(func.start)}")
    
    # Get entry function
    entry_func = bv.entry_function
    print(f"Entry function: {entry_func.name} @ {hex(entry_func.start)}")
    
    # Get entry functions (including init/fini)
    entry_functions = bv.entry_functions
    for func in entry_functions:
        print(f"Entry: {func.name} @ {hex(func.start)}")

```


### 3.2 Finding Functions

In the following examples I have used address of `_sayHello` function -

```python
with load("hello.exe") as bv:
    # Get function at specific address
    func = bv.get_function_at(0x401460)
    if func:
        print(f"Found function: {func.name}")
    
    # Get all functions at address
    functions = bv.get_functions_at(0x401460)
    
    # Get functions containing an address
    functions = bv.get_functions_containing(0x401460)
    
    # Get functions by name
    functions = bv.get_functions_by_name("_sayHello")
    for func in functions:
        print(f"_sayHello @ {hex(func.start)}")
```

### 3.3 Creating Functions

Sometimes Binary Ninja's auto-analysis misses functions, or you want to define custom functions that aren't automatically discovered.


**Method 1: `create_user_function()`**

**Use case:** When you manually discovered a function and want to tell Binary Ninja about it.

```python
with load("hello_modified.exe") as bv:

    # Addresses where we suspect functions exist but weren't auto-detected
    suspected_functions = [0x401100, 0x401200, 0x401300]
    
    for addr in suspected_functions:
        # Check if function already exists
        existing_func = bv.get_function_at(addr)
        if not existing_func:
            # Create new function
            new_func = bv.create_user_function(addr)
            if new_func:
                print(f"Created function at {hex(addr)}: {new_func.name}")
            else:
                print(f"Failed to create function at {hex(addr)}")
```

**Method 4: `add_entry_point()`**

**Use case:** Define new entry points for the binary (like alternative main functions).

```python
# Use add_entry_point()
# bv.add_entry_point(addr, plat)
```

### 3.4 Function Properties

```python
with load("hello.exe") as bv:
    func = bv.get_function_at(bv.entry_point)
    
    # Basic properties
    print(f"Name: {func.name}")
    print(f"Start: {hex(func.start)}")
    print(f"Architecture: {func.arch}")
    print(f"Platform: {func.platform}")
    
    # Function type information
    print(f"Type: {func.type}")
    print(f"Return type: {func.return_type}")
    print(f"Calling convention: {func.calling_convention}")
    print(f"Can return: {func.can_return}")
    print(f"Is pure: {func.is_pure}")
    print(f"Is thunk: {func.is_thunk}")
    print(f"Has variable arguments: {func.has_variable_arguments}")
    
    # Analysis information
    print(f"Total bytes: {func.total_bytes}")
    print(f"Too large: {func.too_large}")
    print(f"Analysis skipped: {func.analysis_skipped}")
```


### 3.5 Function Variables

For this example I'm using the following code -

```c
#include <stdio.h>

// Simple function with parameters and local variables
int calculate(int a, int b) {
    // Local variables
    int result = 0;
    int temp = 5;
    char message[20] = "Calculating...";
    
    // Parameters
    result = a + b + temp;
    
    printf("%s\n", message);
    printf("Result: %d\n", result);
    
    return result;
}

int main()
{
    int x = 10;
    int y = 20;
    int answer = calculate(x, y);
    return 0;
}
```

```python
with load("hello.exe") as bv:
    # Get the main function
    # func = bv.get_function_at(bv.entry_point)
    func = bv.get_functions_by_name("_calculate")[0]
    print(f"\t_calculate @ {func}")
    print("[+] Variables\n");
    # Get all variables
    for var in func.vars:
        print(f"Variable: {var.name} (Type: {var.type})")
    
    print("[+] Parameters\n");
    # Get parameter variables
    for param in func.parameter_vars:
        print(f"Parameter: {param.name} (Type: {param.type})")
```


## Chapter 4: Intermediate Language (IL) Systems

Binary Ninja uses multiple levels of Intermediate Language (IL) representations, each serving a different purpose in analysis.

```txt
Raw Assembly
    ↓
Lifted IL (Architecture-specific IL)
    ↓
Low Level IL (LLIL) - Architecture-independent
    ↓
Mapped Medium Level IL (MLIL) - SSA form with memory/register mapping
    ↓
Medium Level IL (MLIL) - Higher-level operations
    ↓
High Level IL (HLIL) - C-like representation
```

### Low Level IL (LLIL)

For `_calculate` function, the LLIL would look like -

```txt
00401460    int32_t _calculate(int32_t arg1, int32_t arg2)

   0 @ 00401460  push(ebp)
   1 @ 00401461  ebp = esp {__saved_ebp}
   2 @ 00401463  esp = esp - 0x38
   3 @ 00401466  [ebp - 0xc {var_10}].d = 0
   4 @ 0040146d  [ebp - 0x10 {var_14}].d = 5
   5 @ 00401474  [ebp - 0x24 {_Buffer}].d = 0x636c6143
   6 @ 0040147b  [ebp - 0x20 {var_24}].d = 0x74616c75
   7 @ 00401482  [ebp - 0x1c {var_20}].d = 0x2e676e69
   8 @ 00401489  [ebp - 0x18 {var_1c}].d = 0x2e2e
   9 @ 00401490  [ebp - 0x14 {var_18}].d = 0
  10 @ 00401497  edx = [ebp + 8 {arg1}].d
  11 @ 0040149a  eax = [ebp + 0xc {arg2}].d
  12 @ 0040149d  edx = edx + eax
  13 @ 0040149f  eax = [ebp - 0x10 {var_14}].d
  14 @ 004014a2  eax = eax + edx
  15 @ 004014a4  [ebp - 0xc {var_10_1}].d = eax
  16 @ 004014a7  eax = ebp - 0x24 {_Buffer}
  17 @ 004014aa  [esp {var_3c}].d = eax {_Buffer}
  18 @ 004014ad  call(puts)
  19 @ 004014b2  eax = [ebp - 0xc {var_10_1}].d
  20 @ 004014b5  [esp + 4 {var_38}].d = eax
  21 @ 004014b9  [esp {var_3c}].d = &_.rdata  {"Result: %d\n"}
  22 @ 004014c0  call(printf)
  23 @ 004014c5  eax = [ebp - 0xc {var_10_1}].d
  24 @ 004014c8  esp = ebp
  25 @ 004014c8  ebp = pop
  26 @ 004014c9  <return> jump(pop)

```

We can achieve same results using the API as well.

```python
from binaryninja import *

with load("hello.exe") as bv:
    # func = bv.get_function_at(bv.entry_point)
    func = bv.get_functions_by_name("_calculate")[0]
    
    # Get LLIL function
    llil = func.llil
    print(f"LLIL instructions: {len(llil)}")
    
    # Get LLIL at specific address
    llil_instr = func.get_llil_at(func.start)
    print(f"\nLLIL @ {hex(func.start)}: {llil_instr}")

     # Print all LLIL instructions
    print(f"\nLLIL for function {func.name}")
    for block in llil:
        for instr in block:
            print(f"  {hex(instr.address)}: {instr}")
```

We can achieve the same results across all Intermediate Language levels using the consistent API pattern:

- **`func.llil`** - Low Level IL (assembly-like)
- **`func.mlil`** - Medium Level IL (simplified, variables identified)
- **`func.hlil`** - High Level IL (C-like representation)

- **`func.get_llil_at(address)`** - Get LLIL at specific address
- **`func.get_mlil_at(address)`** - Get MLIL at specific address
- **`func.get_hlil_at(address)`** - Get HLIL at specific address


## Chapter 5: Basic Blocks and Control Flow


In the world of reverse engineering and binary analysis, a **basic block** is a fundamental concept that represents a straight-line sequence of code with exactly one entry point and one exit point. Think of it as a "block" of instructions that executes from start to finish without any branching, except possibly at the end.

### 5.1 Accessing Basic Blocks

```python
from binaryninja import *

with load("hello.exe") as bv:
    # Get function by name
    func = bv.get_functions_by_name("_calculate")[0]
    
    # Iterate through all basic blocks in the function
    for block in func.basic_blocks:
        print(f"Block @ {hex(block.start)}-{hex(block.end)}")
        print(f"  Length: {block.length} bytes")
        print(f"  Instruction count: {block.instruction_count}")
```

### 5.2 Working with Basic Blocks

**Iterating Through Instructions**

```python
from binaryninja import *

with load("hello.exe") as bv:
    # func = bv.get_function_at(bv.entry_point)
    func = bv.get_functions_by_name("_calculate")[0]
    # Get all basic blocks
    for block in func.basic_blocks:
        print(f"Block @ {hex(block.start)}-{hex(block.end)}")
        print(f"  Length: {block.length}")
        print(f"  Instruction count: {block.instruction_count}")
        
        # Iterate through disassembly
        for addr in range(block.start, block.end):
            # Get the instruction at this address
            instr = bv.get_disassembly(addr)
            if instr:
                print(f"    {hex(addr)}: {instr}")
```

**Using Disassembly Text**

```python
from binaryninja import *

with load("hello.exe") as bv:
    # Get function by name
    func = bv.get_functions_by_name("_calculate")[0]
    
    # Iterate through all basic blocks in the function
    for block in func.basic_blocks:
        print(f"\nBlock @ {hex(block.start)}-{hex(block.end)}")
        
        # Get all disassembly text for the block
        disasm_lines = block.get_disassembly_text()
        for line in disasm_lines:
            print(f"    {hex(line.address)}: {line}")
```

**Filter Instructions**

In this example, I have only filtered `call` instructions.

```python
from binaryninja import *

with load("hello.exe") as bv:
    # Get function by name
    func = bv.get_functions_by_name("_calculate")[0]

    for block in func.basic_blocks:
        print(f"\nBlock @ {hex(block.start)}-{hex(block.end)}")
        
        disasm_lines = block.get_disassembly_text()
        for line in disasm_lines:
            # The tokens include mnemonic as first text token after the address: filter by "call"
            tokens_text = "".join(token.text for token in line.tokens).lower()
            if tokens_text.startswith("call"):
                print(f"    {hex(line.address)}: {line}")
```

**Highlighting Address**

To highlight an instruction at a specific address `here`, import `highlight` from the `binaryninja` module:

```python
from binaryninja import highlight
```

Use the currently loaded function object (`current_function`) to set the highlight on the instruction at address `here`:

```python
current_function.set_user_instr_highlight(here, highlight.HighlightColor(red=255, green=255, blue=0))
```

You can also use predefined standard highlight colors:

```python
from binaryninja.enums import HighlightStandardColor

current_function.set_user_instr_highlight(here, HighlightStandardColor.BlueHighlightColor)
```


[Refer](https://api.binary.ninja/binaryninja.enums-module.html#highlightstandardcolor)


**Handy Predefined Variables in Binary Ninja Console**

`current_function` - The `Function` object currently in focus, such as the function containing the cursor or "here". Used to manipulate instructions, basic blocks, etc. For more just press TAB after `current_`

`here` - The current cursor address or instruction pointer location within the binary view.

`bv` (BinaryView) - The main object representing the analyzed binary file or memory view. Provides access to functions, sections, segments, data, and architecture.

Also, in console to see all the values in hex just use `monkeyhex`.

```python
from monkeyhex import *
```

### 5.3 Control Flow Analysis

Basic blocks form the nodes of a **Control Flow Graph (CFG)**, which represents all possible paths through a function. Binary Ninja provides powerful tools to analyze this graph.

In Binary Ninja's Python API, the control flow graph (CFG) of a function can be represented and manipulated by the classes in the `flowgraph` module.

A Simple Flow Graph will look like -

*NOTE*

Flow graphs created by the API generally require Binary Ninja’s UI environment (e.g., console inside BN or plugin context) to display. Running scripts standalone in a plain Python shell or external environment may not show the graph.

```python
from binaryninja.flowgraph import FlowGraph, FlowGraphNode, EdgeStyle
from binaryninja.enums import EdgePenStyle, ThemeColor, BranchType
from binaryninja import show_graph_report

graph = FlowGraph()

node_a = FlowGraphNode(graph)
node_a.lines = ["Node A"]
graph.append(node_a)

node_b = FlowGraphNode(graph)
node_b.lines = ["Node B"]
graph.append(node_b)

edge_style = EdgeStyle(EdgePenStyle.DashDotDotLine, 2, ThemeColor.AddressColor)
node_a.add_outgoing_edge(BranchType.UserDefinedBranch, node_b, edge_style)

show_graph_report("Custom Graph", graph)

```


#### Steps to create flowgraph

**Step 1: Create a FlowGraph instance**

```python
from binaryninja.flowgraph import FlowGraph

graph = FlowGraph()
```

**Step 2: Create FlowGraphNodes**

```python
from binaryninja.flowgraph import FlowGraphNode

node_a = FlowGraphNode(graph)
node_b = FlowGraphNode(graph)

node_a.lines = ["Start node"]
node_b.lines = ["End node"]
```

**Step 3: Add nodes to FlowGraph**

```python
graph.append(node_a)
graph.append(node_b)
```

**Step 4: Connect nodes with edges**

```python
from binaryninja.flowgraph import EdgeStyle
from binaryninja.enums import EdgePenStyle, ThemeColor, BranchType

edge_style = EdgeStyle(EdgePenStyle.SolidLine, 2, ThemeColor.AddressColor)
node_a.add_outgoing_edge(BranchType.UnconditionalBranch, node_b, edge_style)
```

**Step 5: Highlight nodes (optional)**

```python
from binaryninja.enums import HighlightStandardColor

node_a.highlight = HighlightStandardColor.RedHighlightColor
node_b.highlight = HighlightStandardColor.GreenHighlightColor
```

**Step 6: Show the graph in Binary Ninja UI**

```python
from binaryninja import show_graph_report

show_graph_report("Custom Flow Graph", graph)
```


You can control the appearance of edges using different `EdgePenStyle` options:

- `SolidLine`
- `DashLine`
- `DashDotLine`
- `DashDotDotLine`
- `DotLine`

Example for a dash-dot-dot line edge:

```python
from binaryninja.enums import EdgePenStyle, ThemeColor
edge_style = EdgeStyle(EdgePenStyle.DashDotDotLine, 3, ThemeColor.AddressColor)
```


## Chapter 6: Data Variables and Types

```python
from binaryninja import *

with load("hello.exe") as bv:
    # Get all data variables
    for addr, var in bv.data_vars.items():
        print(f"Data variable @ {hex(addr)}: {var.name} (Type: {var.type})")
    
    # Get data variable at specific address
    var = bv.get_data_var_at(0x404000)
    if var:
        print(f"Found: {var.name} @ {hex(var.address)}")
        print(f"Type: {var.type}")
        print(f"Auto discovered: {var.auto_discovered}")
```

## Chapter 7: Cross-References and Analysis

### 7.1 Code Cross-References

```python
from binaryninja import *

with load("hello.exe") as bv:
    # Get code references TO an address
    refs = bv.get_code_refs(0x401000)
    print(f"Code references to {hex(0x401000)}:")
    for ref in refs:
        print(f"  From {hex(ref.address)} in {ref.function.name}")
    
    # Get code references FROM an address
    refs = bv.get_code_refs_from(0x401000)
    print(f"Code references from {hex(0x401000)}:")
    for ref in refs:
        print(f"  To {hex(ref.address)}")
```

### 7.2 Get Callers 

```python
# Get Callers (Who calls _calculate)
from binaryninja import *

# Load your binary
with load("hello.exe") as bv:
   
    # Get all callers of a function (e.g. _calculate)
    # target_func = bv.get_function_at(0x401000)
    target_func = bv.get_functions_by_name("_calculate")[0]
    callers = bv.get_callers(target_func.start)
    print(f"Functions calling {target_func.name}:")
    for caller in callers:
        print(f"  {caller.function.name} @ {hex(caller.address)}")
```

### 7.3 Get Callees 

For getting Callees we will leverage MLIL (`MediumLevelIL`).

```python
# Get Callees (Which functions are called from _calculate)
from binaryninja import *

with load("hello.exe") as bv:
    func = bv.get_functions_by_name("_calculate")[0]
    print(f"Functions called by {func.name}:")

    # Use Medium Level IL (works for x86/x64 most binaries)
    callees = set()
    if func.mlil:
        for block in func.mlil.basic_blocks:
            for instr in block:
                il = func.mlil[instr]
                # Check for call operations
                if il.operation == MediumLevelILOperation.MLIL_CALL:
                    # Try to resolve direct target
                    if il.dest.operation == MediumLevelILOperation.MLIL_CONST_PTR:
                        target_addr = il.dest.constant
                        dest_func = bv.get_function_at(target_addr)
                        if dest_func and dest_func.start != func.start:
                            callees.add((dest_func.name, dest_func.start))
    else:
        print("  (No MLIL available)")
    for name, addr in sorted(callees):
        print(f"  {name} @ {hex(addr)}")

```


### 7.4 String References

**Get all strings**

```python
from binaryninja import *

with load("hello.exe") as bv:
    # Get all strings
    for string in bv.strings:
        print(f"String @ {hex(string.start)}: {repr(string.value)}")
        
        # Get code references to string
        refs = bv.get_code_refs(string.start)
        for ref in refs:
            print(f"  Referenced by {ref.function.name} @ {hex(ref.address)}")
```

**Get code references to string**


```python
from binaryninja import *

with load("hello.exe") as bv:
    # Get string at specific address
    string = bv.get_string_at(0x405064)
    if string:
        print(f"String: {repr(string.value)}")
```

## Chapter 8: Symbols, Sections, and Segments

### 8.1 Working with Symbols


Symbols are defined as one of the following types:

| SymbolType             | Description                                                                                       |
| ---------------------- | ------------------------------------------------------------------------------------------------- |
| FunctionSymbol         | Symbol for function that exists in the current binary                                             |
| ImportAddressSymbol    | Symbol defined in the Import Address Table                                                        |
| ImportedFunctionSymbol | Symbol for a function that is not defined in the current binary                                   |
| DataSymbol             | Symbol for data in the current binary                                                             |
| ImportedDataSymbol     | Symbol for data that is not defined in the current binary                                         |
| ExternalSymbol         | Symbols for data and code that reside outside the BinaryView                                      |
| LibraryFunctionSymbol  | Symbols for functions identified as belonging to a shared library                                 |
| SymbolicFunctionSymbol | Symbols for functions without a concrete implementation or which have been abstractly represented |
| LocalLabelSymbol       | Symbol for a local label in the current binary                                                    |

```python
from binaryninja import *

with load("hello.exe") as bv:
    # Get all symbols
    for symbol in bv.symbols:
        print(f"{symbol}")
    
    # Get symbol at address
    symbol = bv.get_symbol_at(0x0405064)
    if symbol:
        print(f"Symbol: {symbol.full_name}")
    
    # Get symbols by name
    sym_name = "_calculate"
    symbols = bv.get_symbols_by_name(sym_name)
    for sym in symbols:
        print(f"{sym_name} @ {hex(sym.address)}")
    
    # Get symbols by type
    from binaryninja import SymbolType
    func_symbols = bv.get_symbols_of_type(SymbolType.FunctionSymbol)
    for sym in func_symbols:
        print(f"Function symbol: {sym.full_name} @ {hex(sym.address)}")
```


### 8.2 Sections

```python
from binaryninja import *

with load("hello.exe") as bv:
    # Get all sections
    for section in bv.sections.values():
        print(f"Section: {section.name}")
        print(f"  Start: {hex(section.start)}")
        print(f"  End:   {hex(section.end)}")
        print(f"  Length: {hex(section.end - section.start)}")
        print(f"  Semantics: {section.semantics}")
    
    # Get section by name
    section = bv.get_section_by_name(".text")
    if section:
        print(f".text section: {hex(section.start)}-{hex(section.end)}")
    else:
        print(".text section not found")

    # Get sections at address (returns a list)
    address = 0x401000
    sections = bv.get_sections_at(address)
    for section in sections:
        print(f"Section containing {hex(address)}: {section.name}")

```


### 8.3 Segments

```python
from binaryninja import *

with load("hello.exe") as bv:
    # Get all segments
    for segment in bv.segments:
        print(f"Segment @ {hex(segment.start)}-{hex(segment.end)}")
        print(f"  Length: {hex(segment.length)}")
        print(f"  Readable: {segment.readable}")
        print(f"  Writable: {segment.writable}")
        print(f"  Executable: {segment.executable}")
    
    # Get segment at address
    segment = bv.get_segment_at(0x401000)
    if segment:
        print(f"Segment: {hex(segment.start)}-{hex(segment.end)}")
```



#### Additional Resources

- [Official Documentation](https://api.binary.ninja/)  
- [Developer Guide](https://docs.binary.ninja/dev/)
- [Plugin Repository](https://github.com/Vector35/community-plugins)
- [Example Scripts](https://github.com/Vector35/binaryninja-api/tree/dev/python/examples)