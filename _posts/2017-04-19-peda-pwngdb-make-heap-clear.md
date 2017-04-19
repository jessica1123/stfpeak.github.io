---
layout:     post
title:      "peda & pwngdb make heap clear"
subtitle:   "Tools to help me understand heap better"
date:       2017-04-19 19:30:00 -0800
author:     "Dafeng"
header-img: "img/post-bg-universe.jpg"
header-mask: 0.3
catalog: true
tags:
    - CTF
    - Tools
    - Heap
---

## Heap tools
libHeap maybe not easy to install, and I find that peda & Pwngdb are alse good enough to handle many problems.

### Install peda

git clone https://github.com/longld/peda.git ~/peda

#### Key Features

* Enhance the display of gdb: colorize and display disassembly codes, registers, memory information during debugging.
* Add commands to support debugging and exploit development (for a full list of commands use peda help):
* aslr -- Show/set ASLR setting of GDB
* **checksec** -- Check for various security options of binary
* dumpargs -- Display arguments passed to a function when stopped at a call instruction
* dumprop -- Dump all ROP gadgets in specific memory range
* elfheader -- Get headers information from debugged ELF file
* elfsymbol -- Get non-debugging symbol information from an ELF file
* lookup -- Search for all addresses/references to addresses which belong to a memory range
* patch -- Patch memory start at an address with string/hexstring/int
* **pattern** -- Generate, search, or write a cyclic pattern to memory
* procinfo -- Display various info from /proc/pid/
* pshow -- Show various PEDA options and other settings
* pset -- Set various PEDA options and other settings
* readelf -- Get headers information from an ELF file
* ropgadget -- Get common ROP gadgets of binary or library
* ropsearch -- Search for ROP gadgets in memory
* searchmem|find -- Search for a pattern in memory; support regex search
* shellcode -- Generate or download common shellcodes.
* skeleton -- Generate python exploit code template
* **vmmap** -- Get virtual mapping address ranges of section(s) in debugged process
* xormem -- XOR a memory region with a key


### Install pwngdb

cd ~/
git clone https://github.com/scwuaptx/Pwngdb.git
cp ~/Pwngdb/.gdbinit ~/

#### .gdbinit
    source ~/peda/peda.py
    source ~/Pwngdb/pwngdb.py
    source ~/Pwngdb/angelheap/gdbinit.py

    define hook-run
    python
    import angelheap
    angelheap.init_angelheap()
    end
    end
> change this file to your patch

#### Heapinfo

If you want to use the feature of heapinfo and tracemalloc , you need to install libc debug file (libc6-dbg & libc6-dbg:i386 for debian package)

#### Key Features
* libc : Print the base address of libc
* ld : Print the base address of ld
* codebase : Print the base of code segment
* heap : Print the base of heap
* got : Print the Global Offset Table infomation
* dyn : Print the Dynamic section infomation
* findcall : Find some function call
* bcall : Set the breakpoint at some function call
* tls : Print the thread local storage address
* at : Attach by process name
* findsyscall : Find the syscall
* fmtarg : Calculate the index of format string
    * You need to stop on printf which has vulnerability.
* force : Calculate the nb in the house of force.
* **heapinfo** : Print some infomation of heap
* chunkinfo: Print the infomation of chunk
    * chunkinfo (Address of victim)
* chunkptr : Print the infomation of chunk
    * chunkptr (Address of user ptr)
* mergeinfo : Print the infomation of merge
    * mergeinfo (Address of victim)
* printfastbin : Print some infomation of fastbin
* **tracemalloc on** : Trace the malloc and free and detect some error .
    * You need to run the process first than tracemalloc on, it will record all of the malloc and free.
    * You can set the DEBUG in pwngdb.py , than it will print all of the malloc and free infomation such as the screeshot.
* **parseheap : Parse heap layout**

> tips: when gdb is attached, tracemalloc on then we can get a record of heap change.
