---
layout:     post
title:      "ELF file unpack Method"
subtitle:   "关于加壳程序脱壳的思路"
date:       2017-04-11 19:30:00 -0800
author:     "Dafeng"
header-img: "img/post-bg-universe.jpg"
header-mask: 0.3
catalog: true
tags:
    - ctf
    - ELF
---

### 加壳和反调试基础上   可以通过断点来抓取core文件分析的方式
> 一般加壳程序都会加上反调试功能，通常是通过检查父进程ID来判断程序是否被调试，所以我们来通过catch syscall ptrace在进程中打断点。

* （gdb） catch syscall ptrace getppid
* （gdb） r
* （gdb） c
* （gdb） generate-core-file（gcore）

> 然后拖入到IDA中通过strings 来定位分析  剩下的就是考验逆向功底了


### IDA远程调试， 脱壳操作往往在 jmp dword ptr [edi] 语句之后
* 在entry处单步调试，跟踪

### 直接dump运行时的内存镜像
1. $ps -ef | grep  xxx
2. cat /proc/xxx_pid/maps
3. 找到内存中text段和data段
4. dd if=/proc/pid/mem  of=/sdcard/aaa.elf  skip=xxx  bs= 1 count=xxxx
> 也可以通过python脚本来dump出程序运行的内存信息

两种方式都可以获取内存镜像
