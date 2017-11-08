---
layout:     post
title:      "Pwn2Win Reverse -- Achievement Unlocked"
subtitle:   "How to use gdb python script to crack the flag"
date:       2017-11-08 19:30:00 -0800
author:     "Dafeng"
header-img: "img/post-bg-universe.jpg"
header-mask: 0.3
catalog: true
tags:
    - CTF
    - Pwn
    - gdb
---

### 简述
Pwn2Win 2017 Reverse problem, 运行程序后如下图：
![程序运行](/img/ach/input.png)

### 逆向分析程序

使用IDA Pro分析binary程序，发现程序在进行复杂的操作后有一个长30位的数值比较，如图：
![数值比较](/img/ach/re1.png)

从汇编上查看程序：
![re](/img/ach/re2.png)

### gdb调试程序
使用gdb peda调试程序，并在0x484e1b处打断点，分析可知当输入中的每一个位置输入正确时，断点处rax的值就和图1中分支的值相同，并且分析可知，每个位置运算得到的值只跟输入得字节和字节所在的位置有关。
![com](/img/ach/com.png)
![com2](/img/ach/comp2.png)

然后我的思路是将30位相同的字符，如果正确那么在经过计算之后，那么结果就会跟对应位置上的值相等。

##### gdb脚本
```python
#!/usr/bin/env python
# coding=utf-8
import gdb

strlen = 30
charsets = "0123456789-_qwertyuioplkjhgfdsazxcvbnmQWERTYUIOPLKJHGFDSAZXCVBNM{}!"
targetnum = [0xd0, 0x71, 0xe6, 0x32, 0xf, 0x3a, 0x9, 0x2e, 0xf8, 0xa1, 0xb6, 0x52, 0xde, 0xcd, 0x65, 0x72, 0x52,\
        0x9f, 0x4f, 0xb9, 0xf4, 0x72, 0x76, 0xc1, 0x34, 0x35, 0xee, 0xf7, 0xda, 0x50]
flagstr =[0 for n in range(strlen)]
gin = 0

class Cal(gdb.Command):
    def __init__(self):
        super(Cal,self).__init__("tocal",gdb.COMMAND_USER)

    def getreg(self, register):
        r = register.lower()
        regs = gdb.execute("info registers %s" % r, to_string=True)
        if regs:
            regs = regs.splitlines()
            if len(regs) > 1:
                return None
            else:
                result = int(str(regs[0].split()[1]), 0)
                return result
        return None

    def get_status(self):
        status = "UNKNOWN"
        out = gdb.execute("info program", to_string=True)
        for line in out.splitlines():
            if line.startswith("It stopped"):
                if "signal" in line: # stopped by signal
                    status = line.split("signal")[1].split(",")[0].strip()
                    break
                if "breakpoint" in line: # breakpoint hit
                    status = "BREAKPOINT"
                    break
            if "not being run" in line:
                status = "STOPPED"
                break
        return status

    def invoke(self, arg, from_tty):
        global gin
        print(gin)
        print(charsets[gin] * strlen)
        gdb.execute('set pagination off')
        gdb.execute('b *0x484e1b')
        gdb.execute('r')
        #for index in range(len(charsets)):
        while 1:           
            totry = charsets[gin] * strlen
            print(totry)
            tmparr = [0 for n in range(strlen)]
            for cy in range(strlen):
                runstat = self.get_status()  
                if runstat == "BREAKPOINT":
                    rax_v = self.getreg("rax")
                    tmparr[cy] = rax_v
                    gdb.execute('c')
                elif runstat == "STOPPED":
                    gin += 1
                    gdb.execute('r')
                    break
                else:
                    #gdb.execute('c')  
                    pass                 
            print(tmparr)

            for an in range(strlen):
                if tmparr[an] == targetnum[an] and gin > 0:
                    flagstr[an] = charsets[gin -1]

            #print(flagstr)
            print(''.join(str(flagstr[n]) for n in range(len(flagstr))))

Cal()

```
> 部分代码借鉴peda源码

操作如下：
1. $ gdb ./Achievement
2. $ source cal.py
3. $ tocal

![caozuo](/img/ach/caozuo.png)
每次需要输入flag的时候，输入[New LWP XXXX]上面的字符串。
最后当输入完成后：
![ach](/img/ach/ach.png)


### 总结
这篇writeup主要练习了，如何编写gdb python script，从而更加方便的进行gdb调试。

### 参考
* [Extending GDB using Python](https://sourceware.org/gdb/current/onlinedocs/gdb/Python.html#Python)
