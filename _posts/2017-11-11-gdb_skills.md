---
layout:     post
title:      "some useful gdb skills"
subtitle:   "use gdb to debug"
date:       2017-11-11 9:30:00 -0800
author:     "Dafeng"
header-img: "img/post-bg-universe.jpg"
header-mask: 0.3
catalog: true
tags:
    - gdb
---

#### 背景
经常使用gdb peda调试程序，一直没有阅读gdb手册，此篇作为一个阅读笔记，工作中更多的喜欢使用gdb python脚本。
* [gdb python](https://sourceware.org/gdb/current/onlinedocs/gdb/Python.html#Python)
* [gdb python 实例](https://stfpeak.github.io/2017/11/08/pwn2win_reverse_Achievement_Unlock/)


#### gdb带参数启动
1. gdb --args xxx arg0 arg1 ...
2. gdb   &  set args xxx arg0 arg1 ...

#### 将GDB中需要的调试信息输出到文件
1. $ (gdb) set logging file <文件名>
设置输出的文件名称
2. $ (gdb) set logging on
输入这个命令后，此后的调试信息将输出到指定文件
3. $ (gdb) thread apply all bt
打印说有线程栈信息
4. $ (gdb) set logging off
输入这个命令，关闭到指定文件的输出

#### set pagination off
1. disable ---Type <return> to continue, or q <return> to quit---

#### 程序继续执行
1. continue [ignore-count]
2. c [ignore-count]
3. fg [ignore-count] 恢复程序运行，直到程序结束，或是下一个断点到来。
**ignore-count表示忽略其后的断点次数。**

#### step mode
1. set step-mode on  打开step-mode模式，于是，在进行单步跟踪时，程序不会因为没有debug信息而不停住,这个参数有很利于查看机器码。
2. set step-mod off 关闭step-mode模式。

#### 查看&&设置gdb环境变量
1. show env 查看环境变量
2. set env AAA=aaa 设置环境变量AAA

#### 查看程序运行的状态
1. info program  来查看程序的是否在运行，进程号，被暂停的原因。
> 分别有*遇见断点，*遇见断点后的step, *程序停止，*信号让程序停止以及*程序接收输入。
```python
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
```

遇见断点后step
Program stopped at 0x484e41.
It stopped after being stepped.

程序接收输入
Program stopped at (0x7f549b1936f0) e.g

#### 调试多个子程序
GDB允许在一个单独的session里面调试多个程序。有些系统允许GDB同时运行多个程序，更一般的情况，在每一个进程中有多个线程执行。
GDB用 **inferior** 来表示每个程序执行，inferior与进程对应，也可用于没有进程的target。Inferiors在进程运行之前创建，在进程退出之后保留。Inferior也有自己的标记，这个标记与PID不同。

#### store/load 调试程序的断点到文件
1. save breakpoints break.cfg
2. source break.cfg


#### 定义钩子命令
钩子用来在执行某个命令前或命令后，先执行某个或某些命令。
假如想在执行print命令前显示一段 “----------”，则：

    define hook-print
    echo ----------/n
    end

**注意“hook-”后接的必须是命令全称，不能是缩写。**

如果想在命令执行完之后，再执行某个或某些命令，则：

    define hookpost-print
    echo ----------/n
    end
