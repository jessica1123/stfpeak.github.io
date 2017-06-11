---
layout:     post
title:      "Finding bugs using AFL"
subtitle:   "Fuzzing测试--软件漏洞挖掘利器"
date:       2017-06-11 17:30:00 -0800
author:     "Dafeng"
header-img: "img/post-bg-universe.jpg"
header-mask: 0.3
catalog: true
tags:
- AFL
- Fuzzing
---

## 简述
AFL号称是当前最高级的Fuzzing测试工具之一，由lcamtuf所开发。在众多安全会议白帽演讲中都介绍过这款工具，以及2016年defcon大会的CGC(Cyber Grand Challenge，形式为机器自动挖掘并修补漏洞)大赛中多支队伍利用AFL fuzzing技术与符号执行(Symbolic Execution)来实现漏洞挖掘，其中参赛队伍shellphish便是采用AFL(Fuzzing) + angr(Symbolic Execution)技术。  

AFLFuzzing工作原理：通过对源码进行重新编译时进行插桩（简称编译时插桩）的方式自动产生测试用例来探索二进制程序内部新的执行路径。

与其他基于插桩技术的fuzzers相比，afl-fuzz具有较低的性能消耗，有各种高效的fuzzing策略和tricks最小化技巧， 不需要先行复杂的配置，能无缝处理复杂的现实中的程序。当然AFL也支持直接对没有源码的二进制程序进行测试，但需要QEMU的支持。

本文主要是以入门使用为主，介绍如何使用AFL Fuzzing。

> CGC大赛主要利用技术包括：动态分析(Dynamic Analysis)、静态分析(Static Analysis)、符号化执行(Symbolic Execution)、Constraint Solving、资讯流追踪技术(Data Flow Tracking)以及自动化测试(Fuzz Testing)

## 安装
1. 从[官网](http://lcamtuf.coredump.cx/afl/)下载最新版的[源码](http://lcamtuf.coredump.cx/afl/releases/afl-latest.tgz)（latest version），解压后进入所在目录。
2. 执行以下命令进行编译和安装：
* make
* sudo make install


## AFL工作流程
### AFL工作原理简介
使用afl-gcc编译工程代码，然后以文件(尽量 <1K)为输入，然后启动afl-fuzz程序，将testcase(seed) 喂给程序代码，然后程序接收此次输入执行程序，如果发现新的路径则保存此testcase到一个queue中，afl-fuzz继续编译testcase，因此程序每次接收不同的输入，如果程序崩溃，则记录crash。
> AFL设计思想在后续使用一篇文章介绍AFL特性与设计思想


### AFL Fuzzing步骤
1. 使用afl-gcc编译项目代码，将编译脚本中的CC=afl-gcc/CXX=afl-g++；
2. 新建两个文件夹，如fuzz_in/fuzz_out,文件夹名随意；
3. 将初始化testcase放到fuzz_in目录下；
4. 执行afl-fuzz -i fuzz_in -o fuzz_out ./xxx @@   xxx为可执行程序名，@@表示从文件中读入
5. 观察fuzzing结果，如有crash，定位问题。

## 示例
### 示例代码
```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>


int vuln(char *Data) {
//printf("Data Size is :%d\n", Size);
int num = rand() % 100 + 1;
//printf("num is %d\n", num);
printf("Data is generated, num is %d\n", num);
if(Data[0] == 'C' && num == 25)
{
    raise(SIGSEGV);
}
else if(Data[0] == 'F' && num == 90)
{
    raise(SIGSEGV);
}
else{
    printf("it is good!\n");
}
return 0;
}

int main(int argc, char *argv[])
{
char buf[40]={0};
FILE *input = NULL;
input = fopen(argv[1], "r");
if(input != 0)
{
    fscanf(input, "%s", &buf);
    printf("buf is %s\n", buf);
    vuln(buf);
    fclose(input);
}
else
{
    printf("bad file!");
}
return 0;
}

```
> 程序说明： 如果编译的数据第一个字母是'C'并且num=25 或者第一个字母是'F'并且num=90,那么程序异常退出。

### 编译
afl-gcc -g -o afl_test  afl_test.c


### 准备环境
1. 新建输入、输出文件夹： mkdir fuzz_in fuzz_out
2. 准备初始化testcase, 将testcase内容随意写成aaa: echo aaa > fuzz_in/testcase

### 开始Fuzzing
afl-fuzz -i fuzz_in -o fuzz_out ./afl_test @@

启动afl-fuzz中往往会报错，表示某些环境变量没有配置或者配置错误，如![core](/img/afl/core.png)
没有打开错误转储机制，执行命令：
* sudo su
* echo core >/proc/sys/kernel/core_pattern

> 根据提示，修改或配置afl-fuzz options以及系统环境变量

重新执行afl-fuzz -i fuzz_in -o fuzz_out ./afl_test @@
![afl](/img/afl/core.png)

### 定位crash
1. 打开设定的fuzz_out目录，如下![out_dir](/img/afl/out_dir.png)
2. 打开crash目录，可以看到crash文件![crashes](/img/afl/crashes.png)
将crash文件用作输入可以使程序崩溃 ./afl_test fuzz_out/crashes/id:000002,sig:06,src:000002,op:havoc,rep:8
然后gdb调试即可

### 结论
查看使程序崩溃的输入文件![file](/img/afl/file.png),可以查看文件内容,符合程序崩溃逻辑。

## 总结
此文章以简单的例子，是AFL Fuzzing工具跑起来，后续将深入分析AFL Fuzzing在实际项目中的应用。
