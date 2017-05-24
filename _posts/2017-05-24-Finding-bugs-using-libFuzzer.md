---
layout:     post
title:      "Finding bugs using libFuzzer"
subtitle:   "Fuzzing测试--软件漏洞挖掘利器"
date:       2017-05-24 19:30:00 -0800
author:     "Dafeng"
header-img: "img/post-bg-universe.jpg"
header-mask: 0.3
catalog: true
tags:
    - Fuzzing
    - libFuzzer
    - Address Sanitizer
---

## Fuzzing测试
当前随着网络安全的兴起，大大小小的公司都开始注重软件安全，顺利成章的造就了我们这样的一个群体————网络安全研究员，也叫白帽子。哈哈，开个玩笑。。。

软件漏洞挖掘有多种方法： 黑盒测试／白盒测试／灰盒测试；
其中：
1. 黑盒测试：渗透测试，无源码测试
2. 白盒测试：源码审计
3. 灰盒测试：Fuzzing测试，模糊测试

## libFuzzer
已经研究了很久afl-fuzz工具，网上也有很多人总结该工具的使用，讲述libFuzzer的寥寥无几，此篇文章从libFuzzer的英文说明文档开始，结合简单的demo来说明libFuzzer的工作原理，以及使用方法。后续也会补充afl-fuzz／oss-fuzz等工具的相关研究。

### 简介

LibFuzzer是在持续执行，基于覆盖引导，演进式的模糊测试引擎。

LibFuzzer与被测试的库链接，并通过特定的模糊入口（也称为“目标函数”）将模糊输入的样例集提供给library。然后模糊器跟踪代码会执行到哪些模板，并且在输入数据的语料库上产生突变，以便最大化代码覆盖度。libFuzzer的代码覆盖信息由LLVM的[SanitizerCoverage](http://clang.llvm.org/docs/SanitizerCoverage.html)指令执行提供。

### 安装
安装最行版的最新版的clang

ubuntu安装方法参见： http://apt.llvm.org/

获取源码编译，请自行Google

### Fuzzing target
使用libFuzzer的第一步是实现一个fuzz target ———— 一个接受一个字节数组的函数，并使用被测试的API对这些字节做一些有趣的事情，如下所示：
``` c
// fuzz_target.cc
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
  DoSomethingInterestingWithMyAPI(Data, Size);
  return 0;  // Non-zero return values are reserved for future use.
}

```

注意事项：
* 模糊引擎将在同一过程中使用不同的输入多次执行模糊测试目标。
* 必须容忍任何类型的输入（空，巨大的数，畸形数据等）。
* 任何输入不能包含exit()。
* 可能使用线程，但理想情况下，所有线程都应在函数结束时加入。
* 它必须尽可能确定。非确定性（例如，不依赖于输入字节的随机决策）将使模糊效率低下。
* 一定要快 尝试避免立方或更大的复杂性，记录或过多的内存消耗。
* 理想情况下，它不应该修改任何全局状态（尽管不是严格的）。
* 通常，目标越窄越好。例如，如果您的目标可以解析多种数据格式，将其分成几个目标，每种格式一个。


### Example
要使用libFuzzer，准备文件结构如下：

    - Fuzz
        - libFuzzer.a
        - target.cc
        - func.h
        - func.c

libFuzzer.a获取方法：        
1. svn co http://llvm.org/svn/llvm-project/llvm/trunk/lib/Fuzzer  
2. git clone https://chromium.googlesource.com/chromium/llvm-project/llvm/lib/Fuzzer

编译： ./Fuzzer/build.sh   # Produces libFuzzer.a
> 建议把build.sh里的CXX修改为 clang-4.0


将libFuzzer.a拷贝到Fuzz文件夹下，其他文件源码如下：

**target.cc**
```c
#include "func.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
  vuln(Data, Size);
  return 0;  // Non-zero return values are reserved for future use.
}

```

**func.h**
```c
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

int vuln(const uint8_t *Data, size_t Size);

```

**func.c**
```c
#include "func.h"

int vuln(const uint8_t *Data, size_t Size)
{
    char buf[16];
    int num = rand() % 100 + 1;
    if(Data[0] == 'C' && num > 50)
    {
        printf("This is a vuln branch\n");
        memcpy(buf, Data, Size);
    }
    else{
        printf("good branch\n");
    }
    return 0;
}

```
触发crash的条件是Fuzz编译生成的种子的第一个字符是‘C’，并且rand()函数随机生成并计算的值大于50,然后会触发memcpy，当Data数据的长度大于16时，程序会发生栈溢出而crash。

编译：

clang++-4.0 -fsanitize=address -fno-omit-frame-pointer -fsanitize-coverage=trace-pc-guard,trace-cmp,trace-gep,trace-div func.c target.cc libFuzzer.a -o my_fuzzer

文件的截图：
![folder](/img/libFuzzer/folder.png)

运行可执行文件：
./my_fuzzer

大概花费1s:
![result](/img/libFuzzer/result.png)

在文件夹下生成一个crash文件，参考crash文件：
![crash](/img/libFuzzer/crash.png)

分析可得： 生成的输入文件的内容，以‘C’开头，并且长度大于16，此次随机生成的数也大于50，从而使使程序执行memcpy而导致栈溢出crash。

### 总结

以上是libFuzzer的一个简单的例子，但是libFuzzer是一个用于漏洞挖掘非常有用的工具。在做项目中，如针对某些基础平台源码，协议源码都可以编写对应的测试套进行fuzzing测试，结果发现10+严重问题，由于公司机密，不可透漏，不过也难以遮盖libFuzzer fuzzing功能的强大。
