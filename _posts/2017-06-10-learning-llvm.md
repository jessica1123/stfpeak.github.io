---
layout:     post
title:      "learning LLVM project —— clang"
subtitle:   "learning LLVM for development && security "
date:       2017-06-10 17:30:00 -0800
author:     "Dafeng"
header-img: "img/post-bg-universe.jpg"
header-mask: 0.3
catalog: true
tags:
    - LLVM
    - Clang
    - Address Sanitizer
---

## LLVM简介
The LLVM Project is a collection of modular and reusable compiler and toolchain technologies.

The primary sub-projects of LLVM are:

1. The **LLVM Core libraries** provide a modern source- and target-independent optimizer, along with code generation support for many popular CPUs (as well as some less common ones!) These libraries are built around a well specified code representation known as the LLVM intermediate representation ("LLVM IR"). The LLVM Core libraries are well documented, and it is particularly easy to invent your own language (or port an existing compiler) to use LLVM as an optimizer and code generator.

2. **Clang** is an "LLVM native" C/C++/Objective-C compiler, which aims to deliver amazingly fast compiles (e.g. about 3x faster than GCC when compiling Objective-C code in a debug configuration), extremely useful error and warning messages and to provide a platform for building great source level tools. The Clang Static Analyzer is a tool that automatically finds bugs in your code, and is a great example of the sort of tool that can be built using the Clang frontend as a library to parse C/C++ code.

3. **dragonegg** integrates the LLVM optimizers and code generator with the GCC parsers. This allows LLVM to compile Ada, Fortran, and other languages supported by the GCC compiler frontends, and access to C features not supported by Clang.

4. The **LLDB** project builds on libraries provided by LLVM and Clang to provide a great native debugger. It uses the Clang ASTs and expression parser, LLVM JIT, LLVM disassembler, etc so that it provides an experience that "just works". It is also blazing fast and much more memory efficient than GDB at loading symbols.

5. The **libc++** and **libc++ ABI** projects provide a standard conformant and high-performance implementation of the C++ Standard Library, including full support for C++11.

6. The **compiler-rt** project provides highly tuned implementations of the low-level code generator support routines like "__fixunsdfdi" and other calls generated when a target doesn't have a short sequence of native instructions to implement a core IR operation. It also provides implementations of run-time libraries for dynamic testing tools such as AddressSanitizer, ThreadSanitizer, MemorySanitizer, and DataFlowSanitizer.

7. The **OpenMP** subproject provides an OpenMP runtime for use with the OpenMP implementation in Clang.

8. The **vmkit** project is an implementation of the Java and .NET Virtual Machines that is built on LLVM technologies.

9. The **polly** project implements a suite of cache-locality optimizations as well as auto-parallelism and vectorization using a polyhedral model.

10. The **libclc** project aims to implement the OpenCL standard library.

11. The **klee** project implements a "symbolic virtual machine" which uses a theorem prover to try to evaluate all dynamic paths through a program in an effort to find bugs and to prove properties of functions. A major feature of klee is that it can produce a testcase in the event that it detects a bug.

12. The **SAFECode** project is a memory safety compiler for C/C++ programs. It instruments code with run-time checks to detect memory safety errors (e.g., buffer overflows) at run-time. It can be used to protect software from security attacks and can also be used as a memory safety error debugging tool like Valgrind.

13. The **lld** project aims to be the built-in linker for clang/llvm. Currently, clang must invoke the system linker to produce executables.

> LLVM包含多个组件，后续将重点研究其中的**CLANG**、**compiler-rt**、**klee**和**ldd**四个组件，此阶段的目的主要是为白盒测试（AFL/libFuzzer)技术研究。


## LLVM架构与设计思想
此章节请参见《开源应用架构》第11章，译文[LLVM](http://blog.csdn.net/wuhui_gdnt/article/details/24625281)。

## LLVM安装
从源码编译——[下载并编译LLVM](http://llvm.org/docs/GettingStarted.html)

直接下载所需要release版本——[Release](http://releases.llvm.org/download.html)，然后解压缩后拷贝对应的文件夹下，如xxx/bin里面的内容拷贝到系统/usr/bin/目录下，然后就可以直接使用。

## Clang
### What is clang?
Clang is one component in a complete toolchain for C family languages.

Clang is designed to support the C family of programming languages, which includes C, Objective-C, C++, and Objective-C++ as well as many dialects of those. For language-specific information, please see the corresponding language specific section:
* C Language: K&R C, ANSI C89, ISO C90, ISO C94 (C89+AMD1), ISO C99 (+TC1, TC2, TC3).
* Objective-C Language: ObjC 1, ObjC 2, ObjC 2.1, plus variants depending on base language.
* C++ Language
* Objective C++ Language
* OpenCL C Language: v1.0, v1.1, v1.2, v2.0.


### 命令行选项
#### 控制错误和警告信息的选项
  -Werror

  将警告转换成错误。

  -Wno-error=foo

  保持警告“foo”不被转换成错误，即使-Werror被指定。

  -Wfoo

  使能警告“foo”。

  -w

  禁用所有警告。

  -Weverything

  使能所有警告。

  -pedantic

  警告语言扩展。

  -pedantic-errors

  把语言扩展视作错误。

  -Wsystem-headers

  使能来自系统头文件的警告。

  -ferror-limit=123

  在诊断出123个错误之后停止诊断。默认是20，错误限制可以通过-ferror-limit=0来禁用。

  -ftemplate-backtrace-limit=123

  最多实例化123个模板在模板实例化回溯对于单个警告或错误。限制的默认是10，也可以通过-ftemplate-backtrace-limit=0来禁用。

  #### 格式化诊断信息
  Clang默认旨在生成漂亮的诊断信息，特被对于clang的新用户。然而，不同的人具有不同的喜好，并且有时候Clang被另一个程序调用想要解析简单和一致的输出，而不是一个人。对于这些情形，Clang提供了一个广泛的范围的选项来控制它生成的诊断信息的输出格式。

  **-f[no-]show-column**

  在诊断信息中打印列数。

  这个选项，默认是开启的，控制是否Clang打印一个诊断信息的列数。举个例子，当使能之后，Clang将会打印如下:

  test.c:28:8: warning: extra tokens at end of #endif directive [-Wextra-tokens]
  #endif bad
     ^
     //
  当被禁用之后，Clang将会打印"test.c:28:warning..."而没有列号。

  打印出的列号从一行开始计数；小心你的源代码中包含多字节字符。

  **-f[no-]show-source-location**

  在诊断信息中打印源 文件/行/列 信息。

  这个选项，默认是开启的，控制Clang是否打印一个诊断的文件名、行号和列号。举个例子，当被使能之后，Clang将会有如下输出:

  test.c:28:8: warning: extra tokens at end of #endif directive [-Wextra-tokens]
  #endif bad
     ^
  	   //
  当被禁用之后，Clang将不会打印"test.c:28:8"部分。

  **-f[no-]caret-diagnostics**

  在诊断信息中打印源代码文件行和范围。这个选项，默认是开启的，控制Clang在遇到一个诊断时候是否打印源行、代码范围和插入记号。举个例子，当被使能之后，Clang将会有如下输出:

  test.c:28:8: warning: extra tokens at end of #endif directive [-Wextra-tokens]
  #endif bad
     ^
  	   //
  **-f[no-]color-diagnostics**

  这个选项，在一个检测到兼容彩色的中断终端上默认是开启的，控制Clang是否带颜色输出。

  当被使能之后，Clang将会使用高粱指定诊断中特殊部分，例如:

  test.c:28:8: warning: extra tokens at end of #endif directive [-Wextra-tokens]
  #endif bad
     ^
  	   //
  当被禁用时候，Clang将只输出:

  test.c:28:8: warning: extra tokens at end of #endif directive [-Wextra-tokens]
  #endif bad
     ^
  	   //
  **-fdiagnostics-format=clang/msvc/vi**

  改变诊断输出使得更高的匹配IDE和命令行工具。

  这个选项控制诊断信息中文件名、行号和列的输出格式。这个选项和它的效果格式化一个简单变换诊断，如下:

  clang (默认)

  t.c:3:11: warning: conversion specifies type 'char *' but the argument has type 'int'
  msvc

  t.c(3,11) : warning: conversion specifies type 'char *' but the argument has type 'int'
  vi

  t.c +3:11: warning: conversion specifies type 'char *' but the argument has type 'int'
  -f[no-]diagnostics-show-name

  使能显示诊断名称。这个选项，默认是关闭的，控制Clang是否打印相关名称。

  **-f[no-]diagnostics-show-option**

  在诊断行中使能[-Woption]信息。

  这个选项，默认是开启的，控制输出一个警告诊断时候Clang是否打印相关的警告组选项名称。举个例子，在这个输出中:

  test.c:28:8: warning: extra tokens at end of #endif directive [-Wextra-tokens]
  #endif bad
     ^
  	   //
  传递-fno-diagnostics-show-option将会阻止Clang在诊断中打印[-Wextra-tokens]信息。这个信息告诉你需要使能或者禁止诊断的标志，不论是从命令行还是#pragma GCC diagnostic。

  **-fdiagnostics-show-category=none/id/name**

  使能在诊断行打印分类信息。

  这个选项，默认是"none",控制Clang在生成诊断的时候是否打印关联的分类。每个诊断信息可能关联或者无关联到一个类，如果有一个，它被列在诊断行中的类域中(在[]中)。

  举个例子，一个格式化字符串警告将会产生如下三行基于这个选项的设置:

  t.c:3:11: warning: conversion specifies type 'char *' but the argument has type 'int' [-Wformat]
  t.c:3:11: warning: conversion specifies type 'char *' but the argument has type 'int' [-Wformat,1]
  t.c:3:11: warning: conversion specifies type 'char *' but the argument has type 'int' [-Wformat,Format String]
  分类可以被客户端使用需要按照类把诊断信息分组的话，所以它应当是一个高的级别。我们只需要几十个，而不是成百上千。

  **-f[no-]diagnostics-fixit-info**

  在诊断输出中使能"FixIt"信息。

  这个选项，默认是开启的，控制Clang当它知道时是否打印如何修复特定诊断信息。举个例子，在这个输出中:

  test.c:28:8: warning: extra tokens at end of #endif directive [-Wextra-tokens]
  #endif bad
     ^
  	   //
  传递-fno-diagnostics-fixit-info将会阻止Clang打印末尾的"//"行。这个信息对不了解是什么错误的用户是非常有用的，但是可能会迷惑机器解析。

  **-fdiagnostics-print-source-range-info**

  打印机器可以解析的有关源范围的信息。这个选项使得Clang以机器可解析格式在 文件/行/列 后打印有关源范围信息。这个信息是一些花括号中的简单序列，每个范围列出了开始和结束 行/列 位置。举个例子，在这个输出中:

  exprs.c:47:15:{47:8-47:14}{47:17-47:24}: error: invalid operands to binary expression ('int *' and '_Complex float')
  P = (P-42) + Gamma*4;
    ~~~~~~ ^ ~~~~~~~
  {}是由 -fdiagnostics-print-source-range-info 产生的。

  打印的列号从行开始计数；小心你的文件中多字节字符。

  **-fdiagnostics-parseable-fixits**

  以机器可解析格式打印Fix-It。

  这个选项使得Clang以一种机器可解析的格式在诊断末尾打印可用的Fix-It信息。下边的例子展示了格式:

  fix-it:"t.cpp":{7:25-7:29}:"Gamma"
  输出中的范围是一个半开范围，所以在这个例子中列t.cpp中25起的字符到但是不包含行7列29的字符串应当被"Gamma"替换。这个范围或者取代字符串都可能为空(分别代表严格的插入和严格擦除)。文件名和插入字符串逃逸反斜杠("\"),tab("\t"),新行("\n")，双引号(""")和不可打印字符(八进制"\xxx")。

  打印的列号从行首开始计数；小心文件中的多字节字符。

  **-fno-elide-type**

  在模板类型打印中关闭省略。

  默认的模板类型打印省略尽可能多的模板参数，移除在模板类型中相同的，只留下不同的。添加这个标志将会打印所有模板参数。如果终端支持，高亮将出现在不同的参数。

  默认:

  t.cc:4:5: note: candidate function not viable: no known conversion from 'vector<map<[...], map<float, [...]>>>' to 'vector<map<[...], map<double, [...]>>>' for 1st argument;
  -fno-elide-type:

  t.cc:4:5: note: candidate function not viable: no known conversion from 'vector<map<int, map<float, int>>>' to 'vector<map<int, map<double, int>>>' for 1st argument;

  **-fdiagnostics-show-template-tree**

  模板类型区分打印文本的树。

  对于大型的模板类型，这个选项将会导致一个故意的文本树，一个参数一行，具有不同的行内标记。这与 -fno-elide-type 兼容。

  默认:

  t.cc:4:5: note: candidate function not viable: no known conversion from 'vector<map<[...], map<float, [...]>>>' to 'vector<map<[...], map<double, [...]>>>' for 1st argument;
  使用 -fdiagnostics-show-template-tree

  t.cc:4:5: note: candidate function not viable: no known conversion for 1st argument;
  vector<
  map<
  [...],
  map<
  [float != float],
  [...]>>>



#### 单独警告组
  TODO: 从tblgen生成这个。为每个警告组定义一个锚。

  **-Wextra-tokens**

  警告一个预处理指令尾部的过度的标识符。

  这个选项，默认是开启的，使能警告一个预处理指令尾部的过度的标识符。举例如下:

  test.c:28:8: warning: extra tokens at end of #endif directive [-Wextra-tokens]
  #endif bad
     	   ^
  这些额外的标识符不严格符合，通常最好注释掉他们。

  **-Wambiguous-member-template**

  警告有关不合格的成员模板的使用，在使用点名字解析到另一个模板。

  这个选项，默认是开启的，使能警告如下代码中:
```c
  template<typename T> struct set{};
  template<typename T> struct trait { typedef const T& type; };
  struct Value {
    template<typename T> void set(typename trait<T>::type value) {}
  };
  void foo() {
  	Value v;
    	v.set<double>(3.2);
  }
```
  C++[basic.lookup.classref] 需要这个成为一个错误，但是，因为工作比较苦难，Clang把它降级为一个警告作为一个扩展。

  **-Wbind-to-temporary-copy**

  警告关于一个不可用的复制构造器当绑定一个引用到一个暂时的。

  这个选项，默认是开启的，使能警告有关绑定一个引用到一个临时的，当临时的没有一个可用的复制构造子。举个例子:
```c
  struct NonCopyable {
    NonCopyable();
  private:
  NonCopyable(const NonCopyable&);
  };
  void foo(const NonCopyable&);
  void bar() {
    foo(NonCopyable());  // Disallowed in C++98; allowed in C++11.
  }

  struct NonCopyable2 {
    NonCopyable2();
    NonCopyable2(NonCopyable2&);
  };
  void foo(const NonCopyable2&);
  void bar() {
    foo(NonCopyable2());  // Disallowed in C++98; allowed in C++11.
  }
```
  注意如果 NonCopyable2::NonCopyable2() 具有一个默认参数，它的实例化产生一个编译错误，这个错误在C++98模式中仍然是一个硬错误，即使这个警告被关闭。




#### 控制代码生成
Clang提供了很多种方式来控制代码生成。选项列表如下:

-fsanitize=check1,check2,...

开启运行时对于多种未定义的或者可疑的行为进行检查。

这个选项控制Clang是否添加运行时对于多种未定义的或者可疑的行为进行检查，默认是关闭的。如果一个检查失败，将会有一个运行时的一个诊断信息生成来解释这个问题。主要检查有:

-fsanitize=address: AddressSanitizer, 一个内存错误检查器。

-fsanitize=init-order: 使得 AddressSanitizer 检查动态初始化顺序问题。Implied by -fsanitize=address.

-fsanitize=address-full: AddressSanitizer 具有所有下面所列的实验性质的特性。

-fsanitize=integer: 使能检查未定义的或者可疑的整数行为。

-fsanitize=thread: ThreadSanitizer, 一个数据竞争检测器。

-fsanitize=memory: MemorySanitizer, 一个实验性质的未初始化读检查器。还不适合广泛使用。

-fsanitize=undefined: 快速的，兼容的未定义行为监测器。使能未定义行为检测，具有很小的运行环境开销并对地址空间布局或ABI没有影响。这包含了下面所列的所有的检测而不单单是 unsigned-integer-overflow 。

-fsanitize=undefined-trap: 这包含所有被 -fsantiize=undefined 包含的 sanitizers, 除了那些需要运行环境支持的。这一组的 sanitizers 通常与

-fsanitize-undefined-trap-on-error 标志结合使用, 将会导致陷阱被触发, 而不是到运行库的调用。这包含了下面所列的所有检查而不单单是 unsigned-integer-overflow 和 vptr 。
下面是更多的更细的可用检查:

-fsanitize=alignment: 使用一个未对齐的指针或者引用。

-fsanitize=bool: 加载一个既不是真也不是假的bool值。

-fsanitize=bounds: 数组索引越界, 以防数组边界可以静态检测。

-fsanitize=enum: 加载一个枚举类型的值，但是值不在那个枚举类型范围内。

-fsanitize=float-cast-overflow: 转换到, 从, 或者浮点类型之间，其目标可能会溢出。

-fsanitize=float-divide-by-zero: 浮点除零。

-fsanitize=integer-divide-by-zero: 整数除零。

-fsanitize=null: 使用一个空指针或者创建一个空引用。

-fsanitize=object-size: 尝试使用优化器可以探测到不属于访问对象的字节。 对象的大小使用 __builtin_object_size 检测, 并且结果可能会探测到多个问题在高层次的优化。

-fsanitize=return: 在 C++ 中, 到达一个具有返回值类型函数的末尾而没有返回值。

-fsanitize=shift: 移位操作符的移位大小超过了位宽或者小于零，或者左边是负值。 对于有符号数移位, 检查C中的有符号溢出，在C++中检查无符号溢出。

-fsanitize=signed-integer-overflow: 有符号整数溢出, 包含所有通过 -ftrapv 添加的检查, 并且检查有符号除法溢出 (INT_MIN / -1)。

-fsanitize=unreachable: 如果控制流到达 __builtin_unreachable.

-fsanitize=unsigned-integer-overflow: 无符号整数溢出。

-fsanitize=vla-bound: 可变长数组边界值非正。

-fsanitize=vptr: 使用一个vptr预示着具有错误动态类型的对象，或者它的生命长度还未开始或者已经结束。与 -fno-rtti 兼容。

AddressSanitizer 的实验性质的特性(还未准备好被广泛使用, 需要明确指定 -fsanitize=address):

-fsanitize=use-after-return: 检查 use-after-return 错误 (在函数退出之后访问局部变量)。
-fsanitize=use-after-scope: 检查 use-after-scope 错误 (在有效域范围外访问局部变量)。
MemorySanitizer 的额外特性(需要明确指定 -fsanitize=memory):

-fsanitize-memory-track-origins: 使能MemorySanitizer中的原始跟踪。 加上一个额外的区域到 MemorySanitizer 报告指向堆或者栈分配未初始化位的来源。执行速度减慢 1.5x-2x.
为了连接到合适的运行库，连接时必须提供 -fsanitize= 参数。不可能在相同的程序中结合 -fsanitize=address 与 -fsanitize=thread 检查。

-f[no-]address-sanitizer

过时的 -f[no-]sanitize=address 的同义词。

-f[no-]thread-sanitizer

过时的 -f[no-]sanitize=thread 的同义词。

-fcatch-undefined-behavior

过时的 -fsanitize=undefined 的同义词。

-fno-assume-sane-operator-new

不要假定C++的新操作是健壮的。

这个选项告诉编译器不要假定C++全局新操作符将会一直返回一个指针而不是其他指针的别名，在函数返回的时候。

-ftrap-function=[name]

指令代码生成器发出一个函数调用到指定的函数名称 __builtin_trap()。

LLVM代码生成器翻译 __builtin_trap() 到一个陷阱指令，如果被目标ISA支持的话。否则，内建被翻译为到abort的调用。如果这个选项被设置，代码生成器将会一直使用内建到一个指定函数而不论是否目标ISA具有陷阱指令。这个选项对于那些不能正确处理陷阱，或者需要定制行为的环境(例如深层嵌入)。

-ftls-model=[model]

选择要使用的TLS模式。

有效值为: global-dynamic, local-dynamic, initial-exec 和 local-exec. 默认值为 global-dynamic。 编译器可能会使用一个不同的模式，如果选择的模式不被目标支持或者具有更具效率的模式可用。TLS模式可以通过每个变量使用tls_model属性来重载。

#### 控制调试信息大小
clang的调试信息类型生成可以设置为下表中的一种。如果有多个标志，使用最后一个。

**-g0**

不生成任何调试信息(默认)。

**-gline-tables-only**

只生成行号表。

这种调试信息允许使用函数名，文件名和行号进行观察栈跟踪(通过这类工具例如 gdb 或者 addr2line)。它不包含任何其他数据 (举个例子: 局部变量的描述或者函数参数)。

**-g**

生成完整的调试信息。

> clang说明参考[clang手册](https://github.com/oxnz/clang-user-manual/blob/master/clang-user-manual.md)

## 总结
此篇从llvm组件介绍起，编译安装以及编译器clang options，来初步了解llvm以及clang，后续文章将着重介绍clang在实际中的应用，结合起编译特性ASAN/MSAN/UBSAN等来检查内存中的错误，继而介绍AFL/libFuzzer Fuzzing工具，以及在实际中的应用。
