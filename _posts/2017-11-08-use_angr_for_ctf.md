---
layout:     post
title:      "How to use angr for CTF"
subtitle:   "use angr to crack the flag"
date:       2017-11-08 19:30:00 -0800
author:     "Dafeng"
header-img: "img/post-bg-universe.jpg"
header-mask: 0.3
catalog: true
tags:
    - CTF
    - Pwn
    - angr
---

#### 什么是angr?

angr是一个二进制代码分析工具，能够自动化完成二进制文件的分析，并找出漏洞。在二进制代码中寻找并且利用漏洞是一项非常具有挑战性的工作，它的挑战性主要在于人工很难直观的看出二进制代码中的数据结构、控制流信息等。angr是一个基于python的二进制漏洞分析框架，它将以前多种分析技术集成进来，­­­它能够进行动态的符号执行分析（如，KLEE和Mayhem），也能够进行多种静态分析。

#### angr过程简述
1）将二进制程序载入angr分析系统

2）将二进制程序转换成中间件语言（intermediate representation, IR）

3）将IR语言转换成语义较强的表达形式，比如，这个程序做了什么，而不是它是什么。

4）执行进一步的分析，比如，完整的或者部分的静态分析（依赖关系分析，程序分块）、程序空间的符号执行探索（挖掘溢出漏洞）、一些对于上面方式的结合。

#### angr安装
**Linux**

$ apt-get install python-dev libffi-dev build-essential virtualenvwrapper

$ mkvirtualenv angr && pip install angr

#### 简单例子
```python
import angr
main = 0x4007DA
find = 0x404FBC
avoid = [0x400590]
p = angr.Project('./angrybird2')
init = p.factory.blank_state(addr=main)
pg = p.factory.path_group(init, threads=8)
ex = pg.explore(find=find, avoid=avoid)
final = ex.found[0].state
flag = final.posix.dumps(0)
print("Flag: {0}".format(final.posix.dumps(1)))

```

#### 执行程序然后从标准输入输入数据
```python
#!/usr/bin/env python
# coding: utf-8
import angr
import time

def main():
    # Load the binary. This is a 64-bit C++ binary, pretty heavily obfuscated.
    p = angr.Project('wyvern')

    # This block constructs the initial program state for analysis.
    # Because we're going to have to step deep into the C++ standard libraries
    # for this to work, we need to run everyone's initializers. The full_init_state
    # will do that. In order to do this peformantly, we will use the unicorn engine!
    st = p.factory.full_init_state(args=['./wyvern'], add_options=angr.options.unicorn)

    # It's reasonably easy to tell from looking at the program in IDA that the key will
    # be 29 bytes long, and the last byte is a newline.

    # Constrain the first 28 bytes to be non-null and non-newline:
    for _ in xrange(28):
        k = st.posix.files[0].read_from(1)
        st.se.add(k != 0)
        st.se.add(k != 10)

    # Constrain the last byte to be a newline
    k = st.posix.files[0].read_from(1)
    st.se.add(k == 10)

    # Reset the symbolic stdin's properties and set its length.
    st.posix.files[0].seek(0)
    st.posix.files[0].length = 29

    # Construct a SimulationManager to perform symbolic execution.
    # Step until there is nothing left to be stepped.
    sm = p.factory.simgr(st)
    sm.run()

    # Get the stdout of every path that reached an exit syscall. The flag should be in one of these!
    out = ''
    for pp in sm.deadended:
        out = pp.posix.dumps(1)
        if 'flag{' in out:
            return filter(lambda s: 'flag{' in s, out.split())[0]

    # Runs in about 15 minutes!

def test():
    assert main() == 'flag{dr4g0n_or_p4tric1an_it5_LLVM}'

if __name__ == "__main__":
    before = time.time()
    print main()
    after = time.time()
    print "Time elapsed: {}".format(after - before)
```

从40行到51行，表示程序从标准输入读取数据，最后加上一个回车换行

#### 程序直接参数中读取参数

```python
#!/usr/bin/env python


'''
ais3_crackme has been developed by Tyler Nighswander (tylerni7) for ais3.
It is an easy crackme challenge. It checks the command line argument.
'''

import angr
import claripy


def main():
    project = angr.Project("./ais3_crackme")

    #create an initial state with a symbolic bit vector as argv1
    argv1 = claripy.BVS("argv1",100*8) #since we do not the length now, we just put 100 bytes
    initial_state = project.factory.entry_state(args=["./crackme1",argv1])

    #create a path group using the created initial state
    sm = project.factory.simgr(initial_state)

    #symbolically execute the program until we reach the wanted value of the instruction pointer
    sm.explore(find=0x400602) #at this instruction the binary will print the "correct" message

    found = sm.found[0]
    #ask to the symbolic solver to get the value of argv1 in the reached state as a string
    solution = found.se.eval(argv1, cast_to=str)

    print repr(solution)
    solution = solution[:solution.find("\x00")]
    print solution
    return solution

def test():
    res = main()
    assert res == "ais3{I_tak3_g00d_n0t3s}"


if __name__ == '__main__':
    print(repr(main()))

```

导入clarify，然后引入参数argv1 = claripy.BVS("argv1",100*8)，再传到程序中。

#### Angr执行与angr状态
在 Angr 寻找路径时，程序的当前状态有多种表示。

1. step()表示向下执行一个block（42bytes），step()函数产生active状态，表示该分支在执行中；
2. run()表示运行到结束，run()函数产生deadended状态，表示分支结束；
3. explore()可以对地址进行限制以减少符号执行遍历的路径。例如
    sm.explore(find=0x400676,avoid=[0x40073d])
    explore()产生found状态，表示探索的结果等等

#### Angr模板
```python
import angr
import sys
print "[*]start------------------------------------"
p = angr.Project(sys.argv[1])  # 建立工程初始化二进制文件
state = p.factory.entry_state() # 获取入口点处状态

'''
state.posix.files[0].read_from(1)   表示从标准输入读取一个字节
'''

for _ in xrange(int(sys.argv[2])):  # 对输入进行简单约束（不为回车）
    k = state.posix.files[0].read_from(1)
    state.se.add(k!=10)

k = state.posix.files[0].read_from(1)
state.se.add(k==10)  # 回车为结束符

state.posix.files[0].seek(0)
state.posix.files[0].length = int(sys.argv[2])+1 # 约束输入长度（大于实际长度也可）

print "[*]simgr start-------------------------------"

sm = p.factory.simgr(state)   # 初始化进程模拟器
sm.explore(find=lambda s:"correct!" in s.posix.dumps(1)) # 寻找运行过程中存在 “correct！”的路径，并丢弃其他路径
print "[*]program excuted---------------------------"

for pp in sm.found:
    out = pp.posix.dumps(1)   # 表示程序的输出
    print out
    inp = pp.posix.files[0].all_bytes()  # 取输入的变量
    print pp.solver.eval(inp,cast_to = str)  # 利用约束求解引擎求解输入

```
从命令行读取参数模板，参照第三个例子


#### 技巧
sm.run 最后我们去sm.deadended中去寻找结果。

sm.explore(find=find_addr, avoid=avoid_addr)  最后我们去sm.found去寻找结果。
> find_addr 可以是 list or tuple eg： find_addr=(0xdeadbeaa, 0xdeadbeaf)

> avoid_addr 也可以是 list or tuple eg： avoid_addr=(0xdeadbeab, 0xdeadbead)

为程序加速可以使用不同的选项如 auto_load_libs  or add_options=angr.options.unicorn等


#### 参考
* [符号执行：利用Angr进行简单CTF逆向分析](http://www.freebuf.com/articles/web/150296.html)
* [angr-doc examples](https://github.com/angr/angr-doc/tree/master/examples)
* [自动化二进制文件分析框架：angr](https://zhuanlan.zhihu.com/p/25192237)
* [編寫 angr 腳本初體驗](http://ysc21.github.io/blog/2016-01-28-angr-script.html)
