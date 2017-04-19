---
layout:     post
title:      "Bctf 2017 pingpong.apk crack"
subtitle:   "just call jni function to crack"
date:       2017-04-18 19:30:00 -0800
author:     "Dafeng"
header-img: "img/post-bg-universe.jpg"
header-mask: 0.3
catalog: true
tags:
    - CTF
    - Android
    - NDK
---

## BCTF Android Crack

### 简介
安装apk，界面如图：
![activity](/img/pingpong/activity.png)

> 点击PONG，显示PING;再点击PONG, 过一会儿会显示PONG。一看就是常规题目，跟之前做过的点击按钮几百万次如出一辙。

### 分析
不多说，上JEB，分析Java层逻辑：
![java逻辑](/img/pingpong/java.png)

> 主要的逻辑是说： 奇数次点击PING, 执行一个jni function，判断下num,当num>=7时，num置零；偶数次点击PONG,同理。

### 分析SO文件
SO 文件分别调用了两个函数：
* Java_com_geekerchina_pingpongmachine_MainActivity_ping(int a1, int a2, int a3, signed int a4);
* Java_com_geekerchina_pingpongmachine_MainActivity_pong(int a1, int a2, int a3, int a4);

反汇编如下图所示：
![ida](/img/pingpong/ida.png)

如图所示so文件利用ollvm混淆加固，我们需要做的是根据反汇编代码来理清算法逻辑，然后写程序计算,有两种思路：
1. 根据混淆的代码来去混淆，技巧：关注相等的分支
2. 不关心调用函数的逻辑，利用ndk编程直接调用so函数

我们选取第二种方法，之前操作apk，点击按钮好感觉到卡顿，我还以为是我手机性能差呢。然后用了下华为mate9试了一下，也卡（这他么天理不容啊）， 从so反汇编的代码可以看出每次在函数调用的时候都sleep(1), 难道这就是传说中的：去掉sleep提升软件效率的方法，哈哈。既然这样那我们就来提升软件效率。

做法： 找到sleep函数，然后直接找到对应的二进制偏移，利用010editor，把.text段对应的sleep代码nop掉(替换成0x90)。

### NDK编程
jin
- Android.mk
- ping.h
- ping.c

#### Android.mk
```
LOCAL_PATH:= $(call my-dir)
include $(CLEAR_VARS)
LOCAL_CFLAGS += -pie -fPIE
LOCAL_LDFLAGS += -pie -fPIE
LOCAL_SRC_FILES:= ping.c
LOCAL_C_INCLUDES:= ping.h
LOCAL_MODULE:= ping
LOCAL_LDLIBS := libpp.so
include $(BUILD_EXECUTABLE)
```
#### ping.h
```c
#include <stdio.h>

int Java_com_geekerchina_pingpongmachine_MainActivity_ping(int a1, int a2, int a3, signed int a4);
int Java_com_geekerchina_pingpongmachine_MainActivity_pong(int a1, int a2, int a3, int a4);

```

#### ping.c
```c
#include <ping.h>

int main()
{
    int ttt = 500000;
    int num = 0;
    int p = 0;
    int index;

    for(index = 0; index < ttt; index++)
    {
        p = Java_com_geekerchina_pingpongmachine_MainActivity_ping(0, 0, p, num);
        num += 1;
        if(num >= 7)
        {
          num = 0;
        }

        p = Java_com_geekerchina_pingpongmachine_MainActivity_pong(0, 0, p, num);
        num += 1;
        if(num >= 7)
        {
          num = 0;
        }

    }
    printf("%d\n", p);
    return 0;
}

```

在当前目录下执行 ndk-build, 可以得到libs & obj 文件夹
1. 拷贝obj中的生成的 ping 可执行文件，**adb push ./ping /data/local/tmp**
2. 拷贝修改过的libpp.so文件到/data/local/tmp， **adb push ./libpp.so /data/local/tmp**
3. 添加/data/local/tmp/到LD_LIBRARY_PATH环境变量中，**export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/data/local/tmp/**
4. 执行可执行文件ping，**./ping**

然后得到结果：

![result](/img/pingpong/result.png)

flag: **BCTF{MagicNum4500009}**

**PS: 这道题第三个做出来，也是不错，MARK!!!**
