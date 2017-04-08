---
layout:     post
title:      "Use Xposed hook to control app or system"
subtitle:   "利用Xposed hook技术来控制改变app 程序流 "
date:       2017-04-09 00:10:00 -0800
author:     "Dafeng"
header-img: "img/Xposed_app.jpg"
tags:
    - Android
    - Xposed
    - Hook
---

# Xposed 简介
>
Xposed，大名鼎鼎得Xposed，是Android平台上最负盛名的一个框架。在这个框架下，我们可以加载很多插件App，这些插件App可以直接或间接操纵系统层面的东西，比如操纵一些本来只对系统厂商才open的功能（实际上是因为Android系统很多API是不公开的，而第三方APP又没有权限）。有了Xposed后，理论上我们的插件APP可以hook到系统任意一个Java进程（zygote，systemserver，systemui好不啦！）
功能太强大，自然也有缺点。Xposed不仅仅是一个插件加载功能，而是它从根上Hook了Android Java虚拟机，所以它需要root，所以每次为它启用新插件APP都需要重新启动。而如果仅是一个插件加载模块的话，当前有很多开源的插件加载模块，就没这么复杂了。
Anyway，Xposed强大，我们可以学习其中的精髓，并且可以把它的思想和技术用到自己的插件加载模块里。这就是我们要学习Xposed的意义。

# Xposed 组建
## Xposed包含如下几个工程：

1. **XposedInstaller**，这是Xposed的插件管理和功能控制APP，也就是说Xposed整体管控功能就是由这个APP来完成的，它包括启用Xposed插件功能，下载和启用指定插件APP，还可以禁用Xposed插件功能等。注意，这个app要正常无误得运行必须能拿到root权限。
2. **Xposed**，这个项目属于Xposed框架，其实它就是单独搞了一套xposed版的zygote。这个zygote会替换系统原生的zygote。所以，它需要由XposedInstaller在root之后放到/system/bin下。
3. **XposedBridge**，这个项目也是Xposed框架，它属于Xposed框架的Java部分，编译出来是一个XposedBridge.jar包。
4. **XposedTools**，Xposed和XposedBridge编译依赖于Android源码，而且还有一些定制化的东西。所以XposedTools就是用来帮助我们编译Xposed和XposedBridge的。


# Xposed 安装
> 网上有很多中安装方法，在这里我们直接采取最简单的方法安装，直接打开应用市场（如：豌豆荚），搜索xPosed就会看见Xposed框架。
