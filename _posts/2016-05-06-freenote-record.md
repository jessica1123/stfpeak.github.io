---
layout:     post
title:      "Freenote writeup -- Understand heap and double free"
subtitle:   "The Next Generation Application Model For The Web - Progressive Web App"
date:       2016-05-06 20:00:00
author:     "Dafeng"
header-img: "img/post-bg-nextgen-web-pwa.jpg"
header-mask: 0.3
catalog:    true
tags:
    - CTF
    - Heap
    - Exploit
---



## 下一代 Web 应用？

近年来，Web 应用在整个软件与互联网行业承载的责任越来越重，软件复杂度和维护成本越来越高，Web 技术，尤其是 Web 客户端技术，迎来了爆发式的发展。

包括但不限于基于 Node.js 的前端工程化方案；诸如 Webpack、Rollup 这样的打包工具；Babel、PostCSS 这样的转译工具；TypeScript、Elm 这样转译至 JavaScript 的编程语言；React、Angular、Vue 这样面向现代 web 应用需求的前端框架及其生态，也涌现出了像[同构 JavaScript][1]与[通用 JavaScript 应用][2]这样将服务器端渲染（Server-side Rendering）与单页面应用模型（Single-page App）结合的 web 应用架构方式，可以说是百花齐放。

但是，Web 应用在移动时代并没有达到其在桌面设备上流行的程度。究其原因，尽管上述的各种方案已经充分利用了现有的 JavaScript 计算能力、CSS 布局能力、HTTP 缓存与浏览器 API 对当代基于 [Ajax][3] 与[响应式设计][4]的 web 应用模型的性能与体验带来了工程角度的巨大突破，我们仍然无法在不借助原生程序辅助浏览器的前提下突破 web 平台本身对 web 应用固有的桎梏：**客户端软件（即网页）需要下载所带来的网络延迟；与 Web 应用依赖浏览器作为入口所带来的体验问题。**

![](/img/in-post/post-nextgen-web-pwa/PWAR-007.jpeg)
*Web 与原生应用在移动平台上的使用时长对比 [图片来源: Google][i2]*

在桌面设备上，由于网络条件稳定，屏幕尺寸充分，交互方式趋向于多任务，这两点造成的负面影响对比 web 应用免于安装、随叫随到、无需更新等优点，瑕不掩瑜。但是在移动时代，脆弱的网络连接与全新的人机交互方式使得这两个问题被无限放大，严重制约了 web 应用在移动平台的发展。在用户眼里，原生应用不会出现「白屏」，清一色都摆在主屏幕上；而 web 应用则是浏览器这个应用中的应用，使用起来并不方便，而且加载也比原生应用要慢。

Progressive Web Apps（以下简称 PWA）以及构成 PWA 的一系列关键技术的出现，终于让我们看到了彻底解决这两个平台级别问题的曙光：能够显著提高应用加载速度、甚至让 web 应用可以在离线环境使用的 Service Worker 与 Cache Storage；用于描述 web 应用元数据（metadata）、让 web 应用能够像原生应用一样被添加到主屏、全屏执行的 Web App Manifest；以及进一步提高 web 应用与操作系统集成能力，让 web 应用能在未被激活时发起推送通知的 Push API 与 Notification API 等等。

将这些技术组合在一起会是怎样的效果呢？「印度阿里巴巴」 —— [Flipkart][17] 在 2015 年一度关闭了自己的移动端网站，却在年底发布了现在最为人津津乐道的 PWA 案例 *FlipKart Lite*，成为世界上第一个支撑大规模业务的 PWA。发布的一周后它就亮相于 [Chrome Dev Summit 2015][15] 上，笔者当时就被惊艳到了。为了方便各媒介上的读者观看，笔者做了几幅图方便给大家介绍：

![](/img/in-post/post-nextgen-web-pwa/flipkart-1.jpeg)
*图片来源: Hux & [Medium.com][i3]*

当浏览器发现用户[需要][16] Flipkart Lite 时，它就会提示用户「嘿，你可以把它添加至主屏哦」（用户也可以手动添加）。这样，Flipkart Lite 就会像原生应用一样在主屏上留下一个自定义的 icon 作为入口；与一般的书签不同，当用户点击 icon 时，Flipkat Lite 将直接全屏打开，不再受困于浏览器的 UI 中，而且有自己的启动屏效果。


![](/img/in-post/post-nextgen-web-pwa/flipkart-2.jpeg)
*图片来源: Hux & [Medium.com][i3]*

更强大的是，在无法访问网络时，Flipkart Lite 可以像原生应用一样照常执行，还会很骚气的变成黑白色；不但如此，曾经访问过的商品都会被缓存下来得以在离线时继续访问。在商品降价、促销等时刻，Flipkart Lite 会像原生应用一样发起推送通知，吸引用户回到应用。

**无需担心网络延迟；有着独立入口与独立的保活机制。**之前两个问题的一并解决，宣告着 web 应用在移动设备上的浴火重生：满足 PWA 模型的 web 应用，将逐渐成为移动操作系统的一等公民，并将向原生应用发起挑战与「复仇」。

更令笔者兴奋的是，就在今年 11 月的 [Chrome Dev Summit 2016][18] 上，Chrome 的工程 VP Darin Fisher 介绍了 Chrome 团队正在做的一些实验：把「添加至主屏」重命名为「安装」，被安装的 PWA 不再仅以 widget 的形式显示在桌面上，而是真正做到与所有原生应用平级，一样被收纳进应用抽屉（App Drawer）里，一样出现在系统设置中 🎉🎉🎉。

![](/img/in-post/post-nextgen-web-pwa/flipkart-3.jpeg)
*图片来源: Hux & [@adityapunjani][i4]*

图中从左到右分别为：类似原生应用的安装界面；被收纳在应用抽屉里的 Flipkart Lite 与 Hux Blog；设置界面中并列出现的 Flipkart 原生应用与 Flipkart Lite PWA （可以看到 PWA 巨大的体积优势）

**笔者相信，PWA 模型将继约 20 年前横空出世的 Ajax 与约 10 年前风靡移动互联网的响应式设计之后，掀起 web 应用模型的第三次根本性革命，将 web 应用带进一个全新的时代。**

## PWA 关键技术的前世今生

### [Web App Manifest][spec1]

Web App Manifest，即通过一个清单文件向浏览器暴露 web 应用的元数据，包括名字、icon 的 URL 等，以备浏览器使用，比如在添加至主屏或推送通知时暴露给操作系统，从而增强 web 应用与操作系统的集成能力。

让 web 应用在移动设备上的体验更接近原生应用的尝试其实早在 2008 年的 [iOS 1.1.3 与 iOS 2.1.0 ][q37]时就开始了，它们分别为 web 应用增加了对自定义 icon 和全屏打开的支持。

![](/img/in-post/post-nextgen-web-pwa/ios2-a2hs.gif)
*图片来源: [appleinsider.com][i1]*

但是很快，随着越来越多的私有平台通过 `<meta>`/`<link>` 标签来为 web 应用添加「私货」，`<head>` 很快就被塞满了：

```html
<!-- Add to homescreen for Safari on iOS -->
<meta name="apple-mobile-web-app-capable" content="yes">
<meta name="apple-mobile-web-app-status-bar-style" content="black">
<meta name="apple-mobile-web-app-title" content="Lighten">

<!-- Add to homescreen for Chrome on Android -->
<meta name="mobile-web-app-capable" content="yes">
<mate name="theme-color" content="#000000">

<!-- Icons for iOS and Android Chrome M31~M38 -->
<link rel="apple-touch-icon-precomposed" sizes="144x144" href="images/touch/apple-touch-icon-144x144-precomposed.png">
<link rel="apple-touch-icon-precomposed" sizes="114x114" href="images/touch/apple-touch-icon-114x114-precomposed.png">
<link rel="apple-touch-icon-precomposed" sizes="72x72" href="images/touch/apple-touch-icon-72x72-precomposed.png">
<link rel="apple-touch-icon-precomposed" href="images/touch/apple-touch-icon-57x57-precomposed.png">

<!-- Icon for Android Chrome, recommended -->
<link rel="shortcut icon" sizes="196x196" href="images/touch/touch-icon-196x196.png">

<!-- Tile icon for Win8 (144x144 + tile color) -->
<meta name="msapplication-TileImage" content="images/touch/ms-touch-icon-144x144-precomposed.png">
<meta name="msapplication-TileColor" content="#3372DF">

<!-- Generic Icon -->
<link rel="shortcut icon" href="images/touch/touch-icon-57x57.png">
```

显然，这种做法并不优雅：分散又重复的元数据定义多余且难以维持同步，与 html 耦合在一起也加重了浏览器检查元数据未来变动的成本。与此同时，社区里开始出现使用 manifest 文件以中心化地描述元数据的方案，比如 [Chrome Extension、 Chrome Hosted Web Apps (2010)][12] 与 [Firefox OS App Manifest (2011)][13] 使用 JSON；[Cordova][19] 与 [Windows Pinned Site][20] 使用 XML；

2013 年，W3C WebApps 工作组开始对基于 JSON 的 Manifest 进行标准化，于同年年底发布[第一份公开 Working Draft][14]，并逐渐演化成为今天的 W3C Web App Manifest：

```json
{
  "short_name": "Manifest Sample",
  "name": "Web Application Manifest Sample",
  "icons": [{
      "src": "launcher-icon-2x.png",
      "sizes": "96x96",
      "type": "image/png"
   }],
  "scope": "/sample/",
  "start_url": "/sample/index.html",
  "display": "standalone",
  "orientation": "landscape"
  "theme_color": "#000",
  "background_color": "#fff",
}
```
```html
<!-- document -->
<link rel="manifest" href="/manifest.json">
```

诸如 `name`、`icons`、`display` 都是我们比较熟悉的，而大部分新增的成员则为 web 应用带来了一系列以前 web 应用想做却做不到（或在之前只能靠 hack）的新特性：

- `scope`：定义了 web 应用的浏览作用域，比如作用域外的 URL 就会打开浏览器而不会在当前 PWA 里继续浏览。
- `start_url`：定义了一个 PWA 的入口页面。比如说你添加 [Hux Blog][21] 的任何一个文章到主屏，从主屏打开时都会访问 [Hux Blog][21] 的主页。
- `orientation`：终于，我们可以锁定屏幕旋转了（喜极而泣…）
- `theme_color`/`background_color`：主题色与背景色，用于配置一些可定制的操作系统 UI 以提高用户体验，比如 Android 的状态栏、任务栏等。

这个清单的成员还有很多，比如用于声明「对应原生应用」的 `related_applications` 等等，本文就不一一列举了。作为 PWA 的「户口本」，承载着 web 应用与操作系统集成能力的重任，Web App Manifest 还将在日后不断扩展，以满足 web 应用高速演化的需要。



### [Service Worker][spec2]

我们原有的整个 Web 应用模型，都是构建在「用户能上网」的前提之下的，所以一离线就只能玩小恐龙了。其实，对于「让 web 应用离线执行」这件事，Service Worker 至少是 web 社区的第三次尝试了。

故事可以追溯到 2007 年的 [Google Gears][48]：为了让自家的 Gmail、Youtube、Google Reader 等 web 应用可以在本地存储数据与离线执行，Google 开发了一个浏览器拓展来增强 web 应用。Google Gears 支持 IE 6、Safari 3、Firefox 1.5 等浏览器；要知道，那一年 Chrome 都还没出生呢。

在 Gears API 中，我们通过向 LocalServer 模块提交一个缓存文件清单来实现离线支持：

```javascript
// Somewhere in your javascript
var localServer = google.gears.factory.create("bata.localserver");
var store = localServer.createManagedStore(STORE_NAME);
store.manifestUrl = "manifest.json"
```
```json
// manifest.json - 假设 JSON 有注释
{
　　"betaManifestVersion":　1,
　　"version": 　"1.0",
　　"entries":　[　
　　　　{　"url": 　"index.html"},
　　　　{　"url": 　"main.js"}
　　]
}
```

是不是感到很熟悉？好像 [HTML5 规范][spec11]中的 Application Cache 也是类似的东西？

```html
<html manifest="cache.appcache">
```
```
CACHE MANIFEST

CACHE:
index.html
main.js
```

是的，Gears 的 LocalServer 就是后来大家所熟知的 App Cache 的前身，大约从 [2008][spec10] 年开始 W3C 就开始尝试将 Gears 进行标准化了；除了 LocalServer，Gears 中用于提供并行计算能力的 WorkerPool 模块与用于提供本地数据库与 SQL 支持的 Database 模块也分别是日后 Web Worker 与 Web SQL Database（后被废弃）的前身。

HTML5 App Cache 作为第二波「让 web 应用离线执行」的尝试，确实也服务了比如 Google Doc、尤雨溪早年作品 HTML5 Clear、以及一直用 web 应用作为自己 iOS 应用的 FT.com（Financial Times）等不少 web 应用。那么，还有 Service Worker 什么事呢？  

是啊，如果 App Cache 没有被设计得[烂到完全不可编程、无法清理缓存、几乎没有路由机制、出了 Bug 一点救都没有][s12]，可能就真没 Service Worker 什么事了。[App Cache 已经在前不久定稿的 HTML5.1 中被拿掉了，W3C 为了挽救 web 世界真是不惜把自己的脸都打肿了……][s13]

时至今日，我们终于迎来了 Service Worker 的曙光。简单来说，Service Worker 是一个可编程的 Web Worker，它就像一个位于浏览器与网络之间的客户端代理，可以拦截、处理、响应流经的 HTTP 请求；配合随之引入 Cache Storage API，你可以自由管理 HTTP 请求文件粒度的缓存，这使得 Service Worker 可以从缓存中向 web 应用提供资源，即使是在离线的环境下。


![](/img/in-post/post-nextgen-web-pwa/sw-sw.png)
*Service Worker 就像一个运行在客户端的代理*

比如说，我们可以给网页 `foo.html` 注册这么一个 Service Worker，它将劫持由 `foo.html` 发起的一切 HTTP 请求，并统统返回未设置 `Content-Type` 的 `Hello World!`：

```javascript
// sw.js
self.onfetch = (e) => {
  e.respondWith(new Response('Hello World!'))
}
```

Service Worker 第一次发布于 2014 年的 Google IO 上，目前已处于 W3C 工作草案的状态。其设计吸取了 Application Cache 的失败经验，作为 web 应用的开发者的你有着完全的控制能力；同时，它还借鉴了 Chrome 多年来在 Chrome Extension 上的设计经验（Chrome Background Pages 与 Chrome Event Pages），采用了基于「事件驱动」的唤醒机制，以大幅节省后台计算的能耗。比如上面的 `fetch` 其实就是会唤醒 Service Worker 的事件之一。

![](/img/in-post/post-nextgen-web-pwa/sw-lifecycle.png)
*Service Worker 的生命周期*

除了类似 `fetch` 这样的功能事件外，Service Worker 还提供了一组生命周期事件，包括安装、激活等等。比如，在 Service Worker 的「安装」事件中，我们可以把 web 应用所需要的资源统统预先下载并缓存到 Cache Storage 中去：

```javascript
// sw.js
self.oninstall = (e) => {
  e.waitUntil(
    caches.open('installation')
      .then(cache =>  cache.addAll([
        './',
        './styles.css',
        './script.js'
      ]))
  )
});
```

这样，当用户离线，网络无法访问时，我们就可以从缓存中启动我们的 web 应用：

```javascript
//sw.js
self.onfetch = (e) => {
  const fetched = fetch(e.request)
  const cached = caches.match(e.request)

  e.respondWith(
    fetched.catch(_ => cached)
  )
}
```

