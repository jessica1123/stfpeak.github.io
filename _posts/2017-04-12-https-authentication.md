---
layout:     post
title:      "How the https authentication act"
subtitle:   "https单向认证双向认证"
date:       2017-04-12 20:30:00 -0800
author:     "Dafeng"
header-img: "img/post-bg-universe.jpg"
header-mask: 0.3
catalog: true
tags:
    - Https
    - SSL
    - PKI
---

## Http

HyperText Transfer Protocol，超文本传输协议，是互联网上使用最广泛的一种协议，所有WWW文件必须遵循的标准。HTTP协议传输的数据都是未加密的，也就是明文的，因此使用HTTP协议传输隐私信息非常不安全。

使用TCP端口为：80


## Https

Hyper Text Transfer Protocol over Secure Socket Layer，安全的超文本传输协议，网景公式设计了SSL(Secure Sockets Layer)协议用于对Http协议传输的数据进行加密，保证会话过程中的安全性。

使用TCP端口默认为443


## SSL协议加密方式

SSL协议即用到了对称加密也用到了非对称加密(公钥加密)，在建立传输链路时，SSL首先对对称加密的密钥使用公钥进行非对称加密，链路建立好之后，SSL对传输内容使用对称加密。
* **client产生随机数random-client，server产生随机数random-server。**
* **客户端使用非对称加密算法（公钥）对对称加密的密钥进行加密；**
* **服务端利用私钥解密得到对称加密算法的密钥secret，然后（random-client, random-server, secret）三元素来加密信息通道。**


    对称加密
    速度高，可加密内容较大，用来加密会话过程中的消息

    公钥加密
    加密速度较慢，但能提供更好的身份认证技术，用来加密对称加密的密钥

## 单向认证

Https在建立Socket连接之前，需要进行握手，具体过程如下：

！[https单向认证](/img/https_authentication/single.jpeg)

1. 客户端向服务端发送SSL协议版本号、加密算法种类、随机数等信息。
2. 服务端给客户端返回SSL协议版本号、加密算法种类、随机数等信息，同时也返回服务器端的证书，即公钥证书。
3. 客户端使用服务端返回的信息验证服务器的合法性，包括：
    * 证书是否过期
    * 发型服务器证书的CA是否可靠
    * 返回的公钥是否能正确解开返回证书中的数字签名
    * 服务器证书上的域名是否和服务器的实际域名相匹配
> 验证通过后，将继续进行通信，否则，终止通信

4.  客户端向服务端发送自己所能支持的对称加密方案，供服务器端进行选择。
5. 服务器端在客户端提供的加密方案中选择加密程度最高的加密方式。
6. 服务器将选择好的加密方案通过明文方式返回给客户端。
7. 客户端接收到服务端返回的加密方式后，使用该加密方式生成产生随机码，用作通信过程中对称加密的密钥，使用服务端返回的公钥进行加密，将加密后的随机码发送至服务器。
8. 服务器收到客户端返回的加密信息后，使用自己的私钥进行解密，获取对称加密密钥。
9. 在接下来的会话中，服务器和客户端将会使用该密码进行对称加密，保证通信过程中信息的安全。


## 双向认证

双向认证和单向认证原理基本差不多，只是除了客户端需要认证服务端以外，增加了服务端对客户端的认证，具体过程如下：

！[https双向认证](/img/https_authentication/double.jpeg)

1. 客户端向服务端发送SSL协议版本号、加密算法种类、随机数等信息。
2. 服务端给客户端返回SSL协议版本号、加密算法种类、随机数等信息，同时也返回服务器端的证书，即公钥证书。
3. 客户端使用服务端返回的信息验证服务器的合法性，包括：
    * 证书是否过期
    * 发型服务器证书的CA是否可靠
    * 返回的公钥是否能正确解开返回证书中的数字签名
    * 服务器证书上的域名是否和服务器的实际域名相匹配
> 验证通过后，将继续进行通信，否则，终止通信

4. 服务端要求客户端发送客户端的证书，客户端会将自己的证书发送至服务端。
5. 验证客户端的证书，通过验证后，会获得客户端的公钥。
6. 客户端向服务端发送自己所能支持的对称加密方案，供服务器端进行选择。
7. 服务器端在客户端提供的加密方案中选择加密程度最高的加密方式。
8. 将加密方案通过使用之前获取到的公钥进行加密，返回给客户端。
9. 客户端收到服务端返回的加密方案密文后，使用自己的私钥进行解密，获取具体加密方式，而后，产生该加密方式的随机码，用作加密过程中的密钥，使用之前从服务端证书中获取到的公钥进行加密后，发送给服务端。
10. 服务端收到客户端发送的消息后，使用自己的私钥进行解密，获取对称加密的密钥，在接下来的会话中，服务器和客户端将会使用该密码进行对称加密，保证通信过程中信息的安全。



# PKI

## 生成密钥、证书

### 1. 为服务器端和客户端准备公钥、私钥
    生成服务器端私钥
    $ openssl genrsa -out server.key 1024

    生成服务器端公钥
    $ openssl rsa -in server.key -pubout -out server.pem

    生成客户端私钥
    $ openssl genrsa -out client.key 1024

    生成客户端公钥
    $ openssl rsa -in client.key -pubout -out client.pem

### 2. 生成 CA 证书
    生成 CA 私钥
    $ openssl genrsa -out ca.key 1024

    X.509 Certificate Signing Request (CSR) Management.
    $ openssl req -new -key ca.key -out ca.csr

    X.509 Certificate Data Management.
    $ openssl x509 -req -in ca.csr -signkey ca.key -out ca.crt


### 3.生成服务器端证书和客户端证书
    服务器端需要向 CA 机构申请签名证书，在申请签名证书之前依然是创建自己的 CSR 文件
    $ openssl req -new -key server.key -out server.csr

    向自己的CA机构申请证书，签名过程需要 CA 的证书和私钥参与，最终颁发一个带有CA签名的证书
    $ openssl x509 -req -CA ca.crt -CAkey ca.key -CAcreateserial -in server.csr -out server.crt

    client端
    $ openssl req -new -key client.key -out client.csr

    client端到CA签名
    $ openssl x509 -req -CA ca.crt -CAkey ca.key -CAcreateserial -in client.csr -out client.crt

此时，我们的 keys 文件夹下已经有如下内容了：
└── keys
├── ca.crt
├── ca.csr
├── ca.key
├── ca.pem
├── ca.srl
├── client.crt
├── client.csr
├── client.key
├── client.pem
├── server.crt
├── server.csr
├── server.key
└── server.pem
