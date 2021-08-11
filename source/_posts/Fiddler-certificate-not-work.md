---
title: Fiddler_certificate_not_workl: Fiddler 证书在某些安卓设备上不可信
date: 2020-05-06 11:20:10
categories:
- [Android]
tags:
- Android, HTTPS
---



部分安卓系统会出现安装了 fiddler 证书，设置了证书信任，甚至把证书移动到系统目录时，https 网页依旧提示证书不可信；

使用 monitor 检查 log 信息发现提示：
> E/chromium(8753): [ERROR:ssl_client_socket_impl.cc(941)] handshake failed; returned -1, SSL error code 1, net_error -213

搜索报错信息，找到 [chromium project](https://chromium.googlesource.com/chromium/src/+/lkgr/net/socket/ssl_client_socket_impl.cc) 的源码，发现似乎是 MapLastOpenSSLError 函数返回的 -213 错误，错误代码的宏格式为 ```ERR_SSL_CLIENT_AUTH_NO_COMMON_ALGORITHMS```；

搜索 "ssl error code list" 找到 ```net_error_list.h```，发现 -213 错误的详细宏定义为：
```c
// The certificate's validity period is too long.
NET_ERROR(CERT_VALIDITY_TOO_LONG, -213)
```

继续搜索 "fiddler The certificate's validity period is too long." 在 Fiddler 论坛找到[该帖子](https://www.telerik.com/forums/shorter-validity-periods-for-certificates)，看起来有人碰到过类似问题且已有解决方案：
> 在 Fiddler [插件页面](https://www.telerik.com/fiddler/add-ons) 找到并下载
> [CertMaker for iOS and Android](https://telerik-fiddler.s3.amazonaws.com/fiddler/addons/fiddlercertmaker.exe)
> 双击下载好的 exe，重启 Fiddler，在 Fiddler https 界面重置证书并重新生成；
> 再按照其他帖子的介绍将证书导入到系统(未测试直接安装为用户证书)，现在就能正常抓 https 网页不提示错误。