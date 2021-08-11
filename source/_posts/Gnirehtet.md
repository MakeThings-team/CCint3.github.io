---
title: Gnirehtet：让Android可以通过USB方式上网
date: 2020-03-07 05:37:35

categories:
- [Android, Tools]

tags:
- Android
- Gnirehtet
---


## 项目简介

[Gnirehtet](https://github.com/Genymobile/gnirehtet)是一个非常优秀的项目。该项目为Android设备提供了通过[adb](https://developer.android.com/studio/command-line/adb.html)方式的反向代理。它允许Android设备通过`USB`使用所接入计算机的`Internet`网络，并且计算机和Android设备都不需要任何`root`权限。它的服务器可以运行在`GNU/Linux`、`Windows`和`Mac OS`上，客户端需要运行在[Android Lollipop API 21](https://developer.android.com/about/versions/lollipopAndroid) 及以上。

`Gnirehtet`的当前版本(`v2.4`)支持通过[IPv4](https://en.wikipedia.org/wiki/IPv4)传输[TCP](https://en.wikipedia.org/wiki/Transmission_Control_Protocol)和[UDP](https://fr.wikipedia.org/wiki/User_Datagram_Protocol)协议的数据，但不支持[IPv6](https://en.wikipedia.org/wiki/IPv6l)。



## 它是如何工作的

客户端(Client)：android设备视为客户端。注册[VPN](https://developer.android.com/reference/android/net/VpnService.html)服务，以拦截整个设备的网络流量。

服务器(Relay Server)：计算机(`Windows`、`GNU/Linux`或`Mac OS`)视为服务器。也称作`中继服务器`。



客户端仅建立与服务器之间的`TCP`连接；并通过该`TCP`连接以`字节数组`的形式交换原生`IPv4数据包`；

客户端和服务器之间的`TCP`连接在开始反向端口重定向后由`adb`建立，反向端口重定向命令如下：

```shell
adb reverse localabstract:gnirehtet tcp:31416
```



这意味着服务器必须监听`31416`端口，并且客户端的所有的[sockets](https://en.wikipedia.org/wiki/Berkeley_sockets)连接都将由`adb`重定向到服务器的`31416`端口上。所以务必确保服务器的`31416`端口未被其他程序占用，务必确保服务器和客户端之间的`USB`连接是正常且稳定的。

服务器从连接的客户端上接收`IPv4数据包`并且根据数据包与对应的目标`IP`建立`sockets`连接，然后开始双向中继传输数据。

这就需要服务器在[OSI model](https://en.wikipedia.org/wiki/OSI_model)上以`Level 3(客户端一边)`和`Level 5(外网一边)`之间传输数据包；

[获取更多详情请点我](https://github.com/Genymobile/gnirehtet/blob/master/DEVELOP.md#overview)



## 为什么选择它

当Android设备的`WIFI`不够稳定时，或想获得更高的下载速度，或其他一些原因；



## 要求

- [Android Lollipop API 21](https://developer.android.com/about/versions/lollipopAndroid) 及以上；

- Android设备需要启动[adb debugging](https://developer.android.com/studio/command-line/adb.html#Enabling) ；

- Java 8的运行时环境，在`Debian-based`发行版上，需要`openjdk-8-jre`；

- `adb 1.0.36`及以上，因为需要`adb reverse`支持；

- 服务器的`31416`端口未被占用且网络正常；



## 下载

根据需要下载对应的版本，建议下载最新版本：[Last Release](https://github.com/Genymobile/gnirehtet/releases/latest)



### Rust 版本

- **Linux：**  `gnirehtet-rust-linux64-XXX.zip`
- **Windows：** `gnirehtet-rust-win64-XXX.zip`
- **Mac OS：** `gnirehtet-rust-macos64-XXX.zip`



`Linux`和`Mac OS` zip文件解压后包含以下文件：

- `gnirehtet.apk`：安装在客户端上。
- `gnirehtet`：安装在服务器上。



`Windows` zip文件解压后包含以下文件：

- `gnirehtet.apk：`安装在客户端上。
- `gnirehtet.exe：`安装在Windows服务器上。
- `gnirehtet-run.cmd：`快速启动`gnirehtet`的批处理文件。



### Java 版本

- **全平台：** `gnirehtet-java-XXX.zip`



解压后包含以下文件：

- `gnirehtet.apk：`安装在客户端上。
- `gnirehtet.jar:`部署在服务器上
- `gnirehtet：`部署在服务器上
- `gnirehtet.cmd：`部署在Windows服务器上
- `gnirehtet-run.cmd：`快速启动`gnirehtet`的批处理文件。



## 运行

在服务器上启动服务，该服务不提供用户界面，以控制台终端的形式呈现：

```shell
./gnirehtet relay
```

在`Ubuntu`上使`Gnirehtet`不占用命令行终端在后台运行：

```
sudo nohup ./gnirehtet relay &
```



在客户端上安装**APK**：

```shell
adb install -r gnirehtet.apk
```



设置反向端口重定向并启动**APP**，该**APP**不提供用户界面，以`Android Service`的方式运行在系统后台：

```shell
adb reverse localabstract:gnirehtet tcp:31416
adb shell am start -a com.genymobile.gnirehtet.START -n com.genymobile.gnirehtet/.GnirehtetActivity
```



停止客户端：

```shell
adb shell am start -a com.genymobile.gnirehtet.STOP -n com.genymobile.gnirehtet/.GnirehtetActivity
```



停止服务器：

```
在gnirehtet的命令行终端上按下Ctrl + C组合键
```

