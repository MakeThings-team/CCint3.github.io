---
title: frida install：安装frida
date: 2020-11-01 02:51:57
categories:
- [Frida, android]
tags:
---



通过`python -m pip install frida-tools` 和 `python -m pip install frida` 安装frida时经常出现假死状态，应该和当前网络环境和frida的编译比较复杂有关。

我们可以手动下载frida的pypi包，并在本地使用`easy_install`安装它。建议使用`python3`和`frida 12`的版本，最新的`frida 14`bug比较多。可以等作者发布几个新版本或修复bug后再使用。



### 安装frida

前往[frida pypi页面](https://pypi.org/project/frida/12.11.18/#history)下载需要的版本，这里选择[frida 12.11.18](https://pypi.org/project/frida/12.11.18/#files)

下载对应版本和平台的egg包后，使用以下命令进行安装：

```bash
$ python -m easy_install frida-12.11.18-py3.8-win-amd64.egg
```

铁头娃可以通过以下命令进行安装：

```bash
$ python -m pip install frida
```



### 安装frida-tools

前往[frida-tools pypi页面](https://pypi.org/project/frida-tools/#history)下载需要的版本，因为frida和frida-tools的版本是有依赖关系的，`frida 12.11.18` 对应[frida-tools 8.2.0](https://pypi.org/project/frida-tools/8.2.0/#files)

下载frida-tools的zip包并解压后，通过以下命令安装：

```bash
$ cd frida-tools-8.2.0
$ python setup.py build
$ python setup.py install
```

如果已经安装好了frida，那么可以直接通过以下命令来安装frida-tools

```bash
$ python -m pip install frida-tools
```

需要注意的是，你可能需要指定frida-tools的版本

```bash
$ python -m pip install frida-tools==8.2.0
```



### 校验frida和frida-tools的安装

通过以下命令来校验：

```bash
$ python -m pip list
$ frida --version
$ frida-ps
# 执行下面的命令时必须保证连接了android或ios设备，并且运行了frida-server。
$ frida-ps -U
```





