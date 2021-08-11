---
title: iptables ipv4 packet redirect：iptables 对 ipv4 数据包的重定向
date: 2020-11-01 02:11:00
categories:
- [iptables, android]

tags:
- [iptables]
---

## iptables 对 ipv4 数据包的重定向

可以使用这个功能将android ipv4的流量转发给中间人代理。



#### 简介

更多关于iptables的内容请看：[iptables详解](http://www.zsythink.net/archives/tag/iptables/)

![Netfilter-packet-flow](https://upload.wikimedia.org/wikipedia/commons/3/37/Netfilter-packet-flow.svg)

iptables是一个命令行工具，可以用来增删改查`netfilter内核组件`维护的表、链和规则。

iptables/netfilter（以下统称为iptables）组成了Linux平台下的IPv4包过滤器，可以使用它提供的功能来实现`软件防火墙`，这也是iptables的最初用意。

它可以代替昂贵的商业防火墙解决方案，它可以做到修改数据包、包过滤、包重定向和网络地址转换（NAT）等功能。

iptables使用表、链和规则的概念来管理网络流量。表包含若干链；链包含若干规则；用户可以在表中新增自定义的链和规则来管理网络流量。

每个表，每个链的功能都是不同的。

iptables提供的内置表如下：

- **filter**

filter表中包含的内置链：INPUT 、FORWARD 和 OUTPUT

- **nat**

nat表中包含的内置链：PREROUTING 、OUTPUT 和 POSTROUTING

- **mangle**

mangle表中包含的内置链：PREROUTING  、OUTPUT  、INPUT 、FORWARD 和 POSTROUTING

- **raw**

raw表中包含的内置链：PREROUTING 和 OUTPUT

- **security**

security表中包含的内置链：INPUT 、OUTPUT 和 FORWARD



#### 流量转发

`nat.OUTPUT`链用来管理本机进程向外发送的数据包，为了做到控制本机所有流量，我们在这个表中配置规则即可。

##### 启用iptables流量转发

1. 创建`nat.REDSOCKS`链：

在nat表中创建REDSOCKS规则链

```bash
$ iptables -t nat -N REDSOCKS
$ iptables --line -t nat -nvxL REDSOCKS
```

结果如下图所示：

![create REDSOCKS chain in nat table.](https://raw.githubusercontent.com/MakeThings-team/picgo-library/main/iptables-ipv4-packet-redirect/create_nat.redsocks.png)

2. 在`nat.REDSOCKS`链中忽略本地地址和保留地址：

不要处理发往本地地址或保留地址的数据包。我们`RETURN`即可，表示`nat.REDSOCKS`链不处理它们，它们将按原本的链继续执行；

关于本地地址或保留地址的更多信息请参阅以下网址：[Reserved_IP_addresses](http://en.wikipedia.org/wiki/Reserved_IP_addresses#Reserved_IPv4_addresses) 和 [rfc5735](http://tools.ietf.org/html/rfc5735)

```bash
$ iptables -t nat -A REDSOCKS -d 10.0.0.0/8     -j RETURN
$ iptables -t nat -A REDSOCKS -d 100.64.0.0/10  -j RETURN
$ iptables -t nat -A REDSOCKS -d 127.0.0.0/8    -j RETURN
$ iptables -t nat -A REDSOCKS -d 169.254.0.0/16 -j RETURN
$ iptables -t nat -A REDSOCKS -d 172.16.0.0/12  -j RETURN
$ iptables -t nat -A REDSOCKS -d 192.168.0.0/16 -j RETURN
$ iptables -t nat -A REDSOCKS -d 198.18.0.0/15  -j RETURN
$ iptables -t nat -A REDSOCKS -d 224.0.0.0/4    -j RETURN
$ iptables -t nat -A REDSOCKS -d 240.0.0.0/4    -j RETURN
$ iptables --line -t nat -nvxL REDSOCKS
```

结果如下图所示：

![add rules to nat.REDSOCKS chain.](https://raw.githubusercontent.com/MakeThings-team/picgo-library/main/iptables-ipv4-packet-redirect/add_rule_nat.redsocks.png)

3. 将其它数据包转发到android设备的 `8989` 端口上

```bash
$ iptables -t nat -A REDSOCKS -p tcp -j REDIRECT --to-ports 8989
$ iptables --line -t nat -nvxL REDSOCKS
```

结果如下图所示，从图中可以看出我们过滤了发往本地或保留地址的数据包，对于发给其它网络设备的数据包我们全部转发至android设备的`8989`端口

![add redirect rule to nat.REDSOCKS chain.](https://raw.githubusercontent.com/MakeThings-team/picgo-library/main/iptables-ipv4-packet-redirect/add_forward_nat.redsocks.png)



4. 在`nat.OUTPUT`链中应用`nat.REDSOCKS`链

iptables支持在一个链中挂上其它链

```bash
$ iptables -t nat -A OUTPUT   -p tcp -j REDSOCKS
$ iptables --line -t nat -nvxL OUTPUT
```

结果如下图所示：

![apply nat.REDSOCKS on nat.OUTPUT chain.](https://raw.githubusercontent.com/MakeThings-team/picgo-library/main/iptables-ipv4-packet-redirect/apply_nat.redsocks.png)



5. 使用第三方转发工具或`adb`将8989端口接收到的数据包转发给中间人代理。

- 第三方工具`redsocks`转发流量：

  redsocks可以在android设备的任意端口（这里我们选择的是`8989`）创建监听，并将该端口接收到的数据包转发给其它网络设备。使用方式不做过多介绍，详见[redsocks官网](https://github.com/darkk/redsocks)。

- `adb`方式转发流量：

  **需要注意的是当使用adb方式转发流量时，必须开启系统代理，否则中间人代理将收不到数据包，该问题目前无法解决。**

  `adb reverse [--no-rebind] REMOTE LOCAL`命令提供了反向代理的功能

  可以使`adbd(运行在android设备上的adb守护进程)`在android设备的`REMOTE`端口上创建监听，并将`REMOTE`端口接收到的数据包转发给`adb server(无特殊情况下一般是执行adb reverse的计算机)`设备上的`LOCAL`端口

  `adb reverse`提供了反向代理的功能，它可以在android设备的任意端口（这里我们选择的是`8989`）创建监听，并将该端口接收到的数据包转发给`adb server(一般是执行adb reverse的计算机)`

  `adb reverse`功能如下：
  
  ```
   reverse --list           list all reverse socket connections from device
   reverse [--no-rebind] REMOTE LOCAL
       reverse socket connection using:
         tcp:<port> (<remote> may be "tcp:0" to pick any open port)
         localabstract:<unix domain socket name>
         localreserved:<unix domain socket name>
         localfilesystem:<unix domain socket name>
   reverse --remove REMOTE  remove specific reverse socket connection
   reverse --remove-all     remove all reverse socket connections from device
  ```



使用`adb reverse`反向代理将8989端口转发到计算机的8888端口，在计算机上启动fiddler或charles中间人代理并咋计算机上监听8888端口。

```bash
$ adb reverse tcp:8989 tcp:8888
$ adb reverse --list
```

![adb reverse](https://raw.githubusercontent.com/MakeThings-team/picgo-library/main/iptables-ipv4-packet-redirect/adb_reverse_add.png)



##### 移除iptables的流量转发

1. 关闭adb的反向代理，使用`adb reverse --remove-all`或`adb reverse --remove REMOTE`命令

```bash
$ adb reverse --remove-all
$ adb reverse --remove tcp:8989
```



2. 重新刷写nat表中的REDSOCKS链，这一操作将清空nat.REDSOCKS链下的所有规则

```bash
$ iptables -t nat -F REDSOCKS
```



3. 删除`nat.OUTPUT`链下的`REDSOCKS`规则链

```bash
$ iptables -t nat -D OUTPUT -p tcp -j REDSOCKS
```



4. 查看 `nat.OUTPUT` 和 `nat.REDSOCKS` 链的规则是否生效

```bash
$ iptables --line -t nat -nvxL OUTPUT
$ iptables --line -t nat -nvxL REDSOCKS
```