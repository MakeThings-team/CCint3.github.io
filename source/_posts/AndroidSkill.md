---
title: Android Skill：小技巧
date: 2020-03-07 13:42:47

categories:
- [Android, Skill]

tags:
- Android
---



## APK安装失败[INSTALL_FAILED_VERIFICATION_FAILURE]

```bash
adb shell su -c settings put global package_verifier_enable 0
adb shell su -c settings put global verifier_verify_adb_installs 0
```



## 不插拔USB恢复offline状态的设备

```shell
$ adb devices
$ adb -s serial reconnect
```



## adb查看apk信息

```shell
$ adb shell pm list packages | grep aweme
$ adb shell dumpsys package com.ss.android.ugc.aweme
```



## armeabi-v7a系统调用表

https://android.googlesource.com/platform/external/kernel-headers/+/refs/tags/android-6.0.1_r66/original/uapi/asm-arm/asm/unistd.h



## Android Studio中指定ABI

编辑`app -> build.gradle`

```
defaultConfig {
    ...
    ndk {
    	abiFilters 'armeabi-v7a'    //只生成armv7的so
    }
}
```

相关ABI连接：

https://google.github.io/android-gradle-dsl/current/com.android.build.gradle.internal.dsl.NdkOptions.html

https://developer.android.com/ndk/guides/abis.html#sa



## 调整屏幕亮度

```shell
$ adb shell su
// 屏幕最亮
# echo 255 > /sys/class/leds/lcd-backlight/brightness

// 屏幕全黑，没有一点亮度；不影响screencap命令
# echo 0 > /sys/class/leds/lcd-backlight/brightness
```



## 截图

```shell
$ adb shell screencap -p /sdcard/01.png & adb pull /sdcard/01.png
```




## 获取Application和Context

```java
android.app.ActivityThread.currentApplication().getApplicationContext()
```



## adb logcat中搜索指定进程的日志正则表达式

```
7679\s+\d+\s+\w
```

android logcat原理：http://gityuan.com/2018/01/27/android-log/



## 打开Url Scheme协议链接

```shell
$ adb shell am start -a android.intent.action.VIEW -d "snssdk1128://user/profile/3733569708763603"
```



## 将用户证书修改为系统证书

```shell
$ adb shell
$ su
# mount -o remount,rw /system
# ls -al /data/misc/user/0/cacerts-added/
# mv /data/misc/user/0/cacerts-added/* /etc/security/cacerts/
# chmod 644 /etc/security/cacerts/*
# chown root:root /etc/security/cacerts/*
```



## 查找端口占用情况

- 通过端口号查找占用该端口的`uid`

例如需要查找`8081`端口，对应的16进制为：`0x1f91`

```shell
$ adb shell
$ cat /proc/net/tcp6 | grep -i 1f91
$ cat /proc/net/tcp | grep -i 1f91
```

结果如下：

```
  53: 00000000000000000000000000000000:1F91 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000 10080        0 300399 1 0000000000000000 99 0 0 10 -1
```

- 通过`uid`查找该`uid`对应的进程号

其中`10080`是`uid`； `UID(10080) - 10000 = 80 = u0_a80`

```shell
$ adb shell su -c ps | grep u0_a80
```

结果如下：

结果有多个进程都属于`u0_a80`用户的，那么`8081`端口就在其中一个进程中

```
u0_a80    9732  530   1828844 114996 SyS_epoll_ 00f734acb8 S com.ss.android.ugc.aweme:push
u0_a80    9907  530   2520916 507228 SyS_epoll_ 00f734acb8 S com.ss.android.ugc.aweme
u0_a80    10029 530   1831376 118660 SyS_epoll_ 00f734acb8 S com.ss.android.ugc.aweme:pushservice
u0_a80    10956 530   1799376 102028 SyS_epoll_ 00f734acb8 S com.ss.android.ugc.aweme:downloader
u0_a80    10968 530   1989384 173844 SyS_epoll_ 00f734acb8 S com.ss.android.ugc.aweme:miniapp0
```

- 根据进程id确定uid

```shell
$ adb shell su -c cat /proc/9907/cgroup
```

结果如下：

```
3:cpuset:/foreground
2:cpu:/
1:cpuacct:/uid_10080/pid_9907
```



## 查找顶级Activity

```shell
$ adb shell dumpsys activity activities > activity_activities.log
```

输出格式如下：其中每个`Hist`代表一个Activity

```verilog
ACTIVITY MANAGER ACTIVITIES (dumpsys activity activities)

Display #0 (activities from top to bottom):

  Stack #4:

    Task id #144

    * TaskRecord{e98d78a #144 A=com.tencent.karaoke U=0 sz=4}
    ...
      * Hist #3: ActivityRecord{6da6fab u0 com.tencent.karaoke/.module.detail.ui.GiftBillboardActivity t144}
      ...

      * Hist #2: ActivityRecord{cea57ec u0 com.tencent.karaoke/.module.live.ui.LiveActivity t144}
      ...

      * Hist #1: ActivityRecord{840f95 u0 com.tencent.karaoke/.module.webview.ui.WebViewContainerActivity t144}
      ...

      * Hist #0: ActivityRecord{ea80b18 u0 com.tencent.karaoke/.module.main.ui.MainTabActivity t144}
      ...
```



## 更改adbd的监听端口

```bash
$ adb shell su
# setprop service.adb.tcp.port 5555
# stop adbd
# start adbd
```



## 启用/关闭开发者选项 - USB debugging

启用：`setprop persist.sys.usb.config mtp,adb`

关闭：`setprop persist.sys.usb.config mtp`
相关代码：

`https://developer.android.com/reference/android/provider/Settings.Global.html#ADB_ENABLED`

`https://android.googlesource.com/platform/frameworks/base/+/android-4.4_r1.2/services/java/com/android/server/usb/UsbDeviceManager.java`



## 调试启动APK

```bat
:: Example:
::   run_dbg.bat org.github.testsignal .MainActivity
@ECHO OFF
CALL :DeQuote %1
SET PACKAGE_NAME=%return%

CALL :DeQuote %2
SET ACTIVITY_NAME=%return%

adb shell am start -D %PACKAGE_NAME%/%ACTIVITY_NAME%
adb shell ps | FINDSTR %PACKAGE_NAME%
ECHO please input process id:
SET /P PID=
adb forward tcp:12346 jdwp:%PID%
jdb -connect com.sun.jdi.SocketAttach:port=12346

PAUSE
GOTO :EOF

:DeQuote
  SET return=%~1
  GOTO :EOF
```



## TWRP模式下挂载指定分区

```bash
adb shell
# make /test
# ls -la /dev/block/platform/soc.0/f9824900.sdhci/by-name/boot
# mount /dev/block/mmcblk0p43 /test
```



## Ubuntu 上使用 Android-SDK

- 安装`platforms`时需要注意引号

  ```bash
  root@github:/opt/android_sdk# ./tools/bin/sdkmanager --install "platforms;android-23"
  [=======================================] 100% Unzipping... android-6.0/source.p
  ```



## logcat

android的Log.d系列日志是写在/dev/log_xxx文件中的；而/dev是挂载在tmpfs文件系统上，所以重启之后日志就消失了。参考：`system/core/liblog/logd_write.c`和`system/core/liblog/logd_write_kern.c`

{% asset_img "1567081826.png" "logd_write.c" %}

```bash
# adb shell su -c mount | grep /dev
tmpfs /dev tmpfs rw,seclabel,nosuid,relatime,size=1424720k,nr_inodes=356180,mode=755 0 0
```



## Hide all methods with CMAKE

在 CMAKE 中设置隐藏所有方法(不显示他们的符号)；

Hide all methods without add "\_\_attribute\_\_(visibility("default"))" for everyone of them:

```cmake
set_target_properties(YOUR_TARGET_NAME PROPERTIES CXX_VISIBILITY_PRESET hidden)
set_target_properties(YOUR_TARGET_NAME PROPERTIES C_VISIBILITY_PRESET hidden)
```



## Fucking knack of use ollvm edition clang to compile so on Android Studio

在 Android Studio 中使用 ollvm 版本的 clang 编译 so；

​	As you know, if you just overwrite the compiler executable file with ollvm edition, then you will get "'xxx.h' file not found" error, actually I am not understand this error explicitly, because the file exactly is there, and it will perform like you want when execute that compile command on shell, so here is my approach to avoid that:

​	Open "YOUT_PROJECT_PATH\app\.externalNativeBuild\cmake\debug\TARGET_ABI\rules.ninja", find the line of "rule C_COMPILER__TARGET"(TARGET mean the target name you specified by "add_library" on "CMakeLists.txt"), and you will find the path of clang executable file under it, modify it with your ollvm edition clang, then build your project as normal, you will get the ollvm compiled file.

​	如果简单的使用 ollvm 版本的 clang.exe 等可执行文件替换掉原版 ndk toolchain 中的 exe，那么将会报一些头文件查找不到的错误，网上说的原因似乎是不同版本的 clang 将会使用的头文件有差异，然而如果在控制台中直接使用 ollvm 版本 clang 去手动执行编译命令，是可以正常编译成功得到 .o 文件的，以下是我避免该坑的方法：

​	打开 "YOUT_PROJECT_PATH\app\.externalNativeBuild\cmake\debug\TARGET_ABI\rules.ninja"，找到 "rule C_COMPILER__TARGET" 这一行(TARGET 指你在 CMakeLists.txt 中使用 add_library 指定的库名)，然后你会在下面几行找到编译使用的 clang 路径，把它替换为你 ollvm 版本 clang 的路径，然后正常编译即可得到你想要的 so。