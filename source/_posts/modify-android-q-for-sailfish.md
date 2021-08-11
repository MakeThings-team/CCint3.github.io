---
title: sailfish 上修改 android Q
date: 2020-12-04 21:33:22
categories:
- [Android, Skill]

tags:
- Android
---



#### 需要

- android系统镜像：[10.0.0 (QP1A.191005.007.A3, Dec 2019)](https://dl.google.com/dl/android/aosp/sailfish-qp1a.191005.007.a3-factory-d4552659.zip) - d455265945bb936a653730031af7d7a4aba70dc0c775024666a53491c9833b61
- simg2img: Android sparse image转Linux image；用来将system.img, vendor.img转为可挂载的image
- img2simg: Linux image转Android sparse image；将可挂载的image转为可刷写的image
- X-Ways Forensics: 以16进制编辑文件内容，并支持ext4文件系统格式挂载文件
- IDA Pro：反汇编支持
- ARM 架构参考手册：汇编指令支持



#### 解压谷歌官方镜像压缩包后得到以下文件树

```shell
$ pwd
/home/ccint3/Desktop
$ tree sailfish
sailfish  # 根目录，将谷歌官方镜像压缩包存放至该目录中
├── sailfish-qp1a.191005.007.a3-factory-d4552659  # 解压谷歌官方镜像压缩包后得到的目录
│   └── sailfish-qp1a.191005.007.a3  # 解压谷歌官方镜像压缩包后得到的目录
│       ├── bootloader-sailfish-8996-012001-1908071822.img  # bootloader image 文件
│       ├── flash-all.bat  # windows刷机脚本
│       ├── flash-all.sh   # linux刷机脚本
│       ├── flash-base.sh  # 刷机脚本，只刷bootloader和基带
│       ├── image-sailfish-qp1a.191005.007.a3  # 解压image压缩包得到的目录
│       │   ├── android-info.txt  # 描述文件，描述当前目录下的image适用于那种设备和基带版本要求
│       │   ├── boot.img  # boot image，包含内核以及recovery分区（android Q及以上版本将boot中的root分区移动至了system.img中）
│       │   ├── system.img  # 包含system分区以及root分区 + avb校验元数据
│       │   ├── system_other.img  # 附属的system分区内容（其中的数据不是非常重要）
│       │   └── vendor.img  # 包含vendor分区 + avb校验元数据
│       ├── image-sailfish-qp1a.191005.007.a3.zip  # image压缩包，包含system和vendor image
│       └── radio-sailfish-8996-130361-1905270421.img  ## 基带 image 文件
└── sailfish-qp1a.191005.007.a3-factory-d4552659.zip  # 谷歌官方镜像压缩包

3 directories, 12 files
```



#### 工作目录和其文件树

下文的操作如无特殊说明，均在`sailfish/sailfish-qp1a.191005.007.a3-factory-d4552659/sailfish-qp1a.191005.007.a3/image-sailfish-qp1a.191005.007.a3`中进行

```shell
$ pwd
/home/ccint3/Desktop/sailfish/sailfish-qp1a.191005.007.a3-factory-d4552659/sailfish-qp1a.191005.007.a3/image-sailfish-qp1a.191005.007.a3
$ tree
.
├── android-info.txt
├── boot.img
├── system.img
├── system_other.img
└── vendor.img

0 directories, 5 files
```



#### 关闭avb

avb功能首先对分区进行每4kb字节的数据生成校验值，并将这些校验值合并到一起生成一个校验值数据块，校验值数据块的大小取决于分区大小并将这个数据块称作avb metadata，最后将avb metadata附加到image结尾，一同刷写进android设备。

android设备启动时，首先对avb metadata的root节点进行校验，如果通过则继续启动，否则将陷入bootloop.

![dm-verity hash table](https://source.android.com/security/images/dm-verity-hash-table.png)

如果不关闭avb功能，对分区的修改会导致android设备bootloop或者修改的内容无法生效（无法生效是通过FEC向前纠错来实现的）。

avb metadata头部的magic number可以控制avb是否生效。通过修改avb metadata magic number可以关闭avb功能；

校验元数据Magic number的定义如下：

[\#define VERITY_METADATA_MAGIC_NUMBER 0xb001b001](https://android.googlesource.com/platform/system/core/+/refs/tags/android-10.0.0_r17/fs_mgr/include/fs_mgr.h#30)

[\#define VERITY_METADATA_MAGIC_DISABLE 0x46464f56 // "VOFF"](https://android.googlesource.com/platform/system/core/+/refs/tags/android-10.0.0_r17/fs_mgr/include/fs_mgr.h#34)



- 在`android O`上可以直接修改`boot.img/fstab.sailfish`文件，删除其中的`verity`字段即可；

  这是因为boot.img中的root分区并没有被avb保护，所以可以直接修改root分区中的文件后重新打包root分区到boot.img中进行刷写。

- 在`android Q`上boot.img中的root分区被移动到system.img中，所以修改boot.img是不生效的。



关闭android Q的avb：

1. 重命名

   将`system.img`和`vendor.img`分别命名为`system.img.org`和`vendor.img.org`以备份

2. android sparse image转linux image

   使用simg2img将`system.img.org`和`vendor.img.org`分别转为`system.img.raw`和`vendor.img.raw`

   ```shell
   $ simg2img system.img.org system.img.raw
   $ simg2img vendor.img.org vendor.img.raw
   ```

3. 修改avb校验元数据Magic number

   使用16进制编辑器`X-Ways Forensics`分别修改`system.img.raw`和`vendor.img.raw`中的校验元数据，将`0xb001b001`修改为`0x46464f56`；

   搜索16进制字符串`01B001B000000000`定位到校验元数据头Magic number的位置

   - 修改system.img.raw，偏移：`0x7EFE5000`

     ![system.img.raw avbmeta magic enabled](https://raw.githubusercontent.com/MakeThings-team/picgo-library/main/modify-android-q-for-sailfish/system.img.raw.avbmeta.magic.enabled.png)

     ![system.img.raw avbmeta magic disabled](https://raw.githubusercontent.com/MakeThings-team/picgo-library/main/modify-android-q-for-sailfish/system.img.raw.avbmeta.magic.disabled.png)

   - 修改vendor.img.raw，偏移：`0x1299b000`

     ![vendor.img.raw avbmeta magic enabled](https://raw.githubusercontent.com/MakeThings-team/picgo-library/main/modify-android-q-for-sailfish/vendor.img.raw.avbmeta.magic.enabled.png)

     ![vendor.img.raw avbmeta magic disabled](https://raw.githubusercontent.com/MakeThings-team/picgo-library/main/modify-android-q-for-sailfish/vendor.img.raw.avbmeta.magic.disabled.png)



#### 关闭selinux

- android O

  修改aosp源码[init.cpp: selinux_is_enforcing](https://android.googlesource.com/platform/system/core/+/refs/tags/android-8.1.0_r52/init/init.cpp#587)函数，使该函数直接返回false。

  重新编译init可执行文件。

  boot.img解包后替换init可执行文件。

  重新打包boot.img后刷写到android设备中。

- android Q

  boot.img中的根分区被移动到system.img中，init可执行文件也同样被移动到system.img中。

  那么就需要对system.img中的init可执行文件进行修改，但是遇到一个问题就是system.img无法挂载为可读可写。并且remount时提示“写保护”。

  ```shell
  $ sudo mount system.img.raw system_raw
  mount: /home/ccint3/Desktop/sailfish/sailfish-qp1a.191005.007.a3-factory-d4552659/sailfish-qp1a.191005.007.a3/image-sailfish-qp1a.191005.007.a3/system_raw: wrong fs type, bad option, bad superblock on /dev/loop6, missing codepage or helper program, or other error.
  $ sudo mount -r system.img.raw system_raw
  $ sudo mount -o rw,remount system_raw
  mount: /home/ccint3/Desktop/sailfish/sailfish-qp1a.191005.007.a3-factory-d4552659/sailfish-qp1a.191005.007.a3/image-sailfish-qp1a.191005.007.a3/system_raw: cannot remount /dev/loop6 read-write, is write-protected.
  ```

  那么只能对system.img进行16进制编辑并保存，因此就需要`X-Ways Forensics`工具提供支持，这个工具支持以16进制编辑system.img，并且可以将system.img转为ext4的文件系统并编辑。

  1. 阅读android Q的源码，了解如何关闭selinux

     android Q上开启selinux的源码发生了变化，对selinux进行了独立的源码管理

     [selinux.cpp: IsEnforcing](https://android.googlesource.com/platform/system/core/+/refs/tags/android-10.0.0_r17/init/selinux.cpp#99)

     查看IsEnforcing的调用关系，并定位到[selinux.cpp: SelinuxInitialize](https://android.googlesource.com/platform/system/core/+/refs/tags/android-10.0.0_r17/init/selinux.cpp#423)

  2. 修改system.img中的init可执行文件

     `X-Ways Forensics`打开system.img，并将文件转换为磁盘

     ![system.img.raw winhex convert to disk](https://raw.githubusercontent.com/MakeThings-team/picgo-library/main/modify-android-q-for-sailfish/system.img.raw.winhex.convert.disk.png)

     将system.img磁盘中的`system/bin/init`可执行文件复制出来

     ![system.img.raw disk pull init](https://raw.githubusercontent.com/MakeThings-team/picgo-library/main/modify-android-q-for-sailfish/system.img.raw.disk.pull.init.png)

     使用`IDA Pro x64`打开init可执行文件进行分析，因为从源码中我们知道SelinuxInitialize函数最终启动了selinux，因此我们在IDA中定位SelinuxInitialize函数，在SelinuxInitialize中有一些日志字符串，我们通过这些字符串就可以定位SelinuxInitialize的位置，例如：`Loading SELinux policy`；在IDA中`shift + F12`打开字符串窗口，并搜索`Loading SELinux policy`获取以下结果

     ![init.SelinuxInitialize string location](https://raw.githubusercontent.com/MakeThings-team/picgo-library/main/modify-android-q-for-sailfish/init.SelinuxInitialize.string.location.png)

     对字符串参考引用后，最终定位到下图的位置

     ![init.SelinuxInitialize string location](https://raw.githubusercontent.com/MakeThings-team/picgo-library/main/modify-android-q-for-sailfish/init.SelinuxInitialize.string.location1.png)

     反汇编后，看到下图中的代码

     ![init.SelinuxInitialize security_getenforce](https://raw.githubusercontent.com/MakeThings-team/picgo-library/main/modify-android-q-for-sailfish/init.SelinuxInitialize.security_getenforce.png)

     关键代码如下：

     ```c++
       // 因为编译器内联汇编的原因，IsEnforcing函数直接被替换为了常量 1
       // 与 security_getenforce 的返回值做比较
       if ( (unsigned int)security_getenforce() != 1 )
       {
         // 因为编译器内联汇编的原因，所以security_setenforce函数的参数被替换为了常量1
         // 通过 security_setenforce(1) 来启动selinux
         // 因此我们需要修改security_setenforce函数的参数，将参数该为0，表示关闭selinux
         v6 = (android::base *)security_setenforce(1LL);
         if ( (_DWORD)v6 )
         {
             // ...
         }
       }
     ```

     我们的最终目的是修改`security_setenforce(1)`为`security_setenforce(0)`即可关闭selinux；

     因为默认请情况下`security_getenforce`返回1，表示默认启动selinux；那么`security_getenforce() != 1`则表示不会调用`security_setenforce`函数。

     至此我们明确了需要修改的两处内容：

     1：将`security_getenforce() != 1`修改为`security_getenforce() != 0`

     2：将`security_setenforce(1LL)`修改为`security_setenforce(0LL)`

     转至汇编代码，查看对应的汇编代码并修改，汇编代码如下图所示：

     ![init.SelinuxInitialize security_getenforce asm](https://raw.githubusercontent.com/MakeThings-team/picgo-library/main/modify-android-q-for-sailfish/init.SelinuxInitialize.security_getenforce.asm.png)

     偏移`6A8FC`处的汇编`CMP W0, #1`修改为`CMP W0, #0`

     `CMP W0, #0`的汇编指令：`0x7100001F`

     偏移`6A904`处的汇编`MOV W0, #1`修改为`MOV W0, #0`

     `MOV W0, #0`的汇编指令：`0x52800000`

     修改后如图所示

     ![init.SelinuxInitialize security_getenforce asm modify](https://raw.githubusercontent.com/MakeThings-team/picgo-library/main/modify-android-q-for-sailfish/init.SelinuxInitialize.security_getenforce.asm.modify.png)

     将修改的内容写到init文件中，查看代码偏移`6A8FC`和`6A904`对应的文件偏移`6A8FC`和`6A904`；

     使用`X-Ways Forensics`打开init文件，并跳转至文件偏移后，将汇编指令写入该位置：

     ![init.SelinuxInitialize security_getenforce file](https://raw.githubusercontent.com/MakeThings-team/picgo-library/main/modify-android-q-for-sailfish/init.SelinuxInitialize.security_getenforce.file.png)

     修改后：

     ![init.SelinuxInitialize security_getenforce file midify](https://raw.githubusercontent.com/MakeThings-team/picgo-library/main/modify-android-q-for-sailfish/init.SelinuxInitialize.security_getenforce.file.midify.png)



#### 关闭adbd指纹认证

- android O

  修改aosp adbd源码，重新编译之后，解包system.img，替换system.img中的adbd可执行文件，然后对system.img重新打包，之后刷写进android设备即可。

- android Q

  实现方式同`关闭selinux`类似，定位adbd源码位置，查看如何在源码级关闭指纹认证。之后使用`IDA Pro`修改对应的汇编，最后在`X-Ways Forensics`中修改system.img中adbd的文件内容。

  源码位置：[adb/daemon/main.cpp：adbd_main](https://android.googlesource.com/platform/system/core/+/refs/tags/android-10.0.0_r17/adb/daemon/main.cpp#190)

  关键代码如下：

  ```c++
  int adbd_main(int server_port) {
      // ...
  #if defined(ALLOW_ADBD_NO_AUTH)
      // If ro.adb.secure is unset, default to no authentication required.
      auth_required = android::base::GetBoolProperty("ro.adb.secure", false);
  #elif defined(__ANDROID__)
      if (is_device_unlocked()) {  // allows no authentication when the device is unlocked.
          auth_required = android::base::GetBoolProperty("ro.adb.secure", false);
      }
  #endif
      adbd_auth_init();
      // ...
      return 0;
  }
  ```

  全局变量`auth_required`为`true`时，开启adbd指纹认证，为`false`时则关闭指纹认证。

  该变量通过`ro.adb.secure`来控制，在`default.prop`中设置该属性，或者修改`GetBoolProperty`函数的返回值。

  在system.img中复制出`system/bin/adbd`可执行文件，并使用`IDA Pro x64`打开。
  通过`ro.adb.secure`字符串参考引用来定位`adbd_main`函数的位置。最终定位到如下图所示：

  ![adbd.adbd_main](https://raw.githubusercontent.com/MakeThings-team/picgo-library/main/modify-android-q-for-sailfish/adbd.adbd_main.png)

  关键代码的反汇编如下：

  ![adbd.adbd_main disasm](https://raw.githubusercontent.com/MakeThings-team/picgo-library/main/modify-android-q-for-sailfish/adbd.adbd_main.disasm.png)

  查看对应的汇编代码如下：

  ![adbd.adbd_main asm](https://raw.githubusercontent.com/MakeThings-team/picgo-library/main/modify-android-q-for-sailfish/adbd.adbd_main.asm.png)

  偏移`20F0`处的汇编`AND W8, W0, #1`修改为`MOV W8, #0`

  `MOV W8, #0`的汇编指令：`0x52800008`

  修改如下：

  ![adbd.adbd_main asm modify](https://raw.githubusercontent.com/MakeThings-team/picgo-library/main/modify-android-q-for-sailfish/adbd.adbd_main.asm.modify.png)

  最后通过`X-Ways Forensics`将修改的内容应用到system.img `system/bin/adbd`中



#### 禁止adbd root权限降级

修改方式同`关闭adbd指纹认证`

源码位置：

[adb/daemon/main.cpp：adbd_main](https://android.googlesource.com/platform/system/core/+/refs/tags/android-10.0.0_r17/adb/daemon/main.cpp#190)

[adb/daemon/main.cpp：drop_privileges](https://android.googlesource.com/platform/system/core/+/refs/tags/android-10.0.0_r17/adb/daemon/main.cpp#109)

[adb/daemon/main.cpp：should_drop_privileges](https://android.googlesource.com/platform/system/core/+/refs/tags/android-10.0.0_r17/adb/daemon/main.cpp#74)



关键代码如下：

```c++
int adbd_main(int server_port) {
    // ...
#if defined(__ANDROID__)
    drop_privileges(server_port);
#endif
    // ...
    return 0;
}

static void drop_privileges(int server_port) {
    // ...
    if (should_drop_privileges()) {
        // ...
    } else {
        // minijail_enter() will abort if any priv-dropping step fails.
        minijail_enter(jail.get());
        if (root_seclabel != nullptr) {
            if (selinux_android_setcon(root_seclabel) < 0) {
                LOG(FATAL) << "Could not set SELinux context";
            }
        }
        std::string error;
        std::string local_name =
            android::base::StringPrintf("tcp:%d", server_port);
        if (install_listener(local_name, "*smartsocket*", nullptr, 0, nullptr, &error)) {
            LOG(FATAL) << "Could not install *smartsocket* listener: " << error;
        }
    }
}

static bool should_drop_privileges() {
    // "adb root" not allowed, always drop privileges.
    if (!ALLOW_ADBD_ROOT && !is_device_unlocked()) return true;
    // The properties that affect `adb root` and `adb unroot` are ro.secure and
    // ro.debuggable. In this context the names don't make the expected behavior
    // particularly obvious.
    //
    // ro.debuggable:
    //   Allowed to become root, but not necessarily the default. Set to 1 on
    //   eng and userdebug builds.
    //
    // ro.secure:
    //   Drop privileges by default. Set to 1 on userdebug and user builds.
    bool ro_secure = android::base::GetBoolProperty("ro.secure", true);
    bool ro_debuggable = __android_log_is_debuggable();
    // Drop privileges if ro.secure is set...
    bool drop = ro_secure;
    // ... except "adb root" lets you keep privileges in a debuggable build.
    std::string prop = android::base::GetProperty("service.adb.root", "");
    bool adb_root = (prop == "1");
    bool adb_unroot = (prop == "0");
    if (ro_debuggable && adb_root) {
        drop = false;
    }
    // ... and "adb unroot" lets you explicitly drop privileges.
    if (adb_unroot) {
        drop = true;
    }
    return drop;
}
```

读取`ro.secure`和`service.adb.root`属性并判断是否需要降级。

我们需要将`should_drop_privileges`的返回值改为`false`；通过字符串`ro.secure`使用`IDA Pro x64`定位到目标代码位置。并反汇编后代码如下：

![adbd.adbd_main adbroot disasm](https://raw.githubusercontent.com/MakeThings-team/picgo-library/main/modify-android-q-for-sailfish/adbd.adbd_main.adbroot.disasm.png)

需要修改的汇编位置如下：

偏移`2270`处汇编` AND W8, W10, #1`修改为`MOV W8, #0`

![adbd.adbd_main adbroot asm modify 2270](https://raw.githubusercontent.com/MakeThings-team/picgo-library/main/modify-android-q-for-sailfish/adbd.adbd_main.adbroot.asm.modify1.png)



偏移`22C8`处汇编`ORR W21, W9, W8`修改为`MOV W21, #0`

![adbd.adbd_main adbroot asm modify 22C8](https://raw.githubusercontent.com/MakeThings-team/picgo-library/main/modify-android-q-for-sailfish/adbd.adbd_main.adbroot.asm.modify2.png)



偏移`22D0`处汇编`AND W8, W8, #1`修改为`MOV W8, #0`

![adbd.adbd_main adbroot asm modify 22D0](https://raw.githubusercontent.com/MakeThings-team/picgo-library/main/modify-android-q-for-sailfish/adbd.adbd_main.adbroot.asm.modify3.png)



偏移`22E8`处汇编`AND W21, W21, W9`修改为`MOV W21, #0`

![adbd.adbd_main adbroot asm modify 22E8](https://raw.githubusercontent.com/MakeThings-team/picgo-library/main/modify-android-q-for-sailfish/adbd.adbd_main.adbroot.asm.modify4.png)



偏移`245C`处汇编`550400948000F8364B0400941F1800710D420054`修改为`0xD503201F*5`

![adbd.adbd_main adbroot asm modify 245C](https://raw.githubusercontent.com/MakeThings-team/picgo-library/main/modify-android-q-for-sailfish/adbd.adbd_main.adbroot.asm.modify5.png)



#### 开机启动adbd，无需打开开发者模式并勾选USB调试

android Q上通过修改vendor.img中的`etc/init/init.usb.rc`来影响adbd的启动

将`init.usb.rc`修改为：

```
on property:sys.usb.config=mtp
    setprop sys.usb.config adb

on property:sys.usb.config=mtp,adb
    write /sys/class/android_usb/android0/enable 0
    write /sys/class/android_usb/android0/idVendor 18D1
    write /sys/class/android_usb/android0/idProduct 4EE2
    write /sys/class/android_usb/android0/bDeviceClass 0
    write /sys/class/android_usb/android0/bDeviceSubClass 0
    write /sys/class/android_usb/android0/bDeviceProtocol 0
    write /sys/class/android_usb/android0/functions ${sys.usb.config}
    write /sys/class/android_usb/android0/enable 1
    start adbd
    setprop sys.usb.state ${sys.usb.config}

on property:sys.usb.config=rndis
    setprop sys.usb.config adb

on property:sys.usb.config=rndis,adb
    write /sys/class/android_usb/android0/enable 0
    write /sys/class/android_usb/android0/idVendor 18D1
    write /sys/class/android_usb/android0/idProduct 4EE4
    write /sys/class/android_usb/android0/bDeviceClass 239
    write /sys/class/android_usb/android0/bDeviceSubClass 2
    write /sys/class/android_usb/android0/bDeviceProtocol 1
    write /sys/class/android_usb/android0/functions ${sys.usb.config}
    write /sys/class/android_usb/android0/enable 1
    start adbd
    setprop sys.usb.state ${sys.usb.config}

on property:sys.usb.config=ptp
    setprop sys.usb.config adb

on property:sys.usb.config=ptp,adb
    write /sys/class/android_usb/android0/enable 0
    write /sys/class/android_usb/android0/idVendor 18D1
    write /sys/class/android_usb/android0/idProduct 4EE6
    write /sys/class/android_usb/android0/bDeviceClass 0
    write /sys/class/android_usb/android0/bDeviceSubClass 0
    write /sys/class/android_usb/android0/bDeviceProtocol 0
    write /sys/class/android_usb/android0/functions ptp,adb
    write /sys/class/android_usb/android0/enable 1
    start adbd
    setprop sys.usb.state ${sys.usb.config}

on property:sys.usb.config=midi
    setprop sys.usb.config adb

on property:sys.usb.config=midi,adb
    write /sys/class/android_usb/android0/enable 0
    write /sys/class/android_usb/android0/idVendor 18D1
    write /sys/class/android_usb/android0/idProduct 4EE9
    write /sys/class/android_usb/android0/bDeviceClass 0
    write /sys/class/android_usb/android0/bDeviceSubClass 0
    write /sys/class/android_usb/android0/bDeviceProtocol 0
    write /sys/class/android_usb/android0/functions ${sys.usb.config}
    write /sys/class/android_usb/android0/enable 1
    start adbd
    setprop sys.usb.state ${sys.usb.config}
```

修改后的`init.usb.rc`相比源文件有所缩短，为了不破坏文件，我们还需要维护这个文件在ext4文件系统inode块文件大小。通过`X-Ways Forensics`跳转至该文件的`inode`数据块，统计修改后这个文件的真实大小并修改`inode`数据库记录即可。

![vendor.img.raw goto inode](https://raw.githubusercontent.com/MakeThings-team/picgo-library/main/modify-android-q-for-sailfish/vendor.img.raw.goto.inode.png)

![vendor.img.raw modify inode](https://raw.githubusercontent.com/MakeThings-team/picgo-library/main/modify-android-q-for-sailfish/vendor.img.raw.modify.inode.png)

最后保存修改并刷写至手机即可