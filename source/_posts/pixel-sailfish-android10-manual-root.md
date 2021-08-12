---
title: Pixel(sailfish) android 10 手动 root
date: 2021-08-12 16:52:53
tags:
- Android
---



#### 需要

- android 10 ROM：[Android 10.0.0 (QP1A.191005.007.A3, Dec 2019)](https://dl.google.com/dl/android/aosp/sailfish-qp1a.191005.007.a3-factory-d4552659.zip)
- simg2img: `Android sparse image`转`Linux image`；用来将system.img, vendor.img转为可挂载的image
- img2simg: `Linux image`转`Android sparse image`；将可挂载的image转为可刷写的image
- X-Ways Forensics: 以16进制编辑文件内容，并支持ext4文件系统格式挂载系统映像文件
- IDA Pro：反汇编支持
- ARM 架构参考手册：汇编指令支持
- mount, umount：挂载和卸载指定分区



#### 解压谷歌官方映像压缩包

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

[Android 启动时验证](https://source.android.com/security/verifiedboot?hl=zh-cn)

该功能是为了防止恶意程序对系统映像文件的恶意修改，它对系统映像文件进行每4kb字节的数据生成校验值，最后将avb metadata附加到系统映像文件的结尾，一同刷写进android设备。android设备启动时，会对avb metadata进行校验。

实现流程：

1. 选择一个随机盐（十六进制编码）
2. 将系统映像拆分成 4k 大小的块
3. 获取每个块的加盐 SHA256 哈希
4. 组合这些哈希以形成层
5. 在层中填充 0，直至达到 4k 块的边界
6. 将层组合到哈希树中
7. 重复第 2-6 步（使用前一层作为下一层的来源），直到最后只有一个哈希

该过程的结果是一个哈希，也就是根哈希。在构建 dm-verity 映射表时会用到该哈希和您选择的盐

![dm-verity hash table](https://source.android.com/security/images/dm-verity-hash-table.png)



如果不关闭avb功能，对分区的修改会无法生效 或者 导致设备bootloop。

例如对分区中的某个文件进行了修改，重新刷写并重启后发现该文件的内容并未发生任何变化，这是因为android7以上开启了[FEC向前纠错](https://source.android.com/security/verifiedboot/dm-verity?hl=zh-cn#fec)功能，简而言之该功能对系统的文件有简单的修复功能。另外如果设备bootloop，那么说明FEC向前纠错无法对更改的文件进行纠错，那么就会进入bootloop。

avb metadata头部的magic number可以控制avb是否生效。通过修改avb metadata magic number可以关闭avb功能；

校验元数据Magic number的定义如下：

[\#define VERITY_METADATA_MAGIC_NUMBER 0xb001b001](https://android.googlesource.com/platform/system/core/+/refs/tags/android-10.0.0_r17/fs_mgr/include/fs_mgr.h#30)

[\#define VERITY_METADATA_MAGIC_DISABLE 0x46464f56 // "VOFF"](https://android.googlesource.com/platform/system/core/+/refs/tags/android-10.0.0_r17/fs_mgr/include/fs_mgr.h#34)

Verity结构

| 字段         | 说明                             | 大小               | 默认值        |
| ------------ | -------------------------------- | ------------------ | ------------- |
| magic number | 供 fs_mgr 用作一个健全性检查项目 | 4 bytes            | 0xb001b001    |
| version      | 用于为Verity数据块添加版本号     | 4 bytes            | android 10为0 |
| signature    | PKCS1.5 填充形式的表签名         | 256 bytes          |               |
| table length | dm-verity 表的长度（以字节数计） | 4 bytes            |               |
| table        | 上文介绍的 dm-verity 表          | table length bytes |               |
| padding      | 此结构会通过填充 0 达到 32k 长度 |                    | 0             |



##### 关闭android 8以下的avb：

在`android 8(包含)`以下可以直接修改`boot.img/fstab.sailfish`文件，删除其中的`verity`字段即可；这是因为boot.img中的root分区并没有被avb保护，所以可以直接修改root分区中的文件后重新打包root分区到boot.img中进行刷写。



##### 关闭android 10的avb：

在`android 10(包含)`以上boot.img中的root分区被移动到system.img中，因此修改boot.img并不能影响到root分区。因此需要通过以下的方式关闭

1. 重命名

   将`system.img`和`vendor.img`分别命名为`system.img.org`和`vendor.img.org`以备份

2. android sparse image转linux image

   使用simg2img将`system.img.org`和`vendor.img.org`分别转为`system.img.raw`和`vendor.img.raw`

   ```shell
   $ simg2img system.img.org system.img.raw
   $ simg2img vendor.img.org vendor.img.raw
   ```

3. 修改avb校验元数据Magic Number

   使用16进制编辑器`X-Ways Forensics`分别修改`system.img.raw`和`vendor.img.raw`中的校验元数据，将`0xb001b001`修改为`0x46464f56`；

   搜索16进制字符串`01B001B000000000`定位到校验元数据头Magic number的位置

   - 修改system.img.raw，偏移：`0x7EFE5000`

     ![system.img.raw avbmeta magic enabled](https://raw.githubusercontent.com/MakeThings-team/picgo-library/main/modify-android-q-for-sailfish/system.img.raw.avbmeta.magic.enabled.png)

     ![system.img.raw avbmeta magic disabled](https://raw.githubusercontent.com/MakeThings-team/picgo-library/main/modify-android-q-for-sailfish/system.img.raw.avbmeta.magic.disabled.png)

   - 修改vendor.img.raw，偏移：`0x1299b000`

     ![vendor.img.raw avbmeta magic enabled](https://raw.githubusercontent.com/MakeThings-team/picgo-library/main/modify-android-q-for-sailfish/vendor.img.raw.avbmeta.magic.enabled.png)

     ![vendor.img.raw avbmeta magic disabled](https://raw.githubusercontent.com/MakeThings-team/picgo-library/main/modify-android-q-for-sailfish/vendor.img.raw.avbmeta.magic.disabled.png)




#### 关闭 EXT4_FEATURE_RO_COMPAT_SHARED_BLOCKS

该功能会导致android 10以上的系统映像文件在ubuntu等系统上只能被挂载为只读模式。

关闭该功能是通过修改映像文件中的`Superblock`结构体来实现的。关闭该功能后虽然可挂载为可读写模式，但是不要试图去删除映像中的文件，这是因为该功能类似于通过引用计数的技术来共享公共文件，如果删除了某个被引用到的文件，那么需要额外的修复它的引用计数。但是不影响修改文件和新增文件。

以system.img.raw举例，superblock结构体的起始位置位于该文件0x400的位置。我们需要修改`superblock.s_feature_ro_compat`位置的4bytes数据，那么文件偏移为`0x400 + 0x64 = 0x464`；下面通过一段python代码展示如何关闭它

```python
from io import SEEK_SET


def main():
    image = open('system.img.raw', 'rb+')
    image.seek(0x464, SEEK_SET)
    s_feature_ro_compat = int.from_bytes(image.read(4), byteorder='little')
    print('old s_feature_ro_compat: 0x%08X' % s_feature_ro_compat)
    if s_feature_ro_compat & 0x4000:
        s_feature_ro_compat = s_feature_ro_compat ^ 0x4000
    image.seek(0x464, SEEK_SET)
    image.write(s_feature_ro_compat.to_bytes(4, byteorder='little'))
    print('new s_feature_ro_compat: 0x%08X' % s_feature_ro_compat)


if __name__ == '__main__':
    main()

```



#### 向selinux中注入策略

google提供的官方系统映像中selinux策略文件被保存在`vendor/etc/selinux/precompiled_sepolicy`文件中，该文件是经过`*.te`使用宏扩展为`*.cil`文件后再由selinux策略编译器生成的最终binary文件。因此我们直接向该文件中注入一些策略即可影响到操作系统的selinux。

[magiskpolicy](https://topjohnwu.github.io/Magisk/tools.html#magiskpolicy)：该工具是Magisk工程中提供的一个小工具，它可以读取`cli`或者`selinux binary`并向其中注入自定义domain，因此从 Magisk 守护进程产生的所有进程，包括 root shell 及其所有分支，都在上下文 `u:r:magisk:s0` 中运行，以此来实现Magisk su。

那么我们可以使用该工具向`vendor/etc/selinux/precompiled_sepolicy`中注入我们自定义的domain；通过修改[selinux.hpp](https://github.com/topjohnwu/Magisk/blob/master/native/jni/utils/include/selinux.hpp)中的几个宏即可自定义domain名称，当然这一步不是必须的。

```c++
// Unconstrained domain the daemon and root processes run in
#define SEPOL_PROC_DOMAIN   "magisk"
// Highly constrained domain, sole purpose is to connect to daemon
#define SEPOL_CLIENT_DOMAIN "magisk_client"
// Unconstrained file type that anyone can access
#define SEPOL_FILE_TYPE     "magisk_file"
// Special file type to allow clients to transit to client domain automatically
#define SEPOL_EXEC_TYPE     "magisk_exec"
```



如果上一步中修改了domain，那么需要重新编译magiskpolicy工具，并执行以下命令使magiskpolicy向目标binary中注入`SEPOL_PROC_DOMAIN domain`

```bash
$ adb push magiskpolicy /data/local/tmp/magiskpolicy
$ adb shell chmod a+x /data/local/tmp/magiskpolicy
$ adb shell /data/local/tmp/magiskpolicy --magisk --load-split --save /sdcard/magisk.sepolicy
$ adb pull /sdcard/magisk.sepolicy magisk.sepolicy
```



得到`magisk.sepolicy`文件之后，挂载vendor.img.raw为可读写模式，并替换`vendor/etc/selinux/precompiled_sepolicy`文件。

```bash
$ mkdir ./vendor
$ sudo mount vendor.img.raw ./vendor
$ cp magisk.sepolicy ./vendor/etc/selinux/precompiled_sepolicy
$ sudo umount ./vendor
```



#### adbd修改

上一步中我们向selinux环境中注入了自定义的context以此来达到可以创建拥有`root`权限的进程。



##### adbd root

adbd root有多种方式：patch adbd binary、修改aosp源码

其中patch adbd binary的方式在另外一篇文章中已经讲过，这里主要讲一下修改aosp源码的方式

```diff
project system/core/
diff --git a/adb/daemon/main.cpp b/adb/daemon/main.cpp
index 620d078..a23e127 100644
--- a/adb/daemon/main.cpp
+++ b/adb/daemon/main.cpp
@@ -62,16 +62,17 @@ static inline bool is_device_unlocked() {
     return "orange" == android::base::GetProperty("ro.boot.verifiedbootstate", "");
 }

-static bool should_drop_capabilities_bounding_set() {
-    if (ALLOW_ADBD_ROOT || is_device_unlocked()) {
-        if (__android_log_is_debuggable()) {
-            return false;
-        }
-    }
-    return true;
-}
+//static bool should_drop_capabilities_bounding_set() {
+//    if (ALLOW_ADBD_ROOT || is_device_unlocked()) {
+//        if (__android_log_is_debuggable()) {
+//            return false;
+//        }
+//    }
+//    return true;
+//}

 static bool should_drop_privileges() {
+    return false;
     // "adb root" not allowed, always drop privileges.
     if (!ALLOW_ADBD_ROOT && !is_device_unlocked()) return true;

@@ -128,46 +129,47 @@ static void drop_privileges(int server_port) {
     // Don't listen on a port (default 5037) if running in secure mode.
     // Don't run as root if running in secure mode.
     if (should_drop_privileges()) {
-        const bool should_drop_caps = should_drop_capabilities_bounding_set();
+        //const bool should_drop_caps = should_drop_capabilities_bounding_set();

-        if (should_drop_caps) {
-            minijail_use_caps(jail.get(), CAP_TO_MASK(CAP_SETUID) | CAP_TO_MASK(CAP_SETGID));
-        }
+        //if (should_drop_caps) {
+        //    minijail_use_caps(jail.get(), CAP_TO_MASK(CAP_SETUID) | CAP_TO_MASK(CAP_SETGID));
+        //}

-        minijail_change_gid(jail.get(), AID_SHELL);
-        minijail_change_uid(jail.get(), AID_SHELL);
+        //minijail_change_gid(jail.get(), AID_SHELL);
+        //minijail_change_uid(jail.get(), AID_SHELL);
         // minijail_enter() will abort if any priv-dropping step fails.
-        minijail_enter(jail.get());
+        //minijail_enter(jail.get());

         // Whenever ambient capabilities are being used, minijail cannot
         // simultaneously drop the bounding capability set to just
         // CAP_SETUID|CAP_SETGID while clearing the inheritable, effective,
         // and permitted sets. So we need to do that in two steps.
-        using ScopedCaps =
-            std::unique_ptr<std::remove_pointer<cap_t>::type, std::function<void(cap_t)>>;
-        ScopedCaps caps(cap_get_proc(), &cap_free);
-        if (cap_clear_flag(caps.get(), CAP_INHERITABLE) == -1) {
-            PLOG(FATAL) << "cap_clear_flag(INHERITABLE) failed";
-        }
-        if (cap_clear_flag(caps.get(), CAP_EFFECTIVE) == -1) {
-            PLOG(FATAL) << "cap_clear_flag(PEMITTED) failed";
-        }
-        if (cap_clear_flag(caps.get(), CAP_PERMITTED) == -1) {
-            PLOG(FATAL) << "cap_clear_flag(PEMITTED) failed";
-        }
-        if (cap_set_proc(caps.get()) != 0) {
-            PLOG(FATAL) << "cap_set_proc() failed";
-        }
-
-        D("Local port disabled");
+        //using ScopedCaps =
+        //    std::unique_ptr<std::remove_pointer<cap_t>::type, std::function<void(cap_t)>>;
+        //ScopedCaps caps(cap_get_proc(), &cap_free);
+        //if (cap_clear_flag(caps.get(), CAP_INHERITABLE) == -1) {
+        //    PLOG(FATAL) << "cap_clear_flag(INHERITABLE) failed";
+        //}
+        //if (cap_clear_flag(caps.get(), CAP_EFFECTIVE) == -1) {
+        //    PLOG(FATAL) << "cap_clear_flag(PEMITTED) failed";
+        //}
+        //if (cap_clear_flag(caps.get(), CAP_PERMITTED) == -1) {
+        //    PLOG(FATAL) << "cap_clear_flag(PEMITTED) failed";
+        //}
+        //if (cap_set_proc(caps.get()) != 0) {
+        //    PLOG(FATAL) << "cap_set_proc() failed";
+        //}
+
+        //D("Local port disabled");
     } else {
         // minijail_enter() will abort if any priv-dropping step fails.
         minijail_enter(jail.get());

         if (root_seclabel != nullptr) {
+            D("root_seclabel: %s", root_seclabel);
             if (selinux_android_setcon(root_seclabel) < 0) {
                 LOG(FATAL) << "Could not set SELinux context";
-            }
+           }
         }
         std::string error;
         std::string local_name =
```



##### adbd 取消认证

```diff
diff --git a/adb/daemon/main.cpp b/adb/daemon/main.cpp
index 72bad5f..79b1780 100644
--- a/adb/daemon/main.cpp
+++ b/adb/daemon/main.cpp
@@ -208,12 +208,13 @@ int adbd_main(int server_port) {

 #if defined(ALLOW_ADBD_NO_AUTH)
     // If ro.adb.secure is unset, default to no authentication required.
-    auth_required = android::base::GetBoolProperty("ro.adb.secure", false);
+    //auth_required = android::base::GetBoolProperty("ro.adb.secure", false);
 #elif defined(__ANDROID__)
-    if (is_device_unlocked()) {  // allows no authentication when the device is unlocked.
-        auth_required = android::base::GetBoolProperty("ro.adb.secure", false);
-    }
+    //if (is_device_unlocked()) {  // allows no authentication when the device is unlocked.
+    //    auth_required = android::base::GetBoolProperty("ro.adb.secure", false);
+    //}
 #endif
+    auth_required = false;

     adbd_auth_init();

```



##### 应用adbd修改

重新编译adbd之后需要挂载system.img.raw为可读写模式并将系统映像中的adbd替换掉

```bash
$ mkdir system
$ sudo mount system.img.raw system
$ cp adbd ./system/system/bin/adbd
$ sudo umount system
```



init 在启动adbd时使用的selinux context是`u:r:adbd:s0`，再经过selinux_android_setcon函数将context切换到`u:r:su:s0`；因为我们是向sepolicy中注入了自定的domain，因此我们需要将 `u:r:magisk:s0` 应用至 `system.img.raw/init.usb.rc`

```bash
$ mkdir system
$ sudo mount system.img.raw system
$ vim ./system/init.usb.rc
$ sudo umount system
```

例如：

```r
# adbd is controlled via property triggers in init.<platform>.usb.rc
service adbd /system/bin/adbd --root_seclabel=u:r:magisk:s0
    class core
    socket adbd seqpacket 660 system system
    disabled
    seclabel u:r:magisk:s0
```



##### adbd开机启动

修改`init.usb.rc`，在`on boot`阶段加入`persist.sys.usb.config adb`

```bash
$ mkdir system
$ sudo mount system.img.raw system
$ vim ./system/init.usb.rc
$ sudo umount system
```

例如：

```r
on boot
    setprop sys.usb.configfs 0
    setprop persist.sys.usb.config adb
```





#### 刷写修改后的系统映像

```bash
$ img2simg system.img.raw system.new.img
$ img2sigm vendor.img.raw vendor.new.img
$ adb reboot bootloader
$ fastboot flash system system.new.img
$ fastboot flash vendor vendor.new.img
$ fastboot reboot
```

