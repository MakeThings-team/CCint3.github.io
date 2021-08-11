---
title: Android Source Code Review
date: 2020-03-07 16:20:08
categories:
- [Android, Source Code]

tags:
- Android

---

## 关闭SELinux

```diff
project system/core/
diff --git a/init/init.cpp b/init/init.cpp
index 93fe944..acbcf66 100644
--- a/init/init.cpp
+++ b/init/init.cpp
@@ -913,6 +913,7 @@ static bool selinux_is_disabled(void)
 
 static bool selinux_is_enforcing(void)
 {
+    return false;
     if (ALLOW_DISABLE_SELINUX) {
         return selinux_status_from_cmdline() == SELINUX_ENFORCING;
     }

```



## adbd 取消授权

`ALLOW_ADBD_NO_AUTH`和`ro.adb.secure`是且的关系，编译release版时`ALLOW_ADBD_NO_AUTH`被置为0；这将导致release版的`ro.adb.secure`无论置1还是0都是不起作用的；

```diff
diff --git a/adb/adb_main.cpp b/adb/adb_main.cpp
index 45a2158..b526c1b 100644
--- a/adb/adb_main.cpp
+++ b/adb/adb_main.cpp
@@ -239,9 +239,9 @@ int adb_main(int is_daemon, int server_port)
     // descriptor will always be open.
     adbd_cloexec_auth_socket();
 
-    if (ALLOW_ADBD_NO_AUTH && property_get_bool("ro.adb.secure", 0) == 0) {
+
         auth_required = false;
-    }
+
```



## adbd ROOT

```diff
project system/core/
diff --git a/adb/adb_main.cpp b/adb/adb_main.cpp
index 45a2158..99050db 100644
--- a/adb/adb_main.cpp
+++ b/adb/adb_main.cpp
@@ -109,6 +109,7 @@ static void drop_capabilities_bounding_set_if_needed() {
 }
 
 static bool should_drop_privileges() {
+    return false;
 #if defined(ALLOW_ADBD_ROOT)
     char value[PROPERTY_VALUE_MAX];
 
@@ -287,12 +288,12 @@ int adb_main(int is_daemon, int server_port)
 
         D("Local port disabled\n");
     } else {
-        if ((root_seclabel != NULL) && (is_selinux_enabled() > 0)) {
-            // b/12587913: fix setcon to allow const pointers
-            if (setcon((char *)root_seclabel) < 0) {
-                exit(1);
-            }
-        }
+
+
+
+
+
+
         std::string local_name = android::base::StringPrintf("tcp:%d", server_port);
         if (install_listener(local_name, "*smartsocket*", NULL, 0)) {
             exit(1);
```

