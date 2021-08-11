---
title: Frida Skill：小技巧
date: 2020-03-07 17:22:48
categories:
- [Frida, Skill]

tags:
- Frida
---



## 使用Frida自动补全和TypeScript模块化脚本

### 简介

配合使用集成开发环境编辑器（例如：JetBrains IDEA或Visual Code）编写[TypeScript](https://www.typescriptlang.org/)脚本来规范化、模块化并提供自动补全你的代码，让你的开发效率大大提升。



### 部署

- 项目地址：[frida-agent-example](https://github.com/oleavr/frida-agent-example)

```shell
$ git clone git://github.com/oleavr/frida-agent-example.git
$ cd frida-agent-example/
$ npm install
$ npm run watch
```



- 集成开发环境打开`frida-agent-example`目录

编辑`frida-agent-example/index.ts`文件并保存

`npm run watch`会监控[index.ts](https://github.com/oleavr/frida-agent-example/blob/master/agent/index.ts)文件并在项目根目录下生成`_agent.js`目标脚本。



- `Frida`注入

```shell
$ frida -U -f com.example.android --runtime=v8 --no-pause -l _agent.js
```



## 遍历Java List

`requestHeaders`是一个Java的List对象，遍历其内容如下：

```javascript
log += "  request.headers: " + rObject.$methods.find("toString").call(rObject, requestHeaders) + "\n";
for (var i = 0; i < requestHeaders.size(); i++)
  log += "    headers[" + i + "]: " + requestHeaders.get(i) + "\n";
```

输出：

```
request.headers: [com.sankuai.meituan.retrofit2.Header@a671e8]
  headers[0]: com.sankuai.meituan.retrofit2.Header@a671e8
```



## Native

静态注册或动态注册的Native函数，第二个参数总是一个`jobject`；如果native函数是静态函数，那么该参数是jclass，如果native函数是成员函数，那么该参数是当前类的对象；

例如Java层有以下声明代码：

```java
private native String TestNative(int arg1, int arg2, String arg3);
```

在Frida hook时：

```javascript
const nativeHook_TestNative = {
  onEnter: function (args) {
    this.env = args[0];
    //this.caller = args[1]; // jobject of the class.
    this.arg1 = args[2];
    this.arg2 = args[3];
    this.arg3 = args[4];
    this.tag = "nativeHook_TestNative";
    this.log = "";
    this.log += "> - - - - - - - - <\n";
    this.log += this.tag + " Enter.\n";
    this.log += "  JNIEnv: " + this.env + "\n";
    this.log += "  arg1: " + this.arg1 + "\n";
    this.log += "  arg2: " + this.arg2 + "\n";
    this.log += "  arg3: " + this.arg3 + ", " + GetStringUTFChars(this.env, this.arg3, NULL).readCString() + "\n";
    console.log(this.log);
  },
  onLeave: function (ret) {
    const tid = gettid();
    this.log = this.tag + " Leave.\n";
    this.log += "  ret: " + ret + ", str:" + GetStringUTFChars(this.env, ret, NULL).readCString() + "\n";
    this.log += "^ - - - - - - - - ^\n";
    console.log(this.log);
  }
};
```



## 华丽的hook代码

以下代码均运行在v8引擎环境中，请使用`frida --runtime=v8`来指定



### gettid, getpid, getuid

定义gettid, getpid, getuid三个[`frida.NativeFunction`](https://frida.re/docs/javascript-api/#nativefunction)供外部直接调用。

```javascript
const gettid = new NativeFunction(Module.getExportByName(null, 'gettid'), 'uint32', []);
const getpid = new NativeFunction(Module.getExportByName(null, 'getpid'), 'uint32', []);
const getuid = new NativeFunction(Module.getExportByName(null, 'getuid'), 'uint32', []);
```



### Hook libart.RegisterNatives

 ```javascript
function nativeHook_RegisterNatives_onEnter(args) {
  let _this = this;
  _this.tag = 'RegisterNatives';
  _this.env = args[0];
  _this.clazz = args[1];
  _this.methods = args[2];
  _this.nMethods = parseInt(args[3]);

  let log = `> - - - - - - - - - - - - - - - - - - tid:[${gettid()}] - - - - - - - - - - - - - - - - - - <\n`;
  log += `${_this.tag} Enter.\n`;
  log += `  env: ${_this.env}\n`;
  log += `  clazz: ${Java.vm.getEnv().getClassName(_this.clazz)}\n`;
  log += `  methods: ${_this.methods}\n`;
  log += `  nMethods: ${_this.nMethods}\n`;
  for (let i = 0; i < _this.nMethods; i++) {
    let methodName = _this.methods.add(i * (Process.pointerSize * 3)).readPointer().readCString();
    let methodSig = _this.methods.add(i * (Process.pointerSize * 3) + (Process.pointerSize)).readPointer().readCString();
    let methodPtr = _this.methods.add(i * (Process.pointerSize * 3) + (Process.pointerSize * 2)).readPointer();
    let methodMod = Process.findModuleByAddress(methodPtr);
    log += `    ${i + 1}:\n`;
    log += `      methodName: ${methodName}\n`;
    log += `      methodSig: ${methodSig}\n`;
    log += `      methodPtr: ${methodPtr}, off: ${methodPtr.sub(methodMod.base)}\n`;
    log += `      methodLib: ${methodMod.name}, base: ${methodMod.base}\n`;
    log += `\n`;
  }
  console.log(log);
}

function nativeHook_RegisterNatives_onLeave(retval) {
  let log = `${this.tag} Leave.\n`;
  log += `  retval: ${retval}\n`;
  log += `> - - - - - - - - - - - - - - - - - - tid:[${gettid()}] - - - - - - - - - - - - - - - - - - <\n`;
  console.log(log);
}

setImmediate(function () {
  Java.perform(function () {
    let JNIEnv = Java.vm.getEnv().handle;
    let JNIEnv_vtable = JNIEnv.readPointer();
    let registerNativesPtr = JNIEnv_vtable.add(215 * Process.pointerSize).readPointer();
    Interceptor.attach(registerNativesPtr, {
      onEnter: nativeHook_RegisterNatives_onEnter,
      onLeave: nativeHook_RegisterNatives_onLeave
    });
  });
  console.log('end');
});
 ```



### 给`Java.use`增加一些功能

```javascript
let classCache = {};

// hook before
Function.prototype.before = function (beforeFunction) {
  let _this = this;
  return function () {
    this._continue = true;
    let ret = beforeFunction(this, arguments);
    if (!ret) {
      //调用原函数
      ret = _this.apply(this, arguments);
    }
    return ret;
  }
};

// hook after
Function.prototype.after = function (afterFunction) {
  let _this = this;
  return function () {
    // 先执行原函数
    let ret = _this.apply(this, arguments);
    // 再执行新函数
    return afterFunction(this, ret, arguments);
  }
};

// 在调用Java.use前，先调用我们指定的匿名函数。
// 该匿名函数先通过classCache全局变量判断是否已经Java.use过这个类
// 如果已经Java.use过，那么直接返回；否则继续执行原本的Java.use
Java.use = Java.use.before(function (_this, args) {
  let className = args[0];
  if (classCache[className]) {
    console.log('[+] Java use:', className, 'is cached.');
    return classCache[className];
  }
  return false;
})

// 在调用Java.use后，再调用我们指定的匿名函数。
// 为Java.use的返回值增加两个属性：$fields 和 $methods
// 可以通过以下方式来使用这两个属性：
// 获取SecretKeySpec类的key字段
// let rSecretKeySpec = Java.use('javax.crypto.spec.SecretKeySpec');
// rSecretKeySpec.$fields.get("key", secKey);
//
// 调用Reference类的get方法
// let rReference = Java.use('java.lang.ref.Reference');
// rReference.$methods.find("get").call(rReference, uObj.get(i))
Java.use = Java.use.after(function (_this, ret, args) {
  let className = args[0];

  if (!classCache[className]) {
    ret.$fields = new class Fields {
      wrapper;

      constructor(wrapper) {
        this.wrapper = wrapper;
      }

      find(name) {
        let field;
        try {
          field = this.wrapper.getDeclaredField(name);
        } catch (e) {
          field = this.wrapper.getField(name);
        }
        return field;
      };

      findall() {
        let fields;
        fields = this.wrapper.getDeclaredFields();
        fields.concat(this.wrapper.getFields());
        return fields;
      };

      get(name, obj) {
        let notAccessible;
        let ret;
        let field = this.find(name);
        notAccessible = !field.isAccessible();
        if (notAccessible) field.setAccessible(true);
        ret = field.get.overload('java.lang.Object').call(field, obj);
        if (!notAccessible) field.setAccessible(false);
        return ret;
      };

      set(name, obj, val) {
        let isAccessible;
        let field = this.find(name);
        isAccessible = field.isAccessible();
        if (!isAccessible) field.setAccessible(true);
        field.set.overload('java.lang.Object', 'java.lang.Object').call(field, obj, val);
        if (!isAccessible) field.setAccessible(false);
      };
    }(ret.class);
    ret.$methods = new class Methods {
      wrapper;

      constructor(wrapper) {
        this.wrapper = wrapper;
      }

      find(name, ...args) {
        let method;
        try {
          method = this.wrapper.getDeclaredMethod(name, args);
        } catch (e) {
          method = this.wrapper.getMethod(name, args);
        }
        return function (obj, ...args) {
          let isAccessible;
          let ret;
          isAccessible = method.isAccessible();
          if (!isAccessible) method.setAccessible(true);
          ret = method.invoke(obj, args);
          if (!isAccessible) method.setAccessible(false);
          return ret;
        };
      };
    }(ret.class);
    classCache[className] = ret;
  }
  return ret;
});
```



### 打印堆栈

#### 根据指定的tab数量转为空格

```javascript
function genTableString(tableSize) {
  let tableString = '';
  tableSize = Math.max(Math.min(tableSize, 10), 0);
  for (let i = 0; i < tableSize; i++) {
    // One table character maps to two space characters.
    tableString += '  ';
  }
  return tableString;
}
```



#### Java层

```javascript
function nativeThreadTraceToString(traces, tableSize) {
  let module;
  let table = genTableString(tableSize);
  const stackTraces = [];
  for (let j = 0; j < traces.length; j++) {
    if (!traces.hasOwnProperty(j)) continue;
    const stackTrace = new class {
      index;
      moduleName;
      moduleBase;
      offset;
      address;

      constructor(index) {
        this.index = index;
        this.moduleName = '';
        this.moduleBase = NULL;
        this.offset = '';
        this.address = NULL;
      }

      toString() {
        return `idx: ${this.index}` +
          `, name: ${this.moduleName}` +
          `, base: ${this.moduleBase}` +
          `, offset: ${this.offset}` +
          `, address: ${this.address}`;
      };
    }(j);
    module = Process.findModuleByAddress(traces[j]);
    if (module) {
      stackTrace.moduleName = module.name;
      stackTrace.moduleBase = module.base;
    }
    stackTrace.address = traces[j];
    stackTrace.offset = `0x${(parseInt(stackTrace.address) - parseInt(stackTrace.moduleBase)).toString(16)}`;
    stackTraces.push(stackTrace);
  }
  return `${table}  ${stackTraces.join(`\n${table}  `)}`
}

// 调用代码丢了，后面再补叭。
```



native层

```javascript
function javaThreadTraceToString(thread, tableSize) {
  let table = genTableString(tableSize);
  let tag = `${table}Thread Trace:\n`;
  return `${tag}${table}  ${thread.getStackTrace().join(`\n${table}  `)}`;
}

// 调用代码
let rThread = Java.use('java.lang.Thread');
let thread = rThread.currentThread();
console.log(javaThreadTraceToString(thread, 1));
```

