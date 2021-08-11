---
title: android retrofit2 hook：retrofit2 框架逆向分析和hook
date: 2020-11-01 05:07:54
categories:
- [android, retrofit]
tags:
---

### 简介

该框架是一个网络框架，一般是作为okhttp的上层框架；请求先经过该框架的处理之后再交给okhttp；它的功能实际上是将java interface提取成request请求接口。之后交给 okhttp将发送request。

下面以美团9.8.0作为例子来分析。





### 分析Retrofit框架

#### Retrofit类

Retrofit类是框架的核心类，管理所有的interface；只要获得该对象，就可以调用任意一个已经创建好的interface接口；



##### Retrofit$Builder

Retrofit类有一个Builder内部类，用来创建Retrofit类的对象。

通过hook `Retrofit$Builder.build`可以获取到Retrofit的对象，也可以通过调用栈继续追踪调用源头（建议）。美团的Retrofit类采用单例设计模式；不同的app Retrofit对象的数量可能不同。

```java
public final Retrofit build() {
    // ...

    if(this.baseUrl != null) {
        Factory v2 = this.callFactory;
        if(v2 != null) {
            Executor v0 = this.httpExecutor;
            if(v0 == null) {
                v0 = Retrofit.defaultHttpExecutor;
                if(v0 == null) {
                    v0 = this.platform.defaultHttpExecutor();
                }
            }

            Executor v7 = v0;
            Executor v0_1 = this.callbackExecutor;
            if(v0_1 == null) {
                v0_1 = this.platform.defaultCallbackExecutor();
            }

            ArrayList v5 = new ArrayList(this.adapterFactories);
            v5.add(this.platform.defaultCallAdapterFactory(v0_1));

            // 构造 Retrofit 对象
            return new Retrofit(v2, this.baseUrl, new ArrayList(this.converterFactories), v5, this.interceptors, v7, v0_1, this.validateEagerly, this.cache);
        }

        throw new IllegalStateException("RawCall.Factory required.");
    }

    throw new IllegalStateException("Base URL required.");
}
```



##### Retrofit对象的源头

通过`Retrofit$Builder.build`调用栈追踪，定位到`com.sankuai.waimai.platform.capacity.network.retrofit.c.a(java.lang.Class): com.sankuai.meituan.retrofit2.Retrofit`方法

该方法传入一个interface后返回Retrofit对象。从代码上来看它是全局保存的

```java
public static Retrofit a(Class arg11) {
    // ...
    
    // 尝试从缓存中读取Retrofit对象
    q v11 = (q)c.c.get(arg11);
    if(v11 == null) {
        v11 = c.b;
    }

    // 创建Retrofit对象，最终调用到 Retrofit$Builder.build 和 Retrofit.create
    return (Retrofit)v11.c();
}
```



##### Retrofit.create

Retrofit类的create方法传入一个interface，然后为这个interface实现代理类；也就是说Retrofit已经为这个接口创建好了request，等待外部调用即可。

```java
public final Object create(Class arg13) {
    // ...

    // 校验arg13，必须是interface才行
    Utils.validateServiceInterface(arg13);
    if(this.validateEagerly) {
        // 解析 interface 中声明的method（解析注解），并为方法创建代理
        this.eagerlyValidateMethods(arg13);
    }

    // 为 interface 创建代理类，并等待外部调用
    return Proxy.newProxyInstance(arg13.getClassLoader(), new Class[]{arg13}, new InvocationHandler() {
        public static ChangeQuickRedirect changeQuickRedirect;
        public final Platform platform;
        public final Retrofit this$0;
        public final Class val$service;

        {
            Class arg2 = arg13;  // captured argument (potential naming conflict with outer method variables - use N to rename)
            this.platform = Platform.get();
        }

        @Override
        public Object invoke(Object arg12, Method arg13, Object[] arg14) throws Throwable {
            // ...

            if(arg13.getDeclaringClass() == Object.class) {
                return arg13.invoke(this, arg14);
            }

            if(this.platform.isDefaultMethod(arg13)) {
                return this.platform.invokeDefaultMethod(arg13, arg13, arg12, arg14);
            }

            // 解析 interface 中声明的 method（解析注解），并为 method 创建代理
            ServiceMethod v12 = Retrofit.this.loadServiceMethod(arg13);
            
            // 创建 ClientCall 对象并根据 method 的参数动态生成 request
            return v12.callAdapter.adapt(new ClientCall(v12, arg14, Retrofit.this.interceptors, Retrofit.defInterceptors, Retrofit.this.httpExecutor, Retrofit.this.cache));
        }
    });
}
```



##### HomePageApi interface

HomePageApi interface 是美团定义的，需要被Retrofit.create注册为动态代理类的interface，它的内部定义了一些method，当Retrofit注册完成后，就可以被外部所调用以完成request。

```java
public interface HomePageApi {
    @FormUrlEncoded
    @POST("v6/home/dynamic/tabs")
    d getDynamicTabInfo(@Field("last_time_actual_latitude") String arg1, @Field("last_time_actual_longitude") String arg2);

    @FormUrlEncoded
    @POST("v7/product/list")
    d getFoodReunionPoilist(@Field("page_index") String arg1, @Field("session_id") String arg2, @Field("rank_trace_id") String arg3, @Field("rank_list_id") String arg4, @Field("filter_tab_list") String arg5, @Field("behavioral_characteristics") String arg6, @Field("navigate_type") long arg7);

    @FormUrlEncoded
    // 通过注解定义 url
    @POST("v7/poi/homepage")
    d getHomePagePoiList(
        // getHomePagePoiList 的参数列表，当调用该参数时需要传入这些参数。
        @Field("seq_num") int arg1,
        @Field("offset") int arg2,
        @Field("dynamic_page") boolean arg3,
        @Field("page_index") long arg4,
        @Field("page_size") long arg5,
        @Field("sort_type") long arg6,
        @Field("activity_filter_codes") String arg7,
        @Field("slider_select_data") String arg8,
        @Field("load_type") int arg9,
        @Field("rank_trace_id") String arg10,
        @Field("session_id") String arg11,
        @Field("union_id") String arg12,
        @Field("rank_list_id") String arg13,
        @Field("category_type") int arg14,
        @Field("second_category_type") int arg15,
        @Field("behavioral_characteristics") String arg16
    );

    @FormUrlEncoded
    @POST("v7/product/recommend/entrance")
    d getRecommendEntrance(@FieldMap Map arg1);

    @FormUrlEncoded
    @POST("v6/poi/dynamicrecommend")
    d getRecommendPoiCard(@FieldMap Map arg1);

    @FormUrlEncoded
    @POST("v8/home/gettopbanner")
    d getTopBanner(@Field("topbanner_refresh_poi_ids") String arg1, @Field("topbanner_refresh_activity_ids") String arg2);

    @FormUrlEncoded
    @POST("v6/product/tag")
    d optimizationFeedbackReport(@Field("poi_id") long arg1, @Field("tag_type") int arg2, @Field("entry_id") int arg3, @Field("reason_type") int arg4, @Field("extend") String arg5);

    @FormUrlEncoded
    @POST("v6/product/tag")
    d tagProduct(@Field("poi_id") long arg1, @Field("spu_id") long arg2, @Field("dpc_id") long arg3, @Field("tag_type") int arg4, @Field("entry_id") int arg5, @Field("reason_type") int arg6, @Field("extend") String arg7);
}
```



#### ServiceMethod 类

ServiceMethod 类用来关联 interface method, 每个ServiceMethod对象关联一个interface method。

通过ServiceMethod$Builder.build来创建ServiceMethod 对象。ServiceMethod 记录了url，请求类型，参数个数，参数类型等等request信息；最终由ClientCall使用ServiceMethod 对象生成和发送request。

可以理解为一个interface method对应一个ServiceMethod；一个ServiceMethod对应一个request；

生成逻辑：interface method生成ServiceMethod，ServiceMethod生成request。

```java
public final ServiceMethod build() {
    Type v4;
    int v2;
    // ...

    this.callAdapter = this.createCallAdapter();
    this.responseType = this.callAdapter.responseType();
    if(this.responseType != Response.class && this.responseType != RawResponse.class) {
        this.responseConverter = this.createResponseConverter();
        Annotation[] v1 = this.methodAnnotations;
        int v3;
        for(v3 = 0; v3 < v1.length; ++v3) {
            // 解析 method 的注解，可以解析出request.method request.url, request.params等等
            this.parseMethodAnnotation(v1[v3]);
        }

        if(this.httpMethod != null) {
            if(!this.hasBody) {
                // 这个request不包含body
                if(this.isMultipart) {
                    throw this.methodError("Multipart can only be specified on HTTP methods with request body (e.g., @POST).", new Object[0]);
                }

                if(this.isFormEncoded) {
                    throw this.methodError("FormUrlEncoded can only be specified on HTTP methods with request body (e.g., @POST).", new Object[0]);
                    throw this.methodError("Multipart can only be specified on HTTP methods with request body (e.g., @POST).", new Object[0]);
                }
            }

            // request.headers
            this.parameterHandlers = new ParameterHandler[this.parameterAnnotationsArray.length];
            v2 = 0;
            goto label_58;
        }

        throw this.methodError("HTTP method annotation is required (e.g., @GET, @POST, etc.).", new Object[0]);
        while(true) {
        label_58:
            // 解析参数注解
            if(v2 >= this.parameterAnnotationsArray.length) {
                goto label_81;
            }

            v4 = this.parameterTypes[v2];
            if(Utils.hasUnresolvableType(v4)) {
                throw this.parameterError(v2, "Parameter type must not include a type variable or wildcard: %s", new Object[]{v4});
            }

            Annotation[] v3_1 = this.parameterAnnotationsArray[v2];
            if(v3_1 == null) {
                throw this.parameterError(v2, "No Retrofit annotation found.", new Object[0]);
            }

            this.parameterHandlers[v2] = this.parseParameter(v2, v4, v3_1);
            ++v2;
        }

        throw this.parameterError(v2, "No Retrofit annotation found.", new Object[0]);
        throw this.parameterError(v2, "Parameter type must not include a type variable or wildcard: %s", new Object[]{v4});
    label_81:
        if(this.relativeUrl == null && !this.gotUrl) {
            throw this.methodError("Missing either @%s URL or @Url parameter.", new Object[]{this.httpMethod});
        }

        if(!this.isFormEncoded && !this.isMultipart && !this.hasBody && (this.gotBody)) {
            throw this.methodError("Non-body HTTP method cannot contain @Body.", new Object[0]);
        }

        if((this.isFormEncoded) && !this.gotField) {
            throw this.methodError("Form-encoded method must contain at least one @Field.", new Object[0]);
        }

        if((this.isMultipart) && !this.gotPart) {
            throw this.methodError("Multipart method must contain at least one @Part.", new Object[0]);
        }

        return new ServiceMethod(this);
    }

    StringBuilder v1_1 = new StringBuilder("\'");
    v1_1.append(Utils.getRawType(this.responseType).getName());
    v1_1.append("\' is not a valid response body type. Did you mean ResponseBody?");
    throw this.methodError(v1_1.toString(), new Object[0]);
}
```



#### ClientCall 类

ClientCall对象由Retrofit生成的动态代理类创建，ClientCall用来生成okhttp.Request对象，并发送request。

如果在Retrofit + okhttp的app中，ClientCall表示为`okhttp3.RealCall`；但是美团app的核心请求没有使用okhttp框架，而是自己实现的一套`ClientCall`代码；所以美团`ClientCall`的功能对标`okhttp3.RealCall`

```java
// 构造
public ClientCall(ServiceMethod arg19, Object[] arg20, List arg21, List arg22, Executor arg23, Cache arg24) {
    // ...

    this.convertElapse = -1L;
    
    // interface method, serviceMethod
    this.serviceMethod = arg19;
    
    // request.param
    this.args = arg20;
    
    // 拦截器
    this.clientInterceptors = arg21;
    
    // 默认拦截器
    this.defInterceptors = arg22;
    
    // 发送http请求的执行器
    this.httpExecutor = arg23;
    this.cache = arg24;
}

// 执行请求，获取响应
public final Response execute() throws IOException {
    Request v2;
    // ...

    long v0 = System.currentTimeMillis();
    __monitor_enter(this);
    try {
        if(this.executed) {
            throw new IllegalStateException("Already executed.");
        }

        this.executed = true;
        if(this.creationFailure != null) {
            if((this.creationFailure instanceof IOException)) {
                throw (IOException)this.creationFailure;
            }

            throw (RuntimeException)this.creationFailure;
        }

        v2 = this.originalRequest;
        if(v2 == null) {
            try {
                // serviceMethod 生成 request
                v2 = this.serviceMethod.toRequest(this.args);
                this.originalRequest = v2;
                goto label_42;
            }
            catch(IOException | RuntimeException v0_2) {
            }

            this.creationFailure = v0_2;
            throw v0_2;
        }

    label_42:
        __monitor_exit(this);
    }
    catch(Throwable v0_1) {
        goto label_67;
    }

    try {
        // 进入拦截器链（对request进行签名，添加公共头，公共参数等等操作），发送请求，获得响应
        Response v0_4 = this.parseResponse(this.getResponseWithInterceptorChain(v2.newBuilder().addHeader("retrofit_exec_time", String.valueOf(v0)).build()));
        Retrofit.RequestCallbackDispatcher.onSuccess(this, this.realRequest, v0_4, this.convertElapse);
        return v0_4;
    }
    catch(Throwable v0_3) {
    }

    Retrofit.RequestCallbackDispatcher.onError(this, this.realRequest, v0_3);
    throw v0_3;
    try {
        throw new IllegalStateException("Already executed.");
    label_67:
        __monitor_exit(this);
    }
    catch(Throwable v0_1) {
        goto label_67;
    }

    throw v0_1;
}
```



### 总结与hook

我们现在需要调用`v7/poi/homepage`这个request，并拦截response。

首先确定这个url 属于 HomePageApi.getHomePagePoiList interface method：

```java
public interface HomePageApi {
    // ...

    @FormUrlEncoded
    @POST("v7/poi/homepage")
    d getHomePagePoiList(@Field("seq_num") int arg1, @Field("offset") int arg2, @Field("dynamic_page") boolean arg3, @Field("page_index") long arg4, @Field("page_size") long arg5, @Field("sort_type") long arg6, @Field("activity_filter_codes") String arg7, @Field("slider_select_data") String arg8, @Field("load_type") int arg9, @Field("rank_trace_id") String arg10, @Field("session_id") String arg11, @Field("union_id") String arg12, @Field("rank_list_id") String arg13, @Field("category_type") int arg14, @Field("second_category_type") int arg15, @Field("behavioral_characteristics") String arg16);

    // ...
}
```



hook `com.sankuai.waimai.platform.capacity.network.retrofit.c.a(java.lang.Class)`方法，传入需要的interface后获取到全局唯一的Retrofit对象；使Retrofit框架为HomePageApi interface注册动态代理；

```javascript
let rObject = Java.use('java.lang.Object');
let rThread = Java.use('java.lang.Thread');
let rString = Java.use('java.lang.String');
let rInteger = Java.use('java.lang.Integer');
let rBoolean = Java.use('java.lang.Boolean');
let rLong = Java.use('java.lang.Long');
let rArray = Java.use('java.lang.reflect.Array');

let rRetrofit = Java.use('com.sankuai.meituan.retrofit2.Retrofit');
let rClientCall = Java.use('com.sankuai.meituan.retrofit2.ClientCall');
let rRetrofit$Builder = Java.use('com.sankuai.meituan.retrofit2.Retrofit$Builder');

// 我们将retrofit.c类视为Retrofit的创建器，用来生成Retrofit对象
let rRetrofit$Creator = Java.use('com.sankuai.waimai.platform.capacity.network.retrofit.c');

// 我们需要注册HomePageApi这个interface
let rHomePageApi = Java.use('com.sankuai.waimai.business.page.home.net.request.HomePageApi');

// 当类中的方法出现重载时，需要通过.overload().call()的方式来调用
let retrofit = rRetrofit$Creator.a.overload('java.lang.Class').call(
    // .overload().call()的第一个参数必须时类本身，也可能时类对象本身，这个需要自己确定。
    rRetrofit$Creator,
    
    // 注册HomePageApi这个interface
    rHomePageApi.class
);
console.log(`retrofit: ${retrofit}`);

// 通过getDeclaredMethods找到 rHomePageApi.getHomePagePoiList method
let methods = rHomePageApi.class.getDeclaredMethods();
let method;
for (let i = 0; i < methods.length; i++) {
    if (methods[i].getName().indexOf('getHomePagePoiList') !== -1) {
        method = methods[i];
        console.log(`method: ${method}`);
        break;
    }
}

// 通过retrofit对象和interface method生成ServiceMethod对象
let serviceMethod = retrofit.loadServiceMethod(method);
console.log(`serviceMethod: ${serviceMethod}`);

// 构造 rHomePageApi.getHomePagePoiList 所需的参数
// 需要注意的是 frida 不能将javascrip中的类型自动转换为java中的基础数据类型。
// 例如javascript中的0和true不能自动转换到java中的int和boolean。
// 需要先Java.use数值类型，之后调用xxx.$new方法手动构造
// javascript中的字符串类型可以直接转到java中的java.lang.String类型，所以不需要手动构造
let params = Java.array('java.lang.Object', [
    rInteger.$new(0),
    rInteger.$new(0),
    rBoolean.$new(true),
    rInteger.$new(0),
    rInteger.$new(20),
    rInteger.$new(0),
    "",
    "",
    rInteger.$new(1),
    "",
    '1884e2f6-0fd6-4254-9555-9e701faf1a771604177571387562',
    '77c5243a18ca439c9e3eb05ee894707ea159474625289990347',
    '9a44b234332e43a69a6bb06d6de1863a',
    rInteger.$new(0),
    rInteger.$new(0),
    ''
]);
console.log(`ary: ${params}, ary.length: ${params.length}`);

// 构造ClientCall对象
let call = rClientCall.$new(serviceMethod, params, retrofit.interceptors.value, retrofit.defInterceptors.value, retrofit.httpExecutor.value, retrofit.cache.value);
console.log(`call: ${call}`);

// 调用ClientCall.execute 执行request并获取response。
let response = call.execute();
console.log(`response: ${response}`);
```


