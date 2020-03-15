---
title: "AspNetCore源码解析_1_CORS中间件"
date: 2020-03-15T17:26:10+08:00
draft: false
---
# 概述
## 什么是跨域
在前后端分离开发方式中，跨域是我们经常会遇到的问题。所谓的跨域，就是处于安全考虑，A域名向B域名发出Ajax请求，浏览器会拒绝，抛出类似下图的错误。

![image](https://fs.31huiyi.com/2c239b54-ad37-4680-bd95-7f76b656be0d.png)

## JSONP
JSONP不是标准跨域协议，更像是聪明程序员投机取巧的办法。这种方式的原理就是js是没有跨域限制的，你想想你引用bootstrap.js是不是网络地址放进来就可以用了。  
**实际上，所有src属性都不限制跨域的，比如img标签使用跨域图片是不会有问题的。**

过程大体分下面四步。
- 首先约定数据格式和回调函数名
- A网站引用B网站的js
- B网站用约定好的回调函数将数据包裹起来，在A引用的js里返回
- A网站在回调函数中获取数据

这个方案的优点是兼容性比较好，很古老的ie都可以支持，毕竟只是基于js的一个技巧，并没有新的技术或协议。  
缺点比较明显，只支持GET，理解起来比较别扭，调用失败不会返回http状态码，安全性存在一定问题。

## CORS
CORS的全称是Cross Origin Resource Sharing，翻译过来就是跨域资源共享。    

跨域问题本质就是浏览器处于安全考虑，阻止了客户端跨域请求。但说到底，客户端请求安不安全还不是服务端说了算的，服务端都说我们家大米你们随便吃，浏览器还阻止，这不是碍事吗，你个物业还当自己业主啦？  

但是浏览器也不能随便放行，毕竟网上冲浪的不仅有正经客人，还有小偷，真出问题了还得吐槽物业稀烂。浏览器说，服务端，这个客户端要去你家吃大米，你得告诉我你同不同意啊，服务端说我咋告诉你啊，我总不能来个人就冲着岗亭喊 I'M OK吧。浏览器说那我们搞个协议吧，整个互联网小区都按这个规范来，你们就按这个格式回复我。

这个协议就是CORS了。

<div class="mermaid">
graph LR;
    A(客户端)-->B(不带Orgin跨域请求);
    B-->C(浏览器拒绝);
    A-->D(带Origin跨域请求);
    D-->E(服务端返回白名单);
    E-->F(白名单内);
    E-->G(白名单外);
    F-->H(浏览器放行);
    G-->C
</div>
<script src="https://unpkg.com/mermaid/dist/mermaid.min.js"></script>

CORS的缺点就是IE10以下不支持，如果你的项目需要兼容这些浏览器的话需要注意。

关于CORS协议详细的内容看这篇文章
> http://www.ruanyifeng.com/blog/2016/04/cors.html

## 怎么实现CORS
CORS说白了其实就是在响应头里加东西，你可以在运维环节比如nginx加，可以在代码里加，常见的做法是中间件统一处理。AspNetCore为我们提供了CORS中间件。

## AspNetCore_CORS中间件的使用
使用CORS中间件两句代码就够了,在Startup文件中
```csharp

//注入CORS相关的服务，配置跨域策略 [CorsPolicy]
public void ConfigureServices(IServiceCollection services)
{
    //策略1，允许所有域名跨域访问
    config.AddPolicy("policy1", policy => {
                    policy.AllowAnyOrigin().
                        AllowAnyMethod().
                        AllowAnyOrigin().
                        AllowAnyMethod();
                        //注意：AllowAnyOrigin和AllowCredential不能同时出现，否则会报错
                        //AllowCredential即是否允许客户端发送cookie，基于安全原因，CORS协议规定不允许AllowOrigin为通配符的情况下设置允许发送cookie
                        //.AllowCredentials();
                });

    //策略2，仅允许特定域名、方法、请求头访问
    config.AddPolicy("policy2",policy=> {
        //只允许https://www.holdengong.com跨域访问
        policy.WithOrigins("https://www.holdengong.com")
        //只允许get,post方法
        .WithMethods("get", "post")
        //请求头中只允许有Authorization
        .WithHeaders("Authorization")
        //对于复杂请求，浏览器会首先发送预检请求(OPTIONS),服务端返回204，并在响应头中返回跨域设置
        //此处可以设置预检请求的有效时长，即30分钟内不会再检查是否允许跨域
        .SetPreflightMaxAge(TimeSpan.FromMinutes(30));
    });
}

//使用CORS中间件, 指定使用CorsPolicy
public void Configure(IApplicationBuilder app)
{
    app.UseCors("CorsPolicy");
}
```

**注意：AllowAnyOrigin和AllowCredential不能同时配置，否则会报错。如果要允许客户端发送cookie的话，只能使用WithOrgin来执行允许跨域白名单**

微软使用的策略设计模式，方便我们灵活使用跨域策略。比如，开发环境允许localhost跨域访问，方便开发调试，正式环境只允许指定域名访问。

## 源码解析
### 核心对象
```csharp
services.TryAdd(ServiceDescriptor.Transient<ICorsService, CorsService>());

services.TryAdd(ServiceDescriptor.Transient<ICorsPolicyProvider, DefaultCorsPolicyProvider>());

services.Configure(setupAction);
```

- CorsOptions：主要定义了字典PolicyMap，键是策略名称，值是跨域策略。用户可以在注入的时候往这个对象里面加跨域策略。然后提供了一些新增策略的操作方法。

```csharp
// DefaultCorsPolicyProvider returns a Task<CorsPolicy>. We'll cache the value to be returned alongside
// the actual policy instance to have a separate lookup.
internal IDictionary<string, (CorsPolicy policy, Task<CorsPolicy> policyTask)> PolicyMap { get; }
    = new Dictionary<string, (CorsPolicy, Task<CorsPolicy>)>(StringComparer.Ordinal);
```

- ICorsService：有两个方法，EvaluatePolicy--评估策略，主要做一些校验、记录日志和分流预检请求和真实请求的工作； PopulateResult--执行策略，将结果填充到CorsResult对象中。

- ICorsPolicyProvider: 有一个方法，GetPolicyAsync--根据policyName取出跨域策略。

### 中间件
```
CorsMiddleware
```

首先，中间件会判断方法节点是否有实现以下两个接口，如果有的话优先执行节点设置。
```
IDisableCorsAttribute: 禁用跨域
ICorsPolicyMetadata：使用指定跨域策略
```

然后，然后判断请求头是否有Origin，没有的话直接略过CORS中间件去下游管道。
```csharp
if (!context.Request.Headers.ContainsKey(CorsConstants.Origin))
{
return _next(context);
}
```

然后，中间件执行ICorsService的ApplyResult方法，将跨域策略写到响应头中。

原文地址：[holdengong.com](https://holdengong.com)