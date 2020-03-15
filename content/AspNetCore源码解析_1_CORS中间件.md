---
title: "AspNetCore源码解析_1_CORS中间件"
date: 2020-03-15T17:26:10+08:00
draft: false
---
# 概述
## 什么是跨域
在前后端分离开发方式中，跨域是我们经常会遇到的问题。所谓的跨域，就是A域名向B域名发出Ajax请求，浏览器会拒绝，抛出类似下图的错误。

![image](https://fs.31huiyi.com/2c239b54-ad37-4680-bd95-7f76b656be0d.png)

## JSONP
JSONP不是标准跨域协议，更像是聪明的程序员钻空子来解决问题的技巧。这种方式的原理就是js是没有跨域限制的，你想想你引用bootstrap.js是不是网络地址放进来就可以用了。这个过程大体分下面四步。
- 首先约定数据格式和回调函数名
- A网站引用B网站的js
- B网站用约定好的回调函数将数据包裹起来，在A引用的js里返回
- A网站在回调函数中获取数据

这个方案的优点是兼容性比较好，很古老的ie都可以支持，毕竟只是基于js的一个技巧，并没有新的技术或协议。  
缺点比较明显，只支持GET，理解起来比较困难，调用失败不会返回http状态码，安全性存在一定问题。

## CORS
CORS的全称是Cross Origin Resource Sharing，简单翻译就是跨域资源共享。    

跨域问题出现的根源就是浏览器为了安全阻止了跨域请求，但说到底，安不安全还不是服务端说了算的，服务端都说我们家大米你们随便池，浏览器还阻止这不是碍事吗。  

但是浏览器也不能随便放行，浏览器说，服务端，这个客户端要吃你家大米，你得告诉我你同不同意啊，服务端说我咋告诉你啊，我又不知道你家电话号码，浏览器说那我们搞个协议吧，你就按这个格式告诉我。

这个协议就是CORS了。

CORS一句话来说就是客户端申请跨域访问，头里带个Origin，浏览器一看你来自xxx，要去吃别人家大米，我问问服务端，然后服务端返回头里带个Access-Control-Allow-Origin，就是允许吃我家大米的名单，浏览器对比之后阻止或者放行。这是简单请求的一个处理流程，协议还规定了请求方式、是否允许带cookie、请求头等约束。

CORS的缺点就是ie10以下不支持，如果你的项目需要兼容这些浏览器的话需要注意。

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
    services.AddCors(config=> {
                config.AddPolicy("CorsPolicy", policy => {
                    policy.AllowAnyOrigin().
                        AllowAnyMethod().
                        AllowAnyOrigin().
                        AllowAnyMethod();
                        /*注意：AllowAnyOrigin和AllowCredential不能同时出现.否则会报错AllowCredential即是否允许客户端发送cookie，基于安全原因，CORS协议规定不允许AllowOrigin为通配符的情况下设置允许发送cookie
                        .AllowCredentials();*/
                });
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



