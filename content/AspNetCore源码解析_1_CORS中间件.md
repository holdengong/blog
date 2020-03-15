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
<script async src="https://unpkg.com/mermaid@8.2.3/dist/mermaid.min.js"></script>

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



