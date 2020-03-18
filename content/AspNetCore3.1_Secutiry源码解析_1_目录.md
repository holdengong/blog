---
title: "AspNetCore3.1_Secutiry源码解析_1_目录"
date: 2020-03-17T23:01:38+08:00
draft: false
---
# 系列文章目录
- [AspNetCore3.1_Secutiry源码解析_1_目录](https://holdengong.com/aspnetcore3.1_secutiry源码解析_1_目录)
- [AspNetCore3.1_Secutiry源码解析_2_Authentication_核心流程](https://holdengong.com/aspnetcore3.1_secutiry源码解析_2_authentication_核心流程)
- AspNetCore3.1_Secutiry源码解析_3_Authentication_Cookies
- AspNetCore3.1_Secutiry源码解析_4_Authentication_JwtBear
- AspNetCore3.1_Secutiry源码解析_5_Authentication_OAuth
- AspNetCore3.1_Secutiry源码解析_6_Authentication_OpenIdConnect
- AspNetCore3.1_Secutiry源码解析_7_Authentication_其他
- AspNetCore3.1_Secutiry源码解析_8_Authorization_核心项目
- AspNetCore3.1_Secutiry源码解析_9_Authorization_Policy

# 概述
最近一直在学习研究认证授权这一块，从AspNetCore的Security解决方案，到Identity，再到OAuth2.0、OpenIdConnect协议，然后IdentityServer4，这一块的东西十分多而且复杂，可以算是DotNet里最难啃的骨头之一了。计划做个认证授权的系列，藉由分析源码来学习、记录和加深对这一块的理解。

如图是AspNetCore.Security解决方案的项目结构。

可以看到主要有5个解决方案文件夹
- Authentication：认证
- Authorization：授权
- CookiePolicy：Cookie策略中间件
- _dependencies：依赖项目
- benchmarks：测试项目

最主要的是Authentication和Authorization这两个里面的内容。

![image](https://fs.31huiyi.com/08b5ab04-13a0-46a4-bd71-5ae61185c27e.png)

# 什么是Authentication， 什么是Authorization
初次接触这一块，可能会比较懵，啥玩意儿啊，俩单词长得差不多像念绕口令的。

我尝试大白话解释下。

Authentication（认证）：***who are you***。系统获知当前用户身份的过程就叫认证。可以类比成身份证。通常来说，在你登录的时候，系统就知道了你的身份，然后将当前用户信息加密后存储在Cookie中来维持登录态。

Authorization（授权）：***are you allowed***。授权就是判断你有没有权限，比如网管拿着你身份证一看，你这不行，未满十八岁，不能在我这上网。而有的黑网吧是没有这个要求的，给钱就能玩。正经网吧和黑网吧，这就是需要授权资源和匿名资源的区别。

# Authentication项目简介
我们可以看到第三个文件夹叫Core，里面只有一个项目叫Microsoft.AspNetCore.Authentication，是我们使用DotNet授权框架必须引用的一个核心类库。

然后其他的Certificate、Cookies、OAuth、OpenIdConnect等这些，在DotNet里叫做Schema，可以翻译为架构。这就好比，证明身份的方式有很多种，身份证、护照、户口本都可以，同理网络世界也有各种各样的协议。最常见传统的是方式是使用Cookie，也可以使用无状态的JwtBear，现在常见的微信、QQ等扫码登录是使用的OAuth协议。

# Authorization项目简介
授权就两个项目，[Microsoft.AspNetCore.Authorization.Policy],[Microsoft.AspNetCore.Authorization]。多看看源码的话，应该对Policy这个词很熟悉了，在DotNet里面属于高频词汇，意思是策略。这两个项目允许设置不同的授权策略/规则，来实现高度灵活的授权方案。




