---
title: "EasyAuthentication项目规划"
date: 2020-03-30T22:44:43+08:00
draft: true
---
# 项目介绍
AspNetCore提供了功能丰富，扩展性良好的认证授权框架，再搭配开源项目IdentityServer4，基本上绝大部分功能可以满足。但是这一套东西，要完全掌握真的不是十分容易的事情。从`Claim`,`Principle`,`Jwt`这些概念，到`OAuth2.0`,`OpenIdConnect`各种协议，还有`IdentityServer4`各种授权流程的实现，真的是头都大了。  

EasyAuth项目提供一个开箱即用认证授权轻量级包，只需要两行代码就可使用，大部分功能修改配置即可。

EasyAuth提供了下面的功能
- 提供单体架构、分布式认证中心模式
- 单点登录
- 单点登出

# 快速开始

# 配置项
- EasyAuthOptions
  - AuthMode：认证服务模式
    - Single：单体架构模式（默认值）
    - AuthCenter：认证中心模式
  - ApplicationType
    - Mvc：Mvc应用，前后端同域，将使用cookie来维持登录态（默认值）
    - Spa：单页应用，前端后分离，属于不同域名，需要前端用LocalStorage自行维护token
  - TokenType
    - Jwt：JsonWebToken，一种自包含的数据格式（默认值）
    - ReferenceToken：token的唯一标识，更短更安全
  - AccessTokenLifeTime：token有效时长，单位秒（默认7200，即2小时）
  - UseRefreshToken：是否使用刷新令牌，AccessToken到期之后自动刷新，避免AccessToken有效期太长不安全的同时，用户不用频繁登录，提供较好的使用体验（默认是）
  - RefreshTokenLifeTime：refreshToken有效时长，单位秒（默认2592000，即1个月）
  - SessonMode：维持会话模式，仅在Mvc模式时生效
    - FinishWhenBrowserClosed：当浏览器关闭时结束会话，下次需要重新登录（默认值）
    - FinishWhenTokenExpired：当Token过期且刷新Token失败才会需要重新登录

# 接口定义
- IEasyAuthService
  - GetTokenAsync 
  - GetUserInfoAsync
  - 


