---
title: "AspNetCore3.1_Middleware源码解析_4_StaticFiles"
date: 2020-03-16T21:59:17+08:00
draft: false
---

# 概述
AspNetCore提供了StaticFiles中间件，使我们可以轻松访问静态文件。

# 使用方法

AspNetCore提供了三个重载方法，没有特殊需求的情况下，我们使用无参的就可以了。

```csharp
//使用默认配置
app.UseStaticFiles();

//自定义静态资源相对路径
app.UseStaticFiles("/MyCustomStaticFilePath");

//所有可以配置的选项
app.UseStaticFiles(new StaticFileOptions
{
    //用于映射file的content-type
    ContentTypeProvider = null,
    //ContentTypeProvider无法决定content-type时的默认content-type
    DefaultContentType = null,
    //文件提供程序
    FileProvider = new PhysicalFileProvider("/"),
    //Https请求，ResponseCompression中间件启用的情况下，是否对返回值压缩
    HttpsCompression = Microsoft.AspNetCore.Http.Features.HttpsCompressionMode.Compress,
    //委托，状态码和Headers设置完，Body写入前触发，可用于修改响应头
    OnPrepareResponse = null,
    //映射静态资源的相对路径
    RequestPath = "/MyStaticFiles",
    //是否伺服未知文件类型
    ServeUnknownFileTypes = false
});
```

TO BE CONTINUE...


