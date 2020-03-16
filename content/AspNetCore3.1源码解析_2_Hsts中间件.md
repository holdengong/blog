---
title: "AspNetCore3.1源码解析_2_Hsts中间件"
date: 2020-03-16T12:40:46+08:00
draft: false
---
# 概述
在DotNetCore2.2版本中，当你新增一个WebAPI项目，生成项目模板，Startup.cs文件中，会有这么一行代码（3.1版本默认没有使用该中间件）。
```csharp
if (env.IsDevelopment())
{
    app.UseDeveloperExceptionPage();
}
else
{
    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    app.UseHsts();
}
```

这段代码，翻译一下就是开发环境使用开发异常页面，其他环境使用Hsts中间件。这个Hsts中间件是个什么东西呢，今天来看一看。

# HSTS是什么
HTTP严格传输安全协议（英语：HTTP Strict Transport Security，简称：HSTS）。
> https://baike.baidu.com/item/HTTP%E4%B8%A5%E6%A0%BC%E4%BC%A0%E8%BE%93%E5%AE%89%E5%85%A8%E5%8D%8F%E8%AE%AE/16018283?fromtitle=HSTS&fromid=8665782&fr=aladdin

> https://developer.mozilla.org/zh-CN/docs/Security/HTTP_Strict_Transport_Security

> https://tools.ietf.org/html/rfc6797

简单描述一下协议内容，就是出于安全考虑，强制客户端使用https与服务端链接。

为什么要这么做呢，比较学术的论述自行查看上面的链接？我这里举个通俗的栗子。

首先我们知道http不安全，而https是安全的，他能保障你访问的A网站就是A，而不是什么其他的野鸡。

某一天，你去逛淘宝，你往chrome地址栏敲 taobao.com，正常情况下岁月静好，什么问题都没有。假如，这时候你接入的是公共免费wifi，而这背后有人搞鬼，他可以将你跳转到一个跟taobao一模一样的网站 *(怎么做到的？比如修改你的host文件，将taobao域名指向他的私人ip)*，浏览器并不知道taobao需要使用https访问，所以无法保护你，你的钱就在你的鼠标点击下，跟随着一个个http请求流入到了黑客的账户。

那要怎么办呢，不上公共wifi行不行，行，但是防不胜防，不是根本的办法。 那我们告诉浏览器taobao需要用https访问行不行，听起来不错，那怎么告诉呢，我们来搞个协议，这个协议就是HSTS。

一句话描述HTST：当你首次使用https访问了taobao后，taobao会返回Strict-Transport-Security头，表名我这个网站需要使用https访问，浏览器记录下这个信息，以后taobao的请求都会使用https，因此堵住了上面案例的安全漏洞。

# HSTS中间件的使用
通常，我们不需要写Hsts的注入代码，因为它没有任何需要注入的服务。除非你需要修改它的默认配置。
```csharp
services.AddHsts(config =>
{
    //是否包含子域名，默认false
    config.IncludeSubDomains = true;

    //有效时长，默认30天
    config.MaxAge = TimeSpan.FromDays(365);
});
```

然后，使用中间件即可。
```
app.UseHsts();
```

***注意：Hsts协议只对https站点有效，如果你的站点是http的，不会报错也不会生效，使用Hsts的代码可以删掉***

# 源码解析
Hsts的源代码比较简单，只有两个类：HstsOptions配置类和HstsMiddleware中间件。

我们先看看HstsOptions，可以看到就是一个普通配置类，定义了默认时长是30天，然后IncludeSubDomains和Preload都是默认false，然后设置ExcludedHosts，排除了本地地址。
<details>
<summary>
点击查看HstsOptions源代码
</summary>

```csharp
/// <summary>
/// Options for the Hsts Middleware
/// </summary>
public class HstsOptions
{
    /// <summary>
    /// Sets the max-age parameter of the Strict-Transport-Security header.
    /// </summary>
    /// <remarks>
    /// Max-age is required; defaults to 30 days.
    /// See: https://tools.ietf.org/html/rfc6797#section-6.1.1
    /// </remarks>
    public TimeSpan MaxAge { get; set; } = TimeSpan.FromDays(30);

    /// <summary>
    /// Enables includeSubDomain parameter of the Strict-Transport-Security header.
    /// </summary>
    /// <remarks>
    /// See: https://tools.ietf.org/html/rfc6797#section-6.1.2
    /// </remarks>
    public bool IncludeSubDomains { get; set; }

    /// <summary>
    /// Sets the preload parameter of the Strict-Transport-Security header.
    /// </summary>
    /// <remarks>
    /// Preload is not part of the RFC specification, but is supported by web browsers
    /// to preload HSTS sites on fresh install. See https://hstspreload.org/.
    /// </remarks>
    public bool Preload { get; set; }

    /// <summary>
    /// A list of host names that will not add the HSTS header.
    /// </summary>
    public IList<string> ExcludedHosts { get; } = new List<string>
    {
        "localhost",
        "127.0.0.1", // ipv4
        "[::1]" // ipv6
    };
```
</details>

然后我们看看中间件的代码，也十分简单。首先判断是不是https请求，不是的话直接跳过本中间件；然后判断是否在除外域名配置中，是的话也跳过。然后就是根据HstsOptions的配置拼装内容，然后写入http的响应头中。

[点击查看原文地址](https://holdengong.com/aspnetcore3.1%E6%BA%90%E7%A0%81%E8%A7%A3%E6%9E%90_1_cors%E4%B8%AD%E9%97%B4%E4%BB%B6/)

<details>
<summary>
点击查看HSTS中间件源代码
</summary>

```csharp
public class HstsMiddleware
{
    private const string IncludeSubDomains = "; includeSubDomains";
    private const string Preload = "; preload";

    private readonly RequestDelegate _next;
    private readonly StringValues _strictTransportSecurityValue;
    private readonly IList<string> _excludedHosts;
    private readonly ILogger _logger;

    /// <summary>
    /// Initialize the HSTS middleware.
    /// </summary>
    /// <param name="next"></param>
    /// <param name="options"></param>
    /// <param name="loggerFactory"></param>
    public HstsMiddleware(RequestDelegate next, IOptions<HstsOptions> options, ILoggerFactory loggerFactory)
    {
        if (options == null)
        {
            throw new ArgumentNullException(nameof(options));
        }

        _next = next ?? throw new ArgumentNullException(nameof(next));

        var hstsOptions = options.Value;
        var maxAge = Convert.ToInt64(Math.Floor(hstsOptions.MaxAge.TotalSeconds))
                        .ToString(CultureInfo.InvariantCulture);
        var includeSubdomains = hstsOptions.IncludeSubDomains ? IncludeSubDomains : StringSegment.Empty;
        var preload = hstsOptions.Preload ? Preload : StringSegment.Empty;
        _strictTransportSecurityValue = new StringValues($"max-age={maxAge}{includeSubdomains}{preload}");
        _excludedHosts = hstsOptions.ExcludedHosts;
        _logger = loggerFactory.CreateLogger<HstsMiddleware>();
    }

    /// <summary>
    /// Initialize the HSTS middleware.
    /// </summary>
    /// <param name="next"></param>
    /// <param name="options"></param>
    public HstsMiddleware(RequestDelegate next, IOptions<HstsOptions> options)
        : this(next, options, NullLoggerFactory.Instance) { }

    /// <summary>
    /// Invoke the middleware.
    /// </summary>
    /// <param name="context">The <see cref="HttpContext"/>.</param>
    /// <returns></returns>
    public Task Invoke(HttpContext context)
    {
        if (!context.Request.IsHttps)
        {
            _logger.SkippingInsecure();
            return _next(context);
        }

        if (IsHostExcluded(context.Request.Host.Host))
        {
            _logger.SkippingExcludedHost(context.Request.Host.Host);
            return _next(context);
        }

        context.Response.Headers[HeaderNames.StrictTransportSecurity] = _strictTransportSecurityValue;
        _logger.AddingHstsHeader();

        return _next(context);
    }

    private bool IsHostExcluded(string host)
    {
        if (_excludedHosts == null)
        {
            return false;
        }

        for (var i = 0; i < _excludedHosts.Count; i++)
        {
            if (string.Equals(host, _excludedHosts[i], StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }
        return false;
    }
```
</details>


[点击查看原文地址](https://holdengong.com/aspnetcore3.1%E6%BA%90%E7%A0%81%E8%A7%A3%E6%9E%90_1_cors%E4%B8%AD%E9%97%B4%E4%BB%B6/)