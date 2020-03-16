---
title: "AspNetCore3"
date: 2020-03-16T18:20:41+08:00
draft: false
---

# 概述
上文提到3.1版本默认没有使用Hsts，但是使用了这个中间件。看名字就很好理解，https跳转，顾名思义，就是跳转到
https地址。

使用场景，当用户使用http访问网站时，自动跳转到https地址。这样更加安全，不需要用户特意输入https://协议。

具体做了些我们一起来看看。

```csharp
  app.UseHttpsRedirection();
```

# 使用方法
跟Hsts一样，HttpsRedirection默认是不需要注入的，除非你需要修改默认配置。
```csharp
services.AddHttpsRedirection(config =>
  {
      //https地址的端口号，默认null
      config.HttpsPort = 12345;

      //跳转响应的状态码，默认307
      config.RedirectStatusCode = 302;
  });
```

直接使用中间件即可
```csharp
 app.UseHttpsRedirection();
```

# 源码解析
源代码很简单，只有两个类：HttpsRedirectionOptions配置类，HttpsRedirectionMiddleware中间件

HttpsRedirectionOptions就只有两个配置项

```csharp
  /// <summary>
  /// Options for the HttpsRedirection middleware
  /// </summary>
  public class HttpsRedirectionOptions
  {
      /// <summary>
      /// The status code used for the redirect response. The default is 307.
      /// </summary>
      public int RedirectStatusCode { get; set; } = StatusCodes.Status307TemporaryRedirect;

      /// <summary>
      /// The HTTPS port to be added to the redirected URL.
      /// </summary>
      /// <remarks>
      /// If the HttpsPort is not set, we will try to get the HttpsPort from the following:
      /// 1. HTTPS_PORT environment variable
      /// 2. IServerAddressesFeature
      /// If that fails then the middleware will log a warning and turn off.
      /// </remarks>
      public int? HttpsPort { get; set; }
  }
```

重点看下中间件做了些什么。代码量很少，大体是这些逻辑。
- 如果请求是Https，跳过本中间件
- 中间件会依次尝试从这三个地方取端口号：HttpsRedirectionOptions的配置，HttpsRedirectionOptions，HTTPS_PORT环境变量或配置，IServerAddressesFeature(*如果Webhost上绑定了https地址，本中间件能够解析出来端口号*)。
- 如果没有解析出来https的端口号，则跳过本中间件。
- 如果能够解析出来https端口号，则拼接出来https地址，返回307跳转响应报文（或者配置的其他状态码）。

***注：3.1同时支持HTTPS_PORT和ANCM_HTTPS_PORT这两个环境变量。***
![image](https://fs.31huiyi.com/782a3141-0f34-4631-bf5b-196b09d1e9a6.png)
> https://docs.microsoft.com/en-us/dotnet/core/compatibility/2.2-3.0


<details>
<summary>
点击查看HttpsRedirectionMiddleware源代码
</summary>

```csharp
public class HttpsRedirectionMiddleware
    {
        private const int PortNotFound = -1;

        private readonly RequestDelegate _next;
        private readonly Lazy<int> _httpsPort;
        private readonly int _statusCode;

        private readonly IServerAddressesFeature _serverAddressesFeature;
        private readonly IConfiguration _config;
        private readonly ILogger _logger;

        /// <summary>
        /// Initializes the HttpsRedirectionMiddleware
        /// </summary>
        /// <param name="next"></param>
        /// <param name="options"></param>
        /// <param name="config"></param>
        /// <param name="loggerFactory"></param>
        public HttpsRedirectionMiddleware(RequestDelegate next, IOptions<HttpsRedirectionOptions> options, IConfiguration config, ILoggerFactory loggerFactory)

        {
            _next = next ?? throw new ArgumentNullException(nameof(next));
            _config = config ?? throw new ArgumentNullException(nameof(config));

            if (options == null)
            {
                throw new ArgumentNullException(nameof(options));
            }
            var httpsRedirectionOptions = options.Value;
            if (httpsRedirectionOptions.HttpsPort.HasValue)
            {
                _httpsPort = new Lazy<int>(() => httpsRedirectionOptions.HttpsPort.Value);
            }
            else
            {
                _httpsPort = new Lazy<int>(TryGetHttpsPort);
            }
            _statusCode = httpsRedirectionOptions.RedirectStatusCode;
            _logger = loggerFactory.CreateLogger<HttpsRedirectionMiddleware>();
        }

        /// <summary>
        /// Initializes the HttpsRedirectionMiddleware
        /// </summary>
        /// <param name="next"></param>
        /// <param name="options"></param>
        /// <param name="config"></param>
        /// <param name="loggerFactory"></param>
        /// <param name="serverAddressesFeature">The</param>
        public HttpsRedirectionMiddleware(RequestDelegate next, IOptions<HttpsRedirectionOptions> options, IConfiguration config, ILoggerFactory loggerFactory,
            IServerAddressesFeature serverAddressesFeature)
            : this(next, options, config, loggerFactory)
        {
            _serverAddressesFeature = serverAddressesFeature ?? throw new ArgumentNullException(nameof(serverAddressesFeature));
        }

        /// <summary>
        /// Invokes the HttpsRedirectionMiddleware
        /// </summary>
        /// <param name="context"></param>
        /// <returns></returns>
        public Task Invoke(HttpContext context)
        {
            if (context.Request.IsHttps)
            {
                return _next(context);
            }

            var port = _httpsPort.Value;
            if (port == PortNotFound)
            {
                return _next(context);
            }

            var host = context.Request.Host;
            if (port != 443)
            {
                host = new HostString(host.Host, port);
            }
            else
            {
                host = new HostString(host.Host);
            }

            var request = context.Request;
            var redirectUrl = UriHelper.BuildAbsolute(
                "https", 
                host,
                request.PathBase,
                request.Path,
                request.QueryString);

            context.Response.StatusCode = _statusCode;
            context.Response.Headers[HeaderNames.Location] = redirectUrl;

            _logger.RedirectingToHttps(redirectUrl);

            return Task.CompletedTask;
        }

        //  Returns PortNotFound (-1) if we were unable to determine the port.
        private int TryGetHttpsPort()
        {
            // The IServerAddressesFeature will not be ready until the middleware is Invoked,
            // Order for finding the HTTPS port:
            // 1. Set in the HttpsRedirectionOptions
            // 2. HTTPS_PORT environment variable
            // 3. IServerAddressesFeature
            // 4. Fail if not sets

            var nullablePort = _config.GetValue<int?>("HTTPS_PORT") ?? _config.GetValue<int?>("ANCM_HTTPS_PORT");
            if (nullablePort.HasValue)
            {
                var port = nullablePort.Value;
                _logger.PortLoadedFromConfig(port);
                return port;
            }

            if (_serverAddressesFeature == null)
            {
                _logger.FailedToDeterminePort();
                return PortNotFound;
            }

            foreach (var address in _serverAddressesFeature.Addresses)
            {
                var bindingAddress = BindingAddress.Parse(address);
                if (bindingAddress.Scheme.Equals("https", StringComparison.OrdinalIgnoreCase))
                {
                    // If we find multiple different https ports specified, throw
                    if (nullablePort.HasValue && nullablePort != bindingAddress.Port)
                    {
                        _logger.FailedMultiplePorts();
                        return PortNotFound;
                    }
                    else
                    {
                        nullablePort = bindingAddress.Port;
                    }
                }
            }

            if (nullablePort.HasValue)
            {
                var port = nullablePort.Value;
                _logger.PortFromServer(port);
                return port;
            }

            _logger.FailedToDeterminePort();
            return PortNotFound;
        }
    }
```
</details>

---
OK，完成了。