---
title: "AspNetCore3.1_Secutiry源码解析_4_Authentication_JwtBear"
date: 2020-03-22T16:29:29+08:00
draft: false
---
# 系列文章目录
- [AspNetCore3.1_Secutiry源码解析_1_目录](https://holdengong.com/aspnetcore3.1_secutiry源码解析_1_目录)
- [AspNetCore3.1_Secutiry源码解析_2_Authentication_核心流程](https://holdengong.com/aspnetcore3.1_secutiry源码解析_2_authentication_核心流程)
- [AspNetCore3.1_Secutiry源码解析_3_Authentication_Cookies](https://holdengong.com/aspnetcore3.1_secutiry源码解析_3_authentication_cookies)
- [AspNetCore3.1_Secutiry源码解析_4_Authentication_JwtBear](https://holdengong.com/aspnetcore3.1_secutiry源码解析_4_authentication_jwtbear)
- [AspNetCore3.1_Secutiry源码解析_5_Authentication_OAuth](https://holdengong.com/aspnetcore3.1_secutiry源码解析_5_authentication_oauth)
- [AspNetCore3.1_Secutiry源码解析_6_Authentication_OpenIdConnect](https://holdengong.com/aspnetcore3.1_secutiry源码解析_6_authentication_openidconnect)
- [AspNetCore3.1_Secutiry源码解析_7_Authentication_其他](https://holdengong.com/aspnetcore3.1_secutiry源码解析_7_authentication_其他)
- AspNetCore3.1_Secutiry源码解析_8_Authorization_核心项目
- AspNetCore3.1_Secutiry源码解析_9_Authorization_Policy

# JwtBear简介

首先回想一下Cookie认证，Cookie认证在用户登录成功之后将用户信息加密后写入浏览器Cookie中，服务端通过解析Cookie内容来验证用户登录状态。这样做有几个缺陷：
- Cookie加密方式是微软自己定义的，并非国际标准，其他语言无法识别。
- 依赖Cookie，在跨域场景下，存在诸多限制。
  - CORS除非设置白名单否则是不允许带Cookie的；
  - 大部分浏览器对跨域设置Cookie有严格的限制。比如：A网站使用iframe嵌套B网站来实现集成，B网站依赖Cookie来维持登录态，如果是Chrome浏览器，需要将Cookie的Secure设置为true，即必须使用https，同时将SameSite设置为None，这样可以解决问题但是存在跨站访问攻击（CSRF）的安全漏洞，而Safari则是完全禁止设置跨站Cookie的）

JwtBear可以解决上面的缺点
- Jwt是国际标准
- Jwt不依赖Cookie，不存在跨站访问攻击问题

# 依赖注入

提供了四个重载方法，主要设置配置类 JwtBearerOptions。
默认添加名称为Bearer的认证Schema，JwtBearerHandler为处理器类。

```csharp
  public static class JwtBearerExtensions
    {
        public static AuthenticationBuilder AddJwtBearer(this AuthenticationBuilder builder)
            => builder.AddJwtBearer(JwtBearerDefaults.AuthenticationScheme, _ => { });

        public static AuthenticationBuilder AddJwtBearer(this AuthenticationBuilder builder, Action<JwtBearerOptions> configureOptions)
            => builder.AddJwtBearer(JwtBearerDefaults.AuthenticationScheme, configureOptions);

        public static AuthenticationBuilder AddJwtBearer(this AuthenticationBuilder builder, string authenticationScheme, Action<JwtBearerOptions> configureOptions)
            => builder.AddJwtBearer(authenticationScheme, displayName: null, configureOptions: configureOptions);

        public static AuthenticationBuilder AddJwtBearer(this AuthenticationBuilder builder, string authenticationScheme, string displayName, Action<JwtBearerOptions> configureOptions)
        {
            builder.Services.TryAddEnumerable(ServiceDescriptor.Singleton<IPostConfigureOptions<JwtBearerOptions>, JwtBearerPostConfigureOptions>());
            return builder.AddScheme<JwtBearerOptions, JwtBearerHandler>(authenticationScheme, displayName, configureOptions);
        }
    }
```
通常来说用默认配置就够了。

```csharp
    public class JwtBearerOptions : AuthenticationSchemeOptions
    {
        /// <summary>
        /// Gets or sets if HTTPS is required for the metadata address or authority.
        /// The default is true. This should be disabled only in development environments.
        /// </summary>
        public bool RequireHttpsMetadata { get; set; } = true;

        /// <summary>
        /// Gets or sets the discovery endpoint for obtaining metadata
        /// </summary>
        public string MetadataAddress { get; set; }

        /// <summary>
        /// Gets or sets the Authority to use when making OpenIdConnect calls.
        /// </summary>
        public string Authority { get; set; }

        /// <summary>
        /// Gets or sets a single valid audience value for any received OpenIdConnect token.
        /// This value is passed into TokenValidationParameters.ValidAudience if that property is empty.
        /// </summary>
        /// <value>
        /// The expected audience for any received OpenIdConnect token.
        /// </value>
        public string Audience { get; set; }

        /// <summary>
        /// Gets or sets the challenge to put in the "WWW-Authenticate" header.
        /// </summary>
        public string Challenge { get; set; } = JwtBearerDefaults.AuthenticationScheme;

        /// <summary>
        /// The object provided by the application to process events raised by the bearer authentication handler.
        /// The application may implement the interface fully, or it may create an instance of JwtBearerEvents
        /// and assign delegates only to the events it wants to process.
        /// </summary>
        public new JwtBearerEvents Events
        {
            get { return (JwtBearerEvents)base.Events; }
            set { base.Events = value; }
        }

        /// <summary>
        /// The HttpMessageHandler used to retrieve metadata.
        /// This cannot be set at the same time as BackchannelCertificateValidator unless the value
        /// is a WebRequestHandler.
        /// </summary>
        public HttpMessageHandler BackchannelHttpHandler { get; set; }

        /// <summary>
        /// Gets or sets the timeout when using the backchannel to make an http call.
        /// </summary>
        public TimeSpan BackchannelTimeout { get; set; } = TimeSpan.FromMinutes(1);

        /// <summary>
        /// Configuration provided directly by the developer. If provided, then MetadataAddress and the Backchannel properties
        /// will not be used. This information should not be updated during request processing.
        /// </summary>
        public OpenIdConnectConfiguration Configuration { get; set; }

        /// <summary>
        /// Responsible for retrieving, caching, and refreshing the configuration from metadata.
        /// If not provided, then one will be created using the MetadataAddress and Backchannel properties.
        /// </summary>
        public IConfigurationManager<OpenIdConnectConfiguration> ConfigurationManager { get; set; }

        /// <summary>
        /// Gets or sets if a metadata refresh should be attempted after a SecurityTokenSignatureKeyNotFoundException. This allows for automatic
        /// recovery in the event of a signature key rollover. This is enabled by default.
        /// </summary>
        public bool RefreshOnIssuerKeyNotFound { get; set; } = true;

        /// <summary>
        /// Gets the ordered list of <see cref="ISecurityTokenValidator"/> used to validate access tokens.
        /// </summary>
        public IList<ISecurityTokenValidator> SecurityTokenValidators { get; } = new List<ISecurityTokenValidator> { new JwtSecurityTokenHandler() };

        /// <summary>
        /// Gets or sets the parameters used to validate identity tokens.
        /// </summary>
        /// <remarks>Contains the types and definitions required for validating a token.</remarks>
        /// <exception cref="ArgumentNullException">if 'value' is null.</exception>
        public TokenValidationParameters TokenValidationParameters { get; set; } = new TokenValidationParameters();

        /// <summary>
        /// Defines whether the bearer token should be stored in the
        /// <see cref="AuthenticationProperties"/> after a successful authorization.
        /// </summary>
        public bool SaveToken { get; set; } = true;

        /// <summary>
        /// Defines whether the token validation errors should be returned to the caller.
        /// Enabled by default, this option can be disabled to prevent the JWT handler
        /// from returning an error and an error_description in the WWW-Authenticate header.
        /// </summary>
        public bool IncludeErrorDetails { get; set; } = true;
    }
```

这里会对配置做校验。JwtBear默认是没有提供发放Token的方法的，需要我们自己实现，这个后面再说。发放Token可以本地发放，也可以请求远程地址。

很多配置都是使用OpenConnectId协议来实现远程认证需要的，如果是本地发放token则不要配置。

```csharp
 /// <summary>
/// Invoked to post configure a JwtBearerOptions instance.
/// </summary>
/// <param name="name">The name of the options instance being configured.</param>
/// <param name="options">The options instance to configure.</param>
public void PostConfigure(string name, JwtBearerOptions options)
{
    if (string.IsNullOrEmpty(options.TokenValidationParameters.ValidAudience) && !string.IsNullOrEmpty(options.Audience))
    {
        options.TokenValidationParameters.ValidAudience = options.Audience;
    }

    if (options.ConfigurationManager == null)
    {
        if (options.Configuration != null)
        {
            options.ConfigurationManager = new StaticConfigurationManager<OpenIdConnectConfiguration>(options.Configuration);
        }
        else if (!(string.IsNullOrEmpty(options.MetadataAddress) && string.IsNullOrEmpty(options.Authority)))
        {
            if (string.IsNullOrEmpty(options.MetadataAddress) && !string.IsNullOrEmpty(options.Authority))
            {
                options.MetadataAddress = options.Authority;
                if (!options.MetadataAddress.EndsWith("/", StringComparison.Ordinal))
                {
                    options.MetadataAddress += "/";
                }

                options.MetadataAddress += ".well-known/openid-configuration";
            }

            if (options.RequireHttpsMetadata && !options.MetadataAddress.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidOperationException("The MetadataAddress or Authority must use HTTPS unless disabled for development by setting RequireHttpsMetadata=false.");
            }

            var httpClient = new HttpClient(options.BackchannelHttpHandler ?? new HttpClientHandler());
            httpClient.Timeout = options.BackchannelTimeout;
            httpClient.MaxResponseContentBufferSize = 1024 * 1024 * 10; // 10 MB

            options.ConfigurationManager = new ConfigurationManager<OpenIdConnectConfiguration>(options.MetadataAddress, new OpenIdConnectConfigurationRetriever(),
                new HttpDocumentRetriever(httpClient) { RequireHttps = options.RequireHttpsMetadata });
        }
    }
}
```

# 发放Token
上面提到了JwtBear项目没有提供发放Token的方法，可以使用微软的扩展库来实现。  
SymmetricSecurityKey ：表示使用对称算法生成的所有密钥的抽象基类。  

```csharp
using Microsoft.AspNetCore.Mvc;
using System;
using System.Text;

using IdentityModel;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;

[Route("api/user/login")]
[HttpPost]
public IActionResult Login([FromBody]UserDto dto)
{
    //验证username.password等逻辑..略
    var tokenHandler = new JwtSecurityTokenHandler();
    var key = Encoding.ASCII.GetBytes("this is a SecretKey");
    var authTime = DateTime.UtcNow;
    var expiresAt = authTime.AddDays(7);
    var tokenDescriptor = new SecurityTokenDescriptor
    {
        Subject = new ClaimsIdentity(new Claim[]
        {
            new Claim(JwtClaimTypes.Id, "1"),
            //谁用token
            new Claim(JwtClaimTypes.Audience,"http://localhost:5000"),
            //谁发token
            new Claim(JwtClaimTypes.Issuer,"http://localhost:5000"),
        }),
        Expires = expiresAt,
        SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
    };
    var token = tokenHandler.CreateToken(tokenDescriptor);
    var tokenString = tokenHandler.WriteToken(token);
    return Ok(tokenString);
}
```
**HS256算法要求key大于128bit即16字节,否则会出错**
扩展库源码地址：
> https://github.com/AzureAD/azure-activedirectory-identitymodel-extensions-for-dotnet/issues

上面的代码只实现了很简单的token颁发的功能，刷新token，scope的校验，单点登录等都没有实现，不建议生产环境使用（除非你的需求十分简单已经可以满足）。实现这些十分麻烦，通常需要借助框架比如IdentityServer，这个后面再聊。

# Cookie认证与Jwt认证对比
Cookie认证简图  
Cookie认证需要通知浏览器操作cookie，以及302跳转，所以前后端同域的web场景比较合适。
<div class="mermaid">
sequenceDiagram
    client->>server: 校验用户名密码后登录(HttpContext.SignInAsync())
    server->>server: Cookie维护登录信息
    server->>client: 302跳转RedirectUrl
    client->>server: 登出(HttpContext.SignOutAsync())
    server->>client: 清除Cookie,302跳转LogoutUrl
</div>

Jwt认证简图  
可以看到服务端只负责颁发token、校验token，校验失败返回标准401，至于401怎么处理在于客户端，服务端不依赖于浏览器，所以用于非web端、或者前后端分离的场景比较合适
<div class="mermaid">
sequenceDiagram
    client->>server: 登录(Login)
    server->>server: 校验信息
    server->>client: 颁发token
    client->>server: 访问受保护api
    server->>server: 校验token,将jwt中的claims信息写入HttpContext
    server->>client: 返回api结果 or 401
    client->>client: 处理401,自行跳到登录页或其他操作
</div>

# JwtBearerHandler源码分析

JwtBearerHandler继承自AuthenticationHandler，比CookieHandler少了SignIn和Signout的实现，它只处理认证（Authenticate）、质询（Chanllenge）和拒绝（Forbid），上面已经说明过原因了。

<div class="mermaid">
 classDiagram
      class AuthenticationHandler{
          AuthenticationScheme Scheme
          TOptions Options
          HttpContext Context
          HttpRequest Request
          HttpResponse Response
          PathString OriginalPath
          PathString OriginalPathBase
          ILogger Logger
          UrlEncoder UrlEncoder
          ISystemClock Clock
          object Events
          string ClaimsIssuer
          string CurrentUri
          InitializeAsync()
          +Task AuthenticateAsync()
          +Task ChallengeAsync(AuthenticationProperties properties)
          +Task ForbidAsync(AuthenticationProperties properties)
      }
      class IAuthenticationHandler{
          HandleAsync()
      }
      JwtBearerHandler-->AuthenticationHandler
      AuthenticationHandler-->IAuthenticationHandler
</div>
<script src="https://unpkg.com/mermaid/dist/mermaid.min.js"></script>

## Authenticate - 认证

- 触发MessageReceived事件，相当于是个钩子，开发可以直接拦截返回认证结果，或者设置token取代header中的token
- 从header中取token
- 获取配置和校验配置
- 循环Option.SecurityTokenValidators执行每个校验器的校验逻辑(默认校验器逻辑等下说)
- 如果配置 Options.SaveToken=true, 则会将access_token保存在HttpContext.Properties中

```csharp
protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
{
    string token = null;
    try
    {
        // Give application opportunity to find from a different location, adjust, or reject token
        var messageReceivedContext = new MessageReceivedContext(Context, Scheme, Options);

        // event can set the token
        await Events.MessageReceived(messageReceivedContext);
        if (messageReceivedContext.Result != null)
        {
            return messageReceivedContext.Result;
        }

        // If application retrieved token from somewhere else, use that.
        token = messageReceivedContext.Token;

        if (string.IsNullOrEmpty(token))
        {
            string authorization = Request.Headers[HeaderNames.Authorization];

            // If no authorization header found, nothing to process further
            if (string.IsNullOrEmpty(authorization))
            {
                return AuthenticateResult.NoResult();
            }

            if (authorization.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
            {
                token = authorization.Substring("Bearer ".Length).Trim();
            }

            // If no token found, no further work possible
            if (string.IsNullOrEmpty(token))
            {
                return AuthenticateResult.NoResult();
            }
        }

        if (_configuration == null && Options.ConfigurationManager != null)
        {
            _configuration = await Options.ConfigurationManager.GetConfigurationAsync(Context.RequestAborted);
        }

        var validationParameters = Options.TokenValidationParameters.Clone();
        if (_configuration != null)
        {
            var issuers = new[] { _configuration.Issuer };
            validationParameters.ValidIssuers = validationParameters.ValidIssuers?.Concat(issuers) ?? issuers;

            validationParameters.IssuerSigningKeys = validationParameters.IssuerSigningKeys?.Concat(_configuration.SigningKeys)
                ?? _configuration.SigningKeys;
        }

        List<Exception> validationFailures = null;
        SecurityToken validatedToken;
        foreach (var validator in Options.SecurityTokenValidators)
        {
            if (validator.CanReadToken(token))
            {
                ClaimsPrincipal principal;
                try
                {
                    principal = validator.ValidateToken(token, validationParameters, out validatedToken);
                }
                catch (Exception ex)
                {
                    Logger.TokenValidationFailed(ex);

                    // Refresh the configuration for exceptions that may be caused by key rollovers. The user can also request a refresh in the event.
                    if (Options.RefreshOnIssuerKeyNotFound && Options.ConfigurationManager != null
                        && ex is SecurityTokenSignatureKeyNotFoundException)
                    {
                        Options.ConfigurationManager.RequestRefresh();
                    }

                    if (validationFailures == null)
                    {
                        validationFailures = new List<Exception>(1);
                    }
                    validationFailures.Add(ex);
                    continue;
                }

                Logger.TokenValidationSucceeded();

                var tokenValidatedContext = new TokenValidatedContext(Context, Scheme, Options)
                {
                    Principal = principal,
                    SecurityToken = validatedToken
                };

                await Events.TokenValidated(tokenValidatedContext);
                if (tokenValidatedContext.Result != null)
                {
                    return tokenValidatedContext.Result;
                }

                if (Options.SaveToken)
                {
                    tokenValidatedContext.Properties.StoreTokens(new[]
                    {
                        new AuthenticationToken { Name = "access_token", Value = token }
                    });
                }

                tokenValidatedContext.Success();
                return tokenValidatedContext.Result;
            }
        }

        if (validationFailures != null)
        {
            var authenticationFailedContext = new AuthenticationFailedContext(Context, Scheme, Options)
            {
                Exception = (validationFailures.Count == 1) ? validationFailures[0] : new AggregateException(validationFailures)
            };

            await Events.AuthenticationFailed(authenticationFailedContext);
            if (authenticationFailedContext.Result != null)
            {
                return authenticationFailedContext.Result;
            }

            return AuthenticateResult.Fail(authenticationFailedContext.Exception);
        }

        return AuthenticateResult.Fail("No SecurityTokenValidator available for token: " + token ?? "[null]");
    }
    catch (Exception ex)
    {
        Logger.ErrorProcessingMessage(ex);

        var authenticationFailedContext = new AuthenticationFailedContext(Context, Scheme, Options)
        {
            Exception = ex
        };

        await Events.AuthenticationFailed(authenticationFailedContext);
        if (authenticationFailedContext.Result != null)
        {
            return authenticationFailedContext.Result;
        }

        throw;
    }
}
```

JwtBearOptions配置类的这段代码可以看到, 默认校验类是JwtSecurityTokenHandler，这是上面提到的扩展包里面的类，命名空间是System.IdentityModel.Tokens.Jwt

```csharp
/// <summary>
/// Gets the ordered list of <see cref="ISecurityTokenValidator"/> used to validate access tokens.
/// </summary>
public IList<ISecurityTokenValidator> SecurityTokenValidators { get; } = new List<ISecurityTokenValidator> { new JwtSecurityTokenHandler() };
```
看一看代码，代码比较简单，就是解码token，然后将claims信息返回。之前生成jwt也是使用的这个类。  
如果需要额外的校验逻辑，可以自己实现ISecurityTokenValidator，用这个类解码token得到claims之后实现自己的业务逻辑。  

```csharp
public override ClaimsPrincipal ValidateToken(string token, TokenValidationParameters validationParameters, out SecurityToken validatedToken)
    {
        if (string.IsNullOrWhiteSpace(token))
            throw LogHelper.LogArgumentNullException(nameof(token));

        if (validationParameters == null)
            throw LogHelper.LogArgumentNullException(nameof(validationParameters));

        if (token.Length > MaximumTokenSizeInBytes)
            throw LogHelper.LogExceptionMessage(new ArgumentException(LogHelper.FormatInvariant(TokenLogMessages.IDX10209, token.Length, MaximumTokenSizeInBytes)));

        var tokenParts = token.Split(new char[] { '.' }, JwtConstants.MaxJwtSegmentCount + 1);
        if (tokenParts.Length != JwtConstants.JwsSegmentCount && tokenParts.Length != JwtConstants.JweSegmentCount)
            throw LogHelper.LogExceptionMessage(new ArgumentException(LogHelper.FormatInvariant(LogMessages.IDX12741, token)));

        if (tokenParts.Length == JwtConstants.JweSegmentCount)
        {
            var jwtToken = ReadJwtToken(token);
            var decryptedJwt = DecryptToken(jwtToken, validationParameters);
            var innerToken = ValidateSignature(decryptedJwt, validationParameters);
            jwtToken.InnerToken = innerToken;
            validatedToken = jwtToken;
            return ValidateTokenPayload(innerToken, validationParameters);
        }
        else
        {
            validatedToken = ValidateSignature(token, validationParameters);
            return ValidateTokenPayload(validatedToken as JwtSecurityToken, validationParameters);
        }
    }
```

## Chanllenge -- 质询

质询逻辑简单说下，执行认证方法，成功则返回结果，失败返回401，生成的报文大致这样  
```
https://tools.ietf.org/html/rfc6750#section-3.1
WWW-Authenticate: Bearer realm="example", error="invalid_token", error_description="The access token expired"
```
```csharp
protected override async Task HandleChallengeAsync(AuthenticationProperties properties)
{
    var authResult = await HandleAuthenticateOnceSafeAsync();
    var eventContext = new JwtBearerChallengeContext(Context, Scheme, Options, properties)
    {
        AuthenticateFailure = authResult?.Failure
    };

    // Avoid returning error=invalid_token if the error is not caused by an authentication failure (e.g missing token).
    if (Options.IncludeErrorDetails && eventContext.AuthenticateFailure != null)
    {
        eventContext.Error = "invalid_token";
        eventContext.ErrorDescription = CreateErrorDescription(eventContext.AuthenticateFailure);
    }

    await Events.Challenge(eventContext);
    if (eventContext.Handled)
    {
        return;
    }

    Response.StatusCode = 401;

    if (string.IsNullOrEmpty(eventContext.Error) &&
        string.IsNullOrEmpty(eventContext.ErrorDescription) &&
        string.IsNullOrEmpty(eventContext.ErrorUri))
    {
        Response.Headers.Append(HeaderNames.WWWAuthenticate, Options.Challenge);
    }
    else
    {
        // https://tools.ietf.org/html/rfc6750#section-3.1
        // WWW-Authenticate: Bearer realm="example", error="invalid_token", error_description="The access token expired"
        var builder = new StringBuilder(Options.Challenge);
        if (Options.Challenge.IndexOf(' ') > 0)
        {
            // Only add a comma after the first param, if any
            builder.Append(',');
        }
        if (!string.IsNullOrEmpty(eventContext.Error))
        {
            builder.Append(" error=\"");
            builder.Append(eventContext.Error);
            builder.Append("\"");
        }
        if (!string.IsNullOrEmpty(eventContext.ErrorDescription))
        {
            if (!string.IsNullOrEmpty(eventContext.Error))
            {
                builder.Append(",");
            }

            builder.Append(" error_description=\"");
            builder.Append(eventContext.ErrorDescription);
            builder.Append('\"');
        }
        if (!string.IsNullOrEmpty(eventContext.ErrorUri))
        {
            if (!string.IsNullOrEmpty(eventContext.Error) ||
                !string.IsNullOrEmpty(eventContext.ErrorDescription))
            {
                builder.Append(",");
            }

            builder.Append(" error_uri=\"");
            builder.Append(eventContext.ErrorUri);
            builder.Append('\"');
        }

        Response.Headers.Append(HeaderNames.WWWAuthenticate, builder.ToString());
    }
}
```

## Forbid - 拒绝
返回403
```csharp
protected override Task HandleForbiddenAsync(AuthenticationProperties properties)
{
    var forbiddenContext = new ForbiddenContext(Context, Scheme, Options);
    Response.StatusCode = 403;
    return Events.Forbidden(forbiddenContext);
}
```

参考资料：  

Cookie的SameSite属性  
> http://www.ruanyifeng.com/blog/2019/09/cookie-samesite.html    
> 
CORS  
> https://holdengong.com/aspnetcore3.1_middleware%E6%BA%90%E7%A0%81%E8%A7%A3%E6%9E%90_1_cors/   

ASPNET Core 认证与授权[4]:JwtBearer认证  
> https://www.cnblogs.com/RainingNight/p/jwtbearer-authentication-in-asp-net-core.html