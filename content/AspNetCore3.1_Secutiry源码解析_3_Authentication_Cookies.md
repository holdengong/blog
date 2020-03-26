---
title: "AspNetCore3.1_Secutiry源码解析_3_Authentication_Cookies"
date: 2020-03-19T22:52:39+08:00
draft: false
---
# 系列文章目录
- [AspNetCore3.1_Secutiry源码解析_1_目录](https://holdengong.com/aspnetcore3.1_secutiry源码解析_1_目录)
- [AspNetCore3.1_Secutiry源码解析_2_Authentication_核心流程](https://holdengong.com/aspnetcore3.1_secutiry源码解析_2_authentication_核心流程)
- [AspNetCore3.1_Secutiry源码解析_3_Authentication_Cookies](https://holdengong.com/aspnetcore3.1_secutiry源码解析_3_authentication_cookies)
- [AspNetCore3.1_Secutiry源码解析_4_Authentication_JwtBear](https://holdengong.com/aspnetcore3.1_secutiry源码解析_4_authentication_jwtbear)
- [AspNetCore3.1_Secutiry源码解析_5_Authentication_OAuth](https://holdengong.com/aspnetcore3.1_secutiry源码解析_5_authentication_oauth)
- [AspNetCore3.1_Secutiry源码解析_6_Authentication_OpenIdConnect](https://holdengong.com/aspnetcore3.1_secutiry源码解析_6_authentication_openidconnect)
- AspNetCore3.1_Secutiry源码解析_7_Authentication_其他
- AspNetCore3.1_Secutiry源码解析_8_Authorization_核心项目
- AspNetCore3.1_Secutiry源码解析_9_Authorization_Policy


# 依赖注入
```csharp
AuthenticationBuilder AddCookie(this AuthenticationBuilder builder);

AuthenticationBuilder AddCookie(this AuthenticationBuilder builder, string authenticationScheme);

AuthenticationBuilder AddCookie(this AuthenticationBuilder builder, Action<CookieAuthenticationOptions> configureOptions);
```
提供了几个重载方法，可以使用默认配置，或者通过委托修改配置类CookieAuthenticationOptions的值。

可以定义登录、登出、拒绝登录页面地址、Cookie过期时间、生命周期各阶段事件等。
<div class="mermaid">
 classDiagram
      class CookieAuthenticationOptions{
          CookieBuilder Cookie
          IDataProtectionProvider DataProtectionProvider
          bool SlidingExpiration
          PathString LoginPath
          PathString LogoutPath
          PathString AccessDeniedPath
          CookieAuthenticationEvents Events
          ISecureDataFormat TicketDataFormat
          ITicketStore SessionStore
          TimeSpan ExpireTimeSpan
      }
      class AuthenticationSchemeOptions{
          string ClaimsIssuer
          object Events
          Type EventsType
          string ForwardDefault
          string ForwardAuthenticate
          string ForwardChallenge
          string ForwardForbid
          string ForwardSignIn
          string ForwardSignOut
          Func ForwardDefaultSelector
      }
      CookieAuthenticationOptions-->AuthenticationSchemeOptions
</div>
<script src="https://unpkg.com/mermaid/dist/mermaid.min.js"></script>

如果没有定义配置，则会使用CookieAuthenticationDefaults定义的默认配置
```csharp
 /// <summary>
    /// Default values related to cookie-based authentication handler
    /// </summary>
    public static class CookieAuthenticationDefaults
    {
        /// <summary>
        /// The default value used for CookieAuthenticationOptions.AuthenticationScheme
        /// </summary>
        public const string AuthenticationScheme = "Cookies";

        /// <summary>
        /// The prefix used to provide a default CookieAuthenticationOptions.CookieName
        /// </summary>
        public static readonly string CookiePrefix = ".AspNetCore.";

        /// <summary>
        /// The default value used by CookieAuthenticationMiddleware for the
        /// CookieAuthenticationOptions.LoginPath
        /// </summary>
        public static readonly PathString LoginPath = new PathString("/Account/Login");

        /// <summary>
        /// The default value used by CookieAuthenticationMiddleware for the
        /// CookieAuthenticationOptions.LogoutPath
        /// </summary>
        public static readonly PathString LogoutPath = new PathString("/Account/Logout");

        /// <summary>
        /// The default value used by CookieAuthenticationMiddleware for the
        /// CookieAuthenticationOptions.AccessDeniedPath
        /// </summary>
        public static readonly PathString AccessDeniedPath = new PathString("/Account/AccessDenied");

        /// <summary>
        /// The default value of the CookieAuthenticationOptions.ReturnUrlParameter
        /// </summary>
        public static readonly string ReturnUrlParameter = "ReturnUrl";
    }
```

注册当前schema的处理器类为CookieAuthenticationHandler

# 处理器类的结构

主干逻辑是层层继承来实现的，CookieAuthenticationHandler主要是重写了父类的五个认证动作的Handle方法来实现自己的处理逻辑。

<div class="mermaid">
 classDiagram
      class CookieAuthenticationHandler{
        HandleAuthenticateAsync()
        HandleSignInAsync()
        HandleSignOutAsync()
        HandleForbiddenAsync()
        HandleChallengeAsync()
        FinishResponseAsync()
      }
      class SignInAuthenticationHandler{
          SignInAsync()
          HandleSignInAsync()
      }
      class IAuthenticationSignInHandler{
          SignIn()
          HandleSignIn()
      }
      class SignOutAuthenticationHandler{
          SignOutAsync()
          HandleSignOutAsync()
      }
      class IAuthenticationSignOutHandler{
          SighOut()
          HandleSignOut()
      }
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
          +Task InitializeAsync(AuthenticationScheme scheme, HttpContext context)
          +Task AuthenticateAsync()
          +Task ChallengeAsync(AuthenticationProperties properties)
          +Task ForbidAsync(AuthenticationProperties properties)
      }
      class IAuthenticationHandler{
          HandleAsync()
      }
      CookieAuthenticationHandler-->SignInAuthenticationHandler
      SignInAuthenticationHandler-->IAuthenticationSignInHandler
      SignInAuthenticationHandler-->SignOutAuthenticationHandler
      SignOutAuthenticationHandler-->IAuthenticationSignOutHandler
      SignOutAuthenticationHandler-->AuthenticationHandler
      AuthenticationHandler-->IAuthenticationHandler
</div>

# 处理器类详解
## HandleSignInAsync - 处理登录
1. 业务方校验完用户之后之后，构造ClaimsPrincipal对象传入SignIn方法，如果user为null则抛出异常
2. IssuedUtc如果未指定的话则使用当前时间，ExpiresUtc过期时间如果没有指定的话则用IssuedUtc和ExpireTimeSpan计算出过期时间
3. 触发SigningIn事件
4. 构造AuthenticationTicket凭证
5. 如果SessionStore不为空，将凭证信息存入SessionStore
6. TicketDataFormat对ticket进行加密
7. CookieManager将t加密后的信息写入cookie
8. 触发SignedIn事件
9. 如果LoginPath有值并且等于OriginalPath，则需要跳转，跳转地址在Properties.RedirectUri

```csharp
protected async override Task HandleSignInAsync(ClaimsPrincipal user, AuthenticationProperties properties)
    {
        if (user == null)
        {
            throw new ArgumentNullException(nameof(user));
        }

        properties = properties ?? new AuthenticationProperties();

        _signInCalled = true;

        // Process the request cookie to initialize members like _sessionKey.
        await EnsureCookieTicket();
        var cookieOptions = BuildCookieOptions();

        var signInContext = new CookieSigningInContext(
            Context,
            Scheme,
            Options,
            user,
            properties,
            cookieOptions);

        DateTimeOffset issuedUtc;
        if (signInContext.Properties.IssuedUtc.HasValue)
        {
            issuedUtc = signInContext.Properties.IssuedUtc.Value;
        }
        else
        {
            issuedUtc = Clock.UtcNow;
            signInContext.Properties.IssuedUtc = issuedUtc;
        }

        if (!signInContext.Properties.ExpiresUtc.HasValue)
        {
            signInContext.Properties.ExpiresUtc = issuedUtc.Add(Options.ExpireTimeSpan);
        }

        await Events.SigningIn(signInContext);

        if (signInContext.Properties.IsPersistent)
        {
            var expiresUtc = signInContext.Properties.ExpiresUtc ?? issuedUtc.Add(Options.ExpireTimeSpan);
            signInContext.CookieOptions.Expires = expiresUtc.ToUniversalTime();
        }

        var ticket = new AuthenticationTicket(signInContext.Principal, signInContext.Properties, signInContext.Scheme.Name);

        if (Options.SessionStore != null)
        {
            if (_sessionKey != null)
            {
                await Options.SessionStore.RemoveAsync(_sessionKey);
            }
            _sessionKey = await Options.SessionStore.StoreAsync(ticket);
            var principal = new ClaimsPrincipal(
                new ClaimsIdentity(
                    new[] { new Claim(SessionIdClaim, _sessionKey, ClaimValueTypes.String, Options.ClaimsIssuer) },
                    Options.ClaimsIssuer));
            ticket = new AuthenticationTicket(principal, null, Scheme.Name);
        }

        var cookieValue = Options.TicketDataFormat.Protect(ticket, GetTlsTokenBinding());

        Options.CookieManager.AppendResponseCookie(
            Context,
            Options.Cookie.Name,
            cookieValue,
            signInContext.CookieOptions);

        var signedInContext = new CookieSignedInContext(
            Context,
            Scheme,
            signInContext.Principal,
            signInContext.Properties,
            Options);

        await Events.SignedIn(signedInContext);

        // Only redirect on the login path
        var shouldRedirect = Options.LoginPath.HasValue && OriginalPath == Options.LoginPath;
        await ApplyHeaders(shouldRedirect, signedInContext.Properties);

        Logger.AuthenticationSchemeSignedIn(Scheme.Name);
    }
```


## HandleAuthentication - 处理认证
1. 从Cookie中读取凭证：首先TicketDataFormat类将Cookie解码，如果SessionStore不为null，说明解码值是只是session的key，从SessionStore中取出值。
2. 构建CookieValidatePrincipalContext，触发ValidatePrincipal事件
3. 如果ShouldRenew位true，则会刷新cookie（ShoudRenew默认为false，可以通过订阅ValidatePrincipal事件来修改）
4. 认证成功，发放凭证AuthenticationTicket，包括context.Principal, context.Properties, Scheme.Name这些信息

```csharp
 protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
{
    var result = await EnsureCookieTicket();
    if (!result.Succeeded)
    {
        return result;
    }

    var context = new CookieValidatePrincipalContext(Context, Scheme, Options, result.Ticket);
    await Events.ValidatePrincipal(context);

    if (context.Principal == null)
    {
        return AuthenticateResult.Fail("No principal.");
    }

    if (context.ShouldRenew)
    {
        RequestRefresh(result.Ticket, context.Principal);
    }

    return AuthenticateResult.Success(new AuthenticationTicket(context.Principal, context.Properties, Scheme.Name));
}
```
## HandleSignOutAsync - 处理登出

1. 获取凭证
2. SessionStore不为null的话则从SessionStore移除会话
3. 触发SigningOut事件
4. CookieManager删除cookie
5. 如果源地址是LogoutPath，则跳转到登出后地址

```csharp
protected async override Task HandleSignOutAsync(AuthenticationProperties properties)
    {
        properties = properties ?? new AuthenticationProperties();

        _signOutCalled = true;

        // Process the request cookie to initialize members like _sessionKey.
        await EnsureCookieTicket();
        var cookieOptions = BuildCookieOptions();
        if (Options.SessionStore != null && _sessionKey != null)
        {
            await Options.SessionStore.RemoveAsync(_sessionKey);
        }

        var context = new CookieSigningOutContext(
            Context,
            Scheme,
            Options,
            properties,
            cookieOptions);

        await Events.SigningOut(context);

        Options.CookieManager.DeleteCookie(
            Context,
            Options.Cookie.Name,
            context.CookieOptions);

        // Only redirect on the logout path
        var shouldRedirect = Options.LogoutPath.HasValue && OriginalPath == Options.LogoutPath;
        await ApplyHeaders(shouldRedirect, context.Properties);

        Logger.AuthenticationSchemeSignedOut(Scheme.Name);
    }
```

## HandleForbidAsync -- 处理禁止访问

如果是ajax请求会返回403状态码，否则跳转到配置的AccessDeniedPath

```csharp
 protected override async Task HandleForbiddenAsync(AuthenticationProperties properties)
{
    var returnUrl = properties.RedirectUri;
    if (string.IsNullOrEmpty(returnUrl))
    {
        returnUrl = OriginalPathBase + OriginalPath + Request.QueryString;
    }
    var accessDeniedUri = Options.AccessDeniedPath + QueryString.Create(Options.ReturnUrlParameter, returnUrl);
    var redirectContext = new RedirectContext<CookieAuthenticationOptions>(Context, Scheme, Options, properties, BuildRedirectUri(accessDeniedUri));
    await Events.RedirectToAccessDenied(redirectContext);
}

public Func<RedirectContext<CookieAuthenticationOptions>, Task> OnRedirectToAccessDenied { get; set; } = context =>
    {
        if (IsAjaxRequest(context.Request))
        {
            context.Response.Headers[HeaderNames.Location] = context.RedirectUri;
            context.Response.StatusCode = 403;
        }
        else
        {
            context.Response.Redirect(context.RedirectUri);
        }
        return Task.CompletedTask;
    };
```



# 其他
## ICookieManager - Cookie管理类

默认实现是ChunkingCookieManager，如果cookie过长，该类会将cookie拆分位多个chunk。

```csharp
 /// <summary>
/// This is used by the CookieAuthenticationMiddleware to process request and response cookies.
/// It is abstracted from the normal cookie APIs to allow for complex operations like chunking.
/// </summary>
public interface ICookieManager
{
    /// <summary>
    /// Retrieve a cookie of the given name from the request.
    /// </summary>
    /// <param name="context"></param>
    /// <param name="key"></param>
    /// <returns></returns>
    string GetRequestCookie(HttpContext context, string key);

    /// <summary>
    /// Append the given cookie to the response.
    /// </summary>
    /// <param name="context"></param>
    /// <param name="key"></param>
    /// <param name="value"></param>
    /// <param name="options"></param>
    void AppendResponseCookie(HttpContext context, string key, string value, CookieOptions options);

    /// <summary>
    /// Append a delete cookie to the response.
    /// </summary>
    /// <param name="context"></param>
    /// <param name="key"></param>
    /// <param name="options"></param>
    void DeleteCookie(HttpContext context, string key, CookieOptions options);
}
```

## ITicketStore - 实现Cookie持久化

ITicketStore默认是没有实现的，如果实现该接口并注入的话，可以将cookie持久化，这样暴露在浏览器的只是一个cookie的id。

```csharp
/// <summary>
/// This provides an abstract storage mechanic to preserve identity information on the server
/// while only sending a simple identifier key to the client. This is most commonly used to mitigate
/// issues with serializing large identities into cookies.
/// </summary>
public interface ITicketStore
{
    /// <summary>
    /// Store the identity ticket and return the associated key.
    /// </summary>
    /// <param name="ticket">The identity information to store.</param>
    /// <returns>The key that can be used to retrieve the identity later.</returns>
    Task<string> StoreAsync(AuthenticationTicket ticket);

    /// <summary>
    /// Tells the store that the given identity should be updated.
    /// </summary>
    /// <param name="key"></param>
    /// <param name="ticket"></param>
    /// <returns></returns>
    Task RenewAsync(string key, AuthenticationTicket ticket);

    /// <summary>
    /// Retrieves an identity from the store for the given key.
    /// </summary>
    /// <param name="key">The key associated with the identity.</param>
    /// <returns>The identity associated with the given key, or if not found.</returns>
    Task<AuthenticationTicket> RetrieveAsync(string key);

    /// <summary>
    /// Remove the identity associated with the given key.
    /// </summary>
    /// <param name="key">The key associated with the identity.</param>
    /// <returns></returns>
    Task RemoveAsync(string key);
}
```





