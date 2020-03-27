---
title: "IdentityServer4源码解析_1_项目结构"
date: 2020-03-26T20:31:25+08:00
draft: false
---
{{%idsv_menu%}}

# 简介
Security源码解析系列介绍了微软提供的各种认证架构，其中OAuth2.0，OpenIdConnect属于远程认证架构，所谓远程认证，是指token的颁发是由其他站点完成的。

IdentityServer4是基于OpenIdConnect协议的认证中心框架，可以帮助我们快速搭建微服务认证中心。

初学者可能看到生涩的概念比较头疼，可以将OAuth, OpenIdConnect协议简单理解成需求文档，idsv4基于需求提供了一系列的api实现。

对于idsv还不太了解的可以看下面的资料，本系列主要学习梳理idsv4的源码，结合协议加深理解。

晓晨姐姐系列文章
> https://www.cnblogs.com/stulzq/p/8119928.html  

官方文档
> https://identityserver4.readthedocs.io/en/latest/

# 项目结构
项目地址如下
> https://github.com/IdentityServer/IdentityServer4

克隆到本地，项目结构如图

![image](https://fs.31huiyi.com/da6e1cbb-4dfd-4eed-a3cc-ff629a404c63.png)

核心项目是IdentityServer4，其余的都是与微软框架集成、以及处理持久化的项目。
项目结构如图。Endpoints文件夹就是接口文件，我们先看下依赖注入、中间件的代码，然后看下每个接口。
![image](https://fs.31huiyi.com/44183a92-cb3e-45f5-8100-a4cd7101e2dd.png)

# 依赖注入
```csharp
public static IIdentityServerBuilder AddIdentityServer(this IServiceCollection services)
{
    var builder = services.AddIdentityServerBuilder();

    builder
        .AddRequiredPlatformServices()
        .AddCookieAuthentication()
        .AddCoreServices()
        .AddDefaultEndpoints()
        .AddPluggableServices()
        .AddValidators()
        .AddResponseGenerators()
        .AddDefaultSecretParsers()
        .AddDefaultSecretValidators();

    // provide default in-memory implementation, not suitable for most production scenarios
    builder.AddInMemoryPersistedGrants();

    return builder;
}
```

- AddRequiredPlatformServices - 注入平台服务 
    - IHttpContextAccessor：HttpContext访问器  
    - IdentityServerOptions：配置类
```csharp
 public static IIdentityServerBuilder AddRequiredPlatformServices(this IIdentityServerBuilder builder)
{
    builder.Services.TryAddSingleton<IHttpContextAccessor, HttpContextAccessor>();            
    builder.Services.AddOptions();
    builder.Services.AddSingleton(
        resolver => resolver.GetRequiredService<IOptions<IdentityServerOptions>>().Value);
    builder.Services.AddHttpClient();

    return builder;
}
```

- AddCookieAuthentication - 注入cookie服务
    - 注入名称为idsrv的cookie认证架构
    - 注入IAuthenticationService的实现IdentityServerAuthenticationService
    - 注入IAuthenticationHandlerProvider的实现FederatedSignoutAuthenticationHandlerProvider
```csharp
public static IIdentityServerBuilder AddCookieAuthentication(this IIdentityServerBuilder builder)
{
    builder.Services.AddAuthentication(IdentityServerConstants.DefaultCookieAuthenticationScheme)
        .AddCookie(IdentityServerConstants.DefaultCookieAuthenticationScheme)
        .AddCookie(IdentityServerConstants.ExternalCookieAuthenticationScheme);

    builder.Services.AddSingleton<IConfigureOptions<CookieAuthenticationOptions>, ConfigureInternalCookieOptions>();
    builder.Services.AddSingleton<IPostConfigureOptions<CookieAuthenticationOptions>, PostConfigureInternalCookieOptions>();
    builder.Services.AddTransientDecorator<IAuthenticationService, IdentityServerAuthenticationService>();
    builder.Services.AddTransientDecorator<IAuthenticationHandlerProvider, FederatedSignoutAuthenticationHandlerProvider>();

    return builder;
}
```

- AddCoreServices - 注入核心服务
```csharp
/// <summary>
/// Adds the core services.
/// </summary>
/// <param name="builder">The builder.</param>
/// <returns></returns>
public static IIdentityServerBuilder AddCoreServices(this IIdentityServerBuilder builder)
{
    builder.Services.AddTransient<SecretParser>();
    builder.Services.AddTransient<SecretValidator>();
    builder.Services.AddTransient<ScopeValidator>();
    builder.Services.AddTransient<ExtensionGrantValidator>();
    builder.Services.AddTransient<BearerTokenUsageValidator>();
    builder.Services.AddTransient<JwtRequestValidator>();

    // todo: remove in 3.0
#pragma warning disable CS0618 // Type or member is obsolete
    builder.Services.AddTransient<BackChannelHttpClient>();
#pragma warning restore CS0618 // Type or member is obsolete

    builder.Services.AddTransient<ReturnUrlParser>();
    builder.Services.AddTransient<IdentityServerTools>();

    builder.Services.AddTransient<IReturnUrlParser, OidcReturnUrlParser>();
    builder.Services.AddScoped<IUserSession, DefaultUserSession>();
    builder.Services.AddTransient(typeof(MessageCookie<>));

    builder.Services.AddCors();
    builder.Services.AddTransientDecorator<ICorsPolicyProvider, CorsPolicyProvider>();

    return builder;
}
```

- AddDefaultEndpoints - 注入接口
    - AuthorizeCallbackEndpoint：认证回调接口
    - AuthorizeEndpoint：认证接口
    - CheckSessionEndpoint：检查会话接口
    - DeviceAuthorizationEndpoint：设备认证接口
    - DiscoveryEndpoint：元数据键接口
    - DiscoveryEndpoint：元数据接口
    - EndSessionCallbackEndpoint：结束会话回调接口
    - EndSessionEndpoint：结束会话接口
    - IntrospectionEndpoint：查询令牌信息接口
    - TokenRevocationEndpoint：撤销令牌接口
    - TokenEndpoint：发放令牌接口
    - UserInfoEndpoint：查询用户信息接口

注入所有默认接口，包括接口名称和地址。请求进来之后，路由类EndPointRouter通过路由来寻找匹配的处理器。

```csharp
 public static IIdentityServerBuilder AddDefaultEndpoints(this IIdentityServerBuilder builder)
{
    builder.Services.AddTransient<IEndpointRouter, EndpointRouter>();

    builder.AddEndpoint<AuthorizeCallbackEndpoint>(EndpointNames.Authorize, ProtocolRoutePaths.AuthorizeCallback.EnsureLeadingSlash());
    builder.AddEndpoint<AuthorizeEndpoint>(EndpointNames.Authorize, ProtocolRoutePaths.Authorize.EnsureLeadingSlash());
    builder.AddEndpoint<CheckSessionEndpoint>(EndpointNames.CheckSession, ProtocolRoutePaths.CheckSession.EnsureLeadingSlash());
    builder.AddEndpoint<DeviceAuthorizationEndpoint>(EndpointNames.DeviceAuthorization, ProtocolRoutePaths.DeviceAuthorization.EnsureLeadingSlash());
    builder.AddEndpoint<DiscoveryKeyEndpoint>(EndpointNames.Discovery, ProtocolRoutePaths.DiscoveryWebKeys.EnsureLeadingSlash());
    builder.AddEndpoint<DiscoveryEndpoint>(EndpointNames.Discovery, ProtocolRoutePaths.DiscoveryConfiguration.EnsureLeadingSlash());
    builder.AddEndpoint<EndSessionCallbackEndpoint>(EndpointNames.EndSession, ProtocolRoutePaths.EndSessionCallback.EnsureLeadingSlash());
    builder.AddEndpoint<EndSessionEndpoint>(EndpointNames.EndSession, ProtocolRoutePaths.EndSession.EnsureLeadingSlash());
    builder.AddEndpoint<IntrospectionEndpoint>(EndpointNames.Introspection, ProtocolRoutePaths.Introspection.EnsureLeadingSlash());
    builder.AddEndpoint<TokenRevocationEndpoint>(EndpointNames.Revocation, ProtocolRoutePaths.Revocation.EnsureLeadingSlash());
    builder.AddEndpoint<TokenEndpoint>(EndpointNames.Token, ProtocolRoutePaths.Token.EnsureLeadingSlash());
    builder.AddEndpoint<UserInfoEndpoint>(EndpointNames.UserInfo, ProtocolRoutePaths.UserInfo.EnsureLeadingSlash());

    return builder;
}
```

- AddPluggableServices - 注入可插拔服务
```csharp
public static IIdentityServerBuilder AddPluggableServices(this IIdentityServerBuilder builder)
{
    builder.Services.TryAddTransient<IPersistedGrantService, DefaultPersistedGrantService>();
    builder.Services.TryAddTransient<IKeyMaterialService, DefaultKeyMaterialService>();
    builder.Services.TryAddTransient<ITokenService, DefaultTokenService>();
    builder.Services.TryAddTransient<ITokenCreationService, DefaultTokenCreationService>();
    builder.Services.TryAddTransient<IClaimsService, DefaultClaimsService>();
    builder.Services.TryAddTransient<IRefreshTokenService, DefaultRefreshTokenService>();
    builder.Services.TryAddTransient<IDeviceFlowCodeService, DefaultDeviceFlowCodeService>();
    builder.Services.TryAddTransient<IConsentService, DefaultConsentService>();
    builder.Services.TryAddTransient<ICorsPolicyService, DefaultCorsPolicyService>();
    builder.Services.TryAddTransient<IProfileService, DefaultProfileService>();
    builder.Services.TryAddTransient<IConsentMessageStore, ConsentMessageStore>();
    builder.Services.TryAddTransient<IMessageStore<LogoutMessage>, ProtectedDataMessageStore<LogoutMessage>>();
    builder.Services.TryAddTransient<IMessageStore<EndSession>, ProtectedDataMessageStore<EndSession>>();
    builder.Services.TryAddTransient<IMessageStore<ErrorMessage>, ProtectedDataMessageStore<ErrorMessage>>();
    builder.Services.TryAddTransient<IIdentityServerInteractionService, DefaultIdentityServerInteractionService>();
    builder.Services.TryAddTransient<IDeviceFlowInteractionService, DefaultDeviceFlowInteractionService>();
    builder.Services.TryAddTransient<IAuthorizationCodeStore, DefaultAuthorizationCodeStore>();
    builder.Services.TryAddTransient<IRefreshTokenStore, DefaultRefreshTokenStore>();
    builder.Services.TryAddTransient<IReferenceTokenStore, DefaultReferenceTokenStore>();
    builder.Services.TryAddTransient<IUserConsentStore, DefaultUserConsentStore>();
    builder.Services.TryAddTransient<IHandleGenerationService, DefaultHandleGenerationService>();
    builder.Services.TryAddTransient<IPersistentGrantSerializer, PersistentGrantSerializer>();
    builder.Services.TryAddTransient<IEventService, DefaultEventService>();
    builder.Services.TryAddTransient<IEventSink, DefaultEventSink>();
    builder.Services.TryAddTransient<IUserCodeService, DefaultUserCodeService>();
    builder.Services.TryAddTransient<IUserCodeGenerator, NumericUserCodeGenerator>();
    builder.Services.TryAddTransient<IBackChannelLogoutService, DefaultBackChannelLogoutService>();

    builder.AddJwtRequestUriHttpClient();
    builder.AddBackChannelLogoutHttpClient();
    //builder.Services.AddHttpClient<BackChannelLogoutHttpClient>();
    //builder.Services.AddHttpClient<JwtRequestUriHttpClient>();

    builder.Services.AddTransient<IClientSecretValidator, ClientSecretValidator>();
    builder.Services.AddTransient<IApiSecretValidator, ApiSecretValidator>();

    builder.Services.TryAddTransient<IDeviceFlowThrottlingService, DistributedDeviceFlowThrottlingService>();
    builder.Services.AddDistributedMemoryCache();

    return builder;
}
```

- AddValidators - 注入校验类
```csharp
public static IIdentityServerBuilder AddValidators(this IIdentityServerBuilder builder)
{
    // core
    builder.Services.TryAddTransient<IEndSessionRequestValidator, EndSessionRequestValidator>();
    builder.Services.TryAddTransient<ITokenRevocationRequestValidator, TokenRevocationRequestValidator>();
    builder.Services.TryAddTransient<IAuthorizeRequestValidator, AuthorizeRequestValidator>();
    builder.Services.TryAddTransient<ITokenRequestValidator, TokenRequestValidator>();
    builder.Services.TryAddTransient<IRedirectUriValidator, StrictRedirectUriValidator>();
    builder.Services.TryAddTransient<ITokenValidator, TokenValidator>();
    builder.Services.TryAddTransient<IIntrospectionRequestValidator, IntrospectionRequestValidator>();
    builder.Services.TryAddTransient<IResourceOwnerPasswordValidator, NotSupportedResourceOwnerPasswordValidator>();
    builder.Services.TryAddTransient<ICustomTokenRequestValidator, DefaultCustomTokenRequestValidator>();
    builder.Services.TryAddTransient<IUserInfoRequestValidator, UserInfoRequestValidator>();
    builder.Services.TryAddTransient<IClientConfigurationValidator, DefaultClientConfigurationValidator>();
    builder.Services.TryAddTransient<IDeviceAuthorizationRequestValidator, DeviceAuthorizationRequestValidator>();
    builder.Services.TryAddTransient<IDeviceCodeValidator, DeviceCodeValidator>();

    // optional
    builder.Services.TryAddTransient<ICustomTokenValidator, DefaultCustomTokenValidator>();
    builder.Services.TryAddTransient<ICustomAuthorizeRequestValidator, DefaultCustomAuthorizeRequestValidator>();
    
    return builder;
}
```

- AddResponseGenerators - 注入响应生成类
```csharp
public static IIdentityServerBuilder AddResponseGenerators(this IIdentityServerBuilder builder)
{
    builder.Services.TryAddTransient<ITokenResponseGenerator, TokenResponseGenerator>();
    builder.Services.TryAddTransient<IUserInfoResponseGenerator, UserInfoResponseGenerator>();
    builder.Services.TryAddTransient<IIntrospectionResponseGenerator, IntrospectionResponseGenerator>();
    builder.Services.TryAddTransient<IAuthorizeInteractionResponseGenerator, AuthorizeInteractionResponseGenerator>();
    builder.Services.TryAddTransient<IAuthorizeResponseGenerator, AuthorizeResponseGenerator>();
    builder.Services.TryAddTransient<IDiscoveryResponseGenerator, DiscoveryResponseGenerator>();
    builder.Services.TryAddTransient<ITokenRevocationResponseGenerator, TokenRevocationResponseGenerator>();
    builder.Services.TryAddTransient<IDeviceAuthorizationResponseGenerator, DeviceAuthorizationResponseGenerator>();

    return builder;
}
```

- AddDefaultSecretParsers & AddDefaultSecretValidators
```csharp
/// <summary>
/// Adds the default secret parsers.
/// </summary>
/// <param name="builder">The builder.</param>
/// <returns></returns>
public static IIdentityServerBuilder AddDefaultSecretParsers(this IIdentityServerBuilder builder)
{
    builder.Services.AddTransient<ISecretParser, BasicAuthenticationSecretParser>();
    builder.Services.AddTransient<ISecretParser, PostBodySecretParser>();

    return builder;
}

/// <summary>
/// Adds the default secret validators.
/// </summary>
/// <param name="builder">The builder.</param>
/// <returns></returns>
public static IIdentityServerBuilder AddDefaultSecretValidators(this IIdentityServerBuilder builder)
{
    builder.Services.AddTransient<ISecretValidator, HashedSharedSecretValidator>();

    return builder;
}
```

# IdentityServerOptions - 配置类
```csharp
 /// <summary>
/// The IdentityServerOptions class is the top level container for all configuration settings of IdentityServer.
/// </summary>
public class IdentityServerOptions
{
    /// <summary>
    /// Gets or sets the unique name of this server instance, e.g. https://myissuer.com.
    /// If not set, the issuer name is inferred from the request
    /// </summary>
    /// <value>
    /// Unique name of this server instance, e.g. https://myissuer.com
    /// </value>
    public string IssuerUri { get; set; }

    /// <summary>
    /// Gets or sets the origin of this server instance, e.g. https://myorigin.com.
    /// If not set, the origin name is inferred from the request
    /// Note: Do not set a URL or include a path.
    /// </summary>
    /// <value>
    /// Origin of this server instance, e.g. https://myorigin.com
    /// </value>
    public string PublicOrigin { get; set; }

    /// <summary>
    /// Gets or sets the value for the JWT typ header for access tokens.
    /// </summary>
    /// <value>
    /// The JWT typ value.
    /// </value>
    public string AccessTokenJwtType { get; set; } = "at+jwt";

    /// <summary>
    /// Emits an aud claim with the format issuer/resources. That's needed for some older access token validation plumbing. Defaults to false.
    /// </summary>
    public bool EmitLegacyResourceAudienceClaim { get; set; } = false;

    /// <summary>
    /// Gets or sets the endpoint configuration.
    /// </summary>
    /// <value>
    /// The endpoints configuration.
    /// </value>
    public EndpointsOptions Endpoints { get; set; } = new EndpointsOptions();

    /// <summary>
    /// Gets or sets the discovery endpoint configuration.
    /// </summary>
    /// <value>
    /// The discovery endpoint configuration.
    /// </value>
    public DiscoveryOptions Discovery { get; set; } = new DiscoveryOptions();

    /// <summary>
    /// Gets or sets the authentication options.
    /// </summary>
    /// <value>
    /// The authentication options.
    /// </value>
    public AuthenticationOptions Authentication { get; set; } = new AuthenticationOptions();

    /// <summary>
    /// Gets or sets the events options.
    /// </summary>
    /// <value>
    /// The events options.
    /// </value>
    public EventsOptions Events { get; set; } = new EventsOptions();

    /// <summary>
    /// Gets or sets the max input length restrictions.
    /// </summary>
    /// <value>
    /// The length restrictions.
    /// </value>
    public InputLengthRestrictions InputLengthRestrictions { get; set; } = new InputLengthRestrictions();

    /// <summary>
    /// Gets or sets the options for the user interaction.
    /// </summary>
    /// <value>
    /// The user interaction options.
    /// </value>
    public UserInteractionOptions UserInteraction { get; set; } = new UserInteractionOptions();

    /// <summary>
    /// Gets or sets the caching options.
    /// </summary>
    /// <value>
    /// The caching options.
    /// </value>
    public CachingOptions Caching { get; set; } = new CachingOptions();

    /// <summary>
    /// Gets or sets the cors options.
    /// </summary>
    /// <value>
    /// The cors options.
    /// </value>
    public CorsOptions Cors { get; set; } = new CorsOptions();

    /// <summary>
    /// Gets or sets the Content Security Policy options.
    /// </summary>
    public CspOptions Csp { get; set; } = new CspOptions();

    /// <summary>
    /// Gets or sets the validation options.
    /// </summary>
    public ValidationOptions Validation { get; set; } = new ValidationOptions();

    /// <summary>
    /// Gets or sets the device flow options.
    /// </summary>
    public DeviceFlowOptions DeviceFlow { get; set; } = new DeviceFlowOptions();

    /// <summary>
    /// Gets or sets the mutual TLS options.
    /// </summary>
    public MutualTlsOptions MutualTls { get; set; } = new MutualTlsOptions();
}
```
# UserIdentityServer - 中间件逻辑
- 执行校验
- BaseUrlMiddleware中间件：设置BaseUrl
- 配置CORS跨域：CorsPolicyProvider根据client信息生成动态策略
- IdentityServerMiddlewareOptions默认调用了UseAuthentication，所以如果使用IdentityServer不用重复注册Authentication中间件
- 使用MutualTlsTokenEndpointMiddleware中间件：要求客户端、服务端都使用https，默认不开启
- 使用IdentityServerMiddleware中间件：IEndpointRouter根据请求寻找匹配的IEndpointHandler，如果找到的话则由EndPointHandler处理请求。

```csharp
public static IApplicationBuilder UseIdentityServer(this IApplicationBuilder app, IdentityServerMiddlewareOptions options = null)
{
    app.Validate();

    app.UseMiddleware<BaseUrlMiddleware>();

    app.ConfigureCors();

    // it seems ok if we have UseAuthentication more than once in the pipeline --
    // this will just re-run the various callback handlers and the default authN 
    // handler, which just re-assigns the user on the context. claims transformation
    // will run twice, since that's not cached (whereas the authN handler result is)
    // related: https://github.com/aspnet/Security/issues/1399
    if (options == null) options = new IdentityServerMiddlewareOptions();
    options.AuthenticationMiddleware(app);

    app.UseMiddleware<MutualTlsTokenEndpointMiddleware>();
    app.UseMiddleware<IdentityServerMiddleware>();

    return app;
}
```

核心中间件IdentityServerMiddleware的代码，逻辑比较清晰
- IEndpointRouter路由类旬斋匹配接口
- 匹配接口处理请求返回结果IEndpointResult
- IEndpointResult执行结果，写入上下文，返回报文
```csharp
 public async Task Invoke(HttpContext context, IEndpointRouter router, IUserSession session, IEventService events)
{
    // this will check the authentication session and from it emit the check session
    // cookie needed from JS-based signout clients.
    await session.EnsureSessionIdCookieAsync();

    try
    {
        var endpoint = router.Find(context);
        if (endpoint != null)
        {
            _logger.LogInformation("Invoking IdentityServer endpoint: {endpointType} for {url}", endpoint.GetType().FullName, context.Request.Path.ToString());

            var result = await endpoint.ProcessAsync(context);

            if (result != null)
            {
                _logger.LogTrace("Invoking result: {type}", result.GetType().FullName);
                await result.ExecuteAsync(context);
            }

            return;
        }
    }
    catch (Exception ex)
    {
        await events.RaiseAsync(new UnhandledExceptionEvent(ex));
        _logger.LogCritical(ex, "Unhandled exception: {exception}", ex.Message);
        throw;
    }

    await _next(context);
}
```

看一下路由类的处理逻辑  
之前AddDefaultEndpoints注入了所有默认接口，路由类可以通过依赖注入拿到所有接口信息，将请求地址与接口地址对比得到匹配的接口，然后从容器拿到对应的接口处理器。
```csharp
public EndpointRouter(IEnumerable<Endpoint> endpoints, IdentityServerOptions options, ILogger<EndpointRouter> logger)
{
    _endpoints = endpoints;
    _options = options;
    _logger = logger;
}

public IEndpointHandler Find(HttpContext context)
{
    if (context == null) throw new ArgumentNullException(nameof(context));

    foreach(var endpoint in _endpoints)
    {
        var path = endpoint.Path;
        if (context.Request.Path.Equals(path, StringComparison.OrdinalIgnoreCase))
        {
            var endpointName = endpoint.Name;
            _logger.LogDebug("Request path {path} matched to endpoint type {endpoint}", context.Request.Path, endpointName);

            return GetEndpointHandler(endpoint, context);
        }
    }

    _logger.LogTrace("No endpoint entry found for request path: {path}", context.Request.Path);

    return null;
}

 private IEndpointHandler GetEndpointHandler(Endpoint endpoint, HttpContext context)
{
    if (_options.Endpoints.IsEndpointEnabled(endpoint))
    {
        var handler = context.RequestServices.GetService(endpoint.Handler) as IEndpointHandler;
        if (handler != null)
        {
            _logger.LogDebug("Endpoint enabled: {endpoint}, successfully created handler: {endpointHandler}", endpoint.Name, endpoint.Handler.FullName);
            return handler;
        }
        else
        {
            _logger.LogDebug("Endpoint enabled: {endpoint}, failed to create handler: {endpointHandler}", endpoint.Name, endpoint.Handler.FullName);
        }
    }
    else
    {
        _logger.LogWarning("Endpoint disabled: {endpoint}", endpoint.Name);
    }

    return null;
}
```

# 总结
主干流程大致如图
<div class="mermaid">
graph TD;
    A([注入EndPoints]);
    B(客户端https请求)-->C(EndPointRouter寻找匹配接口);
    C-->D(从容器中得到接口对应的处理器类IEndPointHandler)
    D-->E(IEndPointHandler处理完毕返回IEndPointResult)
    E-->F([IEndPointResult执行完毕返回报文])
</div>
<script src="https://unpkg.com/mermaid/dist/mermaid.min.js"></script>

idsv的代码量还是比较大的，有很多的类，但是代码还是要写的挺规范清晰，梳理下来脉络还是很明了的。
