---
title: "AspNetCore3.1_Secutiry源码解析_6_Authentication_OpenIdConnect"
date: 2020-03-25T21:33:12+08:00
draft: false
---

# oidc简介
oidc是基于oauth2.0的上层协议。

OAuth有点像卖电影票的，只关心用户能不能进电影院，不关心用户是谁。而oidc则像身份证，扫描就可以上飞机，一次扫描，机场不仅能知道你是否能上飞机，还可以知道你的身份信息。
  
oidc兼容OAuth2.0, 可以实现跨顶级域的SSO(单点登录、登出)，下个系列要学习的IdentityServer4就是对oidc协议族的一个具体实现框架。

更多理论知识看下面的参考资料，本系列主要过下源码脉络

博客园
> https://www.cnblogs.com/linianhui/p/openid-connect-core.html  

协议  
> https://openid.net/connect/

# 依赖注入

默认架构名称是OpenIdConnect，处理器类是OpenIdConnectHandler，配置类是OpenIdConnectOptions

```csharp
public static AuthenticationBuilder AddOpenIdConnect(this AuthenticationBuilder builder)
        => builder.AddOpenIdConnect(OpenIdConnectDefaults.AuthenticationScheme, _ => { });

    public static AuthenticationBuilder AddOpenIdConnect(this AuthenticationBuilder builder, Action<OpenIdConnectOptions> configureOptions)
        => builder.AddOpenIdConnect(OpenIdConnectDefaults.AuthenticationScheme, configureOptions);

    public static AuthenticationBuilder AddOpenIdConnect(this AuthenticationBuilder builder, string authenticationScheme, Action<OpenIdConnectOptions> configureOptions)
        => builder.AddOpenIdConnect(authenticationScheme, OpenIdConnectDefaults.DisplayName, configureOptions);

    public static AuthenticationBuilder AddOpenIdConnect(this AuthenticationBuilder builder, string authenticationScheme, string displayName, Action<OpenIdConnectOptions> configureOptions)
    {
        builder.Services.TryAddEnumerable(ServiceDescriptor.Singleton<IPostConfigureOptions<OpenIdConnectOptions>, OpenIdConnectPostConfigureOptions>());
        return builder.AddRemoteScheme<OpenIdConnectOptions, OpenIdConnectHandler>(authenticationScheme, displayName, configureOptions);
    }
```

# 配置类 - OpenIdConnectOptions
## 构造函数
CallbackPath: 回调地址，即远程认证之后跳回的地址  
SignedOutCallbackPath：登出后的回调地址  
RemoteSignOutPath：远程登出地址  

scope添加openid（用户id）,profile（用户基本信息），所以如果client没有这两个基本的权限是会被远程认证拒绝的。  

删除了nonce,aud等claim，添加了sub(用户id,必须有),name,profile,email等claim。MapUniqueJsonKey方法的意思是如果某claim无值，远程认证服务返回的用户json数据中中存在此key且有值，则将值插入claim中，否则什么也不做。  

然后new了防重放攻击的nonce cookie。

```csharp
public OpenIdConnectOptions()
{
    CallbackPath = new PathString("/signin-oidc");
    SignedOutCallbackPath = new PathString("/signout-callback-oidc");
    RemoteSignOutPath = new PathString("/signout-oidc");

    Events = new OpenIdConnectEvents();
    Scope.Add("openid");
    Scope.Add("profile");

    ClaimActions.DeleteClaim("nonce");
    ClaimActions.DeleteClaim("aud");
    ClaimActions.DeleteClaim("azp");
    ClaimActions.DeleteClaim("acr");
    ClaimActions.DeleteClaim("iss");
    ClaimActions.DeleteClaim("iat");
    ClaimActions.DeleteClaim("nbf");
    ClaimActions.DeleteClaim("exp");
    ClaimActions.DeleteClaim("at_hash");
    ClaimActions.DeleteClaim("c_hash");
    ClaimActions.DeleteClaim("ipaddr");
    ClaimActions.DeleteClaim("platf");
    ClaimActions.DeleteClaim("ver");

    // http://openid.net/specs/openid-connect-core-1_0.html#StandardClaims
    ClaimActions.MapUniqueJsonKey("sub", "sub");
    ClaimActions.MapUniqueJsonKey("name", "name");
    ClaimActions.MapUniqueJsonKey("given_name", "given_name");
    ClaimActions.MapUniqueJsonKey("family_name", "family_name");
    ClaimActions.MapUniqueJsonKey("profile", "profile");
    ClaimActions.MapUniqueJsonKey("email", "email");

    _nonceCookieBuilder = new OpenIdConnectNonceCookieBuilder(this)
    {
        Name = OpenIdConnectDefaults.CookieNoncePrefix,
        HttpOnly = true,
        SameSite = SameSiteMode.None,
        SecurePolicy = CookieSecurePolicy.SameAsRequest,
        IsEssential = true,
    };
}
```
## 配置校验 - Validate

父类RemoteAuthenticationOptions会校验SignInSchema不允许与当前Schema相同（SignInSchema微软只提供了Cookie的实现，登录似乎除了Cookie没有别的方式可以维持登录态？）  

校验max-age不能为负数  

ClientId不能为空  

CallbackPath必须有值   

ConfigurationManager不能为null

```csharp
public override void Validate()
{
    base.Validate();

    if (MaxAge.HasValue && MaxAge.Value < TimeSpan.Zero)
    {
        throw new ArgumentOutOfRangeException(nameof(MaxAge), MaxAge.Value, "The value must not be a negative TimeSpan.");
    }

    if (string.IsNullOrEmpty(ClientId))
    {
        throw new ArgumentException("Options.ClientId must be provided", nameof(ClientId));
    }

    if (!CallbackPath.HasValue)
    {
        throw new ArgumentException("Options.CallbackPath must be provided.", nameof(CallbackPath));
    }

    if (ConfigurationManager == null)
    {
        throw new InvalidOperationException($"Provide {nameof(Authority)}, {nameof(MetadataAddress)}, "
        + $"{nameof(Configuration)}, or {nameof(ConfigurationManager)} to {nameof(OpenIdConnectOptions)}");
    }
}
```

## 属性
```csharp
/// <summary>
/// Gets or sets timeout value in milliseconds for back channel communications with the remote identity provider.
/// </summary>
/// <value>
/// The back channel timeout.
/// </value>
public TimeSpan BackchannelTimeout { get; set; } = TimeSpan.FromSeconds(60);

/// <summary>
/// The HttpMessageHandler used to communicate with remote identity provider.
/// This cannot be set at the same time as BackchannelCertificateValidator unless the value 
/// can be downcast to a WebRequestHandler.
/// </summary>
public HttpMessageHandler BackchannelHttpHandler { get; set; }

/// <summary>
/// Used to communicate with the remote identity provider.
/// </summary>
public HttpClient Backchannel { get; set; }

/// <summary>
/// Gets or sets the type used to secure data.
/// </summary>
public IDataProtectionProvider DataProtectionProvider { get; set; }

/// <summary>
/// The request path within the application's base path where the user-agent will be returned.
/// The middleware will process this request when it arrives.
/// </summary>
public PathString CallbackPath { get; set; }

/// <summary>
/// Gets or sets the optional path the user agent is redirected to if the user
/// doesn't approve the authorization demand requested by the remote server.
/// This property is not set by default. In this case, an exception is thrown
/// if an access_denied response is returned by the remote authorization server.
/// </summary>
public PathString AccessDeniedPath { get; set; }

/// <summary>
/// Gets or sets the name of the parameter used to convey the original location
/// of the user before the remote challenge was triggered up to the access denied page.
/// This property is only used when the <see cref="AccessDeniedPath"/> is explicitly specified.
/// </summary>
// Note: this deliberately matches the default parameter name used by the cookie handler.
public string ReturnUrlParameter { get; set; } = "ReturnUrl";

/// <summary>
/// Gets or sets the authentication scheme corresponding to the middleware
/// responsible of persisting user's identity after a successful authentication.
/// This value typically corresponds to a cookie middleware registered in the Startup class.
/// When omitted, <see cref="AuthenticationOptions.DefaultSignInScheme"/> is used as a fallback value.
/// </summary>
public string SignInScheme { get; set; }

/// <summary>
/// Gets or sets the time limit for completing the authentication flow (15 minutes by default).
/// </summary>
public TimeSpan RemoteAuthenticationTimeout { get; set; } = TimeSpan.FromMinutes(15);

public new RemoteAuthenticationEvents Events
{
    get => (RemoteAuthenticationEvents)base.Events;
    set => base.Events = value;
}

/// <summary>
/// Defines whether access and refresh tokens should be stored in the
/// <see cref="AuthenticationProperties"/> after a successful authorization.
/// This property is set to <c>false</c> by default to reduce
/// the size of the final authentication cookie.
/// </summary>
public bool SaveTokens { get; set; }

/// <summary>
/// Determines the settings used to create the correlation cookie before the
/// cookie gets added to the response.
/// </summary>
public CookieBuilder CorrelationCookie
{
    get => _correlationCookieBuilder;
    set => _correlationCookieBuilder = value ?? throw new ArgumentNullException(nameof(value));
}
```

## 配置后处理逻辑 - OpenIdConnectPostConfigureOptions

主要处理如果DataProtectionProvider，StateDataFormat等对象没有配置的话，则构造默认实现类。options.MetadataAddress += ".well-known/openid-configuration"，这是配置的元数据地址，描述了oidc的所有接口地址和其他信息。

```csharp
public class OpenIdConnectPostConfigureOptions : IPostConfigureOptions<OpenIdConnectOptions>
{
    private readonly IDataProtectionProvider _dp;

    public OpenIdConnectPostConfigureOptions(IDataProtectionProvider dataProtection)
    {
        _dp = dataProtection;
    }

    /// <summary>
    /// Invoked to post configure a TOptions instance.
    /// </summary>
    /// <param name="name">The name of the options instance being configured.</param>
    /// <param name="options">The options instance to configure.</param>
    public void PostConfigure(string name, OpenIdConnectOptions options)
    {
        options.DataProtectionProvider = options.DataProtectionProvider ?? _dp;

        if (string.IsNullOrEmpty(options.SignOutScheme))
        {
            options.SignOutScheme = options.SignInScheme;
        }

        if (options.StateDataFormat == null)
        {
            var dataProtector = options.DataProtectionProvider.CreateProtector(
                typeof(OpenIdConnectHandler).FullName, name, "v1");
            options.StateDataFormat = new PropertiesDataFormat(dataProtector);
        }

        if (options.StringDataFormat == null)
        {
            var dataProtector = options.DataProtectionProvider.CreateProtector(
                typeof(OpenIdConnectHandler).FullName,
                typeof(string).FullName,
                name,
                "v1");

            options.StringDataFormat = new SecureDataFormat<string>(new StringSerializer(), dataProtector);
        }

        if (string.IsNullOrEmpty(options.TokenValidationParameters.ValidAudience) && !string.IsNullOrEmpty(options.ClientId))
        {
            options.TokenValidationParameters.ValidAudience = options.ClientId;
        }

        if (options.Backchannel == null)
        {
            options.Backchannel = new HttpClient(options.BackchannelHttpHandler ?? new HttpClientHandler());
            options.Backchannel.DefaultRequestHeaders.UserAgent.ParseAdd("Microsoft ASP.NET Core OpenIdConnect handler");
            options.Backchannel.Timeout = options.BackchannelTimeout;
            options.Backchannel.MaxResponseContentBufferSize = 1024 * 1024 * 10; // 10 MB
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

                options.ConfigurationManager = new ConfigurationManager<OpenIdConnectConfiguration>(options.MetadataAddress, new OpenIdConnectConfigurationRetriever(),
                    new HttpDocumentRetriever(options.Backchannel) { RequireHttps = options.RequireHttpsMetadata });
            }
        }
    }

    private class StringSerializer : IDataSerializer<string>
    {
        public string Deserialize(byte[] data)
        {
            return Encoding.UTF8.GetString(data);
        }

        public byte[] Serialize(string model)
        {
            return Encoding.UTF8.GetBytes(model);
        }
    }
```

# 处理器类 -  OpenIdConnectHandler
## 处理认证 - HandRemoteAuthenticate
```csharp
/// <summary>
/// Invoked to process incoming OpenIdConnect messages.
/// </summary>
/// <returns>An <see cref="HandleRequestResult"/>.</returns>
protected override async Task<HandleRequestResult> HandleRemoteAuthenticateAsync()
{
    Logger.EnteringOpenIdAuthenticationHandlerHandleRemoteAuthenticateAsync(GetType().FullName);

    OpenIdConnectMessage authorizationResponse = null;

    if (string.Equals(Request.Method, "GET", StringComparison.OrdinalIgnoreCase))
    {
        authorizationResponse = new OpenIdConnectMessage(Request.Query.Select(pair => new KeyValuePair<string, string[]>(pair.Key, pair.Value)));

        // response_mode=query (explicit or not) and a response_type containing id_token
        // or token are not considered as a safe combination and MUST be rejected.
        // See http://openid.net/specs/oauth-v2-multiple-response-types-1_0.html#Security
        if (!string.IsNullOrEmpty(authorizationResponse.IdToken) || !string.IsNullOrEmpty(authorizationResponse.AccessToken))
        {
            if (Options.SkipUnrecognizedRequests)
            {
                // Not for us?
                return HandleRequestResult.SkipHandler();
            }
            return HandleRequestResult.Fail("An OpenID Connect response cannot contain an " +
                    "identity token or an access token when using response_mode=query");
        }
    }
    // assumption: if the ContentType is "application/x-www-form-urlencoded" it should be safe to read as it is small.
    else if (string.Equals(Request.Method, "POST", StringComparison.OrdinalIgnoreCase)
        && !string.IsNullOrEmpty(Request.ContentType)
        // May have media/type; charset=utf-8, allow partial match.
        && Request.ContentType.StartsWith("application/x-www-form-urlencoded", StringComparison.OrdinalIgnoreCase)
        && Request.Body.CanRead)
    {
        var form = await Request.ReadFormAsync();
        authorizationResponse = new OpenIdConnectMessage(form.Select(pair => new KeyValuePair<string, string[]>(pair.Key, pair.Value)));
    }

    if (authorizationResponse == null)
    {
        if (Options.SkipUnrecognizedRequests)
        {
            // Not for us?
            return HandleRequestResult.SkipHandler();
        }
        return HandleRequestResult.Fail("No message.");
    }

    AuthenticationProperties properties = null;
    try
    {
        properties = ReadPropertiesAndClearState(authorizationResponse);

        var messageReceivedContext = await RunMessageReceivedEventAsync(authorizationResponse, properties);
        if (messageReceivedContext.Result != null)
        {
            return messageReceivedContext.Result;
        }
        authorizationResponse = messageReceivedContext.ProtocolMessage;
        properties = messageReceivedContext.Properties;

        if (properties == null || properties.Items.Count == 0)
        {
            // Fail if state is missing, it's required for the correlation id.
            if (string.IsNullOrEmpty(authorizationResponse.State))
            {
                // This wasn't a valid OIDC message, it may not have been intended for us.
                Logger.NullOrEmptyAuthorizationResponseState();
                if (Options.SkipUnrecognizedRequests)
                {
                    return HandleRequestResult.SkipHandler();
                }
                return HandleRequestResult.Fail(Resources.MessageStateIsNullOrEmpty);
            }

            properties = ReadPropertiesAndClearState(authorizationResponse);
        }

        if (properties == null)
        {
            Logger.UnableToReadAuthorizationResponseState();
            if (Options.SkipUnrecognizedRequests)
            {
                // Not for us?
                return HandleRequestResult.SkipHandler();
            }

            // if state exists and we failed to 'unprotect' this is not a message we should process.
            return HandleRequestResult.Fail(Resources.MessageStateIsInvalid);
        }

        if (!ValidateCorrelationId(properties))
        {
            return HandleRequestResult.Fail("Correlation failed.", properties);
        }

        // if any of the error fields are set, throw error null
        if (!string.IsNullOrEmpty(authorizationResponse.Error))
        {
            // Note: access_denied errors are special protocol errors indicating the user didn't
            // approve the authorization demand requested by the remote authorization server.
            // Since it's a frequent scenario (that is not caused by incorrect configuration),
            // denied errors are handled differently using HandleAccessDeniedErrorAsync().
            // Visit https://tools.ietf.org/html/rfc6749#section-4.1.2.1 for more information.
            if (string.Equals(authorizationResponse.Error, "access_denied", StringComparison.Ordinal))
            {
                var result = await HandleAccessDeniedErrorAsync(properties);
                if (!result.None)
                {
                    return result;
                }
            }

            return HandleRequestResult.Fail(CreateOpenIdConnectProtocolException(authorizationResponse, response: null), properties);
        }

        if (_configuration == null && Options.ConfigurationManager != null)
        {
            Logger.UpdatingConfiguration();
            _configuration = await Options.ConfigurationManager.GetConfigurationAsync(Context.RequestAborted);
        }

        PopulateSessionProperties(authorizationResponse, properties);

        ClaimsPrincipal user = null;
        JwtSecurityToken jwt = null;
        string nonce = null;
        var validationParameters = Options.TokenValidationParameters.Clone();

        // Hybrid or Implicit flow
        if (!string.IsNullOrEmpty(authorizationResponse.IdToken))
        {
            Logger.ReceivedIdToken();
            user = ValidateToken(authorizationResponse.IdToken, properties, validationParameters, out jwt);

            nonce = jwt.Payload.Nonce;
            if (!string.IsNullOrEmpty(nonce))
            {
                nonce = ReadNonceCookie(nonce);
            }

            var tokenValidatedContext = await RunTokenValidatedEventAsync(authorizationResponse, null, user, properties, jwt, nonce);
            if (tokenValidatedContext.Result != null)
            {
                return tokenValidatedContext.Result;
            }
            authorizationResponse = tokenValidatedContext.ProtocolMessage;
            user = tokenValidatedContext.Principal;
            properties = tokenValidatedContext.Properties;
            jwt = tokenValidatedContext.SecurityToken;
            nonce = tokenValidatedContext.Nonce;
        }

        Options.ProtocolValidator.ValidateAuthenticationResponse(new OpenIdConnectProtocolValidationContext()
        {
            ClientId = Options.ClientId,
            ProtocolMessage = authorizationResponse,
            ValidatedIdToken = jwt,
            Nonce = nonce
        });

        OpenIdConnectMessage tokenEndpointResponse = null;

        // Authorization Code or Hybrid flow
        if (!string.IsNullOrEmpty(authorizationResponse.Code))
        {
            var authorizationCodeReceivedContext = await RunAuthorizationCodeReceivedEventAsync(authorizationResponse, user, properties, jwt);
            if (authorizationCodeReceivedContext.Result != null)
            {
                return authorizationCodeReceivedContext.Result;
            }
            authorizationResponse = authorizationCodeReceivedContext.ProtocolMessage;
            user = authorizationCodeReceivedContext.Principal;
            properties = authorizationCodeReceivedContext.Properties;
            var tokenEndpointRequest = authorizationCodeReceivedContext.TokenEndpointRequest;
            // If the developer redeemed the code themselves...
            tokenEndpointResponse = authorizationCodeReceivedContext.TokenEndpointResponse;
            jwt = authorizationCodeReceivedContext.JwtSecurityToken;

            if (!authorizationCodeReceivedContext.HandledCodeRedemption)
            {
                tokenEndpointResponse = await RedeemAuthorizationCodeAsync(tokenEndpointRequest);
            }

            var tokenResponseReceivedContext = await RunTokenResponseReceivedEventAsync(authorizationResponse, tokenEndpointResponse, user, properties);
            if (tokenResponseReceivedContext.Result != null)
            {
                return tokenResponseReceivedContext.Result;
            }

            authorizationResponse = tokenResponseReceivedContext.ProtocolMessage;
            tokenEndpointResponse = tokenResponseReceivedContext.TokenEndpointResponse;
            user = tokenResponseReceivedContext.Principal;
            properties = tokenResponseReceivedContext.Properties;

            // no need to validate signature when token is received using "code flow" as per spec
            // [http://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation].
            validationParameters.RequireSignedTokens = false;

            // At least a cursory validation is required on the new IdToken, even if we've already validated the one from the authorization response.
            // And we'll want to validate the new JWT in ValidateTokenResponse.
            var tokenEndpointUser = ValidateToken(tokenEndpointResponse.IdToken, properties, validationParameters, out var tokenEndpointJwt);

            // Avoid reading & deleting the nonce cookie, running the event, etc, if it was already done as part of the authorization response validation.
            if (user == null)
            {
                nonce = tokenEndpointJwt.Payload.Nonce;
                if (!string.IsNullOrEmpty(nonce))
                {
                    nonce = ReadNonceCookie(nonce);
                }

                var tokenValidatedContext = await RunTokenValidatedEventAsync(authorizationResponse, tokenEndpointResponse, tokenEndpointUser, properties, tokenEndpointJwt, nonce);
                if (tokenValidatedContext.Result != null)
                {
                    return tokenValidatedContext.Result;
                }
                authorizationResponse = tokenValidatedContext.ProtocolMessage;
                tokenEndpointResponse = tokenValidatedContext.TokenEndpointResponse;
                user = tokenValidatedContext.Principal;
                properties = tokenValidatedContext.Properties;
                jwt = tokenValidatedContext.SecurityToken;
                nonce = tokenValidatedContext.Nonce;
            }
            else
            {
                if (!string.Equals(jwt.Subject, tokenEndpointJwt.Subject, StringComparison.Ordinal))
                {
                    throw new SecurityTokenException("The sub claim does not match in the id_token's from the authorization and token endpoints.");
                }

                jwt = tokenEndpointJwt;
            }

            // Validate the token response if it wasn't provided manually
            if (!authorizationCodeReceivedContext.HandledCodeRedemption)
            {
                Options.ProtocolValidator.ValidateTokenResponse(new OpenIdConnectProtocolValidationContext()
                {
                    ClientId = Options.ClientId,
                    ProtocolMessage = tokenEndpointResponse,
                    ValidatedIdToken = jwt,
                    Nonce = nonce
                });
            }
        }

        if (Options.SaveTokens)
        {
            SaveTokens(properties, tokenEndpointResponse ?? authorizationResponse);
        }

        if (Options.GetClaimsFromUserInfoEndpoint)
        {
            return await GetUserInformationAsync(tokenEndpointResponse ?? authorizationResponse, jwt, user, properties);
        }
        else
        {
            using (var payload = JsonDocument.Parse("{}"))
            {
                var identity = (ClaimsIdentity)user.Identity;
                foreach (var action in Options.ClaimActions)
                {
                    action.Run(payload.RootElement, identity, ClaimsIssuer);
                }
            }
        }

        return HandleRequestResult.Success(new AuthenticationTicket(user, properties, Scheme.Name));
    }
    catch (Exception exception)
    {
        Logger.ExceptionProcessingMessage(exception);

        // Refresh the configuration for exceptions that may be caused by key rollovers. The user can also request a refresh in the event.
        if (Options.RefreshOnIssuerKeyNotFound && exception is SecurityTokenSignatureKeyNotFoundException)
        {
            if (Options.ConfigurationManager != null)
            {
                Logger.ConfigurationManagerRequestRefreshCalled();
                Options.ConfigurationManager.RequestRefresh();
            }
        }

        var authenticationFailedContext = await RunAuthenticationFailedEventAsync(authorizationResponse, exception);
        if (authenticationFailedContext.Result != null)
        {
            return authenticationFailedContext.Result;
        }

        return HandleRequestResult.Fail(exception, properties);
    }
}
```


OpenIdConectHandler跟OAuthHandler一样，继承自RemoteAuthenticationHandler，但是OpenId还实现了IAuthenticationSignOutHandler接口，因为OpenId是支持单点登录登出的，本地登出之后需要通知认证服务远程登出（注销本地站点Cookie），这样实现帐号的同步登出（注销sso站点cookie）。

## 处理远程登出 - HandleRemoteSignOutAsync

- 远程登出支持GET和Form-Post两种提交方式，客户端根据请求方式，将报文拼装好。
- 触发远程登出事件
- 使用SignOutScheme认证，得到身份信息 - Context.AuthenticateAsync(Options.SignOutScheme)
- Context.Proerties中必须有iss信息，issuer就是提供认证方
- 调用本地登出方法 - Context.SignOutAsync(Options.SignOutScheme)

```csharp
protected virtual async Task<bool> HandleRemoteSignOutAsync()
{
    OpenIdConnectMessage message = null;

    if (string.Equals(Request.Method, "GET", StringComparison.OrdinalIgnoreCase))
    {
        message = new OpenIdConnectMessage(Request.Query.Select(pair => new KeyValuePair<string, string[]>(pair.Key, pair.Value)));
    }

    // assumption: if the ContentType is "application/x-www-form-urlencoded" it should be safe to read as it is small.
    else if (string.Equals(Request.Method, "POST", StringComparison.OrdinalIgnoreCase)
        && !string.IsNullOrEmpty(Request.ContentType)
        // May have media/type; charset=utf-8, allow partial match.
        && Request.ContentType.StartsWith("application/x-www-form-urlencoded", StringComparison.OrdinalIgnoreCase)
        && Request.Body.CanRead)
    {
        var form = await Request.ReadFormAsync();
        message = new OpenIdConnectMessage(form.Select(pair => new KeyValuePair<string, string[]>(pair.Key, pair.Value)));
    }

    var remoteSignOutContext = new RemoteSignOutContext(Context, Scheme, Options, message);
    await Events.RemoteSignOut(remoteSignOutContext);

    if (remoteSignOutContext.Result != null)
    {
        if (remoteSignOutContext.Result.Handled)
        {
            Logger.RemoteSignOutHandledResponse();
            return true;
        }
        if (remoteSignOutContext.Result.Skipped)
        {
            Logger.RemoteSignOutSkipped();
            return false;
        }
        if (remoteSignOutContext.Result.Failure != null)
        {
            throw new InvalidOperationException("An error was returned from the RemoteSignOut event.", remoteSignOutContext.Result.Failure);
        }
    }

    if (message == null)
    {
        return false;
    }

    // Try to extract the session identifier from the authentication ticket persisted by the sign-in handler.
    // If the identifier cannot be found, bypass the session identifier checks: this may indicate that the
    // authentication cookie was already cleared, that the session identifier was lost because of a lossy
    // external/application cookie conversion or that the identity provider doesn't support sessions.
    var principal = (await Context.AuthenticateAsync(Options.SignOutScheme))?.Principal;

    var sid = principal?.FindFirst(JwtRegisteredClaimNames.Sid)?.Value;
    if (!string.IsNullOrEmpty(sid))
    {
        // Ensure a 'sid' parameter was sent by the identity provider.
        if (string.IsNullOrEmpty(message.Sid))
        {
            Logger.RemoteSignOutSessionIdMissing();
            return true;
        }
        // Ensure the 'sid' parameter corresponds to the 'sid' stored in the authentication ticket.
        if (!string.Equals(sid, message.Sid, StringComparison.Ordinal))
        {
            Logger.RemoteSignOutSessionIdInvalid();
            return true;
        }
    }

    var iss = principal?.FindFirst(JwtRegisteredClaimNames.Iss)?.Value;
    if (!string.IsNullOrEmpty(iss))
    {
        // Ensure a 'iss' parameter was sent by the identity provider.
        if (string.IsNullOrEmpty(message.Iss))
        {
            Logger.RemoteSignOutIssuerMissing();
            return true;
        }
        // Ensure the 'iss' parameter corresponds to the 'iss' stored in the authentication ticket.
        if (!string.Equals(iss, message.Iss, StringComparison.Ordinal))
        {
            Logger.RemoteSignOutIssuerInvalid();
            return true;
        }
    }

    Logger.RemoteSignOut();

    // We've received a remote sign-out request
    await Context.SignOutAsync(Options.SignOutScheme);
    return true;
}
```
## 处理本地登出 - Context.SignOutAsync(Options.SignOutScheme)

方法的注释：将用户重定向到身份认证站点登出。  

- ForwardXXX是所有认证配置项的基类，可以拦截使用自己配置的Scheme。  
- 构造要发送给oidc服务的报文，包括IssuerAddress（EndSessionEndpoint：即结束会话节点地址），PostLogoutRedirectUri（登出回跳地址）等。
- 构造RedirectUri（登录流程结束最终回到的地址）：优先使用HttpContext.Properties中的RedirectUri，然后使用配置中的SignedOutRedirectUri，最后使用请求源地址。
- 获取IdToken，放到登出请求中
- state字段加密后（包含了redirecturi等信息），放入请求消息
- 给oidc站点发送GET或者FormPost请求

```csharp
/// <summary>
/// Redirect user to the identity provider for sign out
/// </summary>
/// <returns>A task executing the sign out procedure</returns>
public async virtual Task SignOutAsync(AuthenticationProperties properties)
{
    var target = ResolveTarget(Options.ForwardSignOut);
    if (target != null)
    {
        await Context.SignOutAsync(target, properties);
        return;
    }

    properties = properties ?? new AuthenticationProperties();

    Logger.EnteringOpenIdAuthenticationHandlerHandleSignOutAsync(GetType().FullName);

    if (_configuration == null && Options.ConfigurationManager != null)
    {
        _configuration = await Options.ConfigurationManager.GetConfigurationAsync(Context.RequestAborted);
    }

    var message = new OpenIdConnectMessage()
    {
        EnableTelemetryParameters = !Options.DisableTelemetry,
        IssuerAddress = _configuration?.EndSessionEndpoint ?? string.Empty,

        // Redirect back to SigneOutCallbackPath first before user agent is redirected to actual post logout redirect uri
        PostLogoutRedirectUri = BuildRedirectUriIfRelative(Options.SignedOutCallbackPath)
    };

    // Get the post redirect URI.
    if (string.IsNullOrEmpty(properties.RedirectUri))
    {
        properties.RedirectUri = BuildRedirectUriIfRelative(Options.SignedOutRedirectUri);
        if (string.IsNullOrWhiteSpace(properties.RedirectUri))
        {
            properties.RedirectUri = OriginalPathBase + OriginalPath + Request.QueryString;
        }
    }
    Logger.PostSignOutRedirect(properties.RedirectUri);

    // Attach the identity token to the logout request when possible.
    message.IdTokenHint = await Context.GetTokenAsync(Options.SignOutScheme, OpenIdConnectParameterNames.IdToken);

    var redirectContext = new RedirectContext(Context, Scheme, Options, properties)
    {
        ProtocolMessage = message
    };

    await Events.RedirectToIdentityProviderForSignOut(redirectContext);
    if (redirectContext.Handled)
    {
        Logger.RedirectToIdentityProviderForSignOutHandledResponse();
        return;
    }

    message = redirectContext.ProtocolMessage;

    if (!string.IsNullOrEmpty(message.State))
    {
        properties.Items[OpenIdConnectDefaults.UserstatePropertiesKey] = message.State;
    }

    message.State = Options.StateDataFormat.Protect(properties);

    if (string.IsNullOrEmpty(message.IssuerAddress))
    {
        throw new InvalidOperationException("Cannot redirect to the end session endpoint, the configuration may be missing or invalid.");
    }

    if (Options.AuthenticationMethod == OpenIdConnectRedirectBehavior.RedirectGet)
    {
        var redirectUri = message.CreateLogoutRequestUrl();
        if (!Uri.IsWellFormedUriString(redirectUri, UriKind.Absolute))
        {
            Logger.InvalidLogoutQueryStringRedirectUrl(redirectUri);
        }

        Response.Redirect(redirectUri);
    }
    else if (Options.AuthenticationMethod == OpenIdConnectRedirectBehavior.FormPost)
    {
        var content = message.BuildFormPost();
        var buffer = Encoding.UTF8.GetBytes(content);

        Response.ContentLength = buffer.Length;
        Response.ContentType = "text/html;charset=UTF-8";

        // Emit Cache-Control=no-cache to prevent client caching.
        Response.Headers[HeaderNames.CacheControl] = "no-cache, no-store";
        Response.Headers[HeaderNames.Pragma] = "no-cache";
        Response.Headers[HeaderNames.Expires] = HeaderValueEpocDate;

        await Response.Body.WriteAsync(buffer, 0, buffer.Length);
    }
    else
    {
        throw new NotImplementedException($"An unsupported authentication method has been configured: {Options.AuthenticationMethod}");
    }

    Logger.AuthenticationSchemeSignedOut(Scheme.Name);
}
```

## oidc处理完后跳到回调地址 

oidc站点处理完登出请求之后（怎么处理的，应该是清除了oidc的cookie，或许回收了token？目前不清楚。后面看identitserver怎么实现的），回跳到callback地址，执行下面的callback方法  

callback方法很简单，就是将state字段解码，将redirect_uri拿到，然后跳过去。

```csharp
/// <summary>
/// Response to the callback from OpenId provider after session ended.
/// </summary>
/// <returns>A task executing the callback procedure</returns>
protected async virtual Task<bool> HandleSignOutCallbackAsync()
{
    var message = new OpenIdConnectMessage(Request.Query.Select(pair => new KeyValuePair<string, string[]>(pair.Key, pair.Value)));
    AuthenticationProperties properties = null;
    if (!string.IsNullOrEmpty(message.State))
    {
        properties = Options.StateDataFormat.Unprotect(message.State);
    }

    var signOut = new RemoteSignOutContext(Context, Scheme, Options, message)
    {
        Properties = properties,
    };

    await Events.SignedOutCallbackRedirect(signOut);
    if (signOut.Result != null)
    {
        if (signOut.Result.Handled)
        {
            Logger.SignOutCallbackRedirectHandledResponse();
            return true;
        }
        if (signOut.Result.Skipped)
        {
            Logger.SignOutCallbackRedirectSkipped();
            return false;
        }
        if (signOut.Result.Failure != null)
        {
            throw new InvalidOperationException("An error was returned from the SignedOutCallbackRedirect event.", signOut.Result.Failure);
        }
    }

    properties = signOut.Properties;
    if (!string.IsNullOrEmpty(properties?.RedirectUri))
    {
        Response.Redirect(properties.RedirectUri);
    }

    return true;
}
```

## 登出时序图

<div class="mermaid">
sequenceDiagram
    mysite->>sso: GET/FormPost mysite/connect/endsession?params...
    sso->>mysite: 302,移除sso站点cookie,回调到signout-callback地址
    mysite->>mysite: 从state中解析redirect_uri,回跳redirect_uri
</div>
<script src="https://unpkg.com/mermaid/dist/mermaid.min.js"></script>

可以看到，oidc的登出只处理了oidc认证站点的cookie，mysite本地的cookie是没有处理的，因为当前schema是OpenIdConnnect，本地Cookie是SignInSchema的事情，所以登出需要掉两次SignOut方法
```
HttpContext.SignOutAsync("Cookies"); //清除本地cookie
HttpContext.SignOutAsync("OpenIdConnect") //清除远程sso站点cookie
```








