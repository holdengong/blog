---
title: "AspNetCore3.1_Secutiry源码解析_5_Authentication_OAuth"
date: 2020-03-24T23:27:45+08:00
draft: false
---
{{%security_menu%}}

# OAuth简介
现在随便一个网站，不用注册，只用微信扫一扫，然后就可以自动登录，然后第三方网站右上角还出现了你的微信头像和昵称，怎么做到的？
<div class="mermaid">
sequenceDiagram
    用户->>x站点: 请求微信登录
    x站点->>微信: 请求 oauth token
    微信->>用户: x站点请求基本资料权限,是否同意?
    用户->>微信: 同意
    微信->>x站点: token
    x站点->>微信: 请求user基本资料(token)
    微信->微信: 校验token
    微信->>x站点: user基本资料
</div>
<script src="https://unpkg.com/mermaid/dist/mermaid.min.js"></script>

大概就这么个意思，OAuth可以让第三方获取有限的授权去获取资源。

入门的看博客
> https://www.cnblogs.com/linianhui/p/oauth2-authorization.html

英文好有基础的直接看协议
> https://tools.ietf.org/html/rfc6749

# 依赖注入

配置类：OAuthOptions  
处理器类： OAuthHandler

```csharp
public static class OAuthExtensions
{
    public static AuthenticationBuilder AddOAuth(this AuthenticationBuilder builder, string authenticationScheme, Action<OAuthOptions> configureOptions)
        => builder.AddOAuth<OAuthOptions, OAuthHandler<OAuthOptions>>(authenticationScheme, configureOptions);

    public static AuthenticationBuilder AddOAuth(this AuthenticationBuilder builder, string authenticationScheme, string displayName, Action<OAuthOptions> configureOptions)
        => builder.AddOAuth<OAuthOptions, OAuthHandler<OAuthOptions>>(authenticationScheme, displayName, configureOptions);

    public static AuthenticationBuilder AddOAuth<TOptions, THandler>(this AuthenticationBuilder builder, string authenticationScheme, Action<TOptions> configureOptions)
        where TOptions : OAuthOptions, new()
        where THandler : OAuthHandler<TOptions>
        => builder.AddOAuth<TOptions, THandler>(authenticationScheme, OAuthDefaults.DisplayName, configureOptions);

    public static AuthenticationBuilder AddOAuth<TOptions, THandler>(this AuthenticationBuilder builder, string authenticationScheme, string displayName, Action<TOptions> configureOptions)
        where TOptions : OAuthOptions, new()
        where THandler : OAuthHandler<TOptions>
    {
        builder.Services.TryAddEnumerable(ServiceDescriptor.Singleton<IPostConfigureOptions<TOptions>, OAuthPostConfigureOptions<TOptions, THandler>>());
        return builder.AddRemoteScheme<TOptions, THandler>(authenticationScheme, displayName, configureOptions);
    }
}
```
## OAuthOptions - 配置类
<div class="mermaid">
 classDiagram
      class OAuthOptions{
          ClientId
          ClientSecret
          AuthorizationEndpoint
          TokenEndPoint
          UserInformationEndPoint
          Scope
          Events
          ClaimActions
          StateDataFormat
      }
      class RemoteAuthenticationOptions{
          BackchannelTimeout
          BackchannelHttpHandler
          Backchannel
          DataProtectionProvider
          CallbackPath
          AccessDeniedPath
          ReturnUrlParameter
          SignInScheme
          RemoteAuthenticationTimeout
          SaveTokens
      }
      class AuthenticationSchemeOptions{
      }
      OAuthOptions-->RemoteAuthenticationOptions
      RemoteAuthenticationOptions-->AuthenticationSchemeOptions
</div>

下面是校验逻辑，这些配置是必需的。

```csharp
public override void Validate()
{
    base.Validate();

    if (string.IsNullOrEmpty(ClientId))
    {
        throw new ArgumentException(string.Format(CultureInfo.CurrentCulture, Resources.Exception_OptionMustBeProvided, nameof(ClientId)), nameof(ClientId));
    }

    if (string.IsNullOrEmpty(ClientSecret))
    {
        throw new ArgumentException(string.Format(CultureInfo.CurrentCulture, Resources.Exception_OptionMustBeProvided, nameof(ClientSecret)), nameof(ClientSecret));
    }

    if (string.IsNullOrEmpty(AuthorizationEndpoint))
    {
        throw new ArgumentException(string.Format(CultureInfo.CurrentCulture, Resources.Exception_OptionMustBeProvided, nameof(AuthorizationEndpoint)), nameof(AuthorizationEndpoint));
    }

    if (string.IsNullOrEmpty(TokenEndpoint))
    {
        throw new ArgumentException(string.Format(CultureInfo.CurrentCulture, Resources.Exception_OptionMustBeProvided, nameof(TokenEndpoint)), nameof(TokenEndpoint));
    }

    if (!CallbackPath.HasValue)
    {
        throw new ArgumentException(string.Format(CultureInfo.CurrentCulture, Resources.Exception_OptionMustBeProvided, nameof(CallbackPath)), nameof(CallbackPath));
    }
}
```

## OAuthPostConfigureOptions - 配置处理

1. DataProtectionProvider没有配置的话则使用默认实现
2. Backchannel没有配置的话则处理构造默认配置
3. StateDataFormat没有配置的话则使用PropertiesDataFormat

```csharp
public void PostConfigure(string name, TOptions options)
{
    options.DataProtectionProvider = options.DataProtectionProvider ?? _dp;
    if (options.Backchannel == null)
    {
        options.Backchannel = new HttpClient(options.BackchannelHttpHandler ?? new HttpClientHandler());
        options.Backchannel.DefaultRequestHeaders.UserAgent.ParseAdd("Microsoft ASP.NET Core OAuth handler");
        options.Backchannel.Timeout = options.BackchannelTimeout;
        options.Backchannel.MaxResponseContentBufferSize = 1024 * 1024 * 10; // 10 MB
    }

    if (options.StateDataFormat == null)
    {
        var dataProtector = options.DataProtectionProvider.CreateProtector(
            typeof(THandler).FullName, name, "v1");
        options.StateDataFormat = new PropertiesDataFormat(dataProtector);
    }
}
```

这个StateDataFormat就是处理state字段的加密解密的，state在认证过程中用于防止跨站伪造攻击和存放一些状态信息，我们看一下协议的定义
```
 state
         RECOMMENDED.  An opaque value used by the client to maintain
         state between the request and callback.  The authorization
         server includes this value when redirecting the user-agent back
         to the client.  The parameter SHOULD be used for preventing
         cross-site request forgery as described in Section 10.12.

```

比如，认证之后的回跳地址就是存放在这里。所以如果希望从state字段中解密得到信息的话，就需要使用到PropertiesDataFormat。PropertiesDataFormat没有任何代码，继承自SecureDataFormat。 为什么这里介绍这么多呢，因为实际项目中用到过这个。
```csharp
public class SecureDataFormat<TData> : ISecureDataFormat<TData>
{
    private readonly IDataSerializer<TData> _serializer;
    private readonly IDataProtector _protector;

    public SecureDataFormat(IDataSerializer<TData> serializer, IDataProtector protector)
    {
        _serializer = serializer;
        _protector = protector;
    }

    public string Protect(TData data)
    {
        return Protect(data, purpose: null);
    }

    public string Protect(TData data, string purpose)
    {
        var userData = _serializer.Serialize(data);

        var protector = _protector;
        if (!string.IsNullOrEmpty(purpose))
        {
            protector = protector.CreateProtector(purpose);
        }

        var protectedData = protector.Protect(userData);
        return Base64UrlTextEncoder.Encode(protectedData);
    }

    public TData Unprotect(string protectedText)
    {
        return Unprotect(protectedText, purpose: null);
    }

    public TData Unprotect(string protectedText, string purpose)
    {
        try
        {
            if (protectedText == null)
            {
                return default(TData);
            }

            var protectedData = Base64UrlTextEncoder.Decode(protectedText);
            if (protectedData == null)
            {
                return default(TData);
            }

            var protector = _protector;
            if (!string.IsNullOrEmpty(purpose))
            {
                protector = protector.CreateProtector(purpose);
            }

            var userData = protector.Unprotect(protectedData);
            if (userData == null)
            {
                return default(TData);
            }

            return _serializer.Deserialize(userData);
        }
        catch
        {
            // TODO trace exception, but do not leak other information
            return default(TData);
        }
    }
}
```

AddRemoteSchema和AddShema的差别就是做了下面的处理，确认始终有不是远程schema的SignInSchema
```csharp
private class EnsureSignInScheme<TOptions> : IPostConfigureOptions<TOptions> where TOptions : RemoteAuthenticationOptions
{
    private readonly AuthenticationOptions _authOptions;

    public EnsureSignInScheme(IOptions<AuthenticationOptions> authOptions)
    {
        _authOptions = authOptions.Value;
    }

    public void PostConfigure(string name, TOptions options)
    {
        options.SignInScheme = options.SignInScheme ?? _authOptions.DefaultSignInScheme ?? _authOptions.DefaultScheme;
    }
}
```

# OAuthHandler
- 解密state
- 校验CorrelationId，防跨站伪造攻击
- 如果error不为空说明失败返回错误
- 拿到授权码code，换取token
- 如果SaveTokens设置为true，将access_token,refresh_token,token_type存放到properties中
- 创建凭据，返回成功
```csharp
  protected override async Task<HandleRequestResult> HandleRemoteAuthenticateAsync()
        {
            var query = Request.Query;

            var state = query["state"];
            var properties = Options.StateDataFormat.Unprotect(state);

            if (properties == null)
            {
                return HandleRequestResult.Fail("The oauth state was missing or invalid.");
            }

            // OAuth2 10.12 CSRF
            if (!ValidateCorrelationId(properties))
            {
                return HandleRequestResult.Fail("Correlation failed.", properties);
            }

            var error = query["error"];
            if (!StringValues.IsNullOrEmpty(error))
            {
                // Note: access_denied errors are special protocol errors indicating the user didn't
                // approve the authorization demand requested by the remote authorization server.
                // Since it's a frequent scenario (that is not caused by incorrect configuration),
                // denied errors are handled differently using HandleAccessDeniedErrorAsync().
                // Visit https://tools.ietf.org/html/rfc6749#section-4.1.2.1 for more information.
                if (StringValues.Equals(error, "access_denied"))
                {
                    return await HandleAccessDeniedErrorAsync(properties);
                }

                var failureMessage = new StringBuilder();
                failureMessage.Append(error);
                var errorDescription = query["error_description"];
                if (!StringValues.IsNullOrEmpty(errorDescription))
                {
                    failureMessage.Append(";Description=").Append(errorDescription);
                }
                var errorUri = query["error_uri"];
                if (!StringValues.IsNullOrEmpty(errorUri))
                {
                    failureMessage.Append(";Uri=").Append(errorUri);
                }

                return HandleRequestResult.Fail(failureMessage.ToString(), properties);
            }

            var code = query["code"];

            if (StringValues.IsNullOrEmpty(code))
            {
                return HandleRequestResult.Fail("Code was not found.", properties);
            }

            var tokens = await ExchangeCodeAsync(code, BuildRedirectUri(Options.CallbackPath));

            if (tokens.Error != null)
            {
                return HandleRequestResult.Fail(tokens.Error, properties);
            }

            if (string.IsNullOrEmpty(tokens.AccessToken))
            {
                return HandleRequestResult.Fail("Failed to retrieve access token.", properties);
            }

            var identity = new ClaimsIdentity(ClaimsIssuer);

            if (Options.SaveTokens)
            {
                var authTokens = new List<AuthenticationToken>();

                authTokens.Add(new AuthenticationToken { Name = "access_token", Value = tokens.AccessToken });
                if (!string.IsNullOrEmpty(tokens.RefreshToken))
                {
                    authTokens.Add(new AuthenticationToken { Name = "refresh_token", Value = tokens.RefreshToken });
                }

                if (!string.IsNullOrEmpty(tokens.TokenType))
                {
                    authTokens.Add(new AuthenticationToken { Name = "token_type", Value = tokens.TokenType });
                }

                if (!string.IsNullOrEmpty(tokens.ExpiresIn))
                {
                    int value;
                    if (int.TryParse(tokens.ExpiresIn, NumberStyles.Integer, CultureInfo.InvariantCulture, out value))
                    {
                        // https://www.w3.org/TR/xmlschema-2/#dateTime
                        // https://msdn.microsoft.com/en-us/library/az4se3k1(v=vs.110).aspx
                        var expiresAt = Clock.UtcNow + TimeSpan.FromSeconds(value);
                        authTokens.Add(new AuthenticationToken
                        {
                            Name = "expires_at",
                            Value = expiresAt.ToString("o", CultureInfo.InvariantCulture)
                        });
                    }
                }

                properties.StoreTokens(authTokens);
            }

            var ticket = await CreateTicketAsync(identity, properties, tokens);
            if (ticket != null)
            {
                return HandleRequestResult.Success(ticket);
            }
            else
            {
                return HandleRequestResult.Fail("Failed to retrieve user information from remote server.", properties);
            }
        }
```

# 实战
最近做一个第三方对接的项目，我们有多个站点、自己的IdentityServer认证中心，这个联合项目要求将我们的系统以iframe的形式嵌套在他们的菜单里面。整个对接流程大致如下。

<div class="mermaid">
sequenceDiagram
    第三方->>第三方: 登录
    第三方->>本公司系统: 点击菜单请求地址
    本公司系统->>第三方: 跳转OAuth静默授权地址（1）
    第三方->>本公司系统: 带授权码跳转回调地址（2）
    本公司系统->>第三方: 使用code换token（3）
    本公司系统->>第三方: 使用token读取个人资料（4）
    本公司系统->>本公司系统: 用户名密码模式与本公司认证中心静默授权（5）
    本公司系统->>本公司系统: 上下文注入需要的Claims，使用CookieSchema登录维持登录态（6）
    本公司系统->>本公司系统: 回跳到开始授权时的地址（7）
</div>

利用微软框架，可以比较快速实现
1. 定义XXOptions，继承自OAuthOptions
    - ClientId：必填，客户端id
    - ClientSecret：必填，客户端秘钥
    - AuthorizationEndpoint：必填，授权地址，对应步骤（1）
    - TokenEndpoint：必填，中间件会带着授权码code跳转到此地址换取token，对应步骤（2，3）
    - UserInformationEndpoint：选填，用户信息接口地址，框架没有使用此属性，需要自己实现，对应步骤（4）
    - CallbackPath：必填，授权流程结束之后回跳地址，对应步骤（7）
    - 订阅事件：Events.OnCreatingTicket += async (OAuthCreatingTicketContext context) => 
            {
               //用户凭据签发时触发，将用户信息同步到本公司，使用ClientCredential模式与
               //本公司IdentityServer认证中心通讯实现静默授权
               //然后将本公司相关会话信息填充到凭据中
            };
    - SignInSchema：认证完后登入架构名（建议Cookies）
    - 如果有特有的配置，也在此处定义

2. 定义XXOAuthHandler，继承自OAuthHandler
    - 重写ExchangeCodeAsync，此方法负责使用code换取token，父类实现使用的是form-post，如果任何地方与实际情况不匹配，可以进行重写
    - 重写HandleChallengeAsync方法，此方法负责构建质询地址，即步骤（1）的静默授权地址+回调地址
    - 重写CreateTicketAsync方法，此方法负责构建用户凭证，包括所有需要未来维持在Cookie中的信息。可以在此处请求UserInformationEndpoint请求用户资料，然后填充到凭证中。
    - 重写HandleRemoteAuthenticateAsync：此方法为主干逻辑方法，如果与实际有差异可以进行重写，否则使用父类实现即可。

  