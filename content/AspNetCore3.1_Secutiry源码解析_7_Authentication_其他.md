---
title: "AspNetCore3.1_Secutiry源码解析_7_Authentication_其他"
date: 2020-03-26T13:23:27+08:00
draft: false
---

{{%security_menu%}}

# 简介
Secutiry的认证目录还有这些项目，基本都是具体的OAuth2.0服务商或者其他用的比较少的认证架构，简单看一下，了解一下。

- Microsoft.AspNetCore.Authentication.Certificate
- Microsoft.AspNetCore.Authentication.Facebook
- Microsoft.AspNetCore.Authentication.Google
- Microsoft.AspNetCore.Authentication.MicrosoftAccount
- Microsoft.AspNetCore.Authentication.Negotiate
- Microsoft.AspNetCore.Authentication.Twitter
- Microsoft.AspNetCore.Authentication.WsFederation

# OAuth2.0服务商
Facebook, Google,MicrosoftAccount这几个都可以归为一类，都是OAuth2.0的服务商。国内用的比较多的是QQ，Weixin。我们看一下Facebook的代码，其他的原理都是大同小异的，根据不同厂商的差异稍作调整就可以了。

Twitter似乎是用的OAuth1.0协议。

## 依赖注入

配置类: FacebookOptions,处理器类：FacebookHandler

```csharp
public static class FacebookAuthenticationOptionsExtensions
{
    public static AuthenticationBuilder AddFacebook(this AuthenticationBuilder builder)
        => builder.AddFacebook(FacebookDefaults.AuthenticationScheme, _ => { });

    public static AuthenticationBuilder AddFacebook(this AuthenticationBuilder builder, Action<FacebookOptions> configureOptions)
        => builder.AddFacebook(FacebookDefaults.AuthenticationScheme, configureOptions);

    public static AuthenticationBuilder AddFacebook(this AuthenticationBuilder builder, string authenticationScheme, Action<FacebookOptions> configureOptions)
        => builder.AddFacebook(authenticationScheme, FacebookDefaults.DisplayName, configureOptions);

    public static AuthenticationBuilder AddFacebook(this AuthenticationBuilder builder, string authenticationScheme, string displayName, Action<FacebookOptions> configureOptions)
        => builder.AddOAuth<FacebookOptions, FacebookHandler>(authenticationScheme, displayName, configureOptions);
}
```

## 配置类 - FacebookOptions

配置类继承自OAuthOptions，构造函数根据Facebook做了一些定制处理，如claim的映射等。

```csharp
/// <summary>
/// Configuration options for <see cref="FacebookHandler"/>.
/// </summary>
public class FacebookOptions : OAuthOptions
{
    /// <summary>
    /// Initializes a new <see cref="FacebookOptions"/>.
    /// </summary>
    public FacebookOptions()
    {
        CallbackPath = new PathString("/signin-facebook");
        SendAppSecretProof = true;
        AuthorizationEndpoint = FacebookDefaults.AuthorizationEndpoint;
        TokenEndpoint = FacebookDefaults.TokenEndpoint;
        UserInformationEndpoint = FacebookDefaults.UserInformationEndpoint;
        Scope.Add("email");
        Fields.Add("name");
        Fields.Add("email");
        Fields.Add("first_name");
        Fields.Add("last_name");

        ClaimActions.MapJsonKey(ClaimTypes.NameIdentifier, "id");
        ClaimActions.MapJsonSubKey("urn:facebook:age_range_min", "age_range", "min");
        ClaimActions.MapJsonSubKey("urn:facebook:age_range_max", "age_range", "max");
        ClaimActions.MapJsonKey(ClaimTypes.DateOfBirth, "birthday");
        ClaimActions.MapJsonKey(ClaimTypes.Email, "email");
        ClaimActions.MapJsonKey(ClaimTypes.Name, "name");
        ClaimActions.MapJsonKey(ClaimTypes.GivenName, "first_name");
        ClaimActions.MapJsonKey("urn:facebook:middle_name", "middle_name");
        ClaimActions.MapJsonKey(ClaimTypes.Surname, "last_name");
        ClaimActions.MapJsonKey(ClaimTypes.Gender, "gender");
        ClaimActions.MapJsonKey("urn:facebook:link", "link");
        ClaimActions.MapJsonSubKey("urn:facebook:location", "location", "name");
        ClaimActions.MapJsonKey(ClaimTypes.Locality, "locale");
        ClaimActions.MapJsonKey("urn:facebook:timezone", "timezone");
    }

    /// <summary>
    /// Check that the options are valid.  Should throw an exception if things are not ok.
    /// </summary>
    public override void Validate()
    {
        if (string.IsNullOrEmpty(AppId))
        {
            throw new ArgumentException(string.Format(CultureInfo.CurrentCulture, Resources.Exception_OptionMustBeProvided, nameof(AppId)), nameof(AppId));
        }

        if (string.IsNullOrEmpty(AppSecret))
        {
            throw new ArgumentException(string.Format(CultureInfo.CurrentCulture, Resources.Exception_OptionMustBeProvided, nameof(AppSecret)), nameof(AppSecret));
        }

        base.Validate();
    }

    // Facebook uses a non-standard term for this field.
    /// <summary>
    /// Gets or sets the Facebook-assigned appId.
    /// </summary>
    public string AppId
    {
        get { return ClientId; }
        set { ClientId = value; }
    }

    // Facebook uses a non-standard term for this field.
    /// <summary>
    /// Gets or sets the Facebook-assigned app secret.
    /// </summary>
    public string AppSecret
    {
        get { return ClientSecret; }
        set { ClientSecret = value; }
    }

    /// <summary>
    /// Gets or sets if the appsecret_proof should be generated and sent with Facebook API calls.
    /// This is enabled by default.
    /// </summary>
    public bool SendAppSecretProof { get; set; }

    /// <summary>
    /// The list of fields to retrieve from the UserInformationEndpoint.
    /// https://developers.facebook.com/docs/graph-api/reference/user
    /// </summary>
    public ICollection<string> Fields { get; } = new HashSet<string>();
}
```

## 处理器类

重写了OAuthHanlder的创建凭据方法，其他的都是使用的父类实现。

```csharp
public class FacebookHandler : OAuthHandler<FacebookOptions>
{
    public FacebookHandler(IOptionsMonitor<FacebookOptions> options, ILoggerFactory logger, UrlEncoder encoder, ISystemClock clock)
        : base(options, logger, encoder, clock)
    { }

    protected override async Task<AuthenticationTicket> CreateTicketAsync(ClaimsIdentity identity, AuthenticationProperties properties, OAuthTokenResponse tokens)
    {
        var endpoint = QueryHelpers.AddQueryString(Options.UserInformationEndpoint, "access_token", tokens.AccessToken);
        if (Options.SendAppSecretProof)
        {
            endpoint = QueryHelpers.AddQueryString(endpoint, "appsecret_proof", GenerateAppSecretProof(tokens.AccessToken));
        }
        if (Options.Fields.Count > 0)
        {
            endpoint = QueryHelpers.AddQueryString(endpoint, "fields", string.Join(",", Options.Fields));
        }

        var response = await Backchannel.GetAsync(endpoint, Context.RequestAborted);
        if (!response.IsSuccessStatusCode)
        {
            throw new HttpRequestException($"An error occurred when retrieving Facebook user information ({response.StatusCode}). Please check if the authentication information is correct and the corresponding Facebook Graph API is enabled.");
        }

        using (var payload = JsonDocument.Parse(await response.Content.ReadAsStringAsync()))
        {
            var context = new OAuthCreatingTicketContext(new ClaimsPrincipal(identity), properties, Context, Scheme, Options, Backchannel, tokens, payload.RootElement);
            context.RunClaimActions();
            await Events.CreatingTicket(context);
            return new AuthenticationTicket(context.Principal, context.Properties, Scheme.Name);
        }
    }

    private string GenerateAppSecretProof(string accessToken)
    {
        using (var algorithm = new HMACSHA256(Encoding.ASCII.GetBytes(Options.AppSecret)))
        {
            var hash = algorithm.ComputeHash(Encoding.ASCII.GetBytes(accessToken));
            var builder = new StringBuilder();
            for (int i = 0; i < hash.Length; i++)
            {
                builder.Append(hash[i].ToString("x2", CultureInfo.InvariantCulture));
            }
            return builder.ToString();
        }
    }

    protected override string FormatScope(IEnumerable<string> scopes)
    {
        // Facebook deviates from the OAuth spec here. They require comma separated instead of space separated.
        // https://developers.facebook.com/docs/reference/dialogs/oauth
        // http://tools.ietf.org/html/rfc6749#section-3.3
        return string.Join(",", scopes);
    }

    protected override string FormatScope()
        => base.FormatScope();
}
```

# Microsoft.AspNetCore.Authentication.Certificate
这个项目是3.1新加的，是做证书校验的，具体的不细说了，不太懂，有兴趣的看巨硬文档
> https://docs.microsoft.com/zh-cn/aspnet/core/security/authentication/certauth?view=aspnetcore-3.1


# Microsoft.AspNetCore.Authentication.Negotiate
这个也是新增的项目，是做Windows校验的，文档如下
> https://docs.microsoft.com/en-us/aspnet/core/security/authentication/windowsauth?view=aspnetcore-3.1&tabs=visual-studio

# Microsoft.AspNetCore.Authentication.WsFederation
Windows的Azure Active Directory认证
> https://docs.microsoft.com/zh-cn/aspnet/core/security/authentication/ws-federation?view=aspnetcore-3.1