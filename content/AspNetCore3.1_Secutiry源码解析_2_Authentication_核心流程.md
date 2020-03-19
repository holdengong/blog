---
title: "AspNetCore3.1_Secutiry源码解析_2_Authentication_核心流程"
date: 2020-03-18T21:19:15+08:00
draft: false
---
# 系列文章目录
- [AspNetCore3.1_Secutiry源码解析_1_目录](https://holdengong.com/aspnetcore3.1_secutiry源码解析_1_目录)
- [AspNetCore3.1_Secutiry源码解析_2_Authentication_核心流程](https://holdengong.com/aspnetcore3.1_secutiry源码解析_2_authentication_核心流程)
- [AspNetCore3.1_Secutiry源码解析_3_Authentication_Cookies](https://holdengong.com/aspnetcore3.1_secutiry源码解析_3_authentication_cookies)
- AspNetCore3.1_Secutiry源码解析_4_Authentication_JwtBear
- AspNetCore3.1_Secutiry源码解析_5_Authentication_OAuth
- AspNetCore3.1_Secutiry源码解析_6_Authentication_OpenIdConnect
- AspNetCore3.1_Secutiry源码解析_7_Authentication_其他
- AspNetCore3.1_Secutiry源码解析_8_Authorization_核心项目
- AspNetCore3.1_Secutiry源码解析_9_Authorization_Policy

# 依赖注入
框架提供了三个依赖注入重载方法。
```csharp
//注入认证服务
services.AddAuthentication();

//注入认证服务并制定默认架构名
services.AddAuthentication("Cookies");

//注入认证服务并设置配置项
services.AddAuthentication(config => 
{
});
```

看看注入代码
```csharp
public static AuthenticationBuilder AddAuthentication(this IServiceCollection services)
    {
        if (services == null)
        {
            throw new ArgumentNullException(nameof(services));
        }

        services.AddAuthenticationCore();
        services.AddDataProtection();
        services.AddWebEncoders();
        services.TryAddSingleton<ISystemClock, SystemClock>();
        return new AuthenticationBuilder(services);
    }
```

AddAuthenticationCore注入了认证服务的核心对象。这个方法在Authentication.Core项目，这个项目定义了认证服务的核心对象，在Authentication.Abstractions项目中定义了核心接口。

![image](https://fs.31huiyi.com/20f775f3-1920-4a7c-90a0-45137ef5cdd3.png)

AddAuthenticationCore方法注入了IAuthenticationService，IClaimsTransformation，IAuthenticationHandlerProvider，IAuthenticationSchemeProvider

```csharp
public static IServiceCollection AddAuthenticationCore(this IServiceCollection services)
{
    if (services == null)
    {
        throw new ArgumentNullException(nameof(services));
    }

    services.TryAddScoped<IAuthenticationService, AuthenticationService>();
    services.TryAddSingleton<IClaimsTransformation, NoopClaimsTransformation>(); // Can be replaced with scoped ones that use DbContext
    services.TryAddScoped<IAuthenticationHandlerProvider, AuthenticationHandlerProvider>();
    services.TryAddSingleton<IAuthenticationSchemeProvider, AuthenticationSchemeProvider>();
    return services;
}
```
AddAuthentication注入方法返回的AuthenticationBuilder对象提供了一些操作schema的方法，方便链式编程添加schema。

## IAuthenticationService
认证服务，定义了五个方法
- AuthenticateAsync: 认证
- ChallengeAsync：挑战，校验认证
- ForbidAsync：禁止认证
- SignInAsync：登入
- SignOutAsync：登出

<div class="mermaid">
 classDiagram
      class IAuthenticationService{
          +AuthenticateAsync(HttpContext context, string scheme)
          +ChallengeAsync(HttpContext context, string scheme, AuthenticationProperties properties)
          +ForbidAsync(HttpContext context, string scheme, AuthenticationProperties properties)
          +SignInAsync(HttpContext context, string scheme, ClaimsPrincipal principal, AuthenticationProperties properties)
          +SignOutAsync(HttpContext context, string scheme, AuthenticationProperties properties)
      }
</div>

通过AuthenticateAsync方法源代码可以看到，AuthenticateService只是做了控制器的角色，校验schema，根据schema获取handler，主要的认证逻辑是由handler处理。其他的方法基本也是这样的逻辑。
```csharp
 public virtual async Task<AuthenticateResult> AuthenticateAsync(HttpContext context, string scheme)
{
    if (scheme == null)
    {
        var defaultScheme = await Schemes.GetDefaultAuthenticateSchemeAsync();
        scheme = defaultScheme?.Name;
        if (scheme == null)
        {
            throw new InvalidOperationException($"No authenticationScheme was specified, and there was no DefaultAuthenticateScheme found. The default schemes can be set using either AddAuthentication(string defaultScheme) or AddAuthentication(Action<AuthenticationOptions> configureOptions).");
        }
    }

    var handler = await Handlers.GetHandlerAsync(context, scheme);
    if (handler == null)
    {
        throw await CreateMissingHandlerException(scheme);
    }

    var result = await handler.AuthenticateAsync();
    if (result != null && result.Succeeded)
    {
        var transformed = await Transform.TransformAsync(result.Principal);
        return AuthenticateResult.Success(new AuthenticationTicket(transformed, result.Properties, result.Ticket.AuthenticationScheme));
    }
    return result;
}
```

## IClaimsTransformation

<div class="mermaid">
 classDiagram
      class IClaimsTransformation{
          +TransformAsync(ClaimsPrincipal principal)
      }
</div>

该接口只有一个方法，用于转换Claims。默认注入的NoopClaimsTransformation，不会做任何操作。如果需要对Claims做一些处理，实现IClaimsTransformation并覆盖注入就可以了。


```csharp
public class NoopClaimsTransformation : IClaimsTransformation
{
    /// <summary>
    /// Returns the principal unchanged.
    /// </summary>
    /// <param name="principal">The user.</param>
    /// <returns>The principal unchanged.</returns>
    public virtual Task<ClaimsPrincipal> TransformAsync(ClaimsPrincipal principal)
    {
        return Task.FromResult(principal);
    }
}
```

## IAuthenticationHandlerProvider
<div class="mermaid">
 classDiagram
      class IAuthenticationHandlerProvider{
          +GetHandlerAsync(HttpContext context, string authenticationScheme)
      }
</div>

上面提到过handler处理了主要的认证业务逻辑，这个接口可以根据schema获取handler。
<script src="https://unpkg.com/mermaid/dist/mermaid.min.js"></script>

## IAuthenticationSchemeProvider
<div class="mermaid">
 classDiagram
      class IAuthenticationSchemeProvider{
          +GetAllSchemesAsync()
          +GetSchemeAsync(string name)
          +GetDefaultAuthenticateSchemeAsync()
          +GetDefaultChallengeSchemeAsync()
          +GetDefaultForbidSchemeAsync()
          +GetDefaultSignInSchemeAsync()
          +GetDefaultSignOutSchemeAsync()
          +AddScheme(AuthenticationScheme scheme)
          +RemoveScheme(string name)
          +GetRequestHandlerSchemesAsync()
      }
</div>

该接口主要定义了一些schema的操作方法。

AuthenticationScheme主要有三个属性，通过HandlerType与handler建立了关联。

<div class="mermaid">
 classDiagram
      class AuthenticationScheme{
          Name
          DisplayName
          HandlerType
      }
</div>

# 认证流程
<div class="mermaid">
graph TD
    A(AuthenticationOptions定义五个认证动作的Schema) 
    A --> B1(Authenticate)
    A --> B2(Challenge)
    A --> B3(Forbid)
    A --> B4(SignIn)
    A --> B5(SingOut)
    C(IAuthenticationSchemeProvider获取Schema)
    B1 --> C
    B2 --> C
    B3 --> C
    B4 --> C
    B5 --> C 
    C --> D(IAuthenticationHandlerProvider获取Schema对应的Handler)
    D --> E(处理请求)
</div>

# 其他
除了核心对象，还注入了用于数据保护和解码的辅助对象
```csharp
services.AddDataProtection();
services.AddWebEncoders();
```

# Authentication中间件

中间件会优先在容器中找IAuthenticationRequestHandler的实现，如果handler不为空的话，则执行handler的HandleRequestAsync方法。IAuthenticationRequestHandler通常在远程认证（如：OAuth, OIDC等）中使用。

如果没有IAuthenticationRequestHandler的实现，则会找默认schema，执行默认schema对应handler的AuthenticationAsync方法，认证成功后，给HttpContext的User对象赋值。

```csharp
public async Task Invoke(HttpContext context)
    {
        context.Features.Set<IAuthenticationFeature>(new AuthenticationFeature
        {
            OriginalPath = context.Request.Path,
            OriginalPathBase = context.Request.PathBase
        });

        // Give any IAuthenticationRequestHandler schemes a chance to handle the request
        var handlers = context.RequestServices.GetRequiredService<IAuthenticationHandlerProvider>();
        foreach (var scheme in await Schemes.GetRequestHandlerSchemesAsync())
        {
            var handler = await handlers.GetHandlerAsync(context, scheme.Name) as IAuthenticationRequestHandler;
            if (handler != null && await handler.HandleRequestAsync())
            {
                return;
            }
        }

        var defaultAuthenticate = await Schemes.GetDefaultAuthenticateSchemeAsync();
        if (defaultAuthenticate != null)
        {
            var result = await context.AuthenticateAsync(defaultAuthenticate.Name);
            if (result?.Principal != null)
            {
                context.User = result.Principal;
            }
        }

        await _next(context);
    }
```

------