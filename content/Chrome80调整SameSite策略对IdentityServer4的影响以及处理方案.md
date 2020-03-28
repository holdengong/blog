---
title: "Chrome80调整SameSite策略对IdentityServer4的影响以及处理方案（翻译）"
date: 2020-03-28T23:43:19+08:00
draft: false
---
首先，好消息是Goole将于2020年2月份发布Chrome 80版本。本次发布将推行Google的“渐进改良Cookie”策略，努力打造一个更为安全和保障用户隐私的网络环境。

坏消息是，本次更新可能使浏览器无法向服务端发送Cookies。首先，如果你有多个应用，它们各自拥有不同的域名，部分用户很有可能出现会话时常被打断的情况。其次，部分用户可能无法正常登出系统。

本篇博客将处理第一个问题（无法发送cookie到服务端）。至于第二个问题（cookie无法被删除），请参考另一篇[博客](https://www.thinktecture.com/identity/samesite/how-to-delete-samesite-cookies/)。

# 首先，SameSite是什么
互联网是十分开放的平台：Cookie诞生于二十多年前，于2011年修订([RFC 6265](https://tools.ietf.org/html/rfc6265))。当时跨站访问攻击（CSRF）没有如此猖獗，侵犯用户隐私的行为也不像现在这样泛滥。

简而言之，Cookie标准规范约定，如果某域名下设置了Cookie，不管你是直接跳转到该域名，或是加载了该域名的某些资源（例如图片），或是向该域名发送POST请求，亦或将其嵌入iframe，浏览器访问该域名的每次请求，都将带上这个Cookie。

对于iframe嵌入这种场景，你可能不希望浏览器将用户会话cookie自动发送到服务端，因为这样任何其他网站都可以在用户不知情的情况下，用他的会话上下文，跟你的服务端发送请求。

为了避免这种情况，SameSite cookie[规范](https://tools.ietf.org/html/draft-west-first-party-cookies-07/)于2016年起草。对于发送cookie我们有了更多的控制权：现在可以明确指定每个cookie是否被发送。规范引入了同站/跨站cookie的概念，如果浏览器访问A域名，请求服务端也是A域名，这些cookie就叫同站cookies（same-site cookies），如果浏览器访问A域名，请求服务端是B域名，这些cookie就叫跨站cookies（cross-site cookies）。

为了向后兼容，same-site的默认设置并未改变之前的行为。你必须手动指定SameSite=Lax或者SameSite=Strict，来能使用这项特性加固安全。所有的.NET框架和常见的浏览器都已支持这一特性。设置为Lax，大多数情况不允许发送第三方Cookie，导航到目标网址的Get请求除外。设置为Strict，完全禁止第三方Cookie，除非你之前访问过该域名而Cookie已经存在于浏览器。

悲哀的是，这项新特性的采用率低的可怜（基于Chrome2019年3月份[统计](https://tools.ietf.org/html/draft-west-http-state-tokens-00#section-1.2/)显示，在所有的cookie中，只有0.1%使用了SameSite标志）。

Google决定推进这项特性的使用。他们决定修改世界上最多人使用的浏览器——Chrome的默认设置：如果想保持之前处理cookie的方式，Chrome 80要求显示指定SameSite=None。如果像以前一样忽略SameSite属性，Chrome将视作SameSite=Lax。

请注意：SameSite=None只有在Cookie同时被标记为Secure并且使用https连接时才会生效。

更新：如果你想知道关于SameSite cookies的更多背景知识，请扩展阅读这篇[文章](https://www.thinktecture.com/en/identity/samesite/samesite-in-a-nutshell/)。

# 这会影响我吗？什么影响？

如果你有一个单页应用（SPA），使用另一域名的认证服务（比如IdentityServer4）进行身份认证，并且使用了所谓的静默令牌刷新的话，你将受影响。  
*译者注：使用refresh_token刷新access_token,用户无感知*

登录到认证服务的时候，它会为当前用户设置会话cookie，这个cookie属于认证服务域名。认证流程结束之后，另一域名会收到认证服务颁发的access token，有效期通常不会太长。当access token过期之后，应用无法访问api，用户需要频繁的登录，体验十分差。

为了避免这一情况，我们可以使用refresh_token实现静默刷新。应用创建一个用户不可见的iframe，在iframe中进行新的认证流程。iframe中加载了认证服务站点，当浏览器发送会话cookie的时候，认证服务识别出当前用户然后颁发新的token。

SPA网站使用iframe嵌入了认证服务站点的内容，这就是一个跨站请求，只有将iframe中属于认证服务站点的cookie设置为SameSite=None，Chrome 80才会将iframe中的cookie发送到认证服务。否则，token静默刷新将无法正常运行。

可能还会导致一些其他的问题：如果应用中嵌入了其他域名的资源，比如视频自动播放设置，它们需要cookie才能正常运行。某些依赖cookie认证来访问第三方API的应用也会出现问题。

注意：很显然你只能修改自己服务的cookie设置。如果使用了其他域名的资源，这些不在你的控制范围之内，你需要联系第三方修改他们的cookie设置。

# 好的，我会修改代码将SameSite设置为None的，这样就万事大吉了，是吗？
很不幸，并不是：Safari存在一个"bug"。这个bug导致Safari不会将None识别为SameSite的合法值。当Safari遇到非法参数值的时候，它会将其视作SameSite=Strict，不会向认证服务发送会话cookie。IOS13和macOS 10.15 Catalina系统上的Safari 13已修复此bug，macOS 10.14 Mojave和iOS 12将不会修复，而这几个版本依旧存在大量用户群。

现在我们进退两难：要么忽略此次更新，Chrome用户无法使用静默刷新，要么设置SameSite=None，那么无法更新到最新系统的iPhone,iPad和Mac用户的应用将出现异常。

# 有没有方法明确知道自己受影响？
幸运的是，你可以。如果你已经设置了SameSite=None，应该注意到应用在iOS 12,macOS 10.4的Safari上运行异常。如果还没有设置的话，确保要在上面版本系统的Safari上做一下测试。

如果还没有设置的话，可以打开Chrome的开发者工具。可以看到这些警告：
```
A cookie associated with a cross-site resource at {cookie domain} was set without the `SameSite` attribute.
A future release of Chrome will only deliver cookies with cross-site requests if they are set with `SameSite=None` and `Secure`.
You can review cookies in developer tools under Application>Storage>Cookies and see more details at
https://www.chromestatus.com/feature/5088147346030592 and
https://www.chromestatus.com/feature/5633521622188032.
```
如果设置了SameSite=None但是没有Secure标识，将看到如下警告：
```
A cookie associated with a resource at {cookie domain} was set with `SameSite=None` but without `Secure`.
A future release of Chrome will only deliver cookies marked `SameSite=None` if they are also marked `Secure`.
You can review cookies in developer tools under Application>Storage>Cookies and
see more details at https://www.chromestatus.com/feature/5633521622188032.
```
# 怎样才能修复这个问题？我需要Chrome和Safari都能正常运行。
我和我的同事Boris Wilhelms做了一些研究和验证，找到了一个解决方案。微软的Barry Dorrans写了一篇很不错的[博客](https://devblogs.microsoft.com/aspnet/upcoming-samesite-cookie-changes-in-asp-net-and-asp-net-core/)可以参考。这个解决方案并不是完美之策，它需要在服务端嗅探浏览器类型，但是它很简单，在过去几周，我们已经用这个方案修复了数个项目。

首先我们需要确保需要通过跨站请求发送的cookie - 比如会话cookie - 被设置为SameSite=None并且标识为Secure。我们需要在项目中找到Cookie选项配置代码，然后做出调整。这样Chrome的问题修复了，然后Safari会出现问题。

然后我们需要将下面的类和代码段加到项目中。这段代码在ASP.NET Core应用中配置了一个cookie策略。这个策略会检查cookie是否应该被设置位SameSite=None。

请注意：这个解决方案是.NET Core使用的。至于.NET Framework项目，请查看Barry Dorran的这篇[博客](https://devblogs.microsoft.com/aspnet/upcoming-samesite-cookie-changes-in-asp-net-and-asp-net-core/)。

# 将这个类加到项目中
```csharp
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
 
namespace Microsoft.Extensions.DependencyInjection
{
   public static class SameSiteCookiesServiceCollectionExtensions
   {
      /// <summary>
      /// -1 defines the unspecified value, which tells ASPNET Core to NOT
      /// send the SameSite attribute. With ASPNET Core 3.1 the
      /// <seealso cref="SameSiteMode" /> enum will have a definition for
      /// Unspecified.
      /// </summary>
      private const SameSiteMode Unspecified = (SameSiteMode) (-1);
 
      /// <summary>
      /// Configures a cookie policy to properly set the SameSite attribute
      /// for Browsers that handle unknown values as Strict. Ensure that you
      /// add the <seealso cref="Microsoft.AspNetCore.CookiePolicy.CookiePolicyMiddleware" />
      /// into the pipeline before sending any cookies!
      /// </summary>
      /// <remarks>
      /// Minimum ASPNET Core Version required for this code:
      ///   - 2.1.14
      ///   - 2.2.8
      ///   - 3.0.1
      ///   - 3.1.0-preview1
      /// Starting with version 80 of Chrome (to be released in February 2020)
      /// cookies with NO SameSite attribute are treated as SameSite=Lax.
      /// In order to always get the cookies send they need to be set to
      /// SameSite=None. But since the current standard only defines Lax and
      /// Strict as valid values there are some browsers that treat invalid
      /// values as SameSite=Strict. We therefore need to check the browser
      /// and either send SameSite=None or prevent the sending of SameSite=None.
      /// Relevant links:
      /// - https://tools.ietf.org/html/draft-west-first-party-cookies-07#section-4.1
      /// - https://tools.ietf.org/html/draft-west-cookie-incrementalism-00
      /// - https://www.chromium.org/updates/same-site
      /// - https://devblogs.microsoft.com/aspnet/upcoming-samesite-cookie-changes-in-asp-net-and-asp-net-core/
      /// - https://bugs.webkit.org/show_bug.cgi?id=198181
      /// </remarks>
      /// <param name="services">The service collection to register <see cref="CookiePolicyOptions" /> into.</param>
      /// <returns>The modified <see cref="IServiceCollection" />.</returns>
      public static IServiceCollection ConfigureNonBreakingSameSiteCookies(this IServiceCollection services)
      {
         services.Configure<CookiePolicyOptions>(options =>
         {
            options.MinimumSameSitePolicy = Unspecified;
            options.OnAppendCookie = cookieContext =>
               CheckSameSite(cookieContext.Context, cookieContext.CookieOptions);
            options.OnDeleteCookie = cookieContext =>
               CheckSameSite(cookieContext.Context, cookieContext.CookieOptions);
         });
 
         return services;
      }

      private static void CheckSameSite(HttpContext httpContext, CookieOptions options)
      {
         if (options.SameSite == SameSiteMode.None)
         {
            var userAgent = httpContext.Request.Headers["User-Agent"].ToString();

            if (DisallowsSameSiteNone(userAgent))
            {
               options.SameSite = Unspecified;
            }
         }
      }
 
      /// <summary>
      /// Checks if the UserAgent is known to interpret an unknown value as Strict.
      /// For those the <see cref="CookieOptions.SameSite" /> property should be
      /// set to <see cref="Unspecified" />.
      /// </summary>
      /// <remarks>
      /// This code is taken from Microsoft:
      /// https://devblogs.microsoft.com/aspnet/upcoming-samesite-cookie-changes-in-asp-net-and-asp-net-core/
      /// </remarks>
      /// <param name="userAgent">The user agent string to check.</param>
      /// <returns>Whether the specified user agent (browser) accepts SameSite=None or not.</returns>
      private static bool DisallowsSameSiteNone(string userAgent)
      {
         // Cover all iOS based browsers here. This includes:
         //   - Safari on iOS 12 for iPhone, iPod Touch, iPad
         //   - WkWebview on iOS 12 for iPhone, iPod Touch, iPad
         //   - Chrome on iOS 12 for iPhone, iPod Touch, iPad
         // All of which are broken by SameSite=None, because they use the
         // iOS networking stack.
         // Notes from Thinktecture:
         // Regarding https://caniuse.com/#search=samesite iOS versions lower
         // than 12 are not supporting SameSite at all. Starting with version 13
         // unknown values are NOT treated as strict anymore. Therefore we only
         // need to check version 12.
         if (userAgent.Contains("CPU iPhone OS 12")
            || userAgent.Contains("iPad; CPU OS 12"))
         {
            return true;
         }

         // Cover Mac OS X based browsers that use the Mac OS networking stack.
         // This includes:
         //   - Safari on Mac OS X.
         // This does not include:
         //   - Chrome on Mac OS X
         // because they do not use the Mac OS networking stack.
         // Notes from Thinktecture: 
         // Regarding https://caniuse.com/#search=samesite MacOS X versions lower
         // than 10.14 are not supporting SameSite at all. Starting with version
         // 10.15 unknown values are NOT treated as strict anymore. Therefore we
         // only need to check version 10.14.
         if (userAgent.Contains("Safari")
            && userAgent.Contains("Macintosh; Intel Mac OS X 10_14")
            && userAgent.Contains("Version/"))
         {
            return true;
         }

         // Cover Chrome 50-69, because some versions are broken by SameSite=None
         // and none in this range require it.
         // Note: this covers some pre-Chromium Edge versions,
         // but pre-Chromium Edge does not require SameSite=None.
         // Notes from Thinktecture:
         // We can not validate this assumption, but we trust Microsofts
         // evaluation. And overall not sending a SameSite value equals to the same
         // behavior as SameSite=None for these old versions anyways.
         if (userAgent.Contains("Chrome/5") || userAgent.Contains("Chrome/6"))
         {
            return true;
         }

         return false;
      }
   }
}
```

# 配置并启用cookie策略
在Starup中加入下面的代码，使用cookie策略
```csharp
public void ConfigureServices(IServiceCollection services)
{
   // Add this
   services.ConfigureNonBreakingSameSiteCookies();
}
 
public void Configure(IApplicationBuilder app)
{
   // Add this before any other middleware that might write cookies
   app.UseCookiePolicy();

   // This will write cookies, so make sure it's after the cookie policy
   app.UseAuthentication();
}
```
# Ok，完事了吗？
还需要做全面的测试，特别是Chrome79，以及受影响的Safari版本。
检查一下你的静默token刷新，还有需要cookie的跨站请求，是否正常工作。
这些都没问题就完事了。
# 可以等IdentityServer4修复这个问题吗？ 
不太可能。并不是IdentityServer在管理这些cookie。IdentityServer依赖于ASP.NET Core框架内置的认证系统，它们在管理会话cookie。然而微软表示它们不能使用在ASP.NET Core直接嗅探浏览器版本的方案。所以基本上短期内只能靠自己了。

# 总结
Chrome于2020年2月发布的新版本修改了cookie的默认行为。新版本需要SameSite明确设置为None，同时有Secure标识，才会将该cookie发送到跨站请求。如果你这么做的话，很多版本的Safari会出现问题。

为了确保应用在所有浏览器运行正常，我们将所有受影响的cookie设置为Secure，SameSite=None，然后新增一个Cookie策略，根据浏览器版本动态处理SameSite设置。

# 译者注
文中提到的方案需要设置SameSiteMode=-1，这个需要更新微软相关包提供支持，详情见下面的博客。
https://devblogs.microsoft.com/aspnet/upcoming-samesite-cookie-changes-in-asp-net-and-asp-net-core/


> 原文地址：https://www.thinktecture.com/en/identity/samesite/prepare-your-identityserver/
