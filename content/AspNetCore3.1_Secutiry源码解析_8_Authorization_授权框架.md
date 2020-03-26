---
title: "AspNetCore3.1_Secutiry源码解析_8_Authorization_授权框架"
date: 2020-03-26T16:23:56+08:00
draft: false
---

{{%security_menu%}}

# 简介
开篇提到过，认证主要解决的是who are you，授权解决的是 are you allowed的问题。各种认证架构可以帮我们知道用户身份（claims），oauth等架构的scope字段能够控制api服务级别的访问权限，但是更加细化和多变的功能授权不是它们的处理范围。  

微软的Authorization项目提供了基于策略的灵活的授权框架。

推荐看下面博客了解，我主要学习和梳理源码。
> https://www.cnblogs.com/RainingNight/p/authorization-in-asp-net-core.html

# 依赖注入
```csharp
注入了以下接口，提供了默认实现
- IAuthorizationService ：授权服务，主干服务
- IAuthorizationPolicyProvider ： 策略提供类
- IAuthorizationHandlerProvider：处理器提供类
- IAuthorizationEvaluator：校验类
- IAuthorizationHandlerContextFactory：授权上下文工厂
- IAuthorizationHandler：授权处理器，这个是注入的集合，一个策略可以有多个授权处理器，依次执行
- 配置类：AuthorizationOptions

微软的命名风格还是比较一致的  
Service：服务  
Provider：某类的提供者
Evaluator：校验预处理类  
Factory：工厂  
Handler：处理器  
Context：上下文

看源码的过程，不仅可以学习框架背后原理，还可以学习编码风格和设计模式，还是挺有用处的。

/// <summary>
/// Adds authorization services to the specified <see cref="IServiceCollection" />. 
/// </summary>
/// <param name="services">The <see cref="IServiceCollection" /> to add services to.</param>
/// <returns>The <see cref="IServiceCollection"/> so that additional calls can be chained.</returns>
public static IServiceCollection AddAuthorizationCore(this IServiceCollection services)
{
    if (services == null)
    {
        throw new ArgumentNullException(nameof(services));
    }
    
    services.TryAdd(ServiceDescriptor.Transient<IAuthorizationService, DefaultAuthorizationService>());
    services.TryAdd(ServiceDescriptor.Transient<IAuthorizationPolicyProvider, DefaultAuthorizationPolicyProvider>());
    services.TryAdd(ServiceDescriptor.Transient<IAuthorizationHandlerProvider, DefaultAuthorizationHandlerProvider>());
    services.TryAdd(ServiceDescriptor.Transient<IAuthorizationEvaluator, DefaultAuthorizationEvaluator>());
    services.TryAdd(ServiceDescriptor.Transient<IAuthorizationHandlerContextFactory, DefaultAuthorizationHandlerContextFactory>());
    services.TryAddEnumerable(ServiceDescriptor.Transient<IAuthorizationHandler, PassThroughAuthorizationHandler>());
    return services;
}

/// <summary>
/// Adds authorization services to the specified <see cref="IServiceCollection" />. 
/// </summary>
/// <param name="services">The <see cref="IServiceCollection" /> to add services to.</param>
/// <param name="configure">An action delegate to configure the provided <see cref="AuthorizationOptions"/>.</param>
/// <returns>The <see cref="IServiceCollection"/> so that additional calls can be chained.</returns>
public static IServiceCollection AddAuthorizationCore(this IServiceCollection services, Action<AuthorizationOptions> configure)
{
    if (services == null)
    {
        throw new ArgumentNullException(nameof(services));
    }

    if (configure != null)
    {
        services.Configure(configure);
    }

    return services.AddAuthorizationCore();
}
```
# 配置类 - AuthorizationOptions
- PolicyMap：策略名称&策略的字典数据  
- InvokeHandlersAfterFailure： 授权处理器失败后是否触发下一个处理器，默认true  
- DefaultPolicy：默认策略，构造了一个RequireAuthenticatedUser策略，即需要认证用户，不允许匿名访问。现在有点线索了，为什么api一加上[Authorize]，就会校验授权。  
- FallbackPolicy：保底策略。没有任何策略的时候会使用保底策略。感觉有点多此一举，不是给了个默认策略吗？  
- AddPolicy：添加策略  
- GetPolicy：获取策略  

```csharp
/// <summary>
/// Provides programmatic configuration used by <see cref="IAuthorizationService"/> and <see cref="IAuthorizationPolicyProvider"/>.
/// </summary>
public class AuthorizationOptions
{
    private IDictionary<string, AuthorizationPolicy> PolicyMap { get; } = new Dictionary<string, AuthorizationPolicy>(StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// Determines whether authentication handlers should be invoked after a failure.
    /// Defaults to true.
    /// </summary>
    public bool InvokeHandlersAfterFailure { get; set; } = true;

    /// <summary>
    /// Gets or sets the default authorization policy. Defaults to require authenticated users.
    /// </summary>
    /// <remarks>
    /// The default policy used when evaluating <see cref="IAuthorizeData"/> with no policy name specified.
    /// </remarks>
    public AuthorizationPolicy DefaultPolicy { get; set; } = new AuthorizationPolicyBuilder().RequireAuthenticatedUser().Build();

    /// <summary>
    /// Gets or sets the fallback authorization policy used by <see cref="AuthorizationPolicy.CombineAsync(IAuthorizationPolicyProvider, IEnumerable{IAuthorizeData})"/>
    /// when no IAuthorizeData have been provided. As a result, the AuthorizationMiddleware uses the fallback policy
    /// if there are no <see cref="IAuthorizeData"/> instances for a resource. If a resource has any <see cref="IAuthorizeData"/>
    /// then they are evaluated instead of the fallback policy. By default the fallback policy is null, and usually will have no 
    /// effect unless you have the AuthorizationMiddleware in your pipeline. It is not used in any way by the 
    /// default <see cref="IAuthorizationService"/>.
    /// </summary>
    public AuthorizationPolicy FallbackPolicy { get; set; }

    /// <summary>
    /// Add an authorization policy with the provided name.
    /// </summary>
    /// <param name="name">The name of the policy.</param>
    /// <param name="policy">The authorization policy.</param>
    public void AddPolicy(string name, AuthorizationPolicy policy)
    {
        if (name == null)
        {
            throw new ArgumentNullException(nameof(name));
        }

        if (policy == null)
        {
            throw new ArgumentNullException(nameof(policy));
        }

        PolicyMap[name] = policy;
    }

    /// <summary>
    /// Add a policy that is built from a delegate with the provided name.
    /// </summary>
    /// <param name="name">The name of the policy.</param>
    /// <param name="configurePolicy">The delegate that will be used to build the policy.</param>
    public void AddPolicy(string name, Action<AuthorizationPolicyBuilder> configurePolicy)
    {
        if (name == null)
        {
            throw new ArgumentNullException(nameof(name));
        }

        if (configurePolicy == null)
        {
            throw new ArgumentNullException(nameof(configurePolicy));
        }

        var policyBuilder = new AuthorizationPolicyBuilder();
        configurePolicy(policyBuilder);
        PolicyMap[name] = policyBuilder.Build();
    }

    /// <summary>
    /// Returns the policy for the specified name, or null if a policy with the name does not exist.
    /// </summary>
    /// <param name="name">The name of the policy to return.</param>
    /// <returns>The policy for the specified name, or null if a policy with the name does not exist.</returns>
    public AuthorizationPolicy GetPolicy(string name)
    {
        if (name == null)
        {
            throw new ArgumentNullException(nameof(name));
        }

        return PolicyMap.ContainsKey(name) ? PolicyMap[name] : null;
    }
}
```
# IAuthorizationService - 授权服务 - 主干逻辑
接口定义了授权方法，有两个重载，一个是基于requirements校验，一个是基于policyName校验。
```csharp
Task<AuthorizationResult> AuthorizeAsync(ClaimsPrincipal user, object resource, IEnumerable<IAuthorizationRequirement> requirements);

Task<AuthorizationResult> AuthorizeAsync(ClaimsPrincipal user, object resource, string policyName);
```

看下默认实现DefaultAuthorizationService的处理,逻辑还是比较简单
- 获取策略
- 获取策略的授权条件
- 获取授权上下文
- 获取处理器集合
- 处理器依次执行，结果存入上下文
- 校验器验证上下文
- 返回授权结果类

```csharp
 /// <summary>
/// The default implementation of an <see cref="IAuthorizationService"/>.
/// </summary>
public class DefaultAuthorizationService : IAuthorizationService
{
    private readonly AuthorizationOptions _options;
    private readonly IAuthorizationHandlerContextFactory _contextFactory;
    private readonly IAuthorizationHandlerProvider _handlers;
    private readonly IAuthorizationEvaluator _evaluator;
    private readonly IAuthorizationPolicyProvider _policyProvider;
    private readonly ILogger _logger;

    /// <summary>
    /// Creates a new instance of <see cref="DefaultAuthorizationService"/>.
    /// </summary>
    /// <param name="policyProvider">The <see cref="IAuthorizationPolicyProvider"/> used to provide policies.</param>
    /// <param name="handlers">The handlers used to fulfill <see cref="IAuthorizationRequirement"/>s.</param>
    /// <param name="logger">The logger used to log messages, warnings and errors.</param>  
    /// <param name="contextFactory">The <see cref="IAuthorizationHandlerContextFactory"/> used to create the context to handle the authorization.</param>  
    /// <param name="evaluator">The <see cref="IAuthorizationEvaluator"/> used to determine if authorization was successful.</param>  
    /// <param name="options">The <see cref="AuthorizationOptions"/> used.</param>  
    public DefaultAuthorizationService(IAuthorizationPolicyProvider policyProvider, IAuthorizationHandlerProvider handlers, ILogger<DefaultAuthorizationService> logger, IAuthorizationHandlerContextFactory contextFactory, IAuthorizationEvaluator evaluator, IOptions<AuthorizationOptions> options)
    {
        if (options == null)
        {
            throw new ArgumentNullException(nameof(options));
        }
        if (policyProvider == null)
        {
            throw new ArgumentNullException(nameof(policyProvider));
        }
        if (handlers == null)
        {
            throw new ArgumentNullException(nameof(handlers));
        }
        if (logger == null)
        {
            throw new ArgumentNullException(nameof(logger));
        }
        if (contextFactory == null)
        {
            throw new ArgumentNullException(nameof(contextFactory));
        }
        if (evaluator == null)
        {
            throw new ArgumentNullException(nameof(evaluator));
        }

        _options = options.Value;
        _handlers = handlers;
        _policyProvider = policyProvider;
        _logger = logger;
        _evaluator = evaluator;
        _contextFactory = contextFactory;
    }

    /// <summary>
    /// Checks if a user meets a specific set of requirements for the specified resource.
    /// </summary>
    /// <param name="user">The user to evaluate the requirements against.</param>
    /// <param name="resource">The resource to evaluate the requirements against.</param>
    /// <param name="requirements">The requirements to evaluate.</param>
    /// <returns>
    /// A flag indicating whether authorization has succeeded.
    /// This value is <value>true</value> when the user fulfills the policy otherwise <value>false</value>.
    /// </returns>
    public async Task<AuthorizationResult> AuthorizeAsync(ClaimsPrincipal user, object resource, IEnumerable<IAuthorizationRequirement> requirements)
    {
        if (requirements == null)
        {
            throw new ArgumentNullException(nameof(requirements));
        }

        var authContext = _contextFactory.CreateContext(requirements, user, resource);
        var handlers = await _handlers.GetHandlersAsync(authContext);
        foreach (var handler in handlers)
        {
            await handler.HandleAsync(authContext);
            if (!_options.InvokeHandlersAfterFailure && authContext.HasFailed)
            {
                break;
            }
        }

        var result = _evaluator.Evaluate(authContext);
        if (result.Succeeded)
        {
            _logger.UserAuthorizationSucceeded();
        }
        else
        {
            _logger.UserAuthorizationFailed();
        }
        return result;
    }

    /// <summary>
    /// Checks if a user meets a specific authorization policy.
    /// </summary>
    /// <param name="user">The user to check the policy against.</param>
    /// <param name="resource">The resource the policy should be checked with.</param>
    /// <param name="policyName">The name of the policy to check against a specific context.</param>
    /// <returns>
    /// A flag indicating whether authorization has succeeded.
    /// This value is <value>true</value> when the user fulfills the policy otherwise <value>false</value>.
    /// </returns>
    public async Task<AuthorizationResult> AuthorizeAsync(ClaimsPrincipal user, object resource, string policyName)
    {
        if (policyName == null)
        {
            throw new ArgumentNullException(nameof(policyName));
        }

        var policy = await _policyProvider.GetPolicyAsync(policyName);
        if (policy == null)
        {
            throw new InvalidOperationException($"No policy found: {policyName}.");
        }
        return await this.AuthorizeAsync(user, resource, policy);
    }
}
```
# 默认策略 - 需要认证用户

默认策略添加了校验条件DenyAnonymousAuthorizationRequirement

```csharp
public AuthorizationPolicyBuilder RequireAuthenticatedUser()
{
    Requirements.Add(new DenyAnonymousAuthorizationRequirement());
    return this;
}
```

校验上下文中是否存在认证用户信息，验证通过则在上下文中将校验条件标记为成功。
```csharp
protected override Task HandleRequirementAsync(AuthorizationHandlerContext context, DenyAnonymousAuthorizationRequirement requirement)
    {
        var user = context.User;
        var userIsAnonymous =
            user?.Identity == null ||
            !user.Identities.Any(i => i.IsAuthenticated);
        if (!userIsAnonymous)
        {
            context.Succeed(requirement);
        }
        return Task.CompletedTask;
    }
```

# 授权时序图
授权项目还是比较好理解的，微软提供了一个基于策略的授权模型，大部门的具体的业务代码还是需要自己去实现的。
<div class="mermaid">
 classDiagram
      class AuthorizationPolicy{
          Requirements
      }
      class Requirement{
      }
      class AuthorizationHandler{
      }
      class IAuthorizationHandler{
          +HandleAsync(AuthorizationHandlerContext context)
      }
      class IAuthorizationRequirement{
      }
      Requirement-->AuthorizationHandler
      AuthorizationHandler-->IAuthorizationHandler
      Requirement-->IAuthorizationHandler
      Requirement-->IAuthorizationRequirement
</div>

# 中间件去哪了？
开发不需要编写UseAuthorization类似代码，项目中也没发现中间件，甚至找不到 使用AuthorizeAttribute的地方。那么问题来了，框架怎么知道某个方法标记了[Authorize]特性，然后执行校验的呢？

答案是Mvc框架处理的，它读取了节点的[Authorize]和[AllowAnonymous]特性，并触发相应的逻辑。关于Mvc的就不细说了，感兴趣可以翻看源码。
AspNetCore\src\Mvc\Mvc.Core\src\ApplicationModels\AuthorizationApplicationModelProvider.cs。
```csharp
public void OnProvidersExecuting(ApplicationModelProviderContext context)
{
    if (context == null)
    {
        throw new ArgumentNullException(nameof(context));
    }

    if (_mvcOptions.EnableEndpointRouting)
    {
        // When using endpoint routing, the AuthorizationMiddleware does the work that Auth filters would otherwise perform.
        // Consequently we do not need to convert authorization attributes to filters.
        return;
    }

    foreach (var controllerModel in context.Result.Controllers)
    {
        var controllerModelAuthData = controllerModel.Attributes.OfType<IAuthorizeData>().ToArray();
        if (controllerModelAuthData.Length > 0)
        {
            controllerModel.Filters.Add(GetFilter(_policyProvider, controllerModelAuthData));
        }
        foreach (var attribute in controllerModel.Attributes.OfType<IAllowAnonymous>())
        {
            controllerModel.Filters.Add(new AllowAnonymousFilter());
        }

        foreach (var actionModel in controllerModel.Actions)
        {
            var actionModelAuthData = actionModel.Attributes.OfType<IAuthorizeData>().ToArray();
            if (actionModelAuthData.Length > 0)
            {
                actionModel.Filters.Add(GetFilter(_policyProvider, actionModelAuthData));
            }

            foreach (var attribute in actionModel.Attributes.OfType<IAllowAnonymous>())
            {
                actionModel.Filters.Add(new AllowAnonymousFilter());
            }
        }
    }
}
```