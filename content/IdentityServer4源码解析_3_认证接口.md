---
title: "IdentityServer4源码解析_3_认证接口"
date: 2020-03-26T23:49:28+08:00
draft: false
---
{{%idsv_menu%}}
# 协议
## 五种认证方式
- **Authorization Code 授权码模式**：认证服务器首先返回授权码，后端用clientid和密钥向认证服务证明身份，使用授权码换取id token 和/或 access token。本模式的好处是由后端请求token，不会将敏感信息暴露在浏览器。本模式允许使用refreshToken去维持长时间的登录状态。使用此模式的客户端必须有后端参与，能够保障客户端密钥的安全性。此模式从authorization接口获取授权码，从token接口获取令牌。

- **Implict 简化模式**：校验跳转URI验证客户端身份之后，直接发放accessToken。通常用于纯客户端应用，如单页应用javascript客户端。因为没有后端参与，密钥存放在前端是不安全的。由于安全校验较宽松，本模式不允许使用refreshToken来长时间维持登录状态。本模式的所有token从authorization接口获取。

- **Hybrid 混合流程**：混合流程顾名思义组合使用了授权码模式+简化模式。第一次前端请求授权服务器返回授权码+id_token，这样前端立刻可以使用用户的基本信息；第二次后端使用授权码+客户端密钥获取accessToken。本模式能够使用refreshToken来长时间维持登录状态。使用本模式必须有后端参与保证客户端密钥的安全性。混合模式比较想不到现实应用场景，之前看b站课程老外的说法是除非是安全性要求极高的金融领域，一般还是授权码模式最常用。

- **Resource Owner Password Credential 用户名密码模式**：一般用于无用户交互场景，或者第三方对接（如对接微信登录，实际登录界面就变成了微信的界面，如果不希望让客户扫了微信之后再跑你们系统登录一遍，就可以在后端用此模式静默登录接上自家的sso即可）
  
- **Client Credential 客户端密钥模式**：仅需要约定密钥，仅用于完全信任的内部系统

## 认证方式特点对比
特点|授权码模式|简化模式|混合模式  
--|--|--|--
所有token从Authorization接口返回|No|Yes|Yes
所有token从Token接口返回|Yes|No|No
所有tokens不暴露在浏览器|Yes|No|No
能够验证客户端密钥|Yes|No|Yes
能够使用刷新令牌|Yes|No|Yes
仅需一次请求|No|Yes|No
大部分请求由后端进行|Yes|No|可变

## 支持返回类型对比
返回类型|认证模式|说明
--|--|--
code|Authorization Code Flow|仅返回授权码
id_token|Implicit Flow|返回身份令牌
id_token token|Implicit Flow|返回身份令牌、通行令牌
code id_token|Hybrid Flow|返回授权码、身份令牌
code token|Hybrid Flow|返回授权码、通行令牌
code id_token token|Hybrid Flow|返回授权码、身份令牌、通行令牌

## 授权码模式解析
相对来说，授权码模式还是用的最多的，我们详细解读一下本模式的协议内容。
### 授权时序图
<div class="mermaid">
sequenceDiagram
    用户->>客户端: 请求受保护资源
    客户端->>认证服务: 准备入参，发起认证请求
    认证服务->>认证服务: 认证用户
    认证服务->>用户: 是否同意授权
    认证服务->>客户端: 发放授权码（前端进行）
    客户端->>认证服务: 使用授权码请求token（后端进行）
    认证服务->>认证服务: 校验客户端密钥，校验授权码
    认证服务->>认证服务: 发放身份令牌、通行令牌（后端进行）
    客户端->>客户端: 校验身份令牌，获取用户标识
</div>

### 认证请求
认证接口必须同时支持GET和POST两种请求方式。如果使用GET方法，客户端必须使用URI Query传递参数，如果使用POST方法，客户端必须使用Form传递参数。  

#### 参数定义
- **scope**：授权范围，必填。必须包含openid。
- **response_type**：返回类型，必填。定义了认证服务返回哪些参数。对于授权码模式，本参数只能是code。
- **client_id**：客户端id，必填。
- **redirect_uri**：跳转地址，必填。授权码生成之后，认证服务会带着授权码和其他参数回跳到此地址。此地址要求使用https。如果使用http，则客户端类型必须是confidential。
- **state**：状态字段，推荐填写。一般用于客户端与认证服务比对此字段，来防跨站伪造攻击，同时state也可以存放状态信息，如发起认证时的页面地址，用于认证完成后回到原始页面。
- 其他：略。上面五个是和OAuth2.0一样的参数，oidc还定义了一些扩展参数，用的很少，不是很懂，感兴趣的自己去看协议。

#### 请求报文示例
```http
HTTP/1.1 302 Found
  Location: https://server.example.com/authorize?
    response_type=code
    &scope=openid%20profile%20email
    &client_id=s6BhdRkqt3
    &state=af0ifjsldkj
    &redirect_uri=https%3A%2F%2Fclient.example.org%2Fcb
```
#### 认证请求校验
- 必填校验
- response_type必须为code
- scope必填，必须包含openid

#### 认证终端用户
- 下面两种情况认证服务必须认证用户
  - 用户尚未认证
  - 认证请求包含参数prompt=login，即使用户已经认证过也需要重新认证
  - 认证请求包含参数prompt=none，然后用户尚未被认证，则需要返回错误信息

认证服务必须想办法防止过程中的跨站伪造攻击和点击劫持攻击。

#### 获取终端用户授权/同意
终端用户通过认证之后，认证服务必须与终端用户交互，询问用户是否同意对客户端的授权。

### 认证响应
#### 成功响应
使用 application/x-www-form-urlencoded格式返回结果  
例如：
```http
 HTTP/1.1 302 Found
  Location: https://client.example.org/cb?
    code=SplxlOBeZQQYbYS6WxSbIA
    &state=af0ifjsldkj
```

#### 失败响应
错误代码包括这些  
oauth2.0定义的响应代码
- invalid_request：非法请求，未提供必填参数，参数非法等情况
- unauthorized_client：客户端未授权
- access_denied：用户无权限
- unsupported_response_type
- invalid_scope：非法的scope参数
- server_error
- temporarily_unavailable
另外oidc还扩展了一些响应代码，不常见，略  


例如：
```http
  HTTP/1.1 302 Found
  Location: https://client.example.org/cb?
    error=invalid_request
    &error_description=
      Unsupported%20response_type%20value
    &state=af0ifjsldkj
```

### 客户端校验授权码
协议规定客户端必须校验授权码的正确性

# 源码解析

从AuthorizeEndpoint的ProcessAsync方法作为入口开始认证接口的源码解析。

- 判断请求方式是GET还是POST，获取入参，如果是其他请求方式415状态码
- 从session中获取user
- 入参和user作为入参，调用父类ProcessAuthorizeRequestAsync方法
```csharp
    public override async Task<IEndpointResult> ProcessAsync(HttpContext context)
        {
            Logger.LogDebug("Start authorize request");

            NameValueCollection values;

            if (HttpMethods.IsGet(context.Request.Method))
            {
                values = context.Request.Query.AsNameValueCollection();
            }
            else if (HttpMethods.IsPost(context.Request.Method))
            {
                if (!context.Request.HasFormContentType)
                {
                    return new StatusCodeResult(HttpStatusCode.UnsupportedMediaType);
                }

                values = context.Request.Form.AsNameValueCollection();
            }
            else
            {
                return new StatusCodeResult(HttpStatusCode.MethodNotAllowed);
            }

            var user = await UserSession.GetUserAsync();
            var result = await ProcessAuthorizeRequestAsync(values, user, null);

            Logger.LogTrace("End authorize request. result type: {0}", result?.GetType().ToString() ?? "-none-");

            return result;
        }
```
认证站点如果cookie中存在当前会话信息，则直接返回用户信息，否则调用cookie架构的认证方法，会跳转到登录页面。

```csharp
public virtual async Task<ClaimsPrincipal> GetUserAsync()
{
    await AuthenticateAsync();

    return Principal;
}

protected virtual async Task AuthenticateAsync()
    {
        if (Principal == null || Properties == null)
        {
            var scheme = await GetCookieSchemeAsync();

            var handler = await Handlers.GetHandlerAsync(HttpContext, scheme);
            if (handler == null)
            {
                throw new InvalidOperationException($"No authentication handler is configured to authenticate for the scheme: {scheme}");
            }

            var result = await handler.AuthenticateAsync();
            if (result != null && result.Succeeded)
            {
                Principal = result.Principal;
                Properties = result.Properties;
            }
        }
    }
```

认证请求处理流程大致分为三步
- AuthorizeRequestValidator校验所有参数
- 认证接口consent入参为null，不需要处理用户交互判断
- 生成返回报文

```csharp
 internal async Task<IEndpointResult> ProcessAuthorizeRequestAsync(NameValueCollection parameters, ClaimsPrincipal user, ConsentResponse consent)
{
    if (user != null)
    {
        Logger.LogDebug("User in authorize request: {subjectId}", user.GetSubjectId());
    }
    else
    {
        Logger.LogDebug("No user present in authorize request");
    }

    // validate request
    var result = await _validator.ValidateAsync(parameters, user);
    if (result.IsError)
    {
        return await CreateErrorResultAsync(
            "Request validation failed",
            result.ValidatedRequest,
            result.Error,
            result.ErrorDescription);
    }

    var request = result.ValidatedRequest;
    LogRequest(request);

    // determine user interaction
    var interactionResult = await _interactionGenerator.ProcessInteractionAsync(request, consent);
    if (interactionResult.IsError)
    {
        return await CreateErrorResultAsync("Interaction generator error", request, interactionResult.Error, interactionResult.ErrorDescription, false);
    }
    if (interactionResult.IsLogin)
    {
        return new LoginPageResult(request);
    }
    if (interactionResult.IsConsent)
    {
        return new ConsentPageResult(request);
    }
    if (interactionResult.IsRedirect)
    {
        return new CustomRedirectResult(request, interactionResult.RedirectUrl);
    }

    var response = await _authorizeResponseGenerator.CreateResponseAsync(request);

    await RaiseResponseEventAsync(response);

    LogResponse(response);

    return new AuthorizeResult(response);
}
```

## 生成返回信息

此处只有AuthorizationCode、Implicit、Hybrid三种授权类型的判断，用户名密码、客户端密钥模式不能使用authorize接口。

```csharp
  public virtual async Task<AuthorizeResponse> CreateResponseAsync(ValidatedAuthorizeRequest request)
{
    if (request.GrantType == GrantType.AuthorizationCode)
    {
        return await CreateCodeFlowResponseAsync(request);
    }
    if (request.GrantType == GrantType.Implicit)
    {
        return await CreateImplicitFlowResponseAsync(request);
    }
    if (request.GrantType == GrantType.Hybrid)
    {
        return await CreateHybridFlowResponseAsync(request);
    }

    Logger.LogError("Unsupported grant type: " + request.GrantType);
    throw new InvalidOperationException("invalid grant type: " + request.GrantType);
}
```

- 如果state字段不为空，使用加密算法得到state的hash值
- 构建AuthorizationCode对象，存放在store中，store是idsv4用于持久化的对象，默认实现存储在内存中，可以对可插拔服务进行注入替换，实现数据保存在在mysql、redis等流行存储中
- 将授权码对象的id返回

```csharp
 protected virtual async Task<AuthorizeResponse> CreateCodeFlowResponseAsync(ValidatedAuthorizeRequest request)
{
    Logger.LogDebug("Creating Authorization Code Flow response.");

    var code = await CreateCodeAsync(request);
    var id = await AuthorizationCodeStore.StoreAuthorizationCodeAsync(code);

    var response = new AuthorizeResponse
    {
        Request = request,
        Code = id,
        SessionState = request.GenerateSessionStateValue()
    };

    return response;
}

protected virtual async Task<AuthorizationCode> CreateCodeAsync(ValidatedAuthorizeRequest request)
    {
        string stateHash = null;
        if (request.State.IsPresent())
        {
            var credential = await KeyMaterialService.GetSigningCredentialsAsync();
            if (credential == null)
            {
                throw new InvalidOperationException("No signing credential is configured.");
            }

            var algorithm = credential.Algorithm;
            stateHash = CryptoHelper.CreateHashClaimValue(request.State, algorithm);
        }

        var code = new AuthorizationCode
        {
            CreationTime = Clock.UtcNow.UtcDateTime,
            ClientId = request.Client.ClientId,
            Lifetime = request.Client.AuthorizationCodeLifetime,
            Subject = request.Subject,
            SessionId = request.SessionId,
            CodeChallenge = request.CodeChallenge.Sha256(),
            CodeChallengeMethod = request.CodeChallengeMethod,

            IsOpenId = request.IsOpenIdRequest,
            RequestedScopes = request.ValidatedScopes.GrantedResources.ToScopeNames(),
            RedirectUri = request.RedirectUri,
            Nonce = request.Nonce,
            StateHash = stateHash,

            WasConsentShown = request.WasConsentShown
        };

        return code;
    }
```

## 返回结果
- 如果ResponseMode等于Query或者Fragment，将授权码code及其他信息拼装到Uri，返回302重定向请求  
例子：
```
302 https://mysite.com?code=xxxxx&state=xxx
```

- 如果是FormPost方式，会生成一段脚本返回到客户端。窗口加载会触发form表单提交，将code、state等信息包裹在隐藏字段里提交到配置的rediret_uri。
```html
<html>
<head>
    <meta http-equiv='X-UA-Compatible' content='IE=edge' />
    <base target='_self'/>
</head>
<body>
    <form method='post' action='https://mysite.com'>
        <input type='hidden' name='code' value='xxx' />
        <input type='hidden' name='state' value='xxx' />
        <noscript>
            <button>Click to continue</button>
        </noscript>
    </form>
    <script>window.addEventListener('load', function(){document.forms[0].submit();});</script>
</body>
</html>
```
```csharp
private async Task RenderAuthorizeResponseAsync(HttpContext context)
{
    if (Response.Request.ResponseMode == OidcConstants.ResponseModes.Query ||
        Response.Request.ResponseMode == OidcConstants.ResponseModes.Fragment)
    {
        context.Response.SetNoCache();
        context.Response.Redirect(BuildRedirectUri());
    }
    else if (Response.Request.ResponseMode == OidcConstants.ResponseModes.FormPost)
    {
        context.Response.SetNoCache();
        AddSecurityHeaders(context);
        await context.Response.WriteHtmlAsync(GetFormPostHtml());
    }
    else
    {
        //_logger.LogError("Unsupported response mode.");
        throw new InvalidOperationException("Unsupported response mode");
    }
}
```

客户端在回调地址接收code，即可向token接口换取token。

## 其他

简单看一下简化流程和混合流程是怎么创建返回报文的。

### 简化流程生成返回报文
- 如果返回类型包含token，生成通行令牌
- 如果返回类型包含id_token，生成身份令牌

可以看到，简化流程的所有token都是由authorization接口返回的，一次请求返回所有token。

```csharp
protected virtual async Task<AuthorizeResponse> CreateImplicitFlowResponseAsync(ValidatedAuthorizeRequest request, string authorizationCode = null)
    {
        Logger.LogDebug("Creating Implicit Flow response.");

        string accessTokenValue = null;
        int accessTokenLifetime = 0;

        var responseTypes = request.ResponseType.FromSpaceSeparatedString();

        if (responseTypes.Contains(OidcConstants.ResponseTypes.Token))
        {
            var tokenRequest = new TokenCreationRequest
            {
                Subject = request.Subject,
                Resources = request.ValidatedScopes.GrantedResources,

                ValidatedRequest = request
            };

            var accessToken = await TokenService.CreateAccessTokenAsync(tokenRequest);
            accessTokenLifetime = accessToken.Lifetime;

            accessTokenValue = await TokenService.CreateSecurityTokenAsync(accessToken);
        }

        string jwt = null;
        if (responseTypes.Contains(OidcConstants.ResponseTypes.IdToken))
        {
            string stateHash = null;
            if (request.State.IsPresent())
            {
                var credential = await KeyMaterialService.GetSigningCredentialsAsync();
                if (credential == null)
                {
                    throw new InvalidOperationException("No signing credential is configured.");
                }

                var algorithm = credential.Algorithm;
                stateHash = CryptoHelper.CreateHashClaimValue(request.State, algorithm);
            }

            var tokenRequest = new TokenCreationRequest
            {
                ValidatedRequest = request,
                Subject = request.Subject,
                Resources = request.ValidatedScopes.GrantedResources,
                Nonce = request.Raw.Get(OidcConstants.AuthorizeRequest.Nonce),
                IncludeAllIdentityClaims = !request.AccessTokenRequested,
                AccessTokenToHash = accessTokenValue,
                AuthorizationCodeToHash = authorizationCode,
                StateHash = stateHash
            };

            var idToken = await TokenService.CreateIdentityTokenAsync(tokenRequest);
            jwt = await TokenService.CreateSecurityTokenAsync(idToken);
        }

        var response = new AuthorizeResponse
        {
            Request = request,
            AccessToken = accessTokenValue,
            AccessTokenLifetime = accessTokenLifetime,
            IdentityToken = jwt,
            SessionState = request.GenerateSessionStateValue()
        };

        return response;
    }
```
### 混合流程生成返回报文
这段代码充分体现了它为啥叫混合流程，把生成授权码的方法调一遍，再把简化流程的方法调一遍，code和token可以一起返回。

```csharp
protected virtual async Task<AuthorizeResponse> CreateHybridFlowResponseAsync(ValidatedAuthorizeRequest request)
    {
        Logger.LogDebug("Creating Hybrid Flow response.");

        var code = await CreateCodeAsync(request);
        var id = await AuthorizationCodeStore.StoreAuthorizationCodeAsync(code);

        var response = await CreateImplicitFlowResponseAsync(request, id);
        response.Code = id;

        return response;
    }
```

