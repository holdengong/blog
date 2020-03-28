---
title: "IdentityServer4源码解析_4_令牌发放接口"
date: 2020-03-26T23:49:34+08:00
draft: false
---
{{%idsv_menu%}}
# 协议
## Token接口
oidc服务需要提供token接口，提供AccessToken,IdToken,以及RefreshToken（可选）。在授权码模式下，token接口必须使用https。

## 请求

必须使用POST方法，使用x-www-form-urlencoded序列化参数，clientId:clientSecret使用Basic加密放在Authorization头中

```http
POST /token HTTP/1.1
Host: server.example.com
Content-Type: application/x-www-form-urlencoded
Authorization: Basic czZCaGRSa3F0MzpnWDFmQmF0M2JW

grant_type=authorization_code&code=SplxlOBeZQQYbYS6WxSbIA
&redirect_uri=https%3A%2F%2Fclient.example.org%2Fcb
```
## 请求校验
认证服务必须校验下列内容：
- 验证client是否颁发了秘钥
- 验证为该客户端颁发了授权码
- 验证授权码有效性
- 如果可能的话，验证授权码是否被使用过
- 验证redirect_uri 与发起认证请求时的值一致

## 成功响应
在收到token请求，并校验通过之后，认证服务返回成功报文，报文包含了身份令牌和通行令牌。数据格式使用application/json。token_type必须返回Bearer，其他类型token不在本协议范围内。在OAuth2.0响应报文基础上，oidc增加了id_tken。所有token包含了token或者其他敏感信息的响应报文，必须包含以下响应头。
```http
Cache-Control no-store
Pragma no-cache
```
## 失败响应
如果认证失败返回application/json格式错误消息，状态码400
```http
  HTTP/1.1 400 Bad Request
  Content-Type: application/json
  Cache-Control: no-store
  Pragma: no-cache

  {
   "error": "invalid_request"
  }
```
## id token校验

客户端必须校验返回的id token, 校验条件如下。对照这些条件，就可以更懂Microsoft.Authentication.OpenIdConnect里面的代码了，要做的事情很多。

1. 如果id token被加密，使用客户端注册时候约定的秘钥和算法解密。如果约定了加密方式，id token未被加密，客户端应该拒绝。
2. 签发方标识必须与iss声明一致
3. 客户端必须校验aud声明包含了它的客户端id，如果id token未返回正确的audience或者反悔了不被新人的audience，应该拒绝
4. 如果id token包含多个audience，需要校验是否有azp声明。azp即Authorized party，标识被授权的client。
5. 如果包含azp声明，客户端需要校验其值是否为自己的客户端id
6. 如果id token由token接口直接颁发给客户端（授权码模式就是如此），客户端必须根据alg参数值的算法验证签名。客户端必须使用签发方提供的秘钥。
7. alg值默认为RS256，客户端可以在注册的时候使用id_token_signed_response_alg参数指定配置。
8. 如果jwt的alg头使用了基于mac地址的加密算法，如HS256, HS384,HS512，aud声明中的字节会用作验签。（意思是会把mac地址相关信息写在aud声明上？）
9.  The current time MUST be before the time represented by the exp Claim.
    当前时间必须早于exp（token过期时间）。
10. iat（签发时间）可以用于拒绝过早、或者过于频繁签发的token，可以用于预防重放攻击。可接受时间范围由客户端自行决定。
11. 如果认证请求包含了nonce参数，客户端必须交验认证响应中返回的nonce值是否一致。防止重放攻击。
12. 如果客户端请求了acr声明（Authentication Context Class Reference，认证会话上下文，用于表示当前认证会话），必须交验acr值是否合法。
13. 如果客户端请求了auth_time声明，客户端应该校验认证时间是否已经超出，是否需要重新认证。

## access token校验
如果id_token中包含了at_hash声明，需要做下面的校验。at_hash标明了access_token和id_token之间的会话关联关系，做这个校验可以防跨站伪造。
1. 用idtoken的alg头标明的算法加密access_token，比如alg位RS256，则是用HSA-256算法加密。
2. 取hash值左边一般使用base64url加密
3. id token中的at_hash值必须跟上个步骤得到的值一致

校验规则很多，了解一下即可，绝大部分属于客户端需要做的部分，绝大部分跟安全有关。这一块的实现可以参考Microsoft.Authentication.OpenIdConnect，这是客户端的实现。我们现在看的IdentityServer是认证服务端的实现。

# 源码
## 五种授权模式
有下面几种授权模式可以请求token接口
- 授权码模式：最常用的code换token
- 混合模式：混合模式是授权码模式+简化模式混合使用的方式，在用授权码code找token接口换通行/身份令牌的逻辑与授权码模式的逻辑是一样的。idsv4中，混合模式没有自己的单独实现，只是把授权码+简化模式的代码同时调用。
- 客户端密钥模式：一般用于完全信任的内部系统，密钥换取access_token，由于没有用户参与，scope包含open_id是非法的
- 用户名密码模式：一般用于第三方对接、无界面交互场景。即username+password换token/id_token，password不一定是密码，也可以是验证码或其他的什么东西，这个完全取决于开发自己的实现
- 设备流模式（略）

**注意：简化模式所有的token都是由认证接口（authorize）一次性返回的，不能使用token接口。**

## 校验请求方法
token接口仅允许POST方法，Content-Type必须为application/x-www-form-urlencoded，否则抛出InvalidRequest错误。

```csharp
public async Task<IEndpointResult> ProcessAsync(HttpContext context)
    {
        _logger.LogTrace("Processing token request.");

        // validate HTTP
        if (!HttpMethods.IsPost(context.Request.Method) || !context.Request.HasFormContentType)
        {
            _logger.LogWarning("Invalid HTTP request for token endpoint");
            return Error(OidcConstants.TokenErrors.InvalidRequest);
        }

        return await ProcessTokenRequestAsync(context);
    }
```

## 处理流程
- 校验客户端
- 校验请求参数
- 创建返回值
- 返回结果
```csharp
private async Task<IEndpointResult> ProcessTokenRequestAsync(HttpContext context)
{
    _logger.LogDebug("Start token request.");

    // validate client
    var clientResult = await _clientValidator.ValidateAsync(context);

    if (clientResult.Client == null)
    {
        return Error(OidcConstants.TokenErrors.InvalidClient);
    }

    // validate request
    var form = (await context.Request.ReadFormAsync()).AsNameValueCollection();
    _logger.LogTrace("Calling into token request validator: {type}", _requestValidator.GetType().FullName);
    var requestResult = await _requestValidator.ValidateRequestAsync(form, clientResult);

    if (requestResult.IsError)
    {
        await _events.RaiseAsync(new TokenIssuedFailureEvent(requestResult));
        return Error(requestResult.Error, requestResult.ErrorDescription, requestResult.CustomResponse);
    }

    // create response
    _logger.LogTrace("Calling into token request response generator: {type}", _responseGenerator.GetType().FullName);
    var response = await _responseGenerator.ProcessAsync(requestResult);

    await _events.RaiseAsync(new TokenIssuedSuccessEvent(response, requestResult));
    LogTokens(response, requestResult);

    // return result
    _logger.LogDebug("Token request success.");
    return new TokenResult(response);
}
```

## 校验客户端
- 解码客户端秘钥，对应的处理类是BasicAuthenticationSecretParser，客户端id和秘钥用base64url加密方法放在Authorzaition头上。base64url基本是明文的，因为授权码换token是后端进行的，所以安全性没有问题
- 解码得到客户端id和秘钥之后，跟store对比校验客户端是否存在，秘钥是否一致。

```csharp
public async Task<ClientSecretValidationResult> ValidateAsync(HttpContext context)
{
    _logger.LogDebug("Start client validation");

    var fail = new ClientSecretValidationResult
    {
        IsError = true
    };

    var parsedSecret = await _parser.ParseAsync(context);
    if (parsedSecret == null)
    {
        await RaiseFailureEventAsync("unknown", "No client id found");

        _logger.LogError("No client identifier found");
        return fail;
    }

    // load client
    var client = await _clients.FindEnabledClientByIdAsync(parsedSecret.Id);
    if (client == null)
    {
        await RaiseFailureEventAsync(parsedSecret.Id, "Unknown client");

        _logger.LogError("No client with id '{clientId}' found. aborting", parsedSecret.Id);
        return fail;
    }

    SecretValidationResult secretValidationResult = null;
    if (!client.RequireClientSecret || client.IsImplicitOnly())
    {
        _logger.LogDebug("Public Client - skipping secret validation success");
    }
    else
    {
        secretValidationResult = await _validator.ValidateAsync(parsedSecret, client.ClientSecrets);
        if (secretValidationResult.Success == false)
        {
            await RaiseFailureEventAsync(client.ClientId, "Invalid client secret");
            _logger.LogError("Client secret validation failed for client: {clientId}.", client.ClientId);

            return fail;
        }
    }

    _logger.LogDebug("Client validation success");

    var success = new ClientSecretValidationResult
    {
        IsError = false,
        Client = client,
        Secret = parsedSecret,
        Confirmation = secretValidationResult?.Confirmation
    };

    await RaiseSuccessEventAsync(client.ClientId, parsedSecret.Type);
    return success;
}
```

## 校验请求参数
- 客户端的PortocalType必须位oidc，否则报错InvalidClient
- 校验GrantType，必填，长度不能超过100。
- GrantType默认支持以下几种类型，还可以自定义GrantType
  - authorization_code：授权码换token
  - client_credentials：客户端秘钥换token
  - password：用户名密码换token
  - refresn_token：刷新令牌换token
  - urn:ietf:params:oauth:grant-type:device_code：deviceflow，略

```csharp
public async Task<TokenRequestValidationResult> ValidateRequestAsync(NameValueCollection parameters, ClientSecretValidationResult clientValidationResult)
{
    _logger.LogDebug("Start token request validation");

    _validatedRequest = new ValidatedTokenRequest
    {
        Raw = parameters ?? throw new ArgumentNullException(nameof(parameters)),
        Options = _options
    };

    if (clientValidationResult == null) throw new ArgumentNullException(nameof(clientValidationResult));

    _validatedRequest.SetClient(clientValidationResult.Client, clientValidationResult.Secret, clientValidationResult.Confirmation);

    /////////////////////////////////////////////
    // check client protocol type
    /////////////////////////////////////////////
    if (_validatedRequest.Client.ProtocolType != IdentityServerConstants.ProtocolTypes.OpenIdConnect)
    {
        LogError("Invalid protocol type for client",
            new
            {
                clientId = _validatedRequest.Client.ClientId,
                expectedProtocolType = IdentityServerConstants.ProtocolTypes.OpenIdConnect,
                actualProtocolType = _validatedRequest.Client.ProtocolType
            });

        return Invalid(OidcConstants.TokenErrors.InvalidClient);
    }

    /////////////////////////////////////////////
    // check grant type
    /////////////////////////////////////////////
    var grantType = parameters.Get(OidcConstants.TokenRequest.GrantType);
    if (grantType.IsMissing())
    {
        LogError("Grant type is missing");
        return Invalid(OidcConstants.TokenErrors.UnsupportedGrantType);
    }

    if (grantType.Length > _options.InputLengthRestrictions.GrantType)
    {
        LogError("Grant type is too long");
        return Invalid(OidcConstants.TokenErrors.UnsupportedGrantType);
    }

    _validatedRequest.GrantType = grantType;

    switch (grantType)
    {
        case OidcConstants.GrantTypes.AuthorizationCode:
            return await RunValidationAsync(ValidateAuthorizationCodeRequestAsync, parameters);
        case OidcConstants.GrantTypes.ClientCredentials:
            return await RunValidationAsync(ValidateClientCredentialsRequestAsync, parameters);
        case OidcConstants.GrantTypes.Password:
            return await RunValidationAsync(ValidateResourceOwnerCredentialRequestAsync, parameters);
        case OidcConstants.GrantTypes.RefreshToken:
            return await RunValidationAsync(ValidateRefreshTokenRequestAsync, parameters);
        case OidcConstants.GrantTypes.DeviceCode:
            return await RunValidationAsync(ValidateDeviceCodeRequestAsync, parameters);
        default:
            return await RunValidationAsync(ValidateExtensionGrantRequestAsync, parameters);
    }
}
```
### 参数校验 - 授权码模式

- 客户端AllowedGrantTypes必须包含authorization_code或者hybrid,否则报错UnauthorizedClient。
- code必填，code长度不能超过100
- 客户端传过来的code只是授权码的id，从store中取出来授权码对象，如果不存在返回错误InvalidGrant
- 从store中移除授权码，此处实现了code只是用一次
- 如果授权码超出有效时长，返回错误invalidGrant
- 校验授权码对象的客户端id与当前客户端是否一致
- redirect_uri必填，且必须与授权码对象保存的redirect_uri一致，否则返回错误UnauthorizedClient
- 如果请求中没有任何scope，返回错误invalidRequest
- 判断用户是否启用，这个判断是由可插拔服务IProfileService的IsActive方法来实现的，开发可以注入自己的实现。如果用户禁用将返回错误InvalidGrant。

```csharp
private async Task<TokenRequestValidationResult> ValidateAuthorizationCodeRequestAsync(NameValueCollection parameters)
    {
        _logger.LogDebug("Start validation of authorization code token request");

        /////////////////////////////////////////////
        // check if client is authorized for grant type
        /////////////////////////////////////////////
        if (!_validatedRequest.Client.AllowedGrantTypes.ToList().Contains(GrantType.AuthorizationCode) &&
            !_validatedRequest.Client.AllowedGrantTypes.ToList().Contains(GrantType.Hybrid))
        {
            LogError("Client not authorized for code flow");
            return Invalid(OidcConstants.TokenErrors.UnauthorizedClient);
        }

        /////////////////////////////////////////////
        // validate authorization code
        /////////////////////////////////////////////
        var code = parameters.Get(OidcConstants.TokenRequest.Code);
        if (code.IsMissing())
        {
            LogError("Authorization code is missing");
            return Invalid(OidcConstants.TokenErrors.InvalidGrant);
        }

        if (code.Length > _options.InputLengthRestrictions.AuthorizationCode)
        {
            LogError("Authorization code is too long");
            return Invalid(OidcConstants.TokenErrors.InvalidGrant);
        }

        _validatedRequest.AuthorizationCodeHandle = code;

        var authZcode = await _authorizationCodeStore.GetAuthorizationCodeAsync(code);
        if (authZcode == null)
        {
            LogError("Invalid authorization code", new { code });
            return Invalid(OidcConstants.TokenErrors.InvalidGrant);
        }

        await _authorizationCodeStore.RemoveAuthorizationCodeAsync(code);

        if (authZcode.CreationTime.HasExceeded(authZcode.Lifetime, _clock.UtcNow.UtcDateTime))
        {
            LogError("Authorization code expired", new { code });
            return Invalid(OidcConstants.TokenErrors.InvalidGrant);
        }

        /////////////////////////////////////////////
        // populate session id
        /////////////////////////////////////////////
        if (authZcode.SessionId.IsPresent())
        {
            _validatedRequest.SessionId = authZcode.SessionId;
        }

        /////////////////////////////////////////////
        // validate client binding
        /////////////////////////////////////////////
        if (authZcode.ClientId != _validatedRequest.Client.ClientId)
        {
            LogError("Client is trying to use a code from a different client", new { clientId = _validatedRequest.Client.ClientId, codeClient = authZcode.ClientId });
            return Invalid(OidcConstants.TokenErrors.InvalidGrant);
        }

        /////////////////////////////////////////////
        // validate code expiration
        /////////////////////////////////////////////
        if (authZcode.CreationTime.HasExceeded(_validatedRequest.Client.AuthorizationCodeLifetime, _clock.UtcNow.UtcDateTime))
        {
            LogError("Authorization code is expired");
            return Invalid(OidcConstants.TokenErrors.InvalidGrant);
        }

        _validatedRequest.AuthorizationCode = authZcode;
        _validatedRequest.Subject = authZcode.Subject;

        /////////////////////////////////////////////
        // validate redirect_uri
        /////////////////////////////////////////////
        var redirectUri = parameters.Get(OidcConstants.TokenRequest.RedirectUri);
        if (redirectUri.IsMissing())
        {
            LogError("Redirect URI is missing");
            return Invalid(OidcConstants.TokenErrors.UnauthorizedClient);
        }

        if (redirectUri.Equals(_validatedRequest.AuthorizationCode.RedirectUri, StringComparison.Ordinal) == false)
        {
            LogError("Invalid redirect_uri", new { redirectUri, expectedRedirectUri = _validatedRequest.AuthorizationCode.RedirectUri });
            return Invalid(OidcConstants.TokenErrors.UnauthorizedClient);
        }

        /////////////////////////////////////////////
        // validate scopes are present
        /////////////////////////////////////////////
        if (_validatedRequest.AuthorizationCode.RequestedScopes == null ||
            !_validatedRequest.AuthorizationCode.RequestedScopes.Any())
        {
            LogError("Authorization code has no associated scopes");
            return Invalid(OidcConstants.TokenErrors.InvalidRequest);
        }

        /////////////////////////////////////////////
        // validate PKCE parameters
        /////////////////////////////////////////////
        var codeVerifier = parameters.Get(OidcConstants.TokenRequest.CodeVerifier);
        if (_validatedRequest.Client.RequirePkce || _validatedRequest.AuthorizationCode.CodeChallenge.IsPresent())
        {
            _logger.LogDebug("Client required a proof key for code exchange. Starting PKCE validation");

            var proofKeyResult = ValidateAuthorizationCodeWithProofKeyParameters(codeVerifier, _validatedRequest.AuthorizationCode);
            if (proofKeyResult.IsError)
            {
                return proofKeyResult;
            }

            _validatedRequest.CodeVerifier = codeVerifier;
        }
        else
        {
            if (codeVerifier.IsPresent())
            {
                LogError("Unexpected code_verifier: {codeVerifier}. This happens when the client is trying to use PKCE, but it is not enabled. Set RequirePkce to true.", codeVerifier);
                return Invalid(OidcConstants.TokenErrors.InvalidGrant);
            }
        }

        /////////////////////////////////////////////
        // make sure user is enabled
        /////////////////////////////////////////////
        var isActiveCtx = new IsActiveContext(_validatedRequest.AuthorizationCode.Subject, _validatedRequest.Client, IdentityServerConstants.ProfileIsActiveCallers.AuthorizationCodeValidation);
        await _profile.IsActiveAsync(isActiveCtx);

        if (isActiveCtx.IsActive == false)
        {
            LogError("User has been disabled", new { subjectId = _validatedRequest.AuthorizationCode.Subject.GetSubjectId() });
            return Invalid(OidcConstants.TokenErrors.InvalidGrant);
        }

        _logger.LogDebug("Validation of authorization code token request success");

        return Valid();
    }
```

### 参数校验 - 客户端秘钥模式
- 校验Client是否允许使用客户端秘钥认证模式
- 校验客户端是否允许访问请求的授权范围scope
- scope中包含openid的话返回错误invlidScope，因为本模式没有涉及用户信息
- cope中包含offline_access则返回错误InvalidScope，本模式不允许使用refresh_token
```csharp
private async Task<TokenRequestValidationResult> ValidateClientCredentialsRequestAsync(NameValueCollection parameters)
    {
        _logger.LogDebug("Start client credentials token request validation");

        /////////////////////////////////////////////
        // check if client is authorized for grant type
        /////////////////////////////////////////////
        if (!_validatedRequest.Client.AllowedGrantTypes.ToList().Contains(GrantType.ClientCredentials))
        {
            LogError("Client not authorized for client credentials flow, check the AllowedGrantTypes setting", new { clientId = _validatedRequest.Client.ClientId });
            return Invalid(OidcConstants.TokenErrors.UnauthorizedClient);
        }

        /////////////////////////////////////////////
        // check if client is allowed to request scopes
        /////////////////////////////////////////////
        if (!await ValidateRequestedScopesAsync(parameters, ignoreImplicitIdentityScopes: true, ignoreImplicitOfflineAccess: true))
        {
            return Invalid(OidcConstants.TokenErrors.InvalidScope);
        }

        if (_validatedRequest.ValidatedScopes.ContainsOpenIdScopes)
        {
            LogError("Client cannot request OpenID scopes in client credentials flow", new { clientId = _validatedRequest.Client.ClientId });
            return Invalid(OidcConstants.TokenErrors.InvalidScope);
        }

        if (_validatedRequest.ValidatedScopes.ContainsOfflineAccessScope)
        {
            LogError("Client cannot request a refresh token in client credentials flow", new { clientId = _validatedRequest.Client.ClientId });
            return Invalid(OidcConstants.TokenErrors.InvalidScope);
        }

        _logger.LogDebug("{clientId} credentials token request validation success", _validatedRequest.Client.ClientId);
        return Valid();
    }
```

### 参数校验 - 用户名密码模式
- 校验客户端是否允许使用用户名密码模式，校验失败返回UnauthoriedClient错误
- 校验客户端是否有权访问所请求的所有scope，校验失败返回InvalidScope错误
- 从请求中获取username和password参数，未提供username返回InvalidGrant错误，未提供password则设置password位空值
- username和password长度不能超过100，否则返回InvalidGrant错误
- 使用IResourceOwnerPasswordValidator校验username和password，此接口需要开发实现后注入，否则会抛出异常
- GrantValidationResult的Subject不能为null，因此开发的IResourceOwnerPasswordValidator实现，校验成功后必须给GrantValidationResult赋值
- 校验用户是否禁用，根据可插拔服务IProfileService的IsAcrtive方法判断，如果禁用返回IvalidGrant错误。

```csharp
private async Task<TokenRequestValidationResult> ValidateResourceOwnerCredentialRequestAsync(NameValueCollection parameters)
{
    _logger.LogDebug("Start resource owner password token request validation");

    /////////////////////////////////////////////
    // check if client is authorized for grant type
    /////////////////////////////////////////////
    if (!_validatedRequest.Client.AllowedGrantTypes.Contains(GrantType.ResourceOwnerPassword))
    {
        LogError("Client not authorized for resource owner flow, check the AllowedGrantTypes setting", new { client_id = _validatedRequest.Client.ClientId });
        return Invalid(OidcConstants.TokenErrors.UnauthorizedClient);
    }

    /////////////////////////////////////////////
    // check if client is allowed to request scopes
    /////////////////////////////////////////////
    if (!(await ValidateRequestedScopesAsync(parameters)))
    {
        return Invalid(OidcConstants.TokenErrors.InvalidScope);
    }

    /////////////////////////////////////////////
    // check resource owner credentials
    /////////////////////////////////////////////
    var userName = parameters.Get(OidcConstants.TokenRequest.UserName);
    var password = parameters.Get(OidcConstants.TokenRequest.Password);

    if (userName.IsMissing())
    {
        LogError("Username is missing");
        return Invalid(OidcConstants.TokenErrors.InvalidGrant);
    }

    if (password.IsMissing())
    {
        password = "";
    }

    if (userName.Length > _options.InputLengthRestrictions.UserName ||
        password.Length > _options.InputLengthRestrictions.Password)
    {
        LogError("Username or password too long");
        return Invalid(OidcConstants.TokenErrors.InvalidGrant);
    }

    _validatedRequest.UserName = userName;


    /////////////////////////////////////////////
    // authenticate user
    /////////////////////////////////////////////
    var resourceOwnerContext = new ResourceOwnerPasswordValidationContext
    {
        UserName = userName,
        Password = password,
        Request = _validatedRequest
    };
    await _resourceOwnerValidator.ValidateAsync(resourceOwnerContext);

    if (resourceOwnerContext.Result.IsError)
    {
        // protect against bad validator implementations
        resourceOwnerContext.Result.Error = resourceOwnerContext.Result.Error ?? OidcConstants.TokenErrors.InvalidGrant;

        if (resourceOwnerContext.Result.Error == OidcConstants.TokenErrors.UnsupportedGrantType)
        {
            LogError("Resource owner password credential grant type not supported");
            await RaiseFailedResourceOwnerAuthenticationEventAsync(userName, "password grant type not supported", resourceOwnerContext.Request.Client.ClientId);

            return Invalid(OidcConstants.TokenErrors.UnsupportedGrantType, customResponse: resourceOwnerContext.Result.CustomResponse);
        }

        var errorDescription = "invalid_username_or_password";

        if (resourceOwnerContext.Result.ErrorDescription.IsPresent())
        {
            errorDescription = resourceOwnerContext.Result.ErrorDescription;
        }

        LogInformation("User authentication failed: ", errorDescription ?? resourceOwnerContext.Result.Error);
        await RaiseFailedResourceOwnerAuthenticationEventAsync(userName, errorDescription, resourceOwnerContext.Request.Client.ClientId);

        return Invalid(resourceOwnerContext.Result.Error, errorDescription, resourceOwnerContext.Result.CustomResponse);
    }

    if (resourceOwnerContext.Result.Subject == null)
    {
        var error = "User authentication failed: no principal returned";
        LogError(error);
        await RaiseFailedResourceOwnerAuthenticationEventAsync(userName, error, resourceOwnerContext.Request.Client.ClientId);

        return Invalid(OidcConstants.TokenErrors.InvalidGrant);
    }

    /////////////////////////////////////////////
    // make sure user is enabled
    /////////////////////////////////////////////
    var isActiveCtx = new IsActiveContext(resourceOwnerContext.Result.Subject, _validatedRequest.Client, IdentityServerConstants.ProfileIsActiveCallers.ResourceOwnerValidation);
    await _profile.IsActiveAsync(isActiveCtx);

    if (isActiveCtx.IsActive == false)
    {
        LogError("User has been disabled", new { subjectId = resourceOwnerContext.Result.Subject.GetSubjectId() });
        await RaiseFailedResourceOwnerAuthenticationEventAsync(userName, "user is inactive", resourceOwnerContext.Request.Client.ClientId);

        return Invalid(OidcConstants.TokenErrors.InvalidGrant);
    }

    _validatedRequest.UserName = userName;
    _validatedRequest.Subject = resourceOwnerContext.Result.Subject;

    await RaiseSuccessfulResourceOwnerAuthenticationEventAsync(userName, resourceOwnerContext.Result.Subject.GetSubjectId(), resourceOwnerContext.Request.Client.ClientId);
    _logger.LogDebug("Resource owner password token request validation success.");
    return Valid(resourceOwnerContext.Result.CustomResponse);
}
```

### 参数校验 - RefreshToken

RefreshToken-刷新令牌。顾名思义，用于刷新通行令牌的凭证。拥有offline_access权限的客户端可以使用刷新令牌。只有授权码、混合流程等由后端参与的授权模式才允许使用刷新令牌。

- 从请求中获取refresh_token参数值，如果为空则返回InvalidRequest错误
- 如果刷新令牌长度超过100，返回InvalidGrant错误
- 判断刷新令牌是否存在且有效
  - 是否能从store中查询到刷新令牌对象
  - 校验刷新令牌是否过期
  - 校验刷新令牌是否属于当前客户端
  - 校验客户端是否仍然有offline_access权限
  - 校验用户是否被禁用

```csharp
private async Task<TokenRequestValidationResult> ValidateRefreshTokenRequestAsync(NameValueCollection parameters)
{
    _logger.LogDebug("Start validation of refresh token request");

    var refreshTokenHandle = parameters.Get(OidcConstants.TokenRequest.RefreshToken);
    if (refreshTokenHandle.IsMissing())
    {
        LogError("Refresh token is missing");
        return Invalid(OidcConstants.TokenErrors.InvalidRequest);
    }

    if (refreshTokenHandle.Length > _options.InputLengthRestrictions.RefreshToken)
    {
        LogError("Refresh token too long");
        return Invalid(OidcConstants.TokenErrors.InvalidGrant);
    }

    var result = await _tokenValidator.ValidateRefreshTokenAsync(refreshTokenHandle, _validatedRequest.Client);

    if (result.IsError)
    {
        LogWarning("Refresh token validation failed. aborting");
        return Invalid(OidcConstants.TokenErrors.InvalidGrant);
    }

    _validatedRequest.RefreshToken = result.RefreshToken;
    _validatedRequest.RefreshTokenHandle = refreshTokenHandle;
    _validatedRequest.Subject = result.RefreshToken.Subject;

    _logger.LogDebug("Validation of refresh token request success");
    return Valid();
}
```

## 生成响应报文 - 授权码模式
- 生成accessToken和refreshToken
  - 通行令牌由ITokenService接口，默认实现DefaultTokenService的CreateAccessTokenAsync方法生成
  - 如果请求了offline_access才生成refresh_token
  - 如果code是oidc授权码，生成id_token。DefaultTokenService的CreateIdentityTokenAsync方法生成Token对象，CreateSecurityTokenAsync方法将Token对象加密为jwt。
```csharp
protected virtual async Task<TokenResponse> ProcessAuthorizationCodeRequestAsync(TokenRequestValidationResult request)
    {
        Logger.LogTrace("Creating response for authorization code request");

        //////////////////////////
        // access token
        /////////////////////////
        (var accessToken, var refreshToken) = await CreateAccessTokenAsync(request.ValidatedRequest);
        var response = new TokenResponse
        {
            AccessToken = accessToken,
            AccessTokenLifetime = request.ValidatedRequest.AccessTokenLifetime,
            Custom = request.CustomResponse,
            Scope = request.ValidatedRequest.AuthorizationCode.RequestedScopes.ToSpaceSeparatedString(),
        };

        //////////////////////////
        // refresh token
        /////////////////////////
        if (refreshToken.IsPresent())
        {
            response.RefreshToken = refreshToken;
        }

        //////////////////////////
        // id token
        /////////////////////////
        if (request.ValidatedRequest.AuthorizationCode.IsOpenId)
        {
            // load the client that belongs to the authorization code
            Client client = null;
            if (request.ValidatedRequest.AuthorizationCode.ClientId != null)
            {
                client = await Clients.FindEnabledClientByIdAsync(request.ValidatedRequest.AuthorizationCode.ClientId);
            }
            if (client == null)
            {
                throw new InvalidOperationException("Client does not exist anymore.");
            }

            var resources = await Resources.FindEnabledResourcesByScopeAsync(request.ValidatedRequest.AuthorizationCode.RequestedScopes);

            var tokenRequest = new TokenCreationRequest
            {
                Subject = request.ValidatedRequest.AuthorizationCode.Subject,
                Resources = resources,
                Nonce = request.ValidatedRequest.AuthorizationCode.Nonce,
                AccessTokenToHash = response.AccessToken,
                StateHash = request.ValidatedRequest.AuthorizationCode.StateHash,
                ValidatedRequest = request.ValidatedRequest
            };

            var idToken = await TokenService.CreateIdentityTokenAsync(tokenRequest);
            var jwt = await TokenService.CreateSecurityTokenAsync(idToken);
            response.IdentityToken = jwt;
        }

        return response;
    }
```

## 生成响应报文 - 客户端密钥模式
- 仅生成accessToken
```csharp
protected virtual Task<TokenResponse> ProcessClientCredentialsRequestAsync(TokenRequestValidationResult request)
{
    Logger.LogTrace("Creating response for client credentials request");

    return ProcessTokenRequestAsync(request);
}

protected virtual async Task<TokenResponse> ProcessTokenRequestAsync(TokenRequestValidationResult validationResult)
    {
        (var accessToken, var refreshToken) = await CreateAccessTokenAsync(validationResult.ValidatedRequest);
        var response = new TokenResponse
        {
            AccessToken = accessToken,
            AccessTokenLifetime = validationResult.ValidatedRequest.AccessTokenLifetime,
            Custom = validationResult.CustomResponse,
            Scope = validationResult.ValidatedRequest.Scopes.ToSpaceSeparatedString()
        };

        if (refreshToken.IsPresent())
        {
            response.RefreshToken = refreshToken;
        }

        return response;
    }
```

## 生成响应报文 - 用户名密码模式
- 生成accessToken
- 如果申请了offline_access且有权限，同时返回refresh_token
- 不会返回id_token，我理解的是授权码等模式是有限授权，需要code换id_token，才能拿到用户id以及其他的基本信息。而密码模式是完全信任授权，账号密码都给你了，还整id_token干嘛，你要啥信息，自己实现IResourceOwnerPasswordValidator，自己去库里取就完事了，还要啥自行车。
```csharp
protected virtual Task<TokenResponse> ProcessPasswordRequestAsync(TokenRequestValidationResult request)
    {
        Logger.LogTrace("Creating response for password request");

        return ProcessTokenRequestAsync(request);
    }
```

## 生成响应报文 - 刷新令牌
- 从请求中取出旧通行令牌
- 判断客户端配置UpdateAccessTokenClaimsOnRefresh-是否在刷新令牌的时候更新通行令牌的claims，默认false。如果为true，则创建新的token对象，否则使用旧的token，只是刷新token的创建时间和有效时间。
- 判断客户端配置RefreshTokenUsage - 刷新令牌用法，0：ReUse可重复使用 1：OnTimeOnly一次性，默认1。如果是一次性的话，从store中删除旧的刷新令牌，创建新的刷新令牌。
- 判断客户端配置RefreshTokenExpiration - 刷新令牌过期类型，0：Sliding，1：Absolute，默认1。如果是0，需要重新计算相对时间。
- 如果刷新令牌请求包含了任意身份资源，创建新的身份令牌。

```csharp
protected virtual async Task<TokenResponse> ProcessRefreshTokenRequestAsync(TokenRequestValidationResult request)
    {
        Logger.LogTrace("Creating response for refresh token request");

        var oldAccessToken = request.ValidatedRequest.RefreshToken.AccessToken;
        string accessTokenString;

        if (request.ValidatedRequest.Client.UpdateAccessTokenClaimsOnRefresh)
        {
            var subject = request.ValidatedRequest.RefreshToken.Subject;

            var creationRequest = new TokenCreationRequest
            {
                Subject = subject,
                ValidatedRequest = request.ValidatedRequest,
                Resources = await Resources.FindEnabledResourcesByScopeAsync(oldAccessToken.Scopes)
            };

            var newAccessToken = await TokenService.CreateAccessTokenAsync(creationRequest);
            accessTokenString = await TokenService.CreateSecurityTokenAsync(newAccessToken);
        }
        else
        {
            oldAccessToken.CreationTime = Clock.UtcNow.UtcDateTime;
            oldAccessToken.Lifetime = request.ValidatedRequest.AccessTokenLifetime;

            accessTokenString = await TokenService.CreateSecurityTokenAsync(oldAccessToken);
        }

        var handle = await RefreshTokenService.UpdateRefreshTokenAsync(request.ValidatedRequest.RefreshTokenHandle, request.ValidatedRequest.RefreshToken, request.ValidatedRequest.Client);

        return new TokenResponse
        {
            IdentityToken = await CreateIdTokenFromRefreshTokenRequestAsync(request.ValidatedRequest, accessTokenString),
            AccessToken = accessTokenString,
            AccessTokenLifetime = request.ValidatedRequest.AccessTokenLifetime,
            RefreshToken = handle,
            Custom = request.CustomResponse,
            Scope = request.ValidatedRequest.RefreshToken.Scopes.ToSpaceSeparatedString()
        };
    }
```