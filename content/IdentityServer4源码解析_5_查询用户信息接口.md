---
title: "IdentityServer4源码解析_5_查询用户信息接口"
date: 2020-03-26T23:49:40+08:00
draft: false
---
{{%idsv_menu%}}

# 协议简析
UserInfo接口是OAuth2.0中规定的需要认证访问的接口，可以返回认证用户的声明信息。请求UserInfo接口需要使用通行令牌。响应报文通常是json数据格式，包含了一组claim键值对集合。与UserInfo接口通讯必须使用https。  

根据RFC2616协议，UserInfo必须支持GET和POST方法。  

UserInfo接口必须接受Bearer令牌。  

UserInfo接口应该支持javascript客户端跨域访问，可以使用CORS协议或者其他方案。  

## UserInfo请求
推荐使用GET方法，使用Authorization头承载Bearer令牌来请求UserInfo接口。  
```http
GET /userinfo HTTP/1.1
Host: server.example.com
Authorization: Bearer SlAV32hkKG
```

## 成功响应
如果某个claim为空或者null，不返回该键。  
必须返回sub（subject）声明。  
必须校验UserInfo返回的sub与id_token中的sub是否一致  
content-type必须是application/json，必须使用utf-8编码  
如果加密位jwt返回，content-type必须位application/jwt  
```http
HTTP/1.1 200 OK
Content-Type: application/json

{
"sub": "248289761001",
"name": "Jane Doe",
"given_name": "Jane",
"family_name": "Doe",
"preferred_username": "j.doe",
"email": "janedoe@example.com",
"picture": "http://example.com/janedoe/me.jpg"
}
```
## 失败响应
```http
HTTP/1.1 401 Unauthorized
WWW-Authenticate: error="invalid_token",
error_description="The Access Token expired"
```
## 响应校验
客户端必须校验如下内容
- 校验认证服务身份(https)
- 如果客户端注册时设置了userinfo_encrypted_response_alg ，收到响应时用对应算法解密
- 如果响应有签名，客户端需要验签

# 源码解析
## 校验通行令牌
- 首先会尝试从`Authorizaton`头中获取`Bearer Token`的值，找到的话则返回
- 如果content-type为表单类型，尝试从表单中获取`access_token`参数值
- 两处都没有获取到`Beaer Token`的话则返回校验失败结果

```csharp
public async Task<BearerTokenUsageValidationResult> ValidateAsync(HttpContext context)
    {
        var result = ValidateAuthorizationHeader(context);
        if (result.TokenFound)
        {
            _logger.LogDebug("Bearer token found in header");
            return result;
        }

        if (context.Request.HasFormContentType)
        {
            result = await ValidatePostBodyAsync(context);
            if (result.TokenFound)
            {
                _logger.LogDebug("Bearer token found in body");
                return result;
            }
        }

        _logger.LogDebug("Bearer token not found");
        return new BearerTokenUsageValidationResult();
    }
```
## 校验请求参数
由`IUserInfoRequestValidator`的默认实现`UserInfoRequestValidator`对入参进行校验。
1. `accessToken`，必须包括`openid`声明的权限
2. 必须有`sub`声明,`sub`是`subject`的缩写，代表用户唯一标识
3. 收集`accessToken`所有`claim`，移除以下与用户信息无关的`claim`。  
  at_hash,aud,azp,c_hash,client_id,exp,iat,iss,jti,nonce,nbf,reference_token_id,sid,scope  
  用筛选后的`claim`创建名称为`UserInfo`的`Principal`
4. 调用`IProfileService`的`IsAcriveAsync`方法判断用户是否启用，不是启动状态的话返回`invalid_token`错误
5. 返回校验成功结果对象，包括步骤3构建的`Principal` 

```csharp

public async Task<UserInfoRequestValidationResult> ValidateRequestAsync(string accessToken)
{
    // the access token needs to be valid and have at least the openid scope
    var tokenResult = await _tokenValidator.ValidateAccessTokenAsync(
        accessToken,
        IdentityServerConstants.StandardScopes.OpenId);

    if (tokenResult.IsError)
    {
        return new UserInfoRequestValidationResult
        {
            IsError = true,
            Error = tokenResult.Error
        };
    }

    // the token must have a one sub claim
    var subClaim = tokenResult.Claims.SingleOrDefault(c => c.Type == JwtClaimTypes.Subject);
    if (subClaim == null)
    {
        _logger.LogError("Token contains no sub claim");

        return new UserInfoRequestValidationResult
        {
            IsError = true,
            Error = OidcConstants.ProtectedResourceErrors.InvalidToken
        };
    }

    // create subject from incoming access token
    var claims = tokenResult.Claims.Where(x => !Constants.Filters.ProtocolClaimsFilter.Contains(x.Type));
    var subject = Principal.Create("UserInfo", claims.ToArray());

    // make sure user is still active
    var isActiveContext = new IsActiveContext(subject, tokenResult.Client, IdentityServerConstants.ProfileIsActiveCallers.UserInfoRequestValidation);
    await _profile.IsActiveAsync(isActiveContext);

    if (isActiveContext.IsActive == false)
    {
        _logger.LogError("User is not active: {sub}", subject.GetSubjectId());

        return new UserInfoRequestValidationResult
        {
            IsError = true,
            Error = OidcConstants.ProtectedResourceErrors.InvalidToken
        };
    }

    return new UserInfoRequestValidationResult
    {
        IsError = false,
        TokenValidationResult = tokenResult,
        Subject = subject
    };
}
```
## 生成响应报文
调用`IUserInfoResponseGenerator`接口的默认实现`UserInfoResponseGenerator`的`ProcessAsync`方法生成响应报文。  
1. 从校验结果中获取`scope`声明值，查询`scope`值关联的`IdentityResource`(身份资源)及其关联的所有`claim`。得到的结果就是用户请求的所有`claim`
2. 调用`DefaultProfileService`的`GetProfileDataAsync`方法，返回校验结果`claim`与用户请求`claim`的交集。
3. 如果`claim`集合中没有`sub`，取校验结果中的`sub`值。如果`IProfileService`返回的`sub`声明值与校验结果的`sub`值不一致抛出异常。
4. 返回`claim`集合。
5. 响应头写入`Cache-Control:no-store, no-cache, max-age=0`,`Pragma:no-cache`
6. `claim`集合用json格式写入响应内容
   
```csharp
 public virtual async Task<Dictionary<string, object>> ProcessAsync(UserInfoRequestValidationResult validationResult)
{
    Logger.LogDebug("Creating userinfo response");

    // extract scopes and turn into requested claim types
    var scopes = validationResult.TokenValidationResult.Claims.Where(c => c.Type == JwtClaimTypes.Scope).Select(c => c.Value);
    var requestedClaimTypes = await GetRequestedClaimTypesAsync(scopes);

    Logger.LogDebug("Requested claim types: {claimTypes}", requestedClaimTypes.ToSpaceSeparatedString());

    // call profile service
    var context = new ProfileDataRequestContext(
        validationResult.Subject,
        validationResult.TokenValidationResult.Client,
        IdentityServerConstants.ProfileDataCallers.UserInfoEndpoint,
        requestedClaimTypes);
    context.RequestedResources = await GetRequestedResourcesAsync(scopes);

    await Profile.GetProfileDataAsync(context);
    var profileClaims = context.IssuedClaims;

    // construct outgoing claims
    var outgoingClaims = new List<Claim>();

    if (profileClaims == null)
    {
        Logger.LogInformation("Profile service returned no claims (null)");
    }
    else
    {
        outgoingClaims.AddRange(profileClaims);
        Logger.LogInformation("Profile service returned the following claim types: {types}", profileClaims.Select(c => c.Type).ToSpaceSeparatedString());
    }

    var subClaim = outgoingClaims.SingleOrDefault(x => x.Type == JwtClaimTypes.Subject);
    if (subClaim == null)
    {
        outgoingClaims.Add(new Claim(JwtClaimTypes.Subject, validationResult.Subject.GetSubjectId()));
    }
    else if (subClaim.Value != validationResult.Subject.GetSubjectId())
    {
        Logger.LogError("Profile service returned incorrect subject value: {sub}", subClaim);
        throw new InvalidOperationException("Profile service returned incorrect subject value");
    }

    return outgoingClaims.ToClaimsDictionary();
}
```
