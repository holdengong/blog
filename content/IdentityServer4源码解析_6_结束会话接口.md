---
title: "IdentityServer4源码解析_6_结束会话接口"
date: 2020-03-26T23:49:47+08:00
draft: false
---
{{%idsv_menu%}}
# 协议简析
会话管理属于可选协议内容，地址如下
> https://openid.net/specs/openid-connect-session-1_0.html

## 认证服务元数据
以下参数必须在元数据中提供
- check_session_iframe：必填。在客户端嵌入一个不可见的iframe，地址指向认证服务的checksession地址，使用HTML5的`postMessage API`互相通讯，客户端向checksession发送请求，认证服务返回用户的登录状态。**注意此处属于跨站请求，Cookie的SameSite设置可能影响此处行为**
  ```
  https://localhost:10000/connect/checksession
  ```

## 登出的两种方式
### 前端登出
客户端在向认证服务注册的时候需要提供`frontchannel_logout_uri`（前端登出地址）。域名端口和架构必须与`redirect_uri`一致。  

登出地址必须是绝对地址，可以包括`application/x-www-form-urlencoded`编码的query参数。  

认证服务在页面中渲染一个隐藏的iframe，src指向`frontchannel_logout_uri`。  
```html
<iframe src="frontchannel_logout_uri">
```

客户端的`frontchannel_logout_session_required`属性，决定认证服务向客户端发送登出请求的时候是否带上`iss`和`sid`参数。  

#### 前端登出 - 认证服务发起
如果有多个客户端登入，认证站点会有多个`iframe`，登出的时候逐个通知。  

认证服务元数据中的`frontchannel_logout_supported`说明是否支持前端登出。`frontchannel_logout_session_supported`说明登出是否支持传递`iss`，`sid`参数。  

`sid` : session id，会话id。  

示例：  
客户端注册`frontchannel_logout_uri`为https://rp.example.org/frontchannel_logout，`frontchannel_logout_session_required`为true，认证服务渲染如下html代码段触发前端登出。  
```http
<iframe src="https://rp.example.org/frontchannel_logout
    ?iss=https://server.example.com
    &sid=08a5019c-17e1-4977-8f42-65a12843ea02">
</iframe>
```

#### 前端登出 - 客户端发起
客户端注册的时候提供`post_logout_redirect_uris`，前端登出后跳转到此地址，此地址只有在客户端发起的登出才会跳转。

详细内容[查看协议](https://openid.net/specs/openid-connect-session-1_0.html#OpenID.FrontChannel)
### 后端登出
认证服务发送`logout_token`到客户端，参数有：
- iss：必填，签发方
- sub：选填，主体标识
- aud：必填
- iat：必填，签发时间
- jtl：必填，token唯一标识
- events：必填
- sid：选填 
 
示例：  
```json
{
"iss": "https://server.example.com",
"sub": "248289761001",
"aud": "s6BhdRkqt3",
"iat": 1471566154,
"jti": "bWJq",
"sid": "08a5019c-17e1-4977-8f42-65a12843ea02",
"events": {
    "http://schemas.openid.net/event/backchannel-logout": {}
    }
}
```

#### 后端登出 - 认证服务发起
认证服务向客户端发起`POST`请求，参数用`application/x-www-form-urlencoded`编码
```http
  POST /backchannel_logout HTTP/1.1
  Host: rp.example.org
  Content-Type: application/x-www-form-urlencoded

  logout_token=eyJhbGci ... .eyJpc3Mi ... .T3BlbklE ...
```

客户端收到登出请求后，定位到要登出的会话，注销当前会话不应当撤销已颁发的`refresh_token`。

详细内容[查看协议](https://openid.net/specs/openid-connect-backchannel-1_0.html)

#### 后端登出 - 客户端发起
客户端在本地登出后，向`end_session_endpoint`接口发起请求，通知认证中心退出。  
请求需包含下列参数：  
- id_token_hint：推荐，之前签发的id_token，用于验证登出人身份。
- post_logout_redirect_uri：选填。登出后跳转地址。
- state：选填。客户端生成，认证服务原样返回，防跨站伪造攻击。

请求logout接口，认证服务需要询问用户是否要登出认证中心。如果用户确认退出，认证服务必须登出当前用户。

# 源码简析
```csharp
public async Task<IEndpointResult> ProcessAsync(HttpContext context)
    {
        if (!HttpMethods.IsGet(context.Request.Method))
        {
            _logger.LogWarning("Invalid HTTP method for end session callback endpoint.");
            return new StatusCodeResult(HttpStatusCode.MethodNotAllowed);
        }

        _logger.LogDebug("Processing signout callback request");

        var parameters = context.Request.Query.AsNameValueCollection();
        var result = await _endSessionRequestValidator.ValidateCallbackAsync(parameters);

        if (result.IsError == false)
        {
            _logger.LogInformation("Successful signout callback.");

            if (result.FrontChannelLogoutUrls?.Any() == true)
            {
                _logger.LogDebug("Client front-channel iframe urls: {urls}", result.FrontChannelLogoutUrls);
            }
            else
            {
                _logger.LogDebug("No client front-channel iframe urls");
            }

            if (result.BackChannelLogouts?.Any() == true)
            {

                _logger.LogDebug("Client back-channel iframe urls: {urls}", result.BackChannelLogouts.Select(x=>x.LogoutUri));
            }
            else
            {
                _logger.LogDebug("No client back-channel iframe urls");
            }

            await InvokeBackChannelClientsAsync(result);
        }

        return new EndSessionCallbackResult(result);
    }
```

