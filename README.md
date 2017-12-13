**用户系统**

> 整个平台的用户信息
> 用户认证服务
> 第三方用户登录

---------------------
> 正在处理 用户认证服务  待处理整个平台的用户信息（看是自己写 还是继承 django.contrib.auth）


**授权接口调用方式**

1. grant_type:password
```
POST /o/token/ HTTP/1.1
Host: localhost:9000
Content-Type: application/x-www-form-urlencoded

client_id=1&client_secret=1&grant_type=password&username=zp&password=penadmin


# 返回值
{
    "access_token": "GntA44vOfsoV6BwsVCTjoNe6j4uR47",
    "expires_in": 3600,
    "token_type": "Bearer",
    "refresh_token": "FhQyA3td8Gr1QTmOmx4WIqMVHjuWI4"
}
```

2. grant_type:authorization_code
> 1. 先GET访问 http://localhost:9000/o/authorize/?response_type=code&client_id=1，这个时候如果用户没有登录的话
会重定向到http://localhost:9000/o/login/?next=/o/authorize/%3Fresponse_type%3Dcode%26client_id%3D1 进行登录
> 2. 用户登录后会跳转到http://localhost:9000/o/authorize/?response_type=code&client_id=1页面，让用户选择是否授权
> 3. 如果选择授权，则验证通过后会重定向到application配置的redirect_uri中同时附带上code参数
> 4. 使用code 参数请求o/token/

```
POST /o/token/ HTTP/1.1
Host: localhost:9000
Content-Type: application/x-www-form-urlencoded

client_id=1&client_secret=1&grant_type=authorization_code&code=WZDZGfDwQzGhrMXyZGjALaTTwhyyJ9&redirect_uri=http%3A%2F%2Fwww.baidu.com

# 返回值
{
    "access_token": "lKCpg4TfewHLDPy7b0TA0wNYzuNDWT",
    "expires_in": 3600,
    "token_type": "Bearer",
    "state": "",
    "refresh_token": "sBK3TKYgNiMr6ZuS8hVsyF5Be2bCms"
}
```

3. grant_type:implicit
> 这就是code模式的简化版
> 1. 先GET访问 http://localhost:9000/o/authorize/?response_type=token&client_id=1，这个时候如果用户没有登录的话
会重定向到http://localhost:9000/o/login/?next=/o/authorize/%3Fresponse_type%3Dcode%26client_id%3D1 进行登录
> 2. 用户登录后会跳转到http://localhost:9000/o/authorize/?response_type=code&client_id=1页面，让用户选择是否授权
> 3. 如果选择授权,且验证通过后会直接重定向到application配置的redirect_uri，同时在url的hash中附带token参数
> 4. 浏览器的js 解析url中的token参数得到token

```
访问 http://localhost:9000/o/authorize/?response_type=token&client_id=1

如果用户登录且认证通过则跳转：

{redirect_uri}/#access_token=HB4G4THME9Yjmfi7OPEJBSfOnKZR3B&expires_in=3600&token_type=Bearer&scope=all&state=
```


4. grant_type:client_credentials
```
POST /o/token/ HTTP/1.1
Host: localhost:9000
Content-Type: application/x-www-form-urlencoded

client_id=1&client_secret=1&grant_type=client_credentials


# 返回值
{
    "access_token": "ysV7EbieowqVmzy2xtSOid2PJJGaMv",
    "expires_in": 3600,
    "token_type": "Bearer"
}
```

5. grant_type:refresh_token
```
POST /o/token/ HTTP/1.1
Host: localhost:9000
Content-Type: application/x-www-form-urlencoded

client_id=1&client_secret=1&grant_type=refresh_token&refresh_token=kR3lbYb1LnOlPtn3E2li3ggjhJzOn3

# 返回值
{
    "access_token": "wHVOGRVYRR0PUPcd7TBWydlrS3cvRL",
    "expires_in": 3600,
    "token_type": "Bearer",
    "refresh_token": "f7YGtAubfHObDSmfSu8kH8ngU1XLSq"
}
```

*如果客户端需要认证（application类型为 confidential）时，需要带上客户端凭证（client_id、client_secret）*