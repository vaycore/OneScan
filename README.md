# OneScan

OneScan是一个递归目录扫描的BurpSuite插件。

## 插件介绍

OneScan插件的思路由One哥提供，我负责将One哥的思路进行编码变现。插件起初是为了发现站点的 `Swagger-API` 文档页面，例如有些站点将 `Swagger-API` 文档存放在当前接口同路径下（或者更深层次目录）。OneScan插件的出现可以快速发现这类页面和接口，只需要配置对应的字典即可。

## 插件安装

BurpSuite 安装流程如下：

```text
Extender -> Extensions -> Add -> Select File -> Next
```

流程结束后，打印如下信息表示插件安装完成（需要配置 [HaE](https://github.com/gh0stkey/HaE) 插件之后才会显示 **HaE** 插件的日志信息）：

![](imgs/install_success.png)

插件配置文件存放路径如下：

```text
linux、macOS：
~/.config/OneScan/

windows：
C:\Users\<用户名>\.config\OneScan\
```

## 插件使用

插件主面板如下

![](imgs/main_panel.png)

主面板的 `Listen Proxy Message` 配置表示被动扫描，代理的请求包都会经过OneScan（建议配置完白名单再启用）

### 主动扫描

可以从BurpSuite其它位置发送到OneScan主动扫描

![](imgs/send_to_onescan.png)

> 注意：白名单同样对主动扫描生效

### Payload

Payload配置界面如下

![](imgs/config_payload.png)

- `Payload` 配置递归扫描的字典
- `Payload Processing` 配置请求过程中对数据包的处理（例如：URL添加前缀、后缀，Body正则匹配和替换）

### Request

Request配置界面如下

![](imgs/config_request.png)

- `Header` 递归扫描过程的请求头配置，可配置变量
- `UserAgent` 这里配置的是 `{{random.ua}}` 变量列表里的值

目前包含的变量如下：

```text
{{host}} - 原请求头中的Host
{{domain}} - 原请求头中的Host（不包含端口号）
{{protocol}} - 原请求头中的协议（http、https）
{{timestamp}} - Unix时间戳（单位：秒）
{{random.ip}} - 随机IPv4值
{{random.ua}} - 随机UserAgent值，随机源可配置
```

### Host

Host配置界面如下

![](imgs/config_host.png)

- `Host Whitelist` 配置白名单列表，如果该列表不为空，插件则只能请求该列表中的Host
- `Host Blacklist` 配置黑名单列表，插件不对该列表配置的Host进行请求

### Other

Other配置界面如下

![](imgs/config_other.png)

- `Web name collect` Web目录名收集（例如：`http://xxx.com/wapi/xxx.html` 会将该 url 中的 `wapi` 写入到指定的文件中）
- `Json field collect` Json字段收集（收集json格式响应包中的所有key值，保存到指定目录）
- `Exclude suffix` 排除指定后缀的数据包
- `HaE` 配置与 [HaE](https://github.com/gh0stkey/HaE) 插件联动，实现主面板数据高亮

## 插件演示

浏览器访问某搜索网站，面板展示如下

![](imgs/main_panel_test.png)

## END

- 代码写的很乱，还请师傅们见谅
- 欢迎各位师傅提交 `Issue` 和 `Pull requests`，一起完善项目
