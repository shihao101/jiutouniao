---
id: request-smuggling
title: HTTP 请求走私手册（CL-TE/TE-CL 变体探测）
tags: smuggling,走私,cl,te,代理,s4
---
# HTTP 请求走私手册（前后端 Content-Length / Transfer-Encoding 解析分歧）

> 判据=「计时差异/下一个请求被污染」的**受控探测**；确证后利用（劫持他人请求/绕过前端控制）转 S5 审批。

## 一、前置确认（有代理/前端链才值得测）

- 响应头：Server 双栈痕迹（Nginx+后端不同签名）、X-Forwarded-* 注入回显、X-Cache；架构：LB/网关+应用双跳。
- 前置扫描面：/api 经网关鉴权 vs 直连后端口径差异（授权网段内多端口时）。

## 二、探测步法（单变量、串行、每次仅一个变体）

```
① CL-TE：POST 声明 Content-Length 且 body 内嵌 Transfer-Encoding: chunked
   探针：第二个请求计时显著变长（后端吃掉部分 body 等待）= 疑似
② TE-CL：Transfer-Encoding: chunked 优先被前端消费，Content-Length 被后端用
   探针：请求 A 注入前缀，紧随请求 B 观察 B 的响应是否包含 A 残留（受控标记如 X-PROBE: 1）
③ TE-TE（混淆）：Transfer-Encoding: xchunked /  "Transfer-Encoding : chunked" / TE: chunked 换行变体
④ CL-CL：两个 Content-Length（值不同看取前/取后/400）
```

- 探测用**可自愈前缀**（无害 header 注入标记），禁止注入破坏性 body（红线 1）。
- 每变体间隔 ≥3s，连接复用状态记录（Connection: keep-alive 是前提）。

## 三、危害定级（确证后）

1. 前端控制绕过（/admin 网关 ACL 绕过）→ 高危 record_finding（cwe-444）。
2. 相邻用户请求劫持能力 → 危害极大；**只做标记位证明**（捕获自己第二请求被污染），不触碰他人会话。
3. 结合 H2 downgrade（:method 大小写/伪头混淆）→ 记录变体，S5 深入。

## 四、纪律

- 本类测试**极易误伤同链路真实用户**（共享连接池）——执行前必须确认目标无真实用户在线（授权窗口/研发环境确认），否则跳过并登记 needs_follow_up。

## TE.TE 八变体与 client-side desync

- **八种混淆**：`xchunked`；`Transfer-Encoding :`（冒号前空格）；双 TE；值 `x`；TAB 分隔；行首空格；`X: X\nTransfer-Encoding: chunked` 延续行；字段名与冒号**分行**
- **TE.CL 精确字节**：CL=4 只吞 `35\r\n`，块长 hex=53 字节，改路径须重算 CL
- **client-side desync**：浏览器内 `fetch(url,{mode:'no-cors',credentials:'include',body:'GET /admin HTTP/1.1\r\n...'})` 打受害者同源
- 工具：defparam/smuggler、Burp HTTP Request Smuggler 扩展

### CL.TE 探针与 H2 专项

CL.TE 精确探针：`Content-Length: 13` + 体 `0\r\n\r\nSMUGGLED`（`0`+`\r\n`+`\r\n`+`SMUGGLED`=13 字节）。加长变体：后端 CL=11、体 `x=1` 时块长 ≈ 76 hex（118 字节），仍用 `Content-Length: 4` 卡长度行。H2 专项：H2 内 `Transfer-Encoding`/`Content-Length` 重复与大小写（H2 要求小写、翻译层可能出错）；`:method`/`:path` 异常字符降级行为；extended CONNECT 隧道与走私交互。工具补：dhmosfunk/simple-http-smuggler-generator（快速拼装原始报文模板）。

### h2c 明文升级走私（v5.3.9 增补——无凭证可达的前端 ACL 绕过）

> 适用：明文 HTTP（无 TLS）链路存在反代/网关→后端双跳；h2c 升级头若被前端原样转发，后端以 h2c 会话绕过前端 ACL/路由改写。

```
① 探针（单请求）：GET / HTTP/1.1 + 头
     Upgrade: h2c
     HTTP2-Settings: AAMAAABkAARAAAAAAAIAAAAA
     Connection: Upgrade, HTTP2-Settings
   响应 101 Switching Protocols + HTTP/2 帧流 = 前端放行 h2c 升级（疑似直通后端）
② 绕过验证（受控）：h2c 会话内直接请求前端 ACL 拦截路径（如 /admin）
   ——前端 403 而升级通道 200 = ACL 绕过确证（record_finding 高危，cwe-444）
③ 变体：Connection 头剔除 Upgrade（部分反代只转发白名单头）+ Upgrade: h2c 独立投递
```

- 判据纪律：**仅明文 HTTP 端口可测**（HTTPS 前端不透传 Upgrade，误报源）；101 响应本身只记 Observation，**ACL 差分（前端拒 vs 通道通）才是确证判据**；
- ROE：h2c 会话只做只读 GET 路径对比，禁止借通道注入写请求；curl `--http2-prior-knowledge` 不适用本场景（需手工原始报文，bash `printf | nc` 或 Burp Repeater 手工构造）；
- 联动：gateway-filter-playbook（白名单矩阵第 h2c 格）、docker/ingress 场景见 k8s-attack ingress 注记。
## v5.6.0 工具探针与自标记判据（三凭证审计补强）

### 工具探针（先探后用——M6 通道纪律）

- `which smuggler`（Burp 扩展等外部工具不视为内置）→ 缺失时用 **原生手工探针矩阵**（本技能主体 CL-TE/TE-CL 变体逐对发探针）。
- 探针自证：先对目标发"无害 smuggler 探测对"（两个相互前置请求），延迟/响应错位判据出现 = 走私面候选；无探针响应 → 降级 needs_follow_up（不得 ruled_out）。
- 代理链影响差分：若走 exit-pool/chain-proxy，先记录直连 vs 代理两种路径的探针结果差异（代理自身可能改写 Content-Length——排除代理引入的假阳性）。

### 自标记判据（检测不再依赖目标报错）

1. **自回显标记**： smuggle 请求体携带唯一标记（`X-JT-Probe: <随机数>`）——走私成功则后继请求"合并"了我们的标记头（目标响应/日志可观测标记）。
2. **前端错位双判据**：①前后夹击（正常请求夹走私请求）看响应串扰；②时间差（走私 payload 挂起 → 后继请求被阻塞）。
3. **无回显场景**：以上任一通道稳定复现 2 次即"疑似"；HTTP 请求走私确证后**立即停止**利用探索（不做缓存投毒组合演示，除非 Lab）——走私确证本身 = 高危 finding（CWE-444）。
