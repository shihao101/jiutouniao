---
id: cache-poisoning
title: Web 缓存投毒/缓存欺骗手册（unkeyed header 发现）
tags: 缓存,投毒,deception,vary,s4
---
# Web 缓存投毒手册

> 判据=「不可缓存键的输入改变了缓存响应」。**投毒仅对测试探针值生效验证，不在共享缓存写入可见载荷**；验证用可自愈参数（短 TTL 或测试域）。

## 一、发现可投毒面

```bash
# ① 缓存行为确认：响应头 X-Cache / X-Cache-Hit / Age / CDN-NODE / Vary
# ② 参数级缓存（cache keying）：同 URL 加随机参数看是否缓存（param miner 思路）
ffuf -u "https://目标/?utm_source=FUZZ" -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt -mc 200,301 -X GET -t 1 -rate 20
# ③ unkeyed header 发现：逐个加头看响应是否进入缓存态
#    X-Forwarded-Host / X-Forwarded-Scheme / X-Original-URL / X-Rewrite-URL / X-Host / Forwarded
curl -sk -H "X-Forwarded-Host: <可控探针域>" -i "https://目标/" | head -20
```

## 二、投毒判据（无害闭环）

1. 反射型：unkeyed header 值进入响应（href/src/Location 重写）→ 确证反射点。
2. 存储型（真投毒）：带探针域请求一次（写缓存）→ 普通 UA 请求同 URL 读到探针痕迹 → 确证**缓存持久化**（cwe-444/cwe-74，高危级）。
3. 缓存欺骗（Cache Deception）：`/非敏感路径/静态后缀`（/home/non.css）吃到**动态响应**且被缓存 → 认证内容缓存泄露（配弱-cred/越权面验证）。

## 三、常见利用面（记录，利用转授权确认）

- 重写资源 URL→劫持 JS（影响所有访客，危害高；证据=探针域回连日志，不真投恶意 JS）。
- Vary 头处理缺陷（UA/Vary 不一致）→ 针对代理缓存的条件性投毒。

## 四、纪律

- 探针域仅回连记录（oob-interactsh 通道）；禁止在真实用户可见路径写长期毒载荷。
- 验证后**缓存清理不可控时必须在交付物声明**（TTL 自愈说明 + 观察窗口）。
- **无凭证三态路由（v5.1）**：①有测试账号 → Deception 四步全流程；②仅匿名 → unkeyed header 发现/反射判据/存储型自投递闭环（探针域自证）无凭证可做，Deception「受害者取回」环节降级 record_vt/needs_follow_up（禁止静默跳过）；③无缓存面 → ruled_out 附缓存行为证据。禁止自动注册（ROE identity.auto_register）。

## 缓存欺骗 Web Cache Deception

- **Deception 四步**：认证端点追加 `.css/.js` → 验证 X-Cache MISS→HIT 差异 → 伪造 URL 发给受害者 → 无凭证取回受害者内容（与投毒的区别：欺骗偷的是**受害者的私有响应**，投毒污染的是**公共缓存**）
- **路径分隔符变体**：`/profile;.css`、`%2F.css`、`/profile/.css`——利用 CDN 与框架路径归一化差异
- **未键控头清单**：X-Forwarded-Host/Scheme/Proto、X-Original-URL、X-Rewrite-URL、True-Client-IP

### Deception 补全

可缓存扩展名清单：`.css .js .jpg .png .gif .svg .ico .woff .woff2 .ttf .pdf`（.json 视 CDN）。路径变体补：`/account/profile/..%2fstatic/app.css`（穿越式）、尾部空格 `/profile .css`、`/dashboard/data.json`；机制表（CDN 按完整路径含扩展名缓存/应用忽略尾段/Nginx 中间改写）。OG/canonical meta 注入落地：`<meta property="og:image" content="https://evil.com/...">`、`<link rel="canonical" href="https://evil.com/">` → JS 路径 XSS/canonical 钓鱼/SEO 劫持。unkeyed 头补 `X-Forwarded-Server`。修复判据行：仅缓存显式静态路径 `/static/*`；认证端点 `Cache-Control: no-store, private`；`Vary: Cookie`；反射头全入缓存键；CDN 剥未知头。
## v4.8 M6 工具通道兼容性声明

> 口径（loop-core v4.8 纪律 3）：先 probe 后 batch——每个外部工具对目标首次使用前先用小样本探针确认可用性，探针被拦/挂起先切适配通道再批量；探针结果写入交付物工具声明小节。各工具在「挑战型 WAF / 封闭站」下的可用性与适配通道：

- ffuf：挑战页统一指纹会掩盖响应长度差异（假阴性）——先 probe 2 个请求人工核对差异真实性；适配通道：会话态 cookie/UA 注入后跑；封闭站签名校验目标改浏览器代理。
- curl：低频手工请求始终可用——也是挑战态复放的最小工具（channel-snapshot 快照 cookie/UA 复放）；禁用它做大批量枚举。
