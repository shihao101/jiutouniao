---
id: auth-bypass
title: 认证与会话攻击手册
tags: 认证,会话,jwt,oauth,爆破,s4,s5
---
# 认证与会话攻击手册

## JWT 攻击链
1. 解码 `eyJ` 头：alg、kid、jku。
2. `alg:none`：去掉签名保留 `.`；弱密钥：`hashcat -m 16500 jwt.txt -w /usr/share/wordlists/rockyou.txt`（限频）。
3. kid 注入：路径穿越/SQLi in kid。

## 会话管理
- Cookie 属性：Secure/HttpOnly/SameSite；会话固定：登录前后值比对。
- 会话不失效：登出后旧 token 重放；多端登录互踢测试。
- 刷新令牌：refresh 无限循环 / 未绑定客户端。

## OAuth/OIDC
- redirect_uri 未校验：`?redirect=//evil`；state 缺失→CSRF 登录绑定。
- code 重放、implicit 流 token 泄露（Referer/日志）。

## 登录接口（严格限频，仅测试账号）
- 用户名枚举：响应差异（错误文案/时间）。
- 验证码绕过：前端校验、可置空、可复用、回显在响应。
- 前端加密协议（JS/WASM 加密、动态挑战 token、参数名陷阱）：放弃明文构造，load_skill browser-auth 走真实浏览器合规登录（验证码 exit 42 转人工），登录后 CLI 接管——协议逆向为可选深挖项，不是登录前置。
- **无凭据口径（v5.1）**：枚举/验证码/前端协议识别均匿名可测；需要账号态的对比实验依赖 identity-bootstrapping 供给身份（客户提供或索取闭环），无身份时逐条 record_vt 移交，禁止静默跳过。

## 判定纪律
- 一切结论以两个账号的对比响应为准（账号来自客户提供/索取闭环，禁止自动注册）；update_coverage(vuln_class=认证, param=具体机制)。

### 登录机制补遗

SQLi 登录绕过 payload 族（legacy/自写 ORM 必测，**逐字段单独测**——用户名/密码/邮箱可能只有一处可注）：`admin'--`、`' OR '1'='1'--`、`admin' OR 'a'='a`、`1' OR '1'='1'/*`、数字型 `1 or 1=1`。重置 token 可预测形态：Unix 时间戳直用、自增 1001→1003、`md5(email)`、`md5(username+timestamp)` 可逆、4-6 位短码；判据=连发 3 封重置邮件对比 token 结构规律。重置 22 矩阵补三条：注册同名邮箱直接覆盖旧账号密码（**评估态只做流程还原；实测需 ROE allow+孤儿测试账号，禁指向真实用户**）；并行会话重置（A 发起、B 会话完成确认步）；跨端重置 token 不互通。归一化变体：`admin%00` 空字节截断、Unicode 同形字/全角（`ⓢcott`→`scott`）、邮箱大小写与尾空格——验证码/登录/查重三处口径可能不一致。会话再生缺失：低权账号被提权后旧 session 直接继承新权限（提权后未 regenerate）；可预测 session：`base64(userid+timestamp)` 可逆、自增整数、32 位短随机可暴破。工具补遗：reset-tolkien（重置 token 自动预测）、sandwich（token 时间戳分析）。