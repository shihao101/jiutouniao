---
id: auth-flow-deep
title: OAuth/OIDC/SAML 认证流程深度手册
tags: oauth,oidc,saml,redirect_uri,state,pkce,s4
---
# 认证流程深度手册（OAuth/OIDC/SAML；JWT 见 jwt-crypto，会话见 auth-bypass）

## 一、OAuth/OIDC 探针链

```bash
# redirect_uri 校验：路径级绕过变体（逐一单变量）
?redirect_uri=https://信任域.evil / https://信任域/..%2f / https://信任域%2f%2e%2e
?redirect_uri=https://信任域.evil.信任域 / https://信任域@evil
# state 缺失：去掉 state 参数完成流程 → CSRF 绑定账号判据（用测试账号 A 触发、B 接收）
# code 复用：同 code 二次兑换 → 返回成功=确证（cwe-294）
# PKCE 缺失：authorization_code 流无 code_verifier 也能兑换
# scope 越权：downgrade/omit scope 换取全量 token；implicit 流 token 经 Referer/日志泄露
# id_token 校验：aud/iss/nonce 不校验 → 跨客户端重放判据
```

## 二、账号绑定/接管链（高价值，只做判据）

- 三方绑定接口未校验已有绑定 → 账号接管候选（测试账号 A 绑 B 的三方身份，判据=登录态互换）。
- 邮箱/手机改绑流程缺二次校验 → 接管候选（全程测试账号内闭环）。

## 三、SAML 探针

- Response 未签名/断言可改：改 NameID/audience → 语义拒绝但报错差异=线索。
- XSW 攻击（签名断言与响应包装）只做**报错差异探测**，实际伪造经授权确认后 S5。

## 四、MFA 流缺陷（配 weak-cred-bruteforce）

- OTP 暴破限速缺失（4-6 位数字码 + 无锁定）：**仅对测试账号测额度**（≤10 次即停，超限记录）。
- OTP 重放/跨账号使用/响应可预测（时间种子）；「记住设备」token 未校验绑定。

## 五、纪律

- 全流程在**测试账号对**之间闭环（A/B 双账号对比口径，同 auth-bypass 判定纪律；账号来自客户提供/索取闭环，禁止自动注册）；涉及真实用户流程一律不触；无凭据时流程探测（redirect_uri 变体/state 缺失等匿名可测项）照做，账号态单元逐条 record_vt 移交（禁止静默跳过）。

## 密码重置/验证码/改绑实证矩阵

- **密码重置 22 模式矩阵**（摘要）：token 不绑用户、响应体回 token、步骤跳过（第二步不再验证身份）、参数污染 email=victim&email=attacker、CDN 缓存重置链接、注册响应回显激活链接、host header 注入重置链接
- **"响应包无 token/sign" 判据**：验证码校验步骤的响应包里没有 token/sign 类可校验字段 → 90% 可改响应包重置任意用户（可直接作为判洞启发式）
- **统一认证两个 bypass**：登录跳转链逐包分析，删某响应体 JSON 的 `{}` → 进功能页；功能点 401 → 手改 200 → 数据返回
- **跨站成功响应包复用**：同厂商系统 A 的成功登录响应（success:true+token）整体替换 B 站失败响应（判据：同框架同端点模式、失败返回 false）
- **改收码人**：签署/改绑/重置流程电话参数可控 → 改为自己手机号收码 → 越权完成他人流程
- **首登强制重置**：首登自动重置为固定值 → 批量判断未重置账号=通杀
- **CAPTCHA 20 法摘要**：丢弃 /api/captcha 请求复用旧值、删 verifycode 参数、清 cookie 重置失败计数、旧验证码复用
- **2FA 五类**：密码通过后 session 直访 /dashboard、TOTP 无锁爆破、关键操作只查登录不查动作、backup code 复用、code 重放
- **随机性预测**：UUIDv1（guidtool）、MongoDB ObjectId（时间+计数器）、PHP mt_rand（php_mt_seed 624 输出恢复状态）
- **bcrypt 72 字节截断**；SSO-only 账户走 forgot-password 设密码绕 SSO

### OAuth/SAML 补遗

state 三变体（不止缺失）：静态值全局同一、可预测（时间戳/自增）、生成后不绑用户会话（A 的 state 配 B 的回调）。多端流程对比：同一 OAuth/OIDC flow 在 SPA/移动端/web 三端各跑一遍——redirect 白名单与 token 校验常分端实现，找最弱端（小程序 callback 常最松）。SAML 校验矩阵补全（8 项）：签名覆盖面（只签 Response/只签 Assertion/签名节点错位）；Recipient/Destination/ACS URL 三处均须校验；issuer 信任（错误 IdP/多租户混淆）；InResponseTo 缺失→断言重放；NotBefore/NotOnOrAfter 时间窗弱校验；账号映射（仅信 email 属性/大小写折叠不一致/未验证属性入库）；SP-initiated vs IdP-initiated 两流程对比；SAML XML 解析器 XXE 面（联动 xxe-full）。账号绑定补两条：攻击者自建 IdP 把 email claim 设为 `victim@target.com` → 服务端信 email claim 不验所有权即合并/接管；provider 混淆（Apple 身份绑到期望 Google 的绑定口）。