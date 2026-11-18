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

- **改密流程完整性（v5.4.5）**：改密不验旧密码、改密/改绑后旧会话与旧 refresh 是否失效——行为级验证 load_skill session-lifecycle（T2/T8），本矩阵只做流程结构还原

- **密码重置 22 模式矩阵**（摘要）：token 不绑用户、响应体回 token、步骤跳过（第二步不再验证身份）、参数污染 email=victim&email=attacker、CDN 缓存重置链接、注册响应回显激活链接、host header 注入重置链接
- **"响应包无 token/sign" 判据（v5.6.1 修订：候选信号，非确证）**：验证码校验步骤的响应包里没有 token/sign 类可校验字段 = *候选信号*——必须闭环正负对照：正例=拦截响应替换为成功响应且**服务端状态真实变化**（复读状态留证，联动 race-condition 复读纪律）稳定复现 2 次；负例=不拦截重放原始流程放行失败。两例齐备才 record_finding；仅凭"无校验字段"不得定级
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
## v5.6.0 OAuth/SAML 矩阵补全（对照 RFC 9700 / OWASP SAML Cheat Sheet，三凭证审计 S2 轨）

### OAuth 2.0 / OIDC 新增矩阵（逐项带判据）

1. **mix-up 攻击（v5.6.1 按 RFC 9700 §4.4 精确化）**：多 IdP 场景，授权响应重定向到攻击者控制回调 → 客户端把 B 的 code 发到 A 的 token 端点。判定三要件（缺一不可）：①客户端把**发起授权的 issuer 绑定到用户代理会话**（cookie/状态记录 iss）②收到响应后校验 issuer 专属回调 URI 或响应中的 `iss` 参数与发起方一致 ③token 请求按绑定 issuer 路由。测试：B 的 code+客户端凭据发到 A 的 token 端点——**客户端侧**用错误 issuer 的 token 访问资源成功 = mix-up 缺陷确证；仅"AS 返回错误码/500"不构成防护证明（可能只是 code 无效）
2. **PKCE downgrade（v5.6.1 按 RFC 9700 §4.8 精确化）**：三步判定——①授权请求**去掉** `code_challenge` 但 token 请求**仍带** `code_verifier`：AS 必须拒绝（接受了=PKCE 绑定失效，确证）；②授权请求带 challenge、token 请求缺 verifier：AS 必须拒绝；③ challenge 与 code 的绑定校验：用 A 授权码的 code_verifier 换 B 授权码的 token，AS 接受 = 绑定缺陷。仅"AS 接受无 PKCE 流程"不足以确证（部分客户端类型本就可选 PKCE）——须对照该 client 注册时的 PKCE 强制策略。
3. **严格 redirect_uri 匹配**：`redirect_uri=https://t/oauth&uri=https://t` 后缀匹配缺陷、路径遍历（`/oauth/../x`）、registerable 前缀域接管组合 subdomain-takeover。判据：AS 接受变体 redirect = 缺陷。
4. **事务状态与 UA 绑定**：state 校验缺失已覆盖；补：`code` 在不同浏览器/UA 复用、同 code 双客户端并发兑换（竞态窗口，联动 race-condition）。
5. **token 端点防护**：`client_secret` 弱口令可枚举（联动 weak-cred-bruteforce 限额纪律）、public client 走 implicit（response_type=token 仍开放=遗留缺陷）。

### SAML 新增矩阵

1. **签名包裹（XSW）八变体逐项清单（v5.6.1 展开；每项=结构+SP 应拒绝判据）**：
   | # | 变体 | 结构 | 拒绝判据 |
   |---|---|---|---|
   | X1 | 签名 Response+明文 Assertion | 明文断言替换被签断言 | 消费的 Assertion 未被任何签名覆盖 |
   | X2 | 签名 Assertion+明文 Response | 断言移出 Response 签名范围 | 断言-Response 绑定校验失败 |
   | X3 | 副本插入（双 Assertion） | 签名版+伪造版并存 | SP 取未签名副本认证 |
   | X4 | 扩展包装 | 伪造断言藏于签名对象扩展点 | 解析到签名外节点 |
   | X5 | 重放包装（ID 复用） | 新断言复用已消费 ID | ID 去重/replay cache 拦截 |
   | X6 | 签名位置互换 | Response 签名当 Assertion 签名用 | 引用定位签名对象校验失败 |
   | X7 | 恶意根/DOCTYPE | XML 实体注入/结构欺骗 | 禁 DTD+schema 校验拦截 |
   | X8 | Reference 指向篡改 | Reference URI 指向伪造节点 | Reference↔实际消费节点一致性失败 |
   通用前置（OWASP）：schema 校验禁 DTD、签名引用节点=实际消费节点、**断言 replay cache**（X5 步骤：同一 Assertion ID 二次投递必须被拒）+ 签名剥离对照（删签名仍被接受=独立缺陷）。
2. **断言签名伪造前置**：取得测试 IdP 自签证书/元数据注入（`ExtraHeaders`）→ 自签断言；判据：SP 接受非受信 IdP 签名 = 信任链缺陷（高危）。
3. **Recipient/Destination/NotOnOrAfter 组合**：单条件篡改逐项测（此前是组合检查）；`InResponseTo` 缺失时 IdP-initiated 流程接受未请求断言。
4. **工具与谱系**：SAML 断言构造用 python3（lxml/signxml——镜像 python3-requests/yaml 基线 + install_tool 兜底 signxml）；伪造产物 store_credential origin=forged method=saml-xsw 登记。

### 纪律

- 伪造测试仅 isolated_lab / 显式授权目标；生产档只做"接受性验证"（无害探针），不产生持久副作用。
- 伪造链产物全部入凭据仓库谱系（origin=forged parent_id=<真实凭据>），与真实身份分账。
