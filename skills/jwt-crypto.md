---
id: jwt-crypto
title: JWT 与密码学实现审计手册
tags: jwt,密码学,加密,认证
---
# JWT 与密码学实现审计

## JWT 全链路
1. 解析三段（base64url）：header.alg/kid/jku/jwk。
2. alg:none / 弱 HMAC 密钥（hashcat -m 16500，限频）/ RS256→HS256 混淆（用公钥当 HMAC 密钥）。
3. kid 注入：路径穿越读取可控文件、SQL 注入。
4. 时序：exp/nbf 缺失、时钟偏移容忍滥用、撤销（jti 黑名单）缺失——结构级判定后，**行为级验证（登出吊销/改密踢会话/refresh 复放/remember-me）load_skill session-lifecycle**（T1-T9 矩阵）。

## 密码学实现面
- ECB 模式、固定 IV、弱 KDF（MD5/SHA1 直接做密钥派生）。
- 自研"加密"：XOR、base64 套娃、哈希截断——还原算法并构造伪造值（PoC 走审批）。
- 随机数：`math.random` 生成 token → 可预测性证明（收集样本预测下一个）。

## 签名/防重放（API/APP/小程序通用）
- 签名要素：timestamp/nonce/参数是否全覆盖；缺 timestamp = 可无限重放。
- nonce 存储窗口；签名密钥是否硬编码在客户端（反编译提取）。

## 产出纪律
- 伪造/解密成功 → PoC + 前后对比证据；update_coverage(vuln_class=认证)。
- **无凭证三态路由（v5.1）**：①有可用 token（客户提供账号取得）→ 全攻击面实测；②仅匿名 → 公开面观测的 token 样本（响应头/JS/移动包）做**离线**解析与弱点判定（alg/kid/jku 结构、弱密钥候选收集、随机数可预测性），伪造尝试归 identity-bootstrapping L5 轨 record_vt 移交（禁止静默跳过）；③无样本 → needs_follow_up 显式登记。禁止自动注册（ROE identity.auto_register）。

## kid/jku 深化

- kid SQL 注入：`{"kid":"' UNION SELECT 'attacker_key' FROM dual--"}`；kid 路径穿越 `/dev/null`（空 key）与 `/etc/hostname`
- jku/x5u 恶意 JWKS 托管全流程：openssl 生成 → JWKS 导出 → `jwt_tool -X s -ju`
- jwt_tool 速查：`-X a`(none)、`-X k -pk`(混淆)、`-C -d`(爆破)
- token 交换时 scope 升级；隐式流 fragment 经第三方资源 Referer 泄露

### claim 改值与多端互用

改 claim 重签目标清单：`role/admin`、`isAdmin:true`、`sub:admin`、`userId→他人ID`、`email→victim@target.com`、`permissions:[admin,write]`、`tier:premium`——改值后必须同步重签，判据=响应身份切换。多端 token 互用：web 签发的 JWT 直接打 App 与小程序接口（同签名体系常不分端校验 audience/token_type）。JWT 弱密钥候选（hashcat 前先手工试）：`secret`、`password`、`123456`、`changeme`、`your-256-bit-secret`、`APP_NAME/app_name`、`production`、`jwt_secret`、`SECRET_KEY`。限流/批量绕过头族（低频轮换，遵守限速红线）：`X-Forwarded-For`、`X-Real-IP`、`Forwarded: for=9.9.9.9`、UA 轮换、路径大小写与斜杠变体（`/API/`、`/api//`、`/api/./`）——同时并入 weak-cred-bruteforce 锁定规避节。
## v5.6.0 伪造凭证矩阵补全（三凭证审计 S2 轨）

### 新增攻击面（逐项带判据）

1. **嵌入式 jwk/jwk 信任**：JWK 头自带公钥且服务端直接用它验签 → 用自有私钥签发伪造 token。判据：伪造 token 访问受保护接口 200 且业务生效；对照：换回原签名 → 401（双对照）。
2. **`crit`/`b64` 头（RFC 7797，v5.6.1 判据精确化）**：RFC 7797 规范要求 JWT **不得**使用 `b64:false`（JWT 规范强制载荷 base64url）——合规实现必须拒绝。攻击面=实现**接受**非规范 JWT 并按未编码载荷完成签名校验/授权。判据（两级）：①服务端接受 `b64:false` 构造的 token 且**授权结果生效**（访问受保护资源 200+业务数据/状态变化）= 缺陷确证；②仅"解析行为差异/报错不同"= *线索*，不得单独定级（RFC 7797 明确此类 JWT 非法，解析差异不是漏洞）。
3. **算法族全覆盖**：ES256/384/512、PS256/384/512、EdDSA——不止 RS/HS 混淆；`alg` 大小写变体（`none`、`None`、`nOnE`）、`alg` 字段删除（部分库默认 HS）。
4. **`iss`/`aud` 校验矩阵（access token 通用，不只 OIDC id_token）**：跨 audience 重放（A 服务签发→B 服务接受）、跨 issuer（同租户多签发方）、`aud` 数组形态混淆、`iss` 尾缀匹配缺陷（`https://x.evil.com` 伪装 `https://x`）。
5. **多租户隔离矩阵**：`tenant/org/workspace` claim 改值 + 跨租户 token 重放；判据：目标租户数据 200 = 租户隔离缺陷（高危，record_finding CWE-283）。
6. **无回显判据（v5.6.1：加噪声基线）**：伪造成功不以 200+回显为唯一标准——行为差分三通道，全部要求**目标级基线对照**：①状态变化副作用（改邮箱/加好友等可读回验证；副作用动作须在授权窗口内且可回滚/登记）②时间差（先用无效 token 测 5 次取基线中位 T_inv，伪造 token 连续 3 轮 ≥1.5×T_inv 才算显著）③长度差（无效 token 响应长度基线 ±5% 之外且 3 轮稳定）。任一通道 3 轮稳定 = "疑似"；两条独立通道同时命中 = "确证"；单次偏离一律 candidate。副作用通道本身非无害——执行前提=ROE 允许 + 动作可登记移交（对齐 s7）。

### 工具链（v5.6.0 已固化进镜像，fail-hard 终检）

- `jwt_tool`（/opt/jwt_tool，PIN 锁定）——`python3 jwt_tool.py <token> -X a`（alg:none）等全部recipe
- `PyJWT`——程序化构造/验签（伪造令牌批量生成：`jwt.encode(claims, key, algorithm=...)`）
- `hashcat -m 16500`（已入 apt 清单）——HS256 弱密钥爆破
- 工具缺失时：install_tool 兜底，不再静默降级

### 谱系纪律（v5.6.0）

每个伪造产物 **store_credential origin=forged method=<手法> parent_id=<父凭据>** 入库（如 method=jwt-none/alg-confusion/kid-injection）；伪造身份与真实身份分开记账；伪造成功的越权效果进 authz-diff/api-idor 矩阵完整测试。生产档以"验证接受即止"为界，不做破坏性副作用。
