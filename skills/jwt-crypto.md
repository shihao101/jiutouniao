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
4. 时序：exp/nbf 缺失、时钟偏移容忍滥用、撤销（jti 黑名单）缺失。

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