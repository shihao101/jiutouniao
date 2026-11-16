---
id: web-top10
title: OWASP Top 10 Web 测试清单
tags: web,top10,注入,xss,越权,ssrf,s4
---
# OWASP Top 10 Web 测试清单（每项测完 update_coverage）

## A01 访问控制失效（越权）
- 水平越权：替换 user_id/order_id/uuid（两个测试账号互查）→ 403/404 判定差异。
- 垂直越权：普通用户访问 /admin/*；HTTP 方法替换（GET→POST/PUT）；X-Original-URL / X-Rewrite-URL。
- 步骤记录到 Param 维度：每个 ID 参数一个矩阵单元。
- **无凭证三态路由（v5.1）**：①客户提供测试账号 → 按上两行全量差分；②仅匿名 → 全部已知端点先过 authz-diff 无 token 矩阵（匿名垂直越权/BLSA 判定），依赖双账号的水平越权单元逐条 record_vt/needs_follow_up 移交（禁止静默跳过）；③无入口 → needs_follow_up 显式登记。禁止无凭证虚构账号结论，禁止自动注册（ROE identity.auto_register）。

## A02 加密失败
- TLS 配置（testssl.sh）；敏感数据明文传输；弱哈希（MD5/SHA1）。

## A03 注入
- SQLi：`'`、`' OR '1'='1`、时间盲注 `'; WAITFOR DELAY '0:0:5'--`；确认后再上 sqlmap（L2 审批）。
- 命令注入：`;id`、`|id`、`` `id` ``、`$(id)`；模板注入 `{{7*7}}` `${7*7}`。

## A05 安全配置错误
- 默认凭据、目录列表、.git/.env 泄露、调试端点（/debug、/actuator、/swagger）。

## A07 认证失效
- 弱密码策略、无验证码爆破（严格限频+测试账号）、JWT 弱密钥/alg:none、会话不失效。

## A09 日志与监控缺失（评估项）
- 恶意请求是否触发告警（与客户确认）。

## 纪律
- 每个 payload 首次只发 1-2 个探测；确证才扩展；不确定先 load_skill 或问审批。

## v4.8 M6 工具通道兼容性声明

> 口径（loop-core v4.8 纪律 3）：先 probe 后 batch——每个外部工具对目标首次使用前先用小样本探针确认可用性，探针被拦/挂起先切适配通道再批量；探针结果写入交付物工具声明小节。各工具在「挑战型 WAF / 封闭站」下的可用性与适配通道：

- sqlmap：注入流量无会话态会被挑战型 WAF 拦截（假阴性）——先 probe（--level 1 单参数）确认可达；适配通道：挑战态 cookie/UA 注入（--cookie/--headers），或经注入通道（mitmproxy↔CDP 上游代理链）带挑战态运行。
- curl：低频手工请求始终可用——也是挑战态复放的最小工具（channel-snapshot 快照 cookie/UA 复放）；禁用它做大批量枚举。
