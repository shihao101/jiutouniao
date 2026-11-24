---
id: http-security-headers
title: HTTP 安全响应头基线（C-25 头配置面）
tags: s4,安全头,csp,hsts,cookie,headers,配置
---
# HTTP 安全响应头基线手册（C-25 拆分：头配置面；TLS 协议/证书面归 tls-deep-audit）

> 触发条件：任何 HTTP(S) 可达主机。定位：**最小探针即可全量覆盖**（每主机 1 次 HEAD/GET）——27 类中性价比最高的广度项；配置类发现按聚合口径登记（参照 F-C1C8694E37 形态）。

## 一、基线清单（逐头判定）

| 头 | 阴性（合理配置） | 阳性（缺口） |
|---|---|---|
| Content-Security-Policy | 存在且非 unsafe-inline 全放 | 缺失/仅 report-only/含 unsafe-inline+unsafe-eval |
| X-Content-Type-Options | nosniff | 缺失 |
| Referrer-Policy | strict-origin* 族 | 缺失/no-referrer-when-downgrade |
| Permissions-Policy | 敏感能力收敛 | 缺失 |
| Strict-Transport-Security | max-age≥31536000 + includeSubDomains（preload 加分） | 缺失/仅 max-age 短值（如 2592000=30d 无 includeSubDomains） |
| X-Frame-Options / frame-ancestors | SAMEORIGIN/DENY | 缺失（点击劫持面） |
| Set-Cookie 属性 | Secure + HttpOnly + SameSite 显式 | **无 Secure**（明文回落）/无 HttpOnly/无 SameSite |
| X-Powered-By / Server / ASRRAffinity 等 | 无框架泄露/无内部拓扑 | ASP.NET/IIS 版本、**ARRAffinity Domain 泄露 ASE 内部宿主名** |
| Cache-Control（敏感面） | no-store | 登录后/个资响应可缓存 |

## 二、探针（每主机一条命令）

```bash
curl -sI -A "Mozilla/5.0" https://<host>/ | tee evidence/s4/headers-<host>.txt
# 批量：for h in $(cat targets); do echo "=== $h ==="; curl -sI "https://$h/" ; done 2>&1 | tee evidence/s4/headers-all.tsv
```

- 建议同时抓一个**登录后/敏感路径**响应（无凭据时取登录页本身）对比公开页——敏感面缺口定级更高；
- 变体：一次 404 路径与根路径各一（错误页头有时不同）。

## 三、定级口径

- **聚合登记**：一台主机全部头缺口 → 一条 finding（低/中），detail 引用逐头清单；**不得逐头拆多条**（防报告噪音）；
- 敏感面（登录后页/个资响应）缺 CSP+Cookie 无 Secure → 中；纯公开页头缺失 → 低/信息；
- 泄露类单列：X-Powered-By/内部宿主名/构建号 → 信息级（与 S2 指纹合并引用同一证据）；
- **正向项也必须记录**（TLS 版本、XFO、无 CORS——防报告只报缺不报全）。

## 四、批量产出纪律

- 多主机批量 → `update_coverage` 每主机一单元（C-25，Notes 记"聚合 N 头缺口"，引用 tsv）；同栈同族主机可用一条聚合 finding 覆盖（detail 列主机清单）；
- 误报防护：CDN/网关剥离头属**边缘行为**——标注"经 <网关> 观测"，不下"应用缺失"定论；对比直连源站证据（若有）再定根因；
- 与 C-05 分工：Cookie 的**会话生命周期语义**（吊销/固定/轮换）归 session-lifecycle/identity-flow-audit，本技能只管**属性基线**。
