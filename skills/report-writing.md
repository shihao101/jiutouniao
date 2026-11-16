---
id: report-writing
title: 报告撰写与漏洞定级手册（CVSS）
tags: 报告,cvss,定级,s8
---
# 报告撰写与定级手册

## 定级（CVSS v3.1 简表 + 业务修正）
- P0 高：RCE、SQL 注入出数据、未授权管理功能、云密钥泄露 → CVSS ≥ 9
- P1 高：存储 XSS、越权读全量、SSRF 打内网 → 7.0-8.9
- P2 中：反射 XSS、CSRF 关键操作、信息泄露（部分）→ 4.0-6.9
- P3 低：低危配置、缺少安全头 → 0-3.9
- 业务修正：涉及 PII/资金/监管系统上调一级；纯测试环境下调。

## 报告结构（report.md）
```
# 渗透测试报告 — <项目名>
## 执行摘要（≤5 段：整体结论/关键数字/Top3 风险/覆盖度概况/修复优先级）
## 测试范围与方法（资产/窗口/审批矩阵执行情况/覆盖度矩阵引用）
## 发现详情（每条：编号/标题/等级/置信度/位置/漏洞详细介绍/POC 请求响应原文对照/修复建议/证据编号 EV-xxx——v5.3.6 起介绍/POC/修复建议直接引用 finding 库的 detail/poc/remediation 字段，页面与报告同源）
## 安全向量确认（no_issue_found 汇总——证明测过且安全）
## 分析盲区（needs_follow_up/skipped 汇总——诚实交代没测到的）
## 修复建议清单（优先级表）
## 附录（攻击时间线/AI 专项结论/导出文件：findings.sarif）
```

## 写作纪律
- 每条发现必须有 EV-xxx 证据编号支撑；推测进「待查」不进正文结论。
- 复现步骤要能让客户工程师独立重现；修复建议给到具体配置/代码层面。
- **漏洞编号规范（v5.1）**：报告条目 `R-<三位序号>`（R-001..，与 findings 库 1:1 由引擎硬校验）；证据 `EV-<四位序号>`；PoC `poc/<R编号>_<漏洞名>.py`——三套编号不混用。
- **密级与分发（v5.1）**：报告首页标注密级（客户授权方指定，默认"秘密——仅限授权方与修复方"）与分发范围；POC/武器化细节（可复用利用代码段）不入主报告，走移交附件说明（S8-3）。
- **复测章节（v5.1）**：修复建议清单后附《复测建议》小节——每条 R-xx 的复测窗口/复测判据（按 evidence-standard 该类确证判据）/复测工作量估计。

## 复现证据标准（Burp 原文对照，强制）

- 捕获方式：`curl -sv -i '<url>' ... 2>&1`（一条命令同时落请求原文与响应原文，便于证据页直接呈现对照）；需要完整请求原文时用原生套接字：
  `printf 'POST /path HTTP/1.1\r\nHost: <目标>\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: N\r\nCookie: ...\r\n\r\n<载荷>' | timeout 5 nc <host> <port>`
- 呈现格式（报告与证据文件统一，成对出现）：

```
=== 请求原文 ===
POST /api/login.php HTTP/1.1
Host: 47.x.x.x:8000
Cookie: uid=1
Content-Type: application/x-www-form-urlencoded

uid=2

=== 响应原文（关键部分） ===
HTTP/1.1 200 OK
Content-Type: application/json

{"uid":2,"email":"victim@x"}
```

- 漏洞条目的复现步骤 = 上述成对原文块 + 一句影响说明；不允许只写"用 Burp 抓包改包"这类无原文描述。
