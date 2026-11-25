---
id: mutation-campaign
title: WAF 变异攻坚闭环（mutation_campaign 提议：变异-观察-再变异）
tags: 方法论,WAF,变异,mutation_campaign,对抗,s4,s5
---
# WAF 变异攻坚闭环（v7.3.0 C2）

**前提**：该单元已 `update_coverage=waf_blocked` 且已 `load_skill waf-fingerprint` 留指纹——引擎核验前提，缺一拒收。

## 闭环协议（变异-观察-再变异）

1. **提议**：`propose(kind=mutation_campaign, focus="C-xx@endpoint", rationale="拦截页形态+变异假设")`
2. **变异族设计**（≤3 族、每候选 ≤6 请求）：按 payload-mutation-algebra 选族——编码类/等价类/参数位类；族内单脚本批量投递（禁逐发）
3. **观察**：响应聚类（长度/时延/状态码/拦截页文案差分）；族间对比找「半通过」信号
4. **再变异**：对半通过族做二轮聚焦变异；两轮无突破即收——单元落 waf_blocked 移交，勿再攻坚

## 纪律

- 每阶段 ≤3 次攻坚提议（引擎配额）；ROE 禁绕过时直接移交不提议
- 变异脚本落盘 evidence/（每次投递请求/响应原文留证，对齐 claims 纪律）
- 攻坚产出（绕过成功）直接 update_coverage=vulnerable + record_finding，`update_proposal` 回写账本
