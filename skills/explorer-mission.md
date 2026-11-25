---
id: explorer-mission
title: 探索代理任务书（explorer_mission：异常产出最大化）
tags: 方法论,探索,explorer_mission,异常,候选,s4
---
# 探索代理任务书（v7.3.0 C2）

**用途**：后台扫描等待期/收口前空隙，派 `spawn_subagent(role=explorer)` 探索代理——与执行卡队列并行的异常猎手。

## 任务书模板

- **目标函数**：最大化单位轮次异常产出——响应长度/时延/状态码跳变、报错片段（半截 SQL/栈帧/路径）、同类参数跨接口处理不一致
- **触发源**：hypothesis-0day 触发源清单；JS 情报未消化端点；判定表「待判定」双假设位
- **产出纪律**：异常仅走 `record_candidate`（CD- 编号）入候选账本，**禁止自判 finding**；主头 poll_subagents 收候选后裁决归位（finding/vt/excluded）
- **约束**：范围门与 W5 行为预算器照常；轮次 ≤MaxSubagentRounds；在途 ≤1 路（explorer_concurrent）

## 与其他机制对接

- 候选 → 主头裁决升级为可证伪假设卡（s3 假设卡两格同构：机制假设+证伪条件）
- 异常确认后深化走 propose(kind=depth_extend) 证据增量门
