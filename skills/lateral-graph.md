---
id: lateral-graph
title: 横向决策图消费（lateral_edge 逐边提议-裁决-执行）
tags: 方法论,横向,lateral_edge,决策图,s6
---
# 横向决策图消费（v7.3.0 C4）

**输入**：S6 上下文「横向决策图」块（ensureAttackGraph 按需生成：黑板 facts links=边 + 战利品凭据边 + 拓扑重建节点）。

## 逐边提案协议

1. **读图**：候选边 = 源访问已确证 → 目标（凭据复用边/信任滥用边/网段可达边）
2. **支撑核验**：每边必须有黑板 fact（凭据存在性/共享态）或战利品 verified 条目支撑；无支撑边先补证
3. **提议**：`propose(kind=lateral_edge, plan="边探测计划", evidence_refs=[fact:键/VT-])`——引擎核验配额（每阶段 ≤5）与生产档写语义禁项
4. **执行**：探测请求 ≤ROE 额度、逐边留证；生产档只做可达性存在性证明，写语义步骤移交
5. **回写**：每边结论 `update_proposal`（可达/不可达/需更高身份）——横向路径图按账本结果增量更新

## 纪律

- windows-lateral/ad-attack/intranet-lateral 剧本提供边内的具体打法（本手册只管图层编排）
- 拓扑重建未覆盖的内网向量逐项三态处置（s6 既有强制不变）
