---
id: chain-planning
title: 链路级计划手册（chain_plan 提议：每步命令/判据/回滚/无害性声明）
tags: 方法论,自主决策,chain_plan,链路,凑链,s5,s6
---
# 链路级计划手册（v7.3.0 C3）

**用途**：凑链场景（primitive-graph 缺口 ≥2 环）不再逐命令等待——`propose(kind=chain_plan, steps=[每步命令 ≤6])` 一次提交整链，引擎逐步过执行档预检后批准；链内每步执行时治理九门仍逐条强制（预检≠放行）。

## 一、工单格式（steps 数组，每步一条完整命令）

每步必须自带三要素（写进命令注释或事后 update_proposal 的 outcome 里）：
1. **判据**：本步的阴阳信号（回显标记/OOB 回连/长度差分/状态码）
2. **回滚/终止**：abort_condition（如「403 连续 2 次即断链」）
3. **无害性**：生产档仅存在性证明链（无害回显/随机标记/受控 OOB）；isolated_lab 才可完整 PoC 链

## 二、两档模板

- **生产档存在性证明链**（默认）：探测 → 差分确认 → OOB/标记落证 → 停（不投递载荷）
- **靶场档完整链**（isolated_lab）：上传 → 解析触发 → 能力证明 → 快照回滚点标注

## 三、纪律

- 步骤 ≤6；更长链拆主链+续链分次提议
- denied 回执 PROFILE_BLOCKED → 该步改存在性证明形态或删除该步后重提
- 执行结果逐环 `update_proposal` 回写（断环位置=下一轮 chain_plan 的反向回推输入）
- 与 capability-primitive-search 配合：原语图 BFS 出候选链 → 本手册打包提交
