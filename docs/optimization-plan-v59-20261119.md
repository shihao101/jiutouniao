# 九头鸟 v5.8.0 → v5.9 优化方案（specA 编排裁决 + 10 分达标定义）

> 产出：GPT-6-Luna（max 推理档，45.9 万 token）基于双轴复审的架构优化方案。
> 状态：方案未实现——本文是实施计划，所有接线点对应当前工作树代码。

### 方案摘要

1. **统一执行治理（P0）**：在 `governanceGates()` 接入 ROE `WritePolicy()`，对 existence-proof 下的非只读 HTTP/命令在审批前拦截；扩展 `scopeGate()`，识别裸域名、域名端口、IP:port 和常见变体。接线点：`roe.go:95-101`、`orchestrator.go:552-670`。

2. **统一阶段状态机（P0）**：主流水线与 loopback 共用阶段执行和状态归并逻辑，统一处理 skipped、paused、failed、killed；把回环额度持久化为项目累计值。当前 loopback 分支漏调 `applyPostExploitGate()`，且最终归并只检查 failed：`orchestrator.go:1225-1284`。

3. **结构化语义门（P1）**：s3 收口时校验假设行的执行卡五要素；IDOR finding 必须关联已验证的 owner 证明，匿名响应参与归属判定；coverage 用结构化证据引用替代 Notes 子串判断，并限定当前阶段。接线点：`orchestrator.go:4211-4243`、`idor-baseline.py:70-96`、`orchestrator.go:4317-4351`。

4. **主代理与子代理统一（P1）**：子代理每轮检查项目预算、做上下文压缩；Token 估算纳入 ToolCalls 和模型扩展字段。当前子代理循环没有预算检查/压缩，`estimateTokens()` 只统计 Content：`subagent.go:141-226`、`context.go:14-21`。

5. **编排与口径收敛（P2）**：修订 specA 的“替换”表述与实际流水线；清理主动索取凭据的矛盾文案；对齐 README 版本；区分技能主命中和配套项，并设组合展开总量上限。相关接线点：`heads.go:67-91`、`credentials_tools.go:67-80`、`skills.go:222-247`、`orchestrator.go:2190-2208`、`README.md:3`。

### specA 裁决

选择 **C 混合模式**：保留 s4、s5 及其通用流程骨架；specA 接管重复的 LLM Top10 专项清单。s4 继续负责适用的通用 Web/API、身份、覆盖和漏洞队列；s5 继续负责利用及实际影响证明。Pipeline 无需改执行算法，需改清晰注释、头文件职责边界和精确顺序测试。

### 10/10 定义概要

- **广度**：靶场覆盖主要目标类型；27 类筛查完整；范围外样例全部拦截；至少 95% 已知范围内入口被测试或有有效移交。
- **深度**：发现具备可解析证据与影响证明；无 owner 证据的 IDOR candidate 升级数为零；阶段故障注入中误报 done 数为零。
- **多 AI 适配度**：至少 3 个模型配置、覆盖 2 种协议；轻量模型按执行卡完成率不低于 80%；P0/P1 语义负例 100% 由引擎拦截，关键环节不只依赖模型自述。

按方案实现、但尚未完成多模型盲测时的预估为：**广度 9.0、深度 8.7、多 AI 适配度 8.3**。这不是实测评分。

**方案路径**：`docs/optimization-plan-v59-20261119.md`（当前未创建）。要完成文件交付，需要在可写工作树中重新执行本任务。
tokens used
459,081
只读审计已完成，但**方案文件未能写入**：当前工作区是只读沙箱，`apply_patch` 明确因写权限被拒绝；审批策略为 `never`，无法通过权限升级解除。实现文件没有改动。

### 方案摘要

1. **统一执行治理（P0）**：在 `governanceGates()` 接入 ROE `WritePolicy()`，对 existence-proof 下的非只读 HTTP/命令在审批前拦截；扩展 `scopeGate()`，识别裸域名、域名端口、IP:port 和常见变体。接线点：`roe.go:95-101`、`orchestrator.go:552-670`。

2. **统一阶段状态机（P0）**：主流水线与 loopback 共用阶段执行和状态归并逻辑，统一处理 skipped、paused、failed、killed；把回环额度持久化为项目累计值。当前 loopback 分支漏调 `applyPostExploitGate()`，且最终归并只检查 failed：`orchestrator.go:1225-1284`。

3. **结构化语义门（P1）**：s3 收口时校验假设行的执行卡五要素；IDOR finding 必须关联已验证的 owner 证明，匿名响应参与归属判定；coverage 用结构化证据引用替代 Notes 子串判断，并限定当前阶段。接线点：`orchestrator.go:4211-4243`、`idor-baseline.py:70-96`、`orchestrator.go:4317-4351`。

4. **主代理与子代理统一（P1）**：子代理每轮检查项目预算、做上下文压缩；Token 估算纳入 ToolCalls 和模型扩展字段。当前子代理循环没有预算检查/压缩，`estimateTokens()` 只统计 Content：`subagent.go:141-226`、`context.go:14-21`。

5. **编排与口径收敛（P2）**：修订 specA 的“替换”表述与实际流水线；清理主动索取凭据的矛盾文案；对齐 README 版本；区分技能主命中和配套项，并设组合展开总量上限。相关接线点：`heads.go:67-91`、`credentials_tools.go:67-80`、`skills.go:222-247`、`orchestrator.go:2190-2208`、`README.md:3`。

### specA 裁决

选择 **C 混合模式**：保留 s4、s5 及其通用流程骨架；specA 接管重复的 LLM Top10 专项清单。s4 继续负责适用的通用 Web/API、身份、覆盖和漏洞队列；s5 继续负责利用及实际影响证明。Pipeline 无需改执行算法，需改清晰注释、头文件职责边界和精确顺序测试。

### 10/10 定义概要

- **广度**：靶场覆盖主要目标类型；27 类筛查完整；范围外样例全部拦截；至少 95% 已知范围内入口被测试或有有效移交。
- **深度**：发现具备可解析证据与影响证明；无 owner 证据的 IDOR candidate 升级数为零；阶段故障注入中误报 done 数为零。
- **多 AI 适配度**：至少 3 个模型配置、覆盖 2 种协议；轻量模型按执行卡完成率不低于 80%；P0/P1 语义负例 100% 由引擎拦截，关键环节不只依赖模型自述。

