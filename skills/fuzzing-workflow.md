---
id: fuzzing-workflow
title: Fuzzing 工作流（目标选型→harness→语料→执行→崩溃去重→复现验证）
tags: fuzzing,模糊测试,0day,harness,崩溃,s4,长任务
---
# Fuzzing 工作流

定位：对**解析器/协议实现/文件处理/API 参数边界**做自动化异常输入注入，产出可复现 crash → 归因为漏洞候选。这是 0day 挖掘的主要机器化手段；本手册给通用闭环，引擎侧长作业走 run_async（checkpoint 见 fuzz-harness-go）。

## 前置三问（任一不满足 → 不做 fuzz，转黑盒清单）

1. **对象所有权**：只 fuzz 授权目标/本地副本/自建环境。**生产目标禁止盲 fuzz**（资源压力+服务影响）；对外部服务只做低速率参数变异（见下"外部目标降级口径"）。
2. **可观测性**：能否拿到 crash 信号（stderr/退出码/coverage）？黑盒远程目标没有 crash 信号 → 只能做"响应异常差分"（降级为 hypothesis-0day 变体）。
3. **资源预算**：run_async 上限 7200s；长 fuzz 必须分批+checkpoint，单批不挤占阶段预算。

## 步骤

1. **目标选型**：优先输入解析面（文件上传解析、协议网关、序列化入口、模板引擎、图片/文档处理库）。每个目标 upsert_fact（key=`fuzz.<目标>.<版本>`）。
2. **Harness 构建**：见 fuzz-harness-go（Go native fuzz）/ 外部适配器（AFL++/libFuzzer，需要编译插桩——仅自建环境）。
3. **语料（corpus）**：种子=真实抓包样本/正常文件/文档示例；变异策略交给 fuzzer（结构化格式用语法感知工具，无格式先瞎变异）；语料入工作区 `fuzz/corpus/`（不含敏感数据）。
4. **执行纪律**：先 5 分钟 smoke（验证 harness 能跑、crash 能被捕获）→ 再批量批次；每批 run_async（timeout 明确），poll_async 收口；**阶段收口前全部作业必须有 [JT-JOB-END] 终态**（引擎强制）。
5. **崩溃去重**：按 crash 签名（栈顶三帧/错误类型+输入族）归并——同一签名只保留最小化样本；签名表写 `fuzz/crashes/signatures.txt`。
6. **最小化与复现**：每个独立签名做输入最小化（删减至最小复现）+ 3 次复现验证（稳定复现才算候选）；查崩溃点对应源码（白盒技能）归因类型。
7. **定性入库**：可复现+可归因 → record_finding（exploitability=untested，S5 受控验证影响）；仅 crash 无归因 → record_vt 待分析。误报（fuzzer 假阳性/OOM/超时类）→ update_coverage needs_follow_up 注明。

## 外部目标降级口径（授权 Web/API，无 harness 条件）

- 仅做**参数级变异**（低速率、单变量、批间冷却对齐 batchBudgetGate）；判据=响应异常差分（500/超时/内容畸变 vs 基线）；
- 等效于 hypothesis-0day 的批量版；禁止高并发轰炸（race-condition 技能另批）。

## 判据

- 候选成立：独立签名 + 最小化样本 3/3 稳定复现 + 崩溃点可归因（栈/源码）。
- 排除：环境性失败（磁盘/权限/依赖缺失）——修正环境重跑，不算候选也不算排除。

## 记账

- 每批作业 evidence（命令+job id+输出尾部）；崩溃签名与最小样本入 evidence/；
- coverage 单元 `vuln_class="fuzz-<目标>"`，status 按结果（needs_follow_up/candidate）。

## 工具可用性探针

`which go afl-fuzz gdb`——Go 栈用 native fuzz（go1.18+ 内置）；AFL++ 缺失走 install_tool 或 Go native 降级；均不可用且目标是黑盒 → 转外部目标降级口径。

## Execution Profile 标注（v5.3.2）

- **Lab Only**：对自建/副本目标的插桩 fuzz（编译、高吞吐变异）——仅 isolated_lab；
- **production_safe**：只允许外部目标降级口径（低速率参数变异）与授权文档说明的受控 fuzz；
- 语料/崩溃样本不出工作区；fuzz 产物按 s7 工件处置两档分流。

## 关联技能

fuzz-harness-go（Go harness 模板）、hypothesis-0day（crash→假设→定性）、whitebox-source-audit（崩溃点归因）、parallel-execution（长作业编排）。
