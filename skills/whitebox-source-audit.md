---
id: whitebox-source-audit
title: 白盒源码审计工作流（源码获取→识别→危险模式检索→验证）
tags: 白盒,代码审计,0day,源码,灰盒,s3,s4
---
# 白盒源码审计工作流

0day 最可靠的来源是**目标源码本身**。本手册定义从"拿到源码"到"可验证候选"的通用流水线；静态候选一律进验证队列（record_vt），不直接当漏洞。

## 前置条件（缺一即降级为黑盒，不硬做）

1. **源码工件合法性**：客户书面提供源码包 / 明确授权的公开仓库 / S1 已确认的 git 服务暴露面。工件入工作区 `source/` 目录，先记录 SHA-256 与来源（evidence/ 留证）。
2. **语言识别**：`find source -name "*.go" -o -name "*.java" -o -name "*.py" -o -name "package.json" -o -name "pom.xml" -o -name "requirements.txt" | head -30` 确定技术栈；多语言分别走对应分支。

## 步骤

1. **工件登记**：hash + 版本 + 来源 → upsert_fact（key=`source.<名称>`，confidence=confirmed）。
2. **结构速览**：入口点清单（main/router/controller/urls.py/App.java）→ 端点与处理函数映射（与黑盒接口清单 diff，**源码里有而接口清单没有的 = 影子端点**，优先测试）。
3. **危险模式检索（source→sink 候选）**：按语言跑 grep 族探针（见 whitebox-sca-taint 的 sink 表），每条命中登记 `record_vt`（title=「白盒候选：<sink>@<文件:行>」，ready_assets=命令+文件路径，priority 按可达性 1-6）。
4. **可达性分析**：对每个候选回答三问——①外部输入能否到达该 sink（路由→参数→处理链）；②有无过滤/编码/权限检查拦截；③验证需要什么前置（登录态/特定参数）。三问答案写入 VT 的 start_conditions。
5. **验证投递**：S5 按 VT 优先级实测（黑盒验证手法见对应技能：sqli-deep/cmdi-deep/xxe-full…）；静态候选**不得**未实测标确证。

## 判据

- 候选成立：外部输入路径完整 + 拦截缺失/可绕过 + 动态验证复现（三要件齐）。
- 候选排除：source→sink 路径断裂或强制拦截在验证点之前 → update_vt closed-roe 附代码行号证据。
- **工具不可用/无源码**：如实 needs_follow_up，不得输出"未发现问题"类结论。

## 证据与记账

- 每个候选的检索命令+命中行 → evidence/；验证结果 update_coverage（vuln_class 用真实类名，notes 引用 `source/<file>:<line>`）。
- 影子端点先 record_asset 再入黑盒接口清单。

## 工具可用性探针

- `which semgrep ctags ripgrep` —— ripgrep 基线必有；semgrep 缺失时用 `grep -rn` + sink 正则表降级（精度下降，VT 里注明降级）；均不可用 → run_command `command not found` 时走 install_tool。

## Execution Profile 标注（v5.3.2）

- 源码检索/阅读全部只读（L0），生产档可执行；验证投递按对应漏洞类技能的档位约束。
- **源码工件不得外传**：不上传公网分析服务、不分发（production_safe/isolated_lab 同禁）。

## 关联技能

whitebox-sca-taint（依赖分析+污点细化）、patch-diffing（已知版本差分）、hypothesis-0day（候选→假设→验证）、cve-weaponization（命中已知 CVE 时转此路）。
