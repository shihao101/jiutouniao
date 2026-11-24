---
id: "llm-agent-protocol-boundaries"
title: "Agent 协议与委托信任边界（MCP/A2A：受众绑定/令牌透传/工具描述替换/出站路径）"
tags: "llm,agent,mcp,a2a,协议,信任边界,受众绑定,specA,a,s4"
---
# Agent 协议与委托信任边界（specA A12 配套——MCP / A2A 委托链专项）

> 定位：llm-agent-toolchain 覆盖「应用层工具滥用」（function calling/插件越权），本技能覆盖**协议层委托信任边界**——「谁在以什么身份调用什么、令牌为谁签发、工具定义是否被换、出站到了哪」。
> 判定铁律（v6.0.2 specA 口径）：**验证结果限于测试 Agent、测试工具与隔离租户内闭环**；Confirmed 需要服务端/资源侧日志证明「错误受众被接受 + 受控效果」，机械探测只产出候选。
> 版本基线：MCP 规范 2026-07-28（无状态请求/逐请求版本协商；OAuth 受众绑定/令牌不透传/混淆代理为核查点）——先问目标实现声称的协议版本，不假设。

## 一、开工基线（产出《协议边界画像》，后续测试全部依赖）

| 盘点项 | 观测方法 | 喂养的测试项 |
|---|---|---|
| 协议与版本声称 | /health、.well-known、握手响应、文档——MCP server 尽量经 stdio/SSE 双通道各探一次 | T1/T4 输入 |
| 工具清单快照 | tools/list 全量导出 → 规范化（名称+描述+schema）哈希落盘 `evidence/a12-tool-manifest.json` | T4 rug-pull 差分基准 |
| 令牌形态 | Agent↔MCP/A2A 各跳的 Authorization 形态（aud claim / 透传上游令牌 / 每跳交换） | T2/T3 输入 |
| 委托拓扑 | 谁的凭据调用谁的资源：用户→Agent→MCP server→下游 API 的身份链草图 | T3/T6 输入 |
| 出站面 | MCP server/A2A agent 可达的外部地址（fetch/webhook/回调） | T5 Canary 预置 |

## 二、A12 测试矩阵（每项：步骤→判据→三态；全部只用测试 Agent/测试工具/隔离租户）

| T | 测试项 | 步骤 | 判据 | 判定 |
|---|---|---|---|---|
| T1 | **工具清单快照与来源校验** | 快照 tools/list → 与文档/声称版本比对 → 记录差异 | 工具集与文档不符/存在未声明工具 = 供应链漂移候选 | Suspected（T4 升级确认）；未见差异=negative_valid |
| T2 | **OAuth 受众绑定** | 签发/获取「面向服务 A 的测试令牌」→ 以该令牌调用服务 B 的 MCP 资源（mock 资源，正对照=正确受众令牌可用） | 错误受众令牌获得 mock 资源（超出批准范围）= **Confirmed**（服务端接受错误受众） | Confirmed（附请求 ID+服务端判定+效果三联）|
| T3 | **令牌透传与混淆代理** | 观察中间层是否原样转发终端用户令牌到下游；构造「代理以自己身份调用」场景 | 令牌跨信任边界原样透传 / 代理身份与最终资源主体不一致且无审计 = Suspected（有服务端混权效果证据升 Confirmed） | Suspected→Confirmed |
| T4 | **工具描述与实现一致性（rug-pull/影子工具）** | 同一工具跨会话/跨时间二次快照 diff；低信任来源的 MCP server 换描述后重试受控效果 | 描述变更未触发审批/重新确认，且低信任变更可绕过审批触发受控效果 = **Confirmed**；仅描述漂移 = Suspected | Confirmed/Suspected |
| T5 | **出站路径 Canary 追踪** | 在测试 Agent 的工具参数中植入唯一 Canary URL/标记 → 观察出站请求落点 | Canary 出站到非授权地址 = 存在性确证（SSRF/外传面）；出站受白名单约束 = negative_valid | 存在性确证（影响按落点定级） |
| T6 | **A2A 委托身份与上下文转移矩阵** | 双测试 Agent（主体 A/B）互发任务：身份声明、上下文来源、任务转授权限逐格观测 | 低信任 Agent 可借委托获得高信任 Agent 的资源访问 = Suspected（有服务端效果证据升 Confirmed） | Suspected→Confirmed |

## 二.5、命令骨架（T2/T4/T5 最小可执行序列；MCP Inspector 为主执行器）

```bash
# 基线：MCP Inspector 2.14.0（版本锁定，记录哈希）连测试 server 导出工具清单快照
npx @modelcontextprotocol/inspector@2.14.0 --cli --method tools/list 2>/dev/null | tee evidence/a12-tools-t0.json
# T4 rug-pull 差分：间隔/换会话后二次快照 → 规范化 diff
npx @modelcontextprotocol/inspector@2.14.0 --cli --method tools/list 2>/dev/null | tee evidence/a12-tools-t1.json
python3 - <<'EOF'
import json,hashlib,re
def norm(p):
    d=json.load(open(p)); return hashlib.sha256(json.dumps(sorted(json.dumps(x,sort_keys=True) for x in d),ensure_ascii=False).encode()).hexdigest()[:16]
print("t0:",norm("evidence/a12-tools-t0.json"),"t1:",norm("evidence/a12-tools-t1.json"))
EOF
# T2 受众绑定负对照：A 受众令牌打 B 服务 mock 资源（正对照：B 受众令牌必须可用——没有正对照不得下结论）
curl -s -m 10 "$B_MCP_RESOURCE" -H "Authorization: Bearer $TOKEN_FOR_SERVICE_A" -w "\n[A-aud→B资源] [%{http_code}]\n" | tail -1
curl -s -m 10 "$B_MCP_RESOURCE" -H "Authorization: Bearer $TOKEN_FOR_SERVICE_B" -w "\n[B-aud→B资源·正对照] [%{http_code}]\n" | tail -1
# T5 出站 Canary：测试 Agent 工具参数植入唯一标记 URL，观察服务端出站
# <AGENT> fetch 参数填 https://canary.<隔离域>/a12-t5-<随机id> → 在 Canary 接收端核对命中即出站存在
```

## 三、判定判据（深度研究 A12 节口径）

- **Confirmed**（两形态）：①错误受众令牌在 mock 资源上获得超出批准的访问（附：请求原文+服务端身份判定日志/响应+受控效果记录）；②低信任工具描述变更绕过审批并触发受控效果。缺任一联（请求/判定/效果）降 Suspected。
- **Suspected**（附假阳性排除清单）：①仅描述漂移但审批仍触发；②透传存在但下游有独立受众校验（正对照证明）；③文档与实现版本号不符但行为一致。
- 机械探测（Inspector/扫描器）只产出候选——**Snyk Agent Scan 0.6.5.1（原 MCP-Scan）先对隔离 mock server 跑通再对目标**，结果人工复核后才可引用。
- **A2A 无稳定官方黑盒审计器**——降级为自建测试 Agent + 代理日志 + HTTP 桩观测，标注「自建降级路径」，不伪造官方工具结论。

## 四、Execution Profile 标注

- production_safe（默认）：T2/T3 只用测试令牌与 mock 资源；T4 只做快照 diff 与测试 Agent 内受控效果；T5 Canary 只指向自建隔离接收端。服务端令牌签发/策略修改类动作 = Lab Only 或须 L2 审批。
- isolated_lab：可在靶场内完成完整受众绑定正负对照链（含服务端日志取证），收尾恢复快照。

## 五、产出对接

- record_finding：cwe=CWE-287/T2（受众绑定缺失）、CWE-863/T3（授权错置）、CWE-1357/T4（供应链完整性）——detail 引用本技能判据项与「请求/判定/效果」三联证据；update_coverage(vuln_class=A12协议边界, notes 记 `T1-T6 三态`)；
- 配合技能：load_skill llm-agent-toolchain（应用层工具滥用联动）、load_skill evidence-standard（确证判据对照）、load_skill auth-flow-deep（令牌链还原）；命中越权资源访问移交 api-idor 口径量化。
