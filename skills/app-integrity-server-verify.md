---
id: "app-integrity-server-verify"
title: "平台应用完整性与服务端判定（Play Integrity/App Attest 挑战绑定→服务端验证→业务决策）"
tags: "app,android,ios,完整性,play-integrity,app-attest,服务端判定,specB1,b1,s4"
---
# 平台应用完整性与服务端判定（specB1 D7 配套——客户端绕过 ≠ 服务端授权缺陷）

> 定位：app-dynamic-audit/hardening-bypass 解决「客户端检测怎么绕」，本技能回答绕过之后**服务端到底怎么判定**——完整性信号（Play Integrity/App Attest）的挑战绑定、服务端验证、重放/缓存/降级处理，及其对高风险业务操作的**实际授权影响**。
> 判定铁律（v6.0.2 specB1 口径）：**客户端检测绕过本身不等同于服务端授权缺陷**——Confirmed 必须证明服务端在信号缺失/绑定错位时仍放行了 Canary 业务操作。平台核验项按地区/商店/设备逐一核验（Android Developer Verification 2026-09-30 起部分地区生效、2027 年全球扩展，不笼统视为全球强制）。
> 版本基线：三平台判定语义分型——**Play Integrity Standard 校验 requestHash（官方防重放）· Classic 依赖服务端 nonce · App Attest 依赖 challenge+clientDataHash+密钥/计数器状态**；不假设三平台同构。

## 一、判定链五段（D7 全程围绕这条链取证，产出《完整性判定链画像》）

| 段 | 观测点 | 观测方法 |
|---|---|---|
| ①挑战请求 | 客户端何时/向谁请求完整性令牌 | mitmproxy 抓包定位 integrity/attest 端点与触发时机（启动/操作前） |
| ②绑定字段 | 请求哈希/nonce/challenge 与业务操作的绑定关系 | 对照两次不同业务操作的 challenge 字段差异（绑定存在性） |
| ③服务端验证 | 服务端是否真的解 verify/decide 并核对绑定 | 剥离/替换信号后观察服务端响应差分（T2/T3） |
| ④风控策略 | 服务端对弱信号/缺失信号的处置（硬拒/降级/放行） | 只在 staging 观察降级路径；生产只观测判定结果 |
| ⑤业务决策 | 完整性结论是否参与业务授权（支付/下单等） | Canary 只读操作与受控写操作的判定差分（Canary-only） |

## 二、D7 测试矩阵（每项：步骤→判据→三态；全部 Canary-only，写操作先审批）

| T | 测试项 | 步骤 | 判据 | 判定 |
|---|---|---|---|---|
| T1 | **挑战-绑定字段完整性（分型核验）** | Standard：改业务请求体后复用旧 integrity token；Classic：nonce 是否服务端签发一次性；App Attest：challenge 是否含 clientDataHash 且计数器单调 | 令牌与业务请求无绑定（换操作体仍可用）= 绑定缺失候选 | Suspected（升 Confirmed 需 T3 服务端效果） |
| T2 | **服务端真实校验** | 剥离 integrity 头/字段重放业务请求（Canary 只读）；对照带完整信号的响应差分 | 无信号仍 200 返回业务数据 = 服务端未强制校验候选 | Suspected→Confirmed（需 T3 受控效果） |
| T3 | **负对照逐字段替换** | 保留其余字段，逐个替换绑定字段（requestHash/nonce/challenge/clientDataHash/包名/设备标识）重放 | 换绑定字段后服务端仍接受并完成业务效果 = **Confirmed**（绑定校验形同虚设）；全部拒绝 = negative_valid | Confirmed/negative_valid |
| T4 | **重放与缓存键复用（三场景）** | ①同令牌双请求 ②跨设备复用令牌 ③服务端缓存窗口内重放（间隔 5s/30s/300s 三档） | 服务端接受已消费/跨主体令牌 = 重放防护缺失 | Confirmed（附判定日志） |
| T5 | **降级与风控口径** | 仅 staging：构造弱信号/超时场景观察降级路径；记录服务端是否按**书面风控策略**执行 | 「未硬拒绝」≠缺陷——有书面分级风控策略佐证 = negative_valid（策略级豁免留痕）；无策略依据的放行 = Suspected | negative_valid/Suspected |

## 二.5、命令骨架（T2/T3/T4 最小可执行序列，客户端侧观测 + 服务端判定差分）

```bash
# 前置：mitmproxy 采集一次完整完整性链（挑战→令牌→业务请求），落盘定位绑定字段
mitmdump -w evidence/d7-flow.mitm --set flow_detail=0   # 目标 APP 挂代理操作一次受保护业务
# T2 服务端校验剥离：原请求 vs 去 integrity 字段重放（Canary 只读端点，排除缓存二次确认）
curl -s -m 10 "$API/protected" -H "X-Integrity-Token: $IT" -H "X-Request-Hash: $RH" -o /dev/null -w "带信号 [%{http_code}] len=%{size_download}\n"
curl -s -m 10 "$API/protected" -o /dev/null -w "剥离信号 [%{http_code}] len=%{size_download}\n"; sleep 5
curl -s -m 10 "$API/protected" -o /dev/null -w "剥离信号·二次(排除缓存) [%{http_code}] len=%{size_download}\n"
# T3 负对照单字段替换（Play Integrity Standard 分型示例）：仅换 requestHash 重放
curl -s -m 10 "$API/protected" -H "X-Integrity-Token: $IT" -H "X-Request-Hash: $RH_TAMPERED" -o /dev/null -w "换requestHash [%{http_code}] len=%{size_download}\n"
# T4 重放三档：同令牌 5s/30s/300s 后各复放一次，判定日志（服务端是否记录"已消费"）逐档留证
# 判读：剥离/替换后 [200]+业务体 且正对照(带全信号)同样 200 = Confirmed 候选；[401/403] = negative_valid
```

## 三、判定判据（深度研究 D7 节口径）

- **Confirmed**：服务端接受「信号缺失/绑定字段被替换」的请求并完成受控 Canary 业务效果（三联证据：请求原文+服务端判定记录/响应+效果留证）；Play Integrity Standard 必须证明 requestHash 未被核对，App Attest 必须证明 challenge/clientDataHash 未被核对。
- **Suspected**（附假阳性排除清单）：①仅客户端可绕过（frida 返回伪造 verdict）但服务端有独立校验（T3 全拒）；②信号字段存在但绑定语义未文档化（需 T3 差分定性）；③缓存窗口内重放成功但窗口有书面 TTL 策略。
- **negative_valid**：全绑定字段替换被拒 + 重放被拒 + 降级符合书面策略——三态齐才可写「完整性链有效」。
- 客户端绕过类发现（frida 绕过 pinning/检测）**只在 app-dynamic-audit 口径下记录存在性**，不得引用本技能判据升 Confirmed。
- 工具：官方 Play Integrity/API 样例仓库**执行时 pin git commit + lockfile**（无稳定语义版本）；App Attest 服务端判定观测以服务端响应形态为主，无法观测时标注「服务端不可观测，降级客户端存在性记录」。

## 四、Execution Profile 标注

- production_safe（默认）：T1-T4 全部 Canary-only 只读或受控写（写操作先 L2 审批）；T5 降级路径仅 staging。
- isolated_lab：可在靶场内完成完整判定链正负对照（含服务端日志取证与降级演练），收尾快照恢复。

## 五、产出对接

- record_finding：cwe=CWE-290（认证绕过-信号信任）/CWE-294（重放）——detail 引用本技能判据项与三联证据；update_coverage(vuln_class=D7完整性判定, notes 记 `T1-T5 三态 + 平台分型`)；
- 配合技能：load_skill app-dynamic-audit（设备通道/抓包前置）、load_skill evidence-standard（确证判据对照）；结论与 specB1《专项条目清单》D7 行对账。
