---
id: "authz-diff"
title: "鉴权差分扫描器（阳性对照法/500 可达判据/家族复查）"
tags: "对抗,鉴权,差分,白名单遗漏,未授权,s4"
---
# 鉴权差分扫描器（v4.6 W3/C2-3，承 某网关过滤目标 差分法 + 某限速分型目标 无鉴权矩阵）

> 审计依据：全部未授权类高危（24,929 人枚举、网关白名单单点遗漏、15 端点无鉴权）都是
> 该方法的手工版；引擎化为标准动作后 128 端点级矩阵是每目标必做项。

## 一、矩阵设计（单变量原则）

```
对每个端点 × {无token, 无效token, 无签名, 正确签名(需 crypto-offensive oracle)} × {GET, POST(空体)}
对照组：①阳性对照=已知 anon 端点（/sys/login /captcha）②阴性对照=随机乱码路径×3（网关通配 200 时以体长/体内容区分）
```

## 二、判读判据（与引擎 E3 语义对齐）

| 观测 | 判定 | coverage |
|---|---|---|
| 401/403 invalid token（与基线一致） | 鉴权有效 | negative_valid |
| 500「未知异常」体（与阳性对照同形态） | **穿透网关到达某应用处理路径**（v5.3.0 口径：错误参数/业务异常/统一异常处理同样产生 500——**仅记为可达候选 Observation，不构成鉴权绕过确证**）；确证须再加：已知公开阳性对照同形 + 随机路径阴性对照不同形 + 受保护资源无身份请求差异 | HIT：候选（需复核） |
| 200 + 业务 JSON（code=0/1 或数据） | **未鉴权数据访问** | vulnerable（量化后） |
| 超时/000 | 未定性 | needs_follow_up（不得 ruled_out） |

## 三、纪律

- 批量探测限速（rate-limit-playbook），随机对照防"网关通配 200"误判；
- HIT 端点做**同族复查**（4 端点家族）确认单点/族级遗漏（某网关过滤目标 口径）；
- 写端点 HIT 按 exploitability=conditional 呈现（引擎 E4），写效果实测需 L2+ROE。

## 四、工具

`python3 /opt/tools/authz-diff.py --base https://t --endpoints evidence/api-endpoints.txt --control /sys/login --out evidence/authz-matrix.tsv`（直连模式；WAF 目标产出的请求计划交 CDP 执行器按同判据回填）。

## 五、全量覆盖率硬门（v5.1，所有任务强制——对治"端点表 N 行只测抽样"事故）

1. **无 token 列纯匿名**：矩阵的「无token」列零依赖身份——**禁止以"等拿到身份再测"为由推迟或抽样**；会话态只用于「有效token/正确签名」列与挑战型 WAF 通道适配。
2. **全量对账**：端点表 N 行（intel-factory ①产物等全部来源，含 checklist.json 自述面与 S4 运行中新发现端点——**新端点入表即入矩阵**）必须 100% 进入矩阵；`update_coverage` 的 Notes 记账 `diffed/total`（如 `authz-diff diffed=67/total=67`）。
3. **三态处置**：每行必须落到 vulnerable / no_issue_found（negative_valid）/ waf_blocked / needs_follow_up 之一并附证据摘要；`超时/000=needs_follow_up`（不得 ruled_out）——被封锁不算"测完"，解封后补测。
4. **破坏性端点只测门控存在性**：DELETE/写端点以无 token GET/OPTIONS 探测门控（401/403/302→CAS/hasLogin:false 判定），不实调；写效果实测走 L2+ROE（见三、纪律）。
5. **收口门槛**：清点覆盖率未达 100%（或缺口行无三态处置）不得收口移交——离线门 `coverage_gate.py` 端点表↔矩阵计数对账会拦截（v5.1）。
6. **清点率 ≠ 测试执行率（v5.3.0 概念分离）**：`diffed/total=100%` 是**清点归账**（每端点有归宿），不等于每个方法/参数/角色都已实测。两类指标分开报告：①端点登记率（目标 100%）；②实际测试执行率（tested/blocked/deferred/ROE_excluded/not_applicable 按端点×方法×身份状态分列）。写端点实测效果属 L2 且生产模式默认不做（见 execution_profile）。

## v4.8 M6 工具通道兼容性声明

> 口径（loop-core v4.8 纪律 3）：先 probe 后 batch——每个外部工具对目标首次使用前先用小样本探针确认可用性，探针被拦/挂起先切适配通道再批量；探针结果写入交付物工具声明小节。各工具在「挑战型 WAF / 封闭站」下的可用性与适配通道：

- authz-diff.py：**无 token 列无需会话态、纯匿名可全量执行（见第五节硬门）**；「有效token/正确签名」列批量复放需会话态；挑战型目标先 channel-snapshot 提取态注入 header 再跑矩阵。
- curl：低频手工请求始终可用——也是挑战态复放的最小工具（channel-snapshot 快照 cookie/UA 复放）；禁用它做大批量枚举。
