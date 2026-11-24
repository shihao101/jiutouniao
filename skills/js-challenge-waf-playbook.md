---
id: "js-challenge-waf-playbook"
title: "JS 挑战型 WAF 对抗剧本（瑞数类：行为预算/通道矩阵/对策阶梯）"
tags: "对抗,WAF,瑞数,js-challenge,浏览器,限速,behavior,s2,s4,s5"
---
# JS 挑战型 WAF 对抗剧本（v4.6 K6/C3）

> 指纹（瑞数族特征卡）：$_ts 变量 / r='m' script 属性 / 动态 JS 路径 / 202 Accepted + Server 打码 + 长效随机 Cookie。
>
> **通用 JS 挑战特征表（v5.1，非瑞数族对照）**：①202/429 挑战页或 meta refresh 中转页；②Set-Cookie 长效随机键（挑战通过后才发业务 cookie）；③动态脚本路径（`/xx.js?ts=` 时间戳参数）；④body 内 JS 自解包（eval/Function 大段字符串数组）；⑤Canvas/WebGL 指纹采集后回传；⑥首次请求无内容+二次请求正常（cookie 种子机制）。命中任一 → 按 js-challenge-waf 行为类处置（行为预算器/通道矩阵全族通用），具体指纹特征与预算参数按 WAF 族分别标定（瑞数族参数见本剧本；其他族先单点标定再固化）。

## 零、单次实验不得升级为全局约束（E5）

任何"该 WAF 下 X 不可能"类结论必须有 ≥3 样本+跨目标类复验，并在 record_lesson 带
`behavior_class=js-challenge-waf, sample_size=N, valid_scope=…`——单点实验固化为组织真理已被审计证伪。

## 一、通道矩阵（健康期建立，失效期重放）

| 通道 | 建立时机 | 失效判定 |
|---|---|---|
| chromium --headless=new（无自动化特征） | 挑战必过首选 | DOM<100B 或含 $_ts |
| CDP Page.navigate 批量 | 健康期 | 首次导航后 WS 超时≠WAF，先排除本地（换端口/新 profile 对照） |
| curl+通道快照 | 快照新鲜（≤30min） | 单请求重放见 channel-snapshot 技能 |
| dump-dom 逐 URL | 批量提取 | 行为预算器限额（见下） |

## 二、行为预算器（防渐进式降级——审计实证：10+ 次批量 dump-dom 触发静默降级 9+ 小时）

- 单日 dump-dom/批量导航 ≤8 次，批间基线自检（登录页字节数）；
- **空壳即停**：任何一次空壳 DOM → 立即停止全部批量动作，转快照重放判定；
- 降级判定三排除（IP 封禁/浏览器故障/WAF 配置变更）后仍空壳 → 记 `channel_status=degraded` 上黑板，停止浏览器通道。

## 三、对策阶梯（按序尝试，逐级上报）

1. 通道快照 + curl 复用（零成本）；
2. 浏览器池轮换（新 profile/UA/端口，限速 6s+批间 90s）；
3. **出口轮换**（换出口 IP 重置 WAF 会话状态——单出口降级不拖垮全局）；
4. **客户协同**：生成《WAF 测试白名单/豁免窗口申请》（缺口+预期收益+回滚），request_user_input 提交——这是实战标配，不是能力缺陷；
5. 离线挑战实现（JS-VM 语义还原）：仅当 ROE Profile `waf_policy.offline_challenge=allow`。

## 四、本地故障与目标行为分离归因（防归因污染）

CDP WS 超时/403 origin = 本地故障（chromium 版本/origin 校验/僵尸进程），与 WAF 无关；
每次失败先做本地对照（example.com + file:// 渲染），两个假设两条证据线，禁止合并叙事。

## v4.8 M6 工具通道兼容性声明

> 口径（loop-core v4.8 纪律 3）：先 probe 后 batch——每个外部工具对目标首次使用前先用小样本探针确认可用性，探针被拦/挂起先切适配通道再批量；探针结果写入交付物工具声明小节。各工具在「挑战型 WAF / 封闭站」下的可用性与适配通道：

- curl：低频手工请求始终可用——也是挑战态复放的最小工具（channel-snapshot 快照 cookie/UA 复放）；禁用它做大批量枚举。
- channel-snapshot.py：适配通道本体（挑战态提取/复放）——挑战型 WAF/封闭站下始终可用，且是本清单其它工具的适配通道来源。

## v4.8 W5 挑战求解增补（离线实现协议，ROE 门控）

- 挑战 JS 特征判定：`python3 /opt/tools/jsvm-challenge-solver.py --js <挑战JS文件>`——输出混淆特征集合（字符串数组/控制流平坦化/VM 分发器）与下一步建议。
- 反混淆脚手架与离线实现骨架：`--scaffold --out poc/challenge/ --roe-allow`——**ROE 门**：仅 ROE Profile `offline_challenge=allow` 时可加 --roe-allow（deny 口径一律走会话通道 channel-snapshot/browser-auth，不破解）；实现成立判据=≥3 组实测向量全命中（vectors.json 单测）。
- 离线实现的 token 计算器与 channel-snapshot 快照态**互为补充**：批量动作优先用快照态重放，快照态失效再离线计算——两者都不可用时降级 browser-farm 换 profile 重试。
