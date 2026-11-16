---
id: "intel-factory"
title: "JS 情报工厂标准管线（v4.6 W2：chunk 全量/配置必取/sourcemap 还原/四件套产出）"
tags: "侦察,bundle,sourcemap,情报,s2,s3"
---
# JS 情报工厂标准管线（v4.6 W2）

> 审计依据：情报质量是九头鸟顶级强项（某瑞数 WAF 案例 bundle 2.5MB→128 端点；某 sourcemap 案例 1149 文件
> 还原为最深情报源；某网关过滤目标 内网拓扑出自运行时配置文件——主 bundle 计数 0≠无线索）。
> 本管线把"碰运气的提取"变成标准动作，产出四件套供 Authz-Diff（authz-diff）直接消费。

## 一、强制取件清单（缺一即未完成）

1. **入口 HTML**：登录页/首页全量 DOM（记录全部 <script src> 与动态 import 线索）；
2. **主 bundle**（hash 命名）+ **全部 chunk**：从 DOM/路由表枚举后逐个下载——某瑞数 WAF 案例 因通道失效
   永久缺 chunk-vendors，SCA 无输入（教训：chunk 全量 = SCA 的前提）；
3. **运行时配置文件**（config/index.js、env.js、runtime.xxx.js 类）——**独立于主 bundle 加载，
   grep 主 bundle 计数为 0 不代表无线索**（内网拓扑最高价值单点）；
4. **source map**：任何 .js 发现 sourceMappingURL 注释即取 .map；还原后 grep 端点/密钥/默认口令/
   内网地址（某 sourcemap 案例从 1149 还原文件中命中默认口令字面量——脱敏教训：口令本体不入文档）。

## 二、四件套产出（本地分析，零目标流量）

| 产物 | 用途 | 下游消费 |
|---|---|---|
| ①端点表 evidence/s3-api-endpoints.txt（/前缀路径+参数名；**表尾写注释行 `# total=N`，运行中新增行时同步更新——供 authz-diff 完成度硬门与 coverage_gate 对账，v5.1**） | 鉴权矩阵输入 | authz-diff（**100% 全量入矩阵，见其第五节硬门**） |
| ②密钥材料（secret/AES/SM4/WASM 入口+oracle 单测） | 离线请求构造 | crypto-offensive |
| ③业务状态机（页面流→API 调用序） | 逻辑滥用测试 | T-12/支付面 |
| ④隐藏路由/内网拓扑（硬编码 IP/域名，标 范围外） | 横向候选 | S6/范围确认 |

## 三、纪律

- 提取产物**先落盘再登记**（record_finding 引用 evidence 路径必须已存在——引擎 E1 校验）；
- 通配符证书使 CT 无子域明细时，子域发现以空间测绘为主（recon-playbook 联动）；
- 批量取件遵守 js-challenge-waf-playbook 行为预算器（通道健康期做 channel-snapshot）。

## v4.8 M6 工具通道兼容性声明

> 口径（loop-core v4.8 纪律 3）：先 probe 后 batch——每个外部工具对目标首次使用前先用小样本探针确认可用性，探针被拦/挂起先切适配通道再批量；探针结果写入交付物工具声明小节。各工具在「挑战型 WAF / 封闭站」下的可用性与适配通道：

- curl：低频手工请求始终可用——也是挑战态复放的最小工具（channel-snapshot 快照 cookie/UA 复放）；禁用它做大批量枚举。
- channel-snapshot.py：适配通道本体（挑战态提取/复放）——挑战型 WAF/封闭站下始终可用，且是本清单其它工具的适配通道来源。
