---
id: "subdomain-takeover"
title: "子域接管指纹库与判定流程（CNAME 悬挂）"
tags: "子域接管,takeover,cname,悬挂,s1,s2"
---
# 子域接管指纹库与判定流程（hypothesis-matrix C-26 配套）

> 定位：S1 影子资产/S2 子域枚举后的接管面判定。**本表只做 DNS 与无害 HTTP 指纹判定（L0）**；
> 候选确认属存在性证明，不执行接管（接管=内容投递，S5 审批且多数 ROE 禁止）。

## 一、判定流程（三步）

1. **CNAME 悬挂判定**：`dig CNAME <sub>` 指向第三方服务的 CNAME + 该记录 NXDOMAIN 或对端返回 404/Nomatch——无 CNAME 的裸 NXDOMAIN 不构成接管条件；
2. **指纹核对**：对悬挂 CNAME 的目标做 HTTP(S) 探测，响应内容与下表指纹匹配 → **candidate**；
3. **处置**：candidate → record_finding（子域接管风险，含指纹证据截图/响应原文）→ 移交客户在第三方平台完成回收（客户侧动作，智能体不接管）。

## 二、指纹库（响应特征 → 可接管判定）

| 悬挂指向 | 响应特征 | 可接管 |
|---|---|---|
| GitHub Pages | `404 There isn't a GitHub Pages site here` | 是（需自定义域 TXT/HOSTNAME 佐证） |
| S3 静态站 | `NoSuchBucket`（XML） | 是 |
| Azure CDN/CloudApps | `404 Not Found`+`X-Azure-Ref` 头 / "The requested content does not exist" | 视配置 |
| CloudFront | `ERROR: The request could not be satisfied`+`X-Cache: Error from cloudfront`（origin 不存在） | 是（需 origin 域释放） |
| Fastly | `Fastly error: unknown domain:` | 是 |
| Heroku | `No such app`（herokuapp 页面） | 是 |
| Shopify | `Sorry, this shop is currently unavailable` | 是（DNS claim） |
| Tumblr/WordPress/Bitrise/Vercel/Netlify | 各自 404 特征串（以官方文档核对为准） | 是/视配置 |
| 泛解析兜底 | 任意子域同一默认页（非 404） | **不可接管**（登记"泛解析"防误报） |

- 指纹匹配后**必须复核 CNAME 可注册性**（第三方平台侧域名 claim 状态会变化）——复述时标注"指纹匹配+平台 claim 待人工复核"，不得单凭 HTTP 404 断言"已可接管"。
- 误报防线：泛解析（全子域同响应）、对端平台已绑定域名、WAF 统一 404——三者一律 negative_valid 附证据。

## 三、工具

`python3 /opt/tools/subdomain-takeover.py --subs evidence/s1-subs-final.txt`（纯 DNS 指纹，L0 合法；candidate 的 HTTP 二次确认需在授权范围内）。

## 纪律

- 本技能全部判定只读；任何"接管演示/内容放置"动作默认禁止（S5+ROE 且多数授权书明文排除）；
- candidate 只证明风险存在性，回收动作属客户——报告按"高风险（可接管候选，需客户侧回收）"如实定级。
