---
id: "history-recon"
title: "历史快照与影子接口挖掘（Wayback CDX · 影子 API 对照矩阵）"
tags: "wayback,历史,shadow-api,影子接口,端点,s2,s4"
---
# 历史快照与影子接口挖掘（已下线功能≠已删权限——鉴权薄弱高发带）

> 定位：用 Web Archive 历史快照还原「页面自己已经不说」的旧接口/旧路由，与当前自述面（bundle/文档）
> 做差分得**影子接口候选**，逐条入 authz-diff 全量矩阵。对治 API9（Improper Inventory Management）：
> 旧版本接口/已下线功能的鉴权常停留在历史版本水位。

## 一、Wayback CDX API（curl 直用，scopeGate 白名单内）

```bash
# 1) 全量历史 URL（collapse 去重，statuscode 过滤存活性线索）
curl -s -m 30 "https://web.archive.org/cdx/search/cdx?url=<域>/*&output=json&collapse=urlkey&fl=original,statuscode,mimetype&filter=mimetype:application/json" | jq -r '.[1:][]|.[0]' | sort -u > evidence/history-urls.txt
# 2) 限定路径前缀（只看 API 带）：
curl -s -m 30 "https://web.archive.org/cdx/search/cdx?url=<域>/api/*&output=json&collapse=urlkey&fl=original,mimetype" | jq -r '.[1:][]|.[0]' >> evidence/history-urls.txt
# 3) waybackurls/gau（若环境可安装则批量更快）：
waybackurls <域> 2>/dev/null | sort -u > evidence/history-urls.txt || echo "MISSING waybackurls，走 CDX 兜底"
# 4) 带参数历史 URL（参数即历史注入点清单）：
grep -E "\?[a-z]+=" evidence/history-urls.txt | head -30
```

- 纪律：CDX 查询间隔 ≥2s（公益服务限速）；快照内容只读、只提取 URL 结构，**不下载归档正文**（内容可能含历史用户数据）。

## 二、影子接口对照矩阵（核心产出）

```
历史路径集合 H（CDX/waybackurls 清洗：去静态资源、去重参数值）
自述面集合 S（intel-factory 端点表 ① + checklist.json）
影子候选 X = H − S（历史存在、当前自述面未提及的路径）
逐条处置：
  ① 匿名直调（当前域名）→ authz-diff 判据三态（401/403=门控有效；200+业务体=影子接口未鉴权，高危）
  ② 前缀变体复核（/api/v1/ → /api/v2/；/api/ → /api/old/ /api/legacy/）——老版本对照
  ③ 命中的影子接口入端点表（表尾 # total=N 同步更新）→ 100% 入 authz-diff 矩阵（v5.1 硬门）
```

| 判据 | 判定 | coverage |
|---|---|---|
| 影子候选匿名返回业务数据 | **影子接口未鉴权**（API9+API5 组合）record_finding 高危 | vulnerable |
| 401/403/跳登录 | 门控有效（负结果入账） | no_issue_found |
| 历史路径当前 404 且无前缀变体命中 | 已下线且已清除 | ruled_out |
| 404 但响应体为应用层（非网关标准 404） | 路由存在权限拦，needs_follow_up | needs_follow_up |

## 三、历史价值信号（优先深挖）

1. **旧版本 API 前缀**（/v1 当前文档只提 /v2）→ 版本残留鉴权差分（api-doc-leak 版本差异联动）；
2. **历史文件下载/取件面**（download/file/export/getfile 类路径）→ path-traversal + ssrf-deep 双假设；
3. **历史 admin/后台路径**（manage/admin/console/dashboard）→ 匿名直调+网关绕过矩阵；
4. **带 ID 参数的历史接口**（?sid=/?userId=）→ 影子 IDOR 候选（api-idor 联动）；
5. 快照时间线对比（同路径 2019 存在/2024 消失）→ 功能下线时间线索，移交客户核实「下线=清理」还是「下线=隐藏」。

## 四、纪律

1. 影子接口**写端点只测门控存在性**不实调（authz-diff 第四节口径）；
2. 影子接口命中数据按 ROE 数据边界处置（存在性证明，PII 掩码）；
3. 「历史 URL 存在」本身不是 finding——确证判定必须来自**当前目标**的实测响应；
4. 全部影子候选（含 ruled_out）入覆盖矩阵留痕，防"测过即忘"与重复试错。

## 五、产出对接

- evidence/history-urls.txt 留证 + 对照矩阵入 deliverables；
- record_finding（影子接口未鉴权，cwe=CWE-477/OWASP API9）+ update_coverage(vuln_class=影子接口，notes 记 `shadow_found/total`)；
- 端点表联动：intel-factory ①产物追加来源注释行（`# 来源: history-recon`）。

## v4.8 M6 工具通道兼容性声明

- web.archive.org/archive.org：scopeGate 默认白名单内（v5.3.0 起），strict_scope 项目直连可用；
- CDX 查询是对公益档案服务的读请求，非对目标发包；waybackurls 不可用时 curl 兜底全程可用（本技能零安装依赖）。
