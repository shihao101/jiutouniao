---
id: "osint-leak-intel"
title: "泄露情报与密钥扫描（L2 泄露面数据源手册 · HIBP/GitHub dork/gitleaks/测绘）"
tags: "osint,泄露,密钥,hibp,gitleaks,dork,s2,s4,网盘,邮箱格式,shodan"
---
# 泄露情报与密钥扫描（identity-bootstrapping L2 轨的数据源手册）

> 定位：L2 轨的**可执行落地层**——无凭证项目把「泄露面」从口号变成数据源逐个查。全部被动查询（L0），
> 不触碰目标；查到的凭据只做**授权面单次存在性验证**（identity-bootstrapping 第四节口径）。

## 一、泄露口令预筛（HIBP Pwned Passwords range API · 免 key）

```bash
# k-匿名：口令 SHA-1 前 5 位查询，本地比对后缀（口令明文不出本机）
sha1=$(printf '%s' '候选口令' | tr -d '\n' | sha1sum | cut -c1-40 | tr 'a-f' 'A-F')
curl -s -m 10 "https://api.pwnedpasswords.com/range/${sha1:0:5}" | grep -i "^${sha1:5}" | cut -d: -f2
# 输出>0 = 该口令在真实泄露库出现过 → 默认口令/字典候选排序依据（weak-cred-bruteforce 联动）
```

- 用途：①默认口令矩阵候选预筛（真实泄露过的优先试）；②命中口令的「已泄露凭据」定性佐证。
- **邮箱/账号维度**查询（`/api/v3/breachedaccount/`）需 $HIBP_KEY（付费 API）：未配置 → **如实登记环境限制**（record_timeline），禁止反复重试。

## 二、GitHub/代码托管 dork（$GITHUB_TOKEN 或免认证通道）

```bash
# 有 token（推荐，配额 30 次/分）：
curl -s -m 15 -H "Authorization: token $GITHUB_TOKEN" \
  "https://api.github.com/search/code?q=%22目标域名%22+password&per_page=20" | jq -r '.items[]|"\(.repository.full_name) \(.path)"' | head
# 无 token 兜底：grep.app（scopeGate 白名单内）Web 查询目标域名/组织名；GitDorker + dorks.txt 走 token 批量
```

- dork 词序：`"目标域名" password|secret|jdbc|smtp|LTAI|AKID` → `"组织名" in:file jdbc:mysql` → 目标 APP 名+conf/env；
- 命中仓库只看**目标相关的**凭据/配置；第三方无关代码不下载不展开（范围纪律）。

## 三、通用 OSINT 情报面（v6.2.0 补全：网盘与文档泄露 / 招聘与技术博客 / 组织架构与邮箱格式）

> 承载 heads/s2.md S2-2 的其余三个子项（代码库泄露见第二/四节）。全部被动查询（L0），只提交目标标识、不触碰目标；无数据源/无凭据时写明「未查询及原因」，不以查询失败断言不存在。产出并入《泄露与情报报告》（deliverables/s2-泄露与情报报告.md）。

### 3.1 网盘与文档泄露（通用 dork 模板矩阵）

```bash
# 搜索引擎 dork 模板（Google/Bing 双引擎；<org>=组织名/域名/系统名，逐个替换组合）
"<目标域名>" filetype:(pdf|doc|docx|xls|xlsx|ppt|pptx|csv|sql|conf|ini|bak|env)
"<组织名>" (intitle:"index of" | inurl:backup | inurl:dump | inurl:data)
"<系统名>" (site:wenku.baidu.com | site:docin.com | site:slideshare.net | site:scribd.com)
"<组织名>" (site:github.com | site:gitee.com) filetype:(env|ini|yaml|yml|properties) password
"<系统名>" 操作手册 OR 运维手册 OR 初始密码          # 默认口令/部署文档线索
```

- 命中文档只记录标题/摘要/来源 URL（第三方无关文件不下载不展开——范围纪律）；目标相关文档存入 evidence/ 并进第四节本地密钥扫描流程。

### 3.2 招聘与技术博客

- 招聘 JD：技术栈要求、安全设备型号（WAF/EDR/VPN 厂商）、岗位规模 → behavior_class 预判与 S3 测试计划输入；
- 技术博客/公众号：架构演进、上云/上 WAF 时间线、基建选型 → 组织画像；命中密钥/内网域名线索进第四节扫描。

### 3.3 组织架构与邮箱格式

- 官网「团队/关于」页 + 第三方名录：部门设置、负责人角色 → 组织架构图（报告「信息收集」章素材）；
- 邮箱格式推导：常见 pattern 逐一登记（`{f}@`、`{l}@`、`{f}.{l}@`、`{f}{l}@`、`{fi}.{l}@`）；hunter.io 免费额度可查域名关联邮箱与置信度（有 Key 用 Key）；
- 用途：S4 W4-L2 泄露面用户名候选集 + weak-cred-bruteforce 字典排序输入（SMTP 存在性验证属 S4 动作，本节只推导登记）。

## 四、本地密钥扫描（拿到 .git/源码/配置包后必做）

```bash
# 首选工具（可安装则用）：
gitleaks detect --source evidence/leaked-src --report evidence/gitleaks.json 2>/dev/null || \
trufflehog filesystem evidence/leaked-src --json 2>/dev/null | head -40
# 兜底正则清单（无工具时 grep 等价执行，模式库与 gitleaks 默认规则对齐）：
grep -rEni "(LTAI[A-Za-z0-9]{12,}|AKID[A-Za-z0-9]{16,}|ghp_[A-Za-z0-9]{36}|sk-[A-Za-z0-9]{20,}|xox[bap]-[A-Za-z0-9-]{10,}|BEGIN (RSA|EC|OPENSSH) PRIVATE KEY|jdbc:(mysql|postgresql|sqlserver)://[^\"]+:[^@\"@]+@|smtp\.[a-z]+\.[a-z]{2,3}[^0-9]{0,30}[0-9]{4,16}|secret[_-]?key[\"']?\s*[:=]\s*[\"'][A-Za-z0-9+/=_-]{16,})" evidence/leaked-src/ 2>/dev/null | head -30
```

- 命中 → 密钥**逐个核对可达性**（键存在≠可用：带 key 的无害只读 API 单次调用判据，identity-bootstrapping L2-1 口径）；
- record_loot 只登记掩码摘要（前 4 位+长度+类型），**明文不落库不外传**。

## 五、空间测绘五平台（被动测绘，scopeGate 白名单已放行）

| 平台 | Host | Key 环境变量 | 用法 |
|---|---|---|---|
| Quake | quake.360.net | $QUAKE_KEY | recon-playbook 空间测绘节（IP 视角/资产视角） |
| FOFA | fofa.info | $FOFA_EMAIL+$FOFA_KEY | `https://fofa.info/api/v1/search/all?email=&key=&qbase64=<base64(查询)>` |
| ZoomEye | zoomeye.org | $ZOOMEYE_KEY | `https://api.zoomeye.org/host/search?query=<ip>` |
| Hunter | hunter.qianxin.com | $HUNTER_KEY | `https://hunter.qianxin.com/openApi/search?api-key=&search=<base64>` |
| Shodan | shodan.io | $SHODAN_KEY | `curl -s "https://api.shodan.io/shodan/host/<目标IP>?key=$SHODAN_KEY"`（历史端口/服务/banner）；网段视角 `query=net:<CIDR>`；域名反查 `https://api.shodan.io/dns/domain/<域>?key=$SHODAN_KEY` |

- 用途统一：IP 历史端口/历史指纹/关联网域**漏报复核**（recon-playbook 全端口扫描的第四段旁证）；
- 纪律：①查询结果只作线索，关键结论本机复核后才能登记确证；②免费 Tier 限速（查询间 sleep 2-3s）；③无 Key 平台跳过并登记，**不重试**；④同段旁站仅记录线索，禁止越界测试。

## 六、泄露库撞库边界（硬约束）

- 拿到「邮箱-口令对」只对**授权范围内登录口**做单次验证（identity-bootstrapping 第四节：不撞库）；
- breached-password 批量字典用途见 weak-cred-bruteforce 字典类目（ROE 额度制）；
- 第三方查询提交的内容仅限**目标标识**（域名/IP/组织名），禁止上传目标数据。

## 七、产出对接

- 命中凭据/密钥：record_loot（掩码）+ record_finding（信息泄露类，引用来源 URL+命中判据）；
- 环境限制（无 key/无源）：record_timeline 如实登记——**该轨"查过但源不可用"≠"该轨已排除"**，S8 报告盲区章注明；
- update_coverage(vuln_class=泄露面，notes 记 `sources_checked/sources_available`)。

## v4.8 M6 工具通道兼容性声明

- api.pwnedpasswords.com/fofa.info/zoomeye.org/hunter.qianxin.com/virustotal.com/shodan.io/censys.io：v5.3.9 起在 scopeGate 默认白名单（orchestrator.go defaultScopeAllowlist）——strict_scope 项目直连可用，无需走 $TOOL_PROXY；
- 上述源查询是**对第三方 API 的读请求**，不属于对目标发包——若仍被护栏拦截，登记环境限制并改 grep.app 兜底，禁止绕护栏。
