---
id: frontend-sca
title: 前端与依赖漏洞手册（JS 依赖 SCA · source map · bundle 情报）
tags: 前端,依赖,retire.js,sourcemap,s2,s4
---
# 前端与依赖漏洞（SCA + JS 情报）

## 一、JS 依赖漏洞（SCA）

```bash
# 从页面/JS 提取依赖特征（版本号常在注释/全局变量/文件名里）
grep -roE "(jquery|bootstrap|vue|react|layui|echarts)[@/-][0-9]+\.[0-9]+[^\"']*" evidence/*.html evidence/*.js 2>/dev/null | sort -u | head -20
# 或用 retire.js（pip/npm 安装后）
retire --js evidence/*.js --path . --outputformat json 2>/dev/null | jq -r '.[].results[].component' 2>/dev/null | head
# 命中依赖版本 → cve-weaponization 检索对应 CVE（XSS/原型污染类居多）
```

## 二、source map 残留（本身即发现）

```bash
# 检测：js 文件尾行 //# sourceMappingURL= 或直接请求 .map
for js in $(grep -roE 'src="[^"]+\.js[^"]*"' evidence/*.html | cut -d'"' -f2 | sort -u | head -10); do
  url=$(case "$js" in http*) echo "$js"; ;; /*) echo "https://目标$js"; ;; *) echo "https://目标/$js";; esac)
  curl -sk -o /dev/null -w "$url.map %{http_code}\n" "$url.map"
done
# 命中 200 → 下载 .map → 恢复源码目录结构（unmap/source-map-explorer）→ 审计源码内密钥/接口/注释
```

## 三、bundle 情报提取（S2-7 的深化）

```bash
# 接口路径提取：grep 正则为主（零安装依赖）；LinkFinder 可选增强（pip 装成功能用，缺省直接走下方 grep）
command -v linkfinder >/dev/null 2>&1 && python3 $(command -v linkfinder) -i https://目标/ -d -o cli 2>/dev/null | head -30 || echo "MISSING linkfinder，走 grep 兜底"
# 兜底正则：url: "..." / baseURL / fetch( / axios. / api/ 前缀
grep -ohE '"/?api/[a-zA-Z0-9_/-]+"' evidence/*.js 2>/dev/null | sort -u | head -30
# 密钥/敏感注释：AK/SK、token、内网域名、jira/禅道链接
grep -ohiE '(access[_-]?key|secret[_-]?key|appkey)["\x27]?\s*[:=]\s*["\x27][a-z0-9]{8,}' evidence/*.js 2>/dev/null | sort -u
```

## 四、第三方 JS 与 SRI 完整性（v5.3.9 增补——客户端供应链面）

```bash
# 1) 外域 script/link 清单（页面+bundle 引用）
grep -ohE '<script[^>]+src="https?://[^/"]+' evidence/*.html | sed 's/.*src="//' | sort -u
grep -ohE '(src|href)="https?://(?!目标域)[^"]+\.(js|css)' -P evidence/*.html 2>/dev/null | sort -u
# 2) SRI 完整性属性核对（integrity= 缺失的第三方 JS = 供应链劫持面）
grep -oE '<script[^>]+>' evidence/*.html | grep -v "integrity=" | grep -E 'https?://' | head
# 3) 第三方域定性：统计/广告/字体/CDN 分类；关键业务 JS 走自控域还是公共 CDN
```

| 观测 | 判定 | 处置 |
|---|---|---|
| 第三方关键业务 JS（支付/加密/上报）无 integrity 属性 | **SRI 缺失**——CDN 被劫持/缓存投毒可注入恶意 JS 到所有患者页面 | record_finding（低-中，cwe-353/CWE-829）+ report-writing 修复建议（加 SRI 或自托管） |
| 第三方 JS 域已失托/解析异常 | 死链第三方引用 | 信息级登记 |
| 目标页面内联引用第三方统计 SDK 收集数据 | 第三方数据流线索 | 移交客户核实合同边界（radinfo 类供应商面同口径） |

- 纪律：**只做缺失性与引用关系定性，不投毒不篡改验证**（供应链攻击验证属破坏性动作，ROE 禁）；第三方域清单与 s1 子域台账同库登记。

## 产出对接
- source map 残留：record_finding（中/低，cwe=CWE-540）+ 恢复源码入 evidence/
- 依赖 CVE：cve-weaponization 流程；密钥泄露：record_finding（高/中）+ 只登记指纹不外传
- SRI/第三方 JS：record_finding（低-中）+ 第三方域清单并入资产台账（record_asset）
