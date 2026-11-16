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
# 接口路径提取：LinkFinder（pip）或 grep 正则
python3 /opt/tools/LinkFinder/linkfinder.py -i https://目标/ -d -o cli 2>/dev/null | head -30
# 兜底正则：url: "..." / baseURL / fetch( / axios. / api/ 前缀
grep -ohE '"/?api/[a-zA-Z0-9_/-]+"' evidence/*.js 2>/dev/null | sort -u | head -30
# 密钥/敏感注释：AK/SK、token、内网域名、jira/禅道链接
grep -ohiE '(access[_-]?key|secret[_-]?key|appkey)["\x27]?\s*[:=]\s*["\x27][a-z0-9]{8,}' evidence/*.js 2>/dev/null | sort -u
```

## 产出对接
- source map 残留：record_finding（中/低，cwe=CWE-540）+ 恢复源码入 evidence/
- 依赖 CVE：cve-weaponization 流程；密钥泄露：record_finding（高/中）+ 只登记指纹不外传
