---
id: project-warmup
title: 项目开工预热清单（工具预检 · 模板/词表 · OOB 回连自检）
tags: 预热,开工,工具预检,oob,回连,词表,s1,s2
---
# 项目开工预热清单（速度纪律 #5 载体）

核心原则：**开工第一轮一条并行命令完成全部预检**——执行中途不被安装/下载打断（实测 install_tool 单次最多 300s×3 策略，触发即分钟级停顿）。

## 一、预热命令（一条并行跑完，≤2 分钟）

```bash
mkdir -p .async
( echo "=== 工具预检 ==="; for t in nmap gobuster ffuf nuclei httpx whatweb dig whois curl sqlmap jq python3 arjun interactsh-client; do \
    command -v $t >/dev/null 2>&1 || echo "MISSING $t"; done; \
  echo "=== nuclei 模板 ==="; [ -d ~/nuclei-templates/http ] && echo TEMPLATES_OK || echo "NO_TEMPLATES"; \
  echo "=== 词表 ==="; ls /usr/share/seclists/Discovery/Web-Content/common.txt 2>/dev/null || echo "NO_SECLISTS"; \
  echo "=== 语料资产 ==="; ls -d /opt/tools/PayloadsAllTheThings >/dev/null 2>&1 && echo PAT_OK || echo "NO_PAT"; \
  ls /opt/tools/wordlists/403-bypass-paths.txt /opt/tools/wordlists/403-bypass-headers.txt /opt/tools/wordlists/ssti-matrix.txt >/dev/null 2>&1 && echo DICTS_OK || echo "NO_DICTS"; \
  echo "=== OOB 自检 ==="; timeout 20 curl -s -o /dev/null -w "oast:%{http_code}" https://oast.pro 2>/dev/null || echo "oast:FAIL" ) \
  2>&1 | tee .async/warmup.txt
```

## 二、按预检结果补齐（集中处理，不逐个补）

1. **缺工具**：对 MISSING 项逐个 install_tool（apt 优先）；一次补完再开工，禁止测到一半再补。
2. **缺模板**：`run_async {"command":"nuclei -update-templates","timeout":600}` 后台下载，期间先做被动侦察。
3. **缺词表**：`install_tool seclists`（apt）或 `env http_proxy=$TOOL_PROXY https_proxy=$TOOL_PROXY git clone --depth 1 https://github.com/danielmiessler/SecLists /opt/tools/seclists`。
4. **无 arjun/interactsh-client**：`install_tool arjun`；interactsh-client 由 apt `interactsh-client` 或 go 安装；都不可用则记入交付物限制（OOB 走公网平台兜底，见下）。
5. **缺语料（PAT/curated 字典）**：PAT 缺失 → `run_async {"command":"env http_proxy=$TOOL_PROXY https_proxy=$TOOL_PROXY git clone --depth 1 https://github.com/swisskyrepo/PayloadsAllTheThings /opt/tools/PayloadsAllTheThings","timeout":600}` 后台补装（期间先做被动侦察），仍失败则记入交付物限制并改用 seclists + web 检索；curated 字典缺失 → 用 load_skill payload-mutation-algebra §7 的表现场构造（不阻塞开工）。语料用法：403 两份字典配合 payload-mutation-algebra §7（路径族×头族组合）；SSTI 矩阵配合 ssti-engine-map。

## 三、OOB 回连通道（开工定死，全程统一）

- **一级（默认）本机反链**：后台启动 `nohup interactsh-client > .async/oob.log 2>&1 & echo "OOB_PID $!"`，从 `.async/oob.log` 取回连域名（形如 `xxxx.oast.pro`）写入交付物；容器与目标同网段时可改用本地监听地址（`nc -lvnp 4444`/HTTP 接收器）。
- **二级（兜底）公网平台**：本机通道自检失败（无回连域名/目标不可达）才用 dnslog.cn、ceye.io 等；**只做存在性证明，不投递敏感 payload**；切换通道必须在证据中注明原因。
- 同一测试单元通道固定；回连域名与交互记录 = 盲注类验证的证据。

## 四、登记

- 预热结果（工具缺失/补齐情况、回连域名、模板/词表状态）写入本阶段交付物「环境就绪清单」+ `record_timeline` 一条事件。
- 预热发现的环境限制（如 OOB 仅公网兜底）如实写交付物，不许静默降级。

## v4.8 M6 工具通道兼容性声明

> 口径（loop-core v4.8 纪律 3）：先 probe 后 batch——每个外部工具对目标首次使用前先用小样本探针确认可用性，探针被拦/挂起先切适配通道再批量；探针结果写入交付物工具声明小节。各工具在「挑战型 WAF / 封闭站」下的可用性与适配通道：

- nmap：传输层扫描与应用层挑战无关——挑战型 WAF 下可用；封闭站/网关白名单外端口可能全 filtered——先 probe（top100 快扫）确认端口可达性再批量，必要时 --max-rate 限速防封锁。
- httpx：JS 挑战下标题/状态码/长度全部来自挑战页（批量假阴性）——先 probe 1 个请求核对响应真实性；适配通道：channel-snapshot 提取 cookie/UA 后 curl -b 复放，或建立会话后注入态再批。
- whatweb：JS 挑战型目标返回的是挑战页指纹（假阴性「无指纹」）——先 probe 单目标核对返回是否挑战页；适配通道：channel-snapshot 快照态（cookie+UA）复放或 browser-auth 会话建立后重跑。
- nuclei：模板请求无浏览器指纹，JS 挑战下全 miss（假阴性）——先 probe 单模板×单 URL 核对；适配通道：channel-snapshot 提取会话态后以 -H/-cookies 传参小批量跑，或改浏览器代理。
- arjun：挑战态未注入时批量请求全失败/全 000（假阴性）——先 probe 2-3 个已知参数验证通道可用；适配通道：browser 会话取 cookie/挑战头注入后重跑，仍拦截则 -t 1 降并发或改 CDP 流量代打。
- ffuf：挑战页统一指纹会掩盖响应长度差异（假阴性）——先 probe 2 个请求人工核对差异真实性；适配通道：会话态 cookie/UA 注入后跑；封闭站签名校验目标改浏览器代理。
- gobuster：同 ffuf（挑战页统一指纹掩盖差异）——先 probe；适配通道：会话态注入或降速。
- sqlmap：注入流量无会话态会被挑战型 WAF 拦截（假阴性）——先 probe（--level 1 单参数）确认可达；适配通道：挑战态 cookie/UA 注入（--cookie/--headers），或经注入通道（mitmproxy↔CDP 上游代理链）带挑战态运行。
- interactsh-client：OOB 回连出站不受目标 WAF 影响；封闭站限制的是目标侧外联回连——本机反链自检先行（loop-core 深度测试纪律 5）。
