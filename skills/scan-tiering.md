---
id: scan-tiering
title: 分级扫描与重试纪律（T1 快扫先行 · T2 深扫后台 · 退避重试）
tags: 分级,快扫,深扫,重试,退避,ffuf,速度,s2,s4
---
# 分级扫描与重试纪律（速度纪律 #2/#4 载体）

核心原则：**先出初步攻击面，再深挖**——T1 快扫 10 分钟内给出可用结论，T2 深扫后台跑，两者不互相等待。

## 一、T1 快扫（同步、限 10 分钟、目标=立刻可分析）

```bash
mkdir -p .async
# 端口：top1000 快速摸底（全端口留给 T2）
nmap -Pn --top-ports 1000 -T3 --max-rate 200 --open -oN .async/nmap-t1.txt <目标>
# Web 存活+指纹（一次拿到 title/tech/状态码）
httpx -u https://<目标>/ -title -tech-detect -status-code -follow-redirects -timeout 10
# 目录：短词表 + ffuf（auto-calibration 自动过滤噪声，比全词表 gobuster 快一个量级）
ffuf -u https://<目标>/FUZZ -w /usr/share/seclists/Discovery/Web-Content/common.txt \
  -mc all -fc 404 -t 10 -rate 100 -timeout 8 -o .async/ffuf-t1.json -of json
```

T1 产物立即用于：指纹→已知漏洞检索（cve-weaponization）、攻击面登记、S3/S4 排期——**不等 T2**。

## 二、T2 深扫（后台，按 parallel-execution 手册启动）

```bash
# 全端口 + 版本识别：后台 30-60 分钟级
run_async {"command": "nmap -Pn -p- -sV --max-rate 300 -oN .async/nmap-full.txt <目标>", "timeout": 5400}
# 大词表目录、nuclei 全模板组：同样后台
run_async {"command": "ffuf -u https://<目标>/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-files.txt -mc all -fc 404 -t 8 -rate 80 -o .async/ffuf-t2.json -of json", "timeout": 3600}
```

T2 结果落地后：与 T1 diff（新增端口/路径→补登记、补测试），结论照常入库。

## 三、重试纪律（退避封装，禁止无脑重试）

```bash
# 统一退避重试：最多 3 次、指数退避；成功即返回，全失败输出 FAILED（不再第 4 次）
t(){ desc="$1"; shift; for i in 1 2 3; do
      r=$(timeout 30 curl -4 -sS -m 25 --compressed -o /tmp/r.out -w "%{http_code}|%{size_download}" "$@" 2>/dev/null)
      c="${r%%|*}"; [ -n "$c" ] && [ "$c" != "000" ] && { echo "$desc try$i -> $r"; return; }
      sleep $((i*i)); done; echo "$desc -> FAILED(3次)"; }
t "主站" "https://<目标>/"
```

- 同类确认命令（存活确认/端口复核）**全项目最多一轮退避重试**；已确认过的结论直接引用，禁止重复提交（引擎护栏会触发导师评审）。
- 连续失败 → `update_coverage(waf_blocked 或 premise_failed)` 并换路径，不硬磕。

## 四、工具选择

| 场景 | 首选 | 替代 |
|---|---|---|
| 目录/文件枚举 | ffuf（-fc 过滤+auto-calibration） | gobuster（仅快扫短词表） |
| 参数挖掘 | arjun | 手工猜测 |
| 存活批量 | httpx | curl 循环 |
| 端口 | nmap（T1 top1000 / T2 -p-） | masscan（仅超大面积，限速） |

## 五、纪律

- 限速永远优先于速度：ROE 窗口内、`-rate`/`-t` 保守设置；目标已有 50% 超时迹象时降并发不升并发。
- 扫描分级不降低覆盖要求：T1+T2 合计仍须过完对应 skill 检查项才能 ruled_out（深度基线不变）。

## 六、噪声感知探测协议（v3.8.9，判定质量基线）

实测教训：目标存在**间歇性空响应/动态丢包**（S2 已确认该行为）时，探测判定被噪声污染——空响应被当无漏洞、时延抖动被当命中。所有探测判定执行以下协议（写进证据留痕）：

1. **空响应即重试**：`CODE=000`/空 body/连接重置 → 一律视为**不可判定**，按第三节退避函数重试 ≥2 次；重试后仍失败标 `inconclusive` 并 update_coverage（notes 注明「3 次均空响应」），**禁止以单次空响应下「不存在」结论**。
2. **时延类判定三重测**：sleep/延时盲注类判定 = **载荷 3 次 + 对照 2 次 + 阈值标定 1 次**取中位数——载荷中位数比对照中位数多 ≥2s 才算命中；单次超时（如一次 4.3s）不算证据，必须复测收敛。
3. **对照先行**：判定前先取对照基线（无载荷同参数请求），目标响应天然慢（>2s）时改用差值判据（载荷-基线 ≥2s）并在 notes 记录两组数值。
4. **成功信号必须归档**：任何判定为命中/可疑的探测结果，立即 record_finding 或 update_coverage（notes 引用证据文件名）——引擎 G1 门按 evidence/ 文件名归账，孤儿结果拦截收口。
5. **批量探测限速**：批量基线/探测命令必须带间隔（`--delay`/循环 `sleep 0.4`+），高速批量会触发目标动态丢弃（实测：全端口扫描期间 80 端口 HTTP 正常但 nmap 报 filtered）。

## v4.8 M6 工具通道兼容性声明

> 口径（loop-core v4.8 纪律 3）：先 probe 后 batch——每个外部工具对目标首次使用前先用小样本探针确认可用性，探针被拦/挂起先切适配通道再批量；探针结果写入交付物工具声明小节。各工具在「挑战型 WAF / 封闭站」下的可用性与适配通道：

- nmap：传输层扫描与应用层挑战无关——挑战型 WAF 下可用；封闭站/网关白名单外端口可能全 filtered——先 probe（top100 快扫）确认端口可达性再批量，必要时 --max-rate 限速防封锁。
- masscan：传输层扫描不受应用层挑战影响；封闭站上游丢包表现为全无响应——先 probe 少量已知开放端口验证通道，必要时 --rate 限速防上游封锁。
- httpx：JS 挑战下标题/状态码/长度全部来自挑战页（批量假阴性）——先 probe 1 个请求核对响应真实性；适配通道：channel-snapshot 提取 cookie/UA 后 curl -b 复放，或建立会话后注入态再批。
- nuclei：模板请求无浏览器指纹，JS 挑战下全 miss（假阴性）——先 probe 单模板×单 URL 核对；适配通道：channel-snapshot 提取会话态后以 -H/-cookies 传参小批量跑，或改浏览器代理。
- arjun：挑战态未注入时批量请求全失败/全 000（假阴性）——先 probe 2-3 个已知参数验证通道可用；适配通道：browser 会话取 cookie/挑战头注入后重跑，仍拦截则 -t 1 降并发或改 CDP 流量代打。
- ffuf：挑战页统一指纹会掩盖响应长度差异（假阴性）——先 probe 2 个请求人工核对差异真实性；适配通道：会话态 cookie/UA 注入后跑；封闭站签名校验目标改浏览器代理。
- gobuster：同 ffuf（挑战页统一指纹掩盖差异）——先 probe；适配通道：会话态注入或降速。
