---
id: parallel-execution
title: 并行与后台执行手册（长任务后台化 · 单命令并行 · 超时预算）
tags: 并行,后台,异步,超时,速度,s2,s4,s5
---
# 并行与后台执行手册（速度纪律 #1/#3 载体）

核心原则：**流水线一次只推进一条命令，任何 >10 分钟的命令都必须后台化**——同步死等会让整个项目停摆（实测一条全词表枚举阻塞流水线 2 小时）。

## 一、长任务后台化

### 1. 首选：引擎异步工具（v2.6+ 引擎提供时优先用）

```json
// ① 启动后台任务（立即返回 job id，不阻塞对话）
run_async {"command": "nmap -Pn -p- -sV --max-rate 200 192.0.2.10 -oN .async/fullport.txt", "timeout": 3600}
// ② 每隔几轮收一次结果（返回 running/finished + 增量输出尾部）
poll_async {"job": "<job_id>"}
```

### 2. 兜底：nohup 约定（任何引擎版本都可用）

```bash
# ① 启动（秒回）：输出必须落到 .async/ 目录，文件名带用途
mkdir -p .async && nohup gobuster dir -u https://target/ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-files.txt \
  -t 5 --timeout 15s -q --no-error -o .async/dirscan.log 2>&1 & echo "BG_PID $!"
# ② 收结果（每次动作间隙顺手看一眼）
tail -30 .async/dirscan.log
# ③ 判存活：kill -0 <PID> 2>/dev/null && echo running || echo finished
# ④ 收口前必须终止：kill -- -<PID> 2>/dev/null（进程组）或 pkill -f gobuster
```

### 3. 纪律

- 后台任务启动即 `record_timeline`（任务/PID/日志路径），收口前逐个确认已结束——**残留进程会在任务结束后继续打目标，属合规事故**。
- 收结果只 `tail`，不反复全量读；日志文件统一放 `.async/`。
- 熔断/阶段失败时优先清理后台任务再继续。

## 二、单命令内并行

相互独立的动作合并一条命令并行跑（引擎每项目并发闸默认 4，单命令内并行不占多个闸位）：

```bash
# 三个独立侦察面一次跑完，各自落文件，最后汇总——总耗时≈最慢的那个
( nmap -Pn --top-ports 1000 -T3 --max-rate 200 -oN .async/nmap-t1.txt 10.0.0.5 & \
  httpx -l .async/alive.txt -title -tech-detect -o .async/httpx.txt & \
  whatweb -a1 https://target/ > .async/whatweb.txt 2>&1 & wait )
echo "=== 汇总 ==="; head -5 .async/nmap-t1.txt .async/httpx.txt .async/whatweb.txt
```

- 输出交错会毁掉分析：**并行体各自 `-o` 落文件**，最后统一读。
- 有依赖关系（先存活后扫描）不并行；同目标高强度扫描不叠加并发（限速优先于速度）。

## 三、超时预算

- 每条 `run_command` 显式带 timeout：快扫 ≤300s、单点验证 ≤120s、深扫一律后台化（run_async timeout 可到 3600s）。
- 易挂命令用 `timeout 60 <cmd>` 双保险（目标 50% 超时场景，curl 必带 `-m 25`）。
- 见到「命令超时（Ns）」返回：改后台化或降规模重试，**禁止同参数原样重跑**。

## 四、产出纪律

- 后台化/并行属执行方式，结论仍按标准留证（证据链自动记录 run_async/命令原文）。
- 深扫结果落地后按 scan-tiering 手册推进分析，不因"已启动深扫"而停止其他测试。

## v4.8 M6 工具通道兼容性声明

> 口径（loop-core v4.8 纪律 3）：先 probe 后 batch——每个外部工具对目标首次使用前先用小样本探针确认可用性，探针被拦/挂起先切适配通道再批量；探针结果写入交付物工具声明小节。各工具在「挑战型 WAF / 封闭站」下的可用性与适配通道：

- nmap：传输层扫描与应用层挑战无关——挑战型 WAF 下可用；封闭站/网关白名单外端口可能全 filtered——先 probe（top100 快扫）确认端口可达性再批量，必要时 --max-rate 限速防封锁。
- httpx：JS 挑战下标题/状态码/长度全部来自挑战页（批量假阴性）——先 probe 1 个请求核对响应真实性；适配通道：channel-snapshot 提取 cookie/UA 后 curl -b 复放，或建立会话后注入态再批。
- whatweb：JS 挑战型目标返回的是挑战页指纹（假阴性「无指纹」）——先 probe 单目标核对返回是否挑战页；适配通道：channel-snapshot 快照态（cookie+UA）复放或 browser-auth 会话建立后重跑。
- gobuster：同 ffuf（挑战页统一指纹掩盖差异）——先 probe；适配通道：会话态注入或降速。
