---
id: "tool-channels"
title: "工具通道兼容性单源（M6 判据单一事实源，各技能按需引用）"
tags: "工具,M6,通道,挑战型waf,封闭站,先probe后batch,s2,s4"
---
# 工具通道兼容性单源（v5.1：M6 判据单一事实源）

> 目的：M6 声明曾整段复制 7+ 文件且内容漂移（版本演进时必漏改）。本文件是**全工具矩阵单一来源**；
> 各技能的 M6 节只保留「本技能专属工具差异 + 引用本文件」，不再内联通用判据。
> 总口径（loop-core v4.8 纪律 3）：先 probe 后 batch——每个外部工具对目标首次使用前用 1-2 请求小样本
> 确认可用性，探针被拦/挂起先切适配通道再批量；探针结果写入交付物工具声明小节。

## 一、Web/扫描类

| 工具 | 挑战型 WAF 下 | 封闭站/网关白名单 | 适配通道 |
|---|---|---|---|
| nmap | 可用（传输层与应用层挑战无关） | 白名单外端口全 filtered——先 top100 probe | --max-rate 限速防封锁 |
| httpx/whatweb | **假阴性**（返回挑战页指纹） | 可用 | channel-snapshot 快照态复放 |
| nuclei | **全 miss**（模板无浏览器指纹） | 可用（限速） | 快照态 -H/-cookies 小批量 |
| arjun/ffuf/gobuster/dirsearch | 批量 000 假阴性 | 可用 | 降并发+probe 先行；封闭站改浏览器通道 |
| sqlmap | 无会话态被拦（假阴性） | 可用 | chain-proxy 上游代理链带挑战态 |
| curl | 低频手工始终可用（**禁大批量枚举**） | 始终可用 | 挑战态复放最小工具 |

## 二、浏览器/会话类（browser-kit，/opt/venv/bin/python）

| 工具 | 用途 | 可用性 |
|---|---|---|
| channel-snapshot.py | 挑战态提取/复放（IP+UA+cookie 三维绑定） | 挑战型目标适配通道本体，始终可用 |
| channel-heartbeat.py | 通道心跳（K5） | 同上 |
| browser_login.py / browser_oracle.py | 合规登录/凭据预言机 | JS 挑战/验证码面主通道 |
| exit-pool.py / browser-farm.py | 出口池/指纹池化 | 配置驱动，标准件零代理资源 |

## 三、内网/AD 工具链（S5/S6 消费，进入条件=已获立足点）

| 工具 | 挑战型/受限通道下 | 说明 |
|---|---|---|
| ldapsearch/smbclient/rpcclient | 低频手工查询始终可用 | 内网无应用层挑战；受网络层 ACL 限 |
| netexec/certipy/Impacket 系列 | 可用（内网直连） | 走隧道时注意双层限速（隧道×目标两端） |
| fscan/内网批量扫描 | **先 probe 后 batch 更严**（内网 IDS/蜜罐面） | 频率红线：内网封锁同样触发熔断 |
| frp/chisel/icmp 隧道 | 按 ROE `outbound` 配置门控 | reverse 连接需出口可达性预检（probe） |

## 四、离线/零流量类

searchsploit（本地库）/ hashcat（ROE 额度）/ openssl/jq/python3 数据处理 / sourcemap 还原 / subdomain-takeover.py（纯 DNS）——**无目标流量，始终可用**，且优先于任何在线探测（窗口 0 零流量纪律）。

## 五、引用规范

- 各技能 M6 节书写格式：`> 通用判据以 tool-channels.md 为准；本技能差异：<仅列本技能特有工具的可用性与适配通道>`；
- 新增外部工具时**先在本文件登记矩阵行**，再在技能 M6 节写差异——禁止两处独立维护。
