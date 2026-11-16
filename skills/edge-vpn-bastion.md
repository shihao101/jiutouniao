---
id: edge-vpn-bastion
title: 边界设备 / SSL VPN / 堡垒机打点（国内授权测试第一入口）
tags: 边界设备,VPN,堡垒机,JumpServer,指纹,CVE,s2,s4,s5
---
# 边界设备 / SSL VPN / 堡垒机打点

**定位**：授权测试中最常见的"第一跳"——SSL VPN 网关、防火墙管理面、堡垒机暴露在互联网侧，版本漏洞密度高、突破即通内网。指纹识别在 S2，本剧本承接"指纹 → CVE 检索 → 判据验证 → 转 S5 利用"。

## 一、指纹速查（S2-8 版本预检索输入）

| 设备 | 指纹特征 |
|---|---|
| SSL VPN（国内主流厂商：深信服/网神/山石/启明星辰等） | 登录页 `/por/login_psw.csp`、`/login` 特征路径、favicon 哈希、`Server` 头、JS 资源名（如 sangfor/某厂商拼音） |
| 华为 USG/HiSec | 登录页 `/login.html`+华为 logo 资源、`webserver` 头特征、`NGFW` 字样 |
| H3C SecPath | `/webpages/login.html`、`SecPath` 页脚标识 |
| 网康 NetentSec/奇安信 NGAF | `/vpn/` 路径族、`nsfocus` 资源名、奇安信页脚 |
| 安恒明御（WAF/堡垒机） | `明御` 页脚/`dbapp` 资源名、WAF 拦截页特征 |
| FortiGate（飞塔） | `/remote/login`、`fgt_lang` 资源 |
| Ivanti/Pulse Connect | `/dana-na/` 路径族、`dsid` cookie |
| Citrix Gateway | `/logon/LogonPoint/`、`ns_cvpn` |
| Zyxel/其他防火墙 | `/UserLogin` 系、设备 model 字符串 |
| 堡垒机 JumpServer | Nginx + `/api/v1/` 特征、`luna/` 前端、`koko` 组件名、登录页"JumpServer"字样 |
| 堡垒机（齐治/帕拉迪等商用） | 登录页厂商标识、`/audit/` 会话审计路径 |

**动作**：指纹 → `whatweb`/favicon hash 确认版本 → 版本号进 cve-weaponization 三通道检索（searchsploit/NVD/官方安全通告）。**版本号常藏在 `/static/js/app.*.js`、登录页 HTML 注释、favicon**。

## 二、高危判据族（按家族套用）

1. **任意文件读取**：路径穿越参数（`?fileName=../../../../etc/passwd` 类）——SSL VPN 历史高频洞型；命中 `/etc/passwd` 后直取配置文件（`/etc/xxxvpn/xxx.conf`、web.xml）→ 数据库/管理凭据（record_loot）。
2. **未认证 RCE**：设备管理接口的命令注入（ping 诊断页、日志导出参数）——判据 OOB 回连（oob-interactsh）优先。
3. **SSRF → 云元数据/内网**：设备常部署在 DMZ，SSRF 打内网探测（ssrf-deep 套用）+ 元数据 IMDSv1。
4. **认证绕过**：管理面 cookie/签名缺陷、默认/弱管理口令（weak-cred-bruteforce，限速）；VPN 多因子降级（只猜主口令面）。
5. **信息泄露**：`/api/` 未授权版本接口、日志目录可列、备份文件（source-backup 思路）。

## 三、堡垒机专项（突破=内网全景图）

- **价值判断**：堡垒机汇聚全部特权账号与内网资产映射——突破后优先导出**资产清单与授权账号列表**（存在性证明口径），这是影响证明的最强形态之一。
- **判据**：历史 CVE 按版本检索（认证绕过/未授权 API/SQLi）；`/api/v1/` 未授权接口枚举（users/assets 列表只读尝试）；默认弱口令面（admin 系）。
- **取证注意**：堡垒机自带会话审计——所有操作天然留痕，动作务必收敛在授权范围内，reason 写清楚。

## 四、纪律

- 边界设备是**生产可用性红线**：并发 1、超时短、禁 DoS/禁重启类 PoC（FORBIDDEN 清单已拦 reboot）；不确定的洞型只做存在性证明。
- 命中读取/RCE 判据 → upsert_fact(confirmed) + evidence 留证 → 利用转 S5（L2 审批）。
- 打点成功后立刻回 s6（S6-2 内网探测），堡垒机资产表反哺 s2 攻击面地图。

## v4.8 M6 工具通道兼容性声明

> 口径（loop-core v4.8 纪律 3）：先 probe 后 batch——每个外部工具对目标首次使用前先用小样本探针确认可用性，探针被拦/挂起先切适配通道再批量；探针结果写入交付物工具声明小节。各工具在「挑战型 WAF / 封闭站」下的可用性与适配通道：

- whatweb：JS 挑战型目标返回的是挑战页指纹（假阴性「无指纹」）——先 probe 单目标核对返回是否挑战页；适配通道：channel-snapshot 快照态（cookie+UA）复放或 browser-auth 会话建立后重跑。
- searchsploit：本地库检索，无网络/挑战影响——始终可用。
- curl：低频手工请求始终可用——也是挑战态复放的最小工具（channel-snapshot 快照 cookie/UA 复放）；禁用它做大批量枚举。
