---
id: mail-postex
title: 邮件系统后渗透手册（OWA/EWS/Exchange/Mail Relay）
tags: mail,owa,ews,exchange,smtp,relay,s6
---
# 邮件系统后渗透手册（邮件系统=凭据与拓扑金矿，全部动作审批）

## 一、暴露面指纹

```bash
# OWA：/owa/、/ecp/（版本指纹：/owa/auth/logon.aspx 页脚、/ecp/Default.aspx）
# EWS：/ews/exchange.asmx（SOAP 面）；Autodiscover：/autodiscover/autodiscover.xml
# CVE 族：按版本 cve-weaponization（proxylogon/proxyshell/proxynotshell 族）→ S5
# IMAP/POP/SMTP 明文端口：STARTTLS 支持判定（加密失败类观察）
```

## 二、凭据与泄露面

```bash
# 拿到邮箱凭据（s5-5 会话/泄露来源）后的只读枚举：
# EWS 通讯录（测试账号视角）：收件人列表采样（拓扑存在性）
# 收件箱规则/委托：测试账号内自查判据（外部转发规则=候选后门位，只查不设）
# NTLM 面（v5.1 错字修正）：OWA/EWS 认证对任意来源凭据 relay 的可达性判据 → relay 利用 S5
```

## 三、发送类能力（高危）

- SMTP open relay 判据：`VRFY`/`EXPN` 枚举判据（只对测试邮箱）；**open relay 外发验证仅发测试机邮箱**。
- 钓鱼模拟属 S6-4：**默认不做**，ROE 明确允许 + 授权测试组名单 + 模板留证（主控/loop-core 红线）。

## 四、纪律

- 邮箱内容只做存在性证明（收件数/主题关键词哈希），正文不下载（红线 3）。
- 通讯录/组织架构导出禁止全量；采样≤10 条。
