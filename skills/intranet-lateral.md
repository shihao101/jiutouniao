---
id: intranet-lateral
title: 内网信息收集与横向移动手册
tags: 内网,横向,后渗透,s6
---
# 内网信息收集与横向移动手册（全部动作需 L2 审批）

## 立足点信息收集（只读优先）
```bash
id; hostname; ip a; cat /etc/hosts; arp -a
ps aux | grep -iE 'agent|monitor'; ls /opt /srv 2>/dev/null
env | grep -iE 'key|token|secret'   # 环境变量密钥（只记存在性）
```
- 云上：`curl -s http://169.254.169.254/latest/meta-data/`（存在性证明）。

## 网络发现（限速）
```bash
nmap -sn 10.0.0.0/24                  # 存活
nmap -sV --top-ports 100 10.0.0.0/24  # 服务（网段粗扫）
# 对关键主机（DMZ/域控/运维跳板）做全端口，服务可能在 100 以外：
nmap -Pn -p- --open --min-rate 800 -T3 <关键主机IP>
```

## 凭据复用面
- 找到的密码/密钥对内网同类型服务复用测试（限频）：ssh/redis/mysql/管理台。
- 只验证「能否登录」，成功即停并留证；不做批量爆破。

## 横向路径记录
- record_timeline 记录每一跳：源→目标→凭据类型→结果。
- 横向路径图（deliverables/s6-横向路径图.md）用文字+箭头表达，标注每步风险等级。

## 红线
- 范围外资产不碰；敏感数据只做存在性证明；发现域控/核心系统立即上报人工，不擅自深入。

## v4.8 M6 工具通道兼容性声明

> 通用判据以 `tool-channels.md` 为准（v5.1 单源去重）；本技能差异：内网横扫类（fscan/crackmapexec 族）在内网 IDS/蜜罐面下先 probe 后 batch 更严——单主机 probe 2 请求正常再批量；凭据喷洒受 weak-cred-bruteforce 锁定纪律约束。nmap/curl 通用行不再内联。
