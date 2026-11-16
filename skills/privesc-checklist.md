---
id: privesc-checklist
title: Linux/Windows 提权清单
tags: 提权,s6,privesc
---
# 提权检查清单（Sudo/SUID/内核/服务）

## Linux（只读枚举优先）
```bash
sudo -l                        # NOPASSWD 项
find / -perm -4000 -type f 2>/dev/null   # SUID
crontab -l; ls -la /etc/cron*  # 定时任务可写
cat /proc/version; uname -r    # 内核版本对照 exploitdb
getcap -r / 2>/dev/null        # capabilities
ls -la /etc/shadow /etc/passwd # 权限配置
env | grep -i path             # PATH 劫持面
ps aux | grep root             # root 服务
# v5.1 常规向量补全：
sudo --version                 # sudo 版本 CVE（CVE-2021-3156 等以检索为准）
id; groups                     # docker/lxd 组成员（=等效 root 面，列出即候选）
ls -l /var/run/docker.sock     # sock 可写=容器逃逸候选（S5）
grep -w ".*" /etc/passwd | awk -F: '$3==0{print}'   # 额外 uid=0 账号
cat /etc/fstab; mount          # 可写敏感挂载
find / -writable -type d 2>/dev/null | grep -vE "^/(tmp|dev|proc|sys)"   # 可写目录
```
- 内核 exploit 实际利用 = L2，先审批；优先配置类提权。
- **出口（v5.1）**：全部候选逐一判读后无果 → update_coverage(ruled_out, 附已测清单+证据) 并把焦点移交横向（intranet-lateral），不空转。

## Windows（PowerShell 只读枚举）
```powershell
whoami /priv                   # SeImpersonate 等关键特权
whoami /groups                 # Token 组
schtasks /query /fo LIST /v    # 计划任务
Get-Service | ? {$_.StartType -eq "Automatic"}
# v5.1 常规向量补全：
Get-ItemProperty HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer -Name AlwaysInstallElevated   # AlwaysInstallElevated（两键都=1 才成立）
Get-CimInstance Win32_Service | ? {$_.StartName -eq "LocalSystem" -and $_.PathName -notlike "*`"*"}   # 服务路径无引号/可写
Get-ChildItem "C:\Program Files*" -Recurse -Include *.exe 2>$null | ? { $_.GetAccessControl() }   # 可写服务二进制（较慢，可降档）
```
- Potato 系列（SeImpersonate）实际利用先审批。

## 记录纪律
- 每个候选路径 → record_timeline + 覆盖矩阵(vuln_class=提权)；成功的写入权限矩阵。

## v4.8 M6 工具通道兼容性声明

> 口径（loop-core v4.8 纪律 3）：先 probe 后 batch。本技能工具在受限环境下的可用性与适配通道：

- strip-fcaps.py：Linux 文件能力（getcap -r）枚举提权面——本机/已获 shell 内运行，不涉及目标网络，始终可用；输出落 evidence/ 供 S6 承接。
