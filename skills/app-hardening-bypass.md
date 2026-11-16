---
id: app-hardening-bypass
title: APP 加固识别与脱壳手册（梆梆/爱加密/乐固/360/腾讯）
tags: app,加固,脱壳,frida,packer,s4,b1
---
# APP 加固识别与脱壳（specB1 前置：加固包直接审计=盲区）


> **v5.3.0 专项前置契约（结构化记录）**：每条任务登记 artifact_source（客户提供包/合法测试包/公共包）、device_owner（客户设备/测试设备）、test_account（测试账号/租户）、network_route（隔离网络/抓包通道）、test_data（合成数据）、runtime_access（动态环境可用性）、limitations（缺失前置）。**静态线索不得替代动态确证**——设备/账号/包缺失时逐条 needs_follow_up（reason=precondition_missing），不误记为无漏洞。

## 一、加固识别（指纹优先）

```bash
# 解包看 dex：jadx 直接开 → 只有壳 stub 类（com.secneo/梆梆、com.qihoo/360、com.tencent.mmkv壳/乐固、
#             com.wrapper/爱加密、NQShell、nagain）= 已加固
# APK 结构指纹：lib 目录 so 名（libDexHelper/libjiagu/libexec/libBugly）、assets 附加文件（ijiami.dat 等）
# 记录加固厂商+版本 → 选择对应脱壳路径
```

## 二、脱壳路径（按厂商选，工具链容器内可装 install_tool）

```bash
# ① 运行时脱壳（主力）：Frida dex dump 类脚本（frida-server 注入，app-dynamic-audit 通道）
#    目标版本 Android 5-11；挂起进程 spawn + 延时 dump → dex 文件落 /data/local/tmp → pull 到工作区
# ② 免 root 路线：模拟器（app-dynamic-audit 真机vs模拟器选型表）+ 内置 frida
# ③ 内存搜索重建：FART/blackdex 思路（主动调用链 dump，修复率更高，成本高）
# ④ 重打包脱壳（兜底）：apktool 反编译壳层 → 完整性校验绕过 → 脱壳辅助（S5 审批：改包行为）
```

## 三、脱壳后衔接

- dump dex → jadx 全量反编译 → app-static-audit 高危点清单照常执行（URL/密钥/加密实现/组件）。
- 加固带来的**运行时防护**也要识别：反 frida（端口/进程/so 检测）、反 root、证书校验 → app-dynamic-audit 绕过段承接。

## 四、纪律

- 脱壳产物只在工作区留存（evidence/ 归档），不外传；壳层分析不计入漏洞（防误报——壳特征≠漏洞）。
- 植入/改包类动作（重打包）默认不做，需 S5 审批 + ROE 允许。
