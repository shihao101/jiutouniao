---
id: iot-firmware
title: IoT 与固件审计（固件提取/文件系统分析/升级链/嵌入式服务面）
tags: iot,固件,嵌入式,binwalk,升级链,s4
---
# IoT 与固件审计

适用：客户提供固件镜像/可获取升级包的设备面（路由器/摄像头/NVR/网关/工控网关）。固件审计 = whitebox-source-audit 的嵌入式特化。

## 工件纪律（同白盒）

固件镜像 hash+来源登记 → 工作区 `firmware/`；不外传、不上传公网分析服务。

## 步骤

1. **提取**：`binwalk -Me <镜像>`（递归提取 squashfs/cramfs/jffs2）；加密/打包固件 → 先静态识别（magic 头/厂商解包工具线索）→ 无法解包如实 needs_follow_up。
2. **文件系统速览**：`/etc/shadow`（默认/弱口令 hash → password-offline 离线破解）、`/etc/passwd`、启动脚本（`rcS`/`init.d`——硬编码凭据/后门口令）、web 根目录（嵌入式 CGI/luasoft——回注 web 黑盒流程）。
3. **危险模式检索**：binwalk -E 熵分析找加密区；`strings`+grep sink 表（system/popen/strcpy——对齐 whitebox-sca-taint）；CGI/二进制参数处理函数 → 命令注入候选（很多家用设备 CGI 直拼 shell——实战高产出区）。
4. **服务面测绘**：运行配置提取（telnetd/sshd/web 默认端口、调试口开关）；已知 CVE 匹配（ BusyBox/Dropbear/lighttpd/GoAhead 版本 → cve-weaponization）。
5. **升级链**：升级包签名校验判据——解包升级包看是否有签名段（厂商工具特征）；无签名+HTTP 拉取 = 升级劫持候选（高危；生产档只报告）。
6. **运行时验证**：QEMU 用户态模拟（`binwalk` 提取的 ELF → `qemu-<arch> -L <squashfs-root>`）跑 CGI 验证注入候选——isolated_lab 档执行。

## 判据

- 候选成立：CGI 参数 → sink 路径完整（静态）+ QEMU/实机复现（动态）；硬编码凭据验证成功。
- 排除：熵加密区无法解包 → VT 移交注明"需硬件调试（UART/JTAG）"。

## 工具探针

`which binwalk qemu-arm-static unsquashfs strings`——binwalk 基线（Kali）；qemu 用户态缺失 → install_tool（qemu-user-static）；全缺 → 静态 strings 降级 + needs_follow_up。

## Execution Profile 标注（v5.3.2）

静态提取/检索只读（L0）生产档可执行；QEMU 模拟与实机刷写 = Lab Only；固件工件不外传；实机测试先快照（设备变砖风险）。

## 关联技能

whitebox-source-audit（上层流水线）、whitebox-sca-taint（sink 表）、cve-weaponization（组件 CVE）、password-offline（固件 hash 破解）、ics-ot（工控网关延伸）。
