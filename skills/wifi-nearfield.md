---
id: wifi-nearfield
title: 无线与近场渗透（Wi-Fi/BLE/NFC/RFID——授权现场任务专用）
tags: 无线,wifi,蓝牙,ble,nfc,rfid,现场,s2
---
# 无线与近场渗透

**授权现场任务专用**（client-site 全天窗口；远程项目不适用——这是与既有技能族的本质差异，开工前先核对授权范围是否含无线频段与现场时段）。

## 前置硬门（缺一即不做）

1. 授权书明确含 Wi-Fi/BLE/NFC 频段与现场时段（ROE 回读）。
2. 硬件探针：`iw dev`（网卡监听模式能力）/ `hciconfig`（BLE）/ `nfctool`（NFC）——缺硬件如实 needs_follow_up，不硬做。
3. 影响边界：去认证（deauth）类干扰动作 = L2 高危，仅 isolated_lab/明确许可的窗口执行。

## 步骤

1. **Wi-Fi 侦察**：`airodump-ng <mon0>`（AP 清单/加密类型/客户端列表）→ WPA2-Enterprise 面评估（EAP 类型/证书校验——Rogue AP 判据）。
2. **WPA2-PSK 面**：握手捕获（授权窗口内）→ 离线爆破（hashcat mode 22000，联动 password-offline 字典纪律：命中即停）。
3. **企业网接入后**：内网横向按 intranet-lateral/ad-attack 正常推进——无线只是入口。
4. **BLE**：`bleah`/`bettercap` 枚举 GATT 特征 → 特征读写权限判据（无认证可写 = 缺陷候选）；BLE 配对模式（Just Works = 中危）。
5. **NFC/RFID 门禁**：`nfctool`/Proxmark（需硬件）——卡片UID 可克隆性、读卡器无加密判据。**门禁克隆演示仅 isolated_lab 且留证**。

## 判据与记账

- 候选成立：捕获→破解成功（PSK）/未认证特征写入生效（BLE）/克隆卡开门（门禁）——全部留证（pcap/日志 hash）。
- 干扰类动作（deauth）不产生"漏洞"，只产生"取证条件"——单独登记时间线，不进 findings。

## 工具探针

`which aircrack-ng hashcat bettercap hciconfig`——缺失 install_tool（aircrack-ng 系 Kali 标准包）；无线网卡监听能力 `iw list | grep monitor` 探针失败 → 硬件不满足，移交人工。

## Execution Profile 标注（v5.3.2）

- **Lab Only**：deauth/门禁克隆/Rogue AP——仅 isolated_lab 或授权书明确列出的现场窗口；
- **production_safe**：被动侦察（AP 清单/信道占用）可执行；任何主动注入帧动作禁。
- 现场产物（pcap/握手包）含第三方隐私面——工作区隔离 + 报告脱敏。

## 关联技能

password-offline（握手离线爆破）、intranet-lateral（接入后横向）、edge-vpn-bastion（无线 Portal 面）、observable-degradation（硬件缺失降级）。
