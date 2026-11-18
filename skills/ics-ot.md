---
id: ics-ot
title: ICS/OT/SCADA 渗透评估（工业协议/PLC/过程安全边界）
tags: ics,ot,scada,plc,modbus,工业,s2,s4
---
# ICS/OT/SCADA 渗透评估

**高影响面领域：评估窗口与动作边界由 ROE 强制**（工业协议的写操作可能导致生产事故——安全第一的领域纪律严于通用 IT）。

## 前置硬门（缺一即降级为纯被动观测）

1. ROE 明确列出可接触的协议/资产/时段（如仅 IT-OT 边界区、仅测试 PLC）。
2. **被动优先原则**：所有评估先纯只读（抓包/指纹），写操作一律需逐项审批 + isolated_lab。
3. 过程安全确认：客户工程师在场/值守（现场任务）或书面确认（远程只读）。

## 步骤

1. **协议指纹（被动）**：nmap 协议探针（`-p 502 --script modbus-discover`）+ 流量镜像抓包（tcpdump → 协议占比）——Modbus/S7/ EtherNet-IP/DNP3/OPC UA 清单。
2. **Modbus 面**：`modbus-discover`/`modbus-enum`（线圈/寄存器只读枚举）；写线圈/寄存器（fc5/fc6）**仅 isolated_lab 台架**——生产 PLC 禁止任何 fc5+。
3. **S7 面**：`s7comm` 枚举（CPU 状态/槽位读）；组态下载/启停（fc 写）同样台架限定。
4. **HMI/SCADA 上位机**：与 IT 域的边界资产（跳板机/ historians）——按 intranet-lateral 推进；historian 数据库 → database-postex。
5. **已知漏洞**：PLC/网关固件版本 → cve-weaponization（Siemens/Phoenix/Moxa CVE 库）；iot-firmware 承接固件面。
6. **边界评估（IT-OT）**：防火墙规则有效性（IT→OT 可达面枚举）；跳板机权限矩阵 → authz-diff 思想复用。

## 判据与记账

- 只读枚举结果：资产/协议/点表清单 = 侦察交付物（不进 findings，除非暴露敏感过程数据）。
- 台架写验证：每项演示登记四元组（操作/设备/恢复步骤/验证命令），收口按 s7 登记移交。
- 任何造成过程异常的评估立即熔断（一键 Kill）——人员安全优先于评估完整性。

## 工具探针

`which nmap tcpdump; nmap --script-updatedb`——modbus/s7 脚本随 nmap 基线；专用台架（PLC 模拟器/真机）由客户提供，缺失 → 静态评估 + needs_follow_up。

## Execution Profile 标注（v5.3.2）

- **Lab Only**：一切写操作（fc5+/组态下载/启停）——仅 isolated_lab 台架；
- **production_safe**：被动抓包/只读枚举/版本指纹；发现"可写面"本身即高危 finding（CWE-306），不验证。
- 报告必须含客户工程师联合确认的过程影响评估。

## 关联技能

intranet-lateral（边界渗透）、iot-firmware（网关固件面）、cve-weaponization（工控组件）、database-postex（historian）、observable-degradation（台架缺失降级）。
