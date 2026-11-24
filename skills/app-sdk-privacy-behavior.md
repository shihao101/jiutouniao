---
id: "app-sdk-privacy-behavior"
title: "APP 隐私清单与 SDK 数据行为（声明 vs 运行时数据流——采集/共享/保留/删除路径逐项比对）"
tags: "app,ios,android,隐私清单,sdk,privacy-manifest,数据行为,specB1,b1,s4"
---
# APP 隐私清单与 SDK 数据行为（specB1 D8 配套——「声明了什么」对拍「运行时做了什么」）

> 定位：app-privacy-compliance 覆盖「PIPL 合规取证面」（权限-使用对拍/明文传输），本技能覆盖 **D8 隐私清单与 SDK 数据行为**——Apple Privacy Manifest / Required Reason API / Android 权限与 SDK 清单的**声明基线 vs 运行时数据流**逐项比对，识别第三方 SDK 的采集、共享、保留与退出/删除路径。
> 判定铁律（深度研究 D8 节）：**SDK 归属需调用栈/模块/线程/差分停用证据——代理上看到厂商域名不等于知道是哪个 SDK 发的**；Android SDK Sandbox 兼容 API 已弃用（API 37），目标未使用即标「不适用」，不硬套。

## 一、声明基线盘点（产出《声明-运行时比对基线表》）

| 盘点项 | 观测方法 | 喂养的测试项 |
|---|---|---|
| Apple Privacy Manifest | PrivacyInfo.xcprivacy 解析（采集类型/关联域名/Required Reason API 类别） | T1/T3 输入 |
| Required Reason API 声明 | Xcode Privacy Report / manifest 中 NSPrivacyAccessedAPITypes | T3 比对 |
| Android 权限与 SDK 清单 | merged manifest 权限表 + SBOM/依赖树（jadx 依赖面） | T2/T4 输入 |
| 用户告知 | 首启弹窗/隐私政策/权限说明文案快照（版本+时间） | T3 一致性比对 |

## 二、D8 测试矩阵（每项：步骤→判据→三态；以测试数据与经授权设备验证）

| T | 测试项 | 步骤 | 判据 | 判定 |
|---|---|---|---|---|
| T1 | **首启/同意前数据流** | mitmproxy 冷启动→同意弹窗前全流量观测 | 同意前出网携带设备标识/位置/PII = **Confirmed**（同意前采集） | Confirmed |
| T2 | **SDK 数据流归属** | 逐 SDK 差分停用（开关/去 SDK 包重打包）+ 堆栈/模块证据定位发送者 | 声明未列的 SDK 采集行为 = Suspected（有调用栈证据升 Confirmed）；声明与运行时一致 = negative_valid | Suspected/Confirmed/negative_valid |
| T3 | **声明 vs 运行时一致性** | 逐项比对：清单采集类型/关联域名/Required Reason API vs mitmproxy 实测字段与频次 | 运行行为超出声明范围 = Confirmed（清单失实）；Required Reason API 使用理由与实际调用场景不符 = Suspected | Confirmed/Suspected |
| T4 | **共享与保留路径** | 追踪 SDK 上行数据的接收域/SDK 间共享（同设备双 SDK 接收同一标识） | 共享超出声明「第三方共享」清单 = Confirmed（共享未披露）；保留期无文档 = 治理发现 | Confirmed/治理确认 |
| T5 | **退出/删除路径** | 撤回同意/删除账号后观察后续流量与 SDK 行为 | 撤回后继续采集 = Confirmed（撤回无效）；无删除接口 = 治理发现（分开定性） | Confirmed/治理确认 |
| T6 | **SDK Sandbox / 新平台边界** | Android SDK Sandbox（按目标 OS 版本确认适用性——API 37 弃用面）数据/IPC 边界；不适标注「不适用」 | 适用且越界访问 = Suspected（沙箱边界） | Suspected/不适用 |

## 二.5、命令骨架（T1/T2/T3 最小可执行序列）

```bash
# T1 首启同意前流量（冷启动窗口只观测不交互）
mitmdump -w evidence/d8-firstlaunch.mitm   # 设备装证书→冷启动 APP→同意弹窗前停止
# T2 SDK 归属差分：逐 SDK 停用重打包（或运行时 Frida 差分）对比接收域集合
frida -U -f <pkg> -l d8-diff.js --no-pause   # hook OkHttp/URL 关键调用，打 stack 标记
# T3 声明比对：解清单 vs 抓包字段
unzip -p <ipa> Payload/*.app/PrivacyInfo.xcprivacy | python3 -c "import plistlib,sys; print(plistlib.load(sys.buffer))" | tee evidence/d8-manifest.txt
grep -r "NSPrivacyAccessedAPIType\|NSPrivacyCollectedData" evidence/d8-manifest.txt | head
# 判读：同意前出网含标识符 = T1 Confirmed；清单未列的接收域 = T4 Suspected 起
```

## 三、判定判据（深度研究 D8 节口径）

- **Confirmed**：①同意前采集（T1 流量+字段证据）；②声明失实（运行超出声明采集/共享清单）；③撤回后继续采集。
- **Suspected**（附假阳性排除清单）：①SDK 归属仅有域名旁证（无调用栈/差分证据）；②平台系统级上报（OS 自身流量不算目标 APP 缺陷——差分停用排除）；③清单格式解析失败（标「清单不可读」，不推断失实）。
- **治理确认单列**：保留期无文档/无删除路径/清单未随版本更新——进 W10/治理章，不混入技术漏洞计数。
- 工具版本：Xcode 27（Privacy Report 导出）· MobSF 4.6.9（静态辅助，人工复核）· mitmproxy 12.3.1 · Frida 17.27.4；报告记录实际使用版本与哈希。

## 四、Execution Profile 标注

- production_safe（默认）：全部以测试数据与经授权设备；差分重打包仅限测试包；真实用户数据不是验证目标。
- isolated_lab：可完整演练同意路径与撤回路径链（含 SDK 服务端 mock 接收端）。

## 五、产出对接

- record_finding：cwe=CWE-359/T4（信息暴露-共享未披露）、CWE-778/T1（同意前采集）——detail 引用清单条目 vs 运行时字段；update_coverage(vuln_class=D8隐私清单, notes 记 `T1-T6 三态 + SDK 归属证据形态`)；
- 配合技能：load_skill app-static-audit（清单/依赖静态面）、load_skill app-dynamic-audit（设备通道前置）、load_skill app-privacy-compliance（PIPL 取证联动）；治理类移交 miniapp-privacy-governance/report-writing 口径。
