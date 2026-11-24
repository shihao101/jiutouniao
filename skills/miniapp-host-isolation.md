---
id: "miniapp-host-isolation"
title: "小程序宿主能力与跨小程序隔离（宿主桥接/敏感权限 API/跨小程序数据边界——仅负对照）"
tags: "小程序,宿主,桥接,跨小程序,隔离,权限api,specB2,b2,s4"
---
# 小程序宿主能力与跨小程序隔离（specB2 W8 配套——只做负对照探测，不越平台边界）

> 定位：miniapp-audit 覆盖「目标小程序自身」，本技能覆盖**宿主侧边界**——宿主桥接、敏感权限 API 授权状态、WebView/页面来源、Cookie/会话共享及跨小程序数据边界。
> 前置与边界（深度研究 W8 节硬约束）：需要 **≥2 个客户自有测试小程序（不同 AppID）+ 宿主专用测试账号**；跨小程序探针**只做负对照**（证明隔离存在或确认越界），不做宿主文件系统/数据库遍历；**平台自身缺陷需平台书面授权，不在目标授权范围内**。

## 一、宿主边界盘点（产出《宿主边界画像》）

| 盘点项 | 观测方法 | 喂养的测试项 |
|---|---|---|
| 桥接面 | 目标小程序调用的宿主 API 清单（JSBridge 方法名/参数形态，解包产物 + 运行时 hook） | T1/T2 输入 |
| 敏感权限 API 状态 | 未授权/已授权/撤销三态下 API 行为差分 | T2 输出 |
| WebView/页面来源 | web-view 组件的 src 域白名单、页面跳转链 | T3 输入 |
| 共享面 | 宿主 Cookie/会话在小程序 WebView 内的可见性 | T4 输入 |

## 二、W8 测试矩阵（每项：步骤→判据→三态；双测试小程序夹具）

| T | 测试项 | 步骤 | 判据 | 判定 |
|---|---|---|---|---|
| T1 | **宿主桥接授权检查** | 逐个敏感桥接 API：未授权态调用（负对照）→ 观察错误处理与授权引导 | 未授权态返回数据/静默成功 = **Confirmed**（授权检查缺失）；拒绝且有引导 = negative_valid | Confirmed/negative_valid |
| T2 | **敏感权限 API 三态** | 同一 API 在 unauthorized/granted/revoked 三态的行为矩阵（Canary 数据） | 撤销态仍可用 = **Confirmed**（撤销不生效）；三态行为一致且正确拒绝 = negative_valid | Confirmed/negative_valid |
| T3 | **WebView 页面来源边界** | web-view src 越界测试（业务域外 URL，测试域） | 白名单外的 URL 可加载并获 Cookie/存储上下文 = Suspected（越界加载） | Suspected |
| T4 | **跨小程序数据边界（负对照）** | 测试小程序 A/B（不同 AppID）：A 写入的本地存储/Cookie/文件在 B 内可达性探测（只读探测自身可达面） | B 可读 A 的会话/Cookie = **Confirmed**（跨小程序共享）；不可达 = negative_valid（隔离有效） | Confirmed/negative_valid |
| T5 | **错误处理与降级** | 桥接 API 传非法参数/超限值（受控） | 错误信息泄露内部路径/堆栈 = Suspected；安全错误码 = negative_valid | Suspected/negative_valid |

## 二.5、命令骨架（T1/T4 最小可执行序列；全部 Canary 数据）

```bash
# T1 未授权态桥接调用（负对照）：目标小程序内构造未授权 API 调用（测试小程序自建面）
#    <测试小程序A> my.requirePrivacy/wx.getLocation 等未授权调用 → 记录返回形态
#    [未授权返回数据] = Confirmed 候选；[拒绝+授权引导] = negative_valid
# T4 跨小程序可达性（只读负对照）：A 内写 Canary 存储 → B 内逐面只读探测
#    B 探测：本地存储 key、Cookie 域、WebView 会话、剪贴板残留 → 任一命中 Canary = 共享（Confirmed）
# 判读纪律：只探测「自身可达面」——不做宿主文件/数据库遍历；平台桥本身缺陷（越权访问其他宿主能力）
# 属平台范围，仅记录线索移交人工（无平台书面授权不验证）。
```

## 三、判定判据（深度研究 W8 节口径）

- **Confirmed**：①未授权/撤销态敏感 API 返回数据或静默成功；②跨测试小程序 Canary 共享（Cookie/存储/会话）。
- **Suspected**（附假阳性排除清单）：①web-view 加载业务合作域（有书面业务关联 = 不算越界）；②桥接拒绝但错误码含内部细节（信息泄露单列，与授权缺陷分开）；③宿主版本差异导致的 API 行为差异（双宿主版本复核）。
- **negative_valid**：三态行为正确 + 跨小程序隔离完整 + 白名单生效——三态齐才可写「宿主边界有效」。
- 边界纪律：宿主平台本身的隔离机制缺陷**不是目标小程序的漏洞**——只记录线索与复现路径，移交平台授权方人工评估；报告引用时标「平台侧观察，未验证」。

## 四、Execution Profile 标注

- production_safe（默认）：全部负对照/只读探测 + Canary 数据；不做宿主遍历/提权尝试；平台 API 调用限频。
- isolated_lab：可完整演练三态矩阵与跨小程序共享链（自建双测试小程序夹具）。

## 五、产出对接

- record_finding：cwe=CWE-862/T1/T2（授权缺失）、CWE-200/T4（跨小程序信息暴露）——detail 引用三态矩阵与 Canary 命中证据；update_coverage(vuln_class=W8宿主隔离, notes 记 `T1-T5 三态 + 夹具形态`)；
- 配合技能：load_skill miniapp-audit（解包/桥接静态面）、load_skill api-idor（越界量化）；平台侧线索进《专项条目清单》W8 行（标注平台边界未验证）。
