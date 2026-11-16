---
id: app-ios-audit
title: iOS APP 审计手册（IPA/class-dump/keychain/ATS）
tags: ios,ipa,ipad,app,越狱检测,s4,b1
---
# iOS APP 审计手册（specB1 iOS 分支；容器内以静态为主，动态需越狱/免越狱设备通道）


> **v5.3.0 专项前置契约（结构化记录）**：每条任务登记 artifact_source（客户提供包/合法测试包/公共包）、device_owner（客户设备/测试设备）、test_account（测试账号/租户）、network_route（隔离网络/抓包通道）、test_data（合成数据）、runtime_access（动态环境可用性）、limitations（缺失前置）。**静态线索不得替代动态确证**——设备/账号/包缺失时逐条 needs_follow_up（reason=precondition_missing），不误记为无漏洞。

## 一、获取与画像

```bash
# IPA 获取（v5.1 更新——iTunes 12.7 起已无 App Store 归档）：客户直发（首选，附授权核验）、企业签分发包、TestFlight 邀请、越狱机 /var/containers 分离（app-dynamic-audit 设备通道）；Swift 应用 class-dump 仅覆盖 ObjC——Swift 态转运行时 dump（Frida ObjC/Swift bridge）或静态 strings 兜底并注明命中率限制
# 结构：unzip Payload/*.app → 二进制 Mach-O + Info.plist + *.lproj + Frameworks
# 画像：Info.plist（URL Scheme/权限声明/ATS 状态/Entitlements）→ 先出攻击面表
```

## 二、静态审计点

```bash
# ① 类与方法枚举：class-dump（ObjC）/ swift-demangle；strings 二进制内 URL/API 路径
otool -L Payload/*.app/* | head    # 链接库（自研 Frameworks 重点）
strings Payload/*.app/* | grep -E "https?://|api\.|token|key" | sort -u | head -40
# ② 硬编码密钥：Info.plist / .plist 配置 / 二进制常量（AES key/私钥类）
# ③ ATS 例外：NSAllowsArbitraryLoads → 明文流量面（对应服务端）
# ④ URL Scheme/Universal Link：未校验来源的 scheme 参数处理（客户端劫持判据）
# ⑤ SDK 清单：第三方 SDK 版本 → 已知问题（frontend-sca 思路）
# Swift 加壳（符号混淆）→ strings 命中率低 → 转 app-hardening-bypass 同思路的运行时 dump
```

## 三、动态点（设备通道可用时）

- Keychain 导出（越狱机+测试 APP 自己的条目）；剪贴板监听面；截图/HTTPS 证书校验绕过（ssl-kill-switch 思路，**S5 审批**）。
- 越狱/root 检测识别（不绕过，只登记防护现状——安全向量章节素材）。

## 四、纪律

- 用户的真实 iCloud/keychain 数据禁止触碰；只对测试 APP 自身数据操作。
- 静态为主：容器内动态能力有限时，动态项登记 needs_follow_up 待设备窗口。
