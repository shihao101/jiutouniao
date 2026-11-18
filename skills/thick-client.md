---
id: thick-client
title: 厚客户端与桌面应用审计（Electron/桌面客户端/自动更新/本地 IPC）
tags: 厚客户端,electron,桌面,ipc,自动更新,s2,s4
---
# 厚客户端与桌面应用审计

覆盖 Windows/macOS 桌面客户端、Electron 应用——现有 APP 技能族（Android/iOS/小程序）之外的客户端形态。

## 前置与工件获取

- 客户端安装包（客户提供 / 官网下载）；Electron 应用本质是 asar 包 + Chromium 运行时。
- 工件 hash+来源登记（对齐 whitebox-source-audit 工件纪律）。

## 步骤

1. **Electron 解包**：`npx asar extract app.asar app/`（asar 是 npm 基线；缺失走 install_tool）——主进程代码/预加载脚本/内置前端全量落盘。
2. **不安全配置判据（Electron 三件套）**：主进程源码 grep `nodeIntegration:\s*true`、`contextIsolation:\s*false`、`webSecurity:\s*false`——任一命中 + 存在渲染外部内容窗口 = RCE 候选（CWE-278/CWE-95）。
3. **敏感信息提取**：解包产物跑 gitleaks 类密钥检索（联动 osint-leak-intel）；内置 API 端点/硬编码凭据 → upsert_fact + 进黑盒接口清单。
4. **本地 IPC 与自定义协议**：注册的自定义协议（`app.setAsDefaultProtocolClient`）与深度链接处理——恶意参数注入（如 `app://...?url=` 任意跳转/命令注入）；Windows 命名管道/Unix socket 权限（`ls -la /proc/net/unix`、管道 ACL）。
5. **自动更新链**：更新服务器地址提取（electron-updater 配置）→ 更新端点 TLS 校验/签名校验缺失判据：更新包无签名校验+HTTP 下载 = 更新劫持候选（高危；生产档只报告不演示）。
6. **服务端面**：客户端泄露的端点全部回注 web 黑盒流程（authz-diff/api-idor）——厚客户端本质是"带 SDK 语义的黑盒前端"。

## 判据

- 候选成立：不安全配置 + 可达输入源（外部内容/深度链接/IPC）双要件。
- 排除：配置不安全但输入源全内部 → tentative，VT 注明边界。

## 工具探针

`which node npx strings; npx asar --version`——缺失 install_tool（asar 随 npm）；Windows 专属面（注册表/管道）标注"需对应系统环境"。

## Execution Profile 标注（v5.3.2）

静态解包/检索只读（L0）生产档可执行；更新劫持演示仅 isolated_lab；客户端样本不外传。

## 关联技能

whitebox-source-audit（工件纪律）、osint-leak-intel（密钥检索）、app-static-audit（移动端姊妹技能）、api-idor（泄露端点回注）。
