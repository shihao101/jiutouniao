---
id: clickjacking
title: 点击劫持（透明 iframe/多步劫持/frame-busting 绕过）
tags: clickjacking,点击劫持,前端,s4
---
# 点击劫持（Clickjacking）

**定位**：目标高价值操作页（OAuth 授权按钮/2FA 关闭/API key 生成/webhook 配置）未设 `X-Frame-Options`/`frame-ancestors` 时的 UI 覆盖攻击。

## 一、判据（是否 frameable）

响应无 XFO/CSP frame-ancestors → frameable。**绕过检测的假象**：服务端仅靠 `X-Frame-Options: ALLOW-FROM`（Chrome/Safari 不支持）= 实际 frameable；`SAMEORIGIN` 可用**同源可嵌套跳板页**双框绕过。

## 二、PoC 模式

1. **透明 iframe 对齐**：目标页放 iframe（opacity:0，position 精确对齐目标按钮），顶层诱导页放诱饵按钮；
2. **sandbox 绕 frame-busting**：`<iframe sandbox="allow-forms allow-scripts">`（不给 allow-top-navigation，JS busting 失效）；
3. **多步劫持**：每步重定位 iframe 对齐下一步按钮（适配多步向导）；
4. **拖放劫持**：敏感拖放操作跨 iframe 拖取数据。

## 三、高价值目标清单

OAuth「允许」按钮、2FA 关闭、API key 生成/重置、webhook 配置、隐私设置开关、支付确认。

## 四、纪律

PoC 全程本地构造（不向目标注入任何内容）；影响证明=录屏展示"用户点击诱饵按钮实际触发了目标操作"；无敏感操作页 frameable 仅记低危/信息。修复判据：目标页返回 XFO DENY 或 CSP frame-ancestors 'none'。

### 补遗

高价值目标补三类：账号删除页、邮箱/密码修改表单、管理后台操作（添加用户/改角色）。前置步骤：先从源码识别 frame-busting 代码（`if (top.location.hostname !== self.location.hostname)`）再决定绕法（sandbox/双框）。