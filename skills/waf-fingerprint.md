---
id: waf-fingerprint
title: WAF/CDN 指纹识别与绕过策略库
tags: waf,指纹,绕过,cdn,s4,s5
---
# WAF 指纹与绕过策略（s5 失败反馈环 waf_blocked 的调整依据）

## 一、指纹识别（先定拦截者再谈绕过）

```bash
# 特征头/拦截页：Server: X / X-Powered-By / Set-Cookie 名 / 拦截页版权文案
whatweb -a 3 https://目标/
wafw00f -a https://目标/
curl -sk "https://目标/?id=1%20AND%201=1" -o - -w '%{http_code}'   # 探针响应 vs 正常响应差异
# 常见拦截页指纹：阿里云盾 / 长亭雷池(SafeLine) / ModSecurity(参考 OWASP CRS) / 创宇盾 / 云锁 / 安全狗 / 宝塔 / CF / AWS WAF
```

## 二、CDN 与源站关系（影响扫描与利用路径）

- 判据：多地解析/响应头（X-Cache/Server: cloudflare）→ CDN 在前。真实 IP：历史 DNS/子域直连/邮件头/SSL 证书 SAN 关联（recon-playbook 联动，**授权范围内源 IP 才允许直连测试**）。
- 直连源站前必须在 ROE/资产台账登记（可能命中「仅测试已授权地址」红线）。

## 三、绕过策略库（按拦截特征选，一次一个变量）

| 拦截特征 | 策略 |
|---|---|
| 关键词拦截 | 大小写交替、内联注释（MySQL `/*!50000and*/`）、等价函数（and→&&） |
| 空格拦截 | %09/%0a/`/**/`/括号包裹 |
| 编码解析差异 | 双重 URL 编码、Unicode 转义、multipart 参数名编码 |
| Content-Type 严格 | `application/x-www-form-urlencoded` vs JSON vs multipart 三态试 |
| 语义分析（长亭类） | 语法等价重写（先拆再合、注释分割）、参数污染（HPP：同名参数多值，看网关/后端取值差异） |
| 频率拦截 | 限速退避 + 分批窗口（scan-tiering 纪律优先，不硬闯） |
| JS 挑战/人机验证 | 该目标对工具态不友好 → 一切验证转 browser-auth 真实浏览器通道 |

## 四、纪律

- 每次策略调整只改一个变量并记录（基线→变异），成功判据必须与功能正常响应区分。
- waf_blocked 是 coverage 状态不是失败：登记拦截特征（响应码/页面片段哈希），供报告「安全向量」章节引用。

## v4.8 M6 工具通道兼容性声明

> 口径（loop-core v4.8 纪律 3）：先 probe 后 batch——每个外部工具对目标首次使用前先用小样本探针确认可用性，探针被拦/挂起先切适配通道再批量；探针结果写入交付物工具声明小节。各工具在「挑战型 WAF / 封闭站」下的可用性与适配通道：

- wafw00f：低频指纹探测基本可用；结果仅作线索，以实测行为为准。
- whatweb：JS 挑战型目标返回的是挑战页指纹（假阴性「无指纹」）——先 probe 单目标核对返回是否挑战页；适配通道：channel-snapshot 快照态（cookie+UA）复放或 browser-auth 会话建立后重跑。
- curl：低频手工请求始终可用——也是挑战态复放的最小工具（channel-snapshot 快照 cookie/UA 复放）；禁用它做大批量枚举。
