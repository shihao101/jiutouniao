---
id: miniapp-server
title: 小程序服务端攻击链手册（解包 API → 鉴权/签名/越权）
tags: miniapp,小程序,api,签名,wxapkg,s4,b2
---
# 小程序服务端攻击链（miniapp-audit 管解包与前端，本手册管「解包之后的服务端测试」）


> **v5.3.0 专项前置契约（结构化记录）**：每条任务登记 artifact_source（客户提供包/合法测试包/公共包）、device_owner（客户设备/测试设备）、test_account（测试账号/租户）、network_route（隔离网络/抓包通道）、test_data（合成数据）、runtime_access（动态环境可用性）、limitations（缺失前置）。**静态线索不得替代动态确证**——设备/账号/包缺失时逐条 needs_follow_up（reason=precondition_missing），不误记为无漏洞。

## 一、从解包产物提取 API 面（衔接 miniapp-audit）

```bash
# wxapkg 解包产物中提取接口清单：
grep -rhoE '"https?://[^"]+"' unpacked/ | sort -u > evidence/b2_api_hosts.txt
grep -rhoE '"/(api|v[0-9])/[a-zA-Z0-9_/-]{3,80}"' unpacked/ | sort -u > evidence/b2_api_paths.txt
# 请求模板还原：找 request 封装层（header 组装/签名函数/公共参数）——签名算法是关键前置于重放
```

## 二、鉴权与签名机制还原

- **签名链**：timestamp+nonce+body 排序 → md5/hmac(key)；key 常在前端 JS 里（解包产物全文检索）→ 签名可重放判据（同签名重发两次，第二次 200=时间窗缺失）。
- **还原完成标准（v5.1 统一口径，引用 crypto-offensive）**：还原算法必须产出**可执行 oracle（≥3 组单测向量全对齐）才算还原完成**——同签名重放两次的 200 判据是"时间窗缺失"的快速信号，不能替代 oracle 单测；oracle 落 poc/ 并入投递队列（破解≠终点）。
- **固定 key**：key 静态 = 签名机制防篡改不防伪造（定级时如实区分）。
- **wx.login code 流**：code 换 session 的服务端校验（code 一次性的服务端核对判据，仅测试 openid）。

## 三、服务端测试主体（复用 WEB 技能族）

| 测试 | 衔接技能 |
|---|---|
| 未授权接口矩阵 | api-doc-leak 思路 + api-idor（无 token 直接枚举） |
| 越权（openid/user_id 替换） | api-idor（双测试账号 A/B 对比口径） |
| 业务逻辑（金额/数量/优惠） | logic-csrf-deser + race-condition（小程序并发下单面） |
| 签名绕过 | 参数篡改后签名不一致的差异响应（签名未覆盖字段=可篡改位清单） |

## 四、纪律

- 微信侧资源（AppSecret）**只登记存在性**；发现泄露立即 record_finding（高危）但不实际调用微信 API。
- 测试全程使用测试 openid/测试商品；支付相关只到「可构造请求」判据层（S5+人工确认）。
