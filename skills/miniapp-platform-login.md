---
id: "miniapp-platform-login"
title: "小程序平台登录态与身份绑定（授权码生命周期/code换会话/身份映射/刷新撤销/防重放）"
tags: "小程序,登录态,授权码,code2session,会话绑定,身份映射,specB2,b2,s4"
---
# 小程序平台登录态与身份绑定（specB2 W7 配套——授权码就是身份的入口）

> 定位：miniapp-server 覆盖「解包 API→签名/越权」的服务端链，本技能覆盖**登录授权码生命周期**——code 换 session 的服务端校验、用户身份与资源所有权映射、令牌刷新/撤销与防重放。W4 的接口鉴权测试以本技能产出的「会话基线」为输入。
> 判定铁律：**三平台授权码机制是不同产品流程，不假设生命周期完全相同**（微信 wx.login code / 抖音 code2session / 支付宝 authCode 各自独立核验）；**不访问真实用户账号**——全部用自有测试小程序 + Canary A/B 测试身份；session_key 永远不应到达客户端。

## 一、三平台授权码基线盘点（产出《登录链画像》，后续测试全部依赖）

| 盘点项 | 微信 | 抖音 | 支付宝 |
|---|---|---|---|
| 客户端凭据 | wx.login → code | tt.login → code | my.getAuthCode → authCode |
| 服务端换取 | code2session（appid+secret+code） | code2session（等价面按平台文档核对） | authCode 换 token/用户信息 |
| 会话态 | session_key + openid（3rd_session 常见自建） | session_key + openid | access_token/user_id |
| **以抓包/文档实测为准** | 平台接口名与参数以当版官方文档逐字核对，不沿用旧资料 | 同左（基库名版本差异大，API 名逐版核验） | 同左 |

> 盘点纪律：上表是**观测框架不是事实**——先 mitmproxy 抓一次完整登录链（测试小程序真实换取），逐字段落盘后再开测。

## 二、W7 测试矩阵（每项：步骤→判据→三态；全部 Canary A/B 双身份操作）

| T | 测试项 | 步骤 | 判据 | 判定 |
|---|---|---|---|---|
| T1 | **授权码一次性/有效期** | 同一 code 二次换取；过期 code（自然过期或时钟面）换取；错配 code（A 小程序的 code 打 B 小程序的 secret） | 旧 code 二次换取成功 = 无一次性；错配 code 成功 = appid-code 绑定缺失 | Suspected→Confirmed（有服务端效果证据） |
| T2 | **code 换会话服务端校验** | 构造「合法 code + 错误 appid/签名」换取；观察 secret 校验失败时的响应形态与错误码 | 错误 secret/签名仍换出会话 = 服务端校验缺失（罕见，通常平台侧拦截）；业务侧跳过校验 = Confirmed | Confirmed/negative_valid |
| T3 | **身份与资源所有权映射** | Canary-A 登录换取会话 → 以 A 会话访问 Canary-B 的资源（订单/地址/数据面逐类） | 跨 Canary 资源可达 = 水平越权（与 api-idor 合并量化） | Confirmed（附响应差分） |
| T4 | **令牌刷新/撤销** | A 会话登出/解绑后，旧 session/token 调用受保护接口；刷新接口旧 token 换新后旧 token 复用 | 登出/解绑后旧态仍有效 = 撤销缺失；旧 refresh 复用 = 无一次性轮换 | Confirmed（会话表态为准） |
| T5 | **防重放与会话键边界** | 重放完整登录换取请求；检查响应/前端产物中是否出现 session_key 明文 | session_key 到达客户端（响应体/前端日志/localStorage）= **Confirmed 泄露**（CWE-311/200） | Confirmed |
| T6 | **会话吊销的服务端语义** | 撤销验证以**服务端会话表/接口状态**为准——前端跳回登录页 ≠ 吊销 | 前端「已登出」但服务端会话仍活跃 = 撤销语义缺失（与 session-lifecycle T1 同族） | Confirmed |

## 二.5、命令骨架（T1/T3/T5 最小可执行序列；测试小程序后端为自建可观测服务）

```bash
# T1 授权码一次性：同 code 二次换取（服务端为自建测试小程序后端，可直观测会话表）
curl -s -m 10 "$API/wx/code2session?code=$CODE_A" | head -c 200; echo " ← 首次换取"
curl -s -m 10 "$API/wx/code2session?code=$CODE_A" | head -c 200; echo " ← 二次换取(应失败)"
# T3 跨 Canary 资源映射：A 会话访问 B 的资源（逐资源类，响应差分留证）
curl -s -m 10 "$API/order/detail?id=$ORDER_B" -H "X-Session: $SESSION_A" -o /dev/null -w "A会话→B订单 [%{http_code}] len=%{size_download}\n"
curl -s -m 10 "$API/order/detail?id=$ORDER_B" -H "X-Session: $SESSION_B" -o /dev/null -w "B会话→B订单·正对照 [%{http_code}] len=%{size_download}\n"
# T5 session_key 边界：抓登录换取响应 + 全局搜前端产物
grep -r "session_key\|sessionKey" evidence/ unpacked/ --include="*.js" --include="*.json" -l | head
# 判读：二次换取 [200]+会话体 = 无一次性（Confirmed 候选）；A→B [200]+B业务体 = 越权（api-idor 口径量化）
```

## 三、判定判据（深度研究 W7 节口径）

- **Confirmed**：①错配/过期/复用 code 在服务端换取会话成功（附换取请求/响应+服务端会话表态）；②跨 Canary 资源映射被打破（A 身份读到 B 资源）；③session_key 明文到达客户端。
- **Suspected**（附假阳性排除清单）：①code 有效期短但无文档（需 T1 复用证据）；②平台侧拦截了错配（判定记录指向平台而非目标 = 不算目标缺陷，标注平台行为）；③前端登出语义完整但服务端有 TTL（需 T6 会话表证据定性）。
- **negative_valid**：一次性/绑定/撤销全部拒绝且正对照可用。
- 平台差异纪律：微信/抖音/支付宝分别出三态结论，**不因接口同名推断行为一致**（W10 备案/隐私治理类发现转 miniapp-privacy-governance 口径分开定性）。

## 四、Execution Profile 标注

- production_safe（默认）：全部操作限自有测试小程序与 Canary 测试身份；**不访问真实用户账号**；平台侧接口只观测不压测；换会话压测限频（≤ROE 额度）。
- isolated_lab：可在靶场完成完整换取链正负对照（自建后端日志取证）。

## 五、产出对接

- record_finding：cwe=CWE-798/T1-T2（硬编码与校验缺失）、CWE-639/T3（越权对象引用）、CWE-613/T4/T6（会话失效）、CWE-200/T5（信息暴露）——detail 引用本技能判据项；update_coverage(vuln_class=W7登录态, notes 记 `T1-T6 三态 + 平台分型`)；
- 配合技能：load_skill miniapp-server（解包 API 与签名链前置）、load_skill api-idor（T3 越权量化）、load_skill session-lifecycle（T4/T6 会话失效族并轨）；结论与 specB2《专项条目清单》W7 行对账。
