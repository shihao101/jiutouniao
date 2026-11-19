---
id: session-state-chain
title: 会话态测试链（注册→登录→会话保持→带态测试→清理）
tags: 会话,登录,session,cookie,越权,存储型,注入,s4,s5
---
# 会话态测试链（认证前置类漏洞的标准路径）

适用场景：**漏洞测试前置依赖登录态**——登录后才可注入、越权矩阵、存储型 XSS、订单/资料逻辑滥用。实测教训：登录面万能密码失败后直接放弃测试（login-gated 注入零结论），缺的就是这条标准路径。

## 一、决策树（何时走本链）

```
测试项需要登录态？
├─ 有测试账号/ROE 提供凭据 → 直接 B 步登录
├─ 无凭据 + ROE auto_register=allow + 注册开放 → A 注册链
├─ 无凭据 + ROE auto_register=deny（v5.1 默认）→ L1 只评估不注册；
│   其余轨（auth-bypass/重置/默认口令/browser-auth）→ 仍无身份 →
│   identity-bootstrapping v5.8.0 口径（不主动询问；用户主动提供的凭据经 request_credential 入库）；
│   拒绝/超时 → update_coverage(premise_failed, notes「ROE 禁自建且客户未提供账号」) 移交，禁止硬磕
├─ 无凭据 + 注册关闭 → 先走 auth-bypass（万能密码/重置/默认口令）；仍失败 →
│   update_coverage(premise_failed, notes「无凭据且注册关闭」) 移交，禁止硬磕
└─ 登录面有加密协议/验证码/UA 指纹 → load_skill browser-auth（真实浏览器合规登录）
```

## 二、A 注册链（ROE auto_register=allow + 注册开放时；v5.1 默认 deny 不执行）

1. 唯一标记账号：用户名/邮箱带任务标记（如 `jt_test_<随机6位>`），record_loot 掩码登记（凭据不落盘，摘要+verified 状态）。
2. 注册响应逐字段核对：成功/失败提示差异（用户名枚举顺带记录）、默认权限（首个测试用户是否自带角色）。
3. 邮箱/短信激活类：配合 logic-sms-otp-matrix 判读（响应含 code / 有效期长 / 六路径矩阵）；ROE 禁止短信轰炸时跳过轰炸变体。

## 三、B 登录与会话保持

1. 登录请求一次留证（curl -sv），成功判据=Set-Cookie/跳转/响应体三选一确认，**不凭单次 200 断言登录成功**。
2. cookie jar 落盘复用（`-c jar.txt` 存、`-b jar.txt` 用），后续全部带态测试统一引用；多账号（水平越权对照）用 jarA/jarB 分文件。
3. CSRF token 类表单：先 GET 取 token 再 POST（两步脚本封装），token 失效重取一次，连续失效记入 notes。
4. 登录后基线：抓取登录态专属端点清单（菜单/接口），登记为「带态测试面」——这部分端点在匿名基线里不可见，是盲挖主战场。

## 四、C 带态测试（按漏洞类）

| 漏洞类 | 带态测试要点 |
|---|---|
| 登录后注入 | 注入点在登录态专属端点（订单/资料/搜索），载荷经会话提交；基线=同会话正常请求 |
| 水平越权 | 双账号 jarA/jarB 互访对象资源；改 ID/改名/改路径三种变体，对照请求留证 |
| 垂直越权 | 低权账号请求高权端点（从 s1 资产/菜单/JS 提取），关注只读面先证可达再证操作 |
| 存储型 XSS | 只对测试账号自身注入（多用户系统禁投他人可见载荷），取出重渲染位逐一检查 |
| **会话生命周期（v5.4.5 必做）** | 会话建立成功即 load_skill session-lifecycle：T1-T9 生命周期矩阵（登出吊销/改密踢会话/refresh 重放/超时/remember-me）——会话怎么死与怎么建同等重要 |
| 逻辑滥用 | 限购/重放/负数/并发——race-condition 与 logic-purchase-limit 剧本，带态是前提 |

## 五、D 清理（S7 承接）

1. 注册账号、自建数据按 v5.1.3 清理铁律：**只登记不删除**——先 SELECT 后登记（受影响行集写《需人工清理清单》四元组移交人工），不执行 DELETE/注销还原类操作。
2. 会话注销：测试结束执行 logout（防悬挂会话被他人利用）；jar.txt 含凭据等价物，收口前删除工作区内的 jar 文件或掩码移出交付物。

## 六、判据与留痕

- 每步成功判据可复核（响应差异/状态码/内容变化），禁止「应该已登录」类假设推进。
- 全部带态测试 update_coverage 引用账号标记与 jar 文件名；前提失败走 premise_failed 并注明缺什么（凭据/注册开放/验证码通道）。

## v5.5.0 凭据仓库与带态注入（方案 A 接线）

- 会话基线盘点后：每个采集到的会话（token/cookie）store_credential 入库（identity=会话名，kind=cookie/bearer/header），list_credentials 盘点带态资产；
- 生命周期矩阵（T1-T9）复放：http_request auth_ref 按行显式引用身份（登出/改密/超时场景切换同一 identity 的不同 session 文件：operator/session-1 与 operator/session-2 分别入库）；
- 证据纪律：请求/响应凭据自动掩码；明文不入 findings/交付物。
