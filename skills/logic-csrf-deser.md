---
id: logic-csrf-deser
title: 业务逻辑滥用 · CSRF · 反序列化 检测与安全验证手册
tags: csrf,逻辑,业务逻辑,反序列化,越权,竞态,支付,重置,s4
---
# 业务逻辑滥用 · CSRF · 反序列化 检测与安全验证手册

覆盖三类常被自动化扫描器漏掉的漏洞类：**业务逻辑漏洞、CSRF、反序列化**，以及越权矩阵方法论。动手前先通读本手册；结论必须命令留证，禁止凭特征断言。

## 一、业务逻辑漏洞（Logic）

自动化工具扫不出来，只能靠「理解业务规则 → 违反它」。

### 1. 常见测试点清单

| 场景 | 测试方法（示例命令骨架） |
|---|---|
| 支付/订单金额篡改 | 抓下单/支付请求，改 `price/amount/total` 为 0、负数、0.01、超大数据：`curl -s -b "$CK" -X POST -d "pid=1&price=0.01&num=1" http://target/order` |
| 数量/库存边界 | `num=-1`、`num=0`、`num=99999999`、小数；观察余额/库存是否穿透 |
| 优惠券/兑换码滥用 | 同一码重复兑换、并发兑换（`for i in $(seq 1 20); do curl ... & done; wait`）、兑换码爆破（限 ROE 允许时） |
| 重置/找回流程 | 重置 token 是否可预测/复用（同一 token 用两次）；改请求中的 `uid/email` 参数为他人邮箱（水平接管）；验证码是否回显/可爆破 |
| 短信/邮件轰炸 | 同一请求重放 20 次（ROE 限速下），观察限频 |
| 签到/积分/抽奖 | 重复提交、跳过步骤（直接调最终接口）、时间参数伪造 |
| 越过前置步骤 | 直接访问第 3 步接口而跳过 1、2 步（订单确认页直提） |

### 2. 验证纪律

- 每个逻辑测试点：先正常流程走通（基线），再单变量违反规则，对比响应差异。
- 涉及写入的业务测试（下单、兑换）只做最小影响（1 单、最低额），产生的业务数据行按 v5.3.0 清理铁律**只登记移交、不执行还原**；真实订单/支付状态变更仅在测试租户/合成对象上进行（production_safe 模式下优先只读结构分析）。
- 竞态测试并发数 ≤20，ROE 禁止 DoS 时不做。
- **无凭证三态路由（v5.1）**：①客户提供测试账号 → 全流程；②仅匿名 → 重置/找回流程（匿名入口）、无 token 重放判据、跳步直接调用等**匿名可达单元**照测，依赖账号态的单元逐条 record_vt/needs_follow_up 移交（禁止静默跳过）；③无入口 → needs_follow_up 显式登记。禁止自动注册（ROE identity.auto_register）。

## 二、CSRF（跨站请求伪造）

### 1. 检测清单（对每个状态变更端点）

```bash
# ① 是否存在 CSRF token：抓正常请求看参数/header（csrf/token/_token/authenticity_token）
curl -s -b "$CK" -X POST -d "action=change&value=new" http://target/user/setting | grep -iE "csrf|token" 
# ② 无 token 直接重放是否成功（核心判据）：响应 200 且状态实际变更 = 无防护
curl -s -i -b "$CK" -X POST -d "action=change&value=new" http://target/user/setting
# ③ Referer/Origin 校验：剥离或伪造跨域 Referer
curl -s -i -b "$CK" -H "Referer: http://evil.example/" -X POST -d "action=change&value=new" http://target/user/setting
# ④ Cookie SameSite 属性（SameSite=Lax/Strict 可缓解 CSRF）
curl -s -i -X POST -d "u=x&p=y" http://target/login | grep -i set-cookie
```

### 2. 判定与 PoC

- 判据（同时满足）：**无 CSRF token 或服务端不校验** + **无 Referer/Origin 校验** + **Cookie 无 SameSite（或 Lax 下非 GET 可打）** + 请求可跨站构造（无自定义 header/一次性参数）。
- PoC（写入 poc/csrf_<端点>.html，无害演示：改自己的资料字段）：

```html
<!-- CSRF PoC：仅演示，目标为测试者自己的账号 -->
<form id=f action="http://target/user/setting" method="POST">
<input name="action" value="change"><input name="value" value="csrf-poc-mark">
</form><script>document.getElementById('f').submit()</script>
```

- 验证：用受害者（测试者自己）会话加载该页后，检查状态是否实际变更（只读确认）。

## 三、反序列化（Deserialization）

### 1. 特征识别（被动观察为主，主动验证需无害探针）

```bash
# PHP session/cookie/参数中的序列化特征（O:类名:长度:...）
curl -s -i -b "$CK" http://target/ | grep -oE 'O:[0-9]+:"[^"]+"|[abdis]:[0-9]+:'
# phar:// 流包装器（上传点 + 文件操作函数组合才可利用）
grep -o "phar://" poc/*.log 2>/dev/null
# Java 序列化魔数 aced0005（base64: rO0AB）
curl -s -b "$CK" http://target/api/export | grep -o "rO0AB" | head -1
# Python pickle 特征（gASV base64 / 8002 95 二进制）
curl -s -b "$CK" http://target/api/state | grep -o "gASV" | head -1
```

### 2. 安全验证方法（禁止真实利用）

- 发现序列化数据可控点后：先用**无害对象**验证反序列化是否发生（如 PHP 构造 `O:8:"stdClass":0:{}` 观察行为差异/报错变化）。
- gadget 链利用（如字段伪装、RCE 链）**不做真实执行**——存在可控反序列化点 + 目标框架已知 gadget = 登记为「高危/待验证」，给出利用条件与建议修复，ROE 允许且影响可控时才做最小化验证。
- 报告必须写明：注入点、序列化格式判定依据、验证步骤、为什么不深入（合规/影响）。

## 四、越权矩阵（与 api-idor 手册配合）

1. **建矩阵**：角色 × 资源 × 操作（读/写/删），用**客户提供的**两个测试账号（水平越权=两个同权账号；垂直越权=低权+高权各一，经身份索取闭环获得——identity-bootstrapping 一a）分别持有会话；**禁止自动注册（ROE identity.auto_register 默认 deny）**；无凭据时本矩阵整体按无凭证三态路由移交。
2. **水平**：A 的会话逐个替换请求中的 `uid/order_id/user_id` 为 B 的资源 ID（遍历 1..N），记录哪些返回 B 的数据。
3. **垂直**：普通用户会话直接请求管理员功能端点（/admin/*、role 参数改写、Mass Assignment：注册/资料更新时附加 `role=admin` 字段——**注册位 mass assignment 仅 ROE allow 执行；deny 下转 record_vt，同 identity-bootstrapping 一节**）。
4. **无对象级授权判据**：返回他人数据 200 + 内容可区分 = 确证；仅状态码相同无内容差异不算。
5. 全部结论 update_coverage（越权类），发现的每条越权附双账号证据。

## 五、收录纪律

- 逻辑漏洞必须给出「正常 vs 违规」两组响应对比作为证据。
- CSRF 必须四要素齐全才登记（缺一标 needs_follow_up）。
- 反序列化只登记有特征证据 + 验证步骤的；未验证的 gadget 链标「待验证」。

## 支付/权益/邮件变体

- **四舍五入精度差**：余额与第三方支付只到分——充值 0.019 显示 0.01、到账 0.02；**举一反三到提现侧**（提现 1.005 实收更多）：同一模式换功能点复测
- **代金券拆分并发**：大额券拆多次小额订单，最后一单并发两单均扣券均成单（50 元券买 53.8 元资源）
- **阶段奖励跳步**：走一次全流程拿"置完成态"+"领取"两包，step 参数与任务序号对应 → 直接构造第 N 任务
- **CSRF 变体——头像 URL=退出链接**：个人资料头像 URL 可控时填站点 logout 链接，浏览者被强制登出（中危）
- **导出邮件参数篡改**：企业导出个人信息邮件的收件人/内容参数可改且发件人为官方域名 → 伪造官方钓鱼
- **`{"price":{"$gt":0}}` NoSQL 操作符**入价格比较
- **数组参数叠券**：`couponid[0]=SAVE20&couponid[1]=SAVE30`

### CSRF 深化与 JSON/multipart

token 校验缺陷四型：跨用户 token（只验存在不验归属）；token 仅存 cookie/双提交破坏（子域 XSS 写 `.target.com` cookie → 表单提交同值 → header==cookie 即过）；静态/可预测 token（全用户同值/base64(username)/md5(session_id)/时间戳）；改随机值仍成功。SameSite 两个 bypass：子域 XSS=same-site origin（Lax/Strict cookie 照发，XSS 作 CSRF 跳板）；Chrome Lax 2 分钟豁免（新设 cookie 跨站 POST 也带，OAuth 流设计→竞态窗口）。

JSON CSRF 三法：fetch 法（需 ACAO 回显+ACAC）；**text/plain 降级表单**：`<form enctype="text/plain" method="POST"><input name='{"email":"attacker@evil.com","ignore":"' value='"}'></form>`（产出 body: `{"email":"attacker@evil.com","ignore":"="}`）；multipart 仍被处理即中（FormData 版 PoC）。OAuth state 缺失完整四步：攻击者发起 OAuth 拿 code → 截回调 URL 发给受害者 → 受害者浏览器换 code 绑到攻击者主体 → 攻击者可登录受害者账号。CSPT2CSRF：前端 fetch 路径段填 `../../admin/dangerous-action` → 同源请求天然免 token/免 SameSite（检测=路径段输入校验）。GET 版本探测：`<img src=".../delete-user?id=1" style="display:none">`（配 Lax 判据）。int32 溢出：`quantity: 2147483648` 溢出为负反向入账。支付参数扩展清单：currency（换低值币种）/payment_method（切 sandbox 网关）/installments（0/负）/return_url+notify_url（指向攻击者截获确认）/receiver（收款改人）。回调伪造三查：验签名/验源 IP/幂等。状态机绕过表：改响应 `{"step":"1","allowed":"false"}`→`{"step":"3","allowed":"true"}`；会话交换；回放前序步骤改数据。验证码 OCR：pytesseract + 灰度/二值化预处理。重置 token 可预测形态表：md5(username)、md5(email+timestamp)、base64(user_id)、纯序号、短随机。应用层 DoS 判据（ROE 禁 DoS 时仅登记）：CVE-2015-4024 multipart 回溯、CVE-2020-13935 Tomcat WS 帧、CVE-2013-2028 Nginx 负 chunk。
### 实战补遗（v4.4 一线 SRC 实战实证，已去标识）

- **支付包挑选**：一次支付 3-4 个数据包，逐包分析敏感参数——账号/单价/数量/金额/余额/优惠/订单 ID 全部尝试篡改；"总金额=单价×数量"类逻辑改单价最常见。
- **代金券拆分并发**：可拆分代金券（如 50 元券多次 10.8 元订单）在券余额耗尽边界做**最后 1-2 单并发**（Turbo Intruder）→ 两单同时 0 元支付，超额抵扣——race-condition 联动（load_skill race-condition 的业务逻辑特例）。
- **异步通知面**：服务器端异步通知（notify_url）的签名验证缺失/金额校验缺失/订单状态一致性缺失是支付逻辑三查项；浏览器跳转通知面参数易篡改。
- **注册覆盖链**：注册同名邮箱/用户名直接覆盖旧账号密码（重置 22 矩阵之外的注册面形态）——**评估态仅做流程还原与响应差异观测；实测需 ROE allow 且仅对客户提供的专用孤儿测试账号执行，禁止指向真实用户账号（存量数据铁律）**；注册流程与找回流程的字段口径三处一致性（注册/登录/查重）逐处核对。

## Execution Profile 标注（v5.3.2）

- **Lab Only 动作**：完整反序列化利用链执行（生产档以无害回显/随机标记证明可达性即止）——仅 isolated_lab（可快照回滚的隔离靶场，项目显式声明）可执行；production_safe 下引擎逐动作强制禁止（v5.3.1 governanceGates 全通道确定性拦截并留证），不要尝试绕行。
- **production_safe 口径**：只做存在性证明（无害回显/随机标记/受控 OOB/量级与哈希证明），可达性证明即止。
- **工件处置两档分流**：生产=四元组（路径/指纹/建议清理命令/验证命令）登记移交《需人工清理清单》；实验室=快照恢复/环境重置回收（恢复成功须只读验证）。两档均不执行目标侧删除/还原。
