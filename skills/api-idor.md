---
id: api-idor
title: API 测试与越权（IDOR/BOLA）手册
tags: api,idor,bola,越权,接口
---
# API 测试与越权手册（OWASP API Top 10）

## BOLA/IDOR（API1）
1. 用账号 A 抓全量接口清单（含 app/小程序流量）。
2. 标识对象 ID：自增数字、uuid、手机号、邮箱、订单号。
3. 账号 B 重放：替换 ID → 对比状态码与响应体差异（哈希对比）。
4. 盲场景（无 B 账号）：改 ID 观察是否 403/404 vs 200+空数据（差异在 body）。

## BFLA 垂直越权（API5）
- 普通角色调用管理端点：/admin/users DELETE 等；方法绕过 GET→POST、Content-Type 换 JSON。

## 限量拉取（API4）
- 分页 size=99999、page 快速遍历（限速）。

## SSRF（API7）
- Webhook/URL 预览/头像导入点：`http://169.254.169.254/latest/meta-data/`（云元数据，只取存在性）、`file:///etc/passwd`、内网 `http://127.0.0.1:port`。
- 重定向绕过、DNS rebinding（需审批）。

## 签名/重放
- 时间戳+nonce 是否参与签名；重放同一请求两次观察幂等。

## 产出纪律
- 每个接口×参数×漏洞类 = 一个覆盖单元；发现确证必须有 A/B 双账号响应证据（账号来自客户提供/索取闭环——水平越权按**同角色两个账号**供给；无凭据时 `idor-baseline.py` 匿名差分可确证 idor_anonymous 形态，需第二身份的单元按 v4.8 W6 路由 record_vt 移交，禁止静默跳过）。

## ORM filter 注入与跨功能对象搬运

- **ORM filter 注入**（高价值新面）：Django `{"password__startswith":"a"}` 逐字符提取、`{"author__user__password__startswith":...}` 关系遍历、`{"email__regex":"^(a+)+$"}` ReDoS；Prisma `prisma.user.findMany({where:req.body})` 嵌套 include 泄 password；Ransack `?q[password_start]=a` + plormber 自动化
- **跨功能对象搬运**：功能 X 泄露/合法持有的对象标识（mad/rightcode/馆 code）→ 搬到功能 Y 替换 → 判据=功能 Y 按被换对象执行。**隐藏 code 收集点：进入页面时初始化请求的响应里常一次性回显全部资源 code**
- **鉴权差横向推广**：一处免费/越权资源调用成立 → 立即把同参数模式套到同站其他写功能（发布/编辑/删除）
- **付费资源直链挖掘**：F12 看免费资源返回结构（mp4 直链）→ 定位 id 参数 → FUZZ 付费 id → 筛带资源直链的返回包 → 下载工具（自动带 Referer/UA）落盘
- **8 类系统化补强**：批量操作加他人 ID、导出端点 `user_id=*`、资源替换写 IDOR、PATCH 最易漏 method、收货地址三兄弟（增/改/删）、评论撤回换 comment_id、小程序 memberId 跨账号改支付密码、loginUuid+资源 ID 双参数
- **掩码重构**：A 端点 `138****5678` + B 端点 `1384***5678` 拼回全号；前端打*的字段传输层常是明文（评论区/播报栏/排行榜/转账提现/客服五处必测）

### IDOR 细分面补全

对象 ID 位置全清单（不只 URL/body）：Header `X-User-ID: 1234`、Cookie `user_id=1234`、GraphQL args `user(id:"1234")`、WebSocket 帧 `{"channel_id":9999}`、表单隐藏域。ID 形态补四行：UUID v1（时间戳+MAC，相邻可算，guidtool）；哈希 ID（md5(user_id)→对 1,2,3 做 md5 再试）；编码 ID（base64(`{"id":1001}`) 解→改→重编）；复合 ID（`/users/1/orders/5` 两个 ID 各自独立校验才算闭环）。双 ID 字段鉴权不一致：`{"userId":1234,"id":5678}` 分别改试；数组 `id[]=1234&id[]=5678` 取首/尾因栈而异（配 hpp）。组合链 IDOR：低权账号读 `/api/v1/users/1/details` 拾取管理员资料中的 auth token → 直接提权（按接管定级）。隐藏管理端点发现 5 法：JS bundle 搜 admin 路由、Swagger 搜 admin/internal 标签、枚举 `/api/v1/admin/**` `/manage/**`、Burp Discover Content、普通 vs 管理文档逐字段 diff。间接 IDOR（引用链）：父对象校验存在、子资源直访缺失——`/api/attachments/5678` 不校验归属；GraphQL 变体 `query{myProfile{followers{privateEmail}}}`。状态机跳步：订单 `pending→delivered` 直接跳态；B 账号改 A 的订单状态。
### 实战补遗（v4.4 一线 SRC 实战实证，已去标识）

- **越权面六类清单**：①隐藏 URL 权限管理（管理页仅对管理员隐藏入口，URL 泄露/可猜即越权）；②引用对象直接改 id（URL 加自己 id 可看，改他人 id 返回他人信息=水平越权）；③**多阶段功能第二步不再验身份**（改密流程第一跳验证码通过后，第二跳抓包改参数可改任意用户密码——每个多阶段功能单独测第二跳）；④静态付费文件 URL 命名规律可推 → 批量下载；⑤平台控件/网关配置错误致后台可达；⑥前端隐藏接口（S2-7 JS 承接）无服务端鉴权。
- **越权操作复用形态**：A 账号正常操作抓包 → 记录主体标识（loginUuid/userId）与资源标识（viewpointId/comment_id/orderId）→ B 账号上下文重放，主体标识保持 B、资源标识替换为 A 的 → 能读/改/删他人资源即确证。
- **撤回/删除类复用**：回复包携带他人 comment_id，替换后调自己的撤回接口 → 越权撤回/删除任意评论（写操作类越权证据等级高于读）。
- **越权+XSS 组合拳**：越权可改他人可见内容 + 存储型 XSS → 定向打管理员/受害者 cookie（capability-primitive-search 原语凑链：AUTHZ+XSS→CRED）。

## v4.8 W6 IDOR 自动基线增补（采样→自增判定→差分→量化）

- 标准件：`python3 /opt/tools/idor-baseline.py --url 'http://t/api/order/{id}' --start <N> --count 5 --cookie <会话态> [--owner-grep 'owner=([0-9]+)']`——输出 verdict（idor_anonymous/idor_predictable_only/inconclusive/not_found）+ 可枚举区间量化 + 匿名差分单次重放；会话态来源 channel-snapshot。
- 口径：采样仅读邻域（存在性证明）；量化只报计数不导出数据；判定 idor_anonymous 时 access=anonymous 登记（impact_rank=3 候选）；idor_predictable_only 需第二身份差分——无凭证项目登记 VT 移交（W4 六轨衔接）。
