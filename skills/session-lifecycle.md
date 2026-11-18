---
id: "session-lifecycle"
title: "会话生命周期缺陷族（登出吊销/改密踢会话/refresh 轮换/超时/并发/remember-me）"
tags: "会话,生命周期,吊销,登出,refresh,超时,s4,s5"
---
# 会话生命周期缺陷族（OWASP A07 后半场——拿到会话之后测"会话怎么死"）

> 定位：session-state-chain 解决"会话怎么建立"，本技能解决"会话怎么失效"——**失效机制缺失=截获即长期重放**。
> 与明文传输类发现成链（截获→登出不吊销→长期重放），对医疗/金融目标是 A07 高产确证面。
> **开工前置：先完成第一节会话基线盘点（P3 有身份测试的第一步），逐项测试都依赖盘点表字段。**

## 一、会话基线盘点（P3 首动作，产出驱动后续测试）

| 盘点项 | 观测方法 | 喂养的测试项 |
|---|---|---|
| token 形态 | JWT（三段可解）/opaque 随机串 | JWT→jwt-crypto 解 exp/iat/jti；opaque→随机性评估 |
| 有效期字段 | exp 值距签发时长；无 exp=不 expiry | 第二节 T5（超时缺失定性） |
| 存储位置 | localStorage/cookie（HttpOnly/Secure/SameSite）| XSS 窃取链可行性（xss-context 联动） |
| 服务端会话表 | 改 token 单字符→400/401 形态 | 服务端校验 vs 纯客户端解（L5 伪造面） |
| 多 token 面 | access+refresh 双发？remember-me cookie？ | T4/T7 输入 |

## 二、生命周期测试矩阵（每项：步骤→判据→三态；全部用**自有测试账号**双会话操作）

| T | 测试项 | 步骤 | 确证判据 | 判定/定级 |
|---|---|---|---|---|
| T1 | **登出不吊销** | 会话 A 登录取 token → logout → 旧 token 复放受保护端点 | logout 后仍 200 返回业务数据 = 服务端无吊销 | record_finding 中-高（CWE-613）；配合长效 token 升高 |
| T2 | **改密不踢会话** | 同账号会话 A+B → B 改密 → A 旧 token 复放 | 改密后 A 会话仍有效 = 凭据变更不传播 | 中-高（CWE-613）；改密+踢会话全缺=凭据泄露后无法止损 |
| T3 | **改密不轮换标识** | 对比改密前后 access_token/会话 ID 是否变化 | 同一 token 跨改密继续有效 | 并入 T2 记（轮换缺失加剧 T1/T2 影响） |
| T4 | **refresh 轮换/重放** | 用 refresh 换新 token → 记录旧 refresh → **旧 refresh 二次兑换** | 旧 refresh 仍可兑换 = 无一次性/轮换 | 高（CWE-613）；被盗 refresh 永久续命 |
| T5 | **超时缺失** | 读 exp 字段（JWT）或长间隔复放；无 exp 且长期复放有效 | 30 天+长效且无服务端失效 = 绝对超时缺失 | 中（黑盒无法久等时按 exp 时长定性，标注「时长级证据」） |
| T6 | **并发会话策略** | 同账号三端同时登录 → 观察互踢/并存 | 并存且互不影响=无并发控制（定性，低） | negative_valid/信息级 |
| T7 | **remember-me 伪造** | 勾选记住我 → cookie 熵值/有效期分析 → 可预测则构造自有账号伪 cookie | 无随机性 cookie 直接管用 = L5 会话构造命中 | 高（转 identity-bootstrapping L5/L6 口径） |
| T8 | **改密流程完整性** | 改密不带 old_password 字段/填错旧密码 | 绕过旧密码验证成功 = 改密面缺陷 | 中（需已持有会话，影响=会话被劫持后可永久换锁） |
| T9 | **权限变更传播** | 角色变更（升/降）后旧会话复放原权限操作 | 降权后旧会话仍执行原操作 = 变更不传播 | 高（转 org-member-abuse 联动记） |

## 二.5、命令骨架（T1/T2/T4 最小可执行序列，双 token 由 session-state-chain 供给）

```bash
# T1 登出不吊销：token_a 登出后复放（二次复放排除响应缓存）
curl -s -m 10 -X POST http://目标/logout -H "Authorization: Bearer $TOKEN_A"; sleep 5
curl -s -m 10 http://目标/Api/User/Info -H "Authorization: Bearer $TOKEN_A" -o /dev/null -w "logout后复放 [%{http_code}] len=%{size_download}\n"
# T2 改密不踢会话：B 会话改密 → A 旧 token 复放
curl -s -m 10 -X POST http://目标/api/user/change-password -H "Authorization: Bearer $TOKEN_B" -H "Content-Type: application/json" -d '{"newPassword":"<RSA密文>"}' | head -c 120; echo
curl -s -m 10 http://目标/Api/User/Info -H "Authorization: Bearer $TOKEN_A" -o /dev/null -w "改密后A会话 [%{http_code}] len=%{size_download}\n"
# T4 refresh 重放：新 refresh 换 token 后，旧 refresh 二次兑换
curl -s -m 10 -X POST http://目标/token -d "grant_type=refresh_token&refresh_token=$RT_OLD&client_id=$CID" -w "\n旧refresh二次兑换 [%{http_code}]\n" | tail -2
# 判读：以上三处 [200]+业务体 = 生命周期缺陷确证候选（evidence-standard 对照）；[401/403] = negative_valid
```

## 三、判读纪律

1. **复放只打自有对象**：旧 token 复放的端点返回他人数据时只记存在性（401/200+数据形态），不消费不下载——对齐 ROE 数据边界；
2. T1/T2 的"仍有效"必须二次确认（登出后等待 5s 再复放一次，排除响应缓存）；
3. JWT 的 exp 判读属**时长级证据**：确证"缺失失效机制"还需 T1 登出复放作行为级证据，两者分开登记；
4. 三态：确认缺陷=record_finding；机制存在（logout 后 401）=negative_valid 入账；不可测（如目标无 logout 功能）=needs_follow_up 附原因。

## 四、产出对接

- record_finding（cwe=CWE-613 为主，T7 归 CWE-521）+ update_coverage(vuln_class=会话生命周期，notes 记 `lifecycle_tested/total`，T1-T9 逐项)；
- 链式组合：T1/T2/T4 任一命中 × 明文传输（F-明文类）× token 长效 → 攻击树"截获→长期重放"链闭环，S8 影响评估引用。

## v4.8 M6 工具通道兼容性声明

- 全部 T 项为**受控复放**：curl + 固定 header 即可执行，无工具依赖；双会话靠双 header 值（session-state-chain 供 token）；
- JWT 解码用 jwt-crypto 技能判读流程；挑战型目标复放需 channel-snapshot 注入态后执行。
