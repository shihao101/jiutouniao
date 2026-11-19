---
id: race-condition
title: 并发竞态手册（双花/重放/限次绕过）
tags: race,竞态,并发,双花,单包,s4,s5
---
# 并发竞态手册（OWASP A04 不安全设计的实证面）

> 判据=「并发窗口内成功执行多次本应单次生效的操作」。**并发规模受控（≤10 并发、≤3 轮），禁 DoS 形态**；涉及真实资金/库存的业务只做状态对比不做真实下单（S5 审批后用最小金额或模拟单）。

## 一、高危点位

| 场景 | 判据 |
|---|---|
| 提现/转账/兑换 | 同一笔余额并发两次提现 → 余额负数/两笔成功记录（**仅测试钱包/最小额**） |
| 签到/抽奖/领取 | 同一日多次领取 → 记录数>1 |
| 优惠券/兑换码 | 一码多次使用 → 核销记录数>1 |
| 验证码/OTP 消费 | 同码并发多次校验通过 |
| 关注/点赞/投票 | 计数与记录不一致（超发） |
| 审批流/OA | 同单据并发审批产生双记录 |

## 二、探测方法

```bash
# ① 传统并发：同请求 N 份并发（互斥锁失效判据）
seq 10 | xargs -P10 -I{} curl -sk -X POST -b cookies.txt https://目标/api/claim -o /tmp/resp_{}.json
# ② 单包竞态（更稳）：对支持 HTTP/2 的目标用单连接多 stream（turbo intruder 思路，last-byte-sync）
# ③ 竞态窗口收窄变体：请求体尾部 sleep 字段差（stack of payload 时序差）
# ④ 先「预热」再竞态：会话/风控预热请求 → 并发主判据请求 → 静置读状态
```

## 三、判据与登记

- 成功判据固定三查：响应 status（多次 200/成功文案）→ **服务端状态复读**（余额/记录数，间隔 2s 再查 1 次防异步）→ 记录落 evidence。
- 排除误报：幂等接口（天然可重复）不算；有乐观锁版本号时改测版本号校验缺口。
- 确证 → record_finding（cwe-362）+ 业务影响换算（写「单次危害×可重复次数」，不夸大）。

## 四、纪律

- 资金类动作：仅在测试环境/测试钱包验证；生产环境只做**状态一致性只读复核**（疑似场景登记 needs_follow_up）。
- 并发测试前后各做一次系统状态快照（记录级），异常残留列入 S7 清理清单。
- **无凭证三态路由（v5.1）**：①客户提供测试账号/测试钱包 → 全量验证；②仅匿名 → 计数器类（阅读量/点赞）无凭证可测，依赖账号或资金的单元逐条 record_vt/needs_follow_up 移交（禁止静默跳过）；③无入口 → needs_follow_up 显式登记。禁止自动注册（ROE identity.auto_register）。

## 并发三子类扩展

- **计数器刷量**：每个访问 +1 的接口（阅读量/播放量/点赞/浏览数）→ intruder 千次放包 → 计数超真实访问量且影响排序。低危但 100% 可稳定复现，适合批量扫点位
- **数量/唯一性上限并发**：资源创建接口带"上限 N 个+重名校验"（书架/收货地址/标签/分组）→ 并发 N 份同请求 → 全部成功。**并发打点清单：签到、每日领积分、点赞、评论点赞、资源创建上限、领取奖励**；危害升级公式：与金钱挂钩才上中危
- **客户端时间信任**：APP 以本机时间判权益有效期 → 领最短试用 → 系统时间前移 → 以**功能可用性**为判据（头标消失但功能可用才是实锤）；时间后移做反向验证
- **工具语法**：Turbo Intruder gate 模板（concurrentConnections=30, requestsPerConnection=30，engine.openGate）；报文任意位置插 `%race%` 标记；多端点变体（1 个状态变更 POST + 30 个读取 GET 同 gate）；`x-request: %s` 关联头取证
- **高价值目标扩展**：不只优惠券——邮箱验证/OAuth 绑定/confirm 归属确认是高价值竞态（CVE-2022-4037 GitLab 邮箱验证竞态）

### 补遗

目标点位补：邀请/推荐/注册奖励类（invite_accept/referral_claim）。限频绕过竞态：限频=逐请求 check-then-increment 计数器时，N 发并发一波 vs N 发顺序对比——并发波内超限通过/锁死不触发（登录爆破接口同理）。多步流水线竞态（beat the pipeline）：`create→pay→confirm` 流程 confirm 未与 pay 密码学绑定时，两并行流水线 A 放弃 pay、B 完成 confirm → 未支付标记已付。白盒 TOCTOU 指纹：`balance = SELECT...; if balance >= amount: UPDATE...`（非原子）；分层缺陷表（应用 flag/ORM 无分布式锁/DB 缺 FOR UPDATE/网关限频 check-then-increment）；UNIQUE 约束与幂等键常整类消除——测热路径是否真强制。工具补：JavanXD/Raceocat、h2spacex、Burp Repeater Send group (parallel)；Turbo 参数补 pipeline=False/engine=THREADED/maxRetriesPerRequest=0。

## v5.8.0 竞态状态读回 Harness（Top#10：脚本化状态核验）

并发竞态的确证必须做**前后状态核验**（HTTP 判据只产候选）：

```
# 状态读回三步（tools-extra 现有 logic-invariant.py 思路的竞态版）
1) 前置态：并发前读回目标对象状态（GET 详情/余额/计数），存 evidence/
2) 并发窗口：race-condition 并发请求 N 连发（参数同 v5.4 节）
3) 后置态：读回状态并 diff——服务端状态变化超出幂等预期（如余额多扣、计数超发、
   订单重复创建）= 确证；仅 HTTP 200 无状态变化 = 前端假放行（candidate）
```

- 每次竞态验证必须产出：前置态证据 + 并发请求留证 + 后置态证据（三件齐才 record_finding）
- 幂等预期判定：对幂等接口（GET/幂等 PUT）状态不变属正常；对非幂等动作（支付/计数/兑换）状态多变为漏洞
