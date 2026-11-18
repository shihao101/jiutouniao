---
id: "org-member-abuse"
title: "组织/成员管理逻辑滥用（邀请提权/移除残留/角色传播/层级穿越）"
tags: "组织,成员,邀请,角色,权限残留,多租户,s4"
---
# 组织/成员管理逻辑滥用（有"团队/组织/成员管理"功能的系统必测）

> 定位：成员管理把「角色」变成「可变更状态」——变更的**传播性**是全部缺陷的根因：
> 授予/撤销/降级任何一步不彻底，就留下残留权限。对象=邀请、移除、角色变更、层级四条状态变更链。
> 触发：目标存在组织/团队/工作区/成员管理/邀请码/角色分配功能（企业协作类/多租户类系统必触发）。

## 一、测试矩阵（在**自建测试组织**内操作，不触碰真实成员）

| T | 测试项 | 步骤 | 确证判据 | 判定 |
|---|---|---|---|---|
| T1 | **邀请提权** | 普通成员调邀请接口，请求体附加 `role:"admin"`（Mass Assignment）或改 role 参数 | 低权可发出高权邀请 = 水平链直达垂直提权 | 高（CWE-285）——logic-csrf-deser 联动 |
| T2 | **邀请码滥用** | 邀请码枚举（熵值）/过期复用/一次性验证（同码二次兑换）/跨组织兑换 | 可枚举或可复用 = 开放注册变体 | 中-高——identity-bootstrapping 邀请轨联动 |
| T3 | **移除残留** | 管理员移除成员 B → **B 的旧 token/API key/refresh 复放** | 移除后 B 仍可操作 = 移除不吊销（成员生命周期不闭环） | 高（CWE-285/CWE-613）——session-lifecycle T1/T2 同构 |
| T4 | **角色变更传播** | B 降权（admin→user）→ B 旧会话执行原 admin 操作；B 升权 → 旧会话是否即时获得新权限 | 降权不生效 = 残留提权（高）；升权不生效 = 可用性问题（低） | 高/低分列——session-lifecycle T9 联动 |
| T5 | **层级穿越** | 子组织成员读/写**父组织**或兄弟组织资源（tenant/inst/org_id 切换） | 跨层可达 = 租户隔离缺陷 | 高——instance-diff 联动 |
| T6 | **成员数据对象级越权** | 成员列表/详情/权限查询接口改他人 member_id | 可读他人成员档案（含邮箱/手机/角色）= 对象级越权 | 中-高——api-idor 联动 |
| T7 | **邀请竞态** | 一次性邀请码/名额限额 → 并发多请求同时兑换 | 多次兑换成功 = check-then-act 竞态 | 中——race-condition（check-then-increment 口径）联动 |
| T8 | **越级操作** | 普通成员直接调管理端点（移除管理员/改组织配置/导出全员） | 低权直调 200 = BFLA 管理面形态 | 高——api-idor BFLA 节联动 |

## 一.5、命令骨架（T1/T3/T5 最小可执行序列，多角色 token 由 session-state-chain 供给）

```bash
# T1 邀请提权：普通成员 token 发邀请，请求体附加 role=admin（mass assignment）
curl -s -m 10 -X POST http://目标/api/org/invite -H "Authorization: Bearer $TOKEN_LOW" \
  -H "Content-Type: application/json" -d '{"orgId":1,"phone":"<测试手机>","role":"admin"}' | head -c 200; echo
# T3 移除残留：管理员移除成员 B → B 旧 token 复放只读端点
curl -s -m 10 -X POST http://目标/api/org/1/member/remove -H "Authorization: Bearer $TOKEN_ADMIN" -H "Content-Type: application/json" -d '{"memberId":<B>}' | head -c 120; echo
curl -s -m 10 http://目标/api/org/1/summary -H "Authorization: Bearer $TOKEN_B" -o /dev/null -w "移除后B复放 [%{http_code}] len=%{size_download}\n"
# T5 层级穿越：子组织成员读父组织资源（tenant/org_id 切换）
curl -s -m 10 "http://目标/api/org/1/reports?page=1" -H "Authorization: Bearer $TOKEN_SUBORG" -o /dev/null -w "父组织资源 [%{http_code}] len=%{size_download}\n"
# 判读：移除/降权后 [200]+业务体 = 残留权限确证候选；[401/403] = 门控有效；写操作仅 L2+ROE 最小状态变更
```

## 二、判读纪律

1. **一切状态变更只在自建测试组织内**：测试组织=用客户测试账号自建（或索取时说明用途）；真实组织/真实成员绝对不动；
2. T3/T4 的复放判定**先只读后写**：旧 token 先复放只读端点确认"仍有效"，写操作按 L2+ROE 最小状态变更；
3. 邀请竞态属**额度制**：≤5 并发波、总量 ≤20 次兑换尝试，命中即停（对齐 race-condition 纪律）；
4. T1 的 role 字段注入需先做参数存在性侦察（injection-points），不可见 role 参数时改试组织设置端点直调；
5. 三态：确认=record_finding；门控有效=negative_valid；无对应功能面=not_applicable（登记不跳过）。

## 三、产出对接

- record_finding（cwe=CWE-285/863/613）+ update_coverage(vuln_class=成员管理，notes 记 `org_tested/total`，T1-T8 逐项)；
- 攻击树衔接：T1/T3/T8 任一命中 → "低权→管理员→全员数据"垂直链闭环，S8 影响评估单列（管理面接管）；
- 多租户类目标：T5 结果与 instance-diff 差分矩阵合并定性（同构实例 vs 层级隔离两族分开记）。

## v4.8 M6 工具通道兼容性声明

- 全部 T 项为受控请求：curl + 固定 header；多角色切换靠 session-state-chain 供多 token；
- T7 竞态用 race-condition 指定工具（Turbo Intruder/Turbospray 类，pipeline 参数按其表）；
- 无身份（无凭证项目）时本技能整体 deferred 移交——逐条 record_vt（W6 口径），不静默跳过。
