---
id: "api-field-exposure"
title: "字段级过度暴露差分（OWASP API3 · 角色间响应字段集合 diff）"
tags: "api,过度暴露,字段,敏感数据,authz,s4"
---
# 字段级过度暴露差分（API Top10 2023 · API3 Broken Object Property Level Authorization）

> 定位：authz-diff 只回答「端点可达性」（状态码级三态），本技能回答「可达的端点**多吐了什么**」——
> 同一对象在匿名/低权/高权三种角色下的响应**字段集合差分**。医疗/金融目标的必做项（PII/PHI 字段级泄露）。
> 对治事故原型：authz-diff 全 MISS 的目标，字段级 diff 照样揪出响应多吐 password_hash/身份证号的真实泄露。

## 一、触发条件（与 authz-diff 硬门串联）

1. authz-diff 矩阵中**每一行 HIT-DATA（200+业务 JSON）**→ 追加本技能字段级 diff（矩阵列 `field_diff` 回填）；
2. 任一匿名可达端点返回对象详情（用户/患者/订单/报告类）→ 必做；
3. 有身份会话时（session-state-chain 后）：低权 vs 高权同端点字段差分（低权多吐管理字段=属性级越权）。

## 二、方法（单变量原则：同一 URL，仅换身份态）

```
① 同一 endpoint × {匿名, 低权, 高权（若有）} 三角色各取 1 次响应（限速 1s）
② JSON 展平为点路径字段集合（a.b.c 视为独立字段；数组取首元素代表）
③ 三集合做差分：
   - anon ∩ sensitive_names ≠ ∅            → over_exposed_anon（匿名多吐敏感字段）
   - low 有而 high 无的字段                  → suspicious_low_only（低权特权字段，异常）
   - high 有而 anon 无的敏感字段             → 参考：确认服务端确有该字段（排除"本来就不吐"）
④ 敏感字段名判据表（中英双语、命中即标记）：
   password/passwd/pwd/salt/hash/token/secret/api_key/access_key/session/cookie/
   idcard/id_card/identity/ssn/phone/mobile/tel/email/birthday/birth/salary/
   bank/bankcard/card_no/diagnosis/medical/record/角色/权限/internal/created_by
⑤ 值掩码核对：字段名敏感 → 看值形态（真实数据/空/占位），只登记掩码样本（前 2 字符+***）
```

## 三、判读判据（三态，对齐引擎 E3）

| 观测 | 判定 | coverage |
|---|---|---|
| 匿名响应含敏感名字段且值非空 | **字段级过度暴露**（over_exposed）——record_finding（中/高视数据类；PII/PHI 直接高） | vulnerable |
| 敏感名字段存在但值恒为空/占位 | 设计冗余（防御纵深缺失，信息级登记，不占 finding） | negative_valid |
| 三角色字段集合一致且无敏感名 | 无过度暴露 | no_issue_found |
| 端点不可达/非 JSON/超时 | 未定性（不得 ruled_out） | needs_follow_up |

## 四、工具

```bash
python3 /opt/tools/field-exposure.py \
  --base http://目标:port \
  --endpoint /Api/User/Info \
  --role anon: \
  --role low:"Authorization: Bearer <低权token>" \
  --role high:"Authorization: Bearer <高权token>" \
  --out evidence/s4/field-exposure.tsv --delay 1
python3 /opt/tools/field-exposure.py --selftest   # 本地 canned 服务验证判读
```

- 无 token 可用（无凭证项目常态）：只跑 `--role anon:` 单角色，用第 ② 步敏感名判据 + 值形态核对定性；
- WAF/挑战目标：channel-snapshot 提取态注入 header 后跑（同 authz-diff M6 适配）。

## 五、纪律

1. **PII 值只做存在性证明**：掩码登记（前 2 字符+长度+哈希前 8 位），不下载不外传——对齐 ROE 数据边界；
2. 数组类响应（列表接口）字段 diff 用首元素；分页参数固定（page=1&size=1）最小化取样；
3. over_exposed 确证前按 evidence-standard 对照「敏感数据暴露类」判据（值非空 + 属业务不需要回传字段）；
4. 字段名匹配是启发式——命中后**人工核对业务必要性**（如患者端回显自己 phone 属正常，回显他人 phone 才是泄露）；
5. 与 api-idor 关系：IDOR=对象级（谁能看哪个对象），本技能=属性级（能看到对象的哪些字段）——同一对象可校验后仍需字段收窄验证。

## 六、产出对接

- record_finding（cwe=CWE-200/CWE-213）+ update_coverage(vuln_class=过度暴露，notes 记 `field_diffed/total`)；
- 端点表↔矩阵对账：coverage_gate 同口径对 `field_diff` 列计数（v5.3.9 起与 authz-diff 第五节硬门联动）。

## v4.8 M6 工具通道兼容性声明

- field-exposure.py：纯匿名单角色模式零会话依赖；多角色模式需会话态（session-state-chain 供 token）；
- curl：单端点手工三请求是字段 diff 的最小兜底（jq 展平：`jq -r 'paths(scalars) | join(".")'`）。
