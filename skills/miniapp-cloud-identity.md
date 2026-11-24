---
id: "miniapp-cloud-identity"
title: "小程序云资源身份与部署边界（调用来源/HTTP 暴露/服务身份 IAM/数据库规则/存储/环境差异）"
tags: "小程序,云开发,云函数,身份,iam,部署边界,security-rules,specB2,b2,s4"
---
# 小程序云资源身份与部署边界（specB2 W9 配套——「客户端规则通过」≠「服务端安全」）

> 定位：miniapp-audit W5 覆盖「云函数未授权调用/security rules 越权」的基础面，本技能把 **W9 云资源身份与部署边界**拆到入口矩阵——云函数调用来源、HTTP 暴露、服务身份/IAM、数据库规则、对象存储及开发/生产配置差异逐项盘点与验证。
> 判定铁律（深度研究 W9 节）：**五条入口链分别验证——不能用「客户端直连被过」代替「服务端函数权限安全」结论**；过宽服务角色只有在**有效资源范围实测**后才是 Confirmed 配置越权，否则 Suspected/配置风险；公开资料不足的平台单元格标「未核实」，不推断。

## 一、云资源入口矩阵盘点（产出《云身份边界矩阵》——逐平台逐格留证）

| 入口 | 核查点 | 验证方法 |
|---|---|---|
| 客户端直连（SDK 规则） | 数据库 security rules / 存储规则对匿名与测试身份的读写允许面 | 测试身份最小探针（读/写/列举） |
| 云函数调用来源 | 哪些身份/来源可触发（SDK invoke / 定时 / 触发器） | 未授权 invoke 负对照 |
| HTTP 入口 | HTTP API 网关暴露面（公网可达函数/路径枚举） | 探测+限频枚举（禁爆破） |
| 服务身份/IAM | 函数运行角色的资源权限（DB/存储/管理面） | 受控 Canary 对象上实测有效资源范围 |
| 管理面 | 云管理 API/控制台凭据面（不在授权内只记录） | 只盘点不触碰（越管理面 = 需再授权） |

## 二、W9 测试矩阵（每项：步骤→判据→三态；全部用无敏感数据的受控 CANARY-W9 对象与 A/B 测试身份）

| T | 测试项 | 步骤 | 判据 | 判定 |
|---|---|---|---|---|
| T1 | **客户端规则越权读写** | 测试身份（A）对 B 的 Canary 对象做读/写/列举三探针 | 跨主体可达 = Confirmed（规则允许跨主体）；拒绝 = negative_valid | Confirmed/negative_valid |
| T2 | **云函数未授权调用** | 未登录/错参数负对照调用 + 参数注入（拼到 Canary 对象） | 未授权触发成功且操作 Canary 资源 = Confirmed；拒绝 = negative_valid | Confirmed/negative_valid |
| T3 | **HTTP 暴露面** | 云函数 HTTP 触发器枚举（限频、字典收敛）+ 未鉴权调用 | 公网可达且无鉴权执行业务 = Confirmed（HTTP 入口未授权） | Confirmed |
| T4 | **服务身份/IAM 有效范围** | 函数内（经注入面/业务功能）访问跨 Canary 资源：列举/读取/写 | 角色可触达超出业务需要的资源范围 = **配置越权（Confirmed 需实测资源范围）**；无法实测 = Suspected/配置风险 | Confirmed/Suspected |
| T5 | **开发/生产环境差异** | 开发环境配置/临时凭据/测试数据在生产可达性（据 W2 审计线索验证） | 开发配置在生产生效 = Confirmed（环境隔离缺失） | Confirmed |
| T6 | **对象存储边界** | 存储桶/对象 ACL 匿名列举/越权读（Canary 对象） | 匿名列举/跨主体读 = Confirmed（ACL 过宽） | Confirmed |

## 二.5、命令骨架（T1/T2/T4 最小可执行序列；平台 API 以当版文档逐字核对）

```bash
# T1 规则越权（测试身份 A → B 的 Canary 对象；三探针全记录响应形态）
#    SDK 读：<cloud> db.collection("canary").doc("<B对象id>").get()
#    判读：[200+B数据] = Confirmed；[权限拒绝] = negative_valid（正对照：B 身份必须可读）
# T2 云函数未授权调用（负对照 + 参数注入到 Canary 对象）
curl -s -m 10 "$CLOUD_FUNC_URL?op=read&id=$CANARY_B" -w "\n[未授权invoke] [%{http_code}]\n" | tail -1
# T4 服务身份有效范围：经函数业务参数（如 export/format 拼接）触达跨 Canary 资源
curl -s -m 10 "$CLOUD_FUNC_URL?op=export&target=$CANARY_B_KEY" | head -c 200; echo
#    [返回B对象内容] = 服务角色越权（Confirmed：有效资源范围实测）；[拒绝] = negative_valid
```

## 三、判定判据（深度研究 W9 节口径）

- **Confirmed**：①跨 Canary 主体读写被规则/函数放行（响应差分+正对照）；②HTTP 入口未鉴权执行业务；③服务角色有效资源范围实测越权；④环境配置越界生效。
- **Suspected**（附假阳性排除清单）：①服务角色过宽但**有效资源范围未实测**（标注「配置风险，未验证可达」）；②规则允许读但对象全空（无敏感数据 ≠ 安全，标「规则过宽+无敏感数据佐证」）；③平台托管规则缓存延迟（复测两次定性）。
- **negative_valid**：五入口全部拒绝且正对照（A 自己的资源）可用——正对照不可用 = 环境缺陷需修复后重测，不得直接下「安全」结论。
- **未核实纪律**：支付宝云管理面/IAM 公开资料不足的单元格标注「未核实」，不猜；各平台（腾讯云开发/抖音云/支付宝）入口矩阵分列，不假设同构。

## 四、Execution Profile 标注

- production_safe（默认）：全部 Canary 对象（无敏感数据）；管理面只盘点不触碰；HTTP 枚举限频禁爆破；跨环境验证只读。
- isolated_lab：可完整演练五入口链（含函数内注入路径取证），收尾恢复规则/角色配置并留快照。

## 五、产出对接

- record_finding：cwe=CWE-285/T1/T4（授权缺失）、CWE-306/T2/T3（关键功能未授权）、CWE-732/T4/T6（资源权限过宽）——detail 引用入口矩阵格与 Canary 差分；update_coverage(vuln_class=W9云身份, notes 记 `入口矩阵逐格三态 + 正对照可用性`)；
- 配合技能：load_skill miniapp-server（云函数调用链还原）、load_skill cloud-security（云 IAM 通用矩阵）、load_skill evidence-standard（确证判据）；结论与 specB2《专项条目清单》W9 行对账（未核实单元格如实标注）。
