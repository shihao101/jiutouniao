---
id: api-doc-leak
title: API 文档泄露手册（Swagger/OpenAPI/Knife4j/Dubbo/Actuator 文档面）
tags: swagger,openapi,api文档,knife4j,dubbo,枚举,s4
---
# API 文档泄露手册（文档=现成攻击面地图，优先级最高的信息面之一）

## 一、文档端点清单（逐个探测，L0 只读）

```bash
# Swagger/OpenAPI 族
/swagger/index.html /swagger-ui.html /swagger-ui/ /api-docs /v2/api-docs /v3/api-docs
/openapi.json /swagger.json /api/swagger.json /docs/openapi.json
# Knife4j（国内常见增强 UI）
/doc.html /knife4j/doc.html /api/doc.html
# Spring Actuator 文档面（配合 spring-family）
/actuator/springdoc /v3/api-docs/swagger-config
# 其他形态
/druid/index.html（ Druid 面，连接串泄露判据）/eolink /yapi /torna 控制台
# RPC 文档：dubbo admin 面（8080）、grpc reflection（go-backend 联动）
# 移动端 API 文档：/m/docs、小程序接口文档位（miniapp-server 联动）
```

## 二、从文档到攻击面（自动衔接）

1. **端点枚举**：doc.json 解析 → paths×methods×参数表 → 直接生成 S4 待测队列（含参数类型/必填性）；**解析出的全部路径并入端点表（intel-factory ①，表尾 `# total=N`），进 authz-diff 全量矩阵——禁止抽样（v5.1 硬门）**。
2. **模型泄露**：schema 定义里敏感字段（idCard/password/token 内部字段）→ 敏感信息面。
3. **未授权试调**：无鉴权端点直接 GET（L0）；**try-it-out UI 交互只允许 GET/只读**（防误触真实业务动作）。
4. **写端点门控判定（v5.1 补偿条款，对治"只看不调=不测"覆盖空洞）**：POST/PUT/DELETE 端点的**门控存在性必须判定，不实调**——①OPTIONS 读 Allow 头枚举写动词；②无 token GET 探测（401/403/302→SSO/hasLogin:false=门控有效；200/500 控制器形态=绕过候选，authz-diff 判读表）；③门控缺失的写端点按 authz-diff `exploitability=conditional` 呈现，**写效果实测走 L2+ROE 最小状态变更（自建对象）**，禁止把"没实调"写成"已排除"。
5. **版本差异**：/v1 /v2 /v3 文档并存 → 老版本遗留端点（越权高发，api-idor 联动）。

## 三、隐蔽文档发现（文档被隐藏时）

```bash
# 前端 JS 里搜 swagger/api-docs 引用（S4 JS 下载分析已有物料）
grep -oE '"/(swagger|api-docs|doc.html)[^"]*"' evidence/s4_js/*.js
# 常见重命名：/api/v1/docs /apihelp /rest-docs /interface/list
# 响应嗅探：404 页面含 {"openapi"} / springdoc 404 变体 → 路径在但权限拦
```

## 四、纪律

- 文档泄露本身即 finding（cwe-1234 级别视内容）；解析出的端点全部登记资产台账（record_asset）。
- try-it-out 类交互只允许 GET/只读；POST 类参数构造仅做静态分析不实调；**写端点的门控判定按第二节第 4 条执行（只测门控不实调，禁止静默跳过）**。

### 文档内容提取清单

从 schema/示例提取 4 类攻击信号：①optional 与未公开字段；②admin-only 请求示例（管理端文档常混入同一 doc）；③`additionalProperties: true`（mass assignment 直通信号，api-idor 联动）；④参数名带 filter/sort/id/role/tenant 字样 → 直接记入越权与批量遍历候选。补充文档路径：`/.well-known/`、`/graphql`、`/gql`、`/legacy/`、`/api/mobile/v1/`。