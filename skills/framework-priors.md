---
id: "framework-priors"
title: "K2 框架先验卡（首批四件：指纹→先验假设→首查清单）"
tags: 框架先验,K2,指纹,先验假设,s2,s3,首查
---
# K2 框架先验卡 · v4.8 首批四件（框架指纹 → 先验假设 → 首查清单）

> **定位**：s2 指纹识别 / s3 筛查矩阵判定 / s4 测试执行的跨目标先验知识卡。指纹命中 → 先验假设（挂筛查矩阵类）→ 首查清单直接执行。
> **口径**：先验是**假设生成器不是结论**（v5.3.0 反幻觉补充：每个先验仅影响**测试排序**，不得直接生成 Finding；升格必须由该目标实测证据触发——行业常见漏洞 ≠ 该目标已存在）——全部首查项结论仍以实测为准（loop-core 纪律 7：目标类型无关，一切结论从实测行为推导）；组件版本命中 CVE 线走 cve-weaponization（版本→已知漏洞必做）。
> **配套**：矩阵判定表 C-07/C-13/C-15/C-22 等类的触发判定直接引用本卡；组件专项剧本（spring-family/php-family 等）是本卡下游深化。

## 卡一 · Java/Spring 系

**指纹特征**：`X-Application-Context` 头、/actuator 端点集、Whitelabel Error Page、`JSESSIONID`、`Shiro` rememberMe cookie（rememberMe=deleteMe）、fastjson 特征响应、rO0AB 序列化串、springdoc/swagger-ui 路径。

**先验假设**（挂矩阵类）：

| 假设 | 矩阵类 | 首查清单 |
|---|---|---|
| Spring Actuator 未授权端点面（env/heapdump/gateway） | C-22 | `/actuator`、`/actuator/env`、`/actuator/heapdump`、`/actuator/gateway/routes` 匿名 GET（heapdump 下载后只做密钥字符串提取，不落全量数据） |
| Shiro 反序列化面 | C-15 | rememberMe cookie 构造探针（以 DNS 回连确认，不投递破坏性 gadget） |
| fastjson autoType 面 | C-15 | JSON 探针 `{"@type":...}` 报错差分 + DNS 回连 |
| Spring Boot 管理端口分离 | C-11/C-10 | 8000-9090 段管理端口探测 + 路径规范化绕过 |
| swagger/doc 契约暴露 | C-07 | `/v3/api-docs`、`/swagger-ui/`、`/doc.html` 匿名可达性 |

**常见坑**：heapdump 大文件走 run_async；Actuator 返回 404 不代表不存在（可能 path 改名，用 `/actuator` 首页 401/404 差分判别）。

## 卡二 · PHP 系

**指纹特征**：`X-Powered-By: PHP/x`、thinkphp 路由报错样式（`ThinkPHP V5.x` 报错页）、`PHPSESSID`、`/composer.json`、phpinfo 页特征、`.user.ini`、TP 特征参数 `s=/index/...`。

**先验假设**：

| 假设 | 矩阵类 | 首查清单 |
|---|---|---|
| ThinkPHP 多语言/路由 RCE 面 | C-13 | 已知 payload 集单发探针（`?lang=../../` 类），命中即转 cmdi-deep 确证流程 |
| phpinfo/调试页残留 | C-22 | `/phpinfo.php`、`/info.php`、`/test.php` + 目录枚举短词表 |
| composer 泄露→组件面 | C-27/C-22 | `/composer.json`、`/composer.lock` 匿名读取 → 组件 CVE 对照 |
| 上传解析执行链 | C-14 | 上传点 `/.htaccess`/`.user.ini` 落点验证 + 路径回显 |
| PHAR 反序列化面 | C-15 | 文件流操作参数 `phar://` 探针 |

**常见坑**：TP 报错页含绝对路径/版本 → 直接喂给 cve-weaponization；宝塔/安全狗类前置先 load_skill gateway-filter-playbook 分型。

## 卡三 · Python 系

**指纹特征**：`Werkzeug/x` 调试PIN页特征、Django DEBUG 报错页（黄色页面）、`csrftoken` cookie、`/admin/` Django 后台、DRF `rest_framework` 样式、`/api/schema/`、`X-Frame-Options` 组合特征。

**先验假设**：

| 假设 | 矩阵类 | 首查清单 |
|---|---|---|
| Werkzeug 调试台暴露 | C-22 | `/console` 匿名可达性（PIN 弱熵假设：如果可达，PIN 熵实测） |
| Django DEBUG 开启 | C-22 | 404 触发 DEBUG 页 → 读 settings/URL conf/内网拓扑（信息直接喂 s3） |
| Django admin 弱口令 | C-01 | `/admin/` 可达性 + 锁定预言机探针（文案差分） |
| DRF 未授权差分 | C-07 | `/api/schema/`、ViewSet 路由匿名 GET/POST 差分（阳性对照法） |
| Jinja2 SSTI 面 | C-13 | 回显位 `${7*7}`/`{{7*7}}` 变体探针（回显位类 C-21 关联） |

**常见坑**：Django DEBUG 页本身就是高价值情报源（settings 泄露 DB/内网），发现即登记情报而不只是漏洞。

## 卡四 · Node/前端工程化系

**指纹特征**：`X-Powered-By: Express`、`/node_modules/` 可达、webpack chunk 加载、`sourceMappingURL`、`/graphql`、`.env` 探针特征、server.js/app.js 目录列表。

**先验假设**：

| 假设 | 矩阵类 | 首查清单 |
|---|---|---|
| .env/配置文件泄露 | C-22 | `/.env`、`/.env.production`、`/config.json` 匿名读取 |
| source map 还原 | C-22 | 主 bundle 尾部 `sourceMappingURL` → `.map` 可达 → intel-factory 四件套还原 |
| Swagger/OpenAPI 契约暴露 | C-07 | `/swagger`、`/api-docs`、`/openapi.json` 匿名可达 |
| GraphQL 内省/注入面 | C-07/C-13 | `/graphql` 内省查询（introspection）+ 批量查询资源耗尽探针（只做存在性） |
| 原型污染面 | C-13 | `?__proto__`/JSON merge 行为差分（prototype-pollution 剧本） |

**常见坑**：前端工程化目标的泄露面往往**先于**应用漏洞出现——先走 intel-factory 情报工厂清出端点表/密钥/内网拓扑，再回灌筛查矩阵判定（C-22 命中往往改变 C-07/C-11 的判定走向）。

## 与矩阵/行业的挂接

- 指纹命中本卡 → s3 判定表对应类**从「不适用」改判前必须完成首查清单**（首查即「不适用」的核查证据）。
- 先验假设全部未命中 → 该卡先验在判定表标注「首查完成未命中」，仍按矩阵通用判据执行。
- **指纹未命中任何卡（v5.1 兜底硬规则）**：①执行通用未授权首查（anon-attack-surface 全族批量普查 + authz-diff 无 token 全量矩阵）；②按指纹家族检索公开漏洞库（cve-weaponization/searchsploit，编号以检索输出为准）；③指纹属行业高频族时核对对应家族剧本（edu-family/idp-family/oa-family/edge-vpn-bastion）——三条全空才允许把该指纹标「首查完成未命中」。
- 行业叠加：K1 模板升格优先级照常生效（框架先验不改变行业升格）。
