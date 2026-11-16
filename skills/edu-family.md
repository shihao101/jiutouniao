---
id: "edu-family"
title: "教育信息化族剧本（金智 ehall/正方/青果教务 + VSB/博达网站群 + 超星）"
tags: "教育,ehall,金智,正方,vsb,网站群,未授权,s3,s4"
---
# 教育信息化族剧本（K1 教育行业的家族层落地，v5.1 新增）

> 定位：高校/职业院校黑盒最高频资产族的指纹→未授权首查清单。全部探针 L0 只读；
> 未授权命中即 record_finding，利用级动作 S5 审批。**本表是首查下限不是全量——命中指纹后
> 仍须按 authz-diff 第五节省对端点表全量入矩阵（禁止抽样）。**

## 一、金智 wisedu 系（一站式服务大厅 ehall / 学工 / 人事）

**指纹**：`X-Application-Context: esop-gateway`、`/jsonp/constant.json`、amp.min.js、`emapAvatarUpload`、金智 rsfw 路径（`/rsfw/sys/<应用>/`）。

**未授权首查清单**（逐项 update_coverage）：

| # | 探针 | 判据 |
|---|---|---|
| 1 | `/jsonp/userInfo.json` 匿名 | 返回真实站点/菜单数据（非 hasLogin:false）=匿名信息暴露（低危，按 guest 数据边界判定） |
| 2 | `/jsonp/constant.json`、`/portal/js/conf/constant.js` 运行时配置 | 内含 **APIList 端点枚举**（67+ 端点常态）→ 端点表入 authz-diff 全量矩阵；含内网地址/密钥即泄露面 |
| 3 | `/jsonp/` 面全端点（APIList 展开）无 token GET | `hasLogin:false`=门控有效；200+业务数据=未授权访问（gateway-filter 二a 量化三件套）；302→CAS=门控 |
| 4 | 写操作端点（favoriteApp/feedbackSubmit/`attachment/feedbackUpload` 等） | **只测门控存在性**（GET/OPTIONS 判 401/302/hasLogin），实调 L2 |
| 5 | `/psfw/` 服务中台前缀 | 404 页指纹判后端（WebLogic 特征页=指纹面）；目录枚举受预算约束 |
| 6 | `/taskcenterapp/` 任务中心面 | 匿名可达性 + 常见路径探针 |
| 7 | rsfw extranet 面（招聘/校友类外网应用） | 注册入口评估（ROE 门控）+ callService 端点族（regist/checkExist/checkLogin 等）匿名可达性——checkExist=用户枚举预言机候选 |

**常见坑**：ehall 前端是 VSB/门户混部时 Host 头区分站点归属；CAS service 参数白名单校验（auth-flow-deep 联动）；rsfw 应用常走明文 http 跳转（配置缺陷线索）。

## 二、正方/青果/强智教务系

**指纹**：`/login.aspx`+`__VIEWSTATE`（ASP.NET）、`xsMain`/`xskbcx` 路径特征、正方 `HomePage.aspx`、青果 `/frame/` 系。

**未授权首查清单**：①登录页版本指纹（页脚版本号→cve-weaponization 检索）；②历史未授权接口族按版本检索（searchsploit/NVD——**编号以检索输出为准，禁止凭记忆**）；③成绩/课表查询接口匿名直调（401/302 差异）；④验证码逻辑（logic-sms-otp-matrix 联动）。教育初始密码规则（学号/证件号后位等）按 weak-cred-bruteforce 默认凭据矩阵执行，单账号 ≤3 次。

## 三、VSB 世纪兴 / 博达网站群（高校门户站群）

**指纹**：`vsb_content` 字段、`/system/resource/code/news/click.jsp`、`separatePlugins.min.js`、博达 `/system/_owned/` 路径、CustomerNO 泄露。

**未授权首查清单**：①`/system/resource/` 管理资源路径族匿名可达性；②`click.jsp?wbnewsid=` 参数注入单引号探针（sqli-deep 口径，一个单引号无信号即换面）；③`ipauth.htm` 认证页=内部内容被 ipauth 门控（记录门控形态，zxt 同构）；④/newsapi/ 或 vsb 服务接口族匿名面。同构站（同指纹多子域）共用过滤规则——单站 bypass 命中后同构复测（loop-core 纪律）。

## 四、超星泛雅/学习通

**指纹**：`chaoxing` 特征串、`/mycourse/`、`/work/` 路径、泛雅 `/api/` 面。

**首查清单**：课程/作业 API 匿名直调差异；`/mooc-ans` 系接口未授权面；按版本检索已知漏洞（检索纪律同上）。

## 五、纪律

- 本表全部为**首查清单**（覆盖下限）：命中指纹 → 清单执行 + 指纹家族公开漏洞检索 + 端点表全量入 authz-diff 矩阵，三者缺一不算完成；
- 生产数据只做存在性证明；学生 PII 类命中按 existence-proof 口径（count+哈希前缀）；
- 教育行业升格（K1 教育行业模板：学籍/成绩 IDOR 最高优先）继续生效。
