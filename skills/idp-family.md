---
id: "idp-family"
title: "统一身份认证族剧本（CAS/Shibboleth IdP/深澜 srun/企业 SSO）"
tags: "cas,shibboleth,sso,idp,统一身份认证,未授权,s3,s4"
---
# 统一身份认证族剧本（v5.1 新增：认证基础设施的匿名面首查清单）

> 定位：IdP/CAS 是高校与政务的认证枢纽——打不穿 IdP 也要把**它的匿名信息面**测全
> （元数据/状态端点/service 白名单）。全部探针 L0 只读；协议流程测试走 auth-flow-deep。

## 一、CAS（Apereo/金智封装）

**指纹**：`/cas/login` 页脚 "Apereo CAS"/Jasig、`CASPraviFix`/`TGC` cookie、302 `?service=` 回跳。

**未授权首查清单**（逐项 update_coverage，auth 类）：

| # | 探针 | 判据 |
|---|---|---|
| 1 | `/cas/status`、`/cas/v1/tickets` REST 端点匿名 | 200/405 差异判端点存在性与方法面；tickets 面匿名可写=高危候选 |
| 2 | `service` 参数白名单 | 任意外域 service 是否被接受（302 Location 判据）→ 开放重定向/票据投递面（auth-flow-deep 承接） |
| 3 | `serviceValidate`/`p3/serviceValidate` | 无票据/伪造票据响应差异（`<cas:authenticationSuccess>` vs Failure 形态）——响应 oracle 记录 |
| 4 | 登录页组件 | 验证码类型/用户枚举文案差分/锁定策略（T-17 口径，单账号 ≤3 次） |
| 5 | `/cas/oauth2.0/` 面 | 未授权端点与 client_id 枚举探针 |
| 6 | 密码找回入口 | `getBackPasswordMainPage.do` 类流程存在性；token 熵测试需流程内身份（record_vt 移交） |

## 二、Shibboleth IdP

**指纹**：`/idp/shibboleth` 元数据、`Shib-Session-ID`、8443 backchannel 端口、idp.war 特征。

**未授权首查清单**：①`/idp/shibboleth` 元数据内容判**默认示例 vs 定制**（含 "This is example metadata only" 字样=部署痕迹发现，F 级信息泄露）；②`/idp/status`、`/idp/profile/Status` 状态端点匿名可达（版本信息泄露）；③`/idp/profile/Metadata/SAML2` 动态元数据暴露面；④证书解析（openssl 判自签/有效期/密钥强度——零流量本地分析）；⑤属性泄露：`/idp/profile/SAML2/SOAP/AttributeQuery` 匿名响应形态。

## 三、深澜 srun / 企业 SSO 网关

**指纹**：`srun_portal`、`/cgi-bin/` 计费路径族、`srun_bras` 特征；企业 SSO（OneAuth/竹云类）登录域。

**首查清单**：portal 页脚本信息泄露（build 号/内网地址）；`cgi-bin` 接口族匿名直调差异（401/403/200 判读）；自助服务面（`/srun_portal_pc.php` 类）与找回密码流程存在性。

## 四、纪律

- 本族命中的价值常在**认证外围信息面**（元数据/状态/配置）与 **service 白名单逻辑**——单独低危，凑链时是 CRED/AUTHZ 原语的跳板（capability-primitive-search 联动）；
- 爆破/枚举一律受 weak-cred-bruteforce 锁定纪律约束；OAuth/SAML 流程伪造类走 auth-flow-deep 的 L2 门；
- 指纹命中本表 → 清单执行 + cve-weaponization 按版本检索 + authz-diff 全量矩阵（对 IdP 暴露的 API 面）三者缺一不算完成。
