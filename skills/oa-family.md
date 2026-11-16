---
id: oa-family
title: 国内 OA 家族武器化手册（致远/泛微/用友/通达/蓝凌）
tags: oa,致远,seeyon,泛微,weaver,用友,通达,蓝凌,s4
---
# OA 家族武器化（三通道之③组件剧本，国内授权测试第一目标族）

> 统一流程：指纹确认 → 未授权/默认凭据面 → 历史漏洞按版本检索（cve-weaponization/searchsploit 命中优先）→ 无害探针 → S5。**利用级动作一律 S5 审批。**

## 一、指纹速查

| 家族 | 指纹特征 |
|---|---|
| 致远 Seeyon | 路径 `/seeyon/`、Server: Seeyon、登录页 A8/V5 标识 |
| 泛微 Weaver | `/wui/`、`/ecology/`、e-cology/e-office 页脚、`/mobile/` |
| 用友 NC/友空间 | `/nccloud/`、端 80/8080 NC servlet、U8 路径 `/U8AppProxy` |
| 通达 OA | `/interface/`、`/mac/`、通达页脚、MYOA |
| 蓝凌 Landray | `/sys/`、`/km/`、EKP 页脚 |
| 万户/若依等 | ezoffice 页脚；ruoyi `/prod-api/` + druid 面 |

## 二、未授权/信息面（只读优先，各家高危矩阵）

```bash
# 泛微 e-cology：/api/ 系列未授权面、数据库配置读取探针（BeanShell 面仅 S5）
# /service/ 系统接口清单、workflow 接口
# 致远：/seeyon/htmlofficeserver 下载类接口探测（任意文件读取/上传族，判据无害化）
# 用友 NC：/servlet/~<模块名>/ 反序列化面识别（报错差异判据）、NCPDP 未授权清单
# 通达：/module/ 接口目录遍历判据、附件上传面（上传绕过见 upload-bypass）
# 蓝凌：/sys/search/ 接口、KM 文件接口越权面
```

- 每家配 **nuclei 模板组**（nuclei-usage 联动，按指纹选 family 标签）+ searchsploit 逐家检索（本地库历史 PoC 丰富）。
- 默认/弱口令面：admin/system/oaadmin + 常见弱口令（weak-cred-bruteforce，失败额度 ≤5/账号）。

### 二a、逐厂商未授权首查清单（v5.1：泛化描述 → 可执行探针位；全部 L0 只读）

| 家族 | 首查探针位（存在性/门控判定，不实调） |
|---|---|
| 致远 Seeyon | `/seeyon/htmlofficeserver`、`/seeyon/rest/` 接口族匿名直调（401/405 差异）；A8 附件接口族 |
| 泛微 e-cology | `/api/` 接口族逐个匿名 GET；`/mobile/` 移动端接口面；`/service/` 服务清单；数据库配置读取探针（命中即停，S5） |
| 泛微 e-office | `/login/` 系之外上传/接口面按版本检索（searchsploit 逐版本） |
| 用友 NC | `/servlet/~<模块名>/` 报错差异枚举（反序列化面识别）；`/nccloud/` 接口族匿名面 |
| 通达 OA | `/interface/` 接口目录逐项探针；`/module/` 遍历判据；附件上传面（upload-bypass 联动） |
| 蓝凌 EKP | `/sys/search/`、`/km/` 文件接口越权面匿名判读 |
| 万户/若依 | `/prod-api/` 接口族 + druid 面（`/druid/index.html` 未授权登录判据） |

- 探针命中 → record_finding（存在性证明）；**每家指纹命中后仍须把探出的端点表全量入 authz-diff 矩阵（v5.1 硬门）**。

## 三、历史漏洞矩阵（按版本核对，编号以检索输出为准——禁止凭记忆写 CVE）

- 版本来源：登录页页脚、`/release/` 系、静态资源版本号、/api/system/info 类接口。
- 命中 cve-weaponization 三步：检索 → PoC 可用性分级 → 无害探针复现 → 确证 record_finding。
- 「历史漏洞已修补但接口仍在」→ 同族变形测试（路径变形/参数变体，hypothesis-0day 差异口径）。

## 四、纪律

- OA 系统生产数据敏感（公文/审批流）：**一切读取只做存在性证明**；审批流不操作（不发起/不审批/不撤销真实单据）。
- 未授权面确认即 record_finding，无需打利用；上传/反序列化/BeanShell 类转 S5。

## v4.8 M6 工具通道兼容性声明

> 口径（loop-core v4.8 纪律 3）：先 probe 后 batch——每个外部工具对目标首次使用前先用小样本探针确认可用性，探针被拦/挂起先切适配通道再批量；探针结果写入交付物工具声明小节。各工具在「挑战型 WAF / 封闭站」下的可用性与适配通道：

- nuclei：模板请求无浏览器指纹，JS 挑战下全 miss（假阴性）——先 probe 单模板×单 URL 核对；适配通道：channel-snapshot 提取会话态后以 -H/-cookies 传参小批量跑，或改浏览器代理。
- searchsploit：本地库检索，无网络/挑战影响——始终可用。
