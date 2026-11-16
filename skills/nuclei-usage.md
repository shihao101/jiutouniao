---
id: nuclei-usage
title: nuclei 工程化使用手册
tags: nuclei,扫描,模板,s4
---
# nuclei 工程化使用手册

## 基础运行（限速 + 范围内）
```bash
nuclei -u https://<目标> -severity medium,high,critical -rate-limit 30 -bulk-size 5 -timeout 8
nuclei -l targets.txt -t http/cves/ -o nuclei-out.txt -silent
```

## 工程化要点
1. **先指纹后扫**：用 whatweb/httpx 结果选择模板组——**指纹→模板组映射表（v5.1）**：
   | 指纹 | 模板组 |
   |---|---|
   | weblogic/tomcat/jenkins/nacos/minio 等中间件 | `-t technologies/<指纹>/` + `-t http/cves/<年份>/` |
   | spring boot/actuator | `-t http/exposures/` + `-t http/cves/2022/` |
   | 致远/泛微/用友/通达/蓝凌（oa-family） | `-t http/cves/` 按检索年份 + 自定义族模板（oa-family 探针位） |
   | 深信服/网神/堡垒机（edge-vpn-bastion） | `-t http/cves/` 高危年份 + `-t http/exposures/` |
   | 金智 ehall/VSB（edu-family） | 自定义族模板（edu-family 首查清单逐条转 yaml） |
   映射表缺失的指纹 → 走 framework-priors 兜底规则（通用未授权清单+检索），不裸跑全模板库。
2. **误报三查**：看响应体关键词、HTTP 状态与长度、模板 match 条件；不确定标「疑似」。
3. **自定义模板**（需要时）：
```yaml
id: my-probe
info: {name: 探测自定义接口, severity: info}
http:
  - method: GET
    path: "{{BaseURL}}/.well-known/security.txt"
    matchers:
      - type: word
        words: ["Contact:"]
```
4. 输出对接：`-json` 逐条解析 → record_finding（位置/模板/响应证据）。
5. 模板更新：`nuclei -update-templates`（容器内首次联网下载）。

## 纪律
- 扫描前确认 ROE 窗口；-rate-limit 与并发保守设置；高危模板（如 rce 类）命中后走 s5 审批流程复验。

## v4.8 M6 工具通道兼容性声明

> 口径（loop-core v4.8 纪律 3）：先 probe 后 batch——每个外部工具对目标首次使用前先用小样本探针确认可用性，探针被拦/挂起先切适配通道再批量；探针结果写入交付物工具声明小节。各工具在「挑战型 WAF / 封闭站」下的可用性与适配通道：

- nuclei：模板请求无浏览器指纹，JS 挑战下全 miss（假阴性）——先 probe 单模板×单 URL 核对；适配通道：channel-snapshot 提取会话态后以 -H/-cookies 传参小批量跑，或改浏览器代理。
- httpx：JS 挑战下标题/状态码/长度全部来自挑战页（批量假阴性）——先 probe 1 个请求核对响应真实性；适配通道：channel-snapshot 提取 cookie/UA 后 curl -b 复放，或建立会话后注入态再批。
- whatweb：JS 挑战型目标返回的是挑战页指纹（假阴性「无指纹」）——先 probe 单目标核对返回是否挑战页；适配通道：channel-snapshot 快照态（cookie+UA）复放或 browser-auth 会话建立后重跑。
