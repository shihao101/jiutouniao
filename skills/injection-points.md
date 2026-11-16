---
id: injection-points
title: 注入点完整性手册（宪法「深度测试纪律」第 3 条依赖）
tags: 注入点,arjun,header,path,cookie,隐藏参数,s4
---
# 注入点完整性（先查我：测任何注入类前先跑本手册）

> 宪法口径：**注入类测试必须覆盖 body 之外的全部入口——URL 参数、path 段、header、cookie、JSON 体、隐藏参数**；只测 body 不算测过。

## 一、隐藏参数挖掘（arjun，Kali 自带）

```bash
# 单目标全参数发现（GET/POST/JSON 自动适配，限速）
arjun -u https://目标/api/user --stable -t 2 -o /tmp/arjun.json
# JSON 模式
arjun -u https://目标/api/login -m JSON --stable
# 结果合并进 s4 待利用队列：每个隐藏参数 = 一个「目标×参数」覆盖单元
```

- wordlist：`/usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt`（arjun 默认集之外的补充）。
- arjun 无果 ≠ 无隐藏参数（可能被网关过滤）→ 转 GET 参数字典爆破（ffuf + 参数 wordlist，L0 限速）。

## 二、各入口的测试口径

| 入口 | 挖掘方法 | 常见被忽视点 |
|---|---|---|
| URL 参数 | 常规 + arjun 隐藏参数 | 分页/排序/语言参数最常被信任 |
| path 段 | 改写最后一段（/api/v1/user → /api/v1/user/1） | REST 风格 path 参数直接进 SQL/文件操作 |
| header | X-Forwarded-For / Referer / User-Agent / X-Original-URL / X-Rewrite-URL | 日志面板回显→存储型 XSS；XFF→SQLi/信任边界 |
| cookie | 自定义 cookie 注入测试 | 自研框架常把 cookie 值直接拼查询 |
| JSON 体 | 层级遍历：同级新增字段/父级嵌套/类型混淆（"id":"1"→"id":1） | mass assignment：多传 role/isAdmin 字段 |
| 隐藏字段 | 表单源码 hidden + JS 里的参数名 | 禁用态字段服务端未校验 |

## 三、覆盖登记

- 每个入口×漏洞类一格 coverage；`injection-points 完整性确认` 是 sqli-deep/cmdi-deep/ssti-engine-map/xxe-full 的开工前置。
- 判据：全部六入口枚举过且留证据（arjun 输出落 evidence/），才允许对「无发现」下 ruled_out 结论。

## v4.8 M6 工具通道兼容性声明

> 口径（loop-core v4.8 纪律 3）：先 probe 后 batch——每个外部工具对目标首次使用前先用小样本探针确认可用性，探针被拦/挂起先切适配通道再批量；探针结果写入交付物工具声明小节。各工具在「挑战型 WAF / 封闭站」下的可用性与适配通道：

- arjun：挑战态未注入时批量请求全失败/全 000（假阴性）——先 probe 2-3 个已知参数验证通道可用；适配通道：browser 会话取 cookie/挑战头注入后重跑，仍拦截则 -t 1 降并发或改 CDP 流量代打。
- ffuf：挑战页统一指纹会掩盖响应长度差异（假阴性）——先 probe 2 个请求人工核对差异真实性；适配通道：会话态 cookie/UA 注入后跑；封闭站签名校验目标改浏览器代理。
