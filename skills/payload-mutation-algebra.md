---
id: payload-mutation-algebra
title: 通用变异代数与绕过路径（过滤器指纹→系统化变体→fallback 链）
tags: 绕过,waf,编码,变异,fuzz,s4
---
# 通用变异代数（任何 payload 被拦后先查我）

> **v5.3.0 配额语义对齐（随 loop-core 纪律 11 重构）**：本技能的 12 探针/七步链/变异族是**可选工具箱**而非 ruled_out 前置配额——是否使用由证据与 ROE 驱动：WAF 403/拦截记 blocked（blocked_waf）即为合法终态；仅在 ROE 明确允许且信号显示有绕过价值时做有限兼容性确认。预写假设/预期信号/预算/停止阈值先于任何变异发送。

> 触发条件：任何探测 payload 被拦截/过滤/无差异时。**禁止在未做过滤器指纹前盲目换 payload**，
> 也禁止一次拦截就 ruled_out。先指纹 → 再按代数构造变体 → 按 fallback 链推进。

## 一、过滤器指纹 12 探针（先判类型再动手）

对同一注入点依次发：①`<` ②`>` ③`"` ④`'` ⑤`<sCrIpT>` ⑥`scr%69pt`
⑦`<scr<script>ipt>` ⑧`%3cscript%3e` ⑨`<svg/onload>` ⑩反引号 ⑪`{{7*7}}` ⑫`${7*7}`。
判读：哪个被剥/被编码/被拦/原样反射 → 定性（黑名单关键字 / 全量编码 / 递归过滤缺失 /
单遍过滤可嵌套 / 模板未隔离）。指纹结果落 evidence/ 并写入 waf-fingerprint 档案。

## 二、编码阶梯（逐级升，每级一次判定）

原始 → URL → 双重 URL → HTML 实体（数字/命名）→ Hex（0x）→ Unicode（\u / U+）→
UTF-8 Overlong → Base64 → 注释嵌（/**/ / %2f%2a%2f）。**关键判据**：
"过滤层解码一次，执行层再解码一次"——双重编码命中的前提，逐级单变量测。

## 三、语法等价替换表（关键字被黑名单时）

| 被滤 | 等价形态 |
|---|---|
| 空格 | %09 %0a %0c /**/ 括号包裹 () |
| AND/OR | && \| \| %26%26 |
| = | LIKE REGEXP BETWEEN < > IS |
| 逗号 | FROM...FOR（substring）、JOIN（union）、OFFSET |
| SELECT | SEL/**/ECT 大小写 SeLeCt 双写 selselectect |
| 引号 | 0x hex CHAR() 宽字节 %bf%27 |
| exec 类（命令） | ${IFS} $IFS$9 {cat,/etc/passwd} /???/c?t 变量拼接 wh$1oami |

## 四、解析器差分（前后端对同一输入理解不一致）

- URL 解析：`@` 凭据位、十进制 IP `2130706433`、八进制 `0177.0.0.1`、`[::ffff:127.0.0.1]`、
  `127.1`、尾点 `127.0.0.1.`——SSRF/重定向/白名单绕过共用。
- 路径解析差分：`/x/../y`（网关不归一化）、`/..;/`（nginx 不解析分号 Tomcat 解析）、
  `/./`、`//`、PATH_INFO `/y.php/`（PHP-FPM 执行）、分号参数 `;jsessionid=`。
- 方法差分：GET→POST→PUT→PATCH→HEAD；X-HTTP-Method-Override；Content-Type 切换
  （form↔JSON，同一参数名两套解析）。
- HTTP 头注入位：X-Original-URL / X-Rewrite-URL / X-Forwarded-Host / X-Real-IP /
  Forwarded——鉴权/限流/重定向常读这些而非 Host。

## 五、上下文感知逃逸（输出位置决定载荷形态）

反射点在：HTML body → `<svg onload>`；属性内 → 事件处理器（onfocus+autofocus 优先，
onerror/onanimationend 次选）+ 引号逃逸；JS 字符串内 → `</script><svg>` 或引号闭合+反引号；
模板内 → {{表达式}}；注释内 → `-->`/`*/` 闭合。
**必测**：渲染后 DOM 变化（browser_render 证据），curl 源码反射不作数（evidence-standard）。

## 六、复合变异与 Fallback 七步链

七步：原始 → 编码升阶 → 大小写/双写 → 语法等价 → 碎片化（scr<!--x-->ipt、字符串拼接）
→ 解析器差分（换解析位）→ 复合（编码+碎片+差分叠加）。**每步一次判定、单独留证**；
七步全空才允许 ruled_out（覆盖登记必须列七步各自结果）。

## 七、403/401 专项（无凭证场景高频死点，禁止一次 403 判死）

变体族：路径 `/./api /api/ /api// /api/./ /;%2fapi /api;.json /api?id=1..%2f`；
头族：X-Original-URL、X-Rewrite-URL、X-Forwarded-For: 127.0.0.1、Referer 同域；
方法族：verb tampering（HEAD/OPTIONS/TRACE）、Override 头；编码族：%2e%2e、双编码、
Unicode 同形；**源站直连**（waf-fingerprint 找真实 IP，绕 CDN）。
判据：任一变体 200 且内容为保护资源 → 未授权访问确证。

## 八、喷射纪律（批量变异时）

批量 payload 用单脚本落盘执行（禁逐轮调用）：Python asyncio 限速并发（≤4）、
记录 status/length/time/反射标记四元组、按响应相似度去重、输出 top 候选表再人工复核——
对齐 strix 喷射指令与九头鸟循环熔断护栏。
