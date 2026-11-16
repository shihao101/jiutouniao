---
id: crlf-injection
title: CRLF 注入（头拆分/会话固定/缓存投毒/Unicode 绕过）
tags: CRLF,头注入,会话固定,s4
---
# CRLF 注入（HTTP 响应拆分）

**进入条件**：参数值被反射进**响应头**（Location/Set-Cookie/自定义头）或重定向 URL。

## 一、注入模式

1. **头拆分**：`%0d%0aSet-Cookie: session=attacker` → 注入任意响应头；
2. **双 CRLF body 注入**：`%0d%0a%0d%0a<script>alert(1)</script>` → 反射型 XSS；
3. **会话固定链**：`%0d%0aSet-Cookie: sessionid=固定值` + 受害者登录 → 会话劫持；
4. **缓存投毒**：注入头被缓存层保留 → 全局缓存污染；
5. **302 多 Location**：部分服务器取**最后一个** Location 头 → 劫持跳转。

## 二、过滤绕过变体

Unicode：`%E5%98%8A%E5%98%8D`（部分解析器解为 \r\n）；双重编码：`%250D%250A`；纯 `%0A`（部分头解析只认 \n）；反射点在 UA/Referer（进日志伪造管理员访问记录）。

## 三、纪律

注入载荷仅含无害标记头（`X-JT-Test: 1`）与本地弹窗，不投放会话固定到真实用户；命中判据=响应中出现注入头；修复判据=参数值 CR/LF 过滤 + 头值编码。

### 补遗

缓存投毒具体 payload（伪造完整 200 响应）：`GET /page?q=%0D%0AContent-Length:0%0D%0A%0D%0AHTTP/1.1%20200%20OK%0D%0AContent-Type:text/html%0D%0A%0D%0A<script>alert(1)</script>`。注入位变体：值被过滤时**注参数名**。白盒代码指纹：PHP `header("Location: ".$_GET['url'])`、Python `redirect(request.args.get('next'))`、Node `res.setHeader('X-Custom', userInput)`、Java `response.setHeader("Location", request.getParameter("url"))`。