---
id: intranet-lateral
title: 内网信息收集与横向移动手册
tags: 内网,横向,后渗透,s6
---
# 内网信息收集与横向移动手册（全部动作需 L2 审批）

## 立足点信息收集（只读优先）
```bash
id; hostname; ip a; cat /etc/hosts; arp -a
ps aux | grep -iE 'agent|monitor'; ls /opt /srv 2>/dev/null
env | grep -iE 'key|token|secret'   # 环境变量密钥（只记存在性）
```
- 云上：`curl -s http://169.254.169.254/latest/meta-data/`（存在性证明）。

## 网络发现（限速）
```bash
nmap -sn 10.0.0.0/24                  # 存活
nmap -sV --top-ports 100 10.0.0.0/24  # 服务（网段粗扫）
# 对关键主机（DMZ/域控/运维跳板）做全端口，服务可能在 100 以外：
nmap -Pn -p- --open --min-rate 800 -T3 <关键主机IP>
```

## 凭据复用面
- 找到的密码/密钥对内网同类型服务复用测试（限频）：ssh/redis/mysql/管理台。
- 只验证「能否登录」，成功即停并留证；不做批量爆破。

## 服务间信任滥用（v6.7.0 S6-⑧ 补节——head S6-2「服务间信任滥用（含 AI 服务→内部 API）」落点）

> 内网服务普遍默认信任「同网段/内网来源」——立足点获得内网位置后，这层信任即成横向面。与 llm-agent-toolchain 分工：那是应用层注入面，这里是**内网信任拓扑面**。

| 信任滥用面 | 判据级探测（只读优先） | 命中信号 |
|---|---|---|
| 内网服务免鉴权调用 | 从立足点对内网管理/数据接口发只读请求（不带凭据），与外网口径对比 | 内网直通 200/数据返回=「内网即可信」信任模型 |
| 服务账号静态凭据 | 配置文件/环境变量/K8s Secret 中的 DB/队列/存储凭据（只记掩码） | 同一凭据跨服务复用 → database-postex / 横向复用面 |
| 内部 API 网关 | 内网路由表/hosts/服务发现（consul/etcd/nacos）只读枚举 | 未鉴权注册接口、内部-only 标头（X-Internal-*）直通 |
| AI 服务→内部 API | 内网 LLM 网关/模型服务端口（常见 8000/8081/11434）只读指纹；Agent 后端的工具调用配置只读 | LLM 服务持有内部 API 凭据且 tool-call 可驱动内网请求=信任链放大面（发现即 record_finding，利用属 L2 审批） |
| SSRF 入内网 | 承接 S4/S5 已确证 SSRF 原语打内网地址（存在性证明：随机标记回显/OOB） | 内网拓扑可达性证实 → 原语图 EXEC/SSRF 凑链 |

- 纪律：全部只读枚举先行；写类验证（如经 AI 服务驱动内部写 API）先审批；范围外内网资产只登记线索交人工确认（expansion 口径以「治理口径」块为准）。

## 立足点后敏感文件定位（v6.7.0 S6-⑧ 补节——S6-3 数据访问证明的文件系统面落点）

> 配合 database-postex（数据库面）/mail-postex（邮件面）补齐主机文件面。**只做存在性证明：截图/计数/哈希前缀，不下载、不带走数据。**

```bash
find / -maxdepth 4 \( -iname '*.conf' -o -iname '*.env' -o -iname '*.yml' -o -iname '*.pem' -o -iname '*.key' -o -iname '*.sql' -o -iname '*.bak' \) -type f 2>/dev/null | head -30   # 配置/密钥/备份候选
grep -rlE '(api[_-]?key|secret|password|token|BEGIN (RSA|EC|OPENSSH) PRIVATE KEY)' /etc /opt /srv /home --include='*' -m1 2>/dev/null | head -20   # 密钥语义文件（只列路径）
ls -la /home/*/.ssh /root/.ssh 2>/dev/null; find / -name "id_rsa*" -not -path "/proc/*" 2>/dev/null | head -5        # 私钥面
find /var/www /app -maxdepth 3 -name '*.env' -o -name 'settings.py' -o -name 'application*.yml' 2>/dev/null | head -10  # 应用配置
```
- 判据：命中即 record_finding（置信度按 evidence-standard 对照；内容只记「文件路径+行数计数+sha256 前 8 位」，禁止粘明文）；密钥类验证可登录性 → 凭据复用面 / password-offline。
- 数量级证明口径：`find … | wc -l` + 抽样 1 条哈希，S6-3《数据访问证明》按此登记。

## 横向路径记录
- record_timeline 记录每一跳：源→目标→凭据类型→结果。
- 横向路径图（deliverables/s6-横向路径图.md）用文字+箭头表达，标注每步风险等级；引用《拓扑重建》最新版（s6.md v5.4 拓扑引用强制）。

## 红线
- 范围外资产不碰；敏感数据只做存在性证明；发现域控/核心系统立即上报人工，不擅自深入。

## v4.8 M6 工具通道兼容性声明

> 通用判据以 `tool-channels.md` 为准（v5.1 单源去重）；本技能差异：内网横扫类（fscan/crackmapexec 族）在内网 IDS/蜜罐面下先 probe 后 batch 更严——单主机 probe 2 请求正常再批量；凭据喷洒受 weak-cred-bruteforce 锁定纪律约束。nmap/curl 通用行不再内联。
