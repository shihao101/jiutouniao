---
id: recon-playbook
title: 侦察与资产测绘手册
tags: 侦察,子域,端口,指纹,s2
---
# 侦察与资产测绘手册（被动优先）

## 子域枚举（被动）
```bash
curl -s "https://crt.sh/?q=%25.<域>&output=json" | jq -r '.[].name_value' | sort -u   # 证书透明度
dig +short <域> ANY; host <域>                                                        # DNS
```

## 存活与指纹（主动，限速）
```bash
httpx -l subs.txt -title -tech-detect -status-code -follow-redirects -rate-limit 20
whatweb -a 1 http://<目标>                              # Web 指纹
```

## 端口扫描（两段式，禁止只凭 top-1000 下结论）
服务完全可能监听在 1000 以外的端口，top-N 只是快速摸底，**全端口扫描是必做项**：
```bash
# 第一段·快速摸底（分钟级，先拿大面）：top-1000 + 常见自定义端口
nmap -sV -Pn --top-ports 1000 --open --min-rate 300 -T3 <目标>
# 第二段·必做全端口（覆盖 1-65535）：发现第一段遗漏的服务（如 8081/6379/11211/5601 等高位端口）
nmap -Pn -p- --open --min-rate 300 --max-retries 2 -T3 <目标>
# 第三段·漏报复核（必做）：高速率跨公网扫描会丢包漏报（实测 --min-rate 800 漏掉开放端口），
# 对常见高位服务端口做低速复核，与全端口结果取并集
nmap -Pn -p 8000,8001,8080,8081,8443,8888,9000,9090,7001,4848,5601,6379,11211,27017,9200 --reason --max-retries 3 <目标>
# 第四段·对全部开放端口做版本与脚本识别
nmap -sV -Pn -p <开放端口列表> --version-intensity 5 <目标>
```
注意：
- 高速率（--min-rate ≥800）跨公网扫描对中间设备（云安全组/IDS）敏感，会丢包漏报开放端口——**漏报复核是必做项**，发现 open/filtered 存疑时用 `--reason` 与低速重扫确认。
- 云主机/防火墙后 UDP 与高位 TCP 常被漏配防护，`-p-` 命中率最高；masscan 可用于 `/24` 以上网段提速（`--rate 2000`），结果再用 nmap 复核。
- 全端口扫描结果必须 `record_asset` 逐端口登记，不允许只登记 top-1000 命中的端口。
- ROE 允许范围内控制速率（`--min-rate`/`-T3`），避免触发告警或影响业务。

## 目录与 API 发现
```bash
ffuf -u https://<目标>/FUZZ -w <字典> -mc 200,301,302,401,403 -rate 50
arjun -u https://<目标>/          # 隐藏参数
```

## AI 入口探测
- 聊天组件特征：页面含 chat/conversation/stream 端点；SSE 流式响应。
- OpenAI 兼容 API：`POST /v1/chat/completions` 探测；模型指纹看响应头/字段。

## 产出要求
- 全部结果 record_asset；覆盖度 update_coverage(vuln_class=资产测绘)。
- 空间测绘数据可能过期，关键结论现场复核。

## 空间测绘（Quake 360，Key 已注入环境变量 $QUAKE_KEY）

IP 直连/无域名目标优先用 Quake 做资产与指纹测绘（被动，L0）：

```bash
# 1) IP 视角：该 IP 历史开放端口与服务指纹
curl -s -X POST "https://quake.360.net/api/v3/search/quake_service" \
  -H "X-QuakeToken: $QUAKE_KEY" -H "Content-Type: application/json" \
  -d '{"query":"ip:\"<目标IP>\"","start":0,"size":20,"include":["ip","port","hostname","service.http.title","service.http.server","service.name","time"]}' | jq '.'

# 2) 资产视角：关联域名/站点
curl -s -X POST "https://quake.360.net/api/v3/search/quake_host" \
  -H "X-QuakeToken: $QUAKE_KEY" -H "Content-Type: application/json" \
  -d '{"query":"ip:\"<目标IP>\"","start":0,"size":20}' | jq '.'

# 3) 同段旁站参考（仅记录线索，禁止越界测试）
curl -s -X POST "https://quake.360.net/api/v3/search/quake_service" \
  -H "X-QuakeToken: $QUAKE_KEY" -H "Content-Type: application/json" \
  -d '{"query":"ip:\"<目标IP>/24\"","start":0,"size":10}' | jq '.data[] | {ip,port,service}'
```

- 查询结果只作侦察线索与漏报复核参照，仍需本机验证后才能登记为确证结论。
- 速率限制：Quake 免费 Tier 有 QPS 限制，连续查询间 sleep 2-3 秒。
- 无 $QUAKE_KEY 或查询失败时跳过测绘，直接走本机主动侦察（不要反复重试）。

## GitHub dork 全集与文库工作流

- **GitHub 搜索语法全集**：`in:name/description/readme`、`stars:>3000`、`stars:1000..3000`、`forks:>1000`、`size:>=5000`、`pushed:>2019-01-01`、`created:>2019-01-01`、`user:xxx`、`license:apache-2.0`、`language:java` 及组合（`user:baidu in:name baidu`）；自动化 GitDorker
- **文库→fofa→通杀工作流（获权后链，S5 审批+范围确认后才可执行）**：peiqi/零组/白泽文库找已知漏洞系统 → 提 fofa 关键词（如 body="DC_Login/QYSignUp"）→ getshell 后打包源码白盒审计出通杀；**进后台直奔"用户管理"：添加管理员包删 cookie 重放，成功则改 Host 打同系统所有站**——⚠ 本行为体属**获权后利用链**（S5/L2），不得在 S2 匿名侦察窗口执行；改 Host 同构复测前逐主机确认授权范围
- **JS 接口三件套**：Burp HTTP history 找页面不渲染的 `?sid` 类参数、F12 网络面板找个人资料接口换参、JSFinder 从 JS 提接口（案例产出未授权上传+SSRF）；谷歌搜"系统名+操作手册/初始密码"拿默认口令
- **VPN 内网定位（S6 内网阶段动作，L2 审批）**：进 SSLVPN → 一站式大厅点开全部应用 → ping 收集 IP → 二分法 ping B 段存活 → fscan 弱口令/nday（严格授权边界）——⚠ 非匿名侦察动作，S2 窗口禁止执行
- **ARL 灯塔弱配置**：默认 admin/admin:5003；mongo 重置 `hex_md5('arlsalt!@#'+'新密码')`——固定盐可用于检验外部 ARL 弱配置
- **供应链侦察联动**：JS sourcemap/CI 日志暴露内部包名 → dependency-confusion 技能（s2 联动）
## v4.8 M6 工具通道兼容性声明

> 口径（loop-core v4.8 纪律 3）：先 probe 后 batch——每个外部工具对目标首次使用前先用小样本探针确认可用性，探针被拦/挂起先切适配通道再批量；探针结果写入交付物工具声明小节。各工具在「挑战型 WAF / 封闭站」下的可用性与适配通道：

- nmap：传输层扫描与应用层挑战无关——挑战型 WAF 下可用；封闭站/网关白名单外端口可能全 filtered——先 probe（top100 快扫）确认端口可达性再批量，必要时 --max-rate 限速防封锁。
- masscan：传输层扫描不受应用层挑战影响；封闭站上游丢包表现为全无响应——先 probe 少量已知开放端口验证通道，必要时 --rate 限速防上游封锁。
- httpx：JS 挑战下标题/状态码/长度全部来自挑战页（批量假阴性）——先 probe 1 个请求核对响应真实性；适配通道：channel-snapshot 提取 cookie/UA 后 curl -b 复放，或建立会话后注入态再批。
- whatweb：JS 挑战型目标返回的是挑战页指纹（假阴性「无指纹」）——先 probe 单目标核对返回是否挑战页；适配通道：channel-snapshot 快照态（cookie+UA）复放或 browser-auth 会话建立后重跑。
- arjun：挑战态未注入时批量请求全失败/全 000（假阴性）——先 probe 2-3 个已知参数验证通道可用；适配通道：browser 会话取 cookie/挑战头注入后重跑，仍拦截则 -t 1 降并发或改 CDP 流量代打。
- ffuf：挑战页统一指纹会掩盖响应长度差异（假阴性）——先 probe 2 个请求人工核对差异真实性；适配通道：会话态 cookie/UA 注入后跑；封闭站签名校验目标改浏览器代理。
- subdomain-takeover.py：子域接管指纹核对（19 类 CNAME 悬挂指纹路由+DoH 解析）——传输层 DNS 查询不受应用层挑战影响，始终可用；`--live` 现场二次确认受目标 HTTP 防护影响，被拦时按指纹仍可给接管概率分级（标注「指纹级证据」）。
