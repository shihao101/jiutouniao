---
id: go-backend
title: Go 生态后端武器化手册（pprof/etcd/consul/Prometheus/Grafana/Harbor）
tags: go,golang,pprof,etcd,consul,prometheus,grafana,harbor,grpc,s4
---
# Go 生态手册（三通道之③组件剧本；Go 服务反序列化家族少，重心在暴露面与组件 CVE）

## 一、Go 服务自暴露面（应用层）

```bash
# pprof 挂载（net/http/pprof 常被注册在根路由）
curl -sk -o /dev/null -w '%{http_code}\n' https://目标/debug/pprof/
# /debug/pprof/cmdline=进程启动参数（信息泄露级）；/debug/pprof/heap 下载后只做存在性+字符串检索（凭据前4字符）
# swagger：/swagger/index.html /swagger/doc.json /swaggerui/
# gin debug：panic 页栈（Gin Debug 模式）、/debug/vars（expvar 泄露）
# grpc reflection：grpcurl -plaintext 目标:50051 list（有反射=全服务枚举泄露）
# Go net/http 目录列表（Dockerfile COPY 行为）、静态目录索引
```

## 二、Go 写的基础设施组件（高频指纹面）

| 组件 | 端口/路径 | 探针要点 |
|---|---|---|
| etcd | 2379 | `curl http://x:2379/version`；未授权 `/v2/keys` 列举（读取判据）；v3 grpc 无 TLS 面 |
| consul | 8500 | `/v1/agent/self`、`/v1/catalog/nodes` 未授权读；`/v1/kv/?recurse`（KV 存在性） |
| Prometheus | 9090 | `/api/v1/label/__name__/values`（指标枚举=拓扑泄露）；`/targets` |
| Grafana | 3000 | `/api/health` 版本；匿名面 /api/org、/api/dashboards（未授权读判据）；CVE 按 cve-weaponization |
| Harbor | 443/80 | `/api/v2.0/systeminfo`；未授权项目列举；registry V2 面 |
| MinIO | 9000 | `/minio/health/live`；console 9090；`MinIO-Server` 头版本族（cve-weaponization） |
| Traefik/Consul connect | 8080 | `/api/http/routers`（Traefik dashboard API） |

## 三、已知漏洞通道（必做）

- 组件+版本 → cve-weaponization（searchsploit/NVD）：etcd/consul/prometheus/grafana/harbor/minio 各自 CVE 族；编号以检索输出为准。
- Go 运行时面：CGO 栈泄露（panic 页）、`X-Gorilla` 类自研头。

## 四、纪律

- 组件 API 默认允许匿名面 → 未授权读 = finding；**写操作（etcd 写 key/consul 注册服务）一律 S5**。
- heapdump/pprof 数据只做存在性证明（红线 3：不下载敏感内容，仅 strings 检索哈希前缀）。
