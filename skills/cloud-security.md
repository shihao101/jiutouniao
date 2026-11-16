---
id: cloud-security
title: 云安全测试手册（元数据/IAM/对象存储）
tags: 云,iam,oss,元数据,s4,s6
---
# 云安全测试手册

## 云元数据（SSRF 落地首选）
```bash
# 只取存在性证明，不下载内容
curl -s http://169.254.169.254/latest/meta-data/            # AWS（IMDSv1）
# AWS IMDSv2：先 PUT 取 token，200+token 头可用=IMDSv2 防护生效（SSRF 只发 GET 时取不到=防护判定依据）
curl -s -X PUT http://169.254.169.254/latest/api/token -H "X-aws-ec2-metadata-token-ttl-seconds: 60"
curl -s -H "Metadata-Flavor: Google" http://metadata.google.internal/  # GCP
curl -s http://100.100.100.200/latest/meta-data/            # 阿里云
curl -s http://metadata.tencentyun.com/latest/meta-data/    # 腾讯云（CVM）
curl -s http://169.254.169.254/openstack/latest/meta_data.json  # 华为云（OpenStack 形态）
curl -s -H "Metadata:true" "http://169.254.169.254/metadata/instance?api-version=2021-02-01"  # Azure
```
- 命中即确证 SSRF→云凭据链，record_finding(高)。IMDSv2（需 token 头）= 防护生效。
- 对象存储归属探测：OSS（aliyuncs.com）/COS（myqcloud.com）/OBS（obs.myhuaweicloud.com）/S3（amazonaws.com）桶域名特征 → 对应存储节。

## 对象存储
- 桶枚举/遍历（按厂商后缀）：`curl -s https://<桶>.oss-<region>.aliyuncs.com/?prefix=/`、COS `?prefix=/`、S3 `https://<桶>.s3.amazonaws.com/?list-type=2`（ListObjects 权限）
- 匿名写测试：PUT 一个 test.txt（需审批，测后删除并留证）
- 目录索引开启 = 信息泄露（中）

## IAM 越权（S6 权限提升）
- 当前凭据可 `sts get-caller-identity`（AWS）/ `aliyun sts GetCallerIdentity` / 腾讯云 `cam GetUserAppId`？（存在性）
- 只读探测为主：角色/策略枚举 → 判断提权路径，不实际提权（需 ROE）

## 容器
- metadata 接口、docker.sock 挂载（`ls /var/run/docker.sock`）、特权容器（`capsh --print`）
- 逃逸候选路径只做评估记录，实际逃逸先审批
