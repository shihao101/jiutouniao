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
- 匿名写测试：PUT 一个带唯一标记的 test.txt（需审批；**写入即登记四元组并入《需人工清理清单》移交，不执行删除**——与 s7「智能体不执行目标侧删除」单一规则一致；报告口径=写权限存在性证明，读取回验证一次后不产生后续读写）
- 目录索引开启 = 信息泄露（中）

## IAM 越权（S6 权限提升）
- 当前凭据可 `sts get-caller-identity`（AWS）/ `aliyun sts GetCallerIdentity` / 腾讯云 `cam GetUserAppId`？（存在性）
- 只读探测为主：角色/策略枚举 → 判断提权路径，不实际提权（需 ROE）

## 容器
- metadata 接口、docker.sock 挂载（`ls /var/run/docker.sock`）、特权容器（`capsh --print`）
- 逃逸候选路径只做评估记录，实际逃逸先审批

## v5.6.0 分云 IAM 矩阵与只读验证器（三凭证审计补强）

### 分云身份权限矩阵（凭据在手时的 IAM 差分——对齐 authz-diff 思想）

| 云 | 凭据形态 | 权限枚举（只读） | 越权判据 |
|---|---|---|---|
| AWS | AK/SK（origin=real） | `aws sts get-caller-identity` + `aws iam simulate-principal-policy --policy-source-arn <arn> --action-names "*" --resource-arns "*"` | SimulatePolicy 出的宽权限（`*:*`）= 过授权候选 |
| 阿里云 | AK/SK | `aliyun sts GetCallerIdentity` + RAM 权限列举（`aliyun ram ListPoliciesForUser`） | Action 通配/RAM 跨账号资源访问 |
| 腾讯云 | AK/SK | `tccli cam DescribeCollaborators` / `GetCredentialInfo` | 角色 assume 跨边界 |
| K8s | SA token（kind=token） | `kubectl auth can-i --list`（全权限矩阵） | `can-i create pods/exec` = 逃逸候选链 |

- 凭据经 store_credential 入库（origin=real kind=bearer/token，target=云厂商 API 域）——**Target-host 绑定生效后跨云 API 使用会拒绝，按需分录入库**。
- 元数据凭证（SSRF 场景）过期时间/角色面：联动 ssrf-deep IMDSv2 节。

### 只读验证器与边界

- 所有权限枚举命令只读（L0）；`simulate-principal-policy` 不产生副作用——生产档可执行。
- 写验证（如 `aws s3 cp` 上传证明）按上文登记移交口径（不删除）。
- 记账：IAM 差分每项 update_coverage（vuln_class="cloud-iam-<动作>"）；越权命中 record_finding（CWE-284）。
