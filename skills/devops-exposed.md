---
id: devops-exposed
title: DevOps 暴露面手册（GitLab/Jenkins/ArgoCD/K8s 面板/Nexus/SonarQube）
tags: devops,gitlab,jenkins,argocd,k8s,ci-cd,s4
---
# DevOps 暴露面（三通道之③组件剧本；CI/CD 面是供应链跳板，高危必须审批）

## 一、指纹与未授权面

```bash
# GitLab：/users/sign_in 页脚版本；未授权 API /api/v4/projects?visibility=public（未鉴权枚举）
#         /api/v4/version（鉴权后）；CVE 按 cve-weaponization（搜索类/注入族）
# Jenkins：/login 页脚版本；未授权 /script 控制台判据（403/200 差异）；/asynchPeople/、/api/json 全局枚举
#         /view/All/builds 未授权读；CVE（CLI 反序列化族）→ S5
# ArgoCD：/api/v1/version 未授权读；SSO 配置面；/api/v1/applications 未授权列举=拓扑泄露
# K8s Dashboard：/api/v1/login 未授权跳过判据；k8s API 6443 匿名（cloud-security 联动）
# Nexus：/service/rest/v1/repositories（匿名仓库枚举）；/service/rest/v1/search
# SonarQube：/api/server/version、/api/components/search_projects（未授权）
```

## 二、凭据面（面面俱到但限频）

- 登录面全走 weak-cred-bruteforce（≤5/账号）；Jenkins/GitLab 默认账（admin/admin 类）单次试探。
- CI 配置泄露：Jenkinsfile/.gitlab-ci.yml/.github/workflows 经未授权 repo 读 → **其中密钥只记存在性**（变量名+前4字符）。

## 三、供应链危害路径（只做判据）

- 构建节点可提交构建（PR 触发构建）→ 供应链注入候选：判据=PR 环境变量回显（无害 echo 构建变量到日志）→ **实际注入转 S5+人工确认**。
- 制品库匿名拉取私有制品 → 源码/密钥存在性证明（哈希前缀）。

## 四、纪律

- CI/CD 面写操作（触发构建/改 pipeline/发布制品）= S5 强审批 + 人工在环；禁触生产部署流水线。
- 拿到 CI 节点等价于拿到生产源码/凭据面——范围外主机禁止横向（ROE 红线）。

## SCM 泄露判据

- **403 目录 + 200 on `/.git/HEAD` = 强暴露信号**（区分 404 与 403 是关键判据）
- SVN≥1.7：下 `wc.db` → sqlite3 查路径 → 取 `/.svn/pristine/` blob 恢复；`.hg/requires`、`.bzr/README`、`.DS_Store`（ds_store_exp）
- 备份扩展名清单：`.bak/.swp/.rar/.sql/backup.zip/wwwroot.rar`
- **依赖混淆联动**：manifest/CI 日志暴露内部包名 → dependency-confusion 技能（侦察→只读探测→无害 PoC）

### .git 文件优先级与恢复工具

.git 关键文件优先级表：`.git/logs/HEAD`（提交历史/reflog 泄露）、`.git/packed-refs`（分支/tag）、`.git/refs/heads/*`、`.git/config`（remote.origin.url 内嵌凭据）、`.git/objects/**`。恢复工具名：arthaud/git-dumper、internetwache/GitTools（Dumper/Extractor/Finder）、WangYihang/GitHacker、anantshri/svn-extractor、sahildhar/mercurial_source_code_dumper。