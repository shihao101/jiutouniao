---
id: weak-cred-bruteforce
title: 弱口令与默认凭据手册（默认凭据矩阵 · hydra 爆破 · 锁定规避）
tags: 弱口令,爆破,hydra,默认凭据,s4,s5
---
# 弱口令与默认凭据（命中率最高的实战面）

## 一、默认凭据矩阵（先查表后爆破）

| 目标 | 常见默认 | 验证方式 |
|---|---|---|
| Tomcat manager | tomcat/s3cret, admin/admin | manager/html 基础认证 |
| Nacos | nacos/nacos | /nacos/v1/auth/login |
| Jenkins | 初始化未设/ admin | /login 未授权枚举 |
| MinIO | minioadmin/minioadmin | /minio/webrpc Login |
| Nexus/SonarQube | admin/admin{,123} | API authentication |
| 网络设备/摄像头 | admin/admin、设备型号默认表 | 登录页特征 |
| 中间件（Redis/MQ） | 无口令 | 直接连接（middleware-web） |

## 二、受控爆破（web 表单/基础认证）

```bash
# 判定前置：登录页有验证码/锁定策略 → 不爆破，改凭据复用与默认口令
# hydra web 表单骨架：失败标志用登录页独有字符串
hydra -L /usr/share/seclists/Usernames/top-usernames-shortlist.txt \
      -P /usr/share/seclists/Passwords/2020-200_most_used_passwords.txt \
      目标 http-post-form "/login:user=^USER^&pass=^PASS^:F=登录失败" -t 4 -w 2 -f
# 基础认证：hydra -L -P 目标 http-get /manager/html -t 4
# 服务类：hydra -l root -P pass.txt ssh://目标 -t 4 （ssh/mysql/mssql/ftp/redis 同构）
```

## 三、锁定规避纪律（硬约束）

1. **先探测锁定阈值**：同一错误凭据连续 5 次，观察是否锁定/验证码升级——有锁定即改用「每个账号最多 3 次候选」策略或放弃爆破
2. 并发 ≤4、间隔 ≥2s；**单源高频 = DoS 性质，禁止**
3. 命中即停（-f），不跑满全表；锁定触发的账号立即登记并停止
4. 测试账号优先：ROE 提供的账号可直接做口令策略测试而非爆破

## 四、凭据复用面

- 任一命中的口令 → 立即在同一目标的其他登录口（后台/数据库/邮箱）复用验证（逐个手工，限速）
- 命中凭据只登记摘要（用户名+口令前2位+长度），不存明文

## 产出
- record_finding（cwe=CWE-798/CWE-1392 视情况）+ update_coverage(认证类) + 命中证据（登录后页面截图/特征串）

### 限流绕过头族与字典增量

限流/批量绕过头族（低频轮换，遵守限速红线）：`X-Forwarded-For`、`X-Real-IP`、`Forwarded: for=`、UA 轮换、路径大小写与斜杠变体（`/API/`、`/api//`、`/api/./`）。**ROE 门（v5.1）**：伪造头轮换仅用于降噪定位（判"限频键=IP 还是账号"），仅当 ROE 未禁伪造头时使用，**禁用于放大请求速率绕过频控**（放大=变相爆破，违反频率红线）。字典增量：厂商缩写+固定后缀组合式（`wrd@123`、`wrd!@#qwe123`）、"手册默认密码"作为独立字典类目、反向爆破（一密码打全用户）——**反向爆破额度：单密码 × 用户表抽样 ≤20 账号（或 ROE 显式额度），命中即停**。

### 泄露口令字典类目（v5.3.9 增补，osint-leak-intel 联动）

- **字典来源**：/usr/share/seclists/Passwords/（Common-Credentials/、Leaked-Databases/、dark-web2017-top10000.txt）+ 行业定向类目（"系统名+年份"、"院区简称+@123"类）；环境无 seclists 时登记并按组合式规则生成 ≤100 候选；
- **HIBP 预筛排序**（免 key，load_skill osint-leak-intel 第一节）：候选口令先过 Pwned Passwords range API，**真实泄露过的排前**——字典额度内优先打"确证在野存在"的口令，命中率优先于数量；
- **ROE 额度**：泄露口令类目并入第二节受控爆破总额度（并发 ≤4、间隔 ≥2s、锁定探测先行、命中即停），不因字典换类目重置额度；每账号候选按锁定阈值收敛（有锁定=每账号 ≤3 候选）。
## 凭据复用矩阵（v5.4 增补）

> 触发：获得任一凭据集（泄露库/确证口令/离线破解结果）。目标：实测口令复用率，横向面收窄表述。

| 步骤 | 动作 | 纪律 |
|---|---|---|
| 1 面枚举 | 同主机全部认证后端清单（不同栈各自登录面） | 只读枚举，登记面清单 |
| 2 单发抽样 | 每面 ≤5 候选单发（ROE 额度优先），锁定预言机先行评估 | 禁爆破；错误文案差分优先于时延差分 |
| 3 派生候选 | 有明确派生证据（口令=标识号固定片段已实证类）才按规则生成候选族 | 单发；无派生证据不猜测 |
| 4 三态登记 | 命中=凭据复用 finding（横向面扩大）；未命中=negative_valid | 复用结论写进横向路径图与影响评估 |

- 复用命中后按 session-state-chain 建会话做带态验证（不重复匿名面）；跨实例复用按 load_skill instance-diff 共享态判定收窄。
