---
id: anon-attack-surface
title: 匿名可达高危面总表（未授权面板/接口/泄露 一页速查）
tags: 未授权,actuator,druid,swagger,nacos,暴露面,s2,s4
---
# 匿名可达高危面总表（无凭证项目第一张查的表）

> 用法：S2-5/S2-7 完成指纹/JS 情报后，把本表当"探针清单"逐族过一遍；
> 每族：指纹特征 → 匿名探针（全部只读）→ 高危信号判据 → 深入技能路由。
> 本表只做**存在性证明**；利用动作（部署/写配置/命令执行）一律 S5 审批。
> **多目标批量执行**：探针全部支持 `-l targets.txt` 批量形态，一轮覆盖全部目标（宪法速度纪律 7）。

## 一、Java 生态（spring-family/middleware-web 联动）

| 目标 | 匿名探针 | 高危信号 | 转入 |
|---|---|---|---|
| Spring Actuator | /actuator /actuator/env /actuator/heapdump（逐个 401/403/200） | env 含密码项；heapdump 可下 | spring-family |
| Actuator 拦截器绕过 | /actuator/../api/v1/<保护路径>、/env;/、%2e%2e 变体 | 保护路径 200 | payload-mutation-algebra |
| Druid | /druid/index.html /druid/sql.html（未授权） | SQL 监控含语句/URI | middleware-web |
| Nacos | /nacos/（默认页）、v1/auth/users 未授权枚举、默认 key accessToken 伪造 | 用户列表/配置读取 | middleware-web |
| XXL-JOB | /xxl-job-admin/（默认 admin/123456 单试） | 任务列表可读 | middleware-web |
| Tomcat | /manager/html、/host-manager | 401 带 realm=Manager 头 | weak-cred-bruteforce |
| Tomcat 写探针（**L1 非 L0**） | PUT /1.txt/ 单请求（v5.1 移出自动执行集：写探针需审批或在 S5 消费） | 201=未授权写（高危确证）；403/401=门控有效 | payload-mutation-algebra |
| Tomcat 绕过 | /manager/html（路径变体 /;.html、/x/../manager） | 变体 200 | payload-mutation-algebra |
| Swagger/knife4j | /swagger-ui /v2/api-docs /v3/api-docs /doc.html | 接口全量清单 | api-doc-leak |

## 二、DevOps/数据层（devops-exposed/go-backend 联动）

GitLab（/api/v4/projects 匿名枚举）· Jenkins（/api/json、/asynchPeople/）·
Kibana（/app/kibana 匿名跳转）· Grafana（/api/health 版本、匿名 dashboard）·
Nexus/SonarQube（匿名 API 列举）· MinIO（/minio/ 默认口令单试）·
Redis（未授权 -h 探测，info 只读）· MongoDB/ES（无鉴权列表）·
pprof/etcd/consul/Prometheus（go-backend 表）· Kubernetes（6443 匿名、kubelet 10250、Dashboard）。

## 三、信息泄露族（S2-7 承接的直测探针）

/.git/HEAD（403 目录+200 HEAD=强暴露）· /.svn/entries、/wc.db · /.env ·
/backup.zip|wwwroot.rar|.sql · /WEB-INF/web.xml（穿越联动）· source map 残留 ·
/phpinfo.php /test.php /info.php · actuator/mappings 全接口清单 ·
错误页框架指纹（报错半截语句→sqli-deep 报错路由表）。

## 四、边缘与 OA（edge-vpn-bastion/oa-family 联动）

SSL VPN 管理面（各厂特征路径按 edge-vpn-bastion 表）· 致远/泛微/用友 OA
默认口令+未授权接口（oa-family 表）· 网络设备默认 admin/admin 单试。

## 五、流程纪律

1. 本表探针全部 L0（只读）自动执行（**例外：标注 L1 的写探针行不自动执行，走审批**——v5.1 修正与表格自洽）；**每族结果 update_coverage（vuln_class=暴露面/族名）**。
2. 命中"高危信号"→ record_finding（未授权访问/信息泄露类）→ 深入技能路由；
   未命中 → 不能 ruled_out 整族（可能路径前缀不同），登记 needs_follow_up 附已测路径清单。
3. 与 S2-9 自述面对账：自述面提到的功能若对应本表入口，收口时逐条引用。
