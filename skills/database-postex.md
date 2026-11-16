---
id: database-postex
title: 数据库后渗透手册（redis/mysql/mssql/pgsql/mongo）
tags: database,redis,mysql,mssql,pgsql,后渗透,s6
---
# 数据库后渗透手册（**写操作全部 S5 审批**；本手册 s6 阶段以「影响证明」为目标）

## 一、Redis（内网未授权/弱口令第一落点）

```bash
# 只读判据：redis-cli -h x INFO server（版本/OS）、CONFIG GET dir、DBSIZE
# 键存在性：KEYS 前缀遍历（限 10 键采样，禁止全量 KEYS 大库）
# 危害路径（S5）：CONFIG SET dir + 写 key 落盘（webshell/cron/ssh key）——写前必须基线快照 + S7 清理方案
# 主从复制面（rogue master）：高危，S5，仅测试节点
```

## 二、MySQL

```bash
# 判据：SELECT version(),user(),@@datadir；secure_file_priv 现状（NULL=无文件面）
# UDF：拥有 mysql 插件目录写权限时候选（S5，动态库注入=植入类动作，ROE 明确允许才做）
# general_log 写 shell：S5；日志文件落点只读确认
```

## 三、MSSQL

```bash
# 判据：SELECT @@version, IS_SRVROLEMEMBER('sysadmin')；xp_cmdshell 现状（启用状态只读查询）
# xp_cmdshell 启用+执行：S5（等价命令执行）；SP_EXECUTE 差异判据
# 链接服务器（linked server）：枚举判据 → 跨库/跨机跳转路径图
```

## 四、PostgreSQL / MongoDB

```bash
# PG：COPY TO PROGRAM（superuser+S5）；pg_read_file 判据（读公开配置样例）
# 大对象/扩展面枚举；Mongo：未授权探活 → 用户/集合枚举（只读）→ 敏感集合存在性（计数+哈希前缀）
```

## 五、统一纪律

- **只读枚举优先**：版本/权限/文件权限配置 → 产出《数据库影响矩阵》（谁可从 DB 落到 OS）。
- 数据内容：存在性证明（count/字段名/单行哈希前缀）；批量导出禁止（红线 3）。
- 任何写落盘动作：S5 审批 + 写前快照 + S7 精确清理（自建 key/文件清单入清理表）。

## Execution Profile 标注（v5.3.2）

- **Lab Only 动作**：数据库新账号创建、写操作、批量数据导出落盘（生产档只做只读取证与量级证明）——仅 isolated_lab（可快照回滚的隔离靶场，项目显式声明）可执行；production_safe 下引擎逐动作强制禁止（v5.3.1 governanceGates 全通道确定性拦截并留证），不要尝试绕行。
- **production_safe 口径**：只做存在性证明（无害回显/随机标记/受控 OOB/量级与哈希证明），可达性证明即止。
- **工件处置两档分流**：生产=四元组（路径/指纹/建议清理命令/验证命令）登记移交《需人工清理清单》；实验室=快照恢复/环境重置回收（恢复成功须只读验证）。两档均不执行目标侧删除/还原。
