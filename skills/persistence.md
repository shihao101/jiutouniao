---
id: persistence
title: 权限维持与持久化演示（per-OS 清单 + 清理映射）
tags: 持久化,权限维持,清理,s6,s7
---
# 权限维持与持久化演示

**定位**：S6-4 的执行剧本——ROE 允许时**演示**权限维持并逐项登记移交清单（v4.8.1 口径：S7 只记录不处置——智能体产生的全部后门/驻留工件一律移交人工，不执行删除/重启/还原等高风险操作）。**默认不做**；能一条命令验证影响就不留第二分钟；每项必须四元组登记（位置/指纹/建议清理命令/验证命令），未登记的驻留视为违规（反思门会拦）。

## 一、Linux 持久化候选（按隐蔽度排序，演示一至两项即可证明）

| 方式 | 演示命令骨架 | 建议清理命令（仅供人工参考，智能体不执行） | 验证 |
|---|---|---|---|
| cron 计划任务 | `echo '* * * * * root /opt/.jt-beacon.sh' > /etc/cron.d/jt-persist`（脚本内容=无害心跳如 `date >> /tmp/.jt-hb`） | `rm /etc/cron.d/jt-persist` + 删脚本 | `ls /etc/cron.d/` 无该项 |
| systemd user 服务 | `~/.config/systemd/user/jt.service` + `systemctl --user enable` | `disable` + 删单元文件 | `systemctl --user list-unit-files` |
| SSH authorized_keys | 追加测试公钥到 `/root/.ssh/authorized_keys` | 移除该行（先备份行号） | 登录失败 |
| 用户态启动项 | `~/.profile` 追加心跳行 | 还原文件（保留原文副本到 evidence） | 重登无执行 |
| at 一次性任务 | `at now + 1 hour` 心跳 | `atq`/`atrm` | 队列为空 |

## 二、Windows 持久化候选

| 方式 | 演示 | 清理 | 验证 |
|---|---|---|---|
| 计划任务 | `schtasks /create /tn JtPersist /sc daily /tr "cmd /c echo hb >> C:\ProgramData\.jt-hb"` | `schtasks /delete /tn JtPersist /f` | `schtasks /query` |
| 注册表 Run 键 | `reg add HKLM\...\Run /v JtUpdate /d <无害载荷>` | `reg delete` | `reg query` |
| 新本地用户 | `net user jt_test Jt@Demo! /add`（标注到 S7 清理清单） | `net user jt_test /delete` | `net user` |
| 服务 | `sc create JtSvc binPath= ...` | `sc delete` | `sc query` |
| WMI 事件订阅 | 原理演示为主（命令级落盘需 ROE 明确允许） | 删除订阅 | `Get-WmiObject` |

## 三、Web 层持久化（与 webshell-memshell 对接，v4.8.1 口径修改）

- 文件马/内存马四元组登记进**《上传文件记录清单》**并移交《需人工清理清单》——**不执行删除、不触发应用重启、不卸载 Filter**。
- **v4.8.1 全域口径**：上表 cron/服务/SSH 公钥/账号等全部自建驻留与上传类同等处理——**只登记移交，S7 不执行任何清理/还原/重启**（智能体产生的后门包含但不限于上传类）。
- 数据库层（如后台可写模板/计划任务配置）：只登记位置与指纹，**不改生产配置**，写"可持久化判据"即可证明影响。

## 四、执行纪律

1. **ROE 门禁**：S6-4 默认跳过并在交付物注明"ROE 未授权持久化演示"；ROE 允许时也**只演示最小集**。
2. **心跳无害化**：任何持久化载荷只做时间戳心跳/只读命令，禁止下载执行类内容。
3. **登记先行**：创建前先把四元组写入《持久化记录》交付物 + record_loot(type=session)；S7 **只核对清单完整性与移交**，不执行清理——验证命令供人工处置后使用。
4. **凭证不做持久化**：真实凭据不落地（掩码口径不变）；持久化只依赖自建工件。

## 五、存量持久化痕迹排查（v4.8.1 增补：前人/第三方遗留后门的只读清点）

> **定位**：S6-6 的执行清单——拿到 RCE/落点后，对主机做**既有持久化面排查**（不是自建演示！）。口径：**只发现、只登记、不处置**——存量数据绝对不动（loop-core 清理铁律），确证后门的处置属客户环境运维决策，列入《需人工清理清单》移交。

### Linux 排查清单（全部只读）

| 排查项 | 只读命令骨架 | 可疑信号 |
|---|---|---|
| 计划任务 | `cat /etc/crontab /etc/cron.d/* /var/spool/cron/* 2>/dev/null`、`systemctl list-timers --all`、`atq; ls -la /var/spool/cron/atjobs 2>/dev/null`（v6.7.0 补：at 一次性任务） | 指向 /tmp//dev/shm/非常见路径的执行项、最近新增且无业务归属 |
| SSH 后门 | `grep -v '^#' /root/.ssh/authorized_keys`（逐用户）、`stat` 各 authorized_keys 修改时间；`cat ~/.ssh/known_hosts` 新增条目比对（v6.7.0 补） | 非运维窗口新增的公钥、备注异常；known_hosts 突然出现授权拓扑外的内网主机指纹（=横向线索或前人遗留） |
| 账号面 | `awk -F: '$3>=1000{print}' /etc/passwd`、`passwd -S` 全量、`/etc/shadow` 最近修改 | uid≥1000 非业务账号、空口令/已锁标记异常 |
| 启动项 | `ls ~/.config/autostart /etc/xdg/autostart`、`cat ~/.profile ~/.bashrc` 尾部 | 隐藏文件执行行、base64/eval 类内容 |
| 进程/端口 | `ss -tlnp`、`ps aux`（对比业务基线） | 未知监听、/tmp 起源进程、非常规端口服务 |
| Web 持久化 | web 目录可解析文件清单（`find <webroot> -name '*.php' -newer <基线文件>` 类）+ 内容特征扫描（eval/assert/system+混淆串） | 时间戳与业务发布窗不符、无路由归属的可解析文件 |
| 系统服务 | `systemctl list-unit-files --state=enabled` | 非包管理器安装的 unit（ExecStart 指向非常规路径） |
| 内核/驱动层 | `lsmod`（对比基线）、`dmesg` 异常 | 未知 LKM |
| 容器层（如在容器内） | 挂载表 `mount`、`docker inspect`（若可读） | hostPath 挂载、privileged 运行的业务外容器 |
| 数据库层 | 作业/触发器/事件只读列举 | 指向文件写或外联的作业 |

### Windows 排查清单（只读）

| 排查项 | 只读命令骨架 | 可疑信号 |
|---|---|---|
| 计划任务 | `schtasks /query /fo LIST` | 非业务命名、触发器指向用户态临时目录 |
| 注册表 Run | `reg query HKLM\...\Run /s` + HKCU 同查 | 指向 %APPDATA%/%TEMP% 的项 |
| 服务 | `sc query state= all` | binPath 指向非常规路径 |
| 账号 | `net user` + `net localgroup administrators` | 非业务账号、异常管理员组成员 |
| WMI 订阅 | `Get-WmiObject -Namespace root\subscription -Class __EventConsumer` | CommandLineEventConsumer 类持久化 |
| Web 持久化 | webshell 特征扫描（同 Linux 口径） | 同上 |

### 处置口径

1. **登记分级**：确证第三方后门（有归属线索/时间线印证）→ record_finding（severity=高，confidence=疑似/确证按证据）；可疑但无法定性 → record_finding（待查）+ detail 写「待客户确证」；全部同步《需人工清理清单》（位置/指纹/建议处置/风险说明四要素）。
2. **证据留存**：每项附只读命令输出落 evidence/（原文即证据，不做变更动作）。
3. **与自建严格隔离**：自建演示走 S6-4 四元组（登记→S7 清理）；存量排查项永不进入《清理确认清单》的执行侧——只在移交清单。
4. **报告承接**：S8 报告「存量风险/遗留后门」单列（与本次测试发现区分标注「存量」），避免责任混淆——这是合规边界也是客户价值点。

## Execution Profile 标注（v5.3.2）

- **Lab Only 动作**：植入计划任务/启动项/SSH 公钥/服务注册/容器逃逸驻留等持久化演示动作——仅 isolated_lab（可快照回滚的隔离靶场，项目显式声明）可执行；production_safe 下引擎逐动作强制禁止（v5.3.1 governanceGates 全通道确定性拦截并留证），不要尝试绕行。
- **production_safe 口径**：只做存在性证明（无害回显/随机标记/受控 OOB/量级与哈希证明），可达性证明即止。
- **工件处置两档分流**：生产=四元组（路径/指纹/建议清理命令/验证命令）登记移交《需人工清理清单》；实验室=快照恢复/环境重置回收（恢复成功须只读验证）。两档均不执行目标侧删除/还原。
