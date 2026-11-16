---
id: app-dynamic-audit
title: APP 动态审计实操手册（设备通道/抓包/插桩）
tags: app,android,frida,mitmproxy,动态,specB1
---
# APP 动态审计实操手册（specB1 动态链 D1-D6 配套）


> **v5.3.0 专项前置契约（结构化记录）**：每条任务登记 artifact_source（客户提供包/合法测试包/公共包）、device_owner（客户设备/测试设备）、test_account（测试账号/租户）、network_route（隔离网络/抓包通道）、test_data（合成数据）、runtime_access（动态环境可用性）、limitations（缺失前置）。**静态线索不得替代动态确证**——设备/账号/包缺失时逐条 needs_follow_up（reason=precondition_missing），不误记为无漏洞。

## 设备通道（D1 前置）
- **容器无 USB/privileged，只能网络 adb**。7 种连接场景（Web「设备连接」页有实时状态与完整说明）：
  1. **无线调试配对（Android 11+，首选）**：`adb pair IP:配对端口` + `adb connect IP:连接端口`，免 root 免 USB
  2. **经典 tcpip 5555**：先插一次 USB 执行 `adb tcpip 5555` 再 `adb connect IP:5555`；测完 `adb usb` 切回
  3. **设备热点反连**：绕办公网 AP 隔离，设备开热点、宿主连热点
  4. **USB 线+共享宿主 adb server**：宿主 `adb -a nodaemon server`，容器 `ADB_SERVER_SOCKET=tcp:<宿主>:5037`（唯一用 USB 线的标准解法）
  5. **USB 直通容器**：devices/privileged 扩权限面，禁用
  6. **异地隧道**：ssh -R/frp 拉回；或设备 frida-server `-l 0.0.0.0:27042` 后 `frida -H` 直连（免 adb）
  7. **云真机/农场**（Sonic/atxserver2/STF）：多设备并行时用
- **frida-server 注入**：先查架构 `adb shell getprop ro.product.cpu.abi`（arm64-v8a 居多），下载**与容器内 frida-tools 同版本**的 frida-server 对应架构包：
  ```bash
  pip install frida-tools          # 缺失时 install_tool 自动装（走 TOOL_PROXY）
  adb push frida-server /data/local/tmp/ && adb shell "chmod 755 /data/local/tmp/frida-server"
  adb shell "nohup /data/local/tmp/frida-server >/dev/null 2>&1 &"   # 长驻 → 配 run_async
  frida-ps -U                      # 出进程列表=链路通
  ```
- **长驻进程一律 run_async**（frida-server / mitmdump / logcat 采集），同步命令 30 分钟硬上限。

## 抓包链路（D2）
```bash
mitmdump --listen-host 0.0.0.0 -p 8080 -s 脚本.py    # 容器 8080 已映射宿主；设备 WiFi 代理指向 宿主IP:8080
```
- **Android 7+ 用户 CA 不被 APP 信任**：root 设备用 Magisk 模块把 mitmproxy CA 移入系统证书区（/system/etc/security/cacerts 按 hash 命名）；无法 root 时改走静态层（反编译提取签名算法自构造请求），或 objection `patchapk` 重打包注入 network_security_config（加固壳包重打包易碎，慎用）。
- **SSL Pinning 绕过**：先试通用脚本（objection `android sslpinning-disable`、friTap）；**通用脚本失效=加固/自实现校验**，回静态链定位 OkHttp `CertificatePinner` / 自定义 TrustManager 的具体类，生成针对性 hook——不硬磕。

## 运行时插桩（D3）
```bash
frida -U -f com.target.pkg -l hook.js --no-pause     # spawn 模式过反调试早挂
objection -g com.target.pkg explore                  # 交互式：android sslpinning-disable / hooking list
```
- hook 目标优先级：Cipher.doFinal / Mac.doFinal（还原算法与密钥）→ 签名拼接函数 → token 生成点；输出与静态结论 diff（specB1 S5 假设队列），误判回写静态链。

## 真机 vs 模拟器选型
| 维度 | root 真机 | 模拟器(AVD) |
|---|---|---|
| 环境真实性/加固兼容 | ✅ ARM+真实 TEE，加固壳正常跑 | ⚠️ x86 跑 ARM-only so 依赖翻译层（Android 11+ 基本无解） |
| 模拟器检测 | ✅ 无此问题 | ❌ 国内 APP 普遍检测（改属性也难全绕） |
| 快照/恢复 | ❌ 手动清理 | ✅ 秒级 revert，适合批量脏测试 |
| 本部署可用性 | ✅ 无线 adb 即接入（**当前唯一现实路径**） | ❌ 容器无 /dev/kvm；宿主机可跑则代理指向容器 8080 兜底 |

结论：**主力 root 真机，模拟器仅作快照型初筛/兜底**。

## 纪律
- 仅测试设备与测试账号；绕过与爆破严格限频；支付/下单等写操作先审批；脱壳与 hook 产物仅授权测试用、禁止分发；测试结束 `adb uninstall` 与设备代理配置回退（S7 清理）。

## 抓包三难点解法（v5.1 口径对齐：Frida 通道为主，本节为历史备选——与主线"主力 root 真机"结论冲突时以主线为准）

- **反"代理检测"**：Frida 绕过代理检测 hook 为先（主线通道）；无 Frida 环境时的历史备选：模拟器关代理，宿主机 Proxifier 按进程规则强制走 Burp——无系统代理抓包
- **双向认证（SSL Pinning）**：Frida objection/unpinning 脚本为主（主线）；Xposed+JustTrustMe 为历史备选（注意 xposed 生态已停更，且不支持 Android 7+）——已有 Frida 方案时不要回退此路径
- **iOS 证书信任遗漏**：装描述文件后必须到 设置→通用→关于本机→证书信任设置 手动开 PortSwigger CA 完全信任，否则抓不到