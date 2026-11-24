---
id: "proxy-channels"
title: "代理通道使用手册（Web 配置的三类流量 + 工具旗标映射）"
tags: 代理,proxy,出口池,工具旗标,下载,抓包,v50
---
# 代理通道使用手册（v5.0 Web 代理模块配套）

> **来源**：Web「设置→代理配置」（v5.0）注入的变量——`$TOOL_PROXY`（工具下载代理，热生效）、`$JT_EXIT_POOL`（目标流量出口池配置文件路径，指向 exit-pool.json，配合 exit-pool.py 出口池工具使用（见通道声明配置））。
> **纪律（不变）**：对目标主机的扫描/利用流量**默认直连**（保持测试真实性）；目标流量走出口池仅限对抗目标（限速/封锁场景）且项目内显式启用（ROE 留痕）。本手册只讲「变量怎么用」，不改变流量口径。

## 一、三类流量与变量

| 流量类 | 变量 | 生效方式 | 智能体用法 |
|---|---|---|---|
| 工具下载（apt/pip/git/curl -O） | `$TOOL_PROXY` | Web 保存即注入命令环境 | 命令前缀 `env http_proxy=$TOOL_PROXY https_proxy=$TOOL_PROXY <cmd>`（loop-core 工具缺失纪律原口径） |
| 目标流量出口池 | `$JT_EXIT_POOL` | Web 启用后指向 dataDir/exit-pool.json | `python3 /opt/tools/exit-pool.py --config $JT_EXIT_POOL --next`（多出口轮换/会话分片/降级，见 rate-limit-playbook W5 增补） |
| LLM 出口 | 部署环境变量（compose LLM_PROXY） | 只读展示，重启生效 | 不在智能体可控范围（上下文包不注入） |

## 二、工具代理旗标映射（env 不生效时的原生旗标；M6「先 probe 后 batch」适用）

| 工具 | 原生旗标 | 备注 |
|---|---|---|
| curl | `-x $TOOL_PROXY`（socks5 加 `--proxy-user`） | env http_proxy 亦生效 |
| sqlmap | `--proxy=$TOOL_PROXY`（socks5 支持） | 注入通道场景配合 chain-proxy 挑战态 |
| nuclei | `-proxy $TOOL_PROXY`（http/socks） | 模板组小批量先 probe |
| httpx | `-http-proxy` / `-socks5-proxy` | 批量存活探测 |
| nmap | `--proxies socks4://…`（仅 socks4） | 多数场景不可用——传输层扫描通常直连 |
| adb/frida | 不走代理（设备通道与代理无关） | 设备页/隧道另走 ssh -R/frp |

**通则**：工具对代理支持差异大——env 试探（`env | grep -i proxy` + 单请求 probe）失败后查 `--help` 原生旗标；两者都不支持的工具如实写交付物「该工具不适用代理通道」，不硬套。

## 三、出口池会话纪律（W5 衔接）

出口池启用后，**WAF 会话状态按出口分片**（evidence/exit-<name>/）：快照态跨出口不混用；单出口连续 2 次空壳即切下一出口；出口失效 `--degrade` 标记（全降级显式错误不静默回退）。行为预算器配额为全局口径（切出口不重置配额）。
