---
id: "channel-snapshot"
title: "通道资产固化标准动作（cookie/UA/挑战态快照与重放）"
tags: "对抗,通道,cookie,快照,瑞数,WAF,s2,s5,s6"
---
# 通道资产固化标准动作（v4.6 K1，通道健康期强制）

> 审计教训：某瑞数 WAF 目标 通道健康期约 50 分钟从未导出 cookie（全流 getCookies=0 次），
> 通道失效后 S6 才想起验证 cookie 重放——jar 是空的、cookie 早已过期，128 端点探测全灭。

## 何时必须做（强制触发点）

1. **首次过挑战成功**（浏览器拿到真实 DOM）后 1 分钟内；
2. **任何登录成功**（CLI 或浏览器）后立即；
3. 每次批量动作（dump-dom/批量导航）**之前**做一次基线快照，之后做一次对比快照。

## 快照步骤（CDP 通道）

```
python3 /opt/tools/browser-kit/channel-snapshot.py --cdp http://127.0.0.1:9222 --out evidence/channel-snapshot-<ts>
```
产物：`cookie.jar`（Netscape 格式，curl 可用）+ `meta.json`（UA/时间戳/cookie 名单/挑战特征摘要）。

## 快照重放（通道失效判定前必须先试）

通道"失效"判定前，先做**单请求重放**：
```
curl -sS -m 20 -b evidence/channel-snapshot-<ts>/cookie.jar \
  -A "$(jq -r .user_agent evidence/channel-snapshot-<ts>/meta.json)" \
  -o /dev/null -w '%{http_code} %{size_download}B\n' https://<目标>/
```
- 非 202/非空壳 → **通道未死**，用「curl+快照」通道继续探测（不需要浏览器）；
- 202 空挑战 → 快照过期（瑞数 cookie 短效，TTL 默认按 30 分钟对待），回浏览器通道重取快照。

## 纪律

- 快照是**通道资产**，失效≠删除：保留全部历史快照（时间序列可判 TTL）；
- 空壳检测：DOM <100B 或含 $_ts 即判挑战未过，立即停止批量任务（不要把空壳当数据入库）；
- 快照与 UA 绑定：重放必须带快照时的 UA（瑞数三维绑定 IP+UA+cookie，换 UA 必失效）。

## v4.8 M6 工具通道兼容性声明

> 口径（loop-core v4.8 纪律 3）：先 probe 后 batch——每个外部工具对目标首次使用前先用小样本探针确认可用性，探针被拦/挂起先切适配通道再批量；探针结果写入交付物工具声明小节。各工具在「挑战型 WAF / 封闭站」下的可用性与适配通道：

- channel-snapshot.py：适配通道本体（挑战态提取/复放）——挑战型 WAF/封闭站下始终可用，且是本清单其它工具的适配通道来源。
- curl：低频手工请求始终可用——也是挑战态复放的最小工具（channel-snapshot 快照 cookie/UA 复放）；禁用它做大批量枚举。
- channel-heartbeat.py：空闲期周期性 dump-dom 基线自检（字节判定状态机）——挑战型 WAF/封闭站下可用；判定 degraded/down 时先 channel-snapshot 重放或重建会话，勿沿用旧通道结论。

## v4.8 W5 出口池/农场衔接增补（会话状态分片）

- **出口分片**：多出口目标（W5 出口池 exit-pool.py）下，快照产物目录按出口分片（`evidence/exit-<name>/`，--next 输出 session_shard 路径）——**WAF 会话状态跨出口不混用**（IP 变化触发挑战重发=旧快照态失效），出口失效 `--degrade` 标记。
- **农场分片**：browser-farm 指纹池（profile-<i>）下快照写对应 `evidence/farm-profile-<i>/`——同 profile 同挑战态，跨 profile 不复用（指纹自矛盾会触发重挑战）。
- 快照失效排查顺序：先确认快照与出口/profile 分片是否同源 → 再判断挑战态时效 → 最后重建会话。
