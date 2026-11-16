---
id: "crypto-offensive"
title: "前端加密/签名协议还原与请求伪造（v4.6 W3：破解→投递→取证一体化）"
tags: "对抗,加密,签名,SM4,WASM,投递,s4,s5"
---
# 前端加密/签名协议还原与请求伪造（v4.6 W3/C2）

> 审计核心教训：某瑞数 WAF 目标 签名（MD5 拼接签名（secret 明文硬编码））/SM4 密钥/128 端点全部破解，
> **一发未投**（转化率 0）；某安全设备管理面目标 WASM oracle 高对齐率还原后登录成功。
> 破解≠终点，投递+取证才是产出。

## 一、协议还原器（标准步骤）

1. bundle 定位加密/签名函数（encryptMD5/sm4.encrypt/_encryptWebuiString/wasm 导出）；
2. 产出**可执行 oracle**（Node/Python 模块 + ≥3 组单测向量：明文→密文/签名对照 bundle 内样例）；
3. WASM 类：`cryptoParam.wasm` 必须当场落盘（差 1 请求=整链搁浅，实证案例）；
   wasm2wat 反编译→本地调用复现（oracle 单测全对齐即可投递）；
4. oracle 落盘 `poc/request-forge-<目标>.py`，单测通过才算还原完成。

## 二、投递器（三通道，按目标行为类选）

| 目标类 | 通道 |
|---|---|
| 无 WAF | curl/requests 直连（带签名头） |
| 限速型 | rate-limit-playbook 窗口化投递 |
| JS 挑战型 | channel-snapshot 的 cookie+UA 经 curl 重放；失效则浏览器通道（CDP fetch 带签名头复测——单次实验结论标 sample_size=单次实验，不得跨目标继承） |

**每次投递强制**：请求原文+响应原文落盘 evidence/，json_code/HTTP 状态码双记录（某瑞数 WAF 案例 探测
无状态码=结果不可判定的根因）；结果回填 record_finding claims。

## 三、Authz-Diff 消费（配合 authz-diff 技能）

签名还原后立即对情报工厂端点表跑差分矩阵：无 token/无签名/正确签名 × GET/POST ×
{真实端点, 阳性对照, 阴性乱码对照}。工具：`python3 tools-extra/authz-diff.py --help`。

## Execution Profile 标注（v5.3.2）

- **Lab Only 动作**：签名/加密绕过的完整利用投递（生产档仅做算法弱点证明与降级面探测）——仅 isolated_lab（可快照回滚的隔离靶场，项目显式声明）可执行；production_safe 下引擎逐动作强制禁止（v5.3.1 governanceGates 全通道确定性拦截并留证），不要尝试绕行。
- **production_safe 口径**：只做存在性证明（无害回显/随机标记/受控 OOB/量级与哈希证明），可达性证明即止。
- **工件处置两档分流**：生产=四元组（路径/指纹/建议清理命令/验证命令）登记移交《需人工清理清单》；实验室=快照恢复/环境重置回收（恢复成功须只读验证）。两档均不执行目标侧删除/还原。
