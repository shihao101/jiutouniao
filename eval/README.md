# 评测环（make eval）

本目录承载九头鸟「技能进化评测环」（communitytools 思想）：
起本地靶场 → 经 API 跑完整项目 → 按预期清单判分 → 产出评测报告 → 未命中项作为技能库迭代输入。

## 本分发的纯净口径（v4.4.3 起）

**本部署包默认不包含评测靶场**（`eval/target/` 故意脆弱应用与 `eval/expected.json`
预期漏洞清单），以保持纯净开源部署包口径——不含任何可被误用的靶场资产。

如需启用评测环，两种方式：

1. **上游仓库获取**：从九头鸟主仓库恢复 `eval/target/` 与 `eval/expected.json` 后，
   `make eval` 即可运行（判分器 `scripts/eval_run.py` 随包分发，接口不变）；
2. **自建靶场**：实现一个只绑定 127.0.0.1 的 HTTP 服务，`scripts/eval_run.py` 的
   `start_target()` 检测到容器内 `/app/eval/target/target.py` 缺失时会给出明确报错。

其余机制说明（判分双指标 + 匿名高危召回、declared/hidden 双模式）见 README「评测环」节
与上游仓库的完整实现。
