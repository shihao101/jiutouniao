# 贡献指南（CONTRIBUTING）

感谢关注九头鸟（鬼車）！欢迎以 Issue / Discussion / Pull Request 的方式参与贡献。

## 开发环境

| 依赖 | 版本 | 用途 |
|---|---|---|
| Go | 1.23+（推荐 1.26） | 核心引擎（`server/`） |
| Node.js | 20+（推荐 24） | Web 控制台（`web-app/`，Vue3 + Vite） |
| Docker + compose v2 | 可选 | 容器化部署（Kali 工具链底座） |

## 本地开发

```bash
make build    # 编译 Go 引擎 → ./jiutouniao
make web      # 构建前端 → web/（本地运行需要；Docker 部署可跳过）
make run      # 启动（默认 http://localhost:8787，无 Key 演示模式 config.json 里 "mock": true）
make test     # Go 全量单元测试
```

- 头提示词（`heads/*.md`）、技能库（`skills/*.md`）、执行循环宪法（`prompts/loop-core.md`）可直接编辑，重启生效；
- 技能增删后运行 `python3 scripts/gen_skill_manifest.py` 重新生成 `skills/manifest.json`；
- 前端改动建议跑 `make ui-check`（体积预算守卫）。

## 提交规范

1. **一个 PR 一件事**：修复、功能、文档分开提交；
2. **提交信息**：`类型(范围): 摘要`，如 `fix(engine): s8 收口死锁` / `feat(skills): 新增 xx 技能`；
3. **测试**：引擎行为变更需带单元测试（`server/internal/**`，参照既有 `v5xx_*_test.go` 风格）；PR 会自动跑 CI（敏感扫描 + go build/vet/test + 前端构建）；
4. **版本记录**：影响用户可见行为的改动，请在 `web-app/src/pages/ChangelogPage.vue` 的 `CHANGELOG` 数组与 `CHANGELOG.md` 同步补条目（发版由维护者统一递增版本常量，遵循「遇十进一」规则）。

## 安全边界（重要）

- **不得降低合规护栏**：审批矩阵、确定性治理门（Execution Profile / ROE 写门 / strict_scope 范围门）、FORBIDDEN 禁令、路径沙箱、证据链留痕——任何削弱这些机制的 PR 不会被接受；新增能力请同步补齐风险分级与护栏正则（`server/internal/config/config.go`）；
- **不得提交敏感数据**：`projects/`（客户任务数据）、`config.json`、`.env`、密钥、令牌、真实目标信息一律不入库；提交前自查：`python3 scripts/sweep-sensitive.py`；
- **技能/提示词内容**：只收方法论与公有技术 payload，禁止携带真实目标痕迹（域名/IP/内部项目编号）；
- **第三方组件**：引入新依赖需声明来源与许可（README「第三方组件声明」表）。

## 报告缺陷

普通缺陷走 [Issue（bug 模板）](https://github.com/shihao101/jiutouniao/issues/new?template=bug_report.md)；**安全漏洞请勿公开 Issue**，走 [SECURITY.md](SECURITY.md) 的私密披露通道。

## 许可

提交即表示同意以 [MIT License](LICENSE) 许可你的贡献；引入第三方代码需保证许可兼容并注明出处。
