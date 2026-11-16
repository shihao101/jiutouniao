<!-- 提交前请确认：目标域名/IP/客户数据/密钥/令牌未出现在 diff 中（CI 会跑 scripts/sweep-sensitive.py） -->

## 变更说明

<!-- 这个 PR 做了什么，为什么 -->

## 变更类型

- [ ] 缺陷修复（fix）
- [ ] 新功能（feat）
- [ ] 头提示词 / 技能库 / 方法论内容
- [ ] 文档
- [ ] 构建 / CI / 其他

## 合规护栏自查（触碰执行链路必填）

<!-- 改动涉及 run_command / 审批矩阵 / 治理门 / 沙箱 / 工具执行器时必须说明 -->

- [ ] 不涉及执行链路，或：已说明对风险分级 / 审批 / 治理门的影响并补齐单测

## 测试证据

- [ ] `make test` 通过（新增行为带单测）
- [ ] 前端改动：`make ui-check` / 构建通过
- [ ] `python3 scripts/sweep-sensitive.py` 通过

## 版本记录

- [ ] 用户可见行为变更已在 `web-app/src/pages/ChangelogPage.vue` 与 `CHANGELOG.md` 补条目（版本常量由维护者发版时统一递增）
