package engine

// v6.3.0 S3 修复方案回归测试（docs/修复方案_S3威胁建模阶段补全_v6.3.0_20261123.md）：
// S3-① s3 确定性收口门 / S3-② 判定表目标列与复合键 / S3-③ VT·候选上下文注入+update_vt ready
// / S3-④ T-xx 计划承接门 / S3-⑤ 端点表↔矩阵运行时门 / S3-⑥ 审批工单状态注入 / S3-⑧ 容量治理。

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"jiutouniao/internal/store"
)

// writeS3ClosureDeliverables 写入 S3-① 收口门要求的最小三件套（威胁模型含 TH、测试计划含
// T 编号+审批点+候选清单声明），供 v48 既有用例与本项目复用。
func writeS3ClosureDeliverables(t *testing.T, o *Orchestrator, p *store.Project) {
	t.Helper()
	_, _ = o.exec.WriteFile(p.ID, "deliverables/s3-威胁模型.md",
		"# S3 威胁模型\n\n## DFD\n外部实体/进程/数据存储/数据流；信任边界标注。\n\n## 威胁清单\n- TH-01 会话固定（L2×I2=P2）\n- TH-02 注入面（L2×I3=P1）\n")
	_, _ = o.exec.WriteFile(p.ID, "deliverables/s3-测试计划.md",
		"# S3 测试计划\n\n| 编号 | 对象 | 审批 | 时间窗 |\n|---|---|---|---|\n| T-01 | 登录面枚举 | — | 第1轮 |\n| T-02 | 注入探针 | L2 | 第2轮 |\n\nS2 未产出候选清单（S2-8 零版本指纹）。\n未产出端点表：夹具项目无 API 面（S4-② 声明形态）。\n")
}

// ---------- S3-① s3 确定性收口门 ----------

func TestV630S3ClosureGate(t *testing.T) {
	o, _ := v48Orchestrator(t)
	p := &store.Project{ ROEAcknowledgedAt: "2026-11-22T00:00:00Z",ID: "P-V630S3C"}
	_ = o.store.SaveProject(p)

	// ① 威胁模型缺失 → 拦截
	_, _ = o.exec.WriteFile(p.ID, "deliverables/s3-筛查矩阵判定表.md", matrixTableFixture(nil, nil))
	issues := o.s3ClosureIssues(p)
	if len(issues) == 0 || !strings.Contains(issues[0], "s3-威胁模型.md") {
		t.Fatalf("威胁模型缺失应拦截: %v", issues)
	}
	// ② 威胁模型无 TH 编号 → 拦截
	_, _ = o.exec.WriteFile(p.ID, "deliverables/s3-威胁模型.md", "# 威胁模型\n只有 DFD 描述，无结构化清单。\n")
	issues = o.s3ClosureIssues(p)
	foundTH := false
	for _, is := range issues {
		if strings.Contains(is, "TH 编号") {
			foundTH = true
		}
	}
	if !foundTH {
		t.Fatalf("威胁模型无 TH 编号应拦截: %v", issues)
	}
	// ③ 测试计划缺失 + 候选清单缺失声明 → 组合拦截
	_, _ = o.exec.WriteFile(p.ID, "deliverables/s3-威胁模型.md", "# 威胁模型\nTH-01 会话固定\nTH-02 注入面\n")
	issues = o.s3ClosureIssues(p)
	foundPlan := false
	for _, is := range issues {
		if strings.Contains(is, "s3-测试计划.md") {
			foundPlan = true
		}
	}
	if !foundPlan {
		t.Fatalf("测试计划缺失应拦截: %v", issues)
	}
	// ③a v6.3.0 补强（S3-⑨①）：TH 条目无等级标注 → 拦截；补 P 级 → 该项消除
	_, _ = o.exec.WriteFile(p.ID, "deliverables/s3-威胁模型.md", "# 威胁模型\nTH-01 会话固定\nTH-02 注入面\n")
	issues = o.s3ClosureIssues(p)
	foundLevel := false
	for _, is := range issues {
		if strings.Contains(is, "等级标注") {
			foundLevel = true
		}
	}
	if !foundLevel {
		t.Fatalf("TH 无等级标注应拦截: %v", issues)
	}
	_, _ = o.exec.WriteFile(p.ID, "deliverables/s3-威胁模型.md", "# 威胁模型\nTH-01 会话固定（L2×I2=P2）\nTH-02 注入面（L2×I3=P1）\n")
	issues = o.s3ClosureIssues(p)
	for _, is := range issues {
		if strings.Contains(is, "等级标注") {
			t.Fatalf("已标注等级不应再拦: %v", issues)
		}
	}
	// ③b v6.3.0 补强（S3-⑦②）：拓扑重建存在而威胁模型未引用 → 拦截；引用后消除
	_, _ = o.exec.WriteFile(p.ID, "deliverables/拓扑重建-V1.md", "# 拓扑重建 V1\n响应头指纹/错误页/JS 内网引用/端口差分四源。\n")
	issues = o.s3ClosureIssues(p)
	foundTR := false
	for _, is := range issues {
		if strings.Contains(is, "拓扑重建") {
			foundTR = true
		}
	}
	if !foundTR {
		t.Fatalf("威胁模型未引用拓扑重建应拦截: %v", issues)
	}
	_, _ = o.exec.WriteFile(p.ID, "deliverables/s3-威胁模型.md", "# 威胁模型\nDFD 以拓扑重建-V1.md 校准（四源核对完成）。\nTH-01 会话固定（L2×I2=P2）\n")
	// ④ 计划存在但无 T 编号 → 拦截（内容 >40 字节绕过空壳判定，专测 T 编号锚点）
	_, _ = o.exec.WriteFile(p.ID, "deliverables/s3-测试计划.md",
		"# 计划\n\n本计划包含完整的排期安排、审批点标注与回滚方案说明，用于承载测试计划正文内容，但暂未编号。\nS2 未产出候选清单。\n")
	issues = o.s3ClosureIssues(p)
	foundT := false
	for _, is := range issues {
		if strings.Contains(is, "T-xx 条目编号") {
			foundT = true
		}
	}
	if !foundT {
		t.Fatalf("计划无 T-xx 编号应拦截: %v", issues)
	}
	// ⑤ S2 候选清单存在但计划无对照层 → 拦截
	_, _ = o.exec.WriteFile(p.ID, "deliverables/s2-已知漏洞候选清单.md", "# 已知漏洞候选清单\n- Envoy 1.28 CVE-2024-xxx\n")
	_, _ = o.exec.WriteFile(p.ID, "deliverables/s3-测试计划.md", "# 计划\n| T-01 | 登录面 | 审批点: 无 L2 |\n")
	issues = o.s3ClosureIssues(p)
	foundCVE := false
	for _, is := range issues {
		if strings.Contains(is, "无对照层") {
			foundCVE = true
		}
	}
	if !foundCVE {
		t.Fatalf("候选清单在而计划无对照层应拦截: %v", issues)
	}
	// ⑥ 计划含对照层 → 通过（checklist.json 不存在不触发⑤项）
	// v6.4.0（S4-②）：计划须同时含端点表产物或「未产出端点表」声明——本用例走声明形态。
	_, _ = o.exec.WriteFile(p.ID, "deliverables/s3-测试计划.md", "# 计划\n| T-01 | CVE 对照层复测 Envoy CVE-2024-xxx | 审批 | 窗内 |\n未产出端点表：无 API 面\n")
	if issues := o.s3ClosureIssues(p); len(issues) != 0 {
		t.Fatalf("三件套齐备应放行: %v", issues)
	}
	// ⑦ checklist.json 存在但计划零条目引用 → 拦截；计划引用 C1 → 放行
	_, _ = o.exec.WriteFile(p.ID, "checklist.json", `{"items":[{"id":"C1","item":"上传附件","hint":"投单页","class":"上传绕过"}]}`)
	issues = o.s3ClosureIssues(p)
	foundCK := false
	for _, is := range issues {
		if strings.Contains(is, "checklist.json") {
			foundCK = true
		}
	}
	if !foundCK {
		t.Fatalf("checklist 零引用应拦截: %v", issues)
	}
	_, _ = o.exec.WriteFile(p.ID, "deliverables/s3-测试计划.md", "# 计划\n| T-01 | C1 上传面存在性 + CVE 候选清单对照复测 | 审批 | 窗内 |\n未产出端点表：无 API 面\n")
	if issues := o.s3ClosureIssues(p); len(issues) != 0 {
		t.Fatalf("计划引用 checklist 条目应放行: %v", issues)
	}
}

// ---------- S3-② M2 证据指针核存 + 执行卡口径统一 + 目标列 ----------

func TestV630MatrixEvidenceAndCards(t *testing.T) {
	o, _ := v48Orchestrator(t)
	p := &store.Project{ ROEAcknowledgedAt: "2026-11-22T00:00:00Z",ID: "P-V630M2"}
	_ = o.store.SaveProject(p)

	// ① 判定表引用不存在的 evidence 文件 → 拦截
	table := strings.Replace(matrixTableFixture(nil, nil), "证据指针", "证据：evidence/s2-loginpages.txt", 1)
	_, _ = o.exec.WriteFile(p.ID, "deliverables/s3-筛查矩阵判定表.md", table)
	issues := o.matrixTableIssues(p)
	if len(issues) == 0 || !strings.Contains(issues[0], "证据指针门") {
		t.Fatalf("幻觉证据路径应拦截: %v", issues)
	}
	// ② 证据文件落盘后 → 通过（evidence 引用核存命中）
	_, _ = o.exec.WriteFile(p.ID, "evidence/s2-loginpages.txt", "login pages list\n")
	issues = o.matrixTableIssues(p)
	if len(issues) != 0 {
		t.Fatalf("证据落盘后应放行: %v", issues)
	}
	// ③ 待判定行无执行卡 → 拦截（v6.3.0 口径统一）
	var b strings.Builder
	for i := 1; i <= 27; i++ {
		verdict := "假设"
		if i%5 == 0 {
			verdict = "不适用"
		} else if i%7 == 0 {
			verdict = "待判定"
		}
		if verdict == "待判定" {
			b.WriteString(fmt.Sprintf("| C-%02d | 触发面摘要 | %s | 证据指针 | 双轨并列：穿越 OR SSRF |\n", i, verdict))
		} else if verdict == "假设" {
			b.WriteString(fmt.Sprintf("| C-%02d | 入口: /e%d 探针: GET 阳性: 差异 阴性: 同 停止: 6 | %s | 证据指针 | TH |\n", i, i, verdict))
		} else {
			b.WriteString(fmt.Sprintf("| C-%02d | 触发面摘要 | %s | 证据指针 | — |\n", i, verdict))
		}
	}
	_, _ = o.exec.WriteFile(p.ID, "deliverables/s3-筛查矩阵判定表.md", b.String())
	issues = o.matrixTableIssues(p)
	if len(issues) == 0 || !strings.Contains(issues[0], "执行卡门") {
		t.Fatalf("待判定行无执行卡应拦截: %v", issues)
	}
	// ④ guard 关闭 → 回退旧口径（待判定行不要求卡），同一张表放行
	tf := false
	o.cfg.Guard.EnforceTargetClassMatrix = &tf
	issues = o.matrixTableIssues(p)
	if len(issues) != 0 {
		t.Fatalf("guard 关闭应回退旧口径放行: %v", issues)
	}
}

// 多目标 (类×目标) 覆盖完备性：缺组合拦截 / 合并行放行 / 未落目标粒度拦截 / token 不匹配拦截
func TestV630MatrixTargetColumn(t *testing.T) {
	o, _ := v48Orchestrator(t)
	p := &store.Project{ ROEAcknowledgedAt: "2026-11-22T00:00:00Z",ID: "P-V630MT", Target: "https://t1.example\nt2.example\nt3.example"}
	_ = o.store.SaveProject(p)

	// ① 多目标 + 假设行未落目标粒度（5 列）→ 拦截
	_, _ = o.exec.WriteFile(p.ID, "deliverables/s3-筛查矩阵判定表.md", matrixTableFixture(nil, nil))
	issues := o.matrixTableIssues(p)
	if len(issues) == 0 || !strings.Contains(issues[0], "未落目标粒度") {
		t.Fatalf("多目标 5 列假设行应拦截: %v", issues)
	}
	// ② 6 列格式：假设/待判定行覆盖全部 3 目标、不适用行（全目标）声明 → 全部通过
	var b strings.Builder
	for i := 1; i <= 27; i++ {
		verdict := "假设"
		targets := "t1.example,t2.example,t3.example"
		if i%5 == 0 {
			verdict = "不适用"
			targets = "（全目标）"
		} else if i%7 == 0 {
			verdict = "待判定"
		}
		if verdict == "不适用" {
			b.WriteString(fmt.Sprintf("| C-%02d | %s | 核查无面 | %s | 证据：全部 3 目标核查 | — |\n", i, targets, verdict))
		} else {
			b.WriteString(fmt.Sprintf("| C-%02d | %s | 入口: /e%d 探针: GET 阳性: 差异 阴性: 同 停止: 6 | %s | 证据指针 | TH |\n", i, targets, i, verdict))
		}
	}
	_, _ = o.exec.WriteFile(p.ID, "deliverables/s3-筛查矩阵判定表.md", b.String())
	if issues := o.matrixTableIssues(p); len(issues) != 0 {
		t.Fatalf("逐目标 6 列判定表应放行: %v", issues)
	}
	// ③ 缺 (C-01, t2/t3) 组合 → 拦截
	partial := strings.Replace(b.String(), "| C-01 | t1.example,t2.example,t3.example |", "| C-01 | t1.example |", 1)
	_, _ = o.exec.WriteFile(p.ID, "deliverables/s3-筛查矩阵判定表.md", partial)
	issues = o.matrixTableIssues(p)
	if len(issues) == 0 || !strings.Contains(issues[0], "覆盖不全") || !strings.Contains(issues[0], "C-01") {
		t.Fatalf("缺 (类×目标) 组合应拦截: %v", issues)
	}
	// ④ 目标列 token 无法匹配项目目标 → 拦截
	badTarget := strings.Replace(b.String(), "| C-01 | t1.example,t2.example,t3.example |", "| C-01 | not-in-project |", 1)
	_, _ = o.exec.WriteFile(p.ID, "deliverables/s3-筛查矩阵判定表.md", badTarget)
	issues = o.matrixTableIssues(p)
	if len(issues) == 0 || !strings.Contains(issues[0], "无法匹配项目目标") {
		t.Fatalf("目标列 token 不匹配应拦截: %v", issues)
	}
	// ⑤ 单目标项目 5 列旧格式零影响
	p1 := &store.Project{ ROEAcknowledgedAt: "2026-11-22T00:00:00Z",ID: "P-V630MT1", Target: "only.example"}
	_ = o.store.SaveProject(p1)
	_, _ = o.exec.WriteFile(p1.ID, "deliverables/s3-筛查矩阵判定表.md", matrixTableFixture(nil, nil))
	if issues := o.matrixTableIssues(p1); len(issues) != 0 {
		t.Fatalf("单目标旧格式应放行: %v", issues)
	}
	// ⑥ 重复 C 编号行逐行卡校验：第一行无卡即拦（修复旧实现只查最后一行）
	var dup strings.Builder
	dup.WriteString("| C-01 | 无卡触发面 | 假设 | 证据指针 | TH |\n")
	for i := 2; i <= 27; i++ {
		verdict := "假设"
		if i%5 == 0 {
			verdict = "不适用"
		} else if i%7 == 0 {
			verdict = "待判定"
		}
		if verdict == "假设" || verdict == "待判定" {
			dup.WriteString(fmt.Sprintf("| C-%02d | t1.example,t2.example | 入口: /e%d 探针: GET 阳性: 差异 阴性: 同 停止: 6 | %s | 证据指针 | TH |\n", i, i, verdict))
		} else {
			dup.WriteString(fmt.Sprintf("| C-%02d | t1.example,t2.example | 核查无面 | %s | 证据 | — |\n", i, verdict))
		}
	}
	_, _ = o.exec.WriteFile(p.ID, "deliverables/s3-筛查矩阵判定表.md", dup.String())
	issues = o.matrixTableIssues(p)
	if len(issues) == 0 || !strings.Contains(issues[0], "执行卡门") || !strings.Contains(issues[0], "C-01") {
		t.Fatalf("重复 C 行首行无卡应拦截: %v", issues)
	}
}

// stageBudget：s3 纳入多目标自适应（base+(N-1)*perTarget，封顶 3×base）
func TestV630StageBudgetS3(t *testing.T) {
	got := stageBudget(40, "s3", 5, 10)
	if got != 80 {
		t.Fatalf("s3 多目标预算应 base+(N-1)*perTarget=80: %d", got)
	}
	if got := stageBudget(40, "s3", 1, 10); got != 40 {
		t.Fatalf("单目标预算应不变: %d", got)
	}
	if got := stageBudget(40, "s3", 100, 10); got != 120 {
		t.Fatalf("s3 预算应封顶 3×base=120: %d", got)
	}
	// v6.7.0 S6-⑩：s6 纳入多目标自适应——多目标横向工作量随目标数线性增长，不再用 s6
	// 充当「非自适应」反例；非自适应反例改用 s7（收尾阶段不放大）。
	if got := stageBudget(40, "s6", 5, 10); got != 80 {
		t.Fatalf("s6 应纳入自适应（40+(5-1)*10=80）: %d", got)
	}
	if got := stageBudget(40, "s7", 5, 10); got != 40 {
		t.Fatalf("s7 非自适应阶段预算应不变: %d", got)
	}
}

// ---------- S3-④ T-xx 计划承接门 ----------

func TestV630PlanHandover(t *testing.T) {
	o, st := v48Orchestrator(t)
	p := &store.Project{ ROEAcknowledgedAt: "2026-11-22T00:00:00Z",ID: "P-V630PH"}
	_ = o.store.SaveProject(p)
	_, _ = o.exec.WriteFile(p.ID, "deliverables/s3-测试计划.md",
		"# S3 测试计划\n\n| T-01 | 登录面 |\n| T-02 | 注入 |\n| T-03 | 上传 |\n")

	// ① 全部条目无归宿 → 拦截并点名
	issues := o.planHandoverIssues(p)
	if len(issues) == 0 || !strings.Contains(issues[0], "T-xx 计划承接门") || !strings.Contains(issues[0], "T-01") {
		t.Fatalf("计划条目零归宿应拦截: %v", issues)
	}
	// ② coverage 引用 T-01 + VT 引用 T-02 → T-03 单独拦截
	_, _ = st.UpsertCoverage(&store.CoverageEntry{ProjectID: p.ID, Stage: "s4",
		Endpoint: "t.example/login", VulnClass: "凭据三件套", Status: "needs_follow_up", Notes: "按 T-01 执行卡投递，锁定预言机"})
	_, _ = st.AddVT(&store.VerificationTask{ProjectID: p.ID, Stage: "s4",
		Title: "T-02 注入批量扩展", Status: "ready", Priority: 2})
	issues = o.planHandoverIssues(p)
	if len(issues) == 0 || strings.Contains(issues[0], "T-01") || strings.Contains(issues[0], "T-02") {
		t.Fatalf("已归宿条目不应再点名: %v", issues[0])
	}
	if !strings.Contains(issues[0], "T-03") {
		t.Fatalf("T-03 应被点名: %v", issues[0])
	}
	// ③ 对账表作废声明 → 全部通过
	_, _ = o.exec.WriteFile(p.ID, "deliverables/s4-逐类对账表.md", "| C-01 | T-03 作废：上传面确证不存在（S4 实测 404） |\n")
	if issues := o.planHandoverIssues(p); len(issues) != 0 {
		t.Fatalf("作废声明后应放行: %v", issues)
	}
	// ④ 计划不存在 → 放行（旧项目）
	p2 := &store.Project{ ROEAcknowledgedAt: "2026-11-22T00:00:00Z",ID: "P-V630PH2"}
	_ = o.store.SaveProject(p2)
	if issues := o.planHandoverIssues(p2); len(issues) != 0 {
		t.Fatalf("无计划项目应放行: %v", issues)
	}
}

// ---------- S3-⑤ 端点表↔矩阵运行时门 ----------

func TestV630EndpointMatrix(t *testing.T) {
	o, st := v48Orchestrator(t)
	p := &store.Project{ ROEAcknowledgedAt: "2026-11-22T00:00:00Z",ID: "P-V630EM"}
	_ = o.store.SaveProject(p)

	// ① total 注记与行数不符 → 拦截
	_, _ = o.exec.WriteFile(p.ID, "evidence/s3-api-endpoints.txt", "/api/a\n/api/b\n# total=5\n")
	issues := o.endpointMatrixIssues(p)
	if len(issues) == 0 || !strings.Contains(issues[0], "total 注记不符") {
		t.Fatalf("total 不符应拦截: %v", issues)
	}
	// ② total 修正后矩阵未执行 → 拦截
	_, _ = o.exec.WriteFile(p.ID, "evidence/s3-api-endpoints.txt", "/api/a\n/api/b\n# total=2\n")
	issues = o.endpointMatrixIssues(p)
	if len(issues) == 0 || !strings.Contains(issues[0], "鉴权差分矩阵未执行") {
		t.Fatalf("矩阵未执行应拦截: %v", issues)
	}
	// ③ 矩阵执行但缺 /api/b → 拦截点名缺口
	_, _ = st.UpsertCoverage(&store.CoverageEntry{ProjectID: p.ID, Stage: "s4",
		Endpoint: "/api/a", VulnClass: "未授权（authz-diff）", Status: "no_issue_found", Notes: "negative_valid"})
	issues = o.endpointMatrixIssues(p)
	if len(issues) == 0 || !strings.Contains(issues[0], "diffed=1/total=2") {
		t.Fatalf("覆盖率缺口应拦截: %v", issues)
	}
	// ④ 缺口行在交付物对账语料显式归宿 → 放行
	_, _ = o.exec.WriteFile(p.ID, "deliverables/s4-待续清单.md", "/api/b 待续：需 WAF 白名单窗口后复测\n")
	issues = o.endpointMatrixIssues(p)
	if len(issues) != 0 {
		t.Fatalf("缺口行显式归宿应放行: %v", issues)
	}
	// ⑤ 无端点表项目 → v6.4.0（S4-②）改口径：无声明拦截、有「未产出端点表」声明放行
	//（原 v6.3.0 静默放行 = v5.1 硬门失去输入却无人知情，S4-② 收敛为「声明形态豁免」）。
	p2 := &store.Project{ ROEAcknowledgedAt: "2026-11-22T00:00:00Z",ID: "P-V630EM2"}
	_ = o.store.SaveProject(p2)
	issues = o.endpointMatrixIssues(p2)
	if len(issues) == 0 || !strings.Contains(issues[0], "未产出端点表") {
		t.Fatalf("无端点表且无声明应拦截: %v", issues)
	}
	_, _ = o.exec.WriteFile(p2.ID, "deliverables/s3-测试计划.md", "# 计划\n未产出端点表：纯内网无 API 面\n")
	if issues := o.endpointMatrixIssues(p2); len(issues) != 0 {
		t.Fatalf("声明形态应放行: %v", issues)
	}
}

// ---------- S3-③ VT/候选上下文注入 + update_vt ready + search_memory 扩域 ----------

func TestV630VTContextAndReady(t *testing.T) {
	o, st := v48Orchestrator(t)
	o.heads = map[string]*Head{}
	p := &store.Project{ ROEAcknowledgedAt: "2026-11-22T00:00:00Z",ID: "P-V630VT"}
	_ = o.store.SaveProject(p)
	vtID, _ := st.AddVT(&store.VerificationTask{ProjectID: p.ID, Stage: "s3",
		Title: "架构信号：前置网关走私矩阵", Status: "pending", Priority: 1})
	candID, _ := st.AddCandidate(&store.Candidate{ProjectID: p.ID, Stage: "s3",
		Title: "验证码端点可批量取码", EvidenceRef: "evidence/s2-captcha.txt"})

	// ① 上下文包含验证队列（P1 优先）与候选账本
	out := o.buildContextPack(p, "s4")
	if !strings.Contains(out, "验证队列") || !strings.Contains(out, vtID) || !strings.Contains(out, "P1") {
		t.Fatalf("验证队列应注入上下文: %s", out[len(out)-600:])
	}
	if !strings.Contains(out, "候选账本") || !strings.Contains(out, candID) {
		t.Fatalf("候选账本应注入上下文")
	}
	// ② update_vt pending→ready 成功（附确认理由）
	res := o.dispatch(testCtx(), p, "s4", mkCall("update_vt", fmt.Sprintf(`{"id":%q,"status":"ready","note":"主头确认：S3 计划 T-01 承接"}`, vtID)))
	if !strings.Contains(res, "已处置") {
		t.Fatalf("pending→ready 应成功: %s", res)
	}
	// ③ ready 无理由 → 拒绝
	vt2, _ := st.AddVT(&store.VerificationTask{ProjectID: p.ID, Stage: "s3", Title: "第二条", Status: "pending"})
	res = o.dispatch(testCtx(), p, "s4", mkCall("update_vt", fmt.Sprintf(`{"id":%q,"status":"ready"}`, vt2)))
	if !strings.Contains(res, "错误") {
		t.Fatalf("ready 无确认理由应拒绝: %s", res)
	}
	// ④ search_memory 命中 VT 与候选
	res = o.dispatch(testCtx(), p, "s4", mkCall("search_memory", `{"query":"走私"}`))
	if !strings.Contains(res, "验证任务") {
		t.Fatalf("search_memory 应命中验证任务: %s", res)
	}
	res = o.dispatch(testCtx(), p, "s4", mkCall("search_memory", `{"query":"验证码"}`))
	if !strings.Contains(res, "候选") {
		t.Fatalf("search_memory 应命中候选账本: %s", res)
	}
}

// ---------- S3-⑥ 审批工单状态注入 ----------

func TestV630ApprovalContext(t *testing.T) {
	o, st := v48Orchestrator(t)
	o.heads = map[string]*Head{}
	p := &store.Project{ ROEAcknowledgedAt: "2026-11-22T00:00:00Z",ID: "P-V630AP"}
	_ = o.store.SaveProject(p)
	apID, _ := st.AddApproval(&store.Approval{ProjectID: p.ID, Stage: "s3",
		Action: "T-05 上传面渐进验证工单", Risk: "L2", Status: "approved", DecidedBy: "web-operator"})
	now := time.Now()
	_, _ = st.AddApproval(&store.Approval{ProjectID: p.ID, Stage: "s3",
		Action: "T-09 OOB 载荷工单", Risk: "L2", Status: "expired", DecidedAt: &now})

	// ① s5 上下文包含工单状态块（expired 单标注催办口径）
	out := o.buildContextPack(p, "s5")
	if !strings.Contains(out, "审批工单状态") || !strings.Contains(out, apID) || !strings.Contains(out, "expired") {
		t.Fatalf("s5 上下文应注入审批工单状态: %s", out[len(out)-800:])
	}
	// ② s3 上下文不注入（面收敛）
	out = o.buildContextPack(p, "s3")
	if strings.Contains(out, "审批工单状态") {
		t.Fatalf("s3 上下文不应注入审批块")
	}
}

// ---------- S3-⑧ 资产排序与容量 + deliverablesText 上限 ----------

func TestV630AssetOrderAndCap(t *testing.T) {
	o, st := v48Orchestrator(t)
	o.heads = map[string]*Head{}
	p := &store.Project{ ROEAcknowledgedAt: "2026-11-22T00:00:00Z",ID: "P-V630AS"}
	_ = o.store.SaveProject(p)
	shadowID, _ := st.AddAsset(&store.Asset{ProjectID: p.ID, Stage: "s2", Type: "域名", Value: "shadow.example", ScopeStatus: "shadow_pending"})
	inID, _ := st.AddAsset(&store.Asset{ProjectID: p.ID, Stage: "s2", Type: "域名", Value: "in.example", ScopeStatus: "in_scope"})

	// ① in_scope 资产排在 shadow 之前（ListAssets 确定性排序）
	assets, _ := st.ListAssets(p.ID)
	if len(assets) != 2 || assets[0].Value != "in.example" {
		t.Fatalf("in_scope 资产应排首: %v", assets)
	}
	// ② 超 60 项时上下文带类型分布摘要
	for i := 0; i < 65; i++ {
		_, _ = st.AddAsset(&store.Asset{ProjectID: p.ID, Stage: "s2", Type: "服务", Value: fmt.Sprintf("svc-%02d.example", i), ScopeStatus: "in_scope"})
	}
	_ = shadowID
	_ = inID
	out := o.buildContextPack(p, "s3")
	if !strings.Contains(out, "服务=65") {
		t.Fatalf("超限资产应附类型分布摘要")
	}
	if !strings.Contains(out, "共 67 项") {
		t.Fatalf("资产总数应展示: %s", out[len(out)-1200:])
	}
}

func TestV630DeliverablesTextCapAndPriority(t *testing.T) {
	o, _ := v48Orchestrator(t)
	p := &store.Project{ ROEAcknowledgedAt: "2026-11-22T00:00:00Z",ID: "P-V630DT"}
	_ = o.store.SaveProject(p)
	// 写 70 个普通文件 + 1 个判定表
	for i := 0; i < 70; i++ {
		_, _ = o.exec.WriteFile(p.ID, fmt.Sprintf("deliverables/note-%02d.md", i), fmt.Sprintf("note %d", i))
	}
	_, _ = o.exec.WriteFile(p.ID, "deliverables/s3-筛查矩阵判定表.md", "| C-01 | marker-keyword-in-corpus | 假设 |  |  |\n")
	corpus := o.deliverablesText(p.ID)
	if !strings.Contains(corpus, "marker-keyword-in-corpus") {
		t.Fatalf("判定表类关键文件应优先进入语料")
	}
	// 60 上限生效（70 个 note 中至少 10 个被挤出，但判定表必在）
	count := strings.Count(corpus, "note ")
	if count > 60 {
		t.Fatalf("语料应封顶 60 文件: %d", count)
	}
}
