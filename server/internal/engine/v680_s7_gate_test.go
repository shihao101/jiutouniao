package engine

// v6.8.0 S7 补全批次回归测试（方案：docs/修复方案_S7影响证明与收尾阶段补全_v6.8.0_20261123.md）。
// S7-① G3 strict pool：净室语义保持；核心回归是污染反例——上游交付物已含端点关键词时，
// 旧池口径被「天然满足」，strict pool 仍拦截（处置留痕必须产生于 S7 本阶段）。

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"jiutouniao/internal/config"
	"jiutouniao/internal/events"
	"jiutouniao/internal/llm"
	"jiutouniao/internal/store"
	"jiutouniao/internal/tools"
)

// mkFileAt 写文件并显式指定 mtime（strict pool 新鲜轨的确定性构造）。
func mkFileAt(t *testing.T, root, rel, content string, mtime time.Time) {
	t.Helper()
	full := filepath.Join(root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(full), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte(content), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(full, mtime, mtime); err != nil {
		t.Fatal(err)
	}
}

// s7GateProject 构造带可选 S7 StartedAt 的最小项目。
func s7GateProject(id string, started time.Time) *store.Project {
	p := &store.Project{ROEAcknowledgedAt: "2026-11-22T00:00:00Z", ID: id}
	if !started.IsZero() {
		p.StageStates = map[string]*store.StageState{
			"s7": {Status: "running", StartedAt: started.Format(time.RFC3339)},
		}
	}
	return p
}

func boolFalse() *bool {
	b := false
	return &b
}

// addNF 注册一条 needs_follow_up 覆盖条目（端点：GET /payload/ssrf/ssrf2.php）。
func addNF(t *testing.T, st *store.Store, projectID string) {
	t.Helper()
	if _, err := st.UpsertCoverage(&store.CoverageEntry{ProjectID: projectID, Stage: "s4",
		Endpoint: "GET /payload/ssrf/ssrf2.php", Param: "url", VulnClass: "SSRF",
		Status: "needs_follow_up", Notes: "同构未逐一验证"}); err != nil {
		t.Fatal(err)
	}
}

// TestV680S7StrictFollowUpPool S7-① 五组用例。
func TestV680S7StrictFollowUpPool(t *testing.T) {
	_, st := testApprover(t)
	old := time.Now().Add(-2 * time.Hour)
	fresh := time.Now().Add(1 * time.Hour)

	// 用例①（净室，既有语义）：上游无端点留痕 → 拦截；写 s7- 处置文件 → 放行。
	dir := t.TempDir()
	o := &Orchestrator{store: st, exec: newTestExec(t, dir), bus: eventsBusForTest(), cfg: &config.Config{DataDir: dir}}
	addNF(t, st, "PD")
	if issues := o.deterministicGate(s7GateProject("PD", time.Time{}), "s7"); countContains(issues, "待续清单未处置") != 1 {
		t.Fatalf("净室无处置应拦截 1 条: %v", issues)
	}
	mkFileAt(t, dir, "PD/deliverables/s7-待续清单处置.md", "# 待续清单处置\n- ssrf2.php：本轮补测完成，update_coverage 已更新\n", old)
	if issues := o.deterministicGate(s7GateProject("PD", time.Time{}), "s7"); len(issues) != 0 {
		t.Fatalf("s7- 前缀处置文件应放行: %v", issues)
	}

	// 用例②（污染反例，本批核心）：上游交付物含端点关键词 + 无任何 s7 产出——
	// 旧池口径被「天然满足」放行；strict pool 拦截。
	dir2 := t.TempDir()
	o2cfg := &config.Config{DataDir: dir2}
	o2 := &Orchestrator{store: st, exec: newTestExec(t, dir2), bus: eventsBusForTest(), cfg: o2cfg}
	mkFileAt(t, dir2, "PD/deliverables/s4-漏洞清单.md", "# S4 漏洞清单\n- GET /payload/ssrf/ssrf2.php SSRF 同构未逐一验证\n", old)
	if issues := o2.deterministicGate(s7GateProject("PD", time.Time{}), "s7"); countContains(issues, "待续清单未处置") != 1 {
		t.Fatalf("上游语料不应满足处置对账（strict pool 应拦截）: %v", issues)
	}
	// guard=false 回退旧池口径 → 上游文件满足 → 放行。
	o2cfg.Guard.EnforceS7StrictFollowUpPool = boolFalse()
	if issues := o2.deterministicGate(s7GateProject("PD", time.Time{}), "s7"); countContains(issues, "待续清单未处置") != 0 {
		t.Fatalf("guard=false 应回退旧池口径放行: %v", issues)
	}
	o2cfg.Guard.EnforceS7StrictFollowUpPool = nil

	// 用例③（新鲜轨）：处置写在无 s7- 前缀文件、mtime 晚于 S7 开工 → 放行。
	mkFileAt(t, dir2, "PD/deliverables/待续清单处置.md", "# 待续清单处置\n- ssrf2.php：本轮补测完成\n", fresh)
	if issues := o2.deterministicGate(s7GateProject("PD", fresh.Add(-time.Minute)), "s7"); countContains(issues, "待续清单未处置") != 0 {
		t.Fatalf("开工后新增文件应入池放行: %v", issues)
	}

	// 用例④（处置只在开工前的上游文件）→ 拦截。
	dir3 := t.TempDir()
	o3 := &Orchestrator{store: st, exec: newTestExec(t, dir3), bus: eventsBusForTest(), cfg: &config.Config{DataDir: dir3}}
	mkFileAt(t, dir3, "PD/deliverables/s5-移交说明.md", "# 移交\n- ssrf2.php 已列入移交（S5 阶段留痕，非 S7 处置）\n", old)
	if issues := o3.deterministicGate(s7GateProject("PD", fresh.Add(-time.Minute)), "s7"); countContains(issues, "待续清单未处置") != 1 {
		t.Fatalf("开工前的上游留痕不应计入 S7 处置: %v", issues)
	}

	// 用例⑤（报告双载体）：处置只写 report.md → 放行。
	mkFileAt(t, dir3, "PD/report.md", "# 报告\n## 待续处置\n- ssrf2.php：移交复测（启动条件：客户提供出口）\n", fresh)
	if issues := o3.deterministicGate(s7GateProject("PD", fresh.Add(-time.Minute)), "s7"); countContains(issues, "待续清单未处置") != 0 {
		t.Fatalf("report.md 双载体应放行: %v", issues)
	}
}

// eventsBusForTest 测试装配总线（确定性门内提示级日志需要非 nil bus）。
func eventsBusForTest() *events.Bus { return events.NewBus() }

// TestV680S7UploadFallbackS7 S7-③：S5 上传落点兜底小节注入 s7 上下文——
// s6-skipped（无 s6-*.md）时「S5 上传落点」样本在场；persistRows 非空时只出指针行。
func TestV680S7UploadFallbackS7(t *testing.T) {
	_, st := testApprover(t)
	dir := t.TempDir()
	o := &Orchestrator{store: st, exec: newTestExec(t, dir), bus: eventsBusForTest(), cfg: &config.Config{DataDir: dir}}
	p := &store.Project{ROEAcknowledgedAt: "2026-11-22T00:00:00Z", ID: "PD"}

	// 场景 A：s6-skipped——无 s6 交付物，s5 文件含四元组行 → S5 兜底小节带样本在场。
	// v6.8.1：s6 skipped 状态在册时，S7 上下文还必须含①范围标注块（影响边界+存量排查如实标注）
	// ②既往阶段交付物的 s6 skipped 摘要行（修复前循环只认 done，S7 零 skipped 信号）。
	mkFileAt(t, dir, "PD/deliverables/s5-需人工清理清单.md",
		"# 需人工清理\n| 1 | /upload/probe.png | 1x1 PNG 82 字节 | 建议清理命令：管理员删除对象 | 验证命令：GET 预期 404 |\n",
		time.Now().Add(-time.Hour))
	p.StageStates = map[string]*store.StageState{
		"s6": {Status: "skipped", Summary: "后渗透未勾选（创建时用户决策）：提权/横向/权限维持/云逃逸/存量排查整段跳过；如需执行可在阶段流水线手动重跑 s6"},
	}
	ctx := o.buildContextPack(p, "s7")
	if !strings.Contains(ctx, "S6 后渗透未执行") || !strings.Contains(ctx, "不得以 S5 证据外推横向/提权影响") {
		t.Fatalf("s6-skipped 项目 s7 上下文应含范围标注块: %.300s", ctx)
	}
	if !strings.Contains(ctx, "- [s6] 后渗透未勾选") {
		t.Fatalf("既往阶段交付物应显示 s6 skipped 摘要行（v6.8.1 修复）: %.300s", ctx)
	}
	// 对照：s8 上下文同样获得 skipped 摘要行（s8.md v5.3.7 范围标注规则的机械依据）。
	ctxS8 := o.buildContextPack(p, "s8")
	if !strings.Contains(ctxS8, "- [s6] 后渗透未勾选") {
		t.Fatalf("s8 上下文应显示 s6 skipped 摘要行")
	}
	if !strings.Contains(ctx, "S5 上传落点") || !strings.Contains(ctx, "登记行样本") {
		t.Fatalf("s6-skipped 场景应注入 S5 兜底小节与样本: %.400s", ctx)
	}
	if !strings.Contains(ctx, "无 s6 交付物") {
		t.Fatalf("兜底场景应使用无 s6 交付物标题: %.200s", ctx)
	}

	// 场景 B：s6 交付物已含持久化登记行（persistRows 非空）→ 只出指针行不出样本。
	mkFileAt(t, dir, "PD/deliverables/s6-持久化记录.md",
		"# 持久化记录\n| 1 | 位置 /tmp/persist.sh | 指纹 sha256:abc123 | 建议清理命令：人工删除 | 验证命令：ls 确认 |\n",
		time.Now().Add(-30*time.Minute))
	ctx2 := o.buildContextPack(p, "s7")
	if !strings.Contains(ctx2, "S6 持久化登记") {
		t.Fatalf("s6 登记行应在场: %.200s", ctx2)
	}
	if strings.Contains(ctx2, "登记行样本（≤5）") {
		t.Fatalf("persistRows 非空时不应重复注入 S5 样本: %.200s", ctx2)
	}

	// 场景 C：s5 无任何四元组行、无 s6 交付物 → 零占位不报错。
	dir2 := t.TempDir()
	o2 := &Orchestrator{store: st, exec: newTestExec(t, dir2), bus: eventsBusForTest(), cfg: &config.Config{DataDir: dir2}}
	ctx3 := o2.buildContextPack(p, "s7")
	if strings.Contains(ctx3, "S6 移交项") || strings.Contains(ctx3, "S5 上传落点") {
		t.Fatalf("无任何登记数据时不应出块: %.200s", ctx3)
	}

	// 场景 D（方案测试④）：多目标项目样本行带 @目标 标签——四元组行命中目标即打标。
	//（独立工作区：persistRows 须为空样本才会注入——与场景 B 的非空断言互不干扰。）
	dirD := t.TempDir()
	oD := &Orchestrator{store: st, exec: newTestExec(t, dirD), bus: eventsBusForTest(), cfg: &config.Config{DataDir: dirD}}
	p2 := &store.Project{ROEAcknowledgedAt: "2026-11-22T00:00:00Z", ID: "PD", Target: "10.20.0.5\n10.20.0.6"}
	mkFileAt(t, dirD, "PD/deliverables/s5-利用报告.md",
		"# 利用报告\n| 1 | http://10.20.0.5/upload/probe.png | 1x1 PNG | 建议清理命令：管理员删除 | 验证命令：GET 预期 404 |\n",
		time.Now().Add(-2*time.Hour))
	ctxD := oD.buildContextPack(p2, "s7")
	if !strings.Contains(ctxD, "登记行样本") || !strings.Contains(ctxD, "@10.20.0.5") {
		t.Fatalf("多目标样本行应带 @目标 标签: %.300s", ctxD)
	}
}

// TestV680S6UploadPointerAfterRefactor S7-③ 重构不变性：s5UploadRegistry 提取后，
// s6「S5 移交项」块的 [上传落点] 指针与登记行样本渲染与 v6.7.0 S6-③ 行为一致。
func TestV680S6UploadPointerAfterRefactor(t *testing.T) {
	_, st := testApprover(t)
	dir := t.TempDir()
	o := &Orchestrator{store: st, exec: newTestExec(t, dir), bus: eventsBusForTest(), cfg: &config.Config{DataDir: dir}}
	p := &store.Project{ROEAcknowledgedAt: "2026-11-22T00:00:00Z", ID: "PD"}
	p.StageStates = map[string]*store.StageState{"s5": {Status: "done"}}
	mkFileAt(t, dir, "PD/deliverables/s5-需人工清理清单.md",
		"# 需人工清理\n| 1 | /upload/probe.png | 1x1 PNG 82 字节 | 建议清理命令：管理员删除对象 | 验证命令：GET 预期 404 |\n",
		time.Now().Add(-time.Hour))
	ctx := o.buildContextPack(p, "s6")
	if !strings.Contains(ctx, "S5 移交项") || !strings.Contains(ctx, "[上传落点]") || !strings.Contains(ctx, "登记行样本") {
		t.Fatalf("s6 上下文应保留 v6.7.0 S6-③ 落点指针与样本渲染: %.300s", ctx)
	}
	if !strings.Contains(ctx, "- [S5 交付物]") {
		t.Fatalf("s6 上下文应保留 S5 交付物指针行")
	}
}

// TestV680S8HandoverBlock S7-④：「S7 收口移交」块注入 s8 上下文——指针+承接落点标注、
// NF 处置统计、open VT「未清完」标注；零 s7 件零占位。
func TestV680S8HandoverBlock(t *testing.T) {
	_, st := testApprover(t)
	dir := t.TempDir()
	o := &Orchestrator{store: st, exec: newTestExec(t, dir), bus: eventsBusForTest(), cfg: &config.Config{DataDir: dir}}
	p := &store.Project{ROEAcknowledgedAt: "2026-11-22T00:00:00Z", ID: "PD"}

	// 零 s7 件零占位。
	if ctx := o.buildContextPack(p, "s8"); strings.Contains(ctx, "S7 收口移交") {
		t.Fatalf("零 s7 件时不应出块")
	}

	mkFileAt(t, dir, "PD/deliverables/s7-需人工清理清单.md", "# 需人工清理\n| 1 | /upload/probe.png | 1x1 PNG | 建议清理命令 | 验证命令 |\n", time.Now())
	mkFileAt(t, dir, "PD/deliverables/s7-攻击时间线.md", "# 时间线\n", time.Now())
	mkFileAt(t, dir, "PD/deliverables/s7-待续清单处置.md", "# 待续处置\n- /payload/ssrf/ssrf2.php：移交复测（启动条件/步骤/工作量）\n", time.Now())
	if _, err := st.UpsertCoverage(&store.CoverageEntry{ProjectID: "PD", Stage: "s4",
		Endpoint: "GET /payload/ssrf/ssrf2.php", Param: "url", VulnClass: "SSRF",
		Status: "needs_follow_up", Notes: "遗留"}); err != nil {
		t.Fatal(err)
	}
	ctx := o.buildContextPack(p, "s8")
	if !strings.Contains(ctx, "S7 收口移交") {
		t.Fatalf("有 s7 件时应出块")
	}
	if !strings.Contains(ctx, "需人工清理清单") || !strings.Contains(ctx, "移交附件说明") {
		t.Fatalf("清理清单指针与承接落点标注应在场")
	}
	if !strings.Contains(ctx, "1/1 已留痕") {
		t.Fatalf("NF 处置统计应计数（strict pool: s7-待续清单处置.md 含端点关键词）")
	}

	// open VT →「未清完」标注在场。
	if _, err := st.AddVT(&store.VerificationTask{ProjectID: "PD", ID: "VT-TEST0001",
		Title: "待清点", Status: "ready", Priority: 1}); err != nil {
		t.Fatal(err)
	}
	ctx2 := o.buildContextPack(p, "s8")
	if !strings.Contains(ctx2, "S7 未清完") {
		t.Fatalf("open VT 应触发未清完标注")
	}

	// L2 清点：已批未用 L2 工单（ID 不在任何使用痕迹语料）→ L2 清点行「未清完」标注在场。
	if _, err := st.AddApproval(&store.Approval{ProjectID: "PD", Stage: "s5",
		Action: "T-99 横向利用载荷投递", Risk: "L2", Mode: "auto", Status: "approved"}); err != nil {
		t.Fatal(err)
	}
	ctx3 := o.buildContextPack(p, "s8")
	if !strings.Contains(ctx3, "L2 清点") || !strings.Contains(ctx3, "S7 未清完") {
		t.Fatalf("approved 未用 L2 应触发 L2 清点标注")
	}
}

// TestV680S7ReadyHandoverBlock S7-⑤：「就绪移交清点」小节把 s4/s5/spec 的 V3 两清单
// 逐行置顶进 s7 上下文；L2 工单状态块在 s7 出现且带清点纪律。
func TestV680S7ReadyHandoverBlock(t *testing.T) {
	_, st := testApprover(t)
	dir := t.TempDir()
	o := &Orchestrator{store: st, exec: newTestExec(t, dir), bus: eventsBusForTest(), cfg: &config.Config{DataDir: dir}}
	p := &store.Project{ROEAcknowledgedAt: "2026-11-22T00:00:00Z", ID: "PD"}
	p.StageStates = map[string]*store.StageState{
		"s4":     {Status: "done", V3Ready: []string{"s4 就绪脚本 A（10.0.0.1）"}},
		"specB1": {Status: "done", V3L2: []string{"specB1 已批未用工单 B"}},
	}
	if _, err := st.AddApproval(&store.Approval{ProjectID: "PD", Stage: "s5",
		Action: "T-01 横向探测", Risk: "L2", Mode: "auto", Status: "approved"}); err != nil {
		t.Fatal(err)
	}
	ctx := o.buildContextPack(p, "s7")
	if !strings.Contains(ctx, "就绪移交清点") || !strings.Contains(ctx, "[s4 就绪未执行]") || !strings.Contains(ctx, "[specB1 已批未用]") {
		t.Fatalf("V3 清点小节应逐行在场: %.200s", ctx)
	}
	if !strings.Contains(ctx, "审批工单状态") || !strings.Contains(ctx, "只清点不再发起新工单") {
		t.Fatalf("L2 工单块应在 s7 出现且带清点纪律")
	}
	// 对照：s5 视角不出现 s7 清点小节。
	ctx5 := o.buildContextPack(p, "s5")
	if strings.Contains(ctx5, "就绪移交清点") {
		t.Fatalf("清点小节应仅注入 s7")
	}
	// 方案测试②：全空项目（无任何 V3 条目）零占位。
	ctxE := o.buildContextPack(&store.Project{ROEAcknowledgedAt: "2026-11-22T00:00:00Z", ID: "PD"}, "s7")
	if strings.Contains(ctxE, "就绪移交清点") {
		t.Fatalf("全空项目不应出清点小节")
	}
}

// TestV680S7OpenCandidateGate S7-⑥：open 候选在 s7 收口拦截（C28 候选归档门文案）。
func TestV680S7OpenCandidateGate(t *testing.T) {
	_, st := testApprover(t)
	dir := t.TempDir()
	o := &Orchestrator{store: st, exec: newTestExec(t, dir), bus: eventsBusForTest()}
	cid, err := st.AddCandidate(&store.Candidate{ProjectID: "PD",
		Title: "待评估线索", EvidenceRef: "evidence/x.txt", Disposition: "open"})
	if err != nil {
		t.Fatal(err)
	}
	issues := o.deterministicGate(s7GateProject("PD", time.Time{}), "s7")
	if countContains(issues, "C28 候选归档门") != 1 {
		t.Fatalf("open 候选应在 s7 收口被 C28 门拦截: %v", issues)
	}
	// 方案测试后半：三态归位（excluded）后放行（AddCandidate 生成 ID，SaveCandidate 按该 ID 更新）。
	if err := st.SaveCandidate(&store.Candidate{ProjectID: "PD", ID: cid,
		Title: "待评估线索", EvidenceRef: "evidence/x.txt", Disposition: "excluded"}); err != nil {
		t.Fatal(err)
	}
	issues2 := o.deterministicGate(s7GateProject("PD", time.Time{}), "s7")
	if countContains(issues2, "C28 候选归档门") != 0 {
		t.Fatalf("归位后 C28 门应放行: %v", issues2)
	}
}

// TestV680S7ReplayStrictPool v6.8.0 S7-① 验收回放（方案「验收与回放」③）：对隔离库副本
// 全部 s7=done 项目 dry-run strict-pool G3——验证门对存量数据的行为。硬断言仅限
// 「高质量处置项目必须放行」（防过拦回归护栏）；存量漏出项目仅 Logf 留痕不作硬断言
// （fresh 轨受后续阶段文件 mtime 影响，历史项目回放是参考证据非精确收口时点还原）。
// ⚠ 环境依赖测试（/tmp/v680-s7/jiutouniao.db 副本）——CI 缺席时 t.Skip。
func TestV680S7ReplayStrictPool(t *testing.T) {
	if _, err := os.Stat("/tmp/v680-s7/jiutouniao.db"); err != nil {
		t.Skip("回放库副本不存在（/tmp/v680-s7），跳过环境回放")
	}
	cfg := &config.Config{}
	cfg.ApplyDefaultsForTest()
	cfg.DataDir = "/root/jiutouniao/projects"
	st, err := store.Open("/tmp/v680-s7")
	if err != nil {
		t.Skipf("回放库打开失败: %v", err)
	}
	defer st.Close()
	gf, gh, gm, gr, gs := config.DefaultGuard()
	exec, err := tools.NewExecutor("/root/jiutouniao/projects", 10, 102400, struct {
		Forbidden, HighRisk, MedRisk, ReadOnly, Sensitive []string
	}{gf, gh, gm, gr, gs})
	if err != nil {
		t.Fatal(err)
	}
	o := &Orchestrator{store: st, exec: exec, bus: events.NewBus(), cfg: cfg,
		heads: map[string]*Head{}, running: map[string]context.CancelFunc{},
		tokens: map[string]int64{}, inputs: map[string][]string{}, loops: map[string][]string{},
		liveP: map[string]*store.Project{}, batchStats: map[string]*batchBudgetState{}}
	ps, err := st.ListProjects()
	if err != nil {
		t.Fatal(err)
	}
	flagged, clean := 0, 0
	for _, p := range ps {
		s7 := p.StageStates["s7"]
		if s7 == nil || s7.Status != "done" {
			continue
		}
		issues := o.followUpDispositionIssues(p)
		if len(issues) == 0 {
			clean++
			continue
		}
		flagged++
		t.Logf("strict pool 将拦截 %s：%s", p.ID, strings.Join(issues[:minInt(2, len(issues))], " | "))
	}
	t.Logf("== G3 strict pool 回放：s7=done 项目 %d 个，放行 %d / 将拦截 %d ==", clean+flagged, clean, flagged)
	// 回归护栏：高质量处置项目（s7-待续清单处置.md 在 strict pool 内）必须放行。
	for _, good := range []string{"某历史任务", "某历史任务"} {
		for _, p := range ps {
			if p.ID != good {
				continue
			}
			if s7 := p.StageStates["s7"]; s7 == nil || s7.Status != "done" {
				continue
			}
			if issues := o.followUpDispositionIssues(p); len(issues) > 0 {
				t.Errorf("高质量处置项目 %s 不应被 strict pool 拦截: %v", good, issues)
			}
		}
	}
}

// TestV680S7ReplayContextSeams v6.8.0 方案「验收与回放」③后两点（dry-run 只读）：
// ①s6-skipped 项目 S5 兜底小节命中情况——凡 s5 四元组双轨命中的项目，s7 上下文必须含
// 「S5 上传落点」（硬断言）；双轨零命中的项目零占位（硬断言）。②多目标项目 @目标 标签
// 渲染与「就绪移交清点」来源阶段标注（有 V3 条目才出小节，Logf 统计）。
// ⚠ 环境依赖测试（/tmp/v680-s7/jiutouniao.db 副本）——CI 缺席时 t.Skip。
func TestV680S7ReplayContextSeams(t *testing.T) {
	if _, err := os.Stat("/tmp/v680-s7/jiutouniao.db"); err != nil {
		t.Skip("回放库副本不存在（/tmp/v680-s7），跳过环境回放")
	}
	cfg := &config.Config{}
	cfg.ApplyDefaultsForTest()
	cfg.DataDir = "/root/jiutouniao/projects"
	st, err := store.Open("/tmp/v680-s7")
	if err != nil {
		t.Skipf("回放库打开失败: %v", err)
	}
	defer st.Close()
	gf, gh, gm, gr, gs := config.DefaultGuard()
	exec, err := tools.NewExecutor("/root/jiutouniao/projects", 10, 102400, struct {
		Forbidden, HighRisk, MedRisk, ReadOnly, Sensitive []string
	}{gf, gh, gm, gr, gs})
	if err != nil {
		t.Fatal(err)
	}
	o := &Orchestrator{store: st, exec: exec, bus: events.NewBus(), cfg: cfg,
		heads: map[string]*Head{}, running: map[string]context.CancelFunc{},
		tokens: map[string]int64{}, inputs: map[string][]string{}, loops: map[string][]string{},
		liveP: map[string]*store.Project{}, batchStats: map[string]*batchBudgetState{}}
	ps, err := st.ListProjects()
	if err != nil {
		t.Fatal(err)
	}
	skipTotal, fallbackHit, fallbackClean := 0, 0, 0
	mtTotal, mtReady, mtTagged := 0, 0, 0
	for _, p := range ps {
		s7 := p.StageStates["s7"]
		if s7 == nil || s7.Status != "done" {
			continue
		}
		ctx := o.buildContextPack(p, "s7")
		// ① s6-skipped 项目的 S5 兜底小节
		if s6 := p.StageStates["s6"]; s6 != nil && s6.Status == "skipped" {
			skipTotal++
			files, _ := o.s5UploadRegistry(p)
			hasFallback := strings.Contains(ctx, "S5 上传落点")
			if len(files) > 0 {
				if !hasFallback {
					t.Errorf("s6-skipped 且 s5 四元组双轨命中 %s 的项目应注入 S5 兜底小节", p.ID)
				} else {
					fallbackHit++
				}
			} else if !strings.Contains(ctx, "S6 移交项") && !strings.Contains(ctx, "S5 上传落点") {
				fallbackClean++ // 零占位形态
			}
		}
		// ② 多目标项目的 @目标 标签与清点小节来源标注
		if len(splitProjectTargets(p)) > 1 {
			mtTotal++
			if strings.Contains(ctx, "就绪移交清点") {
				mtReady++
				if !strings.Contains(ctx, "就绪未执行]") && !strings.Contains(ctx, "已批未用]") {
					t.Errorf("多目标 %s 清点小节应含来源阶段标注行", p.ID)
				}
			}
			if strings.Contains(ctx, "@") {
				mtTagged++
			}
		}
		// ③ S7→S8 接缝（验收③补充）：有 s7- 交付物的项目，s8 上下文必含「S7 收口移交」块；
		// 无 s7 件的项目零占位。
		s7Files, _ := o.exec.ListDir(p.ID, "deliverables")
		hasS7Deliv := false
		for _, rel := range s7Files {
			if strings.HasPrefix(filepath.Base(rel), "s7-") {
				hasS7Deliv = true
				break
			}
		}
		ctx8 := o.buildContextPack(p, "s8")
		if hasS7Deliv && !strings.Contains(ctx8, "S7 收口移交") {
			t.Errorf("含 s7 交付物的项目 %s，s8 上下文应含「S7 收口移交」块", p.ID)
		}
		if !hasS7Deliv && strings.Contains(ctx8, "S7 收口移交") && !strings.Contains(ctx8, "needs_follow_up 处置统计") && !strings.Contains(ctx8, "S7 未清完") {
			t.Errorf("无 s7 件项目 %s 不应出移交块（清点统计行亦不应在场）", p.ID)
		}
	}
	t.Logf("== 接缝回放：s6-skipped %d 个（S5 兜底命中 %d / 零占位 %d）；多目标 %d 个（清点小节 %d、含 @ 标签 %d）==",
		skipTotal, fallbackHit, fallbackClean, mtTotal, mtReady, mtTagged)
}

// ---------- v6.8.0 方案「验收与回放」⑤ 的离线等价：dispatch 级 S7 e2e ----------
// 生产 smoke（真实 LLM + 靶场）不可离线执行；本组用 dispatch 真实链路（complete_stage 全
// 路径：强制产出 → 反思门 stub → deterministicGate → 收口/拦截）覆盖同一闭环：
// E1 反例（G3 strict pool 拦截）/ E2 正例（处置留痕后收口）/ E3 反思节新问句运行时捕获。

// captureReflectClient 捕获反思门提示词并恒 PASS（S7-② 运行时验证：问句经真实链路注入）。
type captureReflectClient struct {
	prompt *string
}

func (c captureReflectClient) Chat(_ context.Context, _ string, msgs []llm.Message, _ []llm.ToolDef, _ float32, _ int) (llm.Message, llm.Usage, error) {
	for _, m := range msgs {
		if m.Role == "user" && strings.Contains(m.Content, "审查对象") {
			*c.prompt = m.Content
		}
	}
	return llm.Message{Role: "assistant", Content: "PASS"}, llm.Usage{}, nil
}

func v680S7E2EProject(t *testing.T, o *Orchestrator, id string) *store.Project {
	t.Helper()
	p := &store.Project{ID: id, Name: "v680S7端到端", Target: "a.test",
		Authorized: true, ROEAcknowledgedAt: "2026-11-23T00:00:00Z",
		StageStates: map[string]*store.StageState{"s7": {Status: "running", StartedAt: "2026-11-23T00:00:00Z"}}}
	_ = o.store.SaveProject(p)
	return p
}

// v680E2EOrch e2e 构造器（返回 dir 句柄——上游交付物需显式回拨 mtime 模拟真实阶段时序：
// 流水线序保证上游文件必早于 s7 开工，测试须构造同一事实）。
func v680E2EOrch(t *testing.T) (*Orchestrator, *store.Store, string) {
	t.Helper()
	_, st := testApprover(t)
	dir := t.TempDir()
	cfg := &config.Config{}
	cfg.ApplyDefaultsForTest()
	cfg.DataDir = dir
	o := &Orchestrator{store: st, exec: newTestExec(t, dir), bus: events.NewBus(), cfg: cfg, tokens: map[string]int64{}}
	return o, st, dir
}

func TestV680S7DispatchE2E(t *testing.T) {
	// E1 反例：NF 条目端点关键词仅在上游交付物（mtime 早于 S7 开工——真实阶段时序）、
	// 无任何 s7 处置产出 → 强制产出已满足（占位交付物）→ 反思 stub PASS →
	// G3 strict pool 真实链路拦截。
	o, st, dir := v680E2EOrch(t)
	o.llm = passThroughClient{}
	p := v680S7E2EProject(t, o, "P-V680-E1")
	_, _ = st.UpsertCoverage(&store.CoverageEntry{ProjectID: p.ID, Stage: "s4",
		Endpoint: "GET /payload/ssrf/ssrf2.php", Param: "url", VulnClass: "SSRF",
		Status: "needs_follow_up", Notes: "同构未逐一验证"})
	mkFileAt(t, dir, p.ID+"/deliverables/s4-漏洞清单.md", "# 漏洞清单\n- GET /payload/ssrf/ssrf2.php 待复核\n",
		time.Date(2026, 11, 22, 0, 0, 0, 0, time.UTC))
	_, _ = o.exec.WriteFile(p.ID, "deliverables/s7-影响评估.md", "# 影响评估\n可触达数据规模待查\n")
	resp := o.dispatch(context.Background(), p, "s7", llm.ToolCall{Name: "complete_stage",
		Arguments: `{"summary":"S7 收口","deliverables":["deliverables/s7-影响评估.md"]}`})
	if !strings.Contains(resp, "收口被确定性质量门拦截") || !strings.Contains(resp, "待续清单未处置") {
		t.Fatalf("dispatch 真实链路应被 G3 strict pool 拦截: %s", resp)
	}

	// E2 正例：补《待续清单处置》（引用端点关键词留痕）→ 同链路放行收口。
	// 同项目注入 s5 四元组文件（mtime 早于开工）→ s7 上下文「S5 上传落点」兜底在场
	//（S6→S7 接缝，s6-skipped 形态）；收口后 s8 上下文必含「S7 收口移交」（S7→S8 接缝，
	// v660 E3 下游承接断言同款）——方案验收⑤「三接缝」的 dispatch 级离线等价。
	_, _ = o.exec.WriteFile(p.ID, "deliverables/s5-需人工清理清单.md",
		"# 需人工清理\n| 1 | /upload/probe.png | 1x1 PNG | 建议清理命令：管理员删除 | 验证命令：GET 预期 404 |\n")
	if f, ferr := os.Stat(dir + "/" + p.ID + "/deliverables/s5-需人工清理清单.md"); ferr == nil {
		old := time.Date(2026, 11, 22, 0, 0, 0, 0, time.UTC)
		_ = os.Chtimes(f.Name(), old, old)
	}
	ctxS7 := o.buildContextPack(p, "s7")
	if !strings.Contains(ctxS7, "S5 上传落点") {
		t.Fatalf("s7 上下文应经兜底小节承接 S5 落点（S6→S7 接缝）")
	}
	_, _ = o.exec.WriteFile(p.ID, "deliverables/s7-待续清单处置.md",
		"# 待续清单处置\n- ssrf2.php：移交复测（启动条件：客户提供出口；步骤：只读复放；工作量：3 请求）\n")
	resp2 := o.dispatch(context.Background(), p, "s7", llm.ToolCall{Name: "complete_stage",
		Arguments: `{"summary":"S7 收口","deliverables":["deliverables/s7-待续清单处置.md"]}`})
	if !strings.HasPrefix(resp2, "阶段已收口") {
		t.Fatalf("处置留痕后应经真实链路收口: %s", resp2)
	}
	if st2 := p.StageStates["s7"]; st2 == nil || st2.Status != "done" {
		t.Fatalf("s7 阶段应置 done")
	}
	ctxS8 := o.buildContextPack(p, "s8")
	if !strings.Contains(ctxS8, "S7 收口移交") || !strings.Contains(ctxS8, "[待续清单处置]") {
		t.Fatalf("收口后 s8 上下文应含 S7 收口移交块与交付物指针（S7→S8 接缝）: %.200s", ctxS8)
	}
	if !strings.Contains(ctxS8, "1/1 已留痕") {
		t.Fatalf("s8 承接块应含 NF 处置统计（1/1）")
	}

	// E3 反思节新问句运行时捕获：真实 reflectStage 构造的提示词含单一规则四问、不含旧口径。
	o3, _ := v48Orchestrator(t)
	var captured string
	o3.llm = captureReflectClient{prompt: &captured}
	p3 := v680S7E2EProject(t, o3, "P-V680-E3")
	_, _ = o3.exec.WriteFile(p3.ID, "deliverables/s7-攻击时间线.md", "# 攻击时间线\n（无日期占位）\n")
	resp3 := o3.dispatch(context.Background(), p3, "s7", llm.ToolCall{Name: "complete_stage",
		Arguments: `{"summary":"S7 收口","deliverables":["deliverables/s7-攻击时间线.md"]}`})
	if !strings.HasPrefix(resp3, "阶段已收口") {
		t.Fatalf("E3 应收口（反思捕获用）: %s", resp3)
	}
	if captured == "" {
		t.Fatalf("反思门提示词未被捕获")
	}
	for _, kw := range []string{"S7 专项核查（清理铁律·v5.1.3/v5.3.0 单一规则）", "登记移交≠执行", "需人工清理清单", "只读复核", "真实三选一"} {
		if !strings.Contains(captured, kw) {
			t.Fatalf("反思提示词应含新问句关键词 %q", kw)
		}
	}
	if strings.Contains(captured, "仅作用于智能体自建数据") {
		t.Fatalf("反思提示词不应再含旧口径句")
	}
}
