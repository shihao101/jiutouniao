package engine

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"jiutouniao/internal/config"
	"jiutouniao/internal/llm"
	"jiutouniao/internal/store"
)

// v690S8Orch S8 专项测试装配：DataDir 指向临时目录（workspaceRoot=DataDir/<pid>），
// guard 缺省全开（nil→FlagOrDefault true）。
func v690S8Orch(t *testing.T) (*Orchestrator, *store.Store, string) {
	t.Helper()
	_, st := testApprover(t)
	dir := t.TempDir()
	o := &Orchestrator{store: st, exec: newTestExec(t, dir), bus: eventsBusForTest(), cfg: &config.Config{DataDir: dir}}
	return o, st, dir
}

// v690call 工具调用入口（与 v46_gate_test.go 的 call 同形，独立命名防重声明）。
func v690call(t *testing.T, o *Orchestrator, p *store.Project, stage, name, args string) string {
	t.Helper()
	return o.dispatch(context.Background(), p, stage, llm.ToolCall{Name: name, Arguments: args})
}

// TestV690S8ContractGuardPreposition S8-①：报告契约守卫前置——
// ①报告只在 deliverables/ 且缺《覆盖边界》章节 → 归位后 C29 内容门对归位文件生效（旧实现此处静默绕过）；
// ②无任何 report.md → 前置拦截；
// ③根目录正常报告 → 行为不变（收口成功）。
func TestV690S8ContractGuardPreposition(t *testing.T) {
	o, _, _ := v690S8Orch(t)

	// ①错位写入 → 归位 + C29 拦截（走三振路径跳过 LLM 反思，确定性门直跑）
	p := &store.Project{ROEAcknowledgedAt: "2026-11-22T00:00:00Z", ID: "P-S8PRE"}
	_ = o.store.SaveProject(p)
	p.StageStates = map[string]*store.StageState{
		"s8": {Status: "running", StartedAt: time.Now().Add(-time.Minute).Format(time.RFC3339), ReviewRounds: 2},
	}
	if _, err := o.exec.WriteFile(p.ID, "deliverables/report.md", "# 报告\n### R-01 测试发现\n正文\n"); err != nil {
		t.Fatal(err)
	}
	got := v690call(t, o, p, "s8", "complete_stage", `{"summary":"错位写入报告"}`)
	if strings.Contains(got, "必须用 write_file 写入工作区根目录 report.md") {
		t.Fatalf("deliverables/report.md 存在应归位而非拦截: %s", got)
	}
	if !strings.Contains(got, "C29 覆盖边界门") {
		t.Fatalf("归位后内容门应对归位文件生效（C29 拦截缺《覆盖边界》）: %s", got)
	}
	if _, err := o.exec.ReadFile(p.ID, "report.md"); err != nil {
		t.Fatalf("归位后根目录 report.md 应存在: %v", err)
	}

	// ②无任何 report.md → 前置拦截（先产出无关交付物过 fresh 检查）
	p2 := &store.Project{ROEAcknowledgedAt: "2026-11-22T00:00:00Z", ID: "P-S8PRE2"}
	_ = o.store.SaveProject(p2)
	p2.StageStates = map[string]*store.StageState{
		"s8": {Status: "running", StartedAt: time.Now().Add(-time.Minute).Format(time.RFC3339), ReviewRounds: 2},
	}
	if _, err := o.exec.WriteFile(p2.ID, "deliverables/notes.md", "# 笔记\n"); err != nil {
		t.Fatal(err)
	}
	got2 := call(t, o, p2, "s8", "complete_stage", `{"summary":"无报告"}`)
	if !strings.Contains(got2, "写入工作区根目录 report.md") {
		t.Fatalf("无 report.md 应被契约守卫前置拦截: %s", got2)
	}

	// ③根目录正常报告（含合规《覆盖边界》）→ 收口成功，行为与 v6.8.0 一致
	p3 := &store.Project{ROEAcknowledgedAt: "2026-11-22T00:00:00Z", ID: "P-S8PRE3"}
	_ = o.store.SaveProject(p3)
	p3.StageStates = map[string]*store.StageState{
		"s8": {Status: "running", StartedAt: time.Now().Add(-time.Minute).Format(time.RFC3339), ReviewRounds: 2},
	}
	if _, err := o.exec.WriteFile(p3.ID, "report.md", "# 报告\n## 覆盖边界\n| 边界项 | 量化数据 | 解锁条件 | 来源 |\n|---|---|---|---|\n| 认证后 | 0/2 | 提供测试账号 | coverage.json |\n"); err != nil {
		t.Fatal(err)
	}
	got3 := call(t, o, p3, "s8", "complete_stage", `{"summary":"正常报告"}`)
	if strings.Contains(got3, "收口失败") || strings.Contains(got3, "拦截") {
		t.Fatalf("合规报告应正常收口: %s", got3)
	}
}

// TestV690S8EnsureReportContract S8-① 第四轮核对：契约归位助手三态——根目录在场通过 /
// 仅 deliverables/ 归位通过 / 两处皆无拦截；complete_stage 与预算代收口（auto_close）两条
// 收口路径共用同一助手（代收口接线由离线锁锚点+终核顺序断言核验）。
func TestV690S8EnsureReportContract(t *testing.T) {
	o, _, _ := v690S8Orch(t)
	p := &store.Project{ROEAcknowledgedAt: "2026-11-22T00:00:00Z", ID: "P-S8RC"}
	_ = o.store.SaveProject(p)
	// 两处皆无 → 拦截
	if ok, msg := o.ensureReportContract(p, "s8"); ok || !strings.Contains(msg, "写入工作区根目录 report.md") {
		t.Fatalf("无报告应拦截: ok=%v msg=%s", ok, msg)
	}
	// 仅 deliverables/ → 归位后通过
	if _, err := o.exec.WriteFile(p.ID, "deliverables/report.md", "# 报告\n"); err != nil {
		t.Fatal(err)
	}
	if ok, _ := o.ensureReportContract(p, "s8"); !ok {
		t.Fatal("deliverables/report.md 应归位后通过")
	}
	if _, err := o.exec.ReadFile(p.ID, "report.md"); err != nil {
		t.Fatalf("归位后根目录 report.md 应存在: %v", err)
	}
	// 根目录在场 → 直接通过（幂等）
	if ok, _ := o.ensureReportContract(p, "s8"); !ok {
		t.Fatal("根目录在场应直接通过")
	}
	// 非 s8 阶段零动作
	if ok, msg := o.ensureReportContract(p, "s7"); !ok || msg != "" {
		t.Fatalf("非 s8 应直接通过且无文案: ok=%v msg=%s", ok, msg)
	}
}

// TestV690S8HappyPathClosure S8-①~③⑤⑥⑦ 组合行为（第五轮核对）：有发现+有报告的正常收口
// 链零误拦——报告含证据引用（文件在场）/C29 章节/F- 编号映射/target_ref 目标呈现，findings
// 双条全部有归宿（一条标题命中、一条 F- 编号映射+目标在场），contract 守卫通过 → 收口成功。
func TestV690S8HappyPathClosure(t *testing.T) {
	o, st, _ := v690S8Orch(t)
	p := &store.Project{ROEAcknowledgedAt: "2026-11-22T00:00:00Z", ID: "P-S8HAPPY"}
	_ = o.store.SaveProject(p)
	p.StageStates = map[string]*store.StageState{
		"s8": {Status: "running", StartedAt: time.Now().Add(-time.Minute).Format(time.RFC3339), ReviewRounds: 2},
	}
	_, _ = o.exec.WriteFile(p.ID, "evidence/probe.txt", "HTTP 200 idor=2 双主体对比命中")
	report := "# 报告\n## 覆盖边界\n| 边界项 | 量化数据 | 解锁条件 | 来源 |\n|---|---|---|---|\n| 认证后 | 0/2 | 提供测试账号 | coverage.json |\n" +
		"### R-001 明文传输\n复现请求见 evidence/probe.txt\n" +
		"## 定级表映射\n- FIDB → R-001（同根因合并）\n" +
		"目标 b.example.com 章节见 R-001\n"
	_, _ = o.exec.WriteFile(p.ID, "report.md", report)
	_, _ = st.AddFinding(&store.Finding{ProjectID: p.ID, Stage: "s4", Title: "明文传输", Detail: "x", Severity: "中", Confidence: "确证"})
	idB, _ := st.AddFinding(&store.Finding{ProjectID: p.ID, Stage: "s4", Title: "越权读取他人订单详情接口可遍历任意订单号矩阵实测", Detail: "y", Severity: "高", Confidence: "确证", TargetRef: "b.example.com"})
	report = strings.ReplaceAll(report, "FIDB", idB)
	_, _ = o.exec.WriteFile(p.ID, "report.md", report)

	got := v690call(t, o, p, "s8", "complete_stage", `{"summary":"正常报告收口"}`)
	if strings.Contains(got, "收口失败") || strings.Contains(got, "拦截") {
		t.Fatalf("全部归宿齐备应零误拦正常收口: %s", got)
	}
	if !strings.Contains(got, "阶段已收口") {
		t.Fatalf("应成功收口: %s", got)
	}
}

// TestV690S8DispatchE2E 第七轮核对：s8 全 dispatch 链路（含反思门的真实链路——既有测试
// 均经三振路径或直调 deterministicGate，反思门在场的组合未验证）。复用 v680 E2E 驱动
//（passThroughClient 反思 stub）：
//  E1 无任何 report.md → 契约守卫在真实链路前置拦截；
//  E2 错位写入（仅 deliverables/）且缺《覆盖边界》→ 归位后内容门在真实链路拦截（含反思在场）；
//  E3 全要素齐备（证据在场/映射/target 呈现）→ 含反思门放行收口。
func TestV690S8DispatchE2E(t *testing.T) {
	o, st, _ := v680E2EOrch(t)
	o.llm = passThroughClient{}

	// E1：无报告 → 前置拦截（反思 stub 在场也拦——守卫在反思门之前）
	p1 := &store.Project{ID: "P-V690-E1", Name: "s8e2e", Target: "a.test",
		Authorized: true, ROEAcknowledgedAt: "2026-11-23T00:00:00Z",
		StageStates: map[string]*store.StageState{"s8": {Status: "running", StartedAt: "2026-11-23T00:00:00Z"}}}
	_ = o.store.SaveProject(p1)
	_, _ = o.exec.WriteFile(p1.ID, "deliverables/notes.md", "# 笔记\n")
	resp := o.dispatch(context.Background(), p1, "s8", llm.ToolCall{Name: "complete_stage",
		Arguments: `{"summary":"无报告"}`})
	if !strings.Contains(resp, "写入工作区根目录 report.md") {
		t.Fatalf("真实链路无报告应被契约守卫前置拦截: %s", resp)
	}

	// E2：错位写入+缺 C29 → 归位后内容门在含反思链路拦截
	p2 := &store.Project{ID: "P-V690-E2", Name: "s8e2e2", Target: "a.test",
		Authorized: true, ROEAcknowledgedAt: "2026-11-23T00:00:00Z",
		StageStates: map[string]*store.StageState{"s8": {Status: "running", StartedAt: "2026-11-23T00:00:00Z"}}}
	_ = o.store.SaveProject(p2)
	_, _ = o.exec.WriteFile(p2.ID, "deliverables/report.md", "# 报告\n### R-001 测试发现\n正文\n")
	resp2 := o.dispatch(context.Background(), p2, "s8", llm.ToolCall{Name: "complete_stage",
		Arguments: `{"summary":"错位报告"}`})
	if strings.Contains(resp2, "必须用 write_file 写入工作区根目录 report.md") {
		t.Fatalf("错位报告应归位而非拦截: %s", resp2)
	}
	if !strings.Contains(resp2, "C29 覆盖边界门") {
		t.Fatalf("归位后内容门应在含反思链路拦截: %s", resp2)
	}
	if _, err := o.exec.ReadFile(p2.ID, "report.md"); err != nil {
		t.Fatalf("真实链路归位后根目录 report.md 应存在: %v", err)
	}

	// E3：全要素齐备 → 含反思门放行收口（机械门组合零误拦在反思在场路径复核）
	p3 := &store.Project{ID: "P-V690-E3", Name: "s8e2e3", Target: "a.test",
		Authorized: true, ROEAcknowledgedAt: "2026-11-23T00:00:00Z",
		StageStates: map[string]*store.StageState{"s8": {Status: "running", StartedAt: "2026-11-23T00:00:00Z"}}}
	_ = o.store.SaveProject(p3)
	_, _ = o.exec.WriteFile(p3.ID, "evidence/probe.txt", "HTTP 200 idor=2")
	report := "# 报告\n## 覆盖边界\n| 边界项 | 量化数据 | 解锁条件 | 来源 |\n|---|---|---|---|\n| 认证后 | 0/2 | 提供测试账号 | coverage.json |\n" +
		"### R-001 明文传输\n复现请求见 evidence/probe.txt\n## 合并映射\n- FIDB → R-001（同根因合并）\n" +
		"目标 b.test 章节见 R-001\n"
	_, _ = st.AddFinding(&store.Finding{ProjectID: p3.ID, Stage: "s4", Title: "明文传输", Detail: "x", Severity: "中", Confidence: "确证"})
	idB, _ := st.AddFinding(&store.Finding{ProjectID: p3.ID, Stage: "s4", Title: "越权读取他人订单详情接口可遍历任意订单号矩阵实测", Detail: "y", Severity: "高", Confidence: "确证", TargetRef: "b.test"})
	_, _ = o.exec.WriteFile(p3.ID, "report.md", strings.ReplaceAll(report, "FIDB", idB))
	resp3 := o.dispatch(context.Background(), p3, "s8", llm.ToolCall{Name: "complete_stage",
		Arguments: `{"summary":"全要素收口"}`})
	if strings.Contains(resp3, "收口失败") || strings.Contains(resp3, "拦截") {
		t.Fatalf("全要素齐备含反思链路应零误拦: %s", resp3)
	}
	if !strings.HasPrefix(resp3, "阶段已收口") {
		t.Fatalf("应成功收口: %s", resp3)
	}
	if st3 := p3.StageStates["s8"]; st3 == nil || st3.Status != "done" {
		t.Fatalf("收口后阶段应置 done: %+v", st3)
	}
}

// TestV690S8ReflectStageExcerptHelpers S8-②：审查素材提取纯函数——《发现详情》章节优先、
// rune 截断标注、R- 条目编号提取。
func TestV690S8ReflectStageExcerptHelpers(t *testing.T) {
	raw := "# 报告\n## 执行摘要\n关键数字\n## 发现详情\n### R-001 SQL注入\n正文A\n### R-002 XSS\n正文B\n## 附录\n时间线"
	ex := s8ReportExcerpt(raw)
	if !strings.Contains(ex, "发现详情") || !strings.Contains(ex, "R-001") || !strings.Contains(ex, "正文B") {
		t.Fatalf("摘录应取《发现详情》章节: %s", ex)
	}
	if strings.Contains(ex, "执行摘要") {
		t.Fatalf("摘录不应包含章节前内容: %s", ex)
	}
	if strings.Contains(ex, "附录") {
		t.Fatalf("章节应在下一个二级标题前结束（附录不入《发现详情》摘录）: %s", ex)
	}
	// 无《发现详情》章节 → 回退全文头部
	fallback := s8ReportExcerpt("# 报告\n正文X")
	if !strings.Contains(fallback, "正文X") {
		t.Fatalf("无发现详情章节应回退全文: %s", fallback)
	}
	// 超长截断标注
	long := strings.Repeat("字", 7000)
	tr := s8ReportExcerpt(long)
	if !strings.Contains(tr, "余略") {
		t.Fatalf("超长应截断并标注余略")
	}
	// 第六轮核对：findings 清单行附证据编号（问句 b「引用证据与 findings 库对得上」的数据源）
	line := s8FindingLine(&store.Finding{ID: "F-ABC", Severity: "高", Confidence: "确证", Title: "SQLi", EvidenceIDs: []string{"EV-0001", "EV-0002"}})
	if !strings.Contains(line, "证据[EV-0001,EV-0002]") || !strings.HasPrefix(line, "- F-ABC [高/确证]") {
		t.Fatalf("findings 清单行应附证据编号: %s", line)
	}
	lineNoEv := s8FindingLine(&store.Finding{ID: "F-DEF", Severity: "低", Confidence: "待查", Title: "观察"})
	if strings.Contains(lineNoEv, "证据[") {
		t.Fatalf("无证据编号应如实缺省: %s", lineNoEv)
	}
	rids := s8ReportRIDs(raw)
	if len(rids) != 2 || rids[0] != "R-001" || rids[1] != "R-002" {
		t.Fatalf("R 编号提取不符: %v", rids)
	}
	// 定级表与发现详情并列书写 → 两章并取（方案 S8-②：「定级表与《发现详情》章节摘录」）
	withTable := "# 报告\n## 漏洞定级表\n| R-001 | 高 |\n## 发现详情\n### R-001 SQL注入\n正文A\n## 附录\n时间线"
	ex2 := s8ReportExcerpt(withTable)
	if !strings.Contains(ex2, "漏洞定级表") || !strings.Contains(ex2, "发现详情") || !strings.Contains(ex2, "正文A") {
		t.Fatalf("并列两章应并取: %s", ex2)
	}
	// 第七轮核对：独立《合并映射》章节并入素材（问句 a/c 拆条与合并核对的数据源）
	withMerge := "# 报告\n## 发现详情\n### R-001 明文传输\n正文A\n## 合并映射\n- F-ABC → R-001\n## 附录\n时间线"
	ex3 := s8ReportExcerpt(withMerge)
	if !strings.Contains(ex3, "合并映射") || !strings.Contains(ex3, "F-ABC") || !strings.Contains(ex3, "发现详情") {
		t.Fatalf("合并映射章节应并入审查素材: %s", ex3)
	}
	if strings.Contains(ex2, "执行摘要") || strings.Contains(ex2, "时间线") {
		t.Fatalf("两章之外的正文不应混入: %s", ex2)
	}
}

// TestV690S8ReverseReconGate S8-③反向对账门：findings 在报告无归宿留痕 → 拦截；
// F- 编号映射留痕 → 放行；guard=false → 回退旧口径放行。
func TestV690S8ReverseReconGate(t *testing.T) {
	o, st, _ := v690S8Orch(t)
	p := &store.Project{ROEAcknowledgedAt: "2026-11-22T00:00:00Z", ID: "P-S8REV"}
	_ = o.store.SaveProject(p)
	// v6.0.1 C29：夹具含合规《覆盖边界》章节（边界门单独有专项测试，本测试只考察反向对账门）
	_, _ = o.exec.WriteFile(p.ID, "report.md", "# 报告\n## 覆盖边界\n| 边界项 | 量化数据 | 解锁条件 | 来源 |\n|---|---|---|---|\n| 认证后 | 0/2 | 提供测试账号 | coverage.json |\n### R-001 明文传输\n正文\n")
	_, _ = st.AddFinding(&store.Finding{ProjectID: p.ID, Stage: "s4", Title: "明文传输", Detail: "x", Severity: "中", Confidence: "确证"})
	idB, _ := st.AddFinding(&store.Finding{ProjectID: p.ID, Stage: "s4", Title: "越权读取他人订单详情接口可遍历任意订单号", Detail: "y", Severity: "高", Confidence: "确证"})

	issues := o.deterministicGate(p, "s8")
	hit := false
	for _, iss := range issues {
		if strings.Contains(iss, "反向对账") && strings.Contains(iss, "越权读取") {
			hit = true
		}
	}
	if !hit {
		t.Fatalf("无归宿发现应被反向对账门拦截: %v", issues)
	}

	// F- 编号映射留痕（定级表映射「F-xxx → R-001」合法归宿）→ 放行
	_, _ = o.exec.WriteFile(p.ID, "report.md", "# 报告\n## 覆盖边界\n| 边界项 | 量化数据 | 解锁条件 | 来源 |\n|---|---|---|---|\n| 认证后 | 0/2 | 提供测试账号 | coverage.json |\n### R-001 明文传输\n正文\n## 定级表映射\n- "+idB+" → R-001（同根因合并）\n")
	if issues = o.deterministicGate(p, "s8"); len(issues) != 0 {
		t.Fatalf("映射留痕后应放行: %v", issues)
	}

	// v6.9.0 S8-⑤ 字段优先：target_ref 已登记但目标串未在报告呈现 → 目标呈现拦截
	fb, _ := st.ListFindings(p.ID)
	var fB *store.Finding
	for _, x := range fb {
		if x.ID == idB {
			fB = x
		}
	}
	fB.TargetRef = "https://b.example.com"
	if err := st.UpdateFinding(fB); err != nil {
		t.Fatal(err)
	}
	issues = o.deterministicGate(p, "s8")
	tgtHit := false
	for _, iss := range issues {
		if strings.Contains(iss, "目标呈现") && strings.Contains(iss, "b.example.com") {
			tgtHit = true
		}
	}
	if !tgtHit {
		t.Fatalf("已归属目标未在报告呈现应被拦截: %v", issues)
	}
	// 目标串在场（裸域即可——canonicalTargetKey 归一后 scheme 差异不误拦）→ 放行
	_, _ = o.exec.WriteFile(p.ID, "report.md", "# 报告\n## 覆盖边界\n| 边界项 | 量化数据 | 解锁条件 | 来源 |\n|---|---|---|---|\n| 认证后 | 0/2 | 提供测试账号 | coverage.json |\n### R-001 明文传输\n正文\n## 定级表映射\n- "+idB+" → R-001（同根因合并）\n目标 b.example.com 章节见发现详情\n")
	if issues = o.deterministicGate(p, "s8"); len(issues) != 0 {
		t.Fatalf("目标串在场应放行: %v", issues)
	}

	// guard=false → 回退旧口径（仅正向门）
	o.cfg.Guard.EnforceS8FindingReportRecon = func() *bool { f := false; return &f }()
	_, _ = o.exec.WriteFile(p.ID, "report.md", "# 报告\n## 覆盖边界\n| 边界项 | 量化数据 | 解锁条件 | 来源 |\n|---|---|---|---|\n| 认证后 | 0/2 | 提供测试账号 | coverage.json |\n### R-001 明文传输\n正文\n")
	if issues = o.deterministicGate(p, "s8"); len(issues) != 0 {
		t.Fatalf("guard=false 应回退旧口径放行: %v", issues)
	}
}

// TestV690S8FindingDirectQuery S8-③：search_memory finding:<id> 直取完整记录（detail/poc/remediation）；
// 命中行附 poc/remediation 摘要；缺失时如实标注「未登记」。
func TestV690S8FindingDirectQuery(t *testing.T) {
	o, st := v46Orchestrator(t)
	p := &store.Project{ROEAcknowledgedAt: "2026-11-22T00:00:00Z", ID: "P-S8FQ"}
	_ = o.store.SaveProject(p)
	id, _ := st.AddFinding(&store.Finding{ProjectID: p.ID, Stage: "s5", Title: "SQL注入取数", Detail: "布尔差分稳定复现", Severity: "高", Confidence: "确证",
		Remediation: "参数化查询改造；上线前用 sqlmap 复测验证。",
		POC:         []store.FindingPOC{{Request: "GET /a?id=1' AND 1=1 HTTP/1.1\nHost: t", Response: "HTTP/1.1 200 OK"}}})

	got := v690call(t, o, p, "s8", "search_memory", `{"query":"finding:`+id+`"}`)
	if !strings.Contains(got, "修复建议") || !strings.Contains(got, "参数化查询") || !strings.Contains(got, "请求原文") || !strings.Contains(got, "AND 1=1") {
		t.Fatalf("finding:<id> 直取应含 detail/poc/remediation 原文: %s", got)
	}
	// 不存在的 id
	got = v690call(t, o, p, "s8", "search_memory", `{"query":"finding:F-NOSUCH"}`)
	if !strings.Contains(got, "无该发现") {
		t.Fatalf("未知 id 应如实返回: %s", got)
	}
	// 关键词命中行附摘要行（无 poc/remediation 的发现 → 「未登记」占位）
	_, _ = st.AddFinding(&store.Finding{ProjectID: p.ID, Stage: "s4", Title: "目录列出暴露", Detail: "list 接口泄露", Severity: "低", Confidence: "待查"})
	got = v690call(t, o, p, "s8", "search_memory", `{"query":"目录列出"}`)
	if !strings.Contains(got, "↳") || !strings.Contains(got, "未登记") || !strings.Contains(got, "完整原文 query=\"finding:") {
		t.Fatalf("命中行应附 poc/remediation 摘要（缺失如实标注）: %s", got)
	}
}

// TestV690S8FindingTargetRef S8-⑤：record_finding 登记 target_ref → update_finding 修正 →
// 导出 findings.json / findings.sarif 携带归属。
func TestV690S8FindingTargetRef(t *testing.T) {
	o, _, _ := v690S8Orch(t)
	p := &store.Project{ROEAcknowledgedAt: "2026-11-22T00:00:00Z", ID: "P-S8TR", Target: "a.example.com\nb.example.com"}
	_ = o.store.SaveProject(p)
	got := v690call(t, o, p, "s4", "record_finding", `{"title":"越权遍历订单","severity":"高","confidence":"确证","detail":"双账号矩阵实测","target_ref":"a.example.com"}`)
	if !strings.Contains(got, "已登记漏洞") {
		t.Fatalf("带 target_ref 登记应成功: %s", got)
	}
	fs, _ := o.store.ListFindings(p.ID)
	if len(fs) != 1 || fs[0].TargetRef != "a.example.com" {
		t.Fatalf("target_ref 应落库: %+v", fs)
	}
	fid := fs[0].ID
	got = v690call(t, o, p, "s4", "update_finding", `{"id":"`+fid+`","target_ref":"b.example.com","reason":"复核确认归属 B 目标（证据 evidence/x.txt）"}`)
	if !strings.Contains(got, "已修订") {
		t.Fatalf("target_ref 修正应成功: %s", got)
	}
	fs, _ = o.store.ListFindings(p.ID)
	if fs[0].TargetRef != "b.example.com" {
		t.Fatalf("target_ref 修正未落库: %+v", fs[0])
	}
	// 导出携带：findings.json + SARIF target 属性（工作区先落盘一文件确保目录存在——实跑常态）
	_, _ = o.exec.WriteFile(p.ID, "report.md", "# 报告\n")
	o.exportArtifacts(p)
	raw, err := os.ReadFile(filepath.Join(o.cfg.DataDir, p.ID, "findings.json"))
	if err != nil || !strings.Contains(string(raw), "b.example.com") {
		t.Fatalf("findings.json 应携带 target_ref: %v %s", err, string(raw))
	}
	sarif, err := os.ReadFile(filepath.Join(o.cfg.DataDir, p.ID, "findings.sarif"))
	if err != nil || !strings.Contains(string(sarif), `"target": "b.example.com"`) {
		t.Fatalf("findings.sarif 应携带 target 属性: %v %s", err, string(sarif))
	}
}

// TestV690S8GroupHandoverBlock S8-⑥：多目标项目 s8 上下文出「分组交付物承接」清单（存在才列）；
// 单目标项目零占位；S8-⑤ 归属登记率行随 findings 在场。
func TestV690S8GroupHandoverBlock(t *testing.T) {
	o, st, _ := v690S8Orch(t)
	multi := &store.Project{ROEAcknowledgedAt: "2026-11-22T00:00:00Z", ID: "P-S8GRP", Target: "a.example.com\nb.example.com"}
	_ = o.store.SaveProject(multi)
	ctx := o.buildContextPack(multi, "s8")
	if strings.Contains(ctx, "分组交付物承接") {
		t.Fatalf("无分组文件时不应出承接清单")
	}
	_, _ = o.exec.WriteFile(multi.ID, "deliverables/s4-a.example.com.md", "# A 组漏洞\n- 越权遍历\n")
	_, _ = o.exec.WriteFile(multi.ID, "deliverables/s5-b.example.com.md", "# B 组利用\n")
	_, _ = o.exec.WriteFile(multi.ID, "deliverables/s7-影响评估.md", "# 影响评估\n")
	ctx = o.buildContextPack(multi, "s8")
	if !strings.Contains(ctx, "分组交付物承接") || !strings.Contains(ctx, "s4-a.example.com.md") || !strings.Contains(ctx, "s5-b.example.com.md") {
		t.Fatalf("多目标应出承接清单并列出分组文件: %.600s", ctx)
	}
	if strings.Contains(ctx, "s7-影响评估.md（→ 已并入") {
		t.Fatalf("s7- 前缀文件归 S7 收口移交块，不应重复出现在承接清单")
	}
	// 第五轮核对：承接清单 60 行截断上限（超大目标数项目防上下文膨胀）
	for i := 0; i < 70; i++ {
		_, _ = o.exec.WriteFile(multi.ID, fmt.Sprintf("deliverables/s4-组%02d.example.com.md", i), "# 组\n")
	}
	ctx = o.buildContextPack(multi, "s8")
	if !strings.Contains(ctx, "其余 12 个分组文件截断") {
		t.Fatalf("承接清单超 60 行应截断并标注剩余数量: %.900s", ctx)
	}
	if !strings.Contains(ctx, "S7 收口移交") || !strings.Contains(ctx, "影响评估") {
		t.Fatalf("S7 收口移交块应继续在场（v6.8.0 行为保留）")
	}
	// 单目标零占位
	single := &store.Project{ROEAcknowledgedAt: "2026-11-22T00:00:00Z", ID: "P-S8GRP1", Target: "a.example.com"}
	_ = o.store.SaveProject(single)
	ctxS := o.buildContextPack(single, "s8")
	if strings.Contains(ctxS, "分组交付物承接") {
		t.Fatalf("单目标项目不应出承接清单（消除 read 不存在 s4-<目标>.md 空转）")
	}
	// S8-⑤ 归属登记率行：2 条发现 1 条带 target_ref → 「已登记 1/2 条」
	_, _ = st.AddFinding(&store.Finding{ProjectID: multi.ID, Stage: "s4", Title: "A组越权", Severity: "高", Confidence: "确证", TargetRef: "a.example.com"})
	_, _ = st.AddFinding(&store.Finding{ProjectID: multi.ID, Stage: "s4", Title: "B组明文", Severity: "中", Confidence: "疑似"})
	ctx = o.buildContextPack(multi, "s8")
	if !strings.Contains(ctx, "发现逐目标归属") || !strings.Contains(ctx, "已登记 1/2 条") {
		t.Fatalf("归属登记率行应计数正确: %.600s", ctx)
	}
}

// TestV690S8KeyFigures S8-⑦：reconciliation API key_figures 六维统计与台账一致。
func TestV690S8KeyFigures(t *testing.T) {
	o, st, dir := v690S8Orch(t)
	pid := "P-S8KF"
	_ = o.store.SaveProject(&store.Project{ROEAcknowledgedAt: "2026-11-22T00:00:00Z", ID: pid})
	// 覆盖 3 单元、2 个去重端点
	for _, c := range []store.CoverageEntry{
		{ProjectID: pid, Stage: "s4", Endpoint: "/api/login", Param: "u", VulnClass: "SQLi", Status: "vulnerable"},
		{ProjectID: pid, Stage: "s4", Endpoint: "/api/login", Param: "p", VulnClass: "BruteForce", Status: "no_issue_found"},
		{ProjectID: pid, Stage: "s5", Endpoint: "/api/order", Param: "id", VulnClass: "IDOR", Status: "needs_follow_up"},
	} {
		if _, err := st.UpsertCoverage(&c); err != nil {
			t.Fatal(err)
		}
	}
	_, _ = st.AddFinding(&store.Finding{ProjectID: pid, Stage: "s4", Title: "SQLi", Severity: "高", Confidence: "确证"})
	_, _ = st.AddFinding(&store.Finding{ProjectID: pid, Stage: "s4", Title: "信息泄露", Severity: "中", Confidence: "疑似"})
	_, _ = st.AddTimeline(&store.TimelineEvent{ProjectID: pid, Stage: "s4", Event: "探测", Detail: "x"})
	_, _ = st.AddAsset(&store.Asset{ProjectID: pid, Stage: "s1", Type: "域名", Value: "a.example.com"})
	if err := os.MkdirAll(filepath.Join(dir, pid, "evidence"), 0o755); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"e1.txt", "e2.txt"} {
		if err := os.WriteFile(filepath.Join(dir, pid, "evidence", f), []byte("x"), 0o640); err != nil {
			t.Fatal(err)
		}
	}
	out := o.ReconciliationPublic(pid)
	kf, ok := out["key_figures"].(map[string]any)
	if !ok {
		t.Fatalf("key_figures 应在场: %v", out)
	}
	if kf["endpoints"].(int) != 2 || kf["coverage_units"].(int) != 3 || kf["findings"].(int) != 2 ||
		kf["evidence_files"].(int) != 2 || kf["timeline_events"].(int) != 1 || kf["assets"].(int) != 1 {
		t.Fatalf("key_figures 统计不符: %+v", kf)
	}
	dist := kf["findings_dist"].(map[string]int)
	if dist["高/确证"] != 1 || dist["中/疑似"] != 1 {
		t.Fatalf("发现分布不符: %+v", dist)
	}
	if !strings.Contains(kf["note"].(string), "待人工确认") {
		t.Fatalf("key_figures 应标注引擎统计待人工确认")
	}
	// v6.9.0 S8-⑦ 第三轮核对补齐：模型侧通道——s8 上下文「关键数字与覆盖边界」块与 API 同源
	ctxS8 := o.buildContextPack(&store.Project{ROEAcknowledgedAt: "2026-11-22T00:00:00Z", ID: pid}, "s8")
	if !strings.Contains(ctxS8, "关键数字与覆盖边界") {
		t.Fatalf("s8 上下文应含关键数字块（模型不能调 API）")
	}
	// 第六轮核对：分布按键排序渲染（稳定输出利于审计 diff）
	if !strings.Contains(ctxS8, "- 发现分布（等级/置信度）: 中/疑似×1, 高/确证×1") {
		t.Fatalf("发现分布应按键排序稳定渲染: %.900s", ctxS8)
	}
	for _, want := range []string{"- 端点数（去重）: 2", "- 覆盖矩阵单元数: 3", "- 发现数: 2", "- 证据文件数: 2", "- 时间线事件数: 1", "- 资产数: 1"} {
		if !strings.Contains(ctxS8, want) {
			t.Fatalf("关键数字块应与台账一致（%s）: %.600s", want, ctxS8)
		}
	}
	if !strings.Contains(ctxS8, "覆盖边界》初稿") {
		t.Fatalf("关键数字块应附《覆盖边界》初稿（C29 取材通道）")
	}
}
