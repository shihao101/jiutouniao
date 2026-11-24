package engine

// v6.2.0 S2 修复方案①回归：s2 确定性收口门（s2ClosureIssues）。
// 覆盖：①攻击面地图/拓扑重建缺失与空壳拦截；②checklist.json 坏 JSON fail-closed；
// 无自述面（无 checklist.json）放行；③多目标逐目标归宿（缺一拦截 / 档案目标显式归宿放行 /
// 单目标不触发对账）；guard.enforce_s2_closure 显式 false 回退。

import (
	"fmt"
	"strings"
	"testing"

	"jiutouniao/internal/store"
)

var s2GateFixture = map[string]string{
	"deliverables/s2-攻击面地图.md": "# S2 攻击面地图\n\n| 目标 | 端口 | 服务 | 指纹 |\n|---|---|---|---|\n| a.test | 443 | https | nginx |\n| b.test | 80 | http | tomcat |\n",
	"deliverables/拓扑重建-V1.md":      "# 拓扑重建 V1\n\n响应头指纹：nginx/1.24；同源多端口：80/8080 同构。\n",
}

// s2GateFixtureProject 构造带 StageStates 与资产的 S2 收口夹具项目。
// v6.3.2：默认登记 S2-1..S2-11 全步骤子任务（步骤计划完整性门要求）。
func s2GateFixtureProject(t *testing.T, o *Orchestrator, targets string, files map[string]string, extraFiles map[string]string) *store.Project {
	t.Helper()
	p := &store.Project{ID: "P-V620-S2G", Name: "S2收口", Target: targets,
		Authorized: true, StrictScope: false, ROEAcknowledgedAt: "2026-11-23T00:00:00Z",
		StageStates: map[string]*store.StageState{
			"s2": {Status: "running"},
		}}
	_ = o.store.SaveProject(p)
	registerS2StepSubtasks(t, o, p.ID)
	for _, tgt := range splitProjectTargets(p) {
		_, _ = o.store.AddAsset(&store.Asset{ProjectID: p.ID, Stage: "s2", Type: "域名",
			Value: tgt, TargetRef: tgt, ScopeStatus: "in_scope", ScopeEvidence: "项目授权清单"})
	}
	for f, body := range files {
		_, _ = o.exec.WriteFile(p.ID, f, body)
	}
	for f, body := range extraFiles {
		_, _ = o.exec.WriteFile(p.ID, f, body)
	}
	return p
}

// registerS2StepSubtasks 登记 S2-1..S2-11 全步骤子任务（标题以步骤编号开头）。
func registerS2StepSubtasks(t *testing.T, o *Orchestrator, projectID string) {
	t.Helper()
	for i := 1; i <= 11; i++ {
		_, err := o.store.AddSubtask(&store.Subtask{ProjectID: projectID, Stage: "s2",
			Title: fmt.Sprintf("S2-%d 步骤%d", i, i), Status: "finished"})
		if err != nil {
			t.Fatalf("登记子任务失败: %v", err)
		}
	}
}

func s2GateIssuesContains(t *testing.T, issues []string, needle string) bool {
	t.Helper()
	for _, iss := range issues {
		if strings.Contains(iss, needle) {
			return true
		}
	}
	return false
}

func TestV620S2ClosureRequiresAttackSurfaceMap(t *testing.T) {
	o, _ := v48Orchestrator(t)
	p := s2GateFixtureProject(t, o, "a.test", s2GateFixture, map[string]string{})
	// 缺攻击面地图 → 固定文案
	_, _ = o.exec.WriteFile(p.ID, "deliverables/s2-攻击面地图.md", "")
	issues := o.s2ClosureIssues(p)
	if !s2GateIssuesContains(t, issues, "缺少或内容为空：deliverables/s2-攻击面地图.md") {
		t.Fatalf("缺攻击面地图应返回固定文案: %v", issues)
	}
	// 补齐 → 无 issues
	_, _ = o.exec.WriteFile(p.ID, "deliverables/s2-攻击面地图.md", s2GateFixture["deliverables/s2-攻击面地图.md"])
	if issues := o.s2ClosureIssues(p); len(issues) != 0 {
		t.Fatalf("攻击面地图/拓扑重建齐全应通过: %v", issues)
	}
}

func TestV620S2ClosureRejectsEmptyShellArtifacts(t *testing.T) {
	o, _ := v48Orchestrator(t)
	files := map[string]string{}
	for k, v := range s2GateFixture {
		files[k] = v
	}
	files["deliverables/拓扑重建-V1.md"] = "占位" // <40 字节空壳
	p := s2GateFixtureProject(t, o, "a.test", files, map[string]string{})
	issues := o.s2ClosureIssues(p)
	if !s2GateIssuesContains(t, issues, "s2-拓扑重建-V1.md") && !s2GateIssuesContains(t, issues, "拓扑重建-V1.md") {
		t.Fatalf("空壳拓扑重建应被拦: %v", issues)
	}
	if !s2GateIssuesContains(t, issues, "占位空壳") {
		t.Fatalf("拦截文案应含占位空壳: %v", issues)
	}
}

func TestV620S2ClosureRejectsBrokenChecklistJSON(t *testing.T) {
	o, _ := v48Orchestrator(t)
	p := s2GateFixtureProject(t, o, "a.test", s2GateFixture,
		map[string]string{"checklist.json": `{"items":[{"id":"C1","item":"登录功能" `}) // 截断 JSON
	issues := o.s2ClosureIssues(p)
	if !s2GateIssuesContains(t, issues, "checklist.json 存在但不可解析") {
		t.Fatalf("坏 JSON checklist 应 fail-closed 拦截: %v", issues)
	}
	// 修复为可解析形态（含 id/item/class）→ 通过
	_, _ = o.exec.WriteFile(p.ID, "checklist.json", `{"items":[{"id":"C1","item":"登录功能存在弱口令","hint":"/login","class":"弱口令"}]}`)
	if issues := o.s2ClosureIssues(p); len(issues) != 0 {
		t.Fatalf("修复后应通过: %v", issues)
	}
}

func TestV620S2ClosureAllowsMissingChecklist(t *testing.T) {
	// 无自述面目标合法缺失 checklist.json（S2-9 条件必做）——门不得打扰
	o, _ := v48Orchestrator(t)
	p := s2GateFixtureProject(t, o, "a.test", s2GateFixture, map[string]string{})
	if issues := o.s2ClosureIssues(p); len(issues) != 0 {
		t.Fatalf("无 checklist.json（无自述面）应放行: %v", issues)
	}
}

func TestV620S2TargetReconMissingTargetBlocks(t *testing.T) {
	o, _ := v48Orchestrator(t)
	// 三目标：a/b 有攻击面地图登记，c.test 静默蒸发（无覆盖/资产已在（对账含资产语料——此处
	// 资产语料来自 fixture 登记，故 c 命中资产会放行；为复现漏扫需 c 无任何资产记录）
	p := &store.Project{ID: "P-V620-S2R", Name: "S2漏扫", Target: "a.test\nb.test\nc.test",
		Authorized: true, StrictScope: false, ROEAcknowledgedAt: "2026-11-23T00:00:00Z",
		StageStates: map[string]*store.StageState{"s2": {Status: "running"}}}
	_ = o.store.SaveProject(p)
	registerS2StepSubtasks(t, o, p.ID)
	for _, tgt := range []string{"a.test", "b.test"} { // c.test 未登记（模拟漏扫）
		_, _ = o.store.AddAsset(&store.Asset{ProjectID: p.ID, Stage: "s2", Type: "域名",
			Value: tgt, TargetRef: tgt, ScopeStatus: "in_scope", ScopeEvidence: "项目授权清单"})
	}
	for f, body := range s2GateFixture {
		_, _ = o.exec.WriteFile(p.ID, f, body)
	}
	// 覆盖登记 a/b（S2-5 普查留痕形态）
	_, _ = o.store.UpsertCoverage(&store.CoverageEntry{ProjectID: p.ID, Stage: "s2",
		Endpoint: "https://a.test", VulnClass: "匿名暴露面", Status: "no_issue_found"})
	_, _ = o.store.UpsertCoverage(&store.CoverageEntry{ProjectID: p.ID, Stage: "s2",
		Endpoint: "https://b.test", VulnClass: "匿名暴露面", Status: "no_issue_found"})
	issues := o.s2ClosureIssues(p)
	if !s2GateIssuesContains(t, issues, "S2 逐目标对账") || !s2GateIssuesContains(t, issues, "c.test") {
		t.Fatalf("漏扫目标 c.test 应逐目标拦截: %v", issues)
	}
}

func TestV620S2TargetReconArchivedTargetPasses(t *testing.T) {
	o, _ := v48Orchestrator(t)
	p := &store.Project{ID: "P-V620-S2A", Name: "S2档案目标", Target: "a.test\nb.test\ndead.test",
		Authorized: true, StrictScope: false, ROEAcknowledgedAt: "2026-11-23T00:00:00Z",
		StageStates: map[string]*store.StageState{"s2": {Status: "running"}}}
	_ = o.store.SaveProject(p)
	registerS2StepSubtasks(t, o, p.ID)
	for _, tgt := range []string{"a.test", "b.test"} {
		_, _ = o.store.AddAsset(&store.Asset{ProjectID: p.ID, Stage: "s2", Type: "域名",
			Value: tgt, TargetRef: tgt, ScopeStatus: "in_scope", ScopeEvidence: "项目授权清单"})
	}
	_, _ = o.store.AddAsset(&store.Asset{ProjectID: p.ID, Stage: "s2", Type: "域名",
		Value: "dead.test", TargetRef: "dead.test", ScopeStatus: "in_scope", ScopeEvidence: "项目授权清单",
		Detail: "档案目标：ICMP/TCP 存活与 HTTP 存活连续两类探针均不可达，判据证据见攻击面地图"})
	for f, body := range s2GateFixture {
		_, _ = o.exec.WriteFile(p.ID, f, body)
	}
	_, _ = o.store.UpsertCoverage(&store.CoverageEntry{ProjectID: p.ID, Stage: "s2",
		Endpoint: "https://a.test", VulnClass: "匿名暴露面", Status: "no_issue_found"})
	_, _ = o.store.UpsertCoverage(&store.CoverageEntry{ProjectID: p.ID, Stage: "s2",
		Endpoint: "https://b.test", VulnClass: "匿名暴露面", Status: "no_issue_found"})
	if issues := o.s2ClosureIssues(p); len(issues) != 0 {
		t.Fatalf("档案目标显式归宿（资产 Detail 留痕）应放行: %v", issues)
	}
}

func TestV620S2ClosureRollbackFlag(t *testing.T) {
	// 开关在 deterministicGate 调用侧读取（与 s1 门同构）：false 回退时不查 s2 收口件
	o, _ := v48Orchestrator(t)
	p := s2GateFixtureProject(t, o, "a.test", map[string]string{}, map[string]string{}) // 全缺
	if issues := o.deterministicGate(p, "s2"); len(issues) == 0 {
		t.Fatalf("enforce_s2_closure 缺省 true 时全缺应拦截")
	}
	f := false
	o.cfg.Guard.EnforceS2Closure = &f
	if issues := o.deterministicGate(p, "s2"); len(issues) != 0 {
		t.Fatalf("enforce_s2_closure=false 应回退（事故手段）: %v", issues)
	}
}
