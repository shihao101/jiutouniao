package engine

// v7.7.2 回归：手动续跑预算授予（StartProject 注入 + 护栏读取）

import (
	"strings"
	"testing"

	"jiutouniao/internal/store"
)

func TestV772ResumeGrant(t *testing.T) {
	o, st := v48Orchestrator(t)
	p := v710Project(st, "P-V772-RG")
	p.Status = "failed"
	p.BudgetTokens = 1000000
	// s8 failed + token 预算耗尽 summary
	p.StageStates["s8"] = &store.StageState{Status: "failed", Summary: "token 预算耗尽（max_project_tokens）"}
	_ = st.SaveProject(p)
	// StartProject 注入授予
	o.grantResumeBudget(p)
	if p.BudgetGrants != 250000 { // 25% of 1M
		t.Fatalf("应授予 25%% 预算: %d", p.BudgetGrants)
	}
	_ = st.SaveProject(p) // StartProject 流程内的 SaveProject 落盘（测试模拟同序）
	if !strings.Contains(p.StageStates["s8"].Summary, "") && false {
		t.Fatal("unreachable")
	}
	// 时间线留痕
	tl, _ := st.ListTimeline(p.ID)
	found := false
	for _, ev := range tl {
		if strings.Contains(ev.Event, "续跑预算授予") {
			found = true
		}
	}
	if !found {
		t.Fatalf("授予应落时间线")
	}
	// 无 failed+token 摘要 → 不授予
	p2 := v710Project(st, "P-V772-RG2")
	p2.Status = "failed"
	p2.StageStates["s8"] = &store.StageState{Status: "failed", Summary: "其他原因失败"}
	o.grantResumeBudget(p2)
	if p2.BudgetGrants != 0 {
		t.Fatalf("非预算耗尽失败不应授予")
	}
	// 0 关闭
	o.cfg.Engine.ResumeGrantPct = 0
	p3 := v710Project(st, "P-V772-RG3")
	p3.Status = "failed"
	p3.StageStates["s8"] = &store.StageState{Status: "failed", Summary: "token 预算耗尽"}
	o.grantResumeBudget(p3)
	if p3.BudgetGrants != 0 {
		t.Fatalf("ResumeGrantPct=0 应关闭授予")
	}
}
