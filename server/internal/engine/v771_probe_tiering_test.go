package engine

// v7.7.1 红队模式回归：基线类深化不计产出（idle 累积）/vulnerable 仍计/关闭回退/非基线不变

import (
	"testing"

	"jiutouniao/internal/store"
)

func blEntry(status string, count int) *store.CoverageEntry {
	return &store.CoverageEntry{Endpoint: "/tls@t1", VulnClass: "TLS (C-24)", Status: status, Count: count}
}

func TestV771BaselineTier(t *testing.T) {
	o, _ := v48Orchestrator(t)
	// 基线类第二次登记（no_issue_found, Count=2）→ 命中
	if !o.baselineTierUnit(blEntry("no_issue_found", 2)) {
		t.Fatal("基线类二登记应命中")
	}
	// vulnerable 在基线类 → 不命中（真发现永远算产出）
	if o.baselineTierUnit(blEntry("vulnerable", 2)) {
		t.Fatal("vulnerable 应豁免")
	}
	// 首轮基线（Count=1）→ 不命中（首轮就是产出）
	if o.baselineTierUnit(blEntry("no_issue_found", 1)) {
		t.Fatal("首轮基线应计产出")
	}
	// 非基线类 → 不命中
	non := &store.CoverageEntry{Endpoint: "/login", VulnClass: "越权 (C-08)", Status: "no_issue_found", Count: 5}
	if o.baselineTierUnit(non) {
		t.Fatal("非基线类不应命中")
	}
	// probe_tiering=false（合规模式）→ 不命中
	f := false
	o.cfg.Engine.ProbeTiering = &f
	if o.baselineTierUnit(blEntry("no_issue_found", 2)) {
		t.Fatal("合规模式应回旧口径")
	}
}

func TestV771BaselineTierConvergenceEffect(t *testing.T) {
	o, st := v48Orchestrator(t)
	p := v710Project(st, "P-V771-BL")
	o.heads = map[string]*Head{"s4": {ID: "s4", Order: 4}}
	// 基线类重复登记（Count=5）→ 不重置 idle
	for i := 0; i < 3; i++ {
		o.convMarkIdle(p, "s4")
	}
	o.baselineTierUnit(blEntry("no_issue_found", 5)) // 命中基线 → 不调 convNote
	if got := o.convIdleRounds(p, "s4"); got != 3 {
		t.Fatalf("基线深化不应重置 idle（got %d）", got)
	}
	// 对照：vulnerable 登记 → 重置 idle
	o.convNote(p, "s4")
	if got := o.convIdleRounds(p, "s4"); got != 0 {
		t.Fatalf("vulnerable 应重置 idle")
	}
}
