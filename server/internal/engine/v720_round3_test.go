package engine

// v7.2.0 核对轮回归：同族提议判重 / 参谋建议证据预校验 / 目标提取 @ 风格 / planDelta 桩 Status

import (
	"context"
	"strings"
	"testing"

	"jiutouniao/internal/llm"
)

// Fix C：同 kind+同 focus 非 denied 提议在场 → DUPLICATE 拒绝重提。
func TestV720ProposalDedup(t *testing.T) {
	o, st := v48Orchestrator(t)
	p := v710Project(st, "P-V720-DUP")
	_, _ = o.exec.WriteFile(p.ID, "evidence/dup.txt", "sig")
	args := `{"kind":"depth_extend","rationale":"差分稳定","focus":"C-13@login","evidence_refs":["evidence/dup.txt"]}`
	r1 := o.dispatch(context.Background(), p, "s4", llm.ToolCall{Name: "propose", Arguments: args})
	if !strings.Contains(r1, "已批准") {
		t.Fatalf("首次提议应批准: %s", r1)
	}
	r2 := o.dispatch(context.Background(), p, "s4", llm.ToolCall{Name: "propose", Arguments: args})
	if !strings.Contains(r2, "DUPLICATE") {
		t.Fatalf("同族重提应判重拒绝: %s", r2)
	}
	// denied 后允许重提（判重只拦非 denied）
	o.dispatch(context.Background(), p, "s4", llm.ToolCall{Name: "propose",
		Arguments: `{"kind":"mutation_campaign","rationale":"无前提","focus":"C-14@x","evidence_refs":["evidence/dup.txt"]}`}) // NO_WAF_BLOCKED denied
	r3 := o.dispatch(context.Background(), p, "s4", llm.ToolCall{Name: "propose",
		Arguments: `{"kind":"mutation_campaign","rationale":"无前提","focus":"C-14@x","evidence_refs":["evidence/dup.txt"]}`})
	if !strings.Contains(r3, "NO_WAF_BLOCKED") {
		t.Fatalf("denied 后同族应可重提（走规则收敛而非判重）: %s", r3)
	}
}

// Fix A：参谋建议证据不可达 → 丢弃不进裁决（parse 层后置的防幻觉闸）。
func TestV720BrainEvidencePreflight(t *testing.T) {
	o, st := v48Orchestrator(t)
	p := v710Project(st, "P-V720-BE")
	// 直接走裁决路径模拟：幻觉引用应被 verifyEvidenceRefs 判无效 → 证据不可达丢弃
	valid, invalid, _ := o.verifyEvidenceRefs(p, []string{"evidence/ghost.txt"})
	if len(valid) != 0 || len(invalid) != 1 {
		t.Fatalf("幻觉引用应判无效: valid=%v invalid=%v", valid, invalid)
	}
	if o.duplicateProposal(p.ID, "depth_extend", "C-13@login") != "" {
		t.Fatalf("空账本应无判重命中")
	}
}

// Fix D：目标提取 @ 风格。
func TestV720ExtractTarget(t *testing.T) {
	if got := extractCoverageTarget("/login@app.test"); got != "app.test" {
		t.Fatalf("@ 风格提取: %q", got)
	}
	if got := extractCoverageTarget("/a（t1.example.com）"); got != "t1.example.com" {
		t.Fatalf("全角括号提取: %q", got)
	}
	if got := extractCoverageTarget("/plain"); got != "" {
		t.Fatalf("无目标应返回空: %q", got)
	}
}

// Fix B：planDelta 在 s4 StageState 缺失时建 pending 桩（非空 Status）。
func TestV720PlanDeltaStubPending(t *testing.T) {
	o, st := v48Orchestrator(t)
	o.heads = map[string]*Head{"s4": {ID: "s4", Order: 4}, "s5": {ID: "s5", Order: 5}}
	p := v710Project(st, "P-V720-STUB")
	delete(p.StageStates, "s4")
	_ = st.SaveProject(p)
	o.dispatch(context.Background(), p, "s5", llm.ToolCall{Name: "record_asset",
		Arguments: `{"type":"域名","value":"stub.example.com","scope_status":"in_scope","scope_evidence":"扩展工单"}`})
	st4 := p.StageStates["s4"]
	if st4 == nil || st4.Status != "pending" || st4.PlanVersion != 1 {
		t.Fatalf("桩应 pending + PlanVersion=1: %+v", st4)
	}
}
