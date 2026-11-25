package engine

// v7.2.0 第三轮核对回归：判重×消费交互（Fix E）+ 单字符串引用宽容解析（Fix F）

import (
	"context"
	"strings"
	"testing"

	"jiutouniao/internal/llm"
)

// Fix E：approved 提议经 update_proposal 消费后，同 kind+focus 重新提议是新周期（放行）；
// 未消费（无 outcome）仍判重。
func TestV720DedupConsumedCycle(t *testing.T) {
	o, st := v48Orchestrator(t)
	p := v710Project(st, "P-V720-CYCLE")
	_, _ = o.exec.WriteFile(p.ID, "evidence/cycle.txt", "sig")
	args := `{"kind":"depth_extend","rationale":"第一周期","focus":"C-13@login","evidence_refs":["evidence/cycle.txt"]}`
	r1 := o.dispatch(context.Background(), p, "s4", llm.ToolCall{Name: "propose", Arguments: args})
	if !strings.Contains(r1, "已批准") {
		t.Fatalf("第一周期应批准: %s", r1)
	}
	r2 := o.dispatch(context.Background(), p, "s4", llm.ToolCall{Name: "propose", Arguments: args})
	if !strings.Contains(r2, "DUPLICATE") {
		t.Fatalf("未消费时同族应判重: %s", r2)
	}
	// 消费：回写 outcome → 新周期放行
	prs, _ := st.ListAutonomy(p.ID)
	var id string
	for _, r := range prs {
		if r.Verdict == "approved" {
			id = r.ID
		}
	}
	o.dispatch(context.Background(), p, "s4", llm.ToolCall{Name: "update_proposal",
		Arguments: `{"id":"` + id + `","outcome":"F-3 确证"}`})
	r3 := o.dispatch(context.Background(), p, "s4", llm.ToolCall{Name: "propose",
		Arguments: strings.Replace(args, "第一周期", "第二周期（条件变化：新变异面）", 1)})
	if !strings.Contains(r3, "已批准") {
		t.Fatalf("已消费提议不应阻塞新周期: %s", r3)
	}
}

// Fix F：evidence_refs 传单字符串（非数组）应宽容解析而非 NO_EVIDENCE。
func TestV720SingleStringRef(t *testing.T) {
	o, st := v48Orchestrator(t)
	p := v710Project(st, "P-V720-STR")
	_, _ = o.exec.WriteFile(p.ID, "evidence/str.txt", "sig")
	r := o.dispatch(context.Background(), p, "s4", llm.ToolCall{Name: "propose",
		Arguments: `{"kind":"depth_extend","rationale":"单串引用","focus":"C-13@x","evidence_refs":"evidence/str.txt"}`})
	if strings.Contains(r, "NO_EVIDENCE") || strings.Contains(r, "被拒") {
		t.Fatalf("单字符串引用应宽容解析: %s", r)
	}
	if !strings.Contains(r, "已批准") {
		t.Fatalf("单字符串引用提议应批准: %s", r)
	}
}
