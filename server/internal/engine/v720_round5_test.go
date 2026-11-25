package engine

// v7.2.0 第四轮核对回归：判重不消耗配额（Fix H）+ killed 归因接线（Fix J）

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"jiutouniao/internal/llm"
)

// Fix H：重复提议不消耗阶段配额——同族 DUPLICATE 拒绝 N 次后，新提议仍在配额内正常批准。
func TestV720DedupNoQuotaBurn(t *testing.T) {
	o, st := v48Orchestrator(t)
	p := v710Project(st, "P-V720-QB")
	_, _ = o.exec.WriteFile(p.ID, "evidence/q.txt", "sig")
	_, _ = o.exec.WriteFile(p.ID, "evidence/q2.txt", "sig2")
	base := `{"kind":"depth_extend","rationale":"r","focus":"C-13@login","evidence_refs":["evidence/q.txt"]}`
	if r := o.dispatch(context.Background(), p, "s4", llm.ToolCall{Name: "propose", Arguments: base}); !strings.Contains(r, "已批准") {
		t.Fatalf("首提应批准: %s", r)
	}
	for i := 0; i < 6; i++ { // 旧序下这 6 次 DUPLICATE 会烧光配额（上限 6）
		r := o.dispatch(context.Background(), p, "s4", llm.ToolCall{Name: "propose", Arguments: base})
		if !strings.Contains(r, "DUPLICATE") {
			t.Fatalf("第 %d 次重复应判重: %s", i+1, r)
		}
	}
	r := o.dispatch(context.Background(), p, "s4", llm.ToolCall{Name: "propose",
		Arguments: `{"kind":"depth_extend","rationale":"真正的新提议","focus":"C-14@order","evidence_refs":["evidence/q2.txt"]}`})
	if !strings.Contains(r, "已批准") {
		t.Fatalf("重复提议不应消耗配额——新提议应正常批准: %s", r)
	}
	// DUPLICATE 不计入升维计数（修复 H 语义）：q 首提 + 新 C-14 = 2 条记录，6 次 DUPLICATE 也留痕但 denials 只应有 C-14 的 0
	recs, _ := st.ListAutonomy(p.ID)
	dups := 0
	for _, r2 := range recs {
		if strings.Contains(r2.Reason, "DUPLICATE") {
			dups++
		}
	}
	if dups != 6 {
		t.Fatalf(fmt.Sprintf("DUPLICATE 应留痕 %d 条", dups))
	}
}

// Fix J：poll_async killed → 通道健康 timeout 归因（经 stage_metrics/冲刺注入消费）。
func TestV720AsyncKilledHealth(t *testing.T) {
	o, st := v48Orchestrator(t)
	p := v710Project(st, "P-V720-KH")
	// 直接触发 killed 分支的反馈构造（走 toolPollAsync 反馈函数语义）
	o.trackToolHealth(p, "s4", "timed out (async job killed)", 1)
	s := o.toolHealthSummary(p.ID, "s4")
	if !strings.Contains(s, "timeout=1") {
		t.Fatalf("killed 应计入 timeout 归因: %s", s)
	}
}
