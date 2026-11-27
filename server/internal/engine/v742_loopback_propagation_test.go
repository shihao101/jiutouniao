package engine

// v7.4.2 回环聚焦传导回归：下游阶段重入原因传播 + 重入承接包（自身既往交付物可见）

import (
	"context"
	"strings"
	"testing"

	"jiutouniao/internal/llm"
	"jiutouniao/internal/store"
)

// 缺口①：loopback(s5→s4, focus) 后，下游 s5/s6/s7/s8 的 ReentryReason 均携带聚焦范围。
func TestV742FocusPropagation(t *testing.T) {
	o, st := v48Orchestrator(t)
	o.heads = map[string]*Head{
		"s4": {ID: "s4", Name: "漏洞发现", Order: 4},
		"s5": {ID: "s5", Name: "利用", Order: 5},
		"s6": {ID: "s6", Name: "后渗透", Order: 6},
		"s7": {ID: "s7", Name: "收尾", Order: 7},
		"s8": {ID: "s8", Name: "报告", Order: 8},
	}
	o.loops = map[string][]string{}
	o.loopTotal = map[string]int{}
	p := v710Project(st, "P-V742-PROP")
	for _, sid := range []string{"s6", "s7", "s8"} {
		p.StageStates[sid] = &store.StageState{Status: "done"}
	}
	_ = st.SaveProject(p)
	resp := o.dispatch(context.Background(), p, "s6", llm.ToolCall{Name: "loopback",
		Arguments: `{"to_stage":"s4","reason":"新攻击面打通","focus":"C-07+C-13@h1;h2"}`})
	if !strings.Contains(resp, "已触发回环") {
		t.Fatalf("回环应入队: %s", resp)
	}
	for _, sid := range []string{"s5", "s6", "s7", "s8"} {
		got := p.StageStates[sid].ReentryReason
		if !strings.Contains(got, "聚焦范围: C-07+C-13@h1;h2") || !strings.Contains(got, "承接聚焦回环") {
			t.Fatalf("下游 %s 应携带聚焦重入原因: %q", sid, got)
		}
	}
	if !strings.Contains(p.StageStates["s4"].ReentryReason, "聚焦范围: C-07+C-13@h1;h2") {
		t.Fatalf("目标阶段 s4 应有聚焦原因（不带承接前缀）")
	}
}

// 缺口②：重入时本阶段既往交付物清单注入上下文。
func TestV742ReentryHandoverPack(t *testing.T) {
	o, st := v48Orchestrator(t)
	p := v710Project(st, "P-V742-PACK")
	st4 := p.StageStates["s4"]
	st4.ReentryReason = "S6 发现新攻击面｜聚焦范围: C-07@h1"
	st4.Deliverables = []string{"deliverables/s4-漏洞清单.md", "deliverables/s4-清单外发现统计.md"}
	_ = st.SaveProject(p)
	ctxPack := o.buildContextPack(p, "s4")
	if !strings.Contains(ctxPack, "本阶段上一轮交付物") || !strings.Contains(ctxPack, "s4-漏洞清单.md") {
		t.Fatalf("重入上下文应含本阶段既往交付物清单")
	}
}
