package engine

// v6.6.0 核对轮增补回归：①S5「专项就绪移交」块同时呈现 V3Ready 与 V3L2（与 S4→S5 块
// 两清单同呈对齐）；②spec 移交项承接提示级核对（零承接 → 提示出现；S5 coverage 引用条目
// 正文后不再提示；spec 自身交付物不构成自匹配放行）。

import (
	"strings"
	"testing"

	"jiutouniao/internal/store"
)

func TestV660SpecHandoverBlockL2(t *testing.T) {
	o, _ := v48Orchestrator(t)
	p := &store.Project{ROEAcknowledgedAt: "2026-11-23T00:00:00Z", ID: "P-V660-SPECL2",
		Target: "a.example.com"}
	_ = o.store.SaveProject(p)
	p.StageStates = map[string]*store.StageState{
		"specB1": {Status: "done",
			V3Ready: []string{"Frida 反 SSL-Pinning 脚本 pinning-bypass.js"},
			V3L2:    []string{"AP-200 已批 frida 注入动态验证未投递"}},
	}
	_ = o.store.SaveProject(p)
	out := o.buildContextPack(p, "s5")
	for _, want := range []string{
		"专项就绪移交（v6.6.0 SP-③", "[specB1 就绪未执行] Frida 反 SSL-Pinning 脚本",
		"[specB1 已批未用] AP-200 已批 frida 注入动态验证未投递",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("S5 专项移交块缺少 %q", want)
		}
	}
}

func TestV660SpecHandoverHint(t *testing.T) {
	o, _ := v48Orchestrator(t)
	p := &store.Project{ROEAcknowledgedAt: "2026-11-23T00:00:00Z", ID: "P-V660-SPECHINT",
		Target: "a.example.com"}
	_ = o.store.SaveProject(p)
	p.StageStates = map[string]*store.StageState{
		"specB1": {Status: "done",
			V3Ready: []string{"Frida 反 SSL-Pinning 脚本 pinning-bypass.js"}},
	}
	_ = o.store.SaveProject(p)
	// spec 自身交付物含条目原文——不得构成自匹配放行（提示仍应出现）
	if _, err := o.exec.WriteFile("P-V660-SPECHINT", "deliverables/specB1-假设队列.md",
		"# 假设队列\n- Frida 反 SSL-Pinning 脚本 pinning-bypass.js（待动态验证）"); err != nil {
		t.Fatal(err)
	}
	if n := o.specHandoverHintCount(p); n != 1 {
		t.Fatalf("spec 自身交付物不应自匹配：应为 1 条零承接，实际 %d", n)
	}
	// 提示级（log）而非拦截：deterministicGate(s5) 不因该提示产出「承接提示」issue
	for _, iss := range o.deterministicGate(p, "s5") {
		if strings.Contains(iss, "专项移交承接提示") {
			t.Errorf("承接提示应为 log 提示级，不得进拦截 issues: %v", iss)
		}
	}
	streams, cursor, _ := o.store.ListStream(p.ID, 0)
	hint := false
	for _, srec := range streams {
		if strings.Contains(srec.Text, "专项移交承接提示") {
			hint = true
		}
	}
	if !hint {
		t.Fatalf("零承接应输出专项移交承接提示（stream log）")
	}
	// S5 coverage 引用条目正文前缀 → 不再新增提示
	_, _ = o.store.UpsertCoverage(&store.CoverageEntry{ProjectID: p.ID, Stage: "s5",
		Endpoint: "http://a.example.com/app", VulnClass: "动态", Status: "vulnerable",
		Notes: "Frida 反 SSL-Pinning 脚本 pinning-bypass.js 已投递动态验证"})
	_ = o.deterministicGate(p, "s5")
	streams2, _, _ := o.store.ListStream(p.ID, cursor)
	for _, srec := range streams2 {
		if strings.Contains(srec.Text, "专项移交承接提示") {
			t.Errorf("S5 已承接（coverage 引用条目正文）不应再新增提示")
		}
	}
}

// TestV660SpecHandoverS6Visibility v6.6.1 核对轮：spec V3 条目在 S6 上下文独立小节保持在场
//（可见性窗口 S5+S6 贯穿；独立小节不与 S5 行清单 20 条截断竞争）。
func TestV660SpecHandoverS6Visibility(t *testing.T) {
	o, _ := v48Orchestrator(t)
	p := &store.Project{ROEAcknowledgedAt: "2026-11-23T00:00:00Z", ID: "P-V661-S6SPEC",
		Target: "a.example.com"}
	_ = o.store.SaveProject(p)
	p.StageStates = map[string]*store.StageState{
		"specB1": {Status: "done",
			V3Ready: []string{"Frida 反 SSL-Pinning 脚本 pinning-bypass.js"},
			V3L2:    []string{"AP-200 已批 frida 注入动态验证未投递"}},
	}
	_ = o.store.SaveProject(p)
	out := o.buildContextPack(p, "s6")
	for _, want := range []string{
		"**专项就绪移交（v6.6.1 核对轮", "[specB1 就绪未执行] Frida 反 SSL-Pinning 脚本",
		"[specB1 已批未用] AP-200", "s7 V4 比对面逐单核对",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("S6 上下文缺少 %q", want)
		}
	}
	// 无 spec 移交项时不出小节（零占位）
	p2 := &store.Project{ROEAcknowledgedAt: "2026-11-23T00:00:00Z", ID: "P-V661-S6SPEC2",
		Target: "a.example.com"}
	_ = o.store.SaveProject(p2)
	if out2 := o.buildContextPack(p2, "s6"); strings.Contains(out2, "专项就绪移交（v6.6.1 核对轮") {
		t.Errorf("无 spec 移交项不应出 S6 专项小节")
	}
}
