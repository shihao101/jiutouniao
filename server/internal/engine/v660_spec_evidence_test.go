package engine

import (
	"strings"
	"testing"

	"jiutouniao/internal/config"
	"jiutouniao/internal/events"
	"jiutouniao/internal/store"
)

// TestSpecEvidenceCriteriaDowngrade v6.6.0 SP-⑥：specA 阶段高危确证未引 evidence-standard
// 判据 → deterministicGate(specA) 内被机械降级为疑似并留痕（与 s4/s5 同口径——工具描述承诺
// 的执行面扩齐）。
func TestSpecEvidenceCriteriaDowngrade(t *testing.T) {
	dir := t.TempDir()
	st, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	o := &Orchestrator{store: st, exec: newTestExec(t, dir), bus: events.NewBus(),
		cfg: &config.Config{Engine: config.EngineConfig{PerTargetRounds: 10}}}
	p := &store.Project{ROEAcknowledgedAt: "2026-11-23T00:00:00Z", ID: "P-SP6", Name: "AI",
		Target: "chat.test", Specializations: []string{"A"}}
	_ = st.SaveProject(p)
	if _, err := st.AddFinding(&store.Finding{ProjectID: p.ID, Stage: "specA",
		Title: "提示注入可驱动越权工具调用", Severity: "高", Confidence: "确证",
		Detail: "间接注入成功后模型调用了邮件工具（未对照标准证据）"}); err != nil {
		t.Fatal(err)
	}

	hit := false
	for _, iss := range o.deterministicGate(p, "specA") {
		if strings.Contains(iss, "未引用 evidence-standard 判据，已自动降级为疑似") {
			hit = true
		}
	}
	if !hit {
		t.Error("specA 高危确证未引判据应被降级（SP-⑥ 扩名单）")
	}
	got, _ := st.ListFindings(p.ID)
	for _, f := range got {
		if f.Title == "提示注入可驱动越权工具调用" && f.Confidence != "疑似" {
			t.Errorf("降级未落库: confidence=%s", f.Confidence)
		}
		if f.Title == "提示注入可驱动越权工具调用" && !strings.Contains(f.Detail, "【引擎降级 v4.4】") {
			t.Error("降级留痕缺失")
		}
	}

	// 引用判据项后不降级：update_finding 回写 detail 引判据 → 再跑门无降级 issue
	for _, f := range got {
		if f.Title == "提示注入可驱动越权工具调用" {
			f.Confidence = "确证"
			f.Detail = "间接注入成功后模型调用了邮件工具。evidence-standard 判据：注入=可复现行为变化≥2轮（判据项 A-注入-2，对照实验见 evidence/a4-pair.txt）"
			_ = st.UpdateFinding(f)
		}
	}
	for _, iss := range o.deterministicGate(p, "specA") {
		if strings.Contains(iss, "未引用 evidence-standard 判据，已自动降级为疑似") {
			t.Errorf("引用判据后不应再降级: %v", iss)
		}
	}
}
