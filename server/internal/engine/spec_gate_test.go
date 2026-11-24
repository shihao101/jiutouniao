package engine

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"jiutouniao/internal/config"
	"jiutouniao/internal/events"
	"jiutouniao/internal/store"
)

// newSpecGateFixture SP-② 测试夹具：空项目 + 引擎（guard 默认全 true）。
func newSpecGateFixture(t *testing.T) (*Orchestrator, *store.Store) {
	t.Helper()
	dir := t.TempDir()
	st, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	o := &Orchestrator{store: st, exec: newTestExec(t, dir), bus: events.NewBus(),
		cfg: &config.Config{Engine: config.EngineConfig{PerTargetRounds: 10}}}
	return o, st
}

// TestSpecClosureIssues_BlocksIncomplete v6.6.0 SP-②：有适用资产但缺前置契约登记/核心交付物/
// 条目清单 → 三类拦截项齐出（文案含确切缺失项）。
func TestSpecClosureIssues_BlocksIncomplete(t *testing.T) {
	o, st := newSpecGateFixture(t)
	p := &store.Project{ROEAcknowledgedAt: "2026-11-23T00:00:00Z", ID: "P-SP2-A", Name: "AI目标",
		Target: "https://chat.example.com"}
	_ = st.SaveProject(p)
	_, _ = st.AddAsset(&store.Asset{ProjectID: p.ID, Type: "AI应用", Value: "chat.example.com", ScopeStatus: "in_scope", ScopeEvidence: "授权清单"})

	issues := o.specClosureIssues(p, "specA")
	joined := strings.Join(issues, "\n")
	if len(issues) < 3 {
		t.Fatalf("缺契约+缺交付物+缺条目清单应至少 3 项拦截: %v", issues)
	}
	if !strings.Contains(joined, "前置契约未登记") || !strings.Contains(joined, "Canary") {
		t.Errorf("应拦前置契约（specA=Canary/合成标记方案）: %v", issues)
	}
	if !strings.Contains(joined, "缺少核心交付物") || !strings.Contains(joined, "AI 系统架构图") {
		t.Errorf("应拦核心交付物缺失: %v", issues)
	}
	if !strings.Contains(joined, "专项条目清单") {
		t.Errorf("应拦条目三态清单缺失: %v", issues)
	}
}

// TestSpecClosureIssues_PassesComplete v6.6.0 SP-②：契约留痕+核心交付物+条目清单齐 → 零拦截。
func TestSpecClosureIssues_PassesComplete(t *testing.T) {
	o, st := newSpecGateFixture(t)
	p := &store.Project{ROEAcknowledgedAt: "2026-11-23T00:00:00Z", ID: "P-SP2-B", Name: "AI目标",
		Target: "https://chat.example.com"}
	_ = st.SaveProject(p)
	_, _ = st.AddAsset(&store.Asset{ProjectID: p.ID, Type: "AI应用", Value: "chat.example.com", ScopeStatus: "in_scope", ScopeEvidence: "授权清单"})
	_, _ = st.AddTimeline(&store.TimelineEvent{ProjectID: p.ID, Stage: "specA",
		Event: "前置契约登记：Canary 合成标记数据方案就绪（合成 RAG 文档 + mock 工具）", Detail: "隔离测试租户"})
	if _, err := o.exec.WriteFile(p.ID, "deliverables/specA-AI系统架构图.md",
		"# AI 系统架构图\n\n## 专项条目清单\n- A1 已测（update_coverage 引用）\n- A2 不适用（无 RAG 面）\n- A3 未测（预算移交）"); err != nil {
		t.Fatal(err)
	}
	if issues := o.specClosureIssues(p, "specA"); len(issues) != 0 {
		t.Errorf("三件齐备应零拦截: %v", issues)
	}
}

// TestSpecClosureIssues_ExemptNoAssets v6.6.0 SP-②：无适用资产 → 豁免（零拦截），提示级留痕。
func TestSpecClosureIssues_ExemptNoAssets(t *testing.T) {
	o, st := newSpecGateFixture(t)
	p := &store.Project{ROEAcknowledgedAt: "2026-11-23T00:00:00Z", ID: "P-SP2-C", Name: "纯Web目标",
		Target: "https://web.example.com"}
	_ = st.SaveProject(p)
	_, _ = st.AddAsset(&store.Asset{ProjectID: p.ID, Type: "域名", Value: "web.example.com", ScopeStatus: "in_scope", ScopeEvidence: "授权清单"})
	if issues := o.specClosureIssues(p, "specA"); len(issues) != 0 {
		t.Errorf("无 AI 类资产应豁免（前提不成立路径）: %v", issues)
	}
	if issues := o.specClosureIssues(p, "specB1"); len(issues) != 0 {
		t.Errorf("无 APP 类资产应豁免: %v", issues)
	}
}

// TestSpecClosureIssues_B1B2Contracts v6.6.0 SP-②：B1 三要素/B2 两要素逐项拦截文案。
func TestSpecClosureIssues_B1B2Contracts(t *testing.T) {
	o, st := newSpecGateFixture(t)
	p := &store.Project{ROEAcknowledgedAt: "2026-11-23T00:00:00Z", ID: "P-SP2-D", Name: "APP目标",
		Target: "app.example.com"}
	_ = st.SaveProject(p)
	_, _ = st.AddAsset(&store.Asset{ProjectID: p.ID, Type: "APP", Value: "com.example.app", ScopeStatus: "in_scope", ScopeEvidence: "授权清单"})

	issues := o.specClosureIssues(p, "specB1")
	joined := strings.Join(issues, "\n")
	for _, want := range []string{"测试包来源", "设备登记", "测试账号"} {
		if !strings.Contains(joined, want) {
			t.Errorf("B1 前置契约应逐项拦 %s: %v", want, issues)
		}
	}

	// 补齐 B1 契约+交付物+清单 → 只剩零拦截
	_, _ = st.AddTimeline(&store.TimelineEvent{ProjectID: p.ID, Stage: "specB1",
		Event: "前置契约登记：测试包来源=客户提供；设备登记=测试设备已root；测试账号已开通", Detail: ""})
	if _, err := o.exec.WriteFile(p.ID, "deliverables/specB1-假设队列.md",
		"# 假设队列\n\n## 专项条目清单\n- 静态链S1 已测\n- D1 未测（设备移交）"); err != nil {
		t.Fatal(err)
	}
	if issues := o.specClosureIssues(p, "specB1"); len(issues) != 0 {
		t.Errorf("B1 三件齐备应零拦截: %v", issues)
	}
}

// TestSpecClosureGateInDeterministicGate v6.6.0 SP-②：deterministicGate(specX) 走同一门
//（反思 PASS/三振降级/auto_close 三路径共用）。
func TestSpecClosureGateInDeterministicGate(t *testing.T) {
	o, st := newSpecGateFixture(t)
	p := &store.Project{ROEAcknowledgedAt: "2026-11-23T00:00:00Z", ID: "P-SP2-E", Name: "小程序",
		Target: "wx-example"}
	_ = st.SaveProject(p)
	_, _ = st.AddAsset(&store.Asset{ProjectID: p.ID, Type: "小程序", Value: "wx-example", ScopeStatus: "in_scope", ScopeEvidence: "授权清单"})
	hit := false
	for _, iss := range o.deterministicGate(p, "specB2") {
		if strings.Contains(iss, "前置契约未登记") {
			hit = true
		}
	}
	if !hit {
		t.Errorf("deterministicGate(specB2) 应包含收口门拦截项")
	}
}

// TestSpecStageInReflectPassGateList v6.6.0 SP-②：反思 PASS 无条件硬校验名单含三专项
//（源码级断言——名单表达式含 isSpecStage；v6.7.0 S6-① 名单扩含 s6，断言同步）。
func TestSpecStageInReflectPassGateList(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "server/internal/engine/orchestrator.go"))
	if err != nil {
		t.Skipf("仓库文件不可达（非源码树运行）: %v", err)
	}
	if !strings.Contains(string(raw), `|| stageID == "s2" || stageID == "s6" || isSpecStage(stageID) {`) {
		t.Error("反思 PASS 无条件确定性门名单应含 s6 与 isSpecStage(stageID)")
	}
}

// TestSpecB1ApplicabilityAndroidTypes v6.6.0 第四遍（回放 某历史任务 实证驱动）：
// 「Android应用/Android APK/iOS」等非标准类型不得被 specB1 豁免误判（回放发现：即刻 APP
// 项目资产全为域名/IP——真实 APP 项目若类型命名非「APP」将漏拦）。
func TestSpecB1ApplicabilityAndroidTypes(t *testing.T) {
	o, st := newSpecGateFixture(t)
	p := &store.Project{ROEAcknowledgedAt: "2026-11-23T00:00:00Z", ID: "P-SP2-F", Name: "APP",
		Target: "app-a.test"}
	_ = st.SaveProject(p)
	for _, typ := range []string{"Android应用", "Android APK", "iOS IPA", "移动应用", "APP"} {
		_, _ = st.AddAsset(&store.Asset{ProjectID: p.ID, Type: typ, Value: "com.a", ScopeStatus: "in_scope", ScopeEvidence: "授权清单"})
	}
	if issues := o.specClosureIssues(p, "specB1"); len(issues) == 0 {
		t.Error("移动生态类型资产应使 specB1 适用（不得豁免）")
	}
}
