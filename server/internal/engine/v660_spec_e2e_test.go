package engine

// v6.6.0 端到端补验（v620_e2e 同款口径——deterministicGate 直测之外的第三层验证）：
// complete_stage(specB1/specA) 经真实 dispatch 链路——V3 双清单拦截 → 专项确定性门拦截
//（契约/交付物/条目清单）→ 全齐放行（stub 反思门 PASS）→ StageState V3 落库 → S5 上下文承接；
// 豁免路径（无适用资产）全链放行。用例顺序即拦截链顺序，任一层缺失都能被本文件定位。

import (
	"context"
	"strings"
	"testing"

	"jiutouniao/internal/llm"
	"jiutouniao/internal/store"
)

func v660SpecProject(t *testing.T, o *Orchestrator, id, target, spec string) *store.Project {
	t.Helper()
	p := &store.Project{ID: id, Name: "v660端到端", Target: target,
		Authorized: true, ROEAcknowledgedAt: "2026-11-23T00:00:00Z",
		Specializations: []string{spec},
		StageStates:     map[string]*store.StageState{spec: {Status: "running", StartedAt: "2026-11-23T00:00:00Z"}}}
	_ = o.store.SaveProject(p)
	return p
}

// TestV660E2ESpecV3GateDispatch 真实链路第 1 层：specB1 收口缺 V3 双清单 → V3 拦截
// （与 s4/s5 同款文案，V3 门位于专项确定性门之前）。
func TestV660E2ESpecV3GateDispatch(t *testing.T) {
	o, _ := v48Orchestrator(t)
	p := v660SpecProject(t, o, "P-V660-E1", "app-a.test", "specB1")
	_, _ = o.store.AddAsset(&store.Asset{ProjectID: p.ID, Stage: "s1", Type: "APP",
		Value: "com.example.app", ScopeStatus: "in_scope", ScopeEvidence: "授权清单"})
	resp := o.dispatch(context.Background(), p, "specB1", llm.ToolCall{Name: "complete_stage", Arguments: `{"summary":"B1 静态链完成"}`})
	if !strings.Contains(resp, "收口被拦截（v4.6 V3）") {
		t.Fatalf("specB1 收口缺 V3 双清单应被真实链路拦截: %s", resp)
	}
}

// TestV660E2ESpecClosureGateDispatch 真实链路第 2 层：V3 显式空数组提交后 → 专项确定性门拦截，
// 文案列出确切缺失项（前置契约/核心交付物/条目清单）。
func TestV660E2ESpecClosureGateDispatch(t *testing.T) {
	o, _ := v48Orchestrator(t)
	p := v660SpecProject(t, o, "P-V660-E2", "app-a.test", "specB1")
	_, _ = o.store.AddAsset(&store.Asset{ProjectID: p.ID, Stage: "s1", Type: "APP",
		Value: "com.example.app", ScopeStatus: "in_scope", ScopeEvidence: "授权清单"})
	args := `{"summary":"B1 静态链完成","ready_but_unexecuted":[],"l2_approved_unused":[]}`
	resp := o.dispatch(context.Background(), p, "specB1", llm.ToolCall{Name: "complete_stage", Arguments: args})
	for _, want := range []string{"前置契约未登记", "缺少核心交付物", "专项条目清单"} {
		if !strings.Contains(resp, want) {
			t.Fatalf("专项确定性门拦截文案缺 %q: %s", want, resp)
		}
	}
}

// TestV660E2ESpecFullClosure 真实链路第 3 层：契约登记+核心交付物+条目清单+V3 就绪项 →
// stub 反思门 PASS → 确定性门通过 → 阶段收口；StageState.V3Ready 落库；S5 上下文出现
// 「专项就绪移交」小节（SP-③ 端到端闭环）。
func TestV660E2ESpecFullClosure(t *testing.T) {
	o, st := v48Orchestrator(t)
	o.llm = passThroughClient{}
	p := v660SpecProject(t, o, "P-V660-E3", "app-a.test", "specB1")
	_, _ = o.store.AddAsset(&store.Asset{ProjectID: p.ID, Stage: "s1", Type: "APP",
		Value: "com.example.app", ScopeStatus: "in_scope", ScopeEvidence: "授权清单"})
	_, _ = o.store.AddTimeline(&store.TimelineEvent{ProjectID: p.ID, Stage: "specB1",
		Event: "前置契约登记：测试包来源=客户提供；设备登记=测试设备已root；测试账号已开通", Detail: ""})
	if _, err := o.exec.WriteFile(p.ID, "deliverables/specB1-假设队列.md",
		"# 假设队列\n\n## 专项条目清单\n- 静态链S1 已测（update_coverage 引用）\n- D1 未测（设备移交）"); err != nil {
		t.Fatal(err)
	}
	args := `{"summary":"B1 静态链完成","ready_but_unexecuted":["Frida hook 脚本 evidence/frida.js（启动条件：root 设备）"],"l2_approved_unused":[]}`
	resp := o.dispatch(context.Background(), p, "specB1", llm.ToolCall{Name: "complete_stage", Arguments: args})
	if !strings.HasPrefix(resp, "阶段已收口") {
		t.Fatalf("全齐应放行收口: %s", resp)
	}
	got, _ := st.GetProject(p.ID)
	if stB1 := got.StageStates["specB1"]; stB1 == nil || len(stB1.V3Ready) != 1 ||
		!strings.Contains(stB1.V3Ready[0], "Frida hook 脚本") {
		t.Fatalf("specB1 V3 未结构化落库: %+v", got.StageStates["specB1"])
	}
	// S5 上下文承接（SP-③ 下游消费端到端）
	out := o.buildContextPack(got, "s5")
	if !strings.Contains(out, "专项就绪移交") || !strings.Contains(out, "[specB1 就绪未执行]") {
		t.Error("S5 上下文应承接专项就绪移交小节")
	}
}

// TestV660E2ESpecExemptClosure 真实链路豁免路径：无 APP 类资产（仅域名）→ 专项确定性门豁免，
// 豁免交付物落盘后收口放行（前提不成立早退闭环，SP-②/SP-⑩ 联动）。
func TestV660E2ESpecExemptClosure(t *testing.T) {
	o, _ := v48Orchestrator(t)
	o.llm = passThroughClient{}
	p := v660SpecProject(t, o, "P-V660-E4", "web-a.test", "specB1")
	_, _ = o.store.AddAsset(&store.Asset{ProjectID: p.ID, Stage: "s1", Type: "域名",
		Value: "web-a.test", ScopeStatus: "in_scope", ScopeEvidence: "授权清单"})
	if _, err := o.exec.WriteFile(p.ID, "deliverables/specB1-豁免说明.md",
		"# 前提不成立说明\n\n资产台账无 APP 类资产（核验记录），本专项按豁免路径如实收口，禁止虚构测试。"); err != nil {
		t.Fatal(err)
	}
	args := `{"summary":"B1 前提不成立豁免收口","ready_but_unexecuted":[],"l2_approved_unused":[]}`
	resp := o.dispatch(context.Background(), p, "specB1", llm.ToolCall{Name: "complete_stage", Arguments: args})
	if !strings.HasPrefix(resp, "阶段已收口") {
		t.Fatalf("豁免路径应放行收口: %s", resp)
	}
}

// TestSpecGuardsExplicitFalseFallback v6.6.0 实施原则①（guard 三态开关）：显式 false 显式回退
// ——enforce_spec_closure/enforce_spec_target_recon 显式 false 时门整体跳过（缺省 true 不受影响）。
func TestSpecGuardsExplicitFalseFallback(t *testing.T) {
	o, st := v48Orchestrator(t)
	o.cfg.Guard.EnforceSpecClosure = boolPtr(false)
	o.cfg.Guard.EnforceSpecTargetRecon = boolPtr(false)
	p := &store.Project{ROEAcknowledgedAt: "2026-11-23T00:00:00Z", ID: "P-SP9", Name: "APP",
		Target: "app-a.test\napp-b.test", Specializations: []string{"B1"}}
	_ = st.SaveProject(p)
	_, _ = st.AddAsset(&store.Asset{ProjectID: p.ID, Type: "APP", Value: "com.a", ScopeStatus: "in_scope", ScopeEvidence: "授权清单"})
	// 缺契约+缺交付物+多目标缺 coverage——两门显式 false 时均不产生拦截项
	if issues := o.deterministicGate(p, "specB1"); len(issues) != 0 {
		t.Errorf("guard 显式 false 应整体回退，issues=%v", issues)
	}
	// 恢复缺省 true 后同项目被拦（对照证明开关真实生效）
	o2, st2 := v48Orchestrator(t)
	p2 := &store.Project{ROEAcknowledgedAt: "2026-11-23T00:00:00Z", ID: "P-SP9b", Name: "APP",
		Target: "app-a.test", Specializations: []string{"B1"}}
	_ = st2.SaveProject(p2)
	_, _ = st2.AddAsset(&store.Asset{ProjectID: p2.ID, Type: "APP", Value: "com.a", ScopeStatus: "in_scope", ScopeEvidence: "授权清单"})
	if issues := o2.deterministicGate(p2, "specB1"); len(issues) == 0 {
		t.Error("缺省 true 应产生专项确定性门拦截项（对照）")
	}
}

// scriptedClient 第五遍：按脚本逐轮返回工具调用；脚本耗尽后恒回 PASS（驱动反思门放行）。
type scriptedClient struct {
	calls []llm.ToolCall
	i     int
}

func (c *scriptedClient) Chat(_ context.Context, _ string, _ []llm.Message, _ []llm.ToolDef, _ float32, _ int) (llm.Message, llm.Usage, error) {
	if c.i >= len(c.calls) {
		return llm.Message{Role: "assistant", Content: "PASS"}, llm.Usage{}, nil
	}
	tc := c.calls[c.i]
	c.i++
	return llm.Message{Role: "assistant", ToolCalls: []llm.ToolCall{tc}}, llm.Usage{}, nil
}

// TestV660E2ESpecRunStageFullLoop 第五遍：specB1 走完整 runStage 执行循环——脚本化 LLM 依次
// 登记前置契约（record_timeline）→ 写核心交付物+条目清单（write_file）→ complete_stage 携带
// V3 空数组——穿越 V3 门/专项确定性门/fresh-file/反思门（stub PASS）/deterministicGate 无条件
// 名单/冲刺消息（剩 1/3 注入含三专项文案）全链，阶段真实收口。
func TestV660E2ESpecRunStageFullLoop(t *testing.T) {
	o, st := v48Orchestrator(t)
	o.llm = &scriptedClient{calls: []llm.ToolCall{
		{Name: "record_timeline", Arguments: `{"event":"前置契约登记：测试包来源=客户提供合法测试包；设备登记=测试设备已root+frida-server；测试账号已开通","detail":"第五遍 runStage 全链验证"}`},
		{Name: "write_file", Arguments: `{"path":"deliverables/specB1-假设队列.md","content":"# 假设队列（runStage 全链验证） ## 专项条目清单 静态链S1 已测（update_coverage 引用） D1 未测（设备移交）"}`},
		{Name: "complete_stage", Arguments: `{"summary":"B1 静态链完成（runStage 全链）","deliverables":["deliverables/specB1-假设队列.md"],"ready_but_unexecuted":[],"l2_approved_unused":[]}`},
	}}
	o.inputs = map[string][]string{}
	o.heads = map[string]*Head{"specB1": {ID: "specB1", Name: "专项B1", Kind: "spec", Stage: "B1", Body: "# 专项B1（runStage 全链验证）"}}
	p := &store.Project{ROEAcknowledgedAt: "2026-11-23T00:00:00Z", ID: "P-V660-R5", Name: "APP全链",
		Target: "app-a.test", Specializations: []string{"B1"},
		StageStates: map[string]*store.StageState{"specB1": {Status: "running", StartedAt: "2026-11-23T00:00:00Z"}}}
	_ = st.SaveProject(p)

	if err := o.runStage(context.Background(), p, "specB1"); err != nil {
		t.Fatalf("runStage 不应报错: %v", err)
	}
	got, _ := st.GetProject(p.ID)
	stB1 := got.StageStates["specB1"]
	if stB1 == nil || stB1.Status != "done" {
		t.Fatalf("specB1 应真实收口 done: %+v", stB1)
	}
	if !strings.Contains(stB1.Summary, "runStage 全链") {
		t.Errorf("收口摘要应持久化: %s", stB1.Summary)
	}
	if len(stB1.V3Ready) != 0 || len(stB1.V3L2) != 0 {
		t.Errorf("V3 空数组应落库为空: %+v", stB1)
	}
	// 交付物与契约留痕可被后续阶段消费
	if files, _ := o.listWorkspaceFiles(p.ID, ""); len(files) == 0 {
		t.Error("工作区应有 specB1 交付物")
	}
}
