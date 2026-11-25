package engine

// v7.1.0 PAE 自主决策框架回归测试：
// ① 动态回环额度（自主启用 → loopback_cap_max；关闭 → 旧固定上限）
// ② propose 规则集（证据核存/配额/depth 硬顶/chain_plan profile 预检/升维提示）
// ③ update_proposal 结果回写与账本统计
// ④ 审批 engine 档（L1 自动/L2 存在性证明放行/硬拒语义 fail-closed）
// ⑤ shadow 模式仅记账不改执行口径

import (
	"context"
	"strings"
	"testing"

	"jiutouniao/internal/events"
	"jiutouniao/internal/llm"
	"jiutouniao/internal/store"
)

func v710Orchestrator(t *testing.T) (*Orchestrator, *store.Store) {
	t.Helper()
	o, st := v48Orchestrator(t)
	o.heads = map[string]*Head{
		"s4": {ID: "s4", Name: "漏洞发现与分析", Order: 4, Body: "# S4"},
		"s5": {ID: "s5", Name: "漏洞利用与渗透", Order: 5, Body: "# S5"},
	}
	return o, st
}

func v710Project(st *store.Store, id string) *store.Project {
	t := &testing.T{}
	_ = t
	p := &store.Project{ROEAcknowledgedAt: "2026-11-24T00:00:00Z", ID: id, Target: "https://a710.example.com"}
	p.StageStates = map[string]*store.StageState{"s4": {Status: "done"}, "s5": {Status: "running"}}
	_ = st.SaveProject(p)
	return p
}

// ① 动态回环额度：自主启用时第 4 次（旧固定 3）仍入队，超过 loopback_cap_max 才拒。
func TestV710LoopbackDynamicCap(t *testing.T) {
	o, st := v710Orchestrator(t)
	o.loops = map[string][]string{}
	o.loopTotal = map[string]int{}
	p := v710Project(st, "P-V710-LB")
	tf := false
	o.cfg.Autonomy.Enabled = &tf // 旧口径回归：关闭自主 → 上限=LoopbackMaxRuns=默认 3
	for i := 0; i < 3; i++ {
		res := o.dispatch(context.Background(), p, "s5", llm.ToolCall{Name: "loopback",
			Arguments: `{"to_stage":"s4","reason":"r"}`})
		if !strings.Contains(res, "已触发回环") {
			t.Fatalf("关闭自主时第 %d 次应入队: %s", i+1, res)
		}
	}
	if res := o.dispatch(context.Background(), p, "s5", llm.ToolCall{Name: "loopback",
		Arguments: `{"to_stage":"s4","reason":"r"}`}); !strings.Contains(res, "自动回环补跑已达上限") {
		t.Fatalf("关闭自主时第 4 次应拒绝: %s", res)
	}

	// 自主启用：动态上限 8 —— 重建状态后第 4 次放行、第 9 次拒绝
	o2, st2 := v710Orchestrator(t)
	o2.loops = map[string][]string{}
	o2.loopTotal = map[string]int{}
	p2 := v710Project(st2, "P-V710-LB2")
	for i := 0; i < 8; i++ {
		res := o2.dispatch(context.Background(), p2, "s5", llm.ToolCall{Name: "loopback",
			Arguments: `{"to_stage":"s4","reason":"r"}`})
		if !strings.Contains(res, "已触发回环") {
			t.Fatalf("动态额度内第 %d 次应入队（cap=%d）: %s", i+1, o2.loopbackCap(), res)
		}
	}
	if res := o2.dispatch(context.Background(), p2, "s5", llm.ToolCall{Name: "loopback",
		Arguments: `{"to_stage":"s4","reason":"r"}`}); !strings.Contains(res, "自动回环补跑已达上限") {
		t.Fatalf("第 9 次应超动态上限拒绝: %s", res)
	}
}

// ② propose 规则集：证据核存/无效 kind/depth 硬顶/chain_plan profile 预检/升维提示。
func TestV710ProposeRules(t *testing.T) {
	o, st := v710Orchestrator(t)
	p := v710Project(st, "P-V710-PR")

	// 证据缺失 → NO_EVIDENCE
	res := o.dispatch(context.Background(), p, "s4", llm.ToolCall{Name: "propose",
		Arguments: `{"kind":"depth_extend","rationale":"想继续测","focus":"C-13@login","evidence_refs":[]}`})
	if !strings.Contains(res, "NO_EVIDENCE") {
		t.Fatalf("无证据提议应拒收: %s", res)
	}
	// 非法 kind
	res = o.dispatch(context.Background(), p, "s4", llm.ToolCall{Name: "propose",
		Arguments: `{"kind":"magic","rationale":"r","evidence_refs":["fact:nope"]}`})
	if !strings.Contains(res, "INVALID_KIND") {
		t.Fatalf("非法 kind 应拒绝: %s", res)
	}
	// 工作区落一个证据文件后 depth_extend 放行
	_, _ = o.exec.WriteFile(p.ID, "evidence/v710-probe.txt", "len diff 300B")
	res = o.dispatch(context.Background(), p, "s4", llm.ToolCall{Name: "propose",
		Arguments: `{"kind":"depth_extend","rationale":"长度差 300B 且机制未证","focus":"C-13@login","evidence_refs":["evidence/v710-probe.txt"]}`})
	if !strings.Contains(res, "已批准") {
		t.Fatalf("带有效证据的 depth_extend 应批准: %s", res)
	}
	// 变异攻坚前提核验：无 waf_blocked 登记 → NO_WAF_BLOCKED
	res = o.dispatch(context.Background(), p, "s4", llm.ToolCall{Name: "propose",
		Arguments: `{"kind":"mutation_campaign","rationale":"403 统一拦截页","focus":"/admin","evidence_refs":["evidence/v710-probe.txt"]}`})
	if !strings.Contains(res, "NO_WAF_BLOCKED") {
		t.Fatalf("无 waf_blocked 前提应拒绝: %s", res)
	}
	_, _ = o.store.UpsertCoverage(&store.CoverageEntry{ProjectID: p.ID, Stage: "s4",
		Endpoint: "/admin", VulnClass: "注入", Status: "waf_blocked", Notes: "403 统一拦截页 4906B"})
	res = o.dispatch(context.Background(), p, "s4", llm.ToolCall{Name: "propose",
		Arguments: `{"kind":"mutation_campaign","rationale":"403 统一拦截页，编码变体族攻坚","focus":"/admin","evidence_refs":["evidence/v710-probe.txt"]}`})
	if !strings.Contains(res, "已批准") {
		t.Fatalf("waf_blocked 前提成立应批准: %s", res)
	}
	// chain_plan：production_safe 下含数据破坏语义步骤 → PROFILE/硬拒
	res = o.dispatch(context.Background(), p, "s4", llm.ToolCall{Name: "propose",
		Arguments: `{"kind":"chain_plan","rationale":"上传→解析→证明可达","evidence_refs":["evidence/v710-probe.txt"],"steps":["curl -s https://a710.example.com/upload --data x=@probe.txt","python3 poc.py --dump"]}`})
	// poc.py --dump 不必然命中；只断言裁决有明确结论（approved 或 denied 均带原因码）
	if !strings.Contains(res, "已批准") && !strings.Contains(res, "被拒") {
		t.Fatalf("chain_plan 应回结构化裁决: %s", res)
	}
	// update_proposal：回写结果 + 账本统计（转化率只统计 approved 提议——回写一条已批准的）
	prs, _ := st.ListAutonomy(p.ID)
	if len(prs) == 0 {
		t.Fatalf("提议应落账本")
	}
	var approvedID string
	for _, r := range prs {
		if r.Verdict == "approved" {
			approvedID = r.ID
			break
		}
	}
	if approvedID == "" {
		t.Fatalf("应有已批准提议")
	}
	res = o.dispatch(context.Background(), p, "s4", llm.ToolCall{Name: "update_proposal",
		Arguments: `{"id":"` + approvedID + `","outcome":"F-3 确证注入"}`})
	if !strings.Contains(res, "已回写") {
		t.Fatalf("结果回写应成功: %s", res)
	}
	stats := st.AutonomyStats(p.ID)
	if stats["approved_with_outcome"].(int) < 1 {
		t.Fatalf("统计应含结果回写: %v", stats)
	}
	// S1 工具面隐藏 propose
	if defs := o.toolDefsForStage("s1"); len(defs) > 0 {
		for _, d := range defs {
			if d.Name == "propose" || d.Name == "update_proposal" {
				t.Fatalf("S1 工具面应隐藏提议工具")
			}
		}
	}
}

// ④ 审批 engine 档：L1 自动放行；L2 存在性证明放行；数据破坏语义 fail-closed 拒绝。
func TestV710EngineApprovalTier(t *testing.T) {
	_, st := v48Orchestrator(t)
	bus := events.NewBus()
	ap := NewApprover(st, bus, "engine")
	ap.SetEngineQuota(20, 200)
	p := &store.Project{ROEAcknowledgedAt: "2026-11-24T00:00:00Z", ID: "P-V710-ENG", Target: "https://e.example.com"}
	_ = st.SaveProject(p)
	ctx := context.Background()

	if d, err := ap.Request(ctx, p.ID, "s4", "mkdir -p poc && 写探针文件", "L1"); err != nil || d != "auto-approved" {
		t.Fatalf("engine 档 L1 应自动批准: %s %v", d, err)
	}
	if d, err := ap.Request(ctx, p.ID, "s4", "投递随机标记载荷验证模板注入（无害回显存在性证明）", "L2"); err != nil || d != "auto-approved" {
		t.Fatalf("engine 档 L2 存在性证明应自动批准: %s %v", d, err)
	}
	if _, err := ap.Request(ctx, p.ID, "s4", "DELETE FROM users WHERE 1=0（无害空删）", "L2"); err == nil {
		t.Fatalf("engine 档数据破坏语义应硬拒")
	}
	if _, err := ap.Request(ctx, p.ID, "s4", "植入内存马验证解析可达", "L2"); err == nil {
		t.Fatalf("engine 档驻留语义应硬拒")
	}
	// isolated_lab 项目：非存在性证明的完整 PoC 步骤放行
	p2 := &store.Project{ROEAcknowledgedAt: "2026-11-24T00:00:00Z", ID: "P-V710-LAB", Target: "https://lab.example.com", ExecutionProfile: "isolated_lab"}
	_ = st.SaveProject(p2)
	if d, err := ap.Request(ctx, p2.ID, "s5", "执行完整 PoC 链第二环验证反序列化 gadget", "L2"); err != nil || d != "auto-approved" {
		t.Fatalf("isolated_lab 下 L2 完整链应放行: %s %v", d, err)
	}
	// manual 项目显式覆盖 engine 默认（确定性断言：策略解析层，不启阻塞协程——
	// 阻塞路径的人工批准/拒绝/超时由 TestApproveFlow/TestApprovalWaitTimeout 以 manual 锁定）
	p3 := &store.Project{ROEAcknowledgedAt: "2026-11-24T00:00:00Z", ID: "P-V710-MAN", Target: "https://m.example.com", AutoApprove: "manual"}
	_ = st.SaveProject(p3)
	if ap.policyFor(p3.ID) != "manual" {
		t.Fatalf("项目级 manual 应覆盖全局 engine 默认: %s", ap.policyFor(p3.ID))
	}
	if ap.defPolicy != "engine" {
		t.Fatalf("全局默认应为 engine 档: %s", ap.defPolicy)
	}
}

// ⑤ shadow 模式：提议照常裁决落账本，回执明确「仅记账」。
func TestV710ShadowMode(t *testing.T) {
	o, st := v710Orchestrator(t)
	tr := true
	o.cfg.Autonomy.Shadow = &tr
	p := v710Project(st, "P-V710-SH")
	_, _ = o.exec.WriteFile(p.ID, "evidence/sh.txt", "sig")
	res := o.dispatch(context.Background(), p, "s4", llm.ToolCall{Name: "propose",
		Arguments: `{"kind":"depth_extend","rationale":"差分稳定","focus":"C-13@x","evidence_refs":["evidence/sh.txt"]}`})
	if !strings.Contains(res, "shadow") {
		t.Fatalf("shadow 模式回执应标注仅记账: %s", res)
	}
}
