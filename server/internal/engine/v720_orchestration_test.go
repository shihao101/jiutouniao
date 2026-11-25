package engine

// v7.2.0 编排权批次回归：B1 作战参谋协议解析/无 LLM fail-open / B3 planDelta / B4 预算账本

import (
	"context"
	"strings"
	"testing"

	"jiutouniao/internal/llm"
	"jiutouniao/internal/store"
)

// B1：宽容 JSON 解析——噪声文本中提取数组、非法 type 过滤、超 3 条截断、空数组返回空。
func TestV720BrainParser(t *testing.T) {
	in := `评审完成。建议如下：
[{"type":"loopback_focus","rationale":"新面 9029 未测","evidence":"evidence/probe.txt","focus":"C-13@n","target_stage":"s4"},
 {"type":"magic_power","rationale":"越权建议（应被过滤）","evidence":"x"},
 {"type":"budget_transfer","rationale":"S8 有 P0 空洞","evidence":"fact:surface.a"},
 {"type":"replan_delta","rationale":"通道批复新 live","evidence":"evidence/live.txt"},
 {"type":"budget_transfer","rationale":"第四条应被截断","evidence":"y"}]`
	out := parseBrainSuggestions(in)
	if len(out) != 3 {
		t.Fatalf("应过滤非法 type 并截断至 3 条: %d", len(out))
	}
	if out[0].Type != "loopback_focus" || out[1].Type != "budget_transfer" || out[2].Type != "replan_delta" {
		t.Fatalf("保留顺序与白名单不符: %+v", out)
	}
	if out := parseBrainSuggestions("无建议。[]"); len(out) != 0 {
		t.Fatalf("空数组应返回空: %v", out)
	}
	if out := parseBrainSuggestions("没有任何数组"); len(out) != 0 {
		t.Fatalf("无数组应返回空: %v", out)
	}
}

// B1：无 LLM 装配（测试环境）fail-open 跳过，不 panic 不阻塞。
func TestV720BrainSkipsWithoutLLM(t *testing.T) {
	o, st := v48Orchestrator(t)
	p := v710Project(st, "P-V720-B1")
	o.campaignBrainReview(context.Background(), p, "s4") // cli==nil → 直接返回
	recs, _ := st.ListAutonomy(p.ID)
	if len(recs) != 0 {
		t.Fatalf("无 LLM 时不应产生提案")
	}
}

// B3：测试中新 in_scope 资产 → 自动建卡（C-00/queued/plan_delta）+ PlanVersion Bump；幂等；S1 不触发。
func TestV720PlanDelta(t *testing.T) {
	o, st := v48Orchestrator(t)
	o.heads = map[string]*Head{"s1": {ID: "s1", Order: 1}, "s4": {ID: "s4", Order: 4}, "s5": {ID: "s5", Order: 5}}
	p := v710Project(st, "P-V720-PD")
	p.StageStates["s4"] = &store.StageState{Status: "running"}
	_ = st.SaveProject(p)
	// s1 登记不触发
	o.dispatch(context.Background(), p, "s1", llm.ToolCall{Name: "record_asset",
		Arguments: `{"type":"域名","value":"s1.example.com","scope_status":"in_scope","scope_evidence":"授权清单"}`})
	if st.CardStats(p.ID)["total"] != 0 {
		t.Fatalf("S1 初始界定不应触发 planDelta")
	}
	// s5 测试中新登记 → 建卡 + Bump
	o.dispatch(context.Background(), p, "s5", llm.ToolCall{Name: "record_asset",
		Arguments: `{"type":"域名","value":"new.example.com","scope_status":"in_scope","scope_evidence":"扩展工单 AP-1"}`})
	cs := st.CardStats(p.ID)
	if cs["total"] != 1 || cs["queued_vt"] != 1 {
		t.Fatalf("planDelta 应建 queued 卡: %v", cs)
	}
	if p.StageStates["s4"].PlanVersion != 1 {
		t.Fatalf("计划版本应 Bump 至 1: %d", p.StageStates["s4"].PlanVersion)
	}
	// 同资产再登记幂等；另一资产 via update_asset 流转
	o.dispatch(context.Background(), p, "s5", llm.ToolCall{Name: "record_asset",
		Arguments: `{"type":"域名","value":"new.example.com","scope_status":"in_scope","scope_evidence":"扩展工单 AP-1"}`})
	a, _ := st.AddAsset(&store.Asset{ProjectID: p.ID, Stage: "s2", Type: "IP", Value: "10.0.0.9", ScopeStatus: "shadow_pending"})
	o.dispatch(context.Background(), p, "s5", llm.ToolCall{Name: "update_asset",
		Arguments: `{"asset_id":"` + a + `","scope_status":"in_scope","scope_evidence":"授权书补充条款","reason":"客户书面确认"}`})
	cs = st.CardStats(p.ID)
	if cs["total"] != 2 {
		t.Fatalf("同资产应幂等、新资产应建卡: %v", cs)
	}
	if p.StageStates["s4"].PlanVersion != 2 {
		t.Fatalf("第二次 planDelta 应 Bump 至 2: %d", p.StageStates["s4"].PlanVersion)
	}
}

// B4：预算账本一行式——目标数/类直方图/深化单元 Top。
func TestV720BudgetLedger(t *testing.T) {
	cov := []*store.CoverageEntry{
		{Endpoint: "/a（t1.example.com）", VulnClass: "SQL注入", Count: 6, Status: "vulnerable"},
		{Endpoint: "/b（t1.example.com）", VulnClass: "XSS", Count: 1, Status: "no_issue_found"},
		{Endpoint: "/c（t2.example.com）", VulnClass: "SQL注入", Count: 2, Status: "needs_follow_up"},
	}
	line := budgetLedgerLine(cov)
	for _, want := range []string{"覆盖单元 3", "目标 2", "深化单元 Top", "/a（t1.example.com） | SQL注入 ×6"} {
		if !strings.Contains(line, want) {
			t.Fatalf("预算账本缺要素 %q: %s", want, line)
		}
	}
	if budgetLedgerLine(nil) != "" {
		t.Fatalf("空覆盖应返回空")
	}
}

// 审计 P-1（第八轮）：planDelta 注入移出覆盖守卫——零覆盖单元时 S4 上下文仍含新面承接卡。
func TestV720PlanDeltaVisibleWithoutCoverage(t *testing.T) {
	o, st := v48Orchestrator(t)
	o.heads = map[string]*Head{"s4": {ID: "s4", Order: 4}, "s5": {ID: "s5", Order: 5}}
	p := v710Project(st, "P-V720-PDV")
	p.StageStates["s4"] = &store.StageState{Status: "running"}
	_ = st.SaveProject(p)
	o.dispatch(context.Background(), p, "s5", llm.ToolCall{Name: "record_asset",
		Arguments: `{"type":"域名","value":"late.example.com","scope_status":"in_scope","scope_evidence":"扩展工单"}`})
	ctxPack := o.buildContextPack(p, "s4")
	if !strings.Contains(ctxPack, "planDelta 新面承接") || !strings.Contains(ctxPack, "late.example.com") {
		t.Fatalf("零覆盖时 planDelta 卡应对模型可见")
	}
}
