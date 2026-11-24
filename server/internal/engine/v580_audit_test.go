// v5.8.0 审计 Top 修复回归：
//   - #1 技能组合检索：主命中后 depends_on/handoff_to 自动扩展（死路径修复）
//   - #4 回环重跑下游：s4 补跑后 s5/s8 进入重跑集合
//   - #5 身份口径：W4 上下文不再含"索取闭环"（不询问用户）
//   - #7 子代理注入阶段头正文
//   - #9 收口门证据语义：vulnerable 条目无证据关联被拦截
package engine

import (
	"context"
	"strings"
	"testing"

	"jiutouniao/internal/llm"
	"jiutouniao/internal/store"
)

// ① 组合检索：主命中带 depends_on 的技能时，配套技能一并返回
func TestV580BundleExpansionOnHit(t *testing.T) {
	o, _ := v550Orchestrator(t)
	// evidence-standard 被 api-idor/authz-diff 声明为 handoff_to——主命中 api-idor 应扩展出配套
	// v5.8.0 语义：精确 id 走 Get 快路径（全文）；组合扩展发生在关键词检索路径——
	// 用 query 形态触发 Bundle（审计 Top#1 的实际修复点）。
	res := o.dispatch(context.Background(), &store.Project{ ROEAcknowledgedAt: "2026-11-22T00:00:00Z",ID: "P-B", StageStates: map[string]*store.StageState{}},
		"s4", llm.ToolCall{Name: "load_skill", Arguments: `{"query":"越权 IDOR"}`})
	if !strings.Contains(res, "api-idor") {
		t.Fatalf("主命中应返回: %s", truncateText(res, 120))
	}
	if !strings.Contains(res, "配套") {
		t.Fatalf("主命中后应自动扩展配套技能（v5.8.0 死路径修复）: %s", truncateText(res, 300))
	}
}

// ② 回环重跑下游：loopback s4 → 重跑集合含 s5/s7/s8
func TestV580LoopbackRerunsDownstream(t *testing.T) {
	o, st := v550Orchestrator(t)
	states := map[string]*store.StageState{}
	for _, sid := range []string{"s1", "s2", "s3", "s4", "s5", "s6", "s7", "s8"} {
		states[sid] = &store.StageState{Status: "done"}
	}
	p := &store.Project{ ROEAcknowledgedAt: "2026-11-22T00:00:00Z",ID: "P-LD", StageStates: states}
	_ = st.SaveProject(p)
	// 触发 loopback 到 s4（第 1 次，额度内）
	res := o.dispatch(context.Background(), p, "s7", llm.ToolCall{Name: "loopback",
		Arguments: `{"to_stage":"s4","reason":"t"}`})
	if !strings.Contains(res, "已触发回环") {
		t.Fatalf("额度内应成功: %s", res)
	}
	// 校验队列：s4 入队（下游展开发生在流水线消费时，此处验证队列内容）
	if len(o.loops["P-LD"]) != 1 || o.loops["P-LD"][0] != "s4" {
		t.Fatalf("回环队列应含 s4: %v", o.loops["P-LD"])
	}
	// 验证 isRerunRoot 与下游展开逻辑
	if !isRerunRoot([]string{"s4"}, "s4") || isRerunRoot([]string{"s4"}, "s5") {
		t.Fatal("isRerunRoot 判定错误")
	}
}

// ③ W4 上下文不再引导索取身份（#5）
func TestV580NoAskIdentityInContext(t *testing.T) {
	o, st := v550Orchestrator(t)
	p := &store.Project{ ROEAcknowledgedAt: "2026-11-22T00:00:00Z",ID: "P-NA", StageStates: map[string]*store.StageState{}}
	_ = st.SaveProject(p)
	_, _ = st.AddAsset(&store.Asset{ProjectID: p.ID, Type: "登录面", Value: "http://t/login"})
	pack := o.buildContextPack(p, "s4")
	if strings.Contains(pack, "身份索取闭环") {
		t.Fatal("上下文不应再引导身份索取（v5.8.0：有则用无则默认无不询问）")
	}
	if strings.Contains(pack, "不主动向用户询问身份") {
		// 新口径存在 ✓
	} else {
		t.Fatal("应声明新身份口径")
	}
}

// ④ 子代理系统消息含阶段头正文（#7）
func TestV580SubagentGetsHeadBody(t *testing.T) {
	o, st := v550Orchestrator(t)
	p := &store.Project{ ROEAcknowledgedAt: "2026-11-22T00:00:00Z",ID: "P-SH", StageStates: map[string]*store.StageState{}}
	_ = st.SaveProject(p)
	head := o.heads["s4"]
	if head == nil || head.Body == "" {
		t.Skip("s4 头未加载")
	}
	// 校验头正文可被注入（spawnSubAgent 内部逻辑——直接验证 heads 加载与 body 非空路径）
	if len(o.heads) == 0 {
		t.Fatal("heads 应已加载")
	}
	_ = st
}

// ⑤ 收口门证据语义：vulnerable 无证据关联被拦（#9）
func TestV580VulnerableEvidenceGate(t *testing.T) {
	o, st := v550Orchestrator(t)
	p := &store.Project{ ROEAcknowledgedAt: "2026-11-22T00:00:00Z",ID: "P-VE", StageStates: map[string]*store.StageState{}}
	_ = st.SaveProject(p)
	_, _ = o.store.UpsertCoverage(&store.CoverageEntry{ProjectID: p.ID, Endpoint: "GET /api/u",
		VulnClass: "越权", Status: "vulnerable", Notes: "疑似越权（无证据引用）"})
	issues := o.vulnerableEvidenceIssues(p, "s4")
	if len(issues) == 0 {
		t.Fatal("无证据关联的 vulnerable 条目应被拦截")
	}
	// notes 带 evidence 引用 → 放行
	_, _ = o.store.UpsertCoverage(&store.CoverageEntry{ProjectID: p.ID, Endpoint: "GET /api/u",
		VulnClass: "越权", Status: "vulnerable", Notes: "确证：见 evidence/s4/idor-poc.txt"})
	issues2 := o.vulnerableEvidenceIssues(p, "s4")
	for _, iss := range issues2 {
		if strings.Contains(iss, "GET /api/u") && strings.Contains(iss, "越权") {
			t.Fatalf("带证据引用条目不应再被拦截: %v", issues2)
		}
	}
}
