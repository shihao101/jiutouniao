package engine

// v7.4.2 回归测试：
// ① NO_EVIDENCE 回执参数化——附项目实时可引用指针示例（替代泛化指引）
// ② 同因（NO_EVIDENCE）重复被拒——回执升级为强指引（第 N 次计数 + 禁止第三次原样重提）
// ③ 自主决策账本时序——created_at（提议时刻）≤ decided_at（裁决时刻），不再倒挂
// ④ 自述清单门状态归一化——covered 同义态（tested 等）不再计入延期/排除，显式处置态才计入

import (
	"context"
	"strings"
	"testing"

	"jiutouniao/internal/llm"
	"jiutouniao/internal/store"
)

// ① 首次 NO_EVIDENCE：回执附五类指针格式 + 项目实时示例（VT 编号）。
func TestV742NoEvidenceReceiptParameterized(t *testing.T) {
	o, st := v710Orchestrator(t)
	p := v710Project(st, "P-V742-NE1")
	vtID, _ := st.AddVT(&store.VerificationTask{ProjectID: p.ID, Stage: "s4", Title: "login 差分"})
	res := o.dispatch(context.Background(), p, "s4", llm.ToolCall{Name: "propose",
		Arguments: `{"kind":"depth_extend","rationale":"想继续测","focus":"C-13@login","evidence_refs":[]}`})
	if !strings.Contains(res, "NO_EVIDENCE") {
		t.Fatalf("无证据提议应拒收: %s", res)
	}
	if !strings.Contains(res, "evidence_refs 必填") || !strings.Contains(res, "fact:") {
		t.Fatalf("回执应给出五类指针格式（参数化指引）: %s", res)
	}
	if !strings.Contains(res, vtID) {
		t.Fatalf("回执应附项目实时可引用示例（%s）: %s", vtID, res)
	}
}

// ② 同因重复被拒：第二次回执升级为强指引（计数 + 禁止第三次原样重提）。
func TestV742NoEvidenceRepeatStrongGuidance(t *testing.T) {
	o, st := v710Orchestrator(t)
	p := v710Project(st, "P-V742-NE2")
	args := `{"kind":"depth_extend","rationale":"想继续测","focus":"C-13@login","evidence_refs":[]}`
	first := o.dispatch(context.Background(), p, "s4", llm.ToolCall{Name: "propose", Arguments: args})
	if !strings.Contains(first, "NO_EVIDENCE") {
		t.Fatalf("首次应 NO_EVIDENCE 拒收: %s", first)
	}
	second := o.dispatch(context.Background(), p, "s4", llm.ToolCall{Name: "propose", Arguments: args})
	if !strings.Contains(second, "第 2 次") || !strings.Contains(second, "禁止第三次原样重提") {
		t.Fatalf("同因重复被拒应收敛强指引: %s", second)
	}
}

// ③ 账本时序：created_at（提议时刻）不得晚于 decided_at（裁决时刻）。
func TestV742AutonomyLedgerOrdering(t *testing.T) {
	o, st := v710Orchestrator(t)
	p := v710Project(st, "P-V742-ORD")
	o.dispatch(context.Background(), p, "s4", llm.ToolCall{Name: "propose",
		Arguments: `{"kind":"loopback_focus","rationale":"回环补证据","focus":"s3 判定表待判定行","evidence_refs":["fact:nope"]}`})
	recs, err := st.ListAutonomy(p.ID)
	if err != nil || len(recs) == 0 {
		t.Fatalf("提议应落账本: %v %d", err, len(recs))
	}
	for _, r := range recs {
		if r.DecidedAt != nil && r.CreatedAt.After(*r.DecidedAt) {
			t.Fatalf("账本时序倒挂：%s created_at(%v) > decided_at(%v)", r.ID, r.CreatedAt, *r.DecidedAt)
		}
	}
}

// ④ 自述清单门状态归一化：tested 同义态按 covered 计；仅显式处置态计入延期/排除；
// 未知状态回落覆盖矩阵对账（无登记 → uncovered 提示）。
func TestV742ChecklistStatusNormalization(t *testing.T) {
	_, st := testApprover(t)
	dir := t.TempDir()
	o := &Orchestrator{store: st, exec: newTestExec(t, dir)}
	mk := func(pid, name, content string) {
		_, _ = o.exec.WriteFile(pid, name, content)
	}

	// 实战对抗形态复现：24 tested + 4 excluded + 2 deferred —— 旧实现整桶计 30/30 触发广度拦截，
	// 归一化后仅显式处置态 6/30（20%）→ 放行，执行侧无需改写状态即可过门。
	items := `{"items":[`
	for i := 1; i <= 24; i++ {
		items += `{"id":"C` + string(rune('0'+i%10)) + `","item":"条目` + string(rune('A'+i)) + `","status":"tested","reason":"已实测"},`
	}
	items += `{"id":"C91","item":"条目Y","status":"excluded","reason":"范围外"},`
	items += `{"id":"C92","item":"条目Z","status":"deferred","reason":"移交复测"}]}`
	mk("PN", "checklist.json", items)
	for _, iss := range checkGate(o, "PN", "s4") {
		if strings.Contains(iss, "广度不足") {
			t.Fatalf("tested 同义态不应计入延期/排除（6/30=20%%）: %v", iss)
		}
	}

	// 显式处置态仍受门约束：缺 reason 拦截、超半数拦截（原口径回归）。
	mk("PN", "checklist.json", `{"items":[
		{"id":"D1","item":"数字型注入","status":"tested","reason":"已实测"},
		{"id":"D2","item":"反射性XSS","status":"deferred","reason":"低优先"},
		{"id":"D3","item":"目录遍历","status":"excluded","reason":"范围外"}]}`)
	if got := countContains(checkGate(o, "PN", "s4"), "广度不足"); got != 1 {
		t.Fatalf("显式处置态超半数仍应触发广度不足项，实际 %d", got)
	}

	// 未知状态：回落覆盖矩阵对账——无登记 → uncovered 提示（fail-safe 不放水）。
	mk("PN", "checklist.json", `{"items":[
		{"id":"E1","item":"数字型注入","status":"in_progress"}]}`)
	found := false
	for _, iss := range checkGate(o, "PN", "s4") {
		if strings.Contains(iss, "无覆盖登记") {
			found = true
		}
	}
	if !found {
		t.Fatalf("未知 status 应回落覆盖矩阵对账（无登记应提示）")
	}
}
