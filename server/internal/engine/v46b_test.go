package engine

// v4.6 二批次专项测试：E5 教训 provisional 标记 / K2 行为类注入 / K5-lite 空闲提醒 /
// V6 僵尸 NF 回填门 / A2 VT 全生命周期 / R1 quality-pending 复核门 / B4 报告引用核验。

import (
	"context"
	"regexp"
	"strings"
	"testing"
	"time"

	"jiutouniao/internal/config"
	"jiutouniao/internal/events"
	"jiutouniao/internal/llm"
	"jiutouniao/internal/store"
)

func testCtx() context.Context              { return context.Background() }
func mkCall(name, args string) llm.ToolCall { return llm.ToolCall{Name: name, Arguments: args} }

func v46bOrchestrator(t *testing.T) (*Orchestrator, *store.Store) {
	t.Helper()
	_, st := testApprover(t)
	dir := t.TempDir()
	o := &Orchestrator{store: st, exec: newTestExec(t, dir), bus: events.NewBus(),
		cfg: func() *config.Config { c := &config.Config{}; c.ApplyDefaultsForTest(); return c }()}
	return o, st
}

// E5：无样本强度教训在上下文中必须带 provisional 标记；K2：行为类命中教训优先注入。
func TestV46bLessonProvisionalAndBehavior(t *testing.T) {
	o, st := v46bOrchestrator(t)
	p := &store.Project{ID: "P-B1"}
	_ = st.SaveProject(p)
	_, _ = st.AddLesson(&store.LessonRecord{Text: "限速目标冷却必须完全静默", BehaviorClass: "rate-limited", SampleSize: "3 样本"})
	_, _ = st.AddLesson(&store.LessonRecord{Text: "批量 dump-dom 触发渐进式降级"}) // 无 SampleSize/behavior_class
	_, _ = st.UpsertFact(&store.FactRecord{ProjectID: p.ID, Key: "behavior." + p.ID, Value: "rate-limited", Confidence: "confirmed"})
	ctx := o.buildContextPack(p, "s4")
	if !strings.Contains(ctx, "provisional：样本强度未标注/单次实验") {
		t.Fatalf("无 SampleSize 教训应带 provisional 标记")
	}
	if !strings.Contains(ctx, "【行为类命中 rate-limited】限速目标冷却必须完全静默") {
		t.Fatalf("行为类命中教训应优先注入: %s", ctx[:0])
	}
}

// K5-lite：跨阶段空闲 >30min 且进入对抗敏感阶段 → 注入通道基线自检提醒。
func TestV46bIdleGapReminder(t *testing.T) {
	o, st := v46bOrchestrator(t)
	p := &store.Project{ID: "P-B2", StageStates: map[string]*store.StageState{
		"s4": {Status: "done", EndedAt: time.Now().Add(-2 * time.Hour).Format(time.RFC3339)},
	}}
	_ = st.SaveProject(p)
	ctx := o.buildContextPack(p, "s5")
	if !strings.Contains(ctx, "空闲提醒（K5-lite）") {
		t.Fatalf("空闲 >30min 应注入提醒")
	}
	// 空闲 5min → 不提醒
	p2 := &store.Project{ID: "P-B2b", StageStates: map[string]*store.StageState{
		"s4": {Status: "done", EndedAt: time.Now().Add(-5 * time.Minute).Format(time.RFC3339)},
	}}
	ctx2 := o.buildContextPack(p2, "s5")
	if strings.Contains(ctx2, "空闲提醒（K5-lite）") {
		t.Fatalf("空闲 <30min 不应提醒")
	}
}

// V6：①UpsertCoverage 归一化键自动原地合并（同义不同写法=同一单元，计数累加，展示保留首见）；
// ②历史数据（原始键漂移已落库）由 s7 门拦截要求合并回填。
func TestV46bCoverageNormalizeMergeAndZombieGate(t *testing.T) {
	o, st := v46bOrchestrator(t)
	p := &store.Project{ID: "P-B3"}
	_ = st.SaveProject(p)
	// ① 归一化合并：两种写法两次登记 → 单一单元 count=2
	_, _ = st.UpsertCoverage(&store.CoverageEntry{ProjectID: p.ID, Stage: "s2", Endpoint: "https://www.example.com/x/", VulnClass: "越权", Status: "needs_follow_up", Notes: "早期登记"})
	_, _ = st.UpsertCoverage(&store.CoverageEntry{ProjectID: p.ID, Stage: "s4", Endpoint: "www.example.com/x", VulnClass: "越权", Status: "ruled_out", Notes: "实测", ObservedResult: "negative_valid"})
	cov, _ := st.ListCoverage(p.ID)
	if len(cov) != 1 || cov[0].Count != 2 || cov[0].Status != "ruled_out" {
		t.Fatalf("归一化合并失败: %+v", cov)
	}
	if cov[0].Endpoint != "https://www.example.com/x/" {
		t.Fatalf("展示应保留首见原文: %+v", cov[0])
	}
	// ② 历史僵尸数据（原始键漂移已落库）→ s7 门拦截
	_ = st.AddCoverageKeepKey(&store.CoverageEntry{ProjectID: p.ID, Stage: "s2", Endpoint: "https://legacy.example.com/y", VulnClass: "注入", Status: "needs_follow_up", Notes: "旧键"})
	_ = st.AddCoverageKeepKey(&store.CoverageEntry{ProjectID: p.ID, Stage: "s4", Endpoint: "legacy.example.com/y", VulnClass: "注入", Status: "ruled_out", Notes: "实测", ObservedResult: "negative_valid"})
	issues := o.deterministicGate(p, "s7")
	if !strings.Contains(strings.Join(issues, "\n"), "僵尸 needs_follow_up") {
		t.Fatalf("历史键漂移僵尸应被拦截: %v", issues)
	}
}

// A2：VT 全生命周期——登记→s7 门拦截开放项→处置（closed-roe 缺理由拒绝）→门放行。
func TestV46bVTLifecycle(t *testing.T) {
	o, st := v46bOrchestrator(t)
	p := &store.Project{ID: "P-B4"}
	_ = st.SaveProject(p)
	vid := ""
	{
		args := `{"title":"wcId SQLi 布尔确认","ready_assets":"scripts/b4.sh","start_conditions":"限速窗口","cost_note":"1 窗口","priority":1,"status":"ready"}`
		got := o.dispatch(testCtx(), p, "s4", mkCall("record_vt", args))
		if !strings.Contains(got, "已登记验证任务 VT-") {
			t.Fatalf("VT 登记失败: %s", got)
		}
		m := regexp.MustCompile(`VT-[0-9A-Fa-f]+`).FindString(got)
		vid = m
	}
	// closed-roe 缺理由 → 拒绝
	got := o.dispatch(testCtx(), p, "s7", mkCall("update_vt", `{"id":"`+vid+`","status":"closed-roe"}`))
	if !strings.Contains(got, "必须附 note") {
		t.Fatalf("closed-roe 缺理由应拒绝: %s", got)
	}
	// s7 门：开放 VT 拦截
	issues := o.deterministicGate(p, "s7")
	if !strings.Contains(strings.Join(issues, "\n"), "仍为开放状态") {
		t.Fatalf("开放 VT 应被 s7 门拦截: %v", issues)
	}
	// 处置后放行
	got = o.dispatch(testCtx(), p, "s7", mkCall("update_vt", `{"id":"`+vid+`","status":"executed","result_ref":"evidence/s7-b4.log","note":"布尔差异确证"}`))
	if !strings.Contains(got, "已处置") {
		t.Fatalf("处置应成功: %s", got)
	}
	vts, _ := st.ListVTs(p.ID)
	if vts[0].Status != "executed" {
		t.Fatalf("落库状态应为 executed: %+v", vts[0])
	}
}

// R1：反思门不可用的阶段标记 quality-pending → s8 门强制复核提示。
// v5.3.8 更新：quality-pending 不再是确定性门硬拦截项（旧语义构成死锁——标记无清除通道，
// 实证模型穷尽 8 条路径仍被永久拦截）。新契约：deterministicGate 不生成该 issue；
// 复核走 complete_stage 的 confirm_quality_review 显式确认（applyQualityReviewConfirm 清除标记）。
func TestV46bGateQualityPending(t *testing.T) {
	o, st := v46bOrchestrator(t)
	p := &store.Project{ID: "P-B5", StageStates: map[string]*store.StageState{
		"s4": {Status: "done", Review: "反思门调用失败（重试 3 次）；确定性质量门通过放行【quality-pending：S8 收口前须复核本阶段交付物】"},
	}}
	_ = st.SaveProject(p)
	issues := o.deterministicGate(p, "s8")
	if strings.Contains(strings.Join(issues, "\n"), "quality-pending") {
		t.Fatalf("quality-pending 不应再触发确定性门硬拦截（死锁源已移除）: %v", issues)
	}
	// 新契约：确认前软提示（返回 true 且标记不动），确认后清除
	p.StageStates["s4"] = &store.StageState{Status: "done", Review: "【quality-pending：须复核】"}
	_ = st.SaveProject(p)
	if !o.applyQualityReviewConfirm(p, false) {
		t.Fatal("未确认应软提示")
	}
	if o.applyQualityReviewConfirm(p, true) {
		t.Fatal("确认后应放行")
	}
	if strings.Contains(p.StageStates["s4"].Review, "quality-pending") {
		t.Fatal("确认后标记应清除")
	}
}

// B4：报告引用不存在的 evidence 路径 → s8 门拦截；存在则不报。
func TestV46bGateReportEvidence(t *testing.T) {
	o, st := v46bOrchestrator(t)
	p := &store.Project{ID: "P-B6"}
	_ = st.SaveProject(p)
	_, _ = o.exec.WriteFile(p.ID, "evidence/exists.txt", "ok")
	_, _ = o.exec.WriteFile(p.ID, "report.md", "### R-01 x\n证据 evidence/missing.txt 与 evidence/exists.txt\n")
	issues := o.deterministicGate(p, "s8")
	joined := strings.Join(issues, "\n")
	if !strings.Contains(joined, "报告引用的证据文件缺失: evidence/missing.txt") {
		t.Fatalf("缺失引用应被拦截: %v", issues)
	}
	if strings.Contains(joined, "evidence/exists.txt") {
		t.Fatalf("存在文件不应被拦截: %v", issues)
	}
}
