// v5.3.2 P1-5 阶段内任务规划优先级自调单测：覆盖缺口/风险/证据缺口驱动排序，id 稳定。
package engine

import (
	"strings"
	"testing"

	"jiutouniao/internal/store"
)

func TestV532RerankSubtasks(t *testing.T) {
	o, st := v48Orchestrator(t)
	p := &store.Project{ID: "P-V532-P1", Name: "优先级"}
	_ = st.SaveProject(p)
	mk := func(title, detail string) string {
		id, err := st.AddSubtask(&store.Subtask{ProjectID: p.ID, Stage: "s4", Title: title, Detail: detail, Status: "created"})
		if err != nil {
			t.Fatal(err)
		}
		return id
	}
	mk("常规资产清点", "对已确证资产做目录整理")
	idB := mk("验证越权缺口", "GET /api/user 越权 needs_follow_up 待验证，无证据")
	idC := mk("闭环命令注入", "/api/exec 命令注入 vulnerable 未闭环，验证 RCE")
	idD := mk("已完成项", "早期基线自检")
	if drec, err := st.GetSubtask(idD); err == nil { // 显式终态（否则按常规任务计分，随机 id 序会翻出末位断言）
		drec.Status = "finished"
		_ = st.SaveSubtask(drec)
	}
	_, _ = st.UpsertCoverage(&store.CoverageEntry{ProjectID: p.ID, Stage: "s4", Endpoint: "GET /api/user", VulnClass: "越权", Status: "needs_follow_up", Notes: "匿名 401 待验证"})
	_, _ = st.UpsertCoverage(&store.CoverageEntry{ProjectID: p.ID, Stage: "s4", Endpoint: "POST /api/exec", VulnClass: "命令注入", Status: "vulnerable", Notes: "回显确证"})

	ranked := o.rerankSubtasks(p, "s4")
	if len(ranked) != 4 {
		t.Fatalf("应重排 4 项: %d", len(ranked))
	}
	// 命令注入（vulnerable +5，且「命令注入/RCE」高危 L2 +2）应居首；越权缺口次之；常规项靠后；终态沉底
	if ranked[0].ID != idC {
		t.Fatalf("vulnerable+高危任务应居首: got=%s want=%s", ranked[0].ID, idC)
	}
	if ranked[1].ID != idB {
		t.Fatalf("覆盖缺口任务应次席: got=%s want=%s", ranked[1].ID, idB)
	}
	if ranked[3].ID != idD {
		t.Fatalf("终态任务应沉底: got=%s want=%s", ranked[3].ID, idD)
	}
	// id 与内容稳定，只动 Priority/PriorityWhy
	for _, stq := range ranked {
		got, _ := st.GetSubtask(stq.ID)
		if got.Title == "" || got.Priority == 0 {
			t.Fatalf("优先级未落库: %+v", got)
		}
	}
	if !strings.Contains(ranked[0].PriorityWhy, "vulnerable") {
		t.Fatalf("排序依据应可读: %s", ranked[0].PriorityWhy)
	}
	// 覆盖账本变化 → 重排随动：越权闭环（needs_follow_up→no_issue_found）后该任务降位
	_, _ = st.UpsertCoverage(&store.CoverageEntry{ProjectID: p.ID, Stage: "s4", Endpoint: "GET /api/user", VulnClass: "越权", Status: "no_issue_found", Notes: "negative_valid", ObservedResult: "negative_valid"})
	ranked2 := o.rerankSubtasks(p, "s4")
	if ranked2[0].ID != idC {
		t.Fatalf("覆盖闭环后排序应随动: %v", ranked2[0].ID)
	}
	bPos := 0
	for i, r := range ranked2 {
		if r.ID == idB {
			bPos = i + 1
		}
	}
	if bPos != 2 {
		t.Fatalf("已闭环缺口任务应降至次席（覆盖项消失只剩证据缺口）: pos=%d", bPos)
	}
}

func TestV532PlanSubtasksPriorityResponse(t *testing.T) {
	o, st := v48Orchestrator(t)
	p := &store.Project{ID: "P-V532-P2", Name: "建档响应"}
	_ = st.SaveProject(p)
	_, _ = st.UpsertCoverage(&store.CoverageEntry{ProjectID: p.ID, Stage: "s4", Endpoint: "/api/admin", VulnClass: "越权", Status: "needs_follow_up", Notes: "n"})
	got := o.dispatch(testCtx(), p, "s4", mkCall("plan_subtasks",
		`{"items":[{"title":"验证 /api/admin 越权缺口","detail":"needs_follow_up 无证据待验证"},{"title":"整理报告目录","detail":"常规整理"}]}`))
	if !strings.Contains(got, "[P1]") || !strings.Contains(got, "[P2]") {
		t.Fatalf("建档响应应带优先级标签: %s", got)
	}
	if !strings.Contains(got, "依据：") {
		t.Fatalf("响应应含排序依据: %s", got)
	}
	if !strings.Contains(got, "验证 /api/admin 越权缺口") || strings.Index(got, "越权缺口") > strings.Index(got, "整理报告目录") {
		t.Fatalf("覆盖缺口任务应排前: %s", got)
	}
}
