package engine

// v7.4.3 回归：plan_subtasks 全量重建改为「归档化重建」——旧计划转 subtask_archive 不蒸发，
// detail 链路（subtasks_archived）可追溯；stream 淘汰件转 stream_archive 由 store 层测试覆盖。

import (
	"context"
	"strings"
	"testing"

	"jiutouniao/internal/llm"
)

func TestV743PlanSubtasksArchivesOldPlan(t *testing.T) {
	o, st := v710Orchestrator(t)
	p := v710Project(st, "P-V743-PLAN")

	// 首次规划：2 项
	res := o.dispatch(context.Background(), p, "s4", llm.ToolCall{Name: "plan_subtasks",
		Arguments: `{"items":[{"title":"枚举门控","detail":"111 端点族"},{"title":"绕过变体","detail":"规范化/方法/头"}]}`})
	if res == "" || strings.Contains(res, "错误") {
		t.Fatalf("首次规划应成功: %s", res)
	}
	live, _ := st.ListSubtasks(p.ID)
	if len(live) != 2 {
		t.Fatalf("首次规划后 live 应 2 条，实际 %d", len(live))
	}

	// 重建（回环/重进阶段场景）：1 项 → 旧 2 项应入归档而非删除
	_ = o.dispatch(context.Background(), p, "s4", llm.ToolCall{Name: "plan_subtasks",
		Arguments: `{"items":[{"title":"复测轮聚焦"}]}`})
	live, _ = st.ListSubtasks(p.ID)
	if len(live) != 1 || live[0].Title != "复测轮聚焦" {
		t.Fatalf("重建后 live 应 1 条新计划: %+v", live)
	}
	arch, err := st.ListArchivedSubtasks(p.ID)
	if err != nil || len(arch) != 2 {
		t.Fatalf("旧计划应归档 2 条（不蒸发），实际 %d（err=%v）", len(arch), err)
	}
	for _, a := range arch {
		if a.ArchivedAt.IsZero() || a.Stage != "s4" {
			t.Fatalf("归档条目应带 ArchivedAt 且保留阶段: %+v", a)
		}
	}
}
