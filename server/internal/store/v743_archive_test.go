package store

// v7.4.3 回归测试：执行流滚动归档（只挪不删）+ 分页回填 + 子任务重建归档。
// 实战背景：项目执行流超过 2000 条后最旧记录被物理删除，刷新回填只剩尾部——
// 对话/工具调用「重置」、子任务重建历史蒸发。修复后：淘汰件转归档桶，分页可回放全量。

import (
	"testing"
)

func addNStream(st *Store, projectID string, n, startSeq int) {
	for i := 0; i < n; i++ {
		_, err := st.AddStream(projectID, &StreamRecord{Kind: "log", Text: string(rune('a' + (startSeq+i)%26))})
		if err != nil {
			panic(err)
		}
	}
}

// ① 淘汰即归档：写 2100 条 → live=2000、archive=100；Tail 回填含全量；Before 分页取回归档段。
func TestV743StreamRollingArchive(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	addNStream(st, "P-A1", 2100, 0)

	live, _, err := st.ListStream("P-A1", 0)
	if err != nil || len(live) != streamKeepPerProject {
		t.Fatalf("live 桶应保留 %d 条，实际 %d（err=%v）", streamKeepPerProject, len(live), err)
	}

	tail, last, exhausted, err := st.ListStreamTail("P-A1", 2000)
	if err != nil || len(tail) != 2000 {
		t.Fatalf("Tail 应返回 2000 条，实际 %d（err=%v）", len(tail), err)
	}
	if exhausted != false {
		t.Fatalf("还有更早记录（归档段）时 exhausted 应为 false（未见底）")
	}
	if tail[len(tail)-1].Seq != last || last != 2100 {
		t.Fatalf("Tail 尾条 seq=%d 应为全局最大 %d", tail[len(tail)-1].Seq, last)
	}
	if tail[0].Seq != 101 {
		t.Fatalf("Tail 首条应为 seq=101（archive 补齐），实际 %d", tail[0].Seq)
	}

	// Before 分页：取 seq<101 的全部归档件
	before, exhausted2, err := st.ListStreamBefore("P-A1", 101, 1000)
	if err != nil || len(before) != 100 {
		t.Fatalf("Before 应返回归档段 100 条，实际 %d（err=%v）", len(before), err)
	}
	if exhausted2 != true {
		t.Fatalf("归档段已到头，exhausted 应为 true")
	}
	if before[0].Seq != 1 || before[99].Seq != 100 {
		t.Fatalf("Before 应升序覆盖 1..100，实际首尾 %d/%d", before[0].Seq, before[99].Seq)
	}

	// v7.4.4 分页中间态与越界态：中途页 exhausted=false；越界页空结果且 exhausted=true
	mid, midEx, err := st.ListStreamBefore("P-A1", 101, 50)
	if err != nil || len(mid) != 50 || midEx != false {
		t.Fatalf("中途页应 50 条且未见底: n=%d exhausted=%v err=%v", len(mid), midEx, err)
	}
	deep, deepEx, err := st.ListStreamBefore("P-A1", 51, 1000)
	if err != nil || len(deep) != 50 || deepEx != true {
		t.Fatalf("末页应 50 条且见底: n=%d exhausted=%v err=%v", len(deep), deepEx, err)
	}
	if deep[0].Seq != 1 || deep[49].Seq != 50 {
		t.Fatalf("末页应升序覆盖 1..50，实际首尾 %d/%d", deep[0].Seq, deep[49].Seq)
	}
	beyond, beyondEx, err := st.ListStreamBefore("P-A1", 1, 1000)
	if err != nil || len(beyond) != 0 || beyondEx != true {
		t.Fatalf("越界页应空且见底: n=%d exhausted=%v err=%v", len(beyond), beyondEx, err)
	}

	// 增量口径不变：after=2050 只返回其后的 live 记录
	inc, _, err := st.ListStream("P-A1", 2050)
	if err != nil || len(inc) != 50 {
		t.Fatalf("增量读取应返回 50 条，实际 %d（err=%v）", len(inc), err)
	}
}

// ② 未超上限的项目：Tail 即全量、exhausted=false（无归档可加载）。
func TestV743StreamTailNoArchiveNeeded(t *testing.T) {
	st, _ := Open(t.TempDir())
	defer st.Close()
	addNStream(st, "P-A2", 30, 0)
	tail, last, exhausted, err := st.ListStreamTail("P-A2", 2000)
	if err != nil || len(tail) != 30 || last != 30 || exhausted != true {
		t.Fatalf("未超限项目 Tail 应全量且已见底（无更早可加载）：n=%d last=%d exhausted=%v err=%v", len(tail), last, exhausted, err)
	}
}

// ③ 子任务重建归档：Move 后 live 清空、归档保留原条目（含 ArchivedAt），列表可查。
func TestV743SubtaskReplanArchive(t *testing.T) {
	st, _ := Open(t.TempDir())
	defer st.Close()
	_, _ = st.AddSubtask(&Subtask{ProjectID: "P-B", Stage: "s4", Title: "枚举门控"})
	_, _ = st.AddSubtask(&Subtask{ProjectID: "P-B", Stage: "s4", Title: "绕过变体"})
	_, _ = st.AddSubtask(&Subtask{ProjectID: "P-B", Stage: "s5", Title: "受控投递"}) // 他阶段不受影响

	moved, err := st.MoveStageSubtasksToArchive("P-B", "s4")
	if err != nil || moved != 2 {
		t.Fatalf("应归档 2 条，实际 %d（err=%v）", moved, err)
	}
	live, _ := st.ListSubtasks("P-B")
	if len(live) != 1 || live[0].Stage != "s5" {
		t.Fatalf("重建后 live 应只剩 s5 一条: %+v", live)
	}
	arch, err := st.ListArchivedSubtasks("P-B")
	if err != nil || len(arch) != 2 {
		t.Fatalf("归档应有 2 条，实际 %d（err=%v）", len(arch), err)
	}
	if arch[0].ArchivedAt.IsZero() {
		t.Fatalf("归档条目应带 ArchivedAt")
	}
}
