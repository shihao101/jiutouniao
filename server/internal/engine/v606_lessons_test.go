package engine

// v6.0.6 P0 验收测试（教训库选取机制重构）：
// ①全库打分选取——窗口外命中教训必须被召回（LS-4DD9BCB0E6 回归）；
// ②token 去重（Stack/Tags 同词不重复计分）；
// ③保底最近槽位；④evidence note 三态；⑤searchLessonsScan 关键词匹配。

import (
	"strings"
	"testing"
	"time"

	"jiutouniao/internal/store"
)

func mkLesson(id string, ageHours int, stack, tags, bc string) *store.LessonRecord {
	return &store.LessonRecord{
		ID: id, Text: "教训-" + id, Stack: stack, Tags: tags, BehaviorClass: bc,
		CreatedAt: time.Now().Add(-time.Duration(ageHours) * time.Hour),
	}
}

// ①回归核心：旧命中教训（排名第 25/30，等价 LS-4DD9BCB0E6 场景）必须被召回——
// 旧实现 ListLessons(8) 按时间截断后该教训永远不可达。
func TestV606LessonsSelectionRecallsOldHit(t *testing.T) {
	var lessons []*store.LessonRecord
	for i := 1; i <= 30; i++ {
		lessons = append(lessons, mkLesson(lessons_id(i), i, "", "方法论,工具", "")) // 近期零分教训
	}
	// 一条“旧命中”教训：排名第 25（按时间），Stack 命中指纹池
	old := mkLesson("LS-OLDHIT9999", 25*24, "nextjs", "前端情报", "")
	lessons = append(lessons, old)

	selected, total, hits := selectLessonsForContext(lessons, "library.rocna nextjs 前端情报", "", 8)
	if total != 31 {
		t.Fatalf("全库条数应 31: %d", total)
	}
	if hits != 1 {
		t.Fatalf("命中应 1 条: %d", hits)
	}
	found := false
	for _, sl := range selected {
		if sl.lesson.ID == old.ID {
			found = true
		}
	}
	if !found {
		t.Fatal("窗口外的旧命中教训必须被召回（LS-4DD9BCB0E6 回归）")
	}
	if len(selected) != 8 {
		t.Fatalf("应选满 8 条: %d", len(selected))
	}
	// 命中教训排在首位
	if selected[0].lesson.ID != old.ID {
		t.Fatalf("命中教训应排首位: %s", selected[0].lesson.ID)
	}
}

// ②token 去重：同一 token 出现在 Stack 和 Tags 中不重复计分
func TestV606ScoreLessonDedup(t *testing.T) {
	l := mkLesson("L1", 1, "nextjs", "nextjs,前端情报", "")
	got := scoreLesson(l, "nextjs 前端情报", "")
	if got != 2 { // nextjs(去重后 1 次) + 前端情报(1 次)
		t.Fatalf("去重后应 2 分: %d", got)
	}
	// behaviorClass 精确命中 +2
	got2 := scoreLesson(mkLesson("L2", 1, "", "", "rate-limited"), "", "rate-limited")
	if got2 != 2 {
		t.Fatalf("行为类命中应 +2: %d", got2)
	}
	// 零命中
	if scoreLesson(mkLesson("L3", 1, "", "方法论", ""), "nextjs", "") != 0 {
		t.Fatal("无命中应 0 分")
	}
}

// ③保底最近槽位：命中数量超过 hitCap 时，最近教训仍保留 ≥2 条
func TestV606SelectionRecentFloor(t *testing.T) {
	var lessons []*store.LessonRecord
	for i := 1; i <= 20; i++ {
		lessons = append(lessons, mkLesson(lessons_id(i), i, "spring", "spring", "")) // 全部命中
	}
	recent := mkLesson("LS-RECENT1", 1, "", "方法论", "")
	recent2 := mkLesson("LS-RECENT2", 2, "", "方法论", "")
	lessons = append(lessons, recent, recent2)

	selected, _, hits := selectLessonsForContext(lessons, "spring", "", 8)
	if hits != 20 {
		t.Fatalf("命中应 20: %d", hits)
	}
	if len(selected) != 8 {
		t.Fatalf("应选 8 条: %d", len(selected))
	}
	hasRecent := false
	for _, sl := range selected {
		if sl.lesson.ID == recent.ID || sl.lesson.ID == recent2.ID {
			hasRecent = true
		}
	}
	if !hasRecent {
		t.Fatal("保底最近槽位（≥2 条）必须保留")
	}
}

// ④evidence note 三态：空=未记录 / 单次=provisional / 多样本=无标注
func TestV606EvidenceNote(t *testing.T) {
	if got := lessonEvidenceNote(&store.LessonRecord{SampleSize: ""}); !strings.Contains(got, "证据强度未记录") {
		t.Fatalf("空 SampleSize 应标「证据强度未记录」: %q", got)
	}
	if got := lessonEvidenceNote(&store.LessonRecord{SampleSize: "单次实验"}); !strings.Contains(got, "provisional") {
		t.Fatalf("单次应标 provisional: %q", got)
	}
	if got := lessonEvidenceNote(&store.LessonRecord{SampleSize: "3+ 样本"}); got != "" {
		t.Fatalf("多样本应无标注: %q", got)
	}
}

// ⑤searchLessonsScan：text/tags/stack 命中（search_memory lessons 分支的纯函数抽取）
func TestV606SearchLessonsScan(t *testing.T) {
	ls := []*store.LessonRecord{
		mkLesson("LS-A", 1, "", "方法论,前端情报", ""),
		mkLesson("LS-B", 2, "nextjs", "", ""),
		mkLesson("LS-C", 3, "", "风控", ""),
	}
	// 需要一条带 HyLib 文案的（模拟 LS-4DD9BCB0E6）
	h := mkLesson("LS-HYLIB", 4, "", "方法论/前端情报/接口发现", "")
	h.Text = "图书馆/教务类系统（HyLib 等）常把 export 类导出接口裸露在 /api/<Product>WS"
	ls = append(ls, h)

	hits := searchLessonsScan(ls, "hylib")
	if len(hits) != 1 || !strings.Contains(hits[0], "LS-HYLIB") {
		t.Fatalf("HyLib 关键词应命中 1 条: %v", hits)
	}
	hits = searchLessonsScan(ls, "nextjs")
	if len(hits) != 1 || !strings.Contains(hits[0], "LS-B") {
		t.Fatalf("stack 命中应 1 条: %v", hits)
	}
	if hits := searchLessonsScan(ls, "zzz-not-exist"); len(hits) != 0 {
		t.Fatalf("无关键词应 0 命中: %v", hits)
	}
}

func lessons_id(i int) string {
	id := "LS-JT"
	n := i
	for n > 0 {
		id += string(rune('A' + n%26))
		n /= 26
	}
	return id + string(rune('0'+i%10))
}

// ⑥方法论槽回归（v6.0.6 B 补充）：指纹池为空时，旧方法论教训必须经方法论槽召回——
// 精确复刻 LS-4DD9BCB0E6 场景（无 Stack、tags 含方法论、时间排名靠后被挤出窗口）
func TestV606MethodologySlotRecallsOldLesson(t *testing.T) {
	var lessons []*store.LessonRecord
	for i := 1; i <= 30; i++ {
		lessons = append(lessons, mkLesson(lessons_id(i), i, "", "工具,风控", "")) // 近期零分、非方法论
	}
	// 旧方法论教训：无 Stack（指纹打分必 0 分），tags 含方法论，时间早（排第 25）
	old := mkLesson("LS-4DD9BCB0E6", 25*24, "", "方法论,前端情报,接口发现", "")
	old.Text = "图书馆/教务类系统（HyLib 等）常把 export 类导出接口裸露在 /api/<Product>WS"
	lessons = append(lessons, old)

	// 指纹池为空（模拟任务早期 confirmed facts 尚未积累）
	selected, total, hits := selectLessonsForContext(lessons, "", "", 8)
	if total != 31 || hits != 0 {
		t.Fatalf("total=%d hits=%d（指纹池空应全零分）", total, hits)
	}
	found := false
	for _, sl := range selected {
		if sl.lesson.ID == old.ID {
			found = true
		}
	}
	if !found {
		t.Fatal("方法论槽必须召回旧方法论教训（LS-4DD9BCB0E6 回归）")
	}
	if len(selected) != 8 {
		t.Fatalf("应选满 8 条: %d", len(selected))
	}
}
