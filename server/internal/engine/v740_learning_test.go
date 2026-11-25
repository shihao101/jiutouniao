package engine

// v7.4.0 学习环回归：D1 质量门（结构化锚点强校验）/判重/检索质量分区

import (
	"strings"
	"testing"

	"jiutouniao/internal/llm"

	"jiutouniao/internal/store"
)

// D1：stack 与 behavior_class 双空 → 拒收（方法论纯文本不进教训库）。
func TestV740LessonGate(t *testing.T) {
	o, st := v48Orchestrator(t)
	p := v710Project(st, "P-V740-GATE")
	resp := o.dispatchChat(p.ID, llm.ToolCall{Name: "record_lesson", Arguments: `{"text":"遇到 WAF 先分型再选变体（纯方法论）"}`})
	if !strings.Contains(resp, "D1 质量门") || !strings.Contains(resp, "拒绝登记") {
		t.Fatalf("无结构化锚点应拒收: %s", resp)
	}
	// 带锚点 → 通过
	resp = o.dispatchChat(p.ID, llm.ToolCall{Name: "record_lesson", Arguments: `{"text":"瑞数类 JS 挑战目标，httpx 批量前先 channel-snapshot 快照态复放","stack":"ruishu","behavior_class":"js-challenge-waf","sample_size":"3 样本"}`})
	if !strings.Contains(resp, "已登记") {
		t.Fatalf("带锚点应通过: %s", resp)
	}
}

// D1：归一化等值判重。
func TestV740LessonDedup(t *testing.T) {
	o, st := v48Orchestrator(t)
	p := v710Project(st, "P-V740-DUP")
	o.dispatchChat(p.ID, llm.ToolCall{Name: "record_lesson", Arguments: `{"text":"IIS 短文件名枚举在模板渲染前可探测 secrets","stack":"iis"}`})
	resp := o.dispatchChat(p.ID, llm.ToolCall{Name: "record_lesson", Arguments: `{"text":"IIS 短文件名枚举在模板渲染前可探测 secrets","stack":"iis"}`})
	if !strings.Contains(resp, "判重") {
		t.Fatalf("归一化等值应判重: %s", resp)
	}
	lessons, _ := st.ListLessons(0)
	if len(lessons) != 1 {
		t.Fatalf("判重后应只有 1 条: %d", len(lessons))
	}
}

// D1：检索未命中槽内结构化完整记录优先于全空记录（稳定分区）。
func TestV740LessonSelectionQuality(t *testing.T) {
	emptyRec := &store.LessonRecord{ID: "L-old", Text: "旧全空记录"}
	structuredRec := &store.LessonRecord{ID: "L-new", Text: "新结构化记录", Stack: "spring"}
	// rest 顺序 = 时间倒序（旧在前）
	_, _, _ = selectLessonsForContext([]*store.LessonRecord{emptyRec, structuredRec}, "spring", "", 2)
	// 直接构造 rest 场景验证分区逻辑：全不命中时选择应先结构化
	sel, _, _ := selectLessonsForContext([]*store.LessonRecord{emptyRec, structuredRec}, "不匹配的指纹", "", 2)
	if len(sel) != 2 || sel[0].lesson.ID != "L-new" {
		t.Fatalf("结构化完整记录应排前: %+v", sel)
	}
}
