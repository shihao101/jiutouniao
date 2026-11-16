package events

import "testing"

func TestSanitizeEmoji(t *testing.T) {
	cases := []struct{ in, want string }{
		{"🚀 已触发断点续跑", " 已触发断点续跑"},
		{"决策留痕（自动 ⚙）", "决策留痕（自动 ）"},
		{"L0 ⚙️ 自动执行", "L0  自动执行"}, // 含变体选择符 FE0F；清洗为纯剥离，不吞相邻空格
		{"阶段完成 ✓ 3 项，失败 ✗ 1 项", "阶段完成 ✓ 3 项，失败 ✗ 1 项"},
		{"耗时 12s → 完成", "耗时 12s → 完成"},
		{"状态 ◉ 工作台 ◍ 资产", "状态 ◉ 工作台 ◍ 资产"},
		{"", ""},
		{"纯中文无图标", "纯中文无图标"},
	}
	for _, c := range cases {
		if got := SanitizeEmoji(c.in); got != c.want {
			t.Errorf("SanitizeEmoji(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestSanitizeTextMap(t *testing.T) {
	in := map[string]any{
		"text":  "🧹 清理完成",
		"ts":    "15:04:05",
		"items": []any{map[string]string{"note": "⚠ 风险"}},
	}
	out := SanitizeText(in).(map[string]any)
	if out["text"] != " 清理完成" {
		t.Errorf("text = %q", out["text"])
	}
	if out["ts"] != "15:04:05" {
		t.Errorf("ts = %q", out["ts"])
	}
	note := out["items"].([]any)[0].(map[string]string)["note"]
	if note != " 风险" {
		t.Errorf("note = %q", note)
	}
}
