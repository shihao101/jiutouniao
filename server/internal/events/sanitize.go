package events

import "strings"

// 去 AI 化展示清洗：剥离 pictograph 类 emoji（AI 生成风格图标）。
// 保留专业控制台惯用的印刷符号：✓(2713) ✗(2717) →(2192) ◉◍◆○◐●(25A0-25FF) 等。

func isEmojiPict(r rune) bool {
	switch {
	case r >= 0x1F000 && r <= 0x1FAFF: // emoji 主体（符号/旗帜/扩展区）
		return true
	case r >= 0x2600 && r <= 0x26FF: // 杂项符号（⚙ ⚠ ⚓ 等）
		return true
	case r >= 0x2700 && r <= 0x27BF: // 丁贝符（❓ ✅ ❌ 等）；✓ ✗ 例外保留
		return r != 0x2713 && r != 0x2717
	case r >= 0x2B00 && r <= 0x2BFF: // 杂项符号与箭头（⭐ ⭕ 等）
		return true
	case r == 0xFE0F || r == 0xFE0E: // 变体选择符（emoji 呈现开关）
		return true
	}
	return false
}

// SanitizeEmoji 剥离字符串中的 pictograph emoji。
func SanitizeEmoji(s string) string {
	if !strings.ContainsFunc(s, isEmojiPict) {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		if !isEmojiPict(r) {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// SanitizeText 递归清洗事件载荷中的字符串字段（map/slice/string）。
func SanitizeText(v any) any {
	switch t := v.(type) {
	case map[string]string:
		out := make(map[string]string, len(t))
		for k, s := range t {
			out[k] = SanitizeEmoji(s)
		}
		return out
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, x := range t {
			out[k] = SanitizeText(x)
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i, x := range t {
			out[i] = SanitizeText(x)
		}
		return out
	case []string:
		out := make([]string, len(t))
		for i, s := range t {
			out[i] = SanitizeEmoji(s)
		}
		return out
	case string:
		return SanitizeEmoji(t)
	default:
		return v
	}
}
