// v3.3.0 输出治理③：对话链窗口压缩（确定性，零额外 LLM 调用）。
// 参照 pentagi window_compaction 的预算思想与 HackSynth「摘要即状态」的收敛目标，
// 采用确定性存根替换而非 LLM 摘要——工具回执前 2000 字符已在证据链（search_memory 可检索），
// 大输出另有 .tool-output/ 溢出文件，存根只丢「重复上下文」，不丢事实。
package engine

import (
	"jiutouniao/internal/llm"
)

// estimateTokens 估算消息链 token 量：CJK ≈ 1 token/字，其余 ≈ 1 token/4 字符（取保守高估）。
func estimateTokens(msgs []llm.Message) int {
	total := 0
	for _, m := range msgs {
		total += 12 + estStringTokens(m.Content)
	}
	return total
}

func estStringTokens(s string) int {
	cjk, other := 0, 0
	for _, r := range s {
		if r > 0x2E7F { // CJK 统一表意文字及扩展区起点之上按单字计
			cjk++
		} else {
			other++
		}
	}
	return cjk + other/4
}

// compactMsgs 确定性窗口压缩：估算超预算时，把最旧的中段工具回执与超长助手消息替换为存根。
// 保护段：开头 system + 首个 user（上下文包）与结尾最近 keepRecent 条。
// 单遍压缩后仍超预算则继续压（工具回执压完压 assistant），压无可压即返回当前链（如实交给上游处理）。
func compactMsgs(msgs []llm.Message, budget, keepRecent int) ([]llm.Message, int) {
	if budget <= 0 || len(msgs) <= 3 || estimateTokens(msgs) <= budget {
		return msgs, 0
	}
	if keepRecent < 4 {
		keepRecent = 4
	}
	out := make([]llm.Message, len(msgs))
	copy(out, msgs)
	total := 0
	// 两遍：第一遍只压工具回执（信息密度最低、体积最大），第二遍压长助手消息
	for pass, role := range []string{"tool", "assistant"} {
		limit := len(out) - keepRecent
		for i := 2; i < limit && estimateTokens(out) > budget; i++ {
			m := out[i]
			if m.Role != role {
				continue
			}
			if pass == 0 {
				if len(m.Content) <= 400 {
					continue
				}
				out[i].Content = truncateRunes(m.Content, 160) +
					"\n[已压缩：原文可经 search_memory 检索证据链（留存前 2000 字符）；大输出另见 .tool-output/ 溢出文件]"
			} else {
				if len(m.Content) <= 2000 {
					continue
				}
				out[i].Content = truncateRunes(m.Content, 400) + "\n[已压缩]"
			}
			total++
		}
		if estimateTokens(out) <= budget {
			break
		}
	}
	return out, total
}

// truncateRunes rune 安全截断（引擎侧与 tools.truncate 的字节语义不同：这里按字符数）。
func truncateRunes(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "…"
}
