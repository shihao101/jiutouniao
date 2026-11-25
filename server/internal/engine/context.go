// v3.3.0 输出治理③：对话链窗口压缩（确定性，零额外 LLM 调用）。
// 参照 pentagi window_compaction 的预算思想与 HackSynth「摘要即状态」的收敛目标，
// 采用确定性存根替换而非 LLM 摘要——工具回执前 2000 字符已在证据链（search_memory 可检索），
// 大输出另有 .tool-output/ 溢出文件，存根只丢「重复上下文」，不丢事实。
package engine

import (
	"fmt"
	"strings"

	"jiutouniao/internal/llm"
)

// estimateTokens 估算消息链 token 量：CJK ≈ 1 token/字，其余 ≈ 1 token/4 字符（取保守高估）。
func estimateTokens(msgs []llm.Message) int {
	total := 0
	for _, m := range msgs {
		total += 12 + estStringTokens(m.Content)
		// v5.9.0（方案 P1-4）：ToolCalls 参数计入估算——此前只算 Content，带大参数的
		// 工具调用轮（write_file 长内容/store_credential）实际 token 远超估算，压缩触发过晚。
		for _, tc := range m.ToolCalls {
			total += 24 + estStringTokens(tc.Arguments)
		}
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
//
// v5.5.0 可恢复压缩（修复方案 G）：archiveToolReceipt 非 nil 时，被压缩的工具回执原文先经
// 回调归档（落 store.receipts 桶），存根携带 receipt id——search_memory query="receipt:<id>"
// 可取回原文，压缩不再不可逆；回调缺失（单测/无 store 场景）保持旧语义。
func compactMsgs(msgs []llm.Message, budget, keepRecent int) ([]llm.Message, int) {
	return compactMsgsWithArchive(msgs, budget, keepRecent, nil)
}

func compactMsgsWithArchive(msgs []llm.Message, budget, keepRecent int, archiveToolReceipt func(stage, content string) string) ([]llm.Message, int) {
	if budget <= 0 || len(msgs) <= 3 || estimateTokens(msgs) <= budget {
		return msgs, 0
	}
	if keepRecent < 4 {
		keepRecent = 4
	}
	// 与消息同序的 stage 标注（用于归档归属）：runStage 以 [[HEAD:<id>]] 系统消息开头标注当前阶段。
	stage := ""
	for _, m := range msgs {
		if m.Role == "system" && strings.HasPrefix(m.Content, "[[HEAD:") {
			if j := strings.Index(m.Content[7:], "]]"); j >= 0 {
				stage = m.Content[7 : 7+j]
			}
			break
		}
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
				if archiveToolReceipt != nil {
					if rid := archiveToolReceipt(stage, m.Content); rid != "" {
						out[i].Content = truncateRunes(m.Content, 160) +
							fmt.Sprintf("\n[已压缩 receipt=%s：原文已归档，search_memory query=\"receipt:%s\" 可取回全文；大输出另见 .tool-output/ 溢出文件]", rid, rid)
						total++
						continue
					}
				}
				out[i].Content = truncateRunes(m.Content, 160) +
					"\n[已压缩：原文可经 search_memory 检索证据链（留存前 2000 字符）；大输出另见 .tool-output/ 溢出文件]"
			} else {
				if len(m.Content) <= 2000 {
					continue
				}
				// v7.1.0 P5（方案 §3.1 A5）：压缩前助手消息原文同样经回调归档（与工具回执同通道，
				// receipt:<id> 可检索）——计划意图与分析过程不再随压缩不可逆丢失（三处审计重复指出的缺口）。
				if archiveToolReceipt != nil {
					if rid := archiveToolReceipt(stage, m.Content); rid != "" {
						out[i].Content = truncateRunes(m.Content, 400) +
							fmt.Sprintf("\n[已压缩 receipt=%s：压缩前分析原文已归档，search_memory query=\"receipt:%s\" 可取回]", rid, rid)
						total++
						continue
					}
				}
				out[i].Content = truncateRunes(m.Content, 400) + "\n[已压缩]"
			}
			total++
		}
		if estimateTokens(out) <= budget {
			break
		}
	}
	// v7.1.0 E4'（确定性兜底，零 LLM 调用）：两遍压缩后仍超预算 → 紧急裁剪模式——
	// 按最旧优先把中段 tool 内容置 stub、超长 assistant 再截半，预算保证单调收敛；
	// 替代旧「压无可压即返回超预算链 → 上游 4xx → 项目 failed」的失败路径（runtime-audit R2 尾巴）。
	if estimateTokens(out) > budget {
		for i := 2; i < len(out)-keepRecent && estimateTokens(out) > budget; i++ {
			// 已带归档指针的存根（receipt=…）不得再裁——那是原文的唯一可检索指针（P5 不变量）
			alreadyArchived := strings.Contains(out[i].Content, "[已压缩 receipt=")
			switch out[i].Role {
			case "tool":
				if len(out[i].Content) > 0 && !alreadyArchived && !strings.HasSuffix(out[i].Content, "（预算紧急裁剪）]") {
					out[i].Content = "[已裁剪（预算紧急裁剪）]"
					total++
				}
			case "assistant":
				if len(out[i].Content) > 200 && !alreadyArchived && !strings.HasSuffix(out[i].Content, "（预算紧急裁剪）]") {
					out[i].Content = truncateRunes(out[i].Content, 200) + "\n[已裁剪（预算紧急裁剪）]"
					total++
				}
			}
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

// headTail v5.6.0 头尾保留截断：技能检索场景的正文裁剪——尾部常含工具兼容/误报排除/
// Execution Profile 补遗，纯头部截断会把它们丢掉（审计实证的能力损失点）。
// 中段以省略标记提示精确 load_skill 可取全文。
func headTail(s string, head, tail int) string {
	r := []rune(s)
	if len(r) <= head+tail+40 {
		return s
	}
	return string(r[:head]) + fmt.Sprintf("\n…[中段省略 %d 字符；精确 load_skill(id) 载入全文]…\n", len(r)-head-tail) + string(r[len(r)-tail:])
}
