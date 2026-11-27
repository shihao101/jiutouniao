// v3.3.0 输出治理③：对话链窗口压缩（确定性，零额外 LLM 调用）。
// 参照 pentagi window_compaction 的预算思想与 HackSynth「摘要即状态」的收敛目标，
// 采用确定性存根替换而非 LLM 摘要——工具回执前 2000 字符已在证据链（search_memory 可检索），
// 大输出另有 .tool-output/ 溢出文件，存根只丢「重复上下文」，不丢事实。
package engine

import (
	"encoding/json"
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

// estToolTokens v7.5.0（A3）：工具面 schema 估算——零 usage 兜底入账时工具定义也占输入
// 预算（PentAGI estimateToolTokens 同口径），漏算会系统性低估 6-8K est tok/次。
func estToolTokens(defs []llm.ToolDef) int {
	total := 0
	for _, d := range defs {
		s := d.Name + d.Description
		if b, err := json.Marshal(d.Parameters); err == nil {
			s += string(b)
		}
		total += 16 + estStringTokens(s)
	}
	return total
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

// compactMsgsWithArchiveFloor v7.6.0（C1 集中式压缩）：触发线=trigger（estimate>trigger 才压），
// 裁剪目标=floor（压到 ≤floor 为止）——floor<trigger 即「单次加深裁剪」，减少触发频次
// = 减少 cache_reset 次数（实测压缩存根就地改写历史破坏前缀缓存，3.5M 全价重发，实测报告 §C1）。
func compactMsgsWithArchiveFloor(msgs []llm.Message, trigger, floor, keepRecent int, archiveToolReceipt func(stage, content string) string) ([]llm.Message, int) {
	if floor <= 0 || floor > trigger {
		floor = trigger
	}
	if trigger <= 0 || len(msgs) <= 3 || estimateTokens(msgs) <= trigger {
		return msgs, 0
	}
	return compactToFloor(msgs, floor, keepRecent, archiveToolReceipt)
}

func compactMsgsWithArchive(msgs []llm.Message, budget, keepRecent int, archiveToolReceipt func(stage, content string) string) ([]llm.Message, int) {
	if budget <= 0 || len(msgs) <= 3 || estimateTokens(msgs) <= budget {
		return msgs, 0
	}
	return compactToFloor(msgs, budget, keepRecent, archiveToolReceipt)
}

func compactToFloor(msgs []llm.Message, floor, keepRecent int, archiveToolReceipt func(stage, content string) string) ([]llm.Message, int) {
	budget := floor
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
	// v7.7.0 P4 技能优先压缩（方案 §一.P4）：pass-0 候选按体积降序处理——技能全文回执
	//（【技能 前缀，21-42k 级）与大回执先裁，单次压缩收益最大化、触发频次下降；小回执与
	// 近期消息后动。存根保留技能 id（重载免费，知识无损——库在磁盘）。E1 混合摘要与
	// receipt 归档语义不变。
	for pass, role := range []string{"tool", "assistant"} {
		limit := len(out) - keepRecent
		if pass == 0 && estimateTokens(out) > budget {
			// 候选收集（>400 字的工具回执，保护区外）按体积降序处理
			type cand struct{ idx, size int }
			cands := make([]cand, 0, limit/2)
			for i := 2; i < limit; i++ {
				if out[i].Role == "tool" && len(out[i].Content) > 400 {
					cands = append(cands, cand{i, len(out[i].Content)})
				}
			}
			for a := 1; a < len(cands); a++ { // 插入排序降序（候选量级小，避免引入 sort 依赖变动）
				for b2 := a; b2 > 0 && cands[b2].size > cands[b2-1].size; b2-- {
					cands[b2], cands[b2-1] = cands[b2-1], cands[b2]
				}
			}
			for _, c := range cands {
				if estimateTokens(out) <= budget {
					break
				}
				i := c.idx
				m := out[i]
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
				total++
			}
			if estimateTokens(out) <= budget {
				continue // pass-0 已达标，跳过 pass-1
			}
		}
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

// compactHybrid v7.5.0（E1 混合压缩）：窗口压缩存根化后，把被存根化的中段内容拼成语料
// 交给 summarize 回调（aux 模型）生成 ≤8KB 结构化摘要，作为一条 user 消息插入保护段之前——
// 中段语义由「摘要 + receipt 指针」双通道承接，治纯存根丢语义诱发的重复检索/重跑。
// 结构安全：只**追加**一条 user 消息，不移动/删除既有消息（tool 配对契约不破坏）；
// summarize 为 nil 或语料过短或摘要失败时返回 ""（零变化，纯存根口径）。
func compactHybrid(msgs []llm.Message, keepRecent int, summarize func(corpus string) string) string {
	if summarize == nil || len(msgs) <= keepRecent+3 {
		return ""
	}
	if keepRecent < 4 {
		keepRecent = 4
	}
	midEnd := len(msgs) - keepRecent
	if midEnd <= 2 {
		return ""
	}
	var parts []string
	budget := 32 * 1024
	used := 0
	for _, m := range msgs[2:midEnd] {
		c := strings.TrimSpace(m.Content)
		if c == "" || strings.HasPrefix(c, "♻ [回放拦截]") || strings.HasPrefix(c, "[已裁剪") {
			continue
		}
		if len(c) > 600 {
			c = truncateRunes(c, 600)
		}
		if used+len(c) > budget {
			break
		}
		parts = append(parts, c)
		used += len(c)
	}
	if len(parts) == 0 {
		return ""
	}
	corpus := strings.Join(parts, "\n---\n")
	if len(corpus) < 2000 {
		return "" // 中段本就单薄，摘要收益不抵调用成本
	}
	sum := summarize(corpus)
	if strings.TrimSpace(sum) == "" {
		return ""
	}
	return "[历史摘要（混合压缩）] " + truncateRunes(strings.TrimSpace(sum), 8*1024) +
		"\n（以上为已被存根化的中段过程的结构化摘要；单条原文可按 receipt:<id> 经 search_memory 检索回）"
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
