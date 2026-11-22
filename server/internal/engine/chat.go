package engine

import (
	"encoding/json"
	"fmt"
	"strings"
	"sync"

	"jiutouniao/internal/llm"
	"jiutouniao/internal/store"
)

// ChatSessions 对话指挥室（参考 PentestGPT 对话引导 + strix 交互式指挥）：
// 真头（主控）人格与用户对话，可调用与阶段头完全相同的工具面——
// 命令照样过审批矩阵、照样全量留证（证据 stage=chat），可跨阶段指挥。
type ChatSessions struct {
	orch *Orchestrator
	mu   sync.Mutex
}

const chatHistoryCap = 60

func newChatSessions(o *Orchestrator) *ChatSessions {
	return &ChatSessions{orch: o}
}

// loadFromStore 从 bbolt 读取会话（持久化：任务结束后仍可继续提问，重启不丢）。
func (c *ChatSessions) loadFromStore(key string) []llm.Message {
	if raw, ok := c.orch.store.LoadChat(key); ok {
		var msgs []llm.Message
		if err := json.Unmarshal(raw, &msgs); err == nil {
			return msgs
		}
	}
	return nil
}

func (c *ChatSessions) saveToStore(key string, msgs []llm.Message) {
	if raw, err := json.Marshal(msgs); err == nil {
		_ = c.orch.store.SaveChat(key, raw)
	}
}

// ---- v5.5.0（修复方案 H）：轮次耗尽的挂起运行链 ----
// 原实现轮次耗尽只回一句「已暂停」，中间的工具调用/结果链随即丢失（promised 延续是假的）。
// 现将完整消息链（system+上下文包+历史+本轮全部 tool call/结果）持久化到独立键，
// 用户下一条消息自动从断点续跑；正常完成后清除挂起链。
func pendingRunKey(key string) string { return "chatrun:" + key }

func (c *ChatSessions) loadPendingRun(key string) ([]llm.Message, bool) {
	raw, ok := c.orch.store.LoadChat(pendingRunKey(key))
	if !ok {
		return nil, false
	}
	var msgs []llm.Message
	if err := json.Unmarshal(raw, &msgs); err != nil || len(msgs) == 0 {
		return nil, false
	}
	// v6.0.1：实质判定——链中必须含真实可续跑动作（assistant 工具轮或 tool 结果）。
	// 纯 user 堆叠链是空回复误挂起的残骸，无动作可续：清键后按新轮次处理（用户历史
	// 消息仍在会话 hist 中，不丢失）。
	for _, m := range msgs {
		if (m.Role == "assistant" && len(m.ToolCalls) > 0) || m.Role == "tool" {
			return msgs, true
		}
	}
	c.clearPendingRun(key)
	return nil, false
}

func (c *ChatSessions) savePendingRun(key string, msgs []llm.Message) {
	if raw, err := json.Marshal(msgs); err == nil {
		_ = c.orch.store.SaveChat(pendingRunKey(key), raw)
	}
}

func (c *ChatSessions) clearPendingRun(key string) {
	_ = c.orch.store.DeleteChat(pendingRunKey(key))
}

// Turn 处理一轮对话；projectID 为空时进入咨询模式（禁用工具）。
// 返回助手最终回复文本。
func (c *ChatSessions) Turn(projectID, userMsg string) (string, error) {
	key := projectID
	if key == "" {
		key = "_global"
	}
	// 用户消息先落执行流（修复：LLM 失败时用户消息凭空消失，表现为「发了没反应」）
	if projectID != "" {
		// v5.6.1（审计 RunB#15）：执行流副本脱敏——用户误粘贴凭据不落明文（LLM 历史保真）
		_, _ = c.orch.store.AddStream(projectID, &store.StreamRecord{Kind: "msg", Role: "user", Stage: "chat", Text: truncateText(maskSensitiveText(userMsg), 2000)})
	}
	c.mu.Lock()
	hist := append([]llm.Message{}, c.loadFromStore(key)...)
	c.mu.Unlock()

	orch := c.orch
	sys := strings.Join([]string{
		"[[HEAD:chat]]",
		orch.coreLoop,
		orch.heads["main"].Body,
		"\n## 对话模式守则\n" +
			"- 你现在处于对话指挥室：用户可能下指令、问状态、要建议或要求直接动手。\n" +
			"- 涉及执行：能自己用工具（run_command/write_file/record_*/update_coverage/load_skill/search_memory 等）就直接做，并把关键过程讲给用户听。\n" +
			"- 高危命令照样进审批队列，被拒绝时向用户解释原因与替代方案。\n" +
			"- 回答精炼、中文；结论标注置信度；发现即时 record_finding。\n" +
			"- 用户问「现在什么情况」时，先 search_memory 再回答。",
	}, "\n\n")

	// v5.5.0（修复方案 H）：存在挂起运行链（上轮轮次耗尽）时从断点续跑——
	// 完整保留上一轮的 system/上下文包/工具调用与结果，不重放已执行的工具（它们只是历史消息）。
	var msgs []llm.Message
	resumed := false
	if projectID != "" {
		if pending, ok := c.loadPendingRun(key); ok {
			msgs = pending
			resumed = true
		}
	}
	// v6.0.1：本轮执行状态追踪——空回复（无文字无工具调用）与真轮次耗尽分离处置，
	// didToolWork 区分「有真实动作可挂起」与「零动作无可续跑」。
	roundsRun := 0
	emptyResp := false
	emptyRetried := false
	didToolWork := false
	if msgs == nil {
		msgs = []llm.Message{{Role: "system", Content: sys}}
		if projectID != "" {
			if p, err := orch.store.GetProject(projectID); err == nil {
				msgs = append(msgs, llm.Message{Role: "user", Content: orch.buildContextPack(p, "chat")})
			}
			toolDefs := orch.toolDefs()
			_ = toolDefs
		} else {
			msgs = append(msgs, llm.Message{
				Role:    "user",
				Content: "（咨询模式：未选择项目，工具不可用。请基于方法论与经验回答，建议用户先创建项目。）",
			})
		}
		msgs = append(msgs, hist...)
	}
	if resumed {
		if projectID != "" {
			_, _ = orch.store.AddStream(projectID, &store.StreamRecord{Kind: "msg", Role: "assistant", Stage: "chat",
				Text: "⏯ 检测到上轮轮次耗尽的挂起执行链，本轮从断点续跑（已执行动作不重放）。"})
		}
	}
	msgs = append(msgs, llm.Message{Role: "user", Content: userMsg})

	// 有项目 → 带工具的执行循环（最多 8 轮内部工具轮次后必须给文字答复）
	var tools []llm.ToolDef
	if projectID != "" {
		tools = orch.toolDefs()
	}
	final := ""
	maxRounds := c.orch.cfg.Engine.ChatToolRounds
	if maxRounds <= 0 {
		maxRounds = 24
	}
	for round := 0; round < maxRounds; round++ {
		roundsRun = round + 1
		chatClient, chatModel := orch.LLM(), orch.cfg.LLM.Model
		if projectID != "" {
			if p, perr := orch.store.GetProject(projectID); perr == nil {
				chatClient, chatModel = orch.clientFor(p)
			}
		}
		chatCtx := orch.chatCtx(projectID) // v3.4.0：可熔断（Kill 级联取消对话轮）
		defer orch.chatTurnDone(projectID)
		resp, usage, err := chatClient.Chat(chatCtx, chatModel, msgs, tools, orch.cfg.LLM.Temperature, orch.cfg.LLM.MaxTokens)
		if err != nil {
			orch.logChatErr(projectID, err)
			// 失败也要在执行流可见（修复：错误只走 toast 一闪而过，用户以为智能体不执行）
			if projectID != "" {
				_, _ = orch.store.AddStream(projectID, &store.StreamRecord{Kind: "msg", Role: "assistant", Stage: "chat",
					Text: "⚠ 本轮回复失败：" + truncateText(err.Error(), 300) + "\n\n你的消息已收到。常见原因：模型服务暂时不可用/网络断连。请稍后重发，或在「设置」检查模型连通性。"})
			}
			return "", err
		}
		orch.accountUsageChat(projectID, usage)
		if len(resp.ToolCalls) == 0 {
			if strings.TrimSpace(resp.Content) == "" {
				// v6.0.1：空回复（无文字无工具调用）——常见于思维型模型把 max_tokens 全部耗在
				// 思维链后被截断（finish_reason=length，content 空）。首轮允许一次引导重试，
				// 仍空则走诊断路径。此前实现把空回复误判成「轮次耗尽」挂起（实证某历史任务
				// 连续 7 轮挂起/续跑空转，挂起链退化为纯 user 堆叠，用户误以为消息未被接收）。
				if !emptyRetried {
					emptyRetried = true
					msgs = append(msgs, llm.Message{Role: "user", Content: "（上一条你返回了空内容。请直接给出文字结论或发起工具调用，不要只输出思考过程。）"})
					continue
				}
				emptyResp = true
			}
			final = resp.Content
			break
		}
		msgs = append(msgs, resp)
		for _, tc := range resp.ToolCalls {
			didToolWork = true
			result := orch.dispatchChat(projectID, tc)
			msgs = append(msgs, llm.Message{Role: "tool", ToolCallID: tc.ID, Content: result})
		}
		continue
	}
	if final == "" {
		if projectID != "" {
			switch {
			case !didToolWork && !resumed:
				// v6.0.1：空回复且本轮零动作、无旧挂起链——不挂起（无可续跑状态），给可行动诊断。
				final = fmt.Sprintf("（模型连续返回空回复：无文字结论、无工具调用，本轮未产生任何动作，执行链未挂起。常见原因：思维型模型把 max_tokens（当前 %d）全部耗在思维链后被截断，或服务端异常。建议在「设置」调大 max_tokens 或更换非思维模型后重发；你的消息已在会话历史中，无需重复粘贴。）", orch.cfg.LLM.MaxTokens)
			default:
				// v5.5.0（修复方案 H）：轮次耗尽/有动作的空回复 → 持久化完整运行链，下一条用户消息自动续跑。
				c.mu.Lock()
				c.savePendingRun(key, msgs)
				c.mu.Unlock()
				switch {
				case emptyResp && !didToolWork:
					final = "（模型返回空回复（无文字结论、无工具调用），上轮挂起链已保留并叠加你的新消息。你直接发送下一条消息即可从断点续跑；若连续空回复，请在「设置」调大 max_tokens 或更换非思维模型。）"
				case emptyResp:
					final = fmt.Sprintf("（模型第 %d 轮返回空回复，本轮已执行的工具动作链已挂起保存。你直接发送下一条消息即可从断点续跑；若连续空回复，请在「设置」调大 max_tokens 或更换非思维模型。）", roundsRun)
				default:
					final = fmt.Sprintf("（内部工具轮次达到上限（%d 轮），本轮执行链已挂起保存。你直接发送下一条消息即可从断点续跑——已执行的工具调用不会重放，无需重复背景。已有动作与结论见执行流。）", maxRounds)
				}
			}
		} else {
			final = fmt.Sprintf("（内部工具轮次达到上限（%d 轮），已暂停本轮执行；已有动作与结论见执行流。继续对话将在此基础上延续。）", maxRounds)
		}
	} else if projectID != "" {
		c.mu.Lock()
		c.clearPendingRun(key) // 正常完成：清除可能存在的挂起链
		c.mu.Unlock()
	}

	// 落历史（持久化）
	c.mu.Lock()
	h := append(hist, llm.Message{Role: "user", Content: userMsg}, llm.Message{Role: "assistant", Content: final})
	if len(h) > chatHistoryCap {
		h = h[len(h)-chatHistoryCap:]
	}
	c.saveToStore(key, h)
	c.mu.Unlock()

	// 对话轮写入执行流（统一时间线：前端单一流数据源；用户消息已在开工时先落，此处补助手回复）
	if projectID != "" {
		_, _ = c.orch.store.AddStream(projectID, &store.StreamRecord{Kind: "msg", Role: "assistant", Stage: "chat", Text: truncateText(maskSensitiveText(final), 4000)})
	}

	return final, nil
}

// History 返回历史（前端展示用）。
func (c *ChatSessions) History(projectID string) []llm.Message {
	key := projectID
	if key == "" {
		key = "_global"
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.loadFromStore(key)
}

// Reset 清空会话。
func (c *ChatSessions) Reset(projectID string) {
	key := projectID
	if key == "" {
		key = "_global"
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	_ = c.orch.store.DeleteChat(key)
	c.clearPendingRun(key) // v5.5.0：会话重置同时清除挂起运行链
}

var _ = fmt.Sprintf
