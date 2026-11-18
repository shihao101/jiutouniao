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
	return msgs, true
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
			final = resp.Content
			break
		}
		msgs = append(msgs, resp)
		for _, tc := range resp.ToolCalls {
			result := orch.dispatchChat(projectID, tc)
			msgs = append(msgs, llm.Message{Role: "tool", ToolCallID: tc.ID, Content: result})
		}
		continue
	}
	if final == "" {
		if projectID != "" {
			// v5.5.0（修复方案 H）：轮次耗尽 → 持久化完整运行链，下一条用户消息自动续跑。
			c.mu.Lock()
			c.savePendingRun(key, msgs)
			c.mu.Unlock()
			final = fmt.Sprintf("（内部工具轮次达到上限（%d 轮），本轮执行链已挂起保存。你直接发送下一条消息即可从断点续跑——已执行的工具调用不会重放，无需重复背景。已有动作与结论见执行流。）", maxRounds)
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
