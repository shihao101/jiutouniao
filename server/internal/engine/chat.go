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

// Turn 处理一轮对话；projectID 为空时进入咨询模式（禁用工具）。
// 返回助手最终回复文本。
func (c *ChatSessions) Turn(projectID, userMsg string) (string, error) {
	key := projectID
	if key == "" {
		key = "_global"
	}
	// 用户消息先落执行流（修复：LLM 失败时用户消息凭空消失，表现为「发了没反应」）
	if projectID != "" {
		_, _ = c.orch.store.AddStream(projectID, &store.StreamRecord{Kind: "msg", Role: "user", Stage: "chat", Text: truncateText(userMsg, 2000)})
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

	msgs := []llm.Message{{Role: "system", Content: sys}}
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
		final = fmt.Sprintf("（内部工具轮次达到上限（%d 轮），已暂停本轮执行；已有动作与结论见执行流。继续对话将在此基础上延续。）", maxRounds)
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
		_, _ = c.orch.store.AddStream(projectID, &store.StreamRecord{Kind: "msg", Role: "assistant", Stage: "chat", Text: truncateText(final, 4000)})
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
}

var _ = fmt.Sprintf
