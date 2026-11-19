// Package llm 提供OpenAI兼容的对话客户端（支持中转站/本地推理），以及用于演示与联调的 Mock 客户端。
package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"time"
)

// ---------- 对话数据结构（OpenAI Chat Completions 格式） ----------

type ToolCall struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Arguments string `json:"arguments"` // JSON 字符串
}

type Message struct {
	Role             string          `json:"role"` // system / user / assistant / tool
	Content          string          `json:"content"`
	ToolCalls        []ToolCall      `json:"tool_calls,omitempty"`
	ToolCallID       string          `json:"tool_call_id,omitempty"`
	ReasoningContent string          `json:"reasoning_content,omitempty"` // DeepSeek 思维链：回传 API 合约必需（400: must be passed back）
	ThinkingBlocks  []ThinkingBlock `json:"thinking_blocks,omitempty"`   // Anthropic 扩展思维块：带签名回传合约必需
}

// ThinkingBlock Anthropic 扩展思维块（thinking / redacted_thinking）。
// 合约：开启 extended thinking 后，多轮对话回传 assistant 消息必须原样携带历史 thinking 块
// （含签名 signature / 加密 data），且位于 content 块序列最前，否则 400。
type ThinkingBlock struct {
	Type      string `json:"type"` // "thinking" | "redacted_thinking"
	Thinking  string `json:"thinking,omitempty"`
	Signature string `json:"signature,omitempty"`
	Data      string `json:"data,omitempty"` // redacted_thinking 的加密载荷，原样回传
}

// ---------- OpenAI 线上格式适配 ----------
// 严格网关（如火山方舟）要求 tool_calls 为 {"id","type":"function","function":{name,arguments}}
// 嵌套结构；业务层保持平铺，收发时在此转换。

type wireToolCall struct {
	ID       string `json:"id"`
	Type     string `json:"type"`
	Function struct {
		Name      string `json:"name"`
		Arguments string `json:"arguments"`
	} `json:"function"`
}

type wireMessage struct {
	Role             string         `json:"role"`
	Content          string         `json:"content"`
	ToolCalls        []wireToolCall `json:"tool_calls,omitempty"`
	ToolCallID       string         `json:"tool_call_id,omitempty"`
	ReasoningContent string         `json:"reasoning_content,omitempty"`
}

func toWireOpenAI(msgs []Message) []wireMessage {
	out := make([]wireMessage, 0, len(msgs))
	for _, m := range msgs {
		w := wireMessage{Role: m.Role, Content: m.Content, ToolCallID: m.ToolCallID}
	if m.ReasoningContent != "" {
		w.ReasoningContent = m.ReasoningContent // DeepSeek reasoner 合约：历史 assistant 消息必须带回 reasoning_content
	}
		if m.Role == "assistant" && m.Content == "" && len(m.ToolCalls) > 0 {
			w.Content = "" // 纯工具调用轮次保留空 content
		}
		for _, tc := range m.ToolCalls {
			var wt wireToolCall
			wt.ID = tc.ID
			wt.Type = "function"
			wt.Function.Name = tc.Name
			wt.Function.Arguments = tc.Arguments
			w.ToolCalls = append(w.ToolCalls, wt)
		}
		out = append(out, w)
	}
	return out
}

func fromWireOpenAI(w wireMessage) Message {
	m := Message{Role: w.Role, Content: w.Content, ToolCallID: w.ToolCallID, ReasoningContent: w.ReasoningContent}
	for _, tc := range w.ToolCalls {
		m.ToolCalls = append(m.ToolCalls, ToolCall{ID: tc.ID, Name: tc.Function.Name, Arguments: tc.Function.Arguments})
	}
	return m
}

type ToolDef struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	Parameters  map[string]any `json:"parameters"` // JSON Schema
}

type Usage struct {
	PromptTokens     int `json:"prompt_tokens"`
	CompletionTokens int `json:"completion_tokens"`
	TotalTokens      int `json:"total_tokens"`
}

// Client 统一对话接口。
type Client interface {
	// Chat 传入消息与可用工具，返回模型的一条回复（可能带工具调用）。
	Chat(ctx context.Context, model string, messages []Message, tools []ToolDef, temperature float32, maxTokens int) (Message, Usage, error)
}

// ---------- OpenAI 兼容客户端 ----------

type openaiCompat struct {
	baseURL string
	apiKey  string
	http    *http.Client
}

func NewOpenAI(baseURL, apiKey string) Client {
	// 自定义 Transport：IPv4 优先（规避容器内 IPv6 路由导致的 TLS 握手挂起）+ 快速回退 + 代理感知
	dialer := &net.Dialer{
		Timeout:       15 * time.Second,
		KeepAlive:     30 * time.Second,
		FallbackDelay: 300 * time.Millisecond, // Happy Eyeballs 快速回退
	}
	transport := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           dialer.DialContext,
		ForceAttemptHTTP2:     false, // 强制 HTTP/1.1：规避个别网关 h2 流挂起
		MaxIdleConns:          20,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   20 * time.Second,
		ResponseHeaderTimeout: 890 * time.Second, // 推理模型生成可能远超 5 分钟
	}
	return &openaiCompat{
		baseURL: baseURL,
		apiKey:  apiKey,
		http:    &http.Client{Timeout: 900 * time.Second, Transport: transport},
	}
}

type wireReq struct {
	Model       string        `json:"model"`
	Messages    []wireMessage `json:"messages"`
	Tools       []wireTool    `json:"tools,omitempty"`
	Temperature float32       `json:"temperature"`
	MaxTokens   int           `json:"max_tokens"`
}

type wireTool struct {
	Type     string  `json:"type"` // function
	Function ToolDef `json:"function"`
}

type wireResp struct {
	Choices []struct {
		Message wireMessage `json:"message"`
	} `json:"choices"`
	Usage Usage `json:"usage"`
	Error *struct {
		Message string `json:"message"`
	} `json:"error,omitempty"`
}

// withRetry 请求级重试：网络错误/5xx/429 退避重试（LLM 网关偶发抖动）；4xx 参数错误不重试。
// v5.7.5 扩展重试跨度（实证事故）：VM 出口 UDP DNS 丢包/直连 TCP 抖动窗口为分钟级，此前
// 3 次尝试（退避 2s/4s）总跨度 ~40s 全部落在窗口内——s1 正常收口后 s2 首个 LLM 调用即
// lookup i/o timeout×3 阶段失败项目终止。扩至 5 次尝试（退避 2s/5s/10s/20s，累计等待 37s，
// 连同请求耗时总跨度 ~2min）覆盖典型抖动窗口；retryable 仅网络/5xx/429 类，
// 真失败（4xx 参数错误）仍首轮即返不受影响。
func withRetry(ctx context.Context, fn func() (Message, Usage, error)) (Message, Usage, error) {
	var lastErr error
	backoffs := []time.Duration{2 * time.Second, 5 * time.Second, 10 * time.Second, 20 * time.Second}
	for attempt := 0; attempt < len(backoffs)+1; attempt++ {
		if attempt > 0 {
			select {
			case <-time.After(backoffs[attempt-1]):
			case <-ctx.Done():
				return Message{}, Usage{}, ctx.Err()
			}
		}
		msg, usage, err := fn()
		if err == nil {
			return msg, usage, nil
		}
		lastErr = err
		if !retryable(err) {
			return Message{}, Usage{}, err
		}
		log.Printf("[llm] 请求失败（第 %d 次，将重试）: %v", attempt+1, err)
	}
	return Message{}, Usage{}, lastErr
}

func retryable(err error) bool {
	s := err.Error()
	// 响应解析失败/空回复：网关截断或空响应属瞬时故障，重试换一次完整响应（实测 S5 曾因此整阶段中断）
	if strings.Contains(s, "响应解析失败") || strings.Contains(s, "空回复") {
		return true
	}
	return strings.Contains(s, "timeout") || strings.Contains(s, "TLS handshake") ||
		strings.Contains(s, "connection reset") || strings.Contains(s, "EOF") ||
		strings.Contains(s, "broken pipe") || strings.Contains(s, "502") ||
		strings.Contains(s, "503") || strings.Contains(s, "504") || strings.Contains(s, "429") ||
		// 全部 5xx（含 500 InternalServiceError）按网关瞬时故障退避重试：
		// 上游错误格式固定为 "LLM 返回 %d: …"（见 chatOnce），前缀匹配可覆盖 500/501/505-599
		strings.Contains(s, "LLM 返回 5")
}

func (c *openaiCompat) Chat(ctx context.Context, model string, messages []Message, tools []ToolDef, temperature float32, maxTokens int) (Message, Usage, error) {
	out := wireReq{
		Model: model, Messages: toWireOpenAI(messages),
		Temperature: temperature, MaxTokens: maxTokens,
	}
	for _, t := range tools {
		out.Tools = append(out.Tools, wireTool{Type: "function", Function: t})
	}
	body, _ := json.Marshal(out)
	log.Printf("[llm-openai] 请求开始: model=%s msgs=%d tools=%d", model, len(messages), len(tools))
	start := time.Now()
	msg, usage, err := withRetry(ctx, func() (Message, Usage, error) { return c.chatOnce(ctx, body) })
	log.Printf("[llm-openai] 请求结束: 耗时=%.1fs tokens=%d err=%v", time.Since(start).Seconds(), usage.TotalTokens, err)
	return msg, usage, err
}

func (c *openaiCompat) chatOnce(ctx context.Context, body []byte) (Message, Usage, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/chat/completions", bytes.NewReader(body))
	if err != nil {
		return Message{}, Usage{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	if c.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+c.apiKey)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return Message{}, Usage{}, fmt.Errorf("LLM 请求失败: %w", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	if resp.StatusCode >= 300 {
		return Message{}, Usage{}, fmt.Errorf("LLM 返回 %d: %s", resp.StatusCode, truncate(string(raw), 512))
	}
	var wr wireResp
	if err := json.Unmarshal(raw, &wr); err != nil {
		return Message{}, Usage{}, fmt.Errorf("LLM 响应解析失败: %w", err)
	}
	if wr.Error != nil {
		return Message{}, Usage{}, fmt.Errorf("LLM 错误: %s", wr.Error.Message)
	}
	if len(wr.Choices) == 0 {
		return Message{}, Usage{}, fmt.Errorf("LLM 空回复")
	}
	return fromWireOpenAI(wr.Choices[0].Message), wr.Usage, nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "...(截断)"
}

// ---------- Mock 客户端：无 Key 演示全流程用 ----------

type mockClient struct{}

// NewMock 返回脚本化的 Mock 客户端：侦察→记录→产出→收口，循环推进。
func NewMock() Client { return &mockClient{} }

func (m *mockClient) Chat(_ context.Context, _ string, messages []Message, _ []ToolDef, _ float32, _ int) (Message, Usage, error) {
	// 对话指挥室脚本：第一轮演示一次工具调用，随后给文字答复
	if len(messages) > 0 && contains(messages[0].Content, "[[HEAD:chat]]") {
		assistants := 0
		for _, msg := range messages {
			if msg.Role == "assistant" {
				assistants++
			}
		}
		if assistants == 0 {
			b, _ := json.Marshal(map[string]any{"command": "date && uptime", "reason": "对话演示：环境时钟与负载（只读）"})
			return Message{Role: "assistant", ToolCalls: []ToolCall{{
				ID: fmt.Sprintf("mock-chat-%d", time.Now().UnixNano()), Name: "run_command", Arguments: string(b),
			}}}, Usage{TotalTokens: 30}, nil
		}
		return Message{Role: "assistant", Content: "（Mock 演示）真头收到。刚才执行了一次只读检查（结果见执行留痕）。接真实模型后，我会在这里按你的指令直接调用工具实战：查技能、跑侦察、记发现、更新覆盖度——高危动作会先进你的审批队列。"}, Usage{TotalTokens: 66}, nil
	}
	// 统计本轮会话中 assistant 轮次，据此推进脚本
	turns := 0
	for _, msg := range messages {
		if msg.Role == "assistant" {
			turns++
		}
	}
	call := func(name string, args any) Message {
		b, _ := json.Marshal(args)
		return Message{
			Role: "assistant",
			ToolCalls: []ToolCall{{
				ID:        fmt.Sprintf("mock-%d", time.Now().UnixNano()),
				Name:      name,
				Arguments: string(b),
			}},
		}
	}
	var resp Message
	switch {
	case turns == 0:
		resp = call("run_command", map[string]any{
			"command": "id && uname -a && pwd",
			"reason":  "确认执行环境基线（mock 演示）",
		})
	case turns == 1:
		// 演示多工具调用：登记资产 + 覆盖度 + 黑板/战利品（v3.7.2 覆盖新工具面，供评测环与 E2E）
		resp = Message{
			Role: "assistant",
			ToolCalls: []ToolCall{
				{ID: fmt.Sprintf("mock-a-%d", time.Now().UnixNano()), Name: "record_asset",
					Arguments: mustJSON(map[string]any{
						"type": "主机", "value": "mock-target.local",
						"detail": "Mock 阶段产出：目标资产画像（演示数据）",
					})},
				{ID: fmt.Sprintf("mock-c-%d", time.Now().UnixNano()), Name: "update_coverage",
					Arguments: mustJSON(map[string]any{
						"endpoint": "mock-target.local", "vuln_class": "服务指纹", "status": "no_issue_found",
						"notes": "Mock 演示：基线确认无异常",
					})},
				{ID: fmt.Sprintf("mock-fct-%d", time.Now().UnixNano()), Name: "upsert_fact",
					Arguments: mustJSON(map[string]any{
						"key": "mock://demo/panel", "value": "primitive:READ Mock 演示事实（黑板链路自检）",
						"confidence": "tentative", "note": "Mock 演示：黑板写入",
					})},
				{ID: fmt.Sprintf("mock-loot-%d", time.Now().UnixNano()), Name: "record_loot",
					Arguments: mustJSON(map[string]any{
						"type": "credential", "target": "mock-target.local", "masked": "dem***01",
						"source": "Mock 演示", "verified": "unverified",
					})},
			},
		}
	case turns == 2:
		// 记录发现 + 产出实体交付物文件（收口强制要求）
		resp = Message{
			Role: "assistant",
			ToolCalls: []ToolCall{
				{ID: fmt.Sprintf("mock-f-%d", time.Now().UnixNano()), Name: "record_finding",
					Arguments: mustJSON(map[string]any{
						"title": "示例发现（Mock 演示）", "severity": "中",
						"detail":     "该发现由 Mock 客户端生成，用于验证证据链与报告链路。",
						"confidence": "待查",
					})},
				{ID: fmt.Sprintf("mock-w-%d", time.Now().UnixNano()), Name: "write_file",
					Arguments: mustJSON(map[string]any{
						"path":    "deliverables/阶段产出.md",
						"content": "# 本阶段交付物（Mock 演示）\n\n## 摘要\n- Mock 阶段按流程完成。\n\n## 结论\n- 示例发现 1 条（中等，待查）。\n",
					})},
			},
		}
	case turns == 3 && isReportStage(messages):
		resp = call("write_file", map[string]any{
			"path":    "report.md",
			"content": "# 渗透测试报告（Mock 演示）\n\n> 本报告由 Mock 客户端生成，验证报告链路。\n\n## 执行摘要\n\n- 项目运行正常，证据链完整。\n\n## 发现清单\n\n| 编号 | 标题 | 等级 |\n|---|---|---|\n| F-1 | 示例发现（Mock 演示） | 中 |\n",
		})
	default:
		resp = call("complete_stage", map[string]any{
			"summary":      "Mock 演示：本阶段按流程完成侦察、记录与产出。",
			"deliverables": []string{"阶段摘要（mock）", "示例发现 1 条"},
			"confidence":   "演示",
		})
	}
	return resp, Usage{TotalTokens: 42}, nil
}

func isReportStage(messages []Message) bool {
	if len(messages) == 0 {
		return false
	}
	sys := messages[0].Content
	return contains(sys, "[[HEAD:s8]]")
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(s) > 0 && indexOf(s, sub) >= 0)
}

func mustJSON(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
