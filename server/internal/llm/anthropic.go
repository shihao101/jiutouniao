package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// anthropicClient Anthropic Messages API 协议客户端（兼容 Claude 官方与各类 Anthropic 协议网关）。
//
// 协议要点：
//   - system 独立于 messages，放顶层 system 字段
//   - 工具定义: {name, description, input_schema}；模型发起工具调用为 content 块 {type:"tool_use",id,name,input}
//   - 工具结果以 user 消息回传: {type:"tool_result", tool_use_id, content}
//   - max_tokens 必填；鉴权头 x-api-key + anthropic-version
//   - extended thinking：响应中的 thinking/redacted_thinking 块被捕获进 Message.ThinkingBlocks，
//     下一轮按原顺序带签名回传（Anthropic 400 合约：missing thinking block with signature）。
//     注意：当前客户端不主动开启 thinking 参数；若未来启用需同时满足 temperature=1 等约束
type anthropicClient struct {
	baseURL string
	apiKey  string
	http    *http.Client
}

func NewAnthropic(baseURL, apiKey string) Client {
	dialer := &net.Dialer{
		Timeout:       15 * time.Second,
		KeepAlive:     30 * time.Second,
		FallbackDelay: 300 * time.Millisecond,
	}
	transport := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           dialer.DialContext,
		ForceAttemptHTTP2:     false,
		MaxIdleConns:          20,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   20 * time.Second,
		ResponseHeaderTimeout: 890 * time.Second,
	}
	return &anthropicClient{
		baseURL: strings.TrimRight(baseURL, "/"),
		apiKey:  apiKey,
		http:    &http.Client{Timeout: 900 * time.Second, Transport: transport},
	}
}

// ---------- Anthropic 线上格式 ----------

type aBlock struct {
	Type string `json:"type"` // text / tool_use / tool_result
	Text string `json:"text,omitempty"`

	// tool_use
	ID    string         `json:"id,omitempty"`
	Name  string         `json:"name,omitempty"`
	Input map[string]any `json:"input,omitempty"`

	// tool_result
	ToolUseID string `json:"tool_use_id,omitempty"`
	Content   string `json:"content,omitempty"`

	// thinking / redacted_thinking（extended thinking 合约：历史块必须原样回传）
	Thinking  string `json:"thinking,omitempty"`
	Signature string `json:"signature,omitempty"`
	Data      string `json:"data,omitempty"` // redacted_thinking 加密载荷
}

type aMessage struct {
	Role    string   `json:"role"` // user / assistant
	Content []aBlock `json:"content"`
}

type aToolDef struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	InputSchema map[string]any `json:"input_schema"`
}

type aReq struct {
	Model       string     `json:"model"`
	MaxTokens   int        `json:"max_tokens"`
	Temperature float32    `json:"temperature,omitempty"`
	System      string     `json:"system,omitempty"`
	Messages    []aMessage `json:"messages"`
	Tools       []aToolDef `json:"tools,omitempty"`
}

type aResp struct {
	Content    []aBlock `json:"content"`
	StopReason string   `json:"stop_reason"` // end_turn / tool_use / max_tokens
	Usage      struct {
		InputTokens  int `json:"input_tokens"`
		OutputTokens int `json:"output_tokens"`
	} `json:"usage"`
	Error *struct {
		Type    string `json:"type"`
		Message string `json:"message"`
	} `json:"error,omitempty"`
}

// toWireAnthropic 业务消息 → Anthropic 格式：
// system 抽离；连续 tool 消息合并为一条带 tool_result 块的 user 消息。
func toWireAnthropic(msgs []Message) (system string, out []aMessage) {
	var sb strings.Builder
	flushToolResults := func(results []aBlock) {
		if len(results) > 0 {
			out = append(out, aMessage{Role: "user", Content: results})
			results = nil
		}
	}
	var pending []aBlock
	for _, m := range msgs {
		switch m.Role {
		case "system":
			if sb.Len() > 0 {
				sb.WriteString("\n\n")
			}
			sb.WriteString(m.Content)
		case "user":
			flushToolResults(pending)
			pending = nil
			out = append(out, aMessage{Role: "user", Content: []aBlock{{Type: "text", Text: m.Content}}})
		case "assistant":
			flushToolResults(pending)
			pending = nil
			am := aMessage{Role: "assistant"}
			// extended thinking 合约：thinking 块必须在 assistant content 序列最前，按原顺序带签名回传
			for _, tb := range m.ThinkingBlocks {
				am.Content = append(am.Content, aBlock{Type: tb.Type, Thinking: tb.Thinking, Signature: tb.Signature, Data: tb.Data})
			}
			if strings.TrimSpace(m.Content) != "" {
				am.Content = append(am.Content, aBlock{Type: "text", Text: m.Content})
			}
			for _, tc := range m.ToolCalls {
				input := map[string]any{}
				_ = json.Unmarshal([]byte(tc.Arguments), &input)
				am.Content = append(am.Content, aBlock{Type: "tool_use", ID: tc.ID, Name: tc.Name, Input: input})
			}
			out = append(out, am)
		case "tool":
			pending = append(pending, aBlock{Type: "tool_result", ToolUseID: m.ToolCallID, Content: m.Content})
		}
	}
	flushToolResults(pending)
	return sb.String(), out
}

func (c *anthropicClient) Chat(ctx context.Context, model string, messages []Message, tools []ToolDef, temperature float32, maxTokens int) (Message, Usage, error) {
	system, msgs := toWireAnthropic(messages)
	if maxTokens <= 0 {
		maxTokens = 4096
	}
	req := aReq{Model: model, MaxTokens: maxTokens, Temperature: temperature, System: system, Messages: msgs}
	for _, t := range tools {
		req.Tools = append(req.Tools, aToolDef{Name: t.Name, Description: t.Description, InputSchema: t.Parameters})
	}
	body, _ := json.Marshal(req)
	return withRetry(ctx, func() (Message, Usage, error) { return c.chatOnce(ctx, body) })
}

func (c *anthropicClient) chatOnce(ctx context.Context, body []byte) (Message, Usage, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/v1/messages", bytes.NewReader(body))
	if err != nil {
		return Message{}, Usage{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-api-key", c.apiKey)
	req.Header.Set("anthropic-version", "2023-06-01")
	resp, err := c.http.Do(req)
	if err != nil {
		return Message{}, Usage{}, fmt.Errorf("LLM 请求失败: %w", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	if resp.StatusCode >= 300 {
		return Message{}, Usage{}, fmt.Errorf("LLM 返回 %d: %s", resp.StatusCode, truncate(string(raw), 512))
	}
	var ar aResp
	if err := json.Unmarshal(raw, &ar); err != nil {
		return Message{}, Usage{}, fmt.Errorf("LLM 响应解析失败: %w", err)
	}
	if ar.Error != nil {
		return Message{}, Usage{}, fmt.Errorf("LLM 错误: %s", ar.Error.Message)
	}
	m := Message{Role: "assistant"}
	for _, b := range ar.Content {
		switch b.Type {
		case "text":
			if m.Content != "" {
				m.Content += "\n"
			}
			m.Content += b.Text
		case "tool_use":
			args, _ := json.Marshal(b.Input)
			m.ToolCalls = append(m.ToolCalls, ToolCall{ID: b.ID, Name: b.Name, Arguments: string(args)})
		case "thinking", "redacted_thinking":
			// 扩展思维块：完整捕获（含签名/加密载荷），供下一轮回传（Anthropic 合约）
			m.ThinkingBlocks = append(m.ThinkingBlocks, ThinkingBlock{Type: b.Type, Thinking: b.Thinking, Signature: b.Signature, Data: b.Data})
		}
	}
	if len(ar.Content) == 0 {
		return Message{}, Usage{}, fmt.Errorf("LLM 空回复（stop_reason=%s）", ar.StopReason)
	}
	u := Usage{PromptTokens: ar.Usage.InputTokens, CompletionTokens: ar.Usage.OutputTokens}
	u.TotalTokens = u.PromptTokens + u.CompletionTokens
	return m, u, nil
}
