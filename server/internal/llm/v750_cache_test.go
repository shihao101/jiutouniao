// v7.5.0（B1/A4）llm 层行为测试：
// ① Anthropic CacheControl=true → system 块数组带 cache_control、末位工具带标记；
//    false → system 保持 string（严格网关零风险）。
// ② OpenAI 兼容路径 prompt_tokens_details.cached_tokens → Usage.CacheReadTokens（A4 分账数据源）。
package llm

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func anthropicProbe(t *testing.T, cacheOn bool) map[string]any {
	t.Helper()
	var captured map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &captured)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"model":"m","content":[{"type":"text","text":"ok"}],"stop_reason":"end_turn","usage":{"input_tokens":10,"output_tokens":2}}`))
	}))
	defer srv.Close()
	cli := NewAnthropicWithOptions(srv.URL, "k", Options{CacheControl: cacheOn, MaxRetries: -1})
	long := strings.Repeat("系统提示词", 600) // >2048 字节
	msgs := []Message{{Role: "system", Content: long}, {Role: "user", Content: "hi"}}
	tools := []ToolDef{
		{Name: "t1", Description: "工具一"},
		{Name: "t2", Description: "工具二"},
	}
	if _, _, err := cli.Chat(context.Background(), "m", msgs, tools, 0.2, 64); err != nil {
		t.Fatalf("Chat: %v", err)
	}
	return captured
}

func TestV750B1CacheControlMarkers(t *testing.T) {
	captured := anthropicProbe(t, true)
	// system：应为块数组且末块带 ephemeral 标记
	sys, ok := captured["system"].([]any)
	if !ok {
		t.Fatalf("CacheControl=true 时 system 应为块数组，got %T", captured["system"])
	}
	last := sys[len(sys)-1].(map[string]any)
	if last["cache_control"].(map[string]any)["type"] != "ephemeral" {
		t.Fatalf("system 末块应带 ephemeral 标记")
	}
	// 工具：仅末位带标记
	tools := captured["tools"].([]any)
	if tools[0].(map[string]any)["cache_control"] != nil {
		t.Fatalf("首位工具不应带标记")
	}
	if tools[len(tools)-1].(map[string]any)["cache_control"].(map[string]any)["type"] != "ephemeral" {
		t.Fatalf("末位工具应带 ephemeral 标记")
	}
}

func TestV750B1CacheControlOffKeepsString(t *testing.T) {
	captured := anthropicProbe(t, false)
	if _, ok := captured["system"].(string); !ok {
		t.Fatalf("CacheControl=false 时 system 应保持 string（默认关，严格网关零风险）")
	}
	tools := captured["tools"].([]any)
	for _, tt := range tools {
		if tt.(map[string]any)["cache_control"] != nil {
			t.Fatalf("关闭时任何工具不应带标记")
		}
	}
}

func TestV750A4OpenAICachedTokensParsed(t *testing.T) {
	var captured map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &captured)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"model":"m","choices":[{"message":{"role":"assistant","content":"ok"}}],
			"usage":{"prompt_tokens":100,"completion_tokens":5,"total_tokens":105,
			"prompt_tokens_details":{"cached_tokens":80}}}`))
	}))
	defer srv.Close()
	cli := NewOpenAIWithOptions(srv.URL, "k", Options{MaxRetries: -1})
	_, usage, err := cli.Chat(context.Background(), "m",
		[]Message{{Role: "user", Content: "hi"}}, nil, 0.2, 64)
	if err != nil {
		t.Fatalf("Chat: %v", err)
	}
	if usage.CacheReadTokens != 80 {
		t.Fatalf("cached_tokens 应解析进 CacheReadTokens（got %d）", usage.CacheReadTokens)
	}
	if usage.TotalTokens != 105 {
		t.Fatalf("total 解析异常: %d", usage.TotalTokens)
	}
}
