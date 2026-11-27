package llm

// v7.5.2 修复 B 回归：思考模型空正文+有 reasoning → 响亮错误（带 token 诊断）；带工具调用 → 正常返回

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestV752ThinkingEmptyIsLoudError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"choices":[{"message":{"role":"assistant","content":"","reasoning_content":"思考过程……全部预算耗在 reasoning"}}],"usage":{"prompt_tokens":10,"completion_tokens":1024,"total_tokens":1034},"model":"glm-5.3"}`))
	}))
	defer srv.Close()
	c := NewOpenAIWithOptions(srv.URL, "k", Options{RequestTimeoutSec: 5, MaxRetries: -1})
	_, _, err := c.Chat(context.Background(), "m", []Message{{Role: "user", Content: "x"}}, nil, 0.2, 1024)
	if err == nil || !strings.Contains(err.Error(), "思考耗尽预算") {
		t.Fatalf("空正文+有 reasoning 应返回响亮错误: %v", err)
	}
}

func TestV752ToolCallEmptyContentOK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"choices":[{"message":{"role":"assistant","content":"","tool_calls":[{"id":"c1","type":"function","function":{"name":"run_command","arguments":"{}"}}]}}],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2},"model":"m"}`))
	}))
	defer srv.Close()
	c := NewOpenAIWithOptions(srv.URL, "k", Options{RequestTimeoutSec: 5, MaxRetries: -1})
	msg, _, err := c.Chat(context.Background(), "m", []Message{{Role: "user", Content: "x"}}, []ToolDef{{Name: "run_command"}}, 0.2, 1024)
	if err != nil || len(msg.ToolCalls) != 1 {
		t.Fatalf("工具调用轮空正文应正常返回: %v %+v", err, msg)
	}
}
