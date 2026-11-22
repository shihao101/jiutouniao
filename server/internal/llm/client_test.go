package llm

// v6.0.1 P1/P7 验收测试（fix-plan 20261122）：
// ①请求级 deadline（延迟响应超预算 → 报错而非挂死）；②503 重试一次 / 400 不重试 /
// 调用方取消立即退出；③慢响应体被总预算截断；④网关回传 model 随 Usage 上报（C30 数据源）。

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// newTestClient 构造短预算客户端（MaxRetries=-1 禁用重试=单次尝试，测试可确定性计时）。
func newTestClient(url string, timeoutSec int) Client {
	return NewOpenAIWithOptions(url, "test-key", Options{
		RequestTimeoutSec: timeoutSec,
		MaxRetries:        -1,
		RetryBaseSec:      1,
		RetryMaxSec:       1,
	})
}

func chatMsgs() []Message {
	return []Message{{Role: "user", Content: "ping"}}
}

// ① 延迟响应头超过请求预算 → 返回超时错误（而非挂死），总耗时受控
func TestLLMRequestDeadline(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(3 * time.Second) // 预算 1s，网关静默挂起场景
		_, _ = w.Write([]byte(`{"choices":[{"message":{"role":"assistant","content":"late"}}]}`))
	}))
	defer srv.Close()
	c := newTestClient(srv.URL, 1)
	start := time.Now()
	_, _, err := c.Chat(context.Background(), "m", chatMsgs(), nil, 0.2, 128)
	if err == nil {
		t.Fatal("超预算的静默网关应返回错误（P1：宁可误杀不可挂死）")
	}
	if elapsed := time.Since(start); elapsed > 2500*time.Millisecond {
		t.Fatalf("请求应在预算 1s 附近失败，实测 %v（超时未生效）", elapsed)
	}
	if !strings.Contains(err.Error(), "LLM 请求失败") && !strings.Contains(err.Error(), "context deadline") &&
		!strings.Contains(err.Error(), "timeout") {
		t.Fatalf("错误应体现超时/请求失败，实际: %v", err)
	}
}

// ②a 503 一次 → 自动重试成功（总尝试 2 次）
func TestLLMRetryOn503(t *testing.T) {
	hits := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		if hits == 1 {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte("upstream unavailable"))
			return
		}
		_, _ = w.Write([]byte(`{"model":"test-model","choices":[{"message":{"role":"assistant","content":"ok"}}],"usage":{"total_tokens":7}}`))
	}))
	defer srv.Close()
	c := NewOpenAIWithOptions(srv.URL, "k", Options{RequestTimeoutSec: 5, MaxRetries: 2, RetryBaseSec: 1, RetryMaxSec: 1})
	msg, usage, err := c.Chat(context.Background(), "m", chatMsgs(), nil, 0.2, 128)
	if err != nil {
		t.Fatalf("503 后重试应成功: %v", err)
	}
	if hits != 2 {
		t.Fatalf("应恰好重试一次（hits=%d）", hits)
	}
	if msg.Content != "ok" {
		t.Fatalf("内容不符: %q", msg.Content)
	}
	// ④ 网关回传 model 随 Usage 上报（C30 漂移检测数据源）
	if usage.ProviderModel != "test-model" {
		t.Fatalf("Usage.ProviderModel 应为网关回传 model，实际 %q", usage.ProviderModel)
	}
}

// ②b 400 参数错误 → 不重试（首轮即返）
func TestLLMNoRetryOn400(t *testing.T) {
	hits := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":{"message":"bad request"}}`))
	}))
	defer srv.Close()
	c := NewOpenAIWithOptions(srv.URL, "k", Options{RequestTimeoutSec: 5, MaxRetries: 3, RetryBaseSec: 1, RetryMaxSec: 1})
	_, _, err := c.Chat(context.Background(), "m", chatMsgs(), nil, 0.2, 128)
	if err == nil {
		t.Fatal("400 应返回错误")
	}
	if hits != 1 {
		t.Fatalf("4xx 参数错误不得重试（hits=%d）", hits)
	}
}

// ②c 调用方取消 → 退避等待立即退出（不吞取消信号）
func TestLLMCancelDuringBackoff(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()
	ctx, cancel := context.WithCancel(context.Background())
	c := NewOpenAIWithOptions(srv.URL, "k", Options{RequestTimeoutSec: 5, MaxRetries: 5, RetryBaseSec: 30, RetryMaxSec: 60})
	go func() {
		time.Sleep(300 * time.Millisecond) // 首次失败后进入 30s 退避窗口
		cancel()
	}()
	start := time.Now()
	_, _, err := c.Chat(ctx, "m", chatMsgs(), nil, 0.2, 128)
	if err == nil {
		t.Fatal("取消后应返回错误")
	}
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Fatalf("取消应立即退出退避等待，实测 %v", elapsed)
	}
}

// ③ 慢响应体读取被总预算截断（Client.Timeout 覆盖 body 读取阶段）
func TestLLMSlowBodyDeadline(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		_, _ = w.Write([]byte(`{"choices":[{"message":{"role":"assistant","content":"`))
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		time.Sleep(3 * time.Second) // body 阶段静默
		_, _ = w.Write([]byte(`"}]}`))
	}))
	defer srv.Close()
	c := newTestClient(srv.URL, 1)
	start := time.Now()
	_, _, err := c.Chat(context.Background(), "m", chatMsgs(), nil, 0.2, 128)
	if err == nil {
		t.Fatal("慢响应体应被总预算截断报错")
	}
	if elapsed := time.Since(start); elapsed > 2500*time.Millisecond {
		t.Fatalf("截断应在预算附近发生，实测 %v", elapsed)
	}
}

// Options 语义：零值取默认 / 负值禁用重试
func TestLLMOptionsDefaults(t *testing.T) {
	o := Options{}.withDefaults()
	if o.RequestTimeoutSec != 300 || o.MaxRetries != 4 || o.ResponseMaxBytes != 32<<20 {
		t.Fatalf("默认值不符: %+v", o)
	}
	o2 := Options{MaxRetries: -1}.withDefaults()
	if o2.MaxRetries != 0 {
		t.Fatalf("负值 MaxRetries 应禁用重试，实际 %d", o2.MaxRetries)
	}
}

// 网关未回传 model → ProviderModel 为空（unreported，不得伪称一致）
func TestLLMProviderModelUnreported(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req map[string]any
		_ = json.NewDecoder(r.Body).Decode(&req)
		_ = req
		_, _ = w.Write([]byte(`{"choices":[{"message":{"role":"assistant","content":"ok"}}],"usage":{"total_tokens":3}}`))
	}))
	defer srv.Close()
	c := newTestClient(srv.URL, 5)
	_, usage, err := c.Chat(context.Background(), "requested-model", chatMsgs(), nil, 0.2, 128)
	if err != nil {
		t.Fatal(err)
	}
	if usage.ProviderModel != "" {
		t.Fatalf("未回传 model 时 ProviderModel 应为空（unreported），实际 %q", usage.ProviderModel)
	}
}
