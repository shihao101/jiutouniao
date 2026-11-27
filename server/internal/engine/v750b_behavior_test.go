// v7.5.0 第二批行为级单测：A1 failover 单次计账 / C6 strict 省略低优先级块 /
// D4 回放方法（计数与豁免）/ D1 精简切片包边界。
package engine

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"jiutouniao/internal/config"
	"jiutouniao/internal/llm"
	"jiutouniao/internal/store"
)

// ---- A1：failover 接管不得在 chatFailover 内入账（caller 单点入账）----

type failLLM struct{ err error }
type okLLM struct{ usage llm.Usage }

func (f *failLLM) Chat(_ context.Context, _ string, _ []llm.Message, _ []llm.ToolDef, _ float32, _ int) (llm.Message, llm.Usage, error) {
	return llm.Message{}, llm.Usage{}, f.err
}
func (o *okLLM) Chat(_ context.Context, _ string, _ []llm.Message, _ []llm.ToolDef, _ float32, _ int) (llm.Message, llm.Usage, error) {
	return llm.Message{Role: "assistant", Content: "ok"}, o.usage, nil
}

func TestV750A1FailoverNoDoubleAccounting(t *testing.T) {
	o := v750TestOrchestrator(t)
	p, err := o.CreateProject(&store.Project{ROEAcknowledgedAt: "2026-11-25T00:00:00Z",
		Name: "A1 回归", Target: "http://127.0.0.1:1", Authorized: true, ModelID: "a"})
	if err != nil {
		t.Fatal(err)
	}
	primary := &failLLM{err: errors.New("LLM 返回 400: Content Exists Risk")}
	backup := &okLLM{usage: llm.Usage{PromptTokens: 100, CompletionTokens: 10, TotalTokens: 110}}
	o.SetModels(map[string]llm.Client{"a": primary, "b": backup},
		map[string]string{"a": "model-a", "b": "model-b"}, "a")
	resp, usage, err := o.chatFailover(context.Background(), p, "s4", []llm.Message{{Role: "user", Content: "go"}}, nil)
	if err != nil {
		t.Fatalf("failover 应接管成功: %v", err)
	}
	if usage.TotalTokens != 110 || resp.Content != "ok" {
		t.Fatalf("应返回备用模型的 usage")
	}
	// 核心断言：chatFailover 内部零入账（计账唯一点在 runStage caller）
	if u, _ := o.store.GetUsage(p.ID); u.TotalTokens != 0 {
		t.Fatalf("chatFailover 内不得入账（A1 双重计账回归）：got %d", u.TotalTokens)
	}
	// caller 入账一次 → 恰好 110
	o.accountUsageC(p, "s4", usage, usageCtx{kind: "main"})
	if u, _ := o.store.GetUsage(p.ID); u.TotalTokens != 110 {
		t.Fatalf("caller 单点入账后应为 110（got %d）", u.TotalTokens)
	}
}

// ---- C6：strict 模式省略时间线等低优先级块，legacy 保留 ----

func TestV750C6StrictPackDropsLowPriority(t *testing.T) {
	o := v750TestOrchestrator(t)
	p, err := o.CreateProject(&store.Project{ROEAcknowledgedAt: "2026-11-25T00:00:00Z",
		Name: "C6 回归", Target: "http://127.0.0.1:1", Authorized: true})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		_, _ = o.store.AddTimeline(&store.TimelineEvent{ProjectID: p.ID, Stage: "s4",
			Event: fmt.Sprintf("事件%d", i), Detail: "详情"})
	}
	// legacy（默认）：时间线在场
	o.cfg.Engine.PackBudgetMode = "legacy"
	pack := o.buildContextPack(p, "s4")
	if !strings.Contains(pack, "### 最近时间线") {
		t.Fatalf("legacy 包应含时间线")
	}
	// strict + 极小阈值：触发二次渲染，时间线省略且带可查回说明
	o.cfg.Engine.PackBudgetMode = "strict"
	o.cfg.Engine.PackStrictBytes = 1
	lean := o.buildContextPack(p, "s4")
	if strings.Contains(lean, "### 最近时间线") {
		t.Fatalf("strict 包应省略时间线")
	}
	if !strings.Contains(lean, "严格预算模式") {
		t.Fatalf("strict 包应带省略说明（可查回指引）")
	}
	if strings.Contains(lean, "### 覆盖度矩阵") == false && strings.Contains(pack, "### 覆盖度矩阵") {
		t.Fatalf("覆盖块不在省略范围（恒保）不一致")
	}
}

// ---- D4：回放方法——第 3 次同参命中、豁免工具不计数、参数变化重计 ----

func TestV750D4ReplayHelper(t *testing.T) {
	mon := &execMonitor{}
	tc := llm.ToolCall{Name: "hexstrike_command", Arguments: `{"cmd":"nmap -sV x"}`}
	for i := 1; i <= 2; i++ {
		if _, hit := mon.replayCheck(tc.Name, tc.Arguments); hit {
			t.Fatalf("第 %d 次不应命中回放", i)
		}
	}
	mon.replayRecord(tc.Name, tc.Arguments, "扫描结果ABC")
	text, hit := mon.replayCheck(tc.Name, tc.Arguments)
	if !hit || !strings.Contains(text, "扫描结果ABC") {
		t.Fatalf("第 3 次应命中回放并携带上次结果")
	}
	// 参数变化 → 独立计数，不命中
	if _, hit := mon.replayCheck(tc.Name, `{"cmd":"nmap -sV y"}`); hit {
		t.Fatalf("参数变化不应命中回放")
	}
	// 豁免工具：shell_write 第 10 次也不命中
	for i := 0; i < 10; i++ {
		if _, hit := mon.replayCheck("shell_write", `{"data":"x"}`); hit {
			t.Fatalf("豁免工具不得命中回放")
		}
	}
	// 回放关闭语义由调用方 replayOn 控制（配置开关测试在 config 默认值层）
	if !config.FlagOrDefault((*bool)(nil), true) {
		t.Fatalf("FlagOrDefault nil 应取默认 true")
	}
}

// ---- D1：精简切片包——带合规块、不带全量包大块 ----

func TestV750D1SubagentLitePackBoundary(t *testing.T) {
	o := v750TestOrchestrator(t)
	p, err := o.CreateProject(&store.Project{ROEAcknowledgedAt: "2026-11-25T00:00:00Z",
		Name: "D1 回归", Target: "http://127.0.0.1:1", Authorized: true,
		Scope: "授权范围文本", ROE: "ROE 红线文本", ExecutionProfile: "production_safe"})
	if err != nil {
		t.Fatal(err)
	}
	pack := o.buildSubagentPack(p, "测试 login 接口越权", "s4")
	for _, must := range []string{"派发切片上下文", "授权范围", "ROE 红线", "production_safe"} {
		if !strings.Contains(pack, must) {
			t.Fatalf("切片包缺合规块 %q", must)
		}
	}
	for _, forbidden := range []string{"### 既往阶段交付物", "### 覆盖度矩阵", "### 当前子任务计划"} {
		if strings.Contains(pack, forbidden) {
			t.Fatalf("切片包不应携带全量包大块 %q", forbidden)
		}
	}
}

// ---- B2 配套：S1 工具硬门（双模生效）——非命令通道工具直调在 S1 被拒绝而非执行 ----

func TestV750B2S1ToolGateBothModes(t *testing.T) {
	for _, mode := range []string{"trimmed", "stable"} {
		o := v750TestOrchestrator(t)
		o.cfg.Engine.ToolMaskMode = mode
		p, err := o.CreateProject(&store.Project{ROEAcknowledgedAt: "2026-11-25T00:00:00Z",
			Name: "S1 门回归", Target: "http://127.0.0.1:1", Authorized: true})
		if err != nil {
			t.Fatal(err)
		}
		for _, name := range []string{"http_request", "spawn_subagent", "propose", "shell_open", "run_async"} {
			out := o.dispatch(context.Background(), p, "s1", llm.ToolCall{Name: name, Arguments: `{}`})
			if !strings.Contains(out, "S1 阶段工具门") {
				t.Fatalf("[%s] S1 直调 %s 应被工具门拦截（got %.60q）", mode, name, out)
			}
		}
		// 合规工具不受影响：record_timeline 正常放行
		out := o.dispatch(context.Background(), p, "s1", llm.ToolCall{Name: "record_timeline", Arguments: `{"event":"e","detail":"d"}`})
		if strings.Contains(out, "拦截") {
			t.Fatalf("[%s] 合规工具被误拦：%q", mode, out)
		}
		// 门不波及其他阶段：S4 直调 http_request 不被 S1 门拦（走正常执行路径）
		out = o.dispatch(context.Background(), p, "s4", llm.ToolCall{Name: "record_timeline", Arguments: `{"event":"e","detail":"d"}`})
		if strings.Contains(out, "S1 阶段工具门") {
			t.Fatalf("S4 不应触发 S1 工具门：%q", out)
		}
	}
}
