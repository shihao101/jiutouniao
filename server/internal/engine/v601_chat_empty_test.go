// v6.0.1 对话空回复处置单测：①首轮空回复→引导重试后走诊断路径不挂起 ②纯 user 堆叠挂起链
// 判定无可续跑动作并清键 ③有工具动作后的空回复按实际轮数挂起（链保留）。
package engine

import (
	"context"
	"strings"
	"testing"

	"jiutouniao/internal/llm"
	"jiutouniao/internal/store"
)

// fakeEmptyLLM 恒返回空 content（无工具调用）——模拟思维型模型 max_tokens 被思维链耗尽后的空回复。
type fakeEmptyLLM struct{ calls int }

func (f *fakeEmptyLLM) Chat(_ context.Context, _ string, _ []llm.Message, _ []llm.ToolDef, _ float32, _ int) (llm.Message, llm.Usage, error) {
	f.calls++
	return llm.Message{Role: "assistant", Content: ""}, llm.Usage{TotalTokens: 5}, nil
}

// fakeToolThenEmptyLLM 首轮返回 1 个工具调用，之后恒空回复。
type fakeToolThenEmptyLLM struct{ calls int }

func (f *fakeToolThenEmptyLLM) Chat(_ context.Context, _ string, _ []llm.Message, _ []llm.ToolDef, _ float32, _ int) (llm.Message, llm.Usage, error) {
	f.calls++
	if f.calls == 1 {
		return llm.Message{Role: "assistant", ToolCalls: []llm.ToolCall{{ID: "t1", Name: "list_files", Arguments: `{}`}}},
			llm.Usage{TotalTokens: 5}, nil
	}
	return llm.Message{Role: "assistant", Content: ""}, llm.Usage{TotalTokens: 5}, nil
}

func v601ChatSetup(t *testing.T, rounds int) (*Orchestrator, *store.Store) {
	t.Helper()
	o, st := v550Orchestrator(t)
	o.cfg.Engine.ChatToolRounds = rounds
	o.approver = NewApprover(st, o.bus, "manual")
	chatSessions = newChatSessions(o)
	return o, st
}

func TestV601ChatEmptyFirstRoundDiagnosticNoPending(t *testing.T) {
	o, st := v601ChatSetup(t, 4)
	p := &store.Project{ ROEAcknowledgedAt: "2026-11-22T00:00:00Z",ID: "P-V601-A", Name: "chat-empty", Target: "http://t"}
	_ = st.SaveProject(p)
	f := &fakeEmptyLLM{}
	o.llm = f
	final, err := chatSessions.Turn(p.ID, "我的长需求")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(final, "空回复") || !strings.Contains(final, "未挂起") {
		t.Fatalf("零动作空回复应给诊断且明示不挂起: %s", final)
	}
	if !strings.Contains(final, "max_tokens") {
		t.Fatalf("诊断应给可行动建议（max_tokens）: %s", final)
	}
	if f.calls != 2 {
		t.Fatalf("首轮空回复应恰好一次引导重试（2 次调用）: %d", f.calls)
	}
	if _, ok := chatSessions.loadPendingRun(p.ID); ok {
		t.Fatal("零动作空回复不应保存挂起链")
	}
}

func TestV601ChatPendingAllUserDiscarded(t *testing.T) {
	_, st := v601ChatSetup(t, 4)
	p := &store.Project{ ROEAcknowledgedAt: "2026-11-22T00:00:00Z",ID: "P-V601-B", Name: "chat-residue", Target: "http://t"}
	_ = st.SaveProject(p)
	// 模拟 v6.0.1 之前的残骸链：纯 user 堆叠（空回复误挂起产物）
	chatSessions.savePendingRun(p.ID, []llm.Message{
		{Role: "system", Content: "s"}, {Role: "user", Content: "a"}, {Role: "user", Content: "b"},
	})
	if msgs, ok := chatSessions.loadPendingRun(p.ID); ok || msgs != nil {
		t.Fatalf("纯 user 堆叠链应判定无可续跑动作: ok=%v msgs=%d", ok, len(msgs))
	}
	if _, ok := st.LoadChat(pendingRunKey(p.ID)); ok {
		t.Fatal("残骸链应被清除")
	}
	// 对照：含工具轮的链仍可续跑
	chatSessions.savePendingRun(p.ID, []llm.Message{
		{Role: "assistant", ToolCalls: []llm.ToolCall{{ID: "t1", Name: "list_files", Arguments: `{}`}}},
		{Role: "tool", ToolCallID: "t1", Content: "ok"},
	})
	if msgs, ok := chatSessions.loadPendingRun(p.ID); !ok || len(msgs) != 2 {
		t.Fatalf("含工具轮的链应可续跑: ok=%v len=%d", ok, func() int { m, _ := chatSessions.loadPendingRun(p.ID); return len(m) }())
	}
}

func TestV601ChatEmptyAfterToolWorkSuspends(t *testing.T) {
	o, st := v601ChatSetup(t, 4)
	p := &store.Project{ ROEAcknowledgedAt: "2026-11-22T00:00:00Z",ID: "P-V601-C", Name: "chat-work-empty", Target: "http://t"}
	_ = st.SaveProject(p)
	f := &fakeToolThenEmptyLLM{}
	o.llm = f
	final, err := chatSessions.Turn(p.ID, "继续推进")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(final, "返回空回复") || !strings.Contains(final, "已挂起保存") {
		t.Fatalf("有动作后的空回复应按实际轮数挂起: %s", final)
	}
	if !strings.Contains(final, "3") { // 第 1 轮工具 + 空回复重试 2 轮 = roundsRun 3
		t.Fatalf("挂起文案应含实际轮数: %s", final)
	}
	msgs, ok := chatSessions.loadPendingRun(p.ID)
	if !ok {
		t.Fatal("有工具动作的空回复应保存挂起链")
	}
	hasTool := false
	for _, m := range msgs {
		if m.Role == "tool" {
			hasTool = true
		}
	}
	if !hasTool {
		t.Fatal("挂起链应保留工具结果消息")
	}
}
