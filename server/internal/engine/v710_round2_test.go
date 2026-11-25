package engine

// v7.1.0 第二轮核对补齐项回归：A2 执行卡状态机 / P5 压缩前助手归档 / E4' 紧急裁剪 / P7 健康归因 / B2 聚焦回环

import (
	"context"
	"strings"
	"testing"

	"jiutouniao/internal/llm"
)

// A2：update_coverage 引用 C-xx → 卡片推进；VT 登记不降级已有卡；收口漏斗直出。
func TestV710CardStateMachine(t *testing.T) {
	o, st := v48Orchestrator(t)
	p := v710Project(st, "P-V710-CARD")
	_ = st.SaveProject(p)
	// VT 登记先建卡（queued）
	o.dispatch(context.Background(), p, "s4", llm.ToolCall{Name: "record_vt",
		Arguments: `{"title":"C-13 注入面验证 VT","start_conditions":"需登录态"}`})
	cs := st.CardStats(p.ID)
	if cs["total"] != 1 || cs["queued_vt"] != 1 {
		t.Fatalf("VT 登记应建 queued 卡: %v", cs)
	}
	// 覆盖投递（非结论态）→ dispatched；同卡不因 VT 重复登记回退
	o.dispatch(context.Background(), p, "s4", llm.ToolCall{Name: "update_coverage",
		Arguments: `{"endpoint":"/login@app.test","vuln_class":"SQL注入","status":"waf_blocked","notes":"403 统一拦截页，C-13"}`})
	cs = st.CardStats(p.ID)
	if cs["dispatched"] != 1 || cs["blocked"] != 1 {
		t.Fatalf("投递应推进 dispatched 并计 blocked: %v", cs)
	}
	o.dispatch(context.Background(), p, "s4", llm.ToolCall{Name: "record_vt",
		Arguments: `{"title":"C-13 再次登记 VT","start_conditions":"x"}`})
	cs = st.CardStats(p.ID)
	if cs["queued_vt"] != 0 || cs["dispatched"] != 1 {
		t.Fatalf("VT 重复登记不得把卡降回 queued: %v", cs)
	}
	// 结论态 → dispositioned
	o.dispatch(context.Background(), p, "s4", llm.ToolCall{Name: "update_coverage",
		Arguments: `{"endpoint":"/login@app.test","vuln_class":"SQL注入","status":"vulnerable","notes":"布尔差分确认 EV- 已落 evidence/，C-13"}`})
	cs = st.CardStats(p.ID)
	if cs["dispositioned"] != 1 {
		t.Fatalf("结论态应推进 dispositioned: %v", cs)
	}
	if line := o.cardFunnelLine(p); !strings.Contains(line, "共 1 张") {
		t.Fatalf("漏斗直出应含卡片数: %s", line)
	}
}

// P5：压缩前助手消息原文经回调归档，存根携带 receipt id。
func TestV710AssistantArchive(t *testing.T) {
	long := ""
	for i := 0; i < 400; i++ {
		long += "分析过程第若干段，包含计划意图与未完成工作的叙述，足够长以触发压缩阈值。\n"
	}
	msgs := []llm.Message{
		{Role: "system", Content: "[[HEAD:s4]] 宪法"},
		{Role: "user", Content: "上下文包"},
		{Role: "assistant", Content: long},
	}
	// 追加足够尾部消息，使长助手消息落在 keepRecent 保护区之外（可压缩中段）
	for i := 0; i < 6; i++ {
		msgs = append(msgs, llm.Message{Role: "tool", Content: "回执片段"}, llm.Message{Role: "assistant", Content: "短分析"})
	}
	msgs = append(msgs, llm.Message{Role: "user", Content: "最新指令"})
	archived := map[string]string{}
	out, n := compactMsgsWithArchive(msgs, 500, 4, func(stage, content string) string {
		rid := "rpt-test-" + stage
		archived[rid] = content
		return rid
	})
	if n == 0 || len(archived) == 0 {
		t.Fatalf("长助手消息应触发压缩并归档: n=%d archived=%d", n, len(archived))
	}
	found := false
	for _, m := range out {
		if strings.Contains(m.Content, "压缩前分析原文已归档") && strings.Contains(m.Content, "receipt:") {
			found = true
		}
	}
	if !found {
		t.Fatalf("助手存根应携带 receipt 归档指针")
	}
}

// E4'：两遍压缩后仍超预算 → 紧急裁剪保证预算单调收敛（替代旧「压无可压即失败」）。
func TestV710EmergencyTrim(t *testing.T) {
	msgs := []llm.Message{{Role: "system", Content: "[[HEAD:s4]]"}, {Role: "user", Content: "包"}}
	for i := 0; i < 30; i++ {
		msgs = append(msgs, llm.Message{Role: "tool", Content: strings.Repeat("工具回执填充内容。", 60)})
		msgs = append(msgs, llm.Message{Role: "assistant", Content: strings.Repeat("助手分析填充。", 80)})
	}
	msgs = append(msgs, llm.Message{Role: "user", Content: "最近指令"}, llm.Message{Role: "tool", Content: "近端"})
	msgs = append(msgs, llm.Message{Role: "assistant", Content: "近端"})
	origin := estimateTokens(msgs)
	out, _ := compactMsgsWithArchive(msgs, 12000, 4, nil)
	after := estimateTokens(out)
	if after > 12000 {
		t.Fatalf("现实预算下两遍压缩+紧急裁剪应收敛: origin=%d after=%d", origin, after)
	}
	if after >= origin/2 {
		t.Fatalf("紧急裁剪应显著缩小消息链: origin=%d after=%d", origin, after)
	}
	trimmed := 0
	for _, m := range out {
		if strings.Contains(m.Content, "（预算紧急裁剪）") {
			trimmed++
		}
	}
	if trimmed == 0 {
		t.Fatalf("应有紧急裁剪标记（两遍常规压缩未达预算时兜底生效）")
	}
}

// P7：错误特征归类计数与阈值提示。
func TestV710ToolHealth(t *testing.T) {
	o, st := v48Orchestrator(t)
	p := v710Project(st, "P-V710-HL")
	for i := 0; i < 3; i++ {
		o.trackToolHealth(p, "s4", "connect: connection refused", 1)
	}
	o.trackToolHealth(p, "s4", "request timed out after 300s", 1)
	s := o.toolHealthSummary(p.ID, "s4")
	if !strings.Contains(s, "refused=3") || !strings.Contains(s, "timeout=1") || !strings.Contains(s, "≥3") {
		t.Fatalf("健康归因汇总不符: %s", s)
	}
	if o.toolHealthSummary(p.ID, "s8") != "" {
		t.Fatalf("无计数阶段应返回空")
	}
}

// B2：loopback focus 参数随重入原因下发。
func TestV710LoopbackFocus(t *testing.T) {
	o, st := v48Orchestrator(t)
	o.heads = map[string]*Head{"s4": {ID: "s4", Name: "漏洞发现", Order: 4}, "s5": {ID: "s5", Name: "利用", Order: 5}}
	o.loops = map[string][]string{}
	o.loopTotal = map[string]int{}
	p := v710Project(st, "P-V710-Focus")
	o.dispatch(context.Background(), p, "s5", llm.ToolCall{Name: "loopback",
		Arguments: `{"to_stage":"s4","reason":"新攻击面","focus":"C-13@login@app.test"}`})
	if !strings.Contains(p.StageStates["s4"].ReentryReason, "聚焦范围: C-13@login@app.test") {
		t.Fatalf("focus 应写入重入原因: %q", p.StageStates["s4"].ReentryReason)
	}
}
