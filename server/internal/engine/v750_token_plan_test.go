// v7.5.0 Token 成本总案单测（docs/优化方案_Token成本总案_通用实战能力无损_v7.4.5_20261125.md）：
// ① D4 回放豁免清单口径 ② E1 compactHybrid 结构安全（只追加不移动）③ A3 estToolTokens
// ④ C1 分阶技能索引（StageFit 命中/低置信度回退）⑤ C3 Summary 设顶 ⑥ C2 read_file 溢出
// 落盘与 offset/limit 分段 ⑦ A3/A4 估算兜底记账与种类分账 ⑧ A2 熔断计数持久化读账本
// ⑨ C5/E2 auxMaxTokens 默认 1024。
package engine

import (
	"context"
	"strings"
	"testing"

	"jiutouniao/internal/config"
	"jiutouniao/internal/events"
	"jiutouniao/internal/llm"
	"jiutouniao/internal/store"
	"jiutouniao/internal/tools"
)

func v750TestOrchestrator(t *testing.T) *Orchestrator {
	t.Helper()
	dir := t.TempDir()
	st, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	exec, err := tools.NewExecutor(dir, 5, 200*1024, struct {
		Forbidden, HighRisk, MedRisk, ReadOnly, Sensitive []string
	}{})
	if err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{}
	cfg.ApplyDefaultsForTest()
	o := &Orchestrator{
		cfg: cfg, store: st, exec: exec, bus: events.NewBus(),
		heads: map[string]*Head{},
		running: map[string]context.CancelFunc{}, tokens: map[string]int64{},
		inputs: map[string][]string{}, loops: map[string][]string{},
		liveP: map[string]*store.Project{}, projModel: map[string]string{},
		batchStats: map[string]*batchBudgetState{}, modelWarn: map[string]bool{},
	}
	return o
}

// ① D4：豁免清单必须覆盖交互式/台账写入类工具，且不得豁免普通幂等读（run_command/read_file）
func TestV750ReplayExemptToolsSanity(t *testing.T) {
	for _, name := range []string{"shell_write", "browser_login", "run_async", "record_finding", "propose", "complete_stage", "poll_async"} {
		if !replayExemptTools[name] {
			t.Fatalf("replayExemptTools 缺少 %s（交互式/流程/台账类必须豁免）", name)
		}
	}
	for _, name := range []string{"run_command", "read_file", "hexstrike_command"} {
		if replayExemptTools[name] {
			t.Fatalf("%s 不应豁免回放拦截（幂等/可重入类）", name)
		}
	}
}

// ② E1：compactHybrid 只产出「待追加文本」，不改既有链；语料不足/无摘要器时零变化
func TestV750CompactHybridStructureSafe(t *testing.T) {
	if got := compactHybrid(nil, 10, func(s string) string { return "摘要" }); got != "" {
		t.Fatalf("nil summarizer 应返回空")
	}
	short := []llm.Message{
		{Role: "system", Content: "sys"}, {Role: "user", Content: "pack"},
		{Role: "user", Content: strings.Repeat("短", 100)},
	}
	if got := compactHybrid(short, 10, func(s string) string { return "摘要" }); got != "" {
		t.Fatalf("语料 <2000 应跳过摘要（收益不抵调用成本）")
	}
	msgs := []llm.Message{
		{Role: "system", Content: "sys"}, {Role: "user", Content: "pack"},
	}
	for i := 0; i < 12; i++ {
		msgs = append(msgs, llm.Message{Role: "tool", ToolCallID: "t", Content: strings.Repeat("回执内容", 500)})
	}
	corpusSeen := ""
	got := compactHybrid(msgs, 4, func(s string) string { corpusSeen = s; return "关键发现：X；证据 EV-1" })
	if got == "" || !strings.Contains(got, "[历史摘要（混合压缩）]") || !strings.Contains(got, "EV-1") {
		t.Fatalf("混合压缩摘要注入缺失: %q", got)
	}
	if corpusSeen == "" {
		t.Fatalf("摘要器未收到语料")
	}
	// 摘要器失败 → 空串（静默回退纯存根口径）
	if got := compactHybrid(msgs, 4, func(s string) string { return "" }); got != "" {
		t.Fatalf("摘要失败应静默回退")
	}
}

// ③ A3：工具面估算非零
func TestV750EstToolTokens(t *testing.T) {
	defs := []llm.ToolDef{{Name: "run_command", Description: "执行命令", Parameters: map[string]any{"type": "object"}}}
	if estToolTokens(defs) <= 0 {
		t.Fatalf("estToolTokens 应大于 0")
	}
	if estToolTokens(nil) != 0 {
		t.Fatalf("空工具面应为 0")
	}
}

// ④ C1：分阶技能索引——StageFit 命中进索引、核心技能恒在、低置信度回退
func TestV750SkillIndexForStage(t *testing.T) {
	reg := &SkillRegistry{skills: map[string]*Skill{}, manifest: map[string]*SkillMeta{}, mOK: true}
	mk := func(id, title string, tags ...string) *Skill {
		return &Skill{ID: id, Title: title, Tags: tags, Body: "正文"}
	}
	// 8 个 s4 相关（manifest StageFit 标注）+ 1 个 s8 专属 + 核心 router
	for i := 0; i < 8; i++ {
		id := "web-skill-" + string(rune('a'+i))
		reg.skills[id] = mk(id, "Web 漏洞测试技能")
		reg.manifest[id] = &SkillMeta{ID: id, StageFit: []string{"s4"}}
	}
	reg.skills["report-skill"] = mk("report-skill", "报告撰写")
	reg.manifest["report-skill"] = &SkillMeta{ID: "report-skill", StageFit: []string{"s8"}}
	reg.skills["00-router"] = mk("00-router", "技能路由")
	got, ok := reg.IndexForStage("s4", 30)
	if !ok {
		t.Fatalf("s4 命中 8+核心，置信度足够应返回 ok")
	}
	if !strings.Contains(got, "web-skill-a") || strings.Contains(got, "report-skill") {
		t.Fatalf("分阶索引应含 s4 技能且不含 s8 专属技能（核心除外）")
	}
	if !strings.Contains(got, "00-router") {
		t.Fatalf("核心路由技能应恒在")
	}
	// 低置信度：仅 1 个命中 → 回退全量（ok=false）
	reg2 := &SkillRegistry{skills: map[string]*Skill{}, manifest: map[string]*SkillMeta{}, mOK: true}
	reg2.skills["lone"] = mk("lone", "Web 注入")
	reg2.manifest["lone"] = &SkillMeta{ID: "lone", StageFit: []string{"s4"}}
	reg2.skills["other"] = mk("other", "无关技能")
	if _, ok := reg2.IndexForStage("s4", 30); ok {
		t.Fatalf("命中 <3 应判定低置信度回退全量")
	}
}

// ⑤ C3：既往阶段 Summary 设顶（默认 800 字符）
func TestV750PackSummaryCap(t *testing.T) {
	o := v750TestOrchestrator(t)
	p, err := o.CreateProject(&store.Project{ROEAcknowledgedAt: "2026-11-25T00:00:00Z",
		Name: "C3 设顶回归", Target: "http://127.0.0.1:1", Authorized: true})
	if err != nil {
		t.Fatal(err)
	}
	long := strings.Repeat("长摘要内容", 400) // 2000 字 > 800
	p.StageStates = map[string]*store.StageState{
		"s3": {Status: "done", Summary: long},
	}
	_ = o.store.SaveProject(p)
	pack := o.buildContextPack(p, "s4")
	if !strings.Contains(pack, "已截断") {
		t.Fatalf("Summary 超长未截断（C3 失效）")
	}
	if strings.Contains(pack, long) {
		t.Fatalf("完整超长 Summary 不应整体入包")
	}
	if !strings.Contains(pack, "长摘要内容") {
		t.Fatalf("骨架前缀应保留（非整块丢弃）")
	}
}

// ⑥ C2：read_file >16KB 溢出落盘 + offset/limit 分段
func TestV750ReadFileSpillAndRange(t *testing.T) {
	o := v750TestOrchestrator(t)
	p, err := o.CreateProject(&store.Project{ROEAcknowledgedAt: "2026-11-25T00:00:00Z",
		Name: "C2 回归", Target: "http://127.0.0.1:1", Authorized: true})
	if err != nil {
		t.Fatal(err)
	}
	big := strings.Repeat("A", 20*1024)
	if _, err := o.exec.WriteFile(p.ID, "deliverables/big.md", big); err != nil {
		t.Fatal(err)
	}
	out := o.dispatch(context.Background(), p, "s4", llm.ToolCall{Name: "read_file", Arguments: `{"path":"deliverables/big.md"}`})
	if !strings.Contains(out, "溢出落盘") || len(out) > 16*1024 {
		t.Fatalf("大文件应溢出落盘且回执受控（len=%d）", len(out))
	}
	// 分段读取：多行文件（200 行 × 100B = 20KB，同样触发溢出但不影响分段语义）
	var linesB strings.Builder
	for i := 0; i < 200; i++ {
		linesB.WriteString(strings.Repeat("L", 99) + "\n")
	}
	if _, err := o.exec.WriteFile(p.ID, "deliverables/lines.md", linesB.String()); err != nil {
		t.Fatal(err)
	}
	out = o.dispatch(context.Background(), p, "s4", llm.ToolCall{Name: "read_file", Arguments: `{"path":"deliverables/lines.md","offset":2,"limit":1}`})
	if !strings.Contains(out, "[行 2-2 / 共 201 行]") || !strings.HasPrefix(out, "[行 2-2 / 共 201 行]\nLLL") {
		t.Fatalf("offset/limit 分段读取未生效: %q", out[:min(len(out), 80)])
	}
	out = o.dispatch(context.Background(), p, "s4", llm.ToolCall{Name: "read_file", Arguments: `{"path":"deliverables/lines.md","offset":2,"limit":3}`})
	if !strings.Contains(out, "[行 2-4 / 共 201 行]") {
		t.Fatalf("limit=3 分段区间错: %q", out[:min(len(out), 80)])
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// ⑦ A3/A4：零 usage 估算兜底入账 + 种类分账 + 明细行
func TestV750AccountingEstimateFallbackAndKinds(t *testing.T) {
	o := v750TestOrchestrator(t)
	p, err := o.CreateProject(&store.Project{ROEAcknowledgedAt: "2026-11-25T00:00:00Z",
		Name: "计账回归", Target: "http://127.0.0.1:1", Authorized: true})
	if err != nil {
		t.Fatal(err)
	}
	msgs := []llm.Message{{Role: "system", Content: strings.Repeat("系统提示", 500)}}
	tools := []llm.ToolDef{{Name: "run_command", Description: "执行命令", Parameters: map[string]any{"type": "object"}}}
	resp := llm.Message{Role: "assistant", Content: strings.Repeat("结论", 100)}
	o.accountUsageC(p, "s4", llm.Usage{}, usageCtx{kind: "main", msgs: msgs, tools: tools, resp: &resp})
	u, _ := o.store.GetUsage(p.ID)
	if u.TotalTokens <= 0 || u.Calls != 1 {
		t.Fatalf("零 usage 应估算兜底入账（got total=%d calls=%d）", u.TotalTokens, u.Calls)
	}
	if o.projectTokens(p.ID) <= 0 {
		t.Fatalf("projectTokens 应读账本（A2）")
	}
	stats := o.store.UsageCallsStats(p.ID)
	if stats["main"] == nil || stats["main"]["calls"] != 1 {
		t.Fatalf("种类分账缺 main 行: %v", stats)
	}
	calls := o.store.ListUsageCalls(p.ID, 10)
	if len(calls) != 1 || !calls[0].Estimate || calls[0].Kind != "main" {
		t.Fatalf("明细行缺失或未打 Estimate 标记: %+v", calls)
	}
	// 真实 usage 路径：cache 分账
	o.accountUsageC(p, "s4", llm.Usage{PromptTokens: 1000, CompletionTokens: 100, TotalTokens: 1100, CacheReadTokens: 800}, usageCtx{kind: "reflect"})
	u, _ = o.store.GetUsage(p.ID)
	if u.CacheReadTokens != 800 {
		t.Fatalf("cache_read 应入账（got %d）", u.CacheReadTokens)
	}
	if stats := o.store.UsageCallsStats(p.ID); stats["reflect"] == nil {
		t.Fatalf("reflect 种类行缺失")
	}
}

// ⑧ A2：熔断计数持久化——重启（新 Orchestrator 实例）后仍读得到账本累计
func TestV750BreakerCounterPersists(t *testing.T) {
	o := v750TestOrchestrator(t)
	p, _ := o.CreateProject(&store.Project{ROEAcknowledgedAt: "2026-11-25T00:00:00Z",
		Name: "熔断持久化", Target: "http://127.0.0.1:1", Authorized: true})
	resp := llm.Message{Role: "assistant", Content: "ok"}
	o.accountUsageC(p, "s4", llm.Usage{PromptTokens: 500, CompletionTokens: 50, TotalTokens: 550}, usageCtx{kind: "main", resp: &resp})
	// 模拟引擎重启：全新实例（共享同一 store），内存 tokens 为空
	o2 := &Orchestrator{cfg: o.cfg, store: o.store, bus: events.NewBus(),
		running: map[string]context.CancelFunc{}, tokens: map[string]int64{},
		inputs: map[string][]string{}, loops: map[string][]string{},
		liveP: map[string]*store.Project{}, projModel: map[string]string{},
		batchStats: map[string]*batchBudgetState{}, modelWarn: map[string]bool{}}
	if got := o2.projectTokens(p.ID); got != 550 {
		t.Fatalf("重启后 projectTokens 应读账本 550（got %d）", got)
	}
}

// ⑨ C5/E2：辅助输出上限默认值（v7.5.2 改为 4096——思考型模型 reasoning 预算，
// 1024 下 glm-5.3 类正文恒空 → 红蓝环/参谋/反思全瞎，实证两个实战项目）；
// aux_model 未配置时 aux 路由回主 client/model
func TestV750AuxDefaults(t *testing.T) {
	o := v750TestOrchestrator(t)
	if got := o.auxMaxTokens(); got != 4096 {
		t.Fatalf("auxMaxTokens 默认应为 4096（思考模型 reasoning 预算，got %d）", got)
	}
}
