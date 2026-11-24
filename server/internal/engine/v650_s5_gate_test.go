package engine

// v6.5.0 S5 修复方案回归测试（docs/修复方案_S5漏洞利用阶段补全_v6.5.0_20261123.md）：
// S5-① 逐目标对账门三重修复（词边界精确键 / s5 语料排除 s4 产物 / 零命中提示级留痕）。
// S5-② 移交项目标维度化（@目标 标签 / 注入块分组 / 承接对账分桶 / 旧格式回退全局）。
// S5-⑥ 预算冲刺预警触发判式（实施更正：remain 取遍全部整数，旧等值条件必然命中——
//       新判式与旧行为等价（首次跨越阈值即同轮），flag 提供显式 exactly-once 语义）。
// S5-⑩ S6「S5 移交项」注入块 + 战利品上限 20。
// 后续小节随实施追加。

import (
	"fmt"
	"strings"
	"testing"

	"jiutouniao/internal/store"
)

// ---------- S5-① targetCoverageRecon 词边界精确键 ----------

// TestV650TargetReconWordBoundary S5-①：词边界命中层消 F-14 形态误报、scheme 精确键消
// scheme 误拦、子域宽松与描述性目标回退保持旧行为。
func TestV650TargetReconWordBoundary(t *testing.T) {
	// ① notexample.com 不应命中目标 example.com（修复前子串包含误命中）
	missing, matched := targetCoverageRecon([]string{"example.com"}, "notexample.com 探测记录\x00", "")
	if matched != 0 || len(missing) != 1 {
		t.Errorf("notexample.com 不应算 example.com 已归宿: matched=%d missing=%v", matched, missing)
	}
	// ② scheme 差异（登记 https、语料 http）→ 精确键命中（修复前误拦）
	missing, matched = targetCoverageRecon([]string{"https://a.example.com"}, "http://a.example.com/api 探测\x00", "")
	if matched != 1 || len(missing) != 0 {
		t.Errorf("scheme 差异应经精确键命中: matched=%d missing=%v", matched, missing)
	}
	// ③ 子域宽松保持：目标 example.com、语料 sub.example.com → 命中（'.' 不属拒绝集）
	_, matched = targetCoverageRecon([]string{"example.com"}, "sub.example.com 探测\x00", "")
	if matched != 1 {
		t.Errorf("子域命中行为不应回归: matched=%d", matched)
	}
	// ④ CIDR 目标语料不含目标串 → 零命中（调用方出提示级留痕，不拦截）
	missing, matched = targetCoverageRecon([]string{"10.0.0.0/24", "10.1.0.0/24"}, "web01 探测\x00", "")
	if matched != 0 || len(missing) != 2 {
		t.Errorf("CIDR 零命中应如实返回: matched=%d missing=%v", matched, missing)
	}
	// ⑤ 描述性目标回退层：词边界不拒中文邻接，原值子串命中保持
	_, matched = targetCoverageRecon([]string{"集团OA系统"}, "集团OA系统门户基线\x00", "")
	if matched != 1 {
		t.Errorf("描述性目标命中行为不应回归: matched=%d", matched)
	}
	// ⑥ 既有行为回归（multitarget_test.go TestTargetCoverageRecon 同形态快速复核）
	targets := []string{"a.example.com", "b.example.com", "d.example.org"}
	cov := "http://a.example.com/news?id=1\x00SQL注入\x00vulnerable\x00\nhttp://B.Example.COM/x\x00\x00\x00\n"
	missing, matched = targetCoverageRecon(targets, cov, "")
	if matched != 2 || len(missing) != 1 || missing[0] != "d.example.org" {
		t.Errorf("既有命中行为回归: matched=%d missing=%v", matched, missing)
	}
}

// TestV650S5ReconGateExcludesS4Corpus S5-①：S4 分组交付物含全部目标时（S4-9 门强制形态），
// S5 逐目标门不得借 S4 语料放行——只测 A 目标时 B 仍应被拦；S4 门消费自己的语料不受影响。
func TestV650S5ReconGateExcludesS4Corpus(t *testing.T) {
	o, _ := v48Orchestrator(t)
	p := &store.Project{ROEAcknowledgedAt: "2026-11-23T00:00:00Z", ID: "P-V650-RECON",
		Target: "a.example.com\nb.example.com"}
	_ = o.store.SaveProject(p)
	// S4 分组交付物：两个目标都在（S4 阶段逐目标产出的强制形态）
	if _, err := o.exec.WriteFile("P-V650-RECON", "deliverables/s4-分组结论.md",
		"# S4 分组结论\n- a.example.com：已测\n- b.example.com：已测\n"); err != nil {
		t.Fatal(err)
	}
	// S5 只覆盖 A 目标
	_, _ = o.store.UpsertCoverage(&store.CoverageEntry{ProjectID: p.ID, Stage: "s5",
		Endpoint: "http://a.example.com/api", VulnClass: "SQL注入", Status: "vulnerable"})

	// S5 门：B 无 S5 自身留痕 → 拦截（修复前借 s4 语料放行）
	issues := o.deterministicGate(p, "s5")
	hit := false
	for _, iss := range issues {
		if strings.Contains(iss, "S5 分段收口对账") && strings.Contains(iss, "b.example.com") {
			hit = true
		}
	}
	if !hit {
		t.Fatalf("S5 逐目标门应拦 b.example.com（不得借 s4 语料放行）: %v", issues)
	}
	// S4 门：s4 交付物已覆盖两目标 → 不拦（自有语料行为不变）
	issues = o.deterministicGate(p, "s4")
	for _, iss := range issues {
		if strings.Contains(iss, "S4 分段收口对账") {
			t.Errorf("S4 门不应受 s5 语料排除影响: %v", issues)
		}
	}
}

// TestV650ReconZeroHitHint S5-①：语料完全不含目标串（CIDR 常态）→ 不拦截但提示级留痕
// （log stream 可见），零命中不再静默。
func TestV650ReconZeroHitHint(t *testing.T) {
	o, _ := v48Orchestrator(t)
	p := &store.Project{ROEAcknowledgedAt: "2026-11-23T00:00:00Z", ID: "P-V650-ZERO",
		Target: "10.0.0.0/24\n10.1.0.0/24"}
	_ = o.store.SaveProject(p)
	_, _ = o.store.UpsertCoverage(&store.CoverageEntry{ProjectID: p.ID, Stage: "s5",
		Endpoint: "web01", VulnClass: "注入", Status: "no_issue_found"})
	issues := o.deterministicGate(p, "s5")
	for _, iss := range issues {
		if strings.Contains(iss, "分段收口对账") {
			t.Errorf("零命中不应拦截（提示级）: %v", issues)
		}
	}
	// 提示级留痕进 log stream
	streams, _, err := o.store.ListStream(p.ID, 0)
	if err != nil {
		t.Fatal(err)
	}
	hint := false
	for _, s := range streams {
		if strings.Contains(s.Text, "逐目标对账零命中") {
			hint = true
		}
	}
	if !hint {
		t.Errorf("零命中应输出提示级留痕（stream log）")
	}
}

// ---------- S5-② 移交项目标维度化 ----------

// TestV650HandoverTargetBucketing S5-②：带 @目标 标签的移交项只认该目标自己的语料——
// B 目标的同类留痕不释放 A 目标的条目；A 语料补留痕后放行；无标签条目回退全局匹配。
func TestV650HandoverTargetBucketing(t *testing.T) {
	o, _ := v48Orchestrator(t)
	p := &store.Project{ROEAcknowledgedAt: "2026-11-23T00:00:00Z", ID: "P-V650-HO",
		Target: "a.example.com\nb.example.com"}
	_ = o.store.SaveProject(p)
	p.StageStates = map[string]*store.StageState{"s4": {Status: "done",
		V3Ready: []string{"sqlmap 四件套批量提取 a.example.com（--banner --current-user --current-db --is-dba）"},
		V3L2:    []string{"无标签条目（旧格式回退全局）sqlmap 四件套批量提取"}}}
	_ = o.store.SaveProject(p)

	// 打标：条目正文含 a.example.com → @a.example.com；无标签 → 无标签
	items := o.s4HandoverItems(p)
	if len(items) != 2 {
		t.Fatalf("移交项应为 2 条: %v", items)
	}
	if got := parseHandoverTarget(items[0]); got != "a.example.com" {
		t.Errorf("条目 0 应打 @a.example.com 标签: %q", items[0])
	}
	if got := parseHandoverTarget(items[1]); got != "" {
		t.Errorf("无目标正文条目应保持无标签: %q", items[1])
	}

	// B 目标语料含同类 key（修复前全局匹配会误释放 A 的条目）；A 语料为空
	_, _ = o.store.UpsertCoverage(&store.CoverageEntry{ProjectID: p.ID, Stage: "s5",
		Endpoint: "http://b.example.com/api", VulnClass: "SQL注入", Status: "vulnerable",
		Notes: "sqlmap 四件套批量提取已完成（b.example.com）"})
	issues := o.v3HandoverIssues(p)
	blocked := false
	for _, iss := range issues {
		if strings.Contains(iss, "S4 移交承接门") && strings.Contains(iss, "批量提取 a.example.com") {
			blocked = true
		}
	}
	if !blocked {
		t.Fatalf("A 目标移交项不应被 B 目标语料误释放: %v", issues)
	}
	// 无标签条目走全局匹配 → B 语料的 key 前缀（「无标签条目（旧格式回退全局）sqlmap 四件」前 12 rune）
	// 未在语料出现 → 该条目也应拦截；两条都在 missing 文案中
	issues = o.v3HandoverIssues(p)
	if len(issues) == 0 || !strings.Contains(issues[0], "2 条") {
		t.Errorf("两条移交项均应拦截: %v", issues)
	}

	// A 语料补承接留痕 → A 条目放行；无标签条目补全局留痕 → 放行
	_, _ = o.store.UpsertCoverage(&store.CoverageEntry{ProjectID: p.ID, Stage: "s5",
		Endpoint: "http://a.example.com/api", VulnClass: "SQL注入", Status: "vulnerable",
		Notes: "sqlmap 四件套批量提取 a.example.com 已投递"})
	_, _ = o.store.UpsertCoverage(&store.CoverageEntry{ProjectID: p.ID, Stage: "s5",
		Endpoint: "http://a.example.com/api", VulnClass: "SQL注入", Status: "vulnerable",
		Notes: "无标签条目（旧格式回退全局）sqlmap 四件套批量提取已投递"})
	if issues := o.v3HandoverIssues(p); len(issues) != 0 {
		t.Errorf("补承接留痕后应放行: %v", issues)
	}
}

// TestV650HandoverSingleTargetUntagged S5-②：单目标项目零行为变化——不打标签、全局匹配。
func TestV650HandoverSingleTargetUntagged(t *testing.T) {
	o, _ := v48Orchestrator(t)
	p := &store.Project{ROEAcknowledgedAt: "2026-11-23T00:00:00Z", ID: "P-V650-SO",
		Target: "a.example.com"}
	_ = o.store.SaveProject(p)
	p.StageStates = map[string]*store.StageState{"s4": {Status: "done",
		V3Ready: []string{"sqlmap 四件套批量提取"}}}
	_ = o.store.SaveProject(p)
	items := o.s4HandoverItems(p)
	if len(items) != 1 || parseHandoverTarget(items[0]) != "" {
		t.Errorf("单目标项目不应打标签: %v", items)
	}
	if issues := o.v3HandoverIssues(p); len(issues) == 0 {
		t.Errorf("单目标无留痕仍应拦截（行为不变）")
	}
}

// ---------- S5-⑥ 冲刺预警触发判式 ----------

// TestV650ShouldInjectSprint S5-⑥：进入「剩 ≤1/3」区间首轮触发恰一次；与旧等值条件
// （remain == budget/3）同轮等价；notified 后不再触发。
func TestV650ShouldInjectSprint(t *testing.T) {
	cases := []int{60, 79, 80, 61, 2, 3}
	for _, budget := range cases {
		firedAt, count := -1, 0
		for iter := 0; iter < budget; iter++ {
			remain := budget - iter - 1
			if shouldInjectSprint(budget, remain, count > 0) {
				firedAt, count = iter, count+1
			}
		}
		if count != 1 {
			t.Errorf("budget=%d 应恰触发一次，实际 %d", budget, count)
		}
		// 与旧条件等价：触发轮 remain == budget/3
		if got := budget - firedAt - 1; got != budget/3 {
			t.Errorf("budget=%d 触发轮 remain=%d 与旧等值条件 budget/3=%d 不一致", budget, got, budget/3)
		}
	}
	if shouldInjectSprint(60, 21, false) {
		t.Errorf("未到阈值（remain=21 > 60/3=20）不应触发")
	}
	if !shouldInjectSprint(60, 20, false) {
		t.Errorf("到达阈值（remain=20 == budget/3）应触发")
	}
	if !shouldInjectSprint(60, 19, false) {
		t.Errorf("阈值区间内（remain=19 <= 20）应触发")
	}
	if shouldInjectSprint(60, 20, true) {
		t.Errorf("已触发不应重复触发")
	}
	if shouldInjectSprint(0, 0, false) {
		t.Errorf("budget<=0 不应触发")
	}
}

// ---------- S5-⑩ S6「S5 移交项」注入块 ----------

// TestV650S6HandoverBlock S5-⑩：S5 V3 两清单非空时 s6 上下文出现「S5 移交项」块（V3 条目 +
// verified 战利品增量 + s5 交付物指针）；S5 未收口时不出块。
func TestV650S6HandoverBlock(t *testing.T) {
	o, st := v48Orchestrator(t)
	p := &store.Project{ROEAcknowledgedAt: "2026-11-23T00:00:00Z", ID: "P-V650-S6H",
		Target: "a.example.com"}
	_ = o.store.SaveProject(p)

	// S5 未收口：无块
	out := o.buildContextPack(p, "s6")
	if strings.Contains(out, "S5 移交项（S6 开工承接") {
		t.Errorf("S5 未收口不应出 s6 移交块")
	}

	// S5 收口：V3 两清单 + verified 战利品 + s5 交付物
	p.StageStates = map[string]*store.StageState{"s5": {Status: "done",
		V3Ready: []string{"sqlmap 四件套批量提取"},
		V3L2:    []string{"AP-XYZ 已批 sqlmap --dump 未投递"}}}
	_ = o.store.SaveProject(p)
	// verified 战利品最早插入（ListLoot 按 CreatedAt 倒序——通用块展示最新 20 条 unverified，
	// verified 落到通用块窗口外 → 应进 s6 移交块「通用块外」小节）
	_, _ = st.AddLoot(&store.LootRecord{ProjectID: p.ID, Stage: "s5", Type: "credential",
		Target: "a.example.com", Masked: "adm***23", Source: "sourcemap 泄露", Verified: "verified"})
	for i := 0; i < 20; i++ {
		_, _ = st.AddLoot(&store.LootRecord{ProjectID: p.ID, Stage: "s5", Type: "credential",
			Target: "a.example.com", Masked: fmt.Sprintf("u%02d***x", i), Source: "泄露", Verified: "unverified"})
	}
	if _, err := o.exec.WriteFile("P-V650-S6H", "deliverables/s5-已验证漏洞与PoC.md",
		"# S5 已验证漏洞\n- V5-1 默认凭据登录"); err != nil {
		t.Fatal(err)
	}
	out = o.buildContextPack(p, "s6")
	for _, want := range []string{"S5 移交项（S6 开工承接", "[S5 就绪未执行] sqlmap 四件套批量提取",
		"[S5 已批未用] AP-XYZ", "[verified 战利品·通用块外]", "adm***23",
		"deliverables/s5-已验证漏洞与PoC.md"} {
		if !strings.Contains(out, want) {
			t.Errorf("s6 上下文缺少 %q", want)
		}
	}
	// verified 战利品恰出现一次（通用块 20 条上限外 → s6 移交块「通用块外」小节）
	if strings.Count(out, "adm***23") != 1 {
		t.Errorf("verified 战利品应恰出现一次（通用块外增量），实际 %d", strings.Count(out, "adm***23"))
	}
}

// TestV650HandoverGroupRendering S5-②：注入端分组渲染——组序=项目目标顺序在前、全局殿后；
// 单组不出小节（单目标零形态变化）；条目命中多个目标时归全局（不误打标）。
func TestV650HandoverGroupRendering(t *testing.T) {
	o, _ := v48Orchestrator(t)
	p := &store.Project{ROEAcknowledgedAt: "2026-11-23T00:00:00Z", ID: "P-V650-GRP",
		Target: "a.example.com\nb.example.com"}
	_ = o.store.SaveProject(p)
	p.StageStates = map[string]*store.StageState{"s4": {Status: "done",
		V3Ready: []string{
			"sqlmap 批量提取 b.example.com（B 目标条目）",
			"sqlmap 批量提取 a.example.com 与 b.example.com（双目标条目——归全局）",
			"无目标描述条目（全局）",
			"sqlmap 批量提取 a.example.com（A 目标条目）",
		}}}
	_ = o.store.SaveProject(p)
	out := o.buildContextPack(p, "s5")
	// 组序：a（项目目标第 1 位）→ b（第 2 位）→ 全局（殿后）
	ia := strings.Index(out, "**目标：a.example.com**")
	ib := strings.Index(out, "**目标：b.example.com**")
	ig := strings.Index(out, "**目标：全局**")
	if ia < 0 || ib < 0 || ig < 0 {
		t.Fatalf("三个分组小节均应渲染: a=%d b=%d 全局=%d", ia, ib, ig)
	}
	if !(ia < ib && ib < ig) {
		t.Errorf("组序应为 项目目标序在前、全局殿后: a=%d b=%d 全局=%d", ia, ib, ig)
	}
	// 双目标命中条目不打标（归全局组）
	if got := parseHandoverTarget(tagHandoverTarget("[就绪未执行] sqlmap 批量提取 a.example.com 与 b.example.com", splitProjectTargets(p))); got != "" {
		t.Errorf("命中多个目标的条目应归全局不打标: %q", got)
	}
	// 单组不出小节
	p2 := &store.Project{ROEAcknowledgedAt: "2026-11-23T00:00:00Z", ID: "P-V650-GRP2",
		Target: "a.example.com"}
	_ = o.store.SaveProject(p2)
	p2.StageStates = map[string]*store.StageState{"s4": {Status: "done",
		V3Ready: []string{"无目标描述条目"}}}
	_ = o.store.SaveProject(p2)
	out2 := o.buildContextPack(p2, "s5")
	if strings.Contains(out2, "**目标：") {
		t.Errorf("单组（单目标项目）不应出分组小节")
	}
	if !strings.Contains(out2, "### S4 移交项") {
		t.Errorf("单组仍应渲染移交项块本体")
	}
}

// TestV650S6HandoverHintTagged S5-⑩+S5-②：多目标项目 s6 移交块复用 @目标 标签——
// S5 V3 条目正文含目标时打标呈现；单目标项目不打标。
func TestV650S6HandoverHintTagged(t *testing.T) {
	o, st := v48Orchestrator(t)
	p := &store.Project{ROEAcknowledgedAt: "2026-11-23T00:00:00Z", ID: "P-V650-S6TAG",
		Target: "a.example.com\nb.example.com"}
	_ = o.store.SaveProject(p)
	p.StageStates = map[string]*store.StageState{"s5": {Status: "done",
		V3Ready: []string{"sqlmap 四件套批量提取 a.example.com"}}}
	_ = o.store.SaveProject(p)
	out := o.buildContextPack(p, "s6")
	if !strings.Contains(out, "[S5 就绪未执行@a.example.com]") {
		t.Errorf("多目标 s6 移交块应复用 @目标 标签: %s", truncateText(out, 200))
	}
	// 单目标：不打标
	p2 := &store.Project{ROEAcknowledgedAt: "2026-11-23T00:00:00Z", ID: "P-V650-S6TAG2",
		Target: "a.example.com"}
	_ = o.store.SaveProject(p2)
	p2.StageStates = map[string]*store.StageState{"s5": {Status: "done",
		V3Ready: []string{"sqlmap 四件套批量提取"}}}
	_ = o.store.SaveProject(p2)
	out2 := o.buildContextPack(p2, "s6")
	if strings.Contains(out2, "@a.example.com") {
		t.Errorf("单目标 s6 移交块不应打标")
	}
	_ = st
}

// TestV650S6HandoverHint S5-⑩（可选提示级校验）：S5 V3 非空且 S6 语料零引用 → 提示级
// log（不拦截）；S6 覆盖 notes 引用条目前缀后不再提示。
func TestV650S6HandoverHint(t *testing.T) {
	o, _ := v48Orchestrator(t)
	p := &store.Project{ROEAcknowledgedAt: "2026-11-23T00:00:00Z", ID: "P-V650-HINT",
		Target: "a.example.com"}
	_ = o.store.SaveProject(p)
	p.StageStates = map[string]*store.StageState{"s5": {Status: "done",
		V3Ready: []string{"sqlmap 四件套批量提取（四件套）"}}}
	_ = o.store.SaveProject(p)

	// S6 语料零引用 → 提示出现、不拦截
	issues := o.deterministicGate(p, "s6")
	for _, iss := range issues {
		if strings.Contains(iss, "承接提示") {
			t.Errorf("承接提示应为 log 提示级，不得进拦截 issues: %v", iss)
		}
	}
	streams, cursor, _ := o.store.ListStream(p.ID, 0)
	hint := false
	for _, srec := range streams {
		if strings.Contains(srec.Text, "S5→S6 承接提示") {
			hint = true
		}
	}
	if !hint {
		t.Errorf("S6 语料零引用应输出承接提示（stream log）")
	}

	// S6 覆盖 notes 引用条目正文前缀 → 不再提示（从上次游标之后查新增 stream）
	_, _ = o.store.UpsertCoverage(&store.CoverageEntry{ProjectID: p.ID, Stage: "s6",
		Endpoint: "http://a.example.com/api", VulnClass: "横向", Status: "vulnerable",
		Notes: "sqlmap 四件套批量提取（四件套）成果用于横向面盘点"})
	streams2, _, _ := o.store.ListStream(p.ID, cursor)
	hint2 := false
	for _, srec := range streams2 {
		if strings.Contains(srec.Text, "S5→S6 承接提示") {
			hint2 = true
		}
	}
	if hint2 {
		t.Errorf("S6 已承接（notes 引用条目前缀）不应再提示")
	}
}

// ---------- 全链路集成：S4 收口移交 → S5 分组消费与承接 → S5 收口 → S6 承接与提示 ----------

// TestV650LifecycleHandoverChain S5-②+S5-⑩ 全链路数据流：一条测试串起
// S4 收口（V3 清单+browser-auth 发现）→ S5 上下文分组呈现 → S5 承接留痕逐条放行 →
// S5 收口（自身 V3 清单）→ S6 上下文移交块 → S6 消费后提示消失。
func TestV650LifecycleHandoverChain(t *testing.T) {
	o, _ := v48Orchestrator(t)
	p := &store.Project{ROEAcknowledgedAt: "2026-11-23T00:00:00Z", ID: "P-V650-E2E",
		Target: "a.example.com\nb.example.com"}
	_ = o.store.SaveProject(p)

	// ── 第 1 段：S4 收口态——V3 两清单（各目标一条）+ browser-auth 移交发现 + S4 摘要
	p.StageStates = map[string]*store.StageState{"s4": {Status: "done",
		Summary:  "[测试范围] a/b 两目标 → [关键结果] 各 1 条待利用",
		V3Ready:  []string{"sqlmap 四件套批量提取 a.example.com", "sqlmap 四件套批量提取 b.example.com"},
		V3L2:     []string{"AP-100 已批 nmap 深扫（双目标）未投递"}}}
	_ = o.store.SaveProject(p)
	_, _ = o.store.AddFinding(&store.Finding{ProjectID: p.ID, Stage: "s4",
		Title: "登录面 JS 加密受阻移交浏览器通道 a.example.com", Detail: "browser-auth 路线",
		Severity: "高", Confidence: "疑似", Route: "browser-auth", Access: "anonymous", ImpactRank: 2})

	// ── 第 2 段：S5 开工上下文——分组呈现 + 认证路线小节 + S4 摘要在场
	out5 := o.buildContextPack(p, "s5")
	for _, want := range []string{
		"**目标：a.example.com**", "**目标：b.example.com**", "**目标：全局**",
		"[就绪未执行@a.example.com]", "[就绪未执行@b.example.com]",
		"[已批未用] AP-100", "S4 收口摘要：", "S4 认证路线移交", "A 目标的留痕不释放 B 目标的同类条目",
	} {
		if !strings.Contains(out5, want) {
			t.Errorf("S5 开工上下文缺少 %q", want)
		}
	}

	// ── 第 3 段：S5 承接推进——先只承接 a 与全局 → 门应点名 b 与认证项；补齐后全放行
	_, _ = o.store.UpsertCoverage(&store.CoverageEntry{ProjectID: p.ID, Stage: "s5",
		Endpoint: "http://a.example.com/api", VulnClass: "SQL注入", Status: "vulnerable",
		Notes: "sqlmap 四件套批量提取 a.example.com 已投递"})
	_, _ = o.store.UpsertCoverage(&store.CoverageEntry{ProjectID: p.ID, Stage: "s5",
		Endpoint: "http://a.example.com/api", VulnClass: "批量", Status: "vulnerable",
		Notes: "AP-100 已批 nmap 深扫（双目标）已按批准范围投递"})
	_, _ = o.store.UpsertCoverage(&store.CoverageEntry{ProjectID: p.ID, Stage: "s5",
		Endpoint: "http://a.example.com/login", VulnClass: "认证", Status: "needs_follow_up",
		Notes: "browser-auth 登录链承接：登录面 JS 加密受阻移交浏览器通道 a.example.com 前置知识复用"})
	issues := o.v3HandoverIssues(p)
	if len(issues) == 0 || !strings.Contains(issues[0], "b.example.com") {
		t.Fatalf("仅承接 a/全局时门应点名 b 目标条目: %v", issues)
	}
	// b 目标承接留痕（S5 交付物映射表形态）
	if _, err := o.exec.WriteFile("P-V650-E2E", "deliverables/s5-移交映射.md",
		"# S5 移交映射\n- sqlmap 四件套批量提取 b.example.com → 显式移交（待续清单）"); err != nil {
		t.Fatal(err)
	}
	if issues := o.v3HandoverIssues(p); len(issues) != 0 {
		t.Fatalf("b 承接留痕后应全放行: %v", issues)
	}

	// ── 第 4 段：S5 收口态——自身 V3 清单 + verified 战利品 + 交付物
	p.StageStates["s5"] = &store.StageState{Status: "done",
		V3Ready: []string{"b.example.com 横向面 sqlmap 提取成果"}, V3L2: []string{}}
	_ = o.store.SaveProject(p)
	_, _ = o.store.AddLoot(&store.LootRecord{ProjectID: p.ID, Stage: "s5", Type: "credential",
		Target: "a.example.com", Masked: "adm***23", Source: "sqlmap 提取", Verified: "verified"})
	if _, err := o.exec.WriteFile("P-V650-E2E", "deliverables/s5-已验证漏洞与PoC.md",
		"# S5 已验证漏洞\n- V5-1 sqlmap 提取"); err != nil {
		t.Fatal(err)
	}

	// ── 第 5 段：S6 开工上下文——移交块（@目标 标签复用 + verified 战利品 + 交付物指针）
	out6 := o.buildContextPack(p, "s6")
	for _, want := range []string{
		"S5 移交项（S6 开工承接", "[S5 就绪未执行@b.example.com]",
		"adm***23",
		"deliverables/s5-已验证漏洞与PoC.md", "deliverables/s5-移交映射.md",
	} {
		if !strings.Contains(out6, want) {
			t.Errorf("S6 开工上下文缺少 %q", want)
		}
	}

	// ── 第 6 段：S6 承接——基线（未承接 → 提示出现），coverage 引用条目后提示不再新增
	_ = o.deterministicGate(p, "s6") // 基线：未承接
	streams, cursor, _ := o.store.ListStream(p.ID, 0)
	baseHint := false
	for _, srec := range streams {
		if strings.Contains(srec.Text, "S5→S6 承接提示") {
			baseHint = true
		}
	}
	if !baseHint {
		t.Fatalf("S6 未承接时应输出承接提示")
	}
	// S6 coverage 引用 S5 V3 条目正文 → 下一轮不再新增提示
	_, _ = o.store.UpsertCoverage(&store.CoverageEntry{ProjectID: p.ID, Stage: "s6",
		Endpoint: "http://b.example.com/internal", VulnClass: "横向", Status: "vulnerable",
		Notes: "b.example.com 横向面 sqlmap 提取成果用于横向路径图"})
	_ = o.deterministicGate(p, "s6")
	streams2, _, _ := o.store.ListStream(p.ID, cursor)
	for _, srec := range streams2 {
		if strings.Contains(srec.Text, "S5→S6 承接提示") {
			t.Errorf("S6 coverage 引用条目后不应再出现新承接提示")
		}
	}
}

// TestV650LootCap20 S5-⑩：通用战利品块上限 10→20（第 11-20 条掩码应出现在上下文）。
func TestV650LootCap20(t *testing.T) {
	o, st := v48Orchestrator(t)
	p := &store.Project{ROEAcknowledgedAt: "2026-11-23T00:00:00Z", ID: "P-V650-LOOT",
		Target: "a.example.com"}
	_ = o.store.SaveProject(p)
	for i := 0; i < 15; i++ {
		_, _ = st.AddLoot(&store.LootRecord{ProjectID: p.ID, Stage: "s5", Type: "credential",
			Target: "a.example.com", Masked: string(rune('a'+i)) + "***" + string(rune('0'+i)),
			Source: "泄露", Verified: "unverified"})
	}
	out := o.buildContextPack(p, "s5")
	// 第 15 条（旧上限 10 之外）应出现在上下文
	if !strings.Contains(out, "o***\x0f") && !strings.Contains(out, "o***") {
		t.Errorf("第 15 条战利品（旧上限外）应出现在上下文")
	}
}

// TestV650SingleTargetReconUntouched S5-①⑤：单目标项目逐目标门不触发（targets==1 路径
// 不变），且 s5/s4 门各自不产出分段对账 issue。
func TestV650SingleTargetReconUntouched(t *testing.T) {
	o, _ := v48Orchestrator(t)
	p := &store.Project{ROEAcknowledgedAt: "2026-11-23T00:00:00Z", ID: "P-V650-ST",
		Target: "a.example.com"}
	_ = o.store.SaveProject(p)
	_, _ = o.store.UpsertCoverage(&store.CoverageEntry{ProjectID: p.ID, Stage: "s5",
		Endpoint: "http://a.example.com/api", VulnClass: "SQL注入", Status: "vulnerable"})
	for _, stage := range []string{"s4", "s5"} {
		for _, iss := range o.deterministicGate(p, stage) {
			if strings.Contains(iss, "分段收口对账") {
				t.Errorf("单目标项目不应触发逐目标门（%s）: %v", stage, iss)
			}
		}
	}
}

// TestV650ContextTextsAligned S5-⑨：非自适应阶段 else 分支文案含 s3（上下文承诺与
// stageBudget 名单一致——「不向模型撒谎」纪律）。
func TestV650ContextTextsAligned(t *testing.T) {
	o, _ := v48Orchestrator(t)
	p := &store.Project{ROEAcknowledgedAt: "2026-11-23T00:00:00Z", ID: "P-V650-TXT",
		Target: "a.example.com\nb.example.com"}
	_ = o.store.SaveProject(p)
	// v6.7.0 S6-⑩：s6 纳入自适应名单；v6.9.0 S8-④：s8 纳入——上下文应承诺放大
	//（不向模型撒谎），s7 仍是非自适应反例。
	out7 := o.buildContextPack(p, "s7")
	if !strings.Contains(out7, "自适应仅 s1/s2/s3/s4/s5/s6/s8/specA/specB1/specB2") {
		t.Errorf("非自适应阶段文案名单应与 stageBudget 一致（含 s6/s8）")
	}
	// s5/s3/s6/s8 adaptive 分支断言（多目标纪律块承诺放大——与 stageBudget 实现一致）
	for _, stage := range []string{"s5", "s3", "s6", "s8"} {
		outA := o.buildContextPack(p, stage)
		if !strings.Contains(outA, "本阶段轮次已按目标数自适应放大") {
			t.Errorf("%s 多目标上下文应承诺轮次自适应放大", stage)
		}
	}
}
