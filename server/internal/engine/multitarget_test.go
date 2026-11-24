package engine

import (
	"strings"
	"testing"

	"jiutouniao/internal/config"
	"jiutouniao/internal/events"
	"jiutouniao/internal/store"
)

func TestCountProjectTargets(t *testing.T) {
	cases := []struct {
		name   string
		target string
		want   int
	}{
		{"单目标", "http://a.com", 1},
		{"多目标含空行", "http://a.com\nhttp://b.com\n\nhttp://c.com", 3},
		{"首尾空白行", "\nhttp://a.com\n  \nhttp://b.com\n", 2},
		{"空串", "", 1},
		{"全空行", "\n\n  \n", 1},
		{"行首尾空白的目标行", "  http://a.com  \n\thttp://b.com\t", 2},
	}
	for _, c := range cases {
		if got := countProjectTargets(&store.Project{ ROEAcknowledgedAt: "2026-11-22T00:00:00Z",Target: c.target}); got != c.want {
			t.Errorf("%s: countProjectTargets=%d want=%d", c.name, got, c.want)
		}
	}
	if got := countProjectTargets(nil); got != 1 {
		t.Errorf("nil project: got=%d want=1", got)
	}
}

func TestStageBudget(t *testing.T) {
	const base = 60
	cases := []struct {
		name            string
		stage           string
		targets, perTgt int
		want            int
	}{
		{"s4 单目标双倍（v4.9 F3）", "s4", 1, 10, 120},
		{"s8 单目标双倍", "s8", 1, 10, 120},
		// v6.9.0 S8-④：s8 纳入多目标自适应——多目标报告按目标组织（分组合并逐组核对），
		// 工作量随目标数线性增长；s7 不入选（收尾按条目不按目标）。
		{"v6.9.0 S8-④：s8 纳入自适应（十目标线性，双倍基准）", "s8", 10, 10, 210},
		{"v6.9.0 S8-④：s8 三目标线性（双倍基准）", "s8", 3, 10, 140},
		{"v6.9.0 S8-④：s8 封顶（双倍基准）", "s8", 100, 10, 360},
		{"v6.9.0 S8-④：s8 perTarget=0 禁用（仍双倍）", "s8", 10, 0, 120},
		{"s7 不放大（v6.9.0 口径不变）", "s7", 10, 10, 60},
		{"s4 五目标线性（双倍基准）", "s4", 5, 10, 160},
		{"s2 十目标线性", "s2", 10, 10, 150},
		{"s5 三目标线性", "s5", 3, 10, 80},
		{"封顶 3 倍（s4 双倍基准）", "s4", 100, 10, 360},
		{"perTarget=0 禁用", "s2", 10, 0, 60},
		{"perTarget 负数禁用（s4 仍双倍）", "s4", 5, -1, 120},
		{"v6.1.0 方案⑤：s1 纳入自适应", "s1", 10, 10, 150},
		{"v6.7.0 S6-⑩：s6 纳入自适应", "s6", 10, 10, 150},
		{"v6.7.0 S6-⑩：s6 三目标线性", "s6", 3, 10, 80},
		{"v6.7.0 S6-⑩：s6 perTarget=0 禁用", "s6", 10, 0, 60},
		// v6.6.0 SP-①：三专项纳入多目标自适应；specB1 重执行阶段 ×2（对齐 v4.9 F3 给 s4 的先例）
		{"SP-① specB1 单目标双倍", "specB1", 1, 10, 120},
		{"SP-① specB1 三目标线性（双倍基准）", "specB1", 3, 10, 140},
		{"SP-① specA 三目标线性", "specA", 3, 10, 80},
		{"SP-① specB2 三目标线性", "specB2", 3, 10, 80},
		{"SP-① specA 封顶 3 倍", "specA", 100, 10, 180},
		{"SP-① specB1 封顶（双倍基准）", "specB1", 100, 10, 360},
		{"SP-① specB1 perTarget=0 仍双倍", "specB1", 5, 0, 120},
	}
	for _, c := range cases {
		if got := stageBudget(base, c.stage, c.targets, c.perTgt); got != c.want {
			t.Errorf("%s: stageBudget=%d want=%d", c.name, got, c.want)
		}
	}
}

func TestClampSubagentRounds(t *testing.T) {
	cases := []struct {
		name        string
		rounds, def int
		want        int
	}{
		{"默认", 0, 12, 12},
		{"负数取默认", -5, 12, 12},
		{"合法值保留", 25, 12, 25},
		{"上限钳到30", 50, 12, 30},
		{"恰在上限", 30, 12, 30},
	}
	for _, c := range cases {
		if got := clampSubagentRounds(c.rounds, c.def); got != c.want {
			t.Errorf("%s: clampSubagentRounds=%d want=%d", c.name, got, c.want)
		}
	}
}

// TestBuildContextPackMultiTarget 硬验证（方向二C）：多目标项目上下文包必须注入
// 「多目标推进纪律」块（目标级轮转/止损/档案目标）；单目标项目必须不注入。
func TestBuildContextPackMultiTarget(t *testing.T) {
	dir := t.TempDir()
	st, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	o := &Orchestrator{store: st, exec: newTestExec(t, dir), cfg: &config.Config{Engine: config.EngineConfig{PerTargetRounds: 10}}}
	o.heads = map[string]*Head{}

	multi := &store.Project{ ROEAcknowledgedAt: "2026-11-22T00:00:00Z",ID: "P-MT", Name: "多目标", Target: "a.example.com\nb.example.com\nc.example.net\nd.example.org\n192.168.100.10"}
	out := o.buildContextPack(multi, "s4")
	for _, want := range []string{"共 5 个", "🎯 多目标推进纪律", "目标级轮转先于类级轮转", "档案目标", "+10 轮"} {
		if !strings.Contains(out, want) {
			t.Errorf("多目标上下文包缺少 %q", want)
		}
	}
	single := &store.Project{ ROEAcknowledgedAt: "2026-11-22T00:00:00Z",ID: "P-ST", Name: "单目标", Target: "a.example.com"}
	out1 := o.buildContextPack(single, "s4")
	if strings.Contains(out1, "多目标推进纪律") {
		t.Error("单目标上下文包不应注入多目标纪律块")
	}
}

func TestSplitProjectTargets(t *testing.T) {
	p := &store.Project{ ROEAcknowledgedAt: "2026-11-22T00:00:00Z",Target: " a.example.com\n\nb.example.com \n"}
	got := splitProjectTargets(p)
	if len(got) != 2 || got[0] != "a.example.com" || got[1] != "b.example.com" {
		t.Errorf("splitProjectTargets=%v", got)
	}
	if len(splitProjectTargets(&store.Project{ ROEAcknowledgedAt: "2026-11-22T00:00:00Z",Target: " \n "})) != 0 {
		t.Error("全空行应得空列表")
	}
	if len(splitProjectTargets(nil)) != 0 {
		t.Error("nil 应得空列表")
	}
}

// TestTargetCoverageRecon S4 分段收口对账纯函数：归一化包含判定（覆盖语料/交付物语料双路归宿）。
func TestTargetCoverageRecon(t *testing.T) {
	targets := []string{"a.example.com", "b.example.com", "c.example.net", "d.example.org", "192.168.100.10"}
	cov := "http://a.example.com/news?id=1\x00SQL注入\x00vulnerable\x00\nhttp://B.Example.COM/x\x00\x00\x00\n"
	deliv := "# 待续清单\n- c.example.net：未覆盖，待回环\n192.168.100.10 列入档案目标（不可达）"
	missing, matched := targetCoverageRecon(targets, cov, deliv)
	// a（覆盖）/b（大小写归一化匹配）/c（待续清单）/192（档案目标）已归宿；d 两处皆无 = 真缺口
	if matched != 4 || len(missing) != 1 || missing[0] != "d.example.org" {
		t.Errorf("matched=%d missing=%v（仅 d.example.org 应缺失）", matched, missing)
	}
	empty, m0 := targetCoverageRecon(targets, "", "")
	if m0 != 0 || len(empty) != len(targets) {
		t.Errorf("空语料应全部未归宿: matched=%d missing=%d", m0, len(empty))
	}
}

// TestS4TargetCoverageGate 门级集成验证（批次6）：多目标 + ≥2 目标已真实覆盖 + 1 目标
// 两处皆无 → deterministicGate(s4) 拦截；全部归宿（含待续清单）→ 不拦。
func TestS4TargetCoverageGate(t *testing.T) {
	dir := t.TempDir()
	st, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	o := &Orchestrator{store: st, exec: newTestExec(t, dir), bus: events.NewBus(),
		cfg: &config.Config{Engine: config.EngineConfig{PerTargetRounds: 10}}}
	p := &store.Project{ ROEAcknowledgedAt: "2026-11-22T00:00:00Z",ID: "P6", Target: "a.example.com\nb.example.com\nc.example.org"}
	_ = st.SaveProject(p)
	if _, err := st.UpsertCoverage(&store.CoverageEntry{ProjectID: "P6", Stage: "s4",
		Endpoint: "http://a.example.com/api", VulnClass: "SQL注入", Status: "vulnerable"}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.UpsertCoverage(&store.CoverageEntry{ProjectID: "P6", Stage: "s4",
		Endpoint: "http://b.example.com/admin", VulnClass: "认证", Status: "no_issue_found"}); err != nil {
		t.Fatal(err)
	}

	issues := o.deterministicGate(p, "s4")
	hit := false
	for _, iss := range issues {
		if strings.Contains(iss, "S4 分段收口对账") && strings.Contains(iss, "c.example.org") {
			hit = true
		}
	}
	if !hit {
		t.Errorf("c.example.org 两处皆无应被拦截，issues=%v", issues)
	}
	// c 目标列入待续清单（deliverables）后 → 已归宿，不再拦
	if _, err := o.exec.WriteFile("P6", "deliverables/s4-待续清单.md", "# 待续清单\n- c.example.org：本轮未覆盖，回环补测"); err != nil {
		t.Fatal(err)
	}
	issues = o.deterministicGate(p, "s4")
	for _, iss := range issues {
		if strings.Contains(iss, "S4 分段收口对账") {
			t.Errorf("列入待续清单后不应再拦截: %v", issues)
		}
	}
}

// TestSpecTargetCoverageGate v6.6.0 SP-①（修复方案_三大专项补全）：多目标项目 specA/specB1/specB2
// 收口时 targetCoverageRecon——3 目标项目 specB1 只留痕 2 个 → 拦截；列入待续清单 → 放行；
// 单目标项目门不触发；其他阶段的 coverage 不为专项语料（Stage 过滤防跨阶段自匹配）。
func TestSpecTargetCoverageGate(t *testing.T) {
	dir := t.TempDir()
	st, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	o := &Orchestrator{store: st, exec: newTestExec(t, dir), bus: events.NewBus(),
		cfg: &config.Config{Engine: config.EngineConfig{PerTargetRounds: 10}}}
	p := &store.Project{ROEAcknowledgedAt: "2026-11-23T00:00:00Z", ID: "P-SP1", Name: "多APP",
		Target: "app-a.example.com\napp-b.example.com\napp-c.example.com"}
	_ = st.SaveProject(p)
	if _, err := st.UpsertCoverage(&store.CoverageEntry{ProjectID: "P-SP1", Stage: "specB1",
		Endpoint: "app-a.example.com", VulnClass: "认证", Status: "vulnerable"}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.UpsertCoverage(&store.CoverageEntry{ProjectID: "P-SP1", Stage: "specB1",
		Endpoint: "app-b.example.com", VulnClass: "越权", Status: "no_issue_found"}); err != nil {
		t.Fatal(err)
	}
	// 跨阶段自匹配防护：s4 阶段对 app-c 的留痕不得为 specB1 放行
	if _, err := st.UpsertCoverage(&store.CoverageEntry{ProjectID: "P-SP1", Stage: "s4",
		Endpoint: "app-c.example.com", VulnClass: "注入", Status: "vulnerable"}); err != nil {
		t.Fatal(err)
	}

	issues := o.deterministicGate(p, "specB1")
	hit := false
	for _, iss := range issues {
		if strings.Contains(iss, "specB1 分段收口对账") && strings.Contains(iss, "app-c.example.com") {
			hit = true
		}
	}
	if !hit {
		t.Errorf("app-c.example.com 两处皆无应被拦截（s4 语料不得代偿），issues=%v", issues)
	}
	// c 目标列入专项待续清单（deliverables，非 s4 前缀）→ 已归宿，不再拦
	if _, err := o.exec.WriteFile("P-SP1", "deliverables/specB1-待续清单.md", "# 待续清单\n- app-c.example.com：设备不可用，动态链移交"); err != nil {
		t.Fatal(err)
	}
	issues = o.deterministicGate(p, "specB1")
	for _, iss := range issues {
		if strings.Contains(iss, "specB1 分段收口对账") {
			t.Errorf("列入专项待续清单后不应再拦截: %v", issues)
		}
	}

	// 单目标项目：门不触发（targets==1 直通）
	single := &store.Project{ROEAcknowledgedAt: "2026-11-23T00:00:00Z", ID: "P-SP1-S", Name: "单APP",
		Target: "app-a.example.com"}
	_ = st.SaveProject(single)
	for _, iss := range o.deterministicGate(single, "specB1") {
		if strings.Contains(iss, "分段收口对账") {
			t.Errorf("单目标项目不应触发专项逐目标门: %v", iss)
		}
	}

	// matched=0：CIDR/描述性目标零命中 → 提示级留痕不拦（3 目标全部无语料）
	cidr := &store.Project{ROEAcknowledgedAt: "2026-11-23T00:00:00Z", ID: "P-SP1-C", Name: "描述目标",
		Target: "集团OA系统\n集团CRM系统\n集团邮箱系统"}
	_ = st.SaveProject(cidr)
	if issues := o.deterministicGate(cidr, "specB2"); len(issues) > 0 {
		for _, iss := range issues {
			if strings.Contains(iss, "分段收口对账") {
				t.Errorf("matched=0 应为提示级留痕不拦截: %v", iss)
			}
		}
	}
}

// TestSpecStageBudgetLogHint v6.6.0 SP-①：多目标专项阶段预算放大在执行日志留痕（与 s1-s5 同款）。
// 轻量验证：buildContextPack 对 specB1 多目标注入自适应纪律块（与 s4 同文案）。
func TestSpecStageBudgetLogHint(t *testing.T) {
	dir := t.TempDir()
	st, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	o := &Orchestrator{store: st, exec: newTestExec(t, dir), cfg: &config.Config{Engine: config.EngineConfig{PerTargetRounds: 10}}}
	o.heads = map[string]*Head{}
	multi := &store.Project{ROEAcknowledgedAt: "2026-11-23T00:00:00Z", ID: "P-SP1-B", Name: "多APP",
		Target: "app-a.test\napp-b.test\napp-c.test"}
	if out := o.buildContextPack(multi, "specB1"); !strings.Contains(out, "本阶段轮次已按目标数自适应放大") {
		t.Errorf("specB1 多目标上下文应注入自适应纪律块（SP-① 扩容后承诺一致）")
	}
}
// TestV620S2FanoutHintMultitarget v6.2.0 S2-⑥（方案回归清单：multitarget_test.go 扩展）：
// s2 多目标注入扇出提示、单目标不注入、s4/s5 既有提示不回归。
func TestV620S2FanoutHintMultitarget(t *testing.T) {
	dir := t.TempDir()
	st, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	o := &Orchestrator{store: st, exec: newTestExec(t, dir), cfg: &config.Config{Engine: config.EngineConfig{PerTargetRounds: 10}}}
	o.heads = map[string]*Head{}
	multi := &store.Project{ID: "P-V620-MT1", Name: "多目标", ROEAcknowledgedAt: "2026-11-23T00:00:00Z",
		Target: "a.test\nb.test\nc.test"}
	if out := o.buildContextPack(multi, "s2"); !strings.Contains(out, "并行扇出提示（S2 多目标）") {
		t.Errorf("s2 多目标上下文应注入扇出提示")
	}
	single := &store.Project{ID: "P-V620-MT2", Name: "单目标", ROEAcknowledgedAt: "2026-11-23T00:00:00Z",
		Target: "a.test"}
	if out1 := o.buildContextPack(single, "s2"); strings.Contains(out1, "并行扇出提示") {
		t.Errorf("s2 单目标上下文不应注入扇出提示")
	}
	if outS4 := o.buildContextPack(multi, "s4"); !strings.Contains(outS4, "并行扇出提示") {
		t.Errorf("s4 扇出提示不得回归")
	}
}
