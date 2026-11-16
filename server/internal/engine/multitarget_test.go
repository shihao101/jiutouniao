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
		if got := countProjectTargets(&store.Project{Target: c.target}); got != c.want {
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
		{"s8 双倍不受影响", "s8", 1, 10, 120},
		{"s8 多目标也不放大", "s8", 10, 10, 120},
		{"s4 五目标线性（双倍基准）", "s4", 5, 10, 160},
		{"s2 十目标线性", "s2", 10, 10, 150},
		{"s5 三目标线性", "s5", 3, 10, 80},
		{"封顶 3 倍（s4 双倍基准）", "s4", 100, 10, 360},
		{"perTarget=0 禁用", "s2", 10, 0, 60},
		{"perTarget 负数禁用（s4 仍双倍）", "s4", 5, -1, 120},
		{"非侦察/发现/利用阶段不放大", "s1", 10, 10, 60},
		{"s7 不放大", "s7", 10, 10, 60},
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

	multi := &store.Project{ID: "P-MT", Name: "多目标", Target: "a.example.com\nb.example.com\nc.example.net\nd.example.org\n192.168.100.10"}
	out := o.buildContextPack(multi, "s4")
	for _, want := range []string{"共 5 个", "🎯 多目标推进纪律", "目标级轮转先于类级轮转", "档案目标", "+10 轮"} {
		if !strings.Contains(out, want) {
			t.Errorf("多目标上下文包缺少 %q", want)
		}
	}
	single := &store.Project{ID: "P-ST", Name: "单目标", Target: "a.example.com"}
	out1 := o.buildContextPack(single, "s4")
	if strings.Contains(out1, "多目标推进纪律") {
		t.Error("单目标上下文包不应注入多目标纪律块")
	}
}

func TestSplitProjectTargets(t *testing.T) {
	p := &store.Project{Target: " a.example.com\n\nb.example.com \n"}
	got := splitProjectTargets(p)
	if len(got) != 2 || got[0] != "a.example.com" || got[1] != "b.example.com" {
		t.Errorf("splitProjectTargets=%v", got)
	}
	if len(splitProjectTargets(&store.Project{Target: " \n "})) != 0 {
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
	p := &store.Project{ID: "P6", Target: "a.example.com\nb.example.com\nc.example.org"}
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
