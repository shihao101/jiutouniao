// v7.0.0 核对加固：OOB 门与深度门的 dispatch 级集成测试——
// 前两轮只验过纯函数与"实现存在性"，本文件验证真实工具调用路径上的行为：
// load_skill 盲态门（直接命中）、update_coverage 盲态 OOB 门、深度门、Depth 字段持久化回路。
package engine

import (
	"context"
	"net"
	"time"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"jiutouniao/internal/config"
	"jiutouniao/internal/events"
	"jiutouniao/internal/llm"
	"jiutouniao/internal/store"
	"jiutouniao/internal/tools"
)

func oobSkillDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	skill := "---\nid: ssrf-deep\ntitle: SSRF 手册\ntags: ssrf,s4\n---\n# SSRF 测试正文\n\noob 回连载荷示例。"
	if err := os.WriteFile(filepath.Join(dir, "ssrf-deep.md"), []byte(skill), 0o600); err != nil {
		t.Fatal(err)
	}
	return dir
}

func oobDispatchFixture(t *testing.T, skillDir string) (*Orchestrator, *store.Project) {
	t.Helper()
	dir := t.TempDir()
	st, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{}
	cfg.ApplyDefaultsForTest()
	exec, err := tools.NewExecutor(filepath.Join(dir, "ws"), 10, 64*1024, struct {
		Forbidden, HighRisk, MedRisk, ReadOnly, Sensitive []string
	}{})
	if err != nil {
		t.Fatal(err)
	}
	skills, err := LoadSkills(skillDir)
	if err != nil {
		t.Fatal(err)
	}
	o := &Orchestrator{
		cfg: cfg, store: st, bus: events.NewBus(), exec: exec, skills: skills,
		heads: map[string]*Head{},
		running: map[string]context.CancelFunc{}, tokens: map[string]int64{},
		inputs: map[string][]string{}, loops: map[string][]string{},
		liveP: map[string]*store.Project{}, projModel: map[string]string{},
		batchStats: map[string]*batchBudgetState{}, modelWarn: map[string]bool{},
	}
	o.oob = NewOOBCoord(cfg.OOB, exec, nil, func() bool { return false })
	p := &store.Project{ID: "t-oob-dispatch", Name: "oob 集成测试"}
	return o, p
}

func oobInjectHealthy(o *Orchestrator, projectID string) {
	o.oob.mu.Lock()
	o.oob.ch[projectID] = &oobChannel{ProjectID: projectID, Status: "healthy",
		BaseDomain: "case.t.oast.pro", Kind: "interactsh", SelfCheck: "ok", builtAt: time.Now()}
	o.oob.mu.Unlock()
}

func oobDispatch(o *Orchestrator, p *store.Project, name, argsJSON string) string {
	return o.dispatch(context.Background(), p, "s4", llm.ToolCall{Name: name, Arguments: argsJSON})
}

// 1) 盲态技能门：通道不可用（mode=off）→ load_skill 直接命中拒绝注入
func TestOOBDispatchBlindSkillBlocked(t *testing.T) {
	o, p := oobDispatchFixture(t, oobSkillDir(t))
	o.oob.SetOverride(&config.OOBConfig{Mode: "off"})
	out := oobDispatch(o, p, "load_skill", `{"id":"ssrf-deep"}`)
	if !strings.Contains(out, "盲态技能前置门") || !strings.Contains(out, "未注入") {
		t.Fatalf("盲态技能门未拦截，got %q", out)
	}
}

// 2) 盲态技能门：通道健康 → 技能正文正常注入
func TestOOBDispatchBlindSkillAllowed(t *testing.T) {
	o, p := oobDispatchFixture(t, oobSkillDir(t))
	oobInjectHealthy(o, p.ID)
	out := oobDispatch(o, p, "load_skill", `{"id":"ssrf-deep"}`)
	if !strings.Contains(out, "【技能 ssrf-deep】") || !strings.Contains(out, "SSRF 测试正文") {
		t.Fatalf("健康通道下技能应正常注入，got %q", out)
	}
}

// 3) 盲态 OOB 门：通道不可用 → ruled_out 自动降级 needs_follow_up
func TestOOBDispatchCoverageDowngradeNoChannel(t *testing.T) {
	o, p := oobDispatchFixture(t, oobSkillDir(t))
	o.oob.SetOverride(&config.OOBConfig{Mode: "off"})
	out := oobDispatch(o, p, "update_coverage",
		`{"endpoint":"GET /api/x","vuln_class":"SSRF","status":"ruled_out","observed_result":"negative_valid","notes":"差分一致"}`)
	if !strings.Contains(out, "盲态类 OOB 门") || !strings.Contains(out, "needs_follow_up") {
		t.Fatalf("通道不可用时盲态 ruled_out 应降级，got %q", out)
	}
	entries, _ := o.store.ListCoverage(p.ID)
	if len(entries) != 1 || entries[0].Status != "needs_follow_up" {
		t.Fatalf("入库状态应为 needs_follow_up，got %+v", entries)
	}
}

// 4) 深度门：通道健康但 depth=D1 → 降级；depth=D3 → ruled_out 入库且 Depth 落账
func TestOOBDispatchCoverageDepthGate(t *testing.T) {
	o, p := oobDispatchFixture(t, oobSkillDir(t))
	oobInjectHealthy(o, p.ID)
	out := oobDispatch(o, p, "update_coverage",
		`{"endpoint":"GET /api/y","vuln_class":"SSRF","status":"ruled_out","observed_result":"negative_valid","notes":"n","depth":"D1"}`)
	if !strings.Contains(out, "盲态类深度门") {
		t.Fatalf("depth=D1 应触发深度门降级，got %q", out)
	}
	out2 := oobDispatch(o, p, "update_coverage",
		`{"endpoint":"GET /api/y","vuln_class":"SSRF","status":"ruled_out","observed_result":"negative_valid","notes":"n2","depth":"D3"}`)
	if strings.Contains(out2, "降为 needs_follow_up") || strings.Contains(out2, "盲态类") {
		t.Fatalf("depth=D3 且通道健康应放行，got %q", out2)
	}
	entries, _ := o.store.ListCoverage(p.ID)
	if len(entries) != 1 || entries[0].Status != "ruled_out" {
		t.Fatalf("终态应为 ruled_out，got %+v", entries)
	}
	if entries[0].Depth != "D3" {
		t.Fatalf("Depth 应为 D3，got %q（回路断裂）", entries[0].Depth)
	}
}

// 5) Depth 持久化回路：同键二次提交必须回写新 Depth（核对加固⑦）
func TestOOBDepthRoundTripStore(t *testing.T) {
	dir := t.TempDir()
	st, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	base := store.CoverageEntry{ProjectID: "t", Stage: "s4", Endpoint: "GET /z",
		Param: "", VulnClass: "XXE", Status: "needs_follow_up", Notes: "n"}
	first, err := st.UpsertCoverage(&base)
	if err != nil {
		t.Fatal(err)
	}
	if first.Depth != "" {
		t.Fatalf("首次提交 Depth 应为空，got %q", first.Depth)
	}
	second := base
	second.Status, second.Notes, second.Depth = "no_issue_found", "n2", "D2"
	updated, err := st.UpsertCoverage(&second)
	if err != nil {
		t.Fatal(err)
	}
	if updated.Depth != "D2" {
		t.Fatalf("同键二次提交 Depth 应回写为 D2，got %q（加固⑦未生效）", updated.Depth)
	}
}

// 8) 热生效作用于已建通道：SetOverride 后缓存通道被回收，下次 Ensure 按新配置裁决（核对加固⑧）
func TestOOBSetOverrideInvalidatesCache(t *testing.T) {
	o, p := oobDispatchFixture(t, oobSkillDir(t))
	oobInjectHealthy(o, p.ID)
	if !o.oob.Healthy(p) {
		t.Fatal("注入通道应 healthy")
	}
	o.oob.SetOverride(&config.OOBConfig{Mode: "off"})
	if ch := o.oob.Ensure(p, ""); ch != nil {
		t.Fatalf("mode=off 热生效后 Ensure 应返回 nil，got %+v", ch)
	}
	out := oobDispatch(o, p, "load_skill", `{"id":"ssrf-deep"}`)
	if !strings.Contains(out, "盲态技能前置门") {
		t.Fatalf("热生效后盲态门应按新配置拦截，got %q", out)
	}
}

// 9) S1 warmup 自动预建（加固⑨）：A2 通道真实绑定 → channel.txt 落盘 → S1 门⑪核验通过
func TestOOBS1WarmupManagedChannel(t *testing.T) {
	o, p := oobDispatchFixture(t, oobSkillDir(t))
	// 找空闲端口：Listen(":0") 取分配端口后释放，避免测试间冲突
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()
	o.oob.SetOverride(&config.OOBConfig{Mode: "local",
		Local: config.OOBLocalConfig{SubMode: "listener", HTTPPort: port}})

	ch := o.oob.Ensure(p, "s1") // 模拟 runStage S1 warmup 钩子
	if ch == nil || ch.Status != "healthy" {
		t.Fatalf("S1 warmup 通道应 healthy，got %+v", ch)
	}
	content, err := o.exec.ReadFile(p.ID, "evidence/oob/channel.txt")
	if err != nil {
		t.Fatalf("channel.txt 未落盘: %v", err)
	}
	if !oobChannelSelfCheckPassed(content) {
		t.Fatalf("S1 收口门⑪不认可引擎托管通道文件：%q", content)
	}
	o.oob.Stop(p.ID) // 项目收口回收（finishRun 钩子路径）
}

// 10) run_async 通道进程拦截（加固⑩）：dispatch 真实路径返回结构性指引
func TestOOBRunAsyncGuardBlocked(t *testing.T) {
	o, p := oobDispatchFixture(t, oobSkillDir(t))
	out := oobDispatch(o, p, "run_async",
		`{"command":"interactsh-client -json -sf /tmp/oob.sf","reason":"起回连通道","timeout":"7200"}`)
	if !strings.Contains(out, "禁止经 run_async") || !strings.Contains(out, "oob_check") {
		t.Fatalf("run_async 通道进程应被确定性拦截并指引 oob_check，got %q", out)
	}
}
