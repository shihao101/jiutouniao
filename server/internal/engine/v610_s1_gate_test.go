// v6.1.0（S1 修复方案）治理硬门回归测试。
// P0-① 授权硬门：创建/启动/命令三级拒绝未授权项目；显式关闭仅事故回滚。
package engine

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"jiutouniao/internal/config"
	"jiutouniao/internal/llm"
	"jiutouniao/internal/store"
)

// TestV610CreateProjectRequiresAuthorization 创建级授权门：Authorized=false 直接拒绝且不落库。
func TestV610CreateProjectRequiresAuthorization(t *testing.T) {
	o := testOrchestratorForCreate(t)
	_, err := o.CreateProject(&store.Project{Name: "未授权项目", Target: "http://127.0.0.1:1", Authorized: false})
	if err == nil || !strings.Contains(err.Error(), "书面授权") {
		t.Fatalf("未授权创建应被拒绝且文案含「书面授权」: err=%v", err)
	}
	projects, _ := o.store.ListProjects()
	if len(projects) != 0 {
		t.Fatalf("被拒项目不得落库: got %d", len(projects))
	}
	if _, err := o.CreateProject(&store.Project{Name: "已授权项目", Target: "http://127.0.0.1:1", Authorized: true}); err != nil {
		t.Fatalf("已授权项目应创建成功: %v", err)
	}
}

// TestV610StartProjectRequiresAuthorization 启动级授权门：历史未授权项目禁止续跑且状态不变、留证。
func TestV610StartProjectRequiresAuthorization(t *testing.T) {
	o := testOrchestratorForCreate(t)
	p := &store.Project{ID: "P-V610-START", Name: "历史未授权", Target: "http://127.0.0.1:1",
		Authorized: false, Status: "paused", StageStates: map[string]*store.StageState{}}
	if err := o.store.SaveProject(p); err != nil {
		t.Fatal(err)
	}
	err := o.StartProject(p.ID)
	if err == nil || !strings.Contains(err.Error(), "授权未确认") {
		t.Fatalf("历史未授权项目应拒绝启动: err=%v", err)
	}
	got, _ := o.store.GetProject(p.ID)
	if got.Status != "paused" {
		t.Fatalf("拒绝启动不得变更状态: got %s", got.Status)
	}
	evs, _ := o.store.ListEvidence(p.ID)
	found := false
	for _, e := range evs {
		if e.ApprovedBy == "authorization-gate" {
			found = true
		}
	}
	if !found {
		t.Fatalf("启动拒绝应留 authorization-gate 证据: %+v", evs)
	}
}

// TestV610GovernanceAuthorizationGateBeforeApproval 命令级授权门：L0 命令在审批前被拦、无审批工单、留证据。
func TestV610GovernanceAuthorizationGateBeforeApproval(t *testing.T) {
	o := testOrchestratorForCreate(t)
	p := &store.Project{ID: "P-V610-GATE", Name: "授权命令门", Target: "http://127.0.0.1:1",
		Authorized: false, StrictScope: false}
	if err := o.store.SaveProject(p); err != nil {
		t.Fatal(err)
	}
	msg := o.governanceGates(p, "s1", "curl -s http://127.0.0.1:1/", "run_command", false)
	if !strings.Contains(msg, "授权未确认") {
		t.Fatalf("L0 命令应被授权门拦截: %q", msg)
	}
	aps, _ := o.store.ListApprovals(p.ID)
	if len(aps) != 0 {
		t.Fatalf("授权门拦截不得产生审批工单: %+v", aps)
	}
	evs, _ := o.store.ListEvidence(p.ID)
	found := false
	for _, e := range evs {
		if e.ApprovedBy == "authorization-gate" && strings.Contains(e.Input, "curl -s") {
			found = true
		}
	}
	if !found {
		t.Fatalf("命令拦截应留 authorization-gate 证据（含命令原文）: %+v", evs)
	}
}

// TestV610AuthorizationGateRollbackFlag 显式关闭授权门=事故回滚路径，恢复旧行为（其余治理门照常）。
func TestV610AuthorizationGateRollbackFlag(t *testing.T) {
	o := testOrchestratorForCreate(t)
	f := false
	o.cfg = &config.Config{Guard: config.GuardConfig{EnforceAuthorization: &f}}
	p := &store.Project{ID: "P-V610-RB", Name: "回滚开关", Target: "http://127.0.0.1:1",
		Authorized: false, StrictScope: false}
	if err := o.store.SaveProject(p); err != nil {
		t.Fatal(err)
	}
	msg := o.governanceGates(p, "s4", "curl -s http://127.0.0.1:1/", "run_command", false)
	if strings.Contains(msg, "授权未确认") {
		t.Fatalf("显式关闭后授权门不得拦截: %q", msg)
	}
	// 已授权项目不受任何配置影响
	p2 := &store.Project{ID: "P-V610-RB2", Name: "已授权", Target: "http://127.0.0.1:1",
		Authorized: true, StrictScope: false}
	o2 := testOrchestratorForCreate(t)
	if msg2 := o2.governanceGates(p2, "s4", "curl -s http://127.0.0.1:1/", "run_command", false); strings.Contains(msg2, "授权未确认") {
		t.Fatalf("已授权项目不应被授权门拦截: %q", msg2)
	}
}

// TestV610AuthorizationGateDefaultsOn 缺省（nil 指针/零配置）必须开启——缺字段不允许静默关闭。
func TestV610AuthorizationGateDefaultsOn(t *testing.T) {
	o := testOrchestratorForCreate(t)
	o.cfg = &config.Config{} // 未调用 applyDefaults：字段 nil → 语义仍为开启
	p := &store.Project{ID: "P-V610-DEF", Name: "缺省开启", Authorized: false, StrictScope: false}
	if err := o.store.SaveProject(p); err != nil {
		t.Fatal(err)
	}
	if msg := o.governanceGates(p, "s1", "curl -s http://127.0.0.1:1/", "run_command", false); !strings.Contains(msg, "授权未确认") {
		t.Fatalf("nil 配置下授权门应按缺省开启拦截: %q", msg)
	}
	// applyDefaults 归一后同为开启
	c := &config.Config{}
	c.ApplyDefaultsForTest()
	if !config.FlagOrDefault(c.Guard.EnforceAuthorization, true) {
		t.Fatal("applyDefaults 后授权门应为 true")
	}
}

// mustJSON 测试参数序列化助手。
func mustJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// ---- v6.1.0 P0-② 影子资产门 ----

// TestV610ShadowAssetRecordDoesNotAuthorize 登记线索≠测试授权：shadow_pending 资产的测试流量被拦且留证。
func TestV610ShadowAssetRecordDoesNotAuthorize(t *testing.T) {
	o := testOrchestratorForCreate(t)
	p := &store.Project{ID: "P-V610-SH", Name: "影子门", Target: "https://auth.example.com",
		Authorized: true, StrictScope: true, ROEAcknowledgedAt: "2026-11-22T00:00:00Z", }
	if err := o.store.SaveProject(p); err != nil {
		t.Fatal(err)
	}
	_, _ = o.store.AddAsset(&store.Asset{ProjectID: p.ID, Stage: "s1", Type: "域名",
		Value: "shadow.example.com", ScopeStatus: "shadow_pending", Source: "CT日志"})
	msg := o.governanceGates(p, "s2", "curl -s https://shadow.example.com/admin", "run_command", false)
	if !strings.Contains(msg, "未授权测试") {
		t.Fatalf("shadow_pending 资产的请求应被影子门拦截: %q", msg)
	}
	evs, _ := o.store.ListEvidence(p.ID)
	found := false
	for _, e := range evs {
		if e.ApprovedBy == "shadow-scope-gate" {
			found = true
		}
	}
	if !found {
		t.Fatal("影子门拦截应留 shadow-scope-gate 证据")
	}
}

// TestV610AssetScopeLegacyDefaultUnknown 旧库无 scope_status 字段 → unknown fail-closed，不放行。
func TestV610AssetScopeLegacyDefaultUnknown(t *testing.T) {
	o := testOrchestratorForCreate(t)
	p := &store.Project{ID: "P-V610-LG", Name: "旧数据", Target: "https://auth.example.com",
		Authorized: true, StrictScope: true, ROEAcknowledgedAt: "2026-11-22T00:00:00Z", }
	_ = o.store.SaveProject(p)
	// 模拟旧 JSON：无 scope_status 字段（ZeroValue 即缺省）
	a := &store.Asset{ProjectID: p.ID, Stage: "s1", Type: "域名", Value: "legacy.example.net"}
	if got := a.EffectiveScope(); got != "unknown" {
		t.Fatalf("无字段资产应为 unknown: %s", got)
	}
	_, _ = o.store.AddAsset(a)
	msg := o.governanceGates(p, "s2", "curl -s https://legacy.example.net/x", "run_command", false)
	if !strings.Contains(msg, "未授权测试") {
		t.Fatalf("unknown（旧数据）资产应 fail-closed 拦截: %q", msg)
	}
}

// TestV610HostAllowedRequiresExplicitWildcard 主域不再自动放行子域；显式通配条目才放行。
func TestV610HostAllowedRequiresExplicitWildcard(t *testing.T) {
	allow := map[string]bool{}
	if !hostAllowed("auth.example.com", "https://auth.example.com/login", allow) {
		t.Fatal("精确目标行必须放行")
	}
	if hostAllowed("shadow.auth.example.com", "https://auth.example.com", allow) {
		t.Fatal("主域子域后缀不得再自动放行（v6.1.0 删除）")
	}
	if hostAllowed("sub.example.com", "*.example.test", allow) {
		t.Fatal("通配条目域不匹配不得放行")
	}
	if !hostAllowed("sub.example.test", "*.example.test", allow) {
		t.Fatal("显式通配授权条目应放行其子域")
	}
	// 多目标逐行精确匹配（v2.4.0 逐行清单）
	multi := "a.test\nb.test\n"
	if !hostAllowed("b.test", multi, allow) || hostAllowed("c.test", multi, allow) {
		t.Fatal("多目标清单应逐行精确匹配")
	}
}

// TestV610ScopeExtensionApprovalSetsInScope 授权扩展批准 → in_scope + 依据，范围门放行。
func TestV610ScopeExtensionApprovalSetsInScope(t *testing.T) {
	o := testOrchestratorForCreate(t)
	p := &store.Project{ID: "P-V610-EXT", Name: "扩展批准", Target: "https://auth.example.com",
		Authorized: true, StrictScope: true, ROEAcknowledgedAt: "2026-11-22T00:00:00Z", }
	_ = o.store.SaveProject(p)
	if err := o.ApplyScopeExtension(p.ID, "new.example.net"); err != nil {
		t.Fatal(err)
	}
	assets, _ := o.store.ListAssets(p.ID)
	ok := false
	for _, a := range assets {
		if a.Value == "new.example.net" && a.EffectiveScope() == "in_scope" && a.ScopeEvidence != "" {
			ok = true
		}
	}
	if !ok {
		t.Fatalf("扩展批准资产应为 in_scope 且附依据: %+v", assets)
	}
	if msg := o.governanceGates(p, "s6", "curl -s https://new.example.net/", "run_command", false); strings.Contains(msg, "范围外") || strings.Contains(msg, "未授权测试") {
		t.Fatalf("扩展批准后应被范围门放行: %q", msg)
	}
}

// TestV610ShadowGateStrictScopeOff strict_scope=false 时影子门依然拦截（登记≠授权与范围开关无关）。
func TestV610ShadowGateStrictScopeOff(t *testing.T) {
	o := testOrchestratorForCreate(t)
	p := &store.Project{ID: "P-V610-NS", Name: "非严格范围", Target: "https://auth.example.com",
		Authorized: true, StrictScope: false, ROEAcknowledgedAt: "2026-11-22T00:00:00Z", }
	_ = o.store.SaveProject(p)
	_, _ = o.store.AddAsset(&store.Asset{ProjectID: p.ID, Stage: "s1", Type: "域名",
		Value: "open.example.org", ScopeStatus: "shadow_pending"})
	msg := o.governanceGates(p, "s2", "curl -s https://open.example.org/", "run_command", false)
	if !strings.Contains(msg, "未授权测试") {
		t.Fatalf("strict_scope=false 时影子门仍应拦截: %q", msg)
	}
}

// TestV610RecordAssetRequiresEvidenceForInScope record_asset：in_scope 缺依据拒绝；metadata 凭据键拒绝。
func TestV610RecordAssetRequiresEvidenceForInScope(t *testing.T) {
	o := testOrchestratorForCreate(t)
	p := &store.Project{ID: "P-V610-RA", Name: "登记校验", Authorized: true}
	_ = o.store.SaveProject(p)
	args := map[string]any{"type": "域名", "value": "x.example.com", "scope_status": "in_scope"}
	if r := o.dispatch(context.Background(), p, "s1", llm.ToolCall{Name: "record_asset", Arguments: mustJSON(t, args)}); !strings.Contains(r, "scope_evidence") {
		t.Fatalf("in_scope 缺依据应拒绝: %s", r)
	}
	args2 := map[string]any{"type": "云账号", "value": "tenant-1", "scope_status": "shadow_pending",
		"metadata": map[string]any{"access_key": "AKIA123"}}
	if r := o.dispatch(context.Background(), p, "s1", llm.ToolCall{Name: "record_asset", Arguments: mustJSON(t, args2)}); !strings.Contains(r, "禁止存放凭据") {
		t.Fatalf("metadata 凭据键应拒绝: %s", r)
	}
	args3 := map[string]any{"type": "域名", "value": "x.example.com", "scope_status": "in_scope",
		"scope_evidence": "项目授权清单第1条"}
	r := o.dispatch(context.Background(), p, "s1", llm.ToolCall{Name: "record_asset", Arguments: mustJSON(t, args3)})
	if !strings.Contains(r, "已登记资产") || !strings.Contains(r, "in_scope") {
		t.Fatalf("合规登记应成功: %s", r)
	}
}

// ---- v6.1.0 P1-③ S1 阶段 L0 门 ----

// TestV610S1ToolDefsFiltered S1 工具面隐藏执行/交互/子代理类工具并追加本地合并器。
func TestV610S1ToolDefsFiltered(t *testing.T) {
	o, _ := v48Orchestrator(t)
	s1 := o.toolDefsForStage("s1")
	names := map[string]bool{}
	for _, d := range s1 {
		names[d.Name] = true
	}
	for _, hidden := range []string{"run_async", "run_batch", "http_request", "cred_command",
		"hexstrike_command", "install_tool", "shell_open", "shell_write", "shell_read", "shell_close",
		"spawn_subagent", "poll_subagents"} {
		if names[hidden] {
			t.Fatalf("S1 工具面不应暴露 %s", hidden)
		}
	}
	for _, keep := range []string{"run_command", "write_file", "read_file", "record_asset", "complete_stage", "build_s1_subdomain_input"} {
		if !names[keep] {
			t.Fatalf("S1 工具面应保留 %s", keep)
		}
	}
	// 非 S1 阶段全量工具面不变
	s4 := o.toolDefsForStage("s4")
	if len(s4) <= len(s1) {
		t.Fatal("S4 工具面应大于 S1 过滤后工具面")
	}
}

// TestV610S1StageGateBlocksNmapAndHTTPX 扫描器动词即使全局 L0 也拦（目标探测是主动流量）。
func TestV610S1StageGateBlocksNmapAndHTTPX(t *testing.T) {
	o, st := v48Orchestrator(t)
	p := &store.Project{ID: "P-V610-S1A", Name: "S1门", Target: "https://auth.example.com",
		Authorized: true, StrictScope: false, ROEAcknowledgedAt: "2026-11-22T00:00:00Z", }
	_ = st.SaveProject(p)
	for _, cmd := range []string{
		"nmap -sV -Pn --top-ports 1000 auth.example.com",
		"httpx -l targets.txt -title -tech-detect",
		"whatweb -a 1 https://auth.example.com",
	} {
		msg := o.governanceGates(p, "s1", cmd, "run_command", false)
		if !strings.Contains(msg, "S1 禁止目标侧探测/扫描") {
			t.Fatalf("扫描器 %q 应被 S1 阶段门拦截: %q", cmd, msg)
		}
	}
	aps, _ := st.ListApprovals(p.ID)
	if len(aps) != 0 {
		t.Fatal("S1 门拦截不得产生审批工单")
	}
}

// TestV610S1StageGateBlocksCurlToProjectTarget 对目标 HTTP GET（即使全局 L0）一律拦。
func TestV610S1StageGateBlocksCurlToProjectTarget(t *testing.T) {
	o, st := v48Orchestrator(t)
	p := &store.Project{ID: "P-V610-S1B", Name: "S1目标HTTP", Target: "https://auth.example.com",
		Authorized: true, StrictScope: false, ROEAcknowledgedAt: "2026-11-22T00:00:00Z", }
	_ = st.SaveProject(p)
	msg := o.governanceGates(p, "s1", "curl -s https://auth.example.com/", "run_command", false)
	if !strings.Contains(msg, "不连接目标服务") {
		t.Fatalf("对目标的 HTTP GET 应被拦: %q", msg)
	}
	if _, err := st.GetAsset(p.ID, "A-NONE"); err == nil {
		t.Fatal("占位")
	}
}

// TestV610S1StageGateAllowsPassiveSources CT/DNS/WHOIS/测绘等被动源放行。
func TestV610S1StageGateAllowsPassiveSources(t *testing.T) {
	o, _ := v48Orchestrator(t)
	p := &store.Project{ID: "P-V610-S1C", Name: "S1被动", Target: "https://auth.example.com",
		Authorized: true, StrictScope: false, ROEAcknowledgedAt: "2026-11-22T00:00:00Z", }
	_ = o.store.SaveProject(p)
	for _, cmd := range []string{
		"curl -s \"https://crt.sh/?q=auth.example.com&output=json\"",
		"dig +short auth.example.com ANY",
		"host auth.example.com",
		"whois example.com",
		"dig +short MX auth.example.com",
	} {
		if msg := o.governanceGates(p, "s1", cmd, "run_command", false); msg != "" {
			t.Fatalf("被动查询 %q 不应被拦: %q", cmd, msg)
		}
	}
}

// TestV610S1GateAcrossCommandChannels S1 门跨通道：run_async/shell_open 等直调仍拦（即使工具面已隐藏）。
func TestV610S1GateAcrossCommandChannels(t *testing.T) {
	o, _ := v48Orchestrator(t)
	p := &store.Project{ID: "P-V610-S1D", Name: "S1跨通道", Target: "https://auth.example.com",
		Authorized: true, StrictScope: false, ROEAcknowledgedAt: "2026-11-22T00:00:00Z", }
	_ = o.store.SaveProject(p)
	for _, ch := range []string{"run_command", "run_async", "run_batch", "shell_open", "hexstrike"} {
		msg := o.governanceGates(p, "s1", "nmap -sV auth.example.com", ch, false)
		if !strings.Contains(msg, "S1 禁止目标侧探测/扫描") {
			t.Fatalf("通道 %s 应被 S1 阶段门拦截: %q", ch, msg)
		}
	}
}

// ---- v6.1.0 P1-④ S1 确定性收口门 / P1-⑤ 多目标预算与逐目标对账 ----

// s1ClosureFixture 构造一个 S1 收口测试项目（四件套写全/缺件可控）。
func s1ClosureFixture(t *testing.T, o *Orchestrator, targets string, inScope bool, files map[string]string) *store.Project {
	t.Helper()
	p := &store.Project{ID: "P-V610-S1CL", Name: "S1收口", Target: targets,
		Authorized: true, StrictScope: false, ROEAcknowledgedAt: "2026-11-22T00:00:00Z", 
		 StageStates: map[string]*store.StageState{
			"s1": {Status: "running"},
		}}
	_ = o.store.SaveProject(p)
	for _, tgt := range splitProjectTargets(p) {
		st := "shadow_pending"
		if inScope {
			st = "in_scope"
		}
		_, _ = o.store.AddAsset(&store.Asset{ProjectID: p.ID, Stage: "s1", Type: "域名",
			Value: tgt, TargetRef: tgt, ScopeStatus: st, ScopeEvidence: "项目授权清单"})
	}
	for f, body := range files {
		_, _ = o.exec.WriteFile(p.ID, f, body)
	}
	return p
}

var s1FourPackFixture = map[string]string{
	"deliverables/s1-资产台账.md":         "# S1 资产台账\n\n| # | 目标 | scope_status |\n|---|---|---|\n| 1 | a.test | in_scope |\n",
	"deliverables/s1-范围边界表.md":        "# S1 范围边界表\n\n| 资产 | 状态 |\n|---|---|\n| a.test | in_scope（授权清单） |\n",
	"deliverables/s1-架构草图V0.md":       "# 架构草图 V0\n\n信任边界：无。\n",
	"deliverables/s1-影子资产线索清单.md":     "# 影子资产线索\n\n无候选（未核实）。\n",
}

func TestV610S1ClosureRequiresFourDeliverables(t *testing.T) {
	o, _ := v48Orchestrator(t)
	p := s1ClosureFixture(t, o, "a.test", true, s1FourPackFixture)
	// 缺范围边界表 → 固定文案
	_, _ = o.exec.WriteFile(p.ID, "deliverables/s1-范围边界表.md", "")
	issues := o.s1ClosureIssues(p)
	found := false
	for _, iss := range issues {
		if strings.Contains(iss, "缺少 deliverables/s1-范围边界表.md") {
			found = true
		}
	}
	if !found {
		t.Fatalf("缺范围表应返回固定文案: %v", issues)
	}
	// 四件套齐全 → 无 issues
_, _ = o.exec.WriteFile(p.ID, "deliverables/s1-范围边界表.md", s1FourPackFixture["deliverables/s1-范围边界表.md"])
	if issues := o.s1ClosureIssues(p); len(issues) != 0 {
		t.Fatalf("四件套齐全+逐目标归宿应通过: %v", issues)
	}
}

func TestV610S1ClosureRejectsEmptyOrHeaderOnlyArtifacts(t *testing.T) {
	o, _ := v48Orchestrator(t)
	files := map[string]string{}
	for k, v := range s1FourPackFixture {
		files[k] = v
	}
	files["deliverables/s1-资产台账.md"] = "占位" // <40 字节空壳
	p := s1ClosureFixture(t, o, "a.test", true, files)
	issues := o.s1ClosureIssues(p)
	hit := false
	for _, iss := range issues {
		if strings.Contains(iss, "s1-资产台账.md") && strings.Contains(iss, "占位空壳") {
			hit = true
		}
	}
	if !hit {
		t.Fatalf("空壳台账应被拦: %v", issues)
	}
}

func TestV610S1TargetReconMissingOneTargetBlocks(t *testing.T) {
	o, _ := v48Orchestrator(t)
	p := s1ClosureFixture(t, o, "a.test\nb.test\nc.test", true, s1FourPackFixture)
	_, _ = o.exec.WriteFile(p.ID, "deliverables/s1-范围边界表.md", "")
	// 删掉 b.test 的资产记录——用独立项目重造：只登记 a/c
	o2, _ := v48Orchestrator(t)
	p2 := &store.Project{ID: "P-V610-S1CL2", Name: "缺目标", Target: "a.test\nb.test\nc.test",
		Authorized: true, StageStates: map[string]*store.StageState{"s1": {Status: "running"}}}
	_ = o2.store.SaveProject(p2)
	for _, tgt := range []string{"a.test", "c.test"} {
		_, _ = o2.store.AddAsset(&store.Asset{ProjectID: p2.ID, Stage: "s1", Type: "域名",
			Value: tgt, TargetRef: tgt, ScopeStatus: "in_scope", ScopeEvidence: "授权清单"})
	}
	issues := o2.s1ClosureIssues(p2)
	hit := false
	for _, iss := range issues {
		if strings.Contains(iss, "b.test 缺少资产台账记录") {
			hit = true
		}
	}
	if !hit {
		t.Fatalf("缺 b.test 台账应逐目标拦截: %v", issues)
	}
	_ = p
	_ = o
}

func TestV610S1TargetReconExactMatchNotSubstring(t *testing.T) {
	// canonicalTargetKey 精确匹配：a.ndu.edu.tw 不得命中 ndu.edu.tw 的资产记录
	assets := []*store.Asset{{Value: "ndu.edu.tw", TargetRef: "ndu.edu.tw", ScopeStatus: "in_scope"}}
	noAsset, _ := missingS1TargetRefs([]string{"a.ndu.edu.tw"}, assets)
	if len(noAsset) != 1 {
		t.Fatalf("子串不得视为已归宿: noAsset=%v", noAsset)
	}
	noAsset2, _ := missingS1TargetRefs([]string{"ndu.edu.tw"}, assets)
	if len(noAsset2) != 0 {
		t.Fatalf("精确键应命中: noAsset=%v", noAsset2)
	}
}

func TestV610S1TargetReconIgnoresBlankLines(t *testing.T) {
	o, _ := v48Orchestrator(t)
	p := &store.Project{ID: "P-V610-S1BL", Name: "空行", Target: "a.test\n\n\nb.test\n\n",
		Authorized: true, ROEAcknowledgedAt: "2026-11-22T00:00:00Z", 
		 StageStates: map[string]*store.StageState{"s1": {Status: "running"}}}
	_ = o.store.SaveProject(p)
	if got := len(splitProjectTargets(p)); got != 2 {
		t.Fatalf("空行不应计数: got %d", got)
	}
	for _, tgt := range splitProjectTargets(p) {
		_, _ = o.store.AddAsset(&store.Asset{ProjectID: p.ID, Stage: "s1", Type: "域名",
			Value: tgt, TargetRef: tgt, ScopeStatus: "in_scope", ScopeEvidence: "授权清单"})
	}
	for f, body := range s1FourPackFixture {
		_, _ = o.exec.WriteFile(p.ID, f, body)
	}
	if issues := o.s1ClosureIssues(p); len(issues) != 0 {
		t.Fatalf("空行目标不应误报缺失: %v", issues)
	}
}

func TestV610DeterministicGateRunsForS1(t *testing.T) {
	o, _ := v48Orchestrator(t)
	p := &store.Project{ID: "P-V610-S1DG", Name: "确定性门", Target: "a.test",
		Authorized: true, ROEAcknowledgedAt: "2026-11-22T00:00:00Z", 
		 StageStates: map[string]*store.StageState{"s1": {Status: "running"}}}
	_ = o.store.SaveProject(p)
	issues := o.deterministicGate(p, "s1")
	if len(issues) == 0 {
		t.Fatal("deterministicGate(s1) 应执行 S1 确定性门（四件套缺失必有 issues）")
	}
	if !strings.Contains(issues[0], "S1 确定性门") {
		t.Fatalf("首个 issue 应来自 S1 确定性门: %v", issues[0])
	}
}

func TestV610S1BudgetAdaptive(t *testing.T) {
	// ⑤：S1 加入多目标自适应名单——base+(N-1)*perTarget，封顶 3×base
	cases := []struct {
		name           string
		stage          string
		base, tgt, pt  int
		want           int
	}{
		{"单目标不变", "s1", 10, 1, 10, 10},
		{"多目标线性", "s1", 10, 3, 10, 30},
		{"多目标封顶", "s1", 10, 99, 10, 30},
		{"s2 同步自适应", "s2", 10, 3, 10, 30},
		{"s4 乘数保留", "s4", 10, 3, 10, 40}, // base*2 + (3-1)*10 = 40
		{"perTarget 禁用", "s1", 10, 3, 0, 10},
	}
	for _, c := range cases {
		if got := stageBudget(c.base, c.stage, c.tgt, c.pt); got != c.want {
			t.Fatalf("%s: stageBudget(%d,%s,%d,%d)=%d want %d", c.name, c.base, c.stage, c.tgt, c.pt, got, c.want)
		}
	}
}

// ---- v6.1.0 P2-⑩ ROE 红线确认门 ----

func TestV610ROEAckRequiredBeforeCommand(t *testing.T) {
	o, _ := v48Orchestrator(t)
	p := &store.Project{ID: "P-V610-ACK", Name: "红线确认", Target: "https://auth.example.com",
		Authorized: true, StrictScope: false}
	_ = o.store.SaveProject(p)
	msg := o.governanceGates(p, "s2", "curl -s https://auth.example.com/", "run_command", false)
	if !strings.Contains(msg, "ROE 红线确认") {
		t.Fatalf("未确认 ROE 的命令应被确认门拦截: %q", msg)
	}
	// 确认后放行（curl 指向目标：s1 门不适用（s2），授权/影子/范围门无涉）
	p.ROEAcknowledgedAt = "2026-11-22T00:00:00Z"
	if msg := o.governanceGates(p, "s2", "curl -s https://auth.example.com/", "run_command", false); strings.Contains(msg, "ROE 红线确认") {
		t.Fatalf("确认后应放行: %q", msg)
	}
}

func TestV610ROEAckAffirmativePersists(t *testing.T) {
	o, _ := v48Orchestrator(t)
	p := &store.Project{ID: "P-V610-ACK2", Name: "确认持久化", Authorized: true}
	_ = o.store.SaveProject(p)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan string, 1)
	go func() { done <- o.dispatch(ctx, p, "s1", llm.ToolCall{Name: "request_user_input", Arguments: mustJSON(t, map[string]any{"purpose": "roe_ack", "question": "四要素复述"})}) }()
	// 等待 ask 记录出现后回答 yes
	deadline := time.Now().Add(3 * time.Second)
	var askID string
	for time.Now().Before(deadline) {
		asks, _ := o.store.ListAsks(p.ID)
		if len(asks) > 0 {
			askID = asks[0].ID
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if askID == "" {
		t.Fatal("roe_ack 提问未落库")
	}
	if err := o.AnswerAsk(askID, "yes", "测试员"); err != nil {
		t.Fatal(err)
	}
	out := <-done
	if !strings.Contains(out, "红线确认完成") {
		t.Fatalf("yes 应回答并置位: %s", out)
	}
	got, _ := o.store.GetProject(p.ID)
	if got.ROEAcknowledgedAt == "" {
		t.Fatal("ROEAcknowledgedAt 未持久化")
	}
}

func TestV610ROEAckNegativeDoesNotPersist(t *testing.T) {
	o, _ := v48Orchestrator(t)
	p := &store.Project{ID: "P-V610-ACK3", Name: "否定不置位", Authorized: true}
	_ = o.store.SaveProject(p)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan string, 1)
	go func() { done <- o.dispatch(ctx, p, "s1", llm.ToolCall{Name: "request_user_input", Arguments: mustJSON(t, map[string]any{"purpose": "roe_ack", "question": "四要素复述"})}) }()
	deadline := time.Now().Add(3 * time.Second)
	var askID string
	for time.Now().Before(deadline) {
		asks, _ := o.store.ListAsks(p.ID)
		if len(asks) > 0 {
			askID = asks[0].ID
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	_ = o.AnswerAsk(askID, "no", "测试员")
	out := <-done
	if !strings.Contains(out, "未通过") {
		t.Fatalf("no 应回答但拒绝置位: %s", out)
	}
	got, _ := o.store.GetProject(p.ID)
	if got.ROEAcknowledgedAt != "" {
		t.Fatal("否定回答不得置位 ROEAcknowledgedAt")
	}
}

func TestV610ROEAckRollbackFlag(t *testing.T) {
	o, _ := v48Orchestrator(t)
	f := false
	o.cfg = &config.Config{Guard: config.GuardConfig{RequireS1ROEAck: &f}}
	p := &store.Project{ID: "P-V610-ACK4", Name: "回滚", Authorized: true, StrictScope: false}
	_ = o.store.SaveProject(p)
	if msg := o.governanceGates(p, "s2", "curl -s http://127.0.0.1:1/", "run_command", false); strings.Contains(msg, "ROE 红线确认") {
		t.Fatalf("显式关闭后确认门不得拦截: %q", msg)
	}
}

// ---- v6.1.0 P1-⑧ ROE 运行时门 ----

func roeProfileFixture(t *testing.T) *ROEProfile {
	t.Helper()
	dir := t.TempDir()
	path := dir + "/roe.yaml"
	content := `profile: test-proj
write_policy: existence-proof
scope:
  note: 项目授权清单
waf_policy:
  offline_challenge: deny
identity:
  auto_register: deny
outbound:
  residential_proxy: deny
windows: '{"start":"09:00","end":"18:00","tz":"UTC"}'
max_conn_per_s: 2
rotation: capped:3
cooldown_protocol: full-silence
`
	if err := osWriteFile(path, content); err != nil {
		t.Fatal(err)
	}
	rp, err := LoadROEProfile(path)
	if err != nil {
		t.Fatal(err)
	}
	return rp
}

func osWriteFile(path, content string) error {
	return os.WriteFile(path, []byte(content), 0o600)
}

func TestV610ROEWindowBlocksOutsideUTC(t *testing.T) {
	rp := roeProfileFixture(t)
	e := NewROERuntimeEnforcer(rp)
	// 窗口外（03:00 UTC）
	out := time.Date(2026, 11, 22, 3, 0, 0, 0, time.UTC)
	if msg := e.Check("s2", "curl -s https://x.example/", out); !strings.Contains(msg, "时间窗") {
		t.Fatalf("窗口外应拦截: %q", msg)
	}
	// 窗口内（12:00 UTC）
	in := time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)
	if msg := e.Check("s2", "curl -s https://x.example/", in); msg != "" {
		t.Fatalf("窗口内应放行: %q", msg)
	}
}

func TestV610ROERateLimitCountsConnections(t *testing.T) {
	rp := roeProfileFixture(t)
	e := NewROERuntimeEnforcer(rp)
	now := time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)
	if msg := e.Check("s2", "cmd1", now); msg != "" {
		t.Fatalf("第 1 次应放行: %q", msg)
	}
	if msg := e.Check("s2", "cmd2", now.Add(100 * time.Millisecond)); msg != "" {
		t.Fatalf("第 2 次应放行（max=2）: %q", msg)
	}
	if msg := e.Check("s2", "cmd3", now.Add(200 * time.Millisecond)); !strings.Contains(msg, "连接预算") {
		t.Fatalf("第 3 次应超预算拦截: %q", msg)
	}
	// 1 秒滑窗过后恢复
	if msg := e.Check("s2", "cmd4", now.Add(1100 * time.Millisecond)); msg != "" {
		t.Fatalf("滑窗过后应放行: %q", msg)
	}
}

func TestV610ROECooldownFullSilence(t *testing.T) {
	rp := roeProfileFixture(t)
	e := NewROERuntimeEnforcer(rp)
	now := time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)
	e.NoteCooldown(now)
	if msg := e.Check("s2", "cmd", now.Add(1 * time.Minute)); !strings.Contains(msg, "冷却协议") {
		t.Fatalf("full-silence 冷却期应拦截: %q", msg)
	}
	if msg := e.Check("s2", "cmd", now.Add(6 * time.Minute)); strings.Contains(msg, "冷却协议") {
		t.Fatalf("冷却结束后应放行: %q", msg)
	}
}

func TestV610ROEUnsupportedEnforcementFailsClosed(t *testing.T) {
	// rotation 未接入出口层：诚实标注 unenforced（Digest + UnenforcedFields），不伪装已强制
	rp := roeProfileFixture(t)
	e := NewROERuntimeEnforcer(rp)
	une := e.UnenforcedFields()
	if len(une) == 0 || !strings.Contains(une[0], "rotation") {
		t.Fatalf("rotation 应列入 unenforced: %v", une)
	}
	d := rp.Digest()
	if !strings.Contains(d, "unenforced") || !strings.Contains(d, "不得当作引擎已强制") {
		t.Fatalf("Digest 应诚实标注 rotation unenforced: %s", d)
	}
	if !strings.Contains(d, "ROE 运行时门（引擎强制）") {
		t.Fatalf("Digest 应标注已强制项: %s", d)
	}
}

// ---- v6.1.0 P2-⑮ 逐目标行为类教训 / ⑱ 目标计数单源 ----

func TestV610LessonsBehaviorClassScopedPerTarget(t *testing.T) {
	o, st := v48Orchestrator(t)
	p := &store.Project{ID: "P-V615-LS", Name: "逐目标教训", Target: "slow.example.com\nwaf.example.org",
		Authorized: true, ROEAcknowledgedAt: "2026-11-22T00:00:00Z"}
	_ = st.SaveProject(p)
	_, _ = st.UpsertFact(&store.FactRecord{ProjectID: p.ID, Key: "behavior.slow.example.com", Value: "rate-limited", Confidence: "confirmed"})
	_, _ = st.UpsertFact(&store.FactRecord{ProjectID: p.ID, Key: "behavior.waf.example.org", Value: "js-challenge-waf", Confidence: "confirmed"})
	_, _ = st.AddLesson(&store.LessonRecord{Text: "限速目标先 probe 后 batch：连续 000 时退避并降并发", Tags: "限速,批量", BehaviorClass: "rate-limited", ValidScope: "通用"})
	_, _ = st.AddLesson(&store.LessonRecord{Text: "JS 挑战站 curl 直连全 000：先 channel-snapshot 取会话态再复放", Tags: "JS挑战,通道", BehaviorClass: "js-challenge-waf", ValidScope: "通用"})
	cp := o.buildContextPack(p, "s2")
	if !strings.Contains(cp, "目标 slow.example.com（行为类 rate-limited）") {
		t.Fatalf("多目标应逐目标标注行为类: %s", cp[len(cp)-1200:])
	}
	if !strings.Contains(cp, "目标 waf.example.org（行为类 js-challenge-waf）") {
		t.Fatal("第二目标行为类缺失")
	}
	// 行为类教训标注在对应目标段内（A 的教训不得标到 B）
	slowIdx := strings.Index(cp, "slow.example.com（行为类 rate-limited）")
	wafIdx := strings.Index(cp, "waf.example.org（行为类 js-challenge-waf）")
	limMark := strings.Index(cp, "限速目标先 probe 后 batch")
	jsMark := strings.Index(cp, "JS 挑战站 curl 直连")
	if !(slowIdx < limMark && limMark < wafIdx && wafIdx < jsMark) {
		t.Fatalf("教训应按目标分段归属: slow=%d lim=%d waf=%d js=%d", slowIdx, limMark, wafIdx, jsMark)
	}
}

func TestV610LessonsMissingTargetClassDoesNotLeak(t *testing.T) {
	o, st := v48Orchestrator(t)
	p := &store.Project{ID: "P-V615-LS2", Name: "无分型目标", Target: "a.example.com\nb.example.com",
		Authorized: true, ROEAcknowledgedAt: "2026-11-22T00:00:00Z"}
	_ = st.SaveProject(p)
	_, _ = st.UpsertFact(&store.FactRecord{ProjectID: p.ID, Key: "behavior.a.example.com", Value: "rate-limited", Confidence: "confirmed"})
	_, _ = st.AddLesson(&store.LessonRecord{Text: "限速目标先 probe 后 batch", Tags: "限速", BehaviorClass: "rate-limited", ValidScope: "通用"})
	cp := o.buildContextPack(p, "s2")
	if !strings.Contains(cp, "b.example.com（行为类未分型") {
		t.Fatal("无分型目标应显式标注未分型（不伪造默认类）")
	}
}

func TestV610SingleTargetLessonsRemainStable(t *testing.T) {
	o, st := v48Orchestrator(t)
	p := &store.Project{ID: "P-V615-LS3", Name: "单目标", Target: "solo.example.com",
		Authorized: true, ROEAcknowledgedAt: "2026-11-22T00:00:00Z"}
	_ = st.SaveProject(p)
	_, _ = st.UpsertFact(&store.FactRecord{ProjectID: p.ID, Key: "behavior.solo.example.com", Value: "rate-limited", Confidence: "confirmed"})
	_, _ = st.AddLesson(&store.LessonRecord{Text: "限速目标先 probe 后 batch", Tags: "限速", BehaviorClass: "rate-limited", ValidScope: "通用"})
	cp := o.buildContextPack(p, "s2")
	if strings.Contains(cp, "目标 solo.example.com（行为类") {
		t.Fatal("单目标应保持旧全局段形态（不拆分目标段）")
	}
	if !strings.Contains(cp, "组织级教训（跨项目脱敏经验）") {
		t.Fatal("单目标教训段应在")
	}
}

func TestV610ContextTargetCountSkipsBlankLines(t *testing.T) {
	o, st := v48Orchestrator(t)
	p := &store.Project{ID: "P-V618-TC", Name: "空行计数", Target: "a.test\n\n\nb.test\n",
		Authorized: true, ROEAcknowledgedAt: "2026-11-22T00:00:00Z"}
	_ = st.SaveProject(p)
	cp := o.buildContextPack(p, "s1")
	if !strings.Contains(cp, "共 2 个") {
		t.Fatalf("上下文应跳过空行计数为 2: %s", cp[:600])
	}
}

func TestV610EmptyTargetRejectedBeforeS1(t *testing.T) {
	o, _ := v48Orchestrator(t)
	p := &store.Project{ID: "P-V618-ET", Name: "空目标", Target: "\n\n", Authorized: true,
		ROEAcknowledgedAt: "2026-11-22T00:00:00Z"}
	_ = o.store.SaveProject(p)
	cp := o.buildContextPack(p, "s1")
	if !strings.Contains(cp, "项目目标为空") {
		t.Fatalf("空目标 S1 应拒绝: %s", cp)
	}
}

func TestV610S1ContextDoesNotAssumeAllTargetsInScope(t *testing.T) {
	o, st := v48Orchestrator(t)
	p := &store.Project{ID: "P-V618-SI", Name: "不预判范围", Target: "a.test\nb.test",
		Authorized: true, ROEAcknowledgedAt: "2026-11-22T00:00:00Z"}
	_ = st.SaveProject(p)
	cp := o.buildContextPack(p, "s1")
	if strings.Contains(cp, "全部在范围内") {
		t.Fatal("上下文不得预判「全部在范围内」（范围判定由 S1-3 逐项产出）")
	}
	if !strings.Contains(cp, "范围状态以《范围边界表》逐项判定为准") {
		t.Fatal("应引导逐项范围判定")
	}
}

// ---- v6.1.0 P2-⑭ manifest stage_fit ↔ frontmatter tags 一致性 / ⑬ 路由断链 / ⑫ 合并器 ----

func TestV610ManifestStageFitMatchesFrontmatter(t *testing.T) {
	dir := "../../.." // 仓库根（skills/ 相对 server/internal/engine）
	reg, err := LoadSkills(dir + "/skills")
	if err != nil {
		t.Fatal(err)
	}
	if reg == nil || len(reg.skills) == 0 {
		t.Fatal("技能库加载失败")
	}
	for id, s := range reg.skills {
		if s.StageFit == nil {
			continue // 无 manifest 条目的技能跳过（frontmatter 无 stage_fit 概念）
		}
		fmStage := map[string]bool{}
		for _, tg := range s.Tags {
			t := strings.ToLower(strings.TrimSpace(tg))
			if strings.HasPrefix(t, "s") && len(t) == 2 && t[1] >= '1' && t[1] <= '8' {
				fmStage[t] = true
			}
			for _, pfx := range []string{"spec"} {
				_ = pfx
			}
		}
		for _, sf := range s.StageFit {
			if strings.HasPrefix(sf, "s") && len(sf) == 2 && sf[1] >= '1' && sf[1] <= '8' {
				if !fmStage[sf] {
					t.Errorf("%s: manifest stage_fit 含 %s 但 frontmatter tags 缺失（v6.1.0 ⑭ 一致性门）", id, sf)
				}
			}
		}
	}
}

func TestV610RouterToolReferencesResolve(t *testing.T) {
	router, err := os.ReadFile("../../../skills/00-router.md")
	if err != nil {
		t.Fatal(err)
	}
	text := string(router)
	// logic-invariant 必须以工具脚本路径出现，不得再当技能 ID（v6.1.0 ⑬）
	if !strings.Contains(text, "tools-extra/logic-invariant.py") {
		t.Fatal("路由应指向 tools-extra/logic-invariant.py（容器路径 /opt/tools/logic-invariant.py）")
	}
	if _, err := os.Stat("../../../tools-extra/logic-invariant.py"); err != nil {
		t.Fatal("logic-invariant.py 必须存在于 tools-extra/")
	}
}

func TestV610BuildS1SubsInputDedupSort(t *testing.T) {
	o, st := v48Orchestrator(t)
	p := &store.Project{ID: "P-V610-SUB", Name: "合并器", Authorized: true, ROEAcknowledgedAt: "2026-11-22T00:00:00Z"}
	_ = st.SaveProject(p)
	_, _ = o.exec.WriteFile(p.ID, "evidence/s1-crtsh-subs.txt", "b.example.com\na.example.com\nb.example.com\n")
	_, _ = o.exec.WriteFile(p.ID, "evidence/s1-subfinder.txt", "c.example.com\n")
	out, err := o.buildS1SubdomainInput(p)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "候选 3 条") || !strings.Contains(out, "来源 2 个") {
		t.Fatalf("合并器输出去重计数不符: %s", out)
	}
	final, _ := o.exec.ReadFile(p.ID, "evidence/s1-subs-final.txt")
	if final != "a.example.com\nb.example.com\nc.example.com" {
		t.Fatalf("应排序去重: %q", final)
	}
	manifest, _ := o.exec.ReadFile(p.ID, "evidence/s1-subs-manifest.json")
	if !strings.Contains(manifest, `"status":"ok"`) || !strings.Contains(manifest, `"candidates":3`) {
		t.Fatalf("manifest 应含状态与候选数: %s", manifest)
	}
	if !strings.Contains(manifest, `"sha256":"`) {
		t.Fatalf("manifest 应附输出哈希（方案⑫）：可核验脚本输入=合并器输出: %s", manifest)
	}
}

func TestV610BuildS1SubsInputNoSourcesMarkedNotChecked(t *testing.T) {
	o, st := v48Orchestrator(t)
	p := &store.Project{ID: "P-V610-SUB2", Name: "无来源", Authorized: true, ROEAcknowledgedAt: "2026-11-22T00:00:00Z"}
	_ = st.SaveProject(p)
	out, err := o.buildS1SubdomainInput(p)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "status=not_checked") {
		t.Fatalf("无来源应标 not_checked（不静默当零候选）: %s", out)
	}
	manifest, _ := o.exec.ReadFile(p.ID, "evidence/s1-subs-manifest.json")
	if !strings.Contains(manifest, "not_checked") {
		t.Fatalf("manifest 应记 not_checked: %s", manifest)
	}
}

// ---- v6.1.0 P2-⑳ 类型化台账字段 / ㉑ 路径解析 ----

func TestV610AssetMetadataByTypeValidation(t *testing.T) {
	o, st := v48Orchestrator(t)
	p := &store.Project{ID: "P-V610-TY", Name: "类型字段", Authorized: true, ROEAcknowledgedAt: "2026-11-22T00:00:00Z"}
	_ = st.SaveProject(p)
	// APP 缺 platform/version/backend_api → 拒绝
	args := map[string]any{"type": "APP", "value": "某App", "scope_status": "shadow_pending"}
	if r := o.dispatch(context.Background(), p, "s1", llm.ToolCall{Name: "record_asset", Arguments: mustJSON(t, args)}); !strings.Contains(r, "类型化台账字段") {
		t.Fatalf("APP 缺类型字段应拒绝: %s", r)
	}
	// 补齐（值可 unknown）→ 通过
	args2 := map[string]any{"type": "APP", "value": "某App", "scope_status": "shadow_pending",
		"metadata": map[string]any{"platform": "android", "version": "unknown", "backend_api": "unknown"}}
	if r := o.dispatch(context.Background(), p, "s1", llm.ToolCall{Name: "record_asset", Arguments: mustJSON(t, args2)}); !strings.Contains(r, "已登记资产") {
		t.Fatalf("字段齐全应通过: %s", r)
	}
	// 云账号缺 provider/role/region → 拒绝
	args3 := map[string]any{"type": "云账号", "value": "tenant-1", "scope_status": "shadow_pending"}
	if r := o.dispatch(context.Background(), p, "s1", llm.ToolCall{Name: "record_asset", Arguments: mustJSON(t, args3)}); !strings.Contains(r, "provider/role/region") {
		t.Fatalf("云账号缺字段应拒绝: %s", r)
	}
}

func TestV610AssetMetadataLegacyJSONCompatible(t *testing.T) {
	// 旧库无 metadata 字段：反序列化为 nil map 不报错（类型字段校验仅约束新建）
	a := &store.Asset{}
	if err := json.Unmarshal([]byte(`{"id":"A-1","type":"域名","value":"x.example.com"}`), a); err != nil {
		t.Fatal(err)
	}
	if a.Metadata != nil || a.EffectiveScope() != "unknown" {
		t.Fatalf("旧 JSON 兼容破坏: %+v scope=%s", a.Metadata, a.EffectiveScope())
	}
}

func TestV610ResolveResourceDirsRelativeToConfig(t *testing.T) {
	cfg := "/srv/jiutouniao/conf/config.json"
	if got := ResolveResourceDir(cfg, "", "heads"); got != "/srv/jiutouniao/conf/heads" {
		t.Fatalf("相对路径应以 config 目录为基准: %s", got)
	}
	if got := ResolveResourceDir(cfg, "/opt/custom/heads", "heads"); got != "/opt/custom/heads" {
		t.Fatalf("绝对路径应直接使用: %s", got)
	}
	if got := ResolveResourceDir(cfg, "", "skills"); got != "skills" && !strings.HasSuffix(got, "skills") {
		t.Fatalf("缺省回退: %s", got)
	}
}

// v6.6.0 回放驱动修复回归：描述性目标回退词边界；主机形态保持精确键。
func TestV66DescriptiveTargetFallback(t *testing.T) {
	assets := []*store.Asset{
		{Value: "微信小程序 demo（wx12345678）", TargetRef: "小程序测试", ScopeStatus: "in_scope", ScopeEvidence: "授权清单"},
		{Value: "https://10.10.254.116/index.html", ScopeStatus: "in_scope", ScopeEvidence: "授权清单"},
		{Value: "ndu.edu.tw", ScopeStatus: "in_scope", ScopeEvidence: "授权清单"},
	}
	// 描述性目标 → 词边界命中
	noAsset, noScope := missingS1TargetRefs([]string{"小程序测试"}, assets)
	if len(noAsset)+len(noScope) != 0 {
		t.Fatalf("描述性目标应经词边界命中: noAsset=%v noScope=%v", noAsset, noScope)
	}
	// 带路径 IP 目标（host-like? 含点但路径段有非主机字符——canonicalTargetKey 已截断路径）
	noAsset2, noScope2 := missingS1TargetRefs([]string{"https://10.10.254.116/index.html"}, assets)
	if len(noAsset2)+len(noScope2) != 0 {
		t.Fatalf("带路径 IP 目标应命中: %v %v", noAsset2, noScope2)
	}
	// 主机形态精确匹配不受影响
	noAsset3, _ := missingS1TargetRefs([]string{"ndu.edu.tw"}, assets)
	if len(noAsset3) != 0 {
		t.Fatalf("精确键命中回归: %v", noAsset3)
	}
	// 子串误命中防线保持：a.ndu.edu.tw 不得命中 ndu.edu.tw（host-like 无回退）
	noAsset4, _ := missingS1TargetRefs([]string{"a.ndu.edu.tw"}, assets)
	if len(noAsset4) != 1 {
		t.Fatalf("host 形态不得词边界放宽: %v", noAsset4)
	}
}

// v6.6.0 回放驱动：IP 目标端口兼容层回归。
func TestV66IPTargetPortCompat(t *testing.T) {
	assets := []*store.Asset{
		{Value: "https://10.10.254.116:443/console/", ScopeStatus: "in_scope", ScopeEvidence: "授权清单"},
	}
	noAsset, noScope := missingS1TargetRefs([]string{"https://10.10.254.116/index.html"}, assets)
	if len(noAsset)+len(noScope) != 0 {
		t.Fatalf("IP 目标应经端口兼容层命中: %v %v", noAsset, noScope)
	}
	// 域名不受影响：a.test:8443 与 a.test 不合并（域名端口语义=新目标）
	assets2 := []*store.Asset{{Value: "a.test:8443", ScopeStatus: "in_scope", ScopeEvidence: "授权清单"}}
	noAsset2, _ := missingS1TargetRefs([]string{"a.test"}, assets2)
	if len(noAsset2) != 1 {
		t.Fatalf("域名端口语义不应合并: %v", noAsset2)
	}
}
