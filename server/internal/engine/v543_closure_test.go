// v5.4.3 引擎修复回归测试（全部使用泛化样本，不复用任何项目特定内容）：
// A 收口执行闭环（async 作业收割 + V3 台账校正）/
// B 覆盖台账自描述契约（notes 必填 + deterministicGate 兜底）/
// C 治理门精确性与可解释性（词边界 + 只读豁免 + 拦截消息含命中细节）。
package engine

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"jiutouniao/internal/config"
	"jiutouniao/internal/events"
	"jiutouniao/internal/store"
)

func v543Orchestrator(t *testing.T) (*Orchestrator, *store.Store, string) {
	t.Helper()
	_, st := testApprover(t)
	dir := t.TempDir()
	o := &Orchestrator{store: st, exec: newTestExec(t, dir), bus: events.NewBus(),
		cfg: func() *config.Config { c := &config.Config{}; c.ApplyDefaultsForTest(); c.DataDir = dir; return c }()}
	return o, st, dir
}

// ---------- A：收口执行闭环 ----------

// 通用样本：任意内容的后台作业（此处以泛化目录清单为例），finished 且未被 poll 消费。
func writeV543AsyncSidecar(t *testing.T, dir, pid, jobID, command, state string) {
	t.Helper()
	ad := filepath.Join(dir, pid, ".async")
	if err := os.MkdirAll(ad, 0o750); err != nil {
		t.Fatal(err)
	}
	sc := `{"id":"` + jobID + `","command":"` + command + `","log":".async/job-` + jobID + `.log","state":"` + state + `"}`
	if err := os.WriteFile(filepath.Join(ad, "job-"+jobID+".json"), []byte(sc), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(ad, "job-"+jobID+".log"), []byte("=== 泛化作业输出 ===\nresult: 3 items\n"), 0o640); err != nil {
		t.Fatal(err)
	}
}

func TestV543HarvestAsyncOutputs(t *testing.T) {
	o, _, dir := v543Orchestrator(t)
	p := &store.Project{ID: "P-V543A"}
	_ = o.store.SaveProject(p)
	writeV543AsyncSidecar(t, dir, p.ID, "job111abc", "bash scripts/gen-inventory.sh", "finished")
	writeV543AsyncSidecar(t, dir, p.ID, "job222def", "bash scripts/long-run.sh", "running") // 在途不收割

	got := o.harvestAsyncOutputs(p, "s4")
	if len(got) != 1 || got[0].ID != "job111abc" {
		t.Fatalf("应仅收割 finished 作业: %v", got)
	}
	evs, _ := o.store.ListEvidence(p.ID)
	found := false
	for _, e := range evs {
		if strings.Contains(e.Input+e.Output, "job111abc") {
			found = true
		}
	}
	if !found {
		t.Fatal("收割结论未落证据链")
	}
	// 幂等：二次收割应判定已消费（0 项）
	if again := o.harvestAsyncOutputs(p, "s4"); len(again) != 0 {
		t.Fatalf("二次收割应为 0（消费判定）: %v", again)
	}
}

func TestV543HarvestV3ListsSkipsExecutedVT(t *testing.T) {
	o, st, dir := v543Orchestrator(t)
	p := &store.Project{ID: "P-V543B"}
	_ = st.SaveProject(p)
	_, _ = st.AddVT(&store.VerificationTask{ID: "VT-A", ProjectID: p.ID, Stage: "s4",
		Title: "泛化枚举确认", ReadyAssets: "scripts/gen-inventory.sh", Status: "ready"})
	_, _ = st.AddVT(&store.VerificationTask{ID: "VT-B", ProjectID: p.ID, Stage: "s4",
		Title: "泛化探针投递", ReadyAssets: "scripts/other-probe.sh", Status: "ready"})
	// 后台作业实际执行了 VT-A 引用的脚本
	writeV543AsyncSidecar(t, dir, p.ID, "job333abc", "bash scripts/gen-inventory.sh && sleep 1", "finished")

	ready, l2 := o.harvestV3Lists(p, "s4", o.harvestAsyncOutputs(p, "s4"))
	if l2 != nil {
		t.Fatalf("l2 不代填: %v", l2)
	}
	// AddVT 由 store 生成 ID——按就绪资产路径定位（同 v49 测试约定）
	for _, r := range ready {
		if strings.Contains(r, "scripts/gen-inventory.sh") {
			t.Fatalf("已由后台作业执行的 VT-A 不应再入「就绪未投递」清单: %v", ready)
		}
	}
	hasB := false
	for _, r := range ready {
		if strings.Contains(r, "scripts/other-probe.sh") {
			hasB = true
		}
	}
	if !hasB {
		t.Fatalf("未执行的 VT-B 应保留在清单: %v", ready)
	}
	// jobs=nil（无收割）时 VT-A 应照常入清单（向后兼容）
	ready0, _ := o.harvestV3Lists(p, "s4", nil)
	found := false
	for _, r := range ready0 {
		if strings.Contains(r, "scripts/gen-inventory.sh") {
			found = true
		}
	}
	if !found {
		t.Fatal("无收割作业时应保持原行为（VT-A 入清单）")
	}
}

// ---------- B：覆盖台账自描述契约 ----------

func TestV543UpdateCoverageNoteRequired(t *testing.T) {
	o, st, _ := v543Orchestrator(t)
	p := &store.Project{ID: "P-V543C"}
	_ = st.SaveProject(p)
	// 结论态 + 空 notes → 拒绝
	got := call(t, o, p, "s4", "update_coverage",
		`{"endpoint":"GET /x/","vuln_class":"泛化类A","status":"vulnerable"}`)
	if !strings.Contains(got, "notes") {
		t.Fatalf("空 notes 的结论态应被拒: %s", got)
	}
	// 附依据 → 通过
	got2 := call(t, o, p, "s4", "update_coverage",
		`{"endpoint":"GET /x/","vuln_class":"泛化类A","status":"vulnerable","notes":"探针实测命中（证据 evidence/probe.txt）"}`)
	if strings.Contains(got2, "错误") {
		t.Fatalf("带依据的更新不应被拒: %s", got2)
	}
	// waf_blocked 过渡态空 notes → 豁免
	got3 := call(t, o, p, "s4", "update_coverage",
		`{"endpoint":"GET /y/","vuln_class":"泛化类B","status":"waf_blocked"}`)
	if strings.Contains(got3, "必须附 notes") {
		t.Fatalf("过渡态应豁免: %s", got3)
	}
}

func TestV543DeterministicGateCoverageNote(t *testing.T) {
	o, st, _ := v543Orchestrator(t)
	p := &store.Project{ID: "P-V543D"}
	_ = st.SaveProject(p)
	_, _ = st.UpsertCoverage(&store.CoverageEntry{ProjectID: p.ID, Stage: "s4",
		Endpoint: "GET /a/", VulnClass: "泛化类A", Status: "vulnerable", Notes: ""})
	_, _ = st.UpsertCoverage(&store.CoverageEntry{ProjectID: p.ID, Stage: "s4",
		Endpoint: "GET /b/", VulnClass: "泛化类B", Status: "needs_follow_up", Notes: "劣化未定性（证据 evidence/a.txt）"})
	issues := o.deterministicGate(p, "s4")
	hit := false
	for _, i := range issues {
		if strings.Contains(i, "notes 为空") {
			hit = true
		}
	}
	if !hit {
		t.Fatalf("空 notes 结论态条目应被确定性门捕获: %v", issues)
	}
	// 补齐 notes 后不再捕获
	cov, _ := st.ListCoverage(p.ID)
	for _, c := range cov {
		if c.Notes == "" {
			c.Notes = "补齐依据"
			_, _ = st.UpsertCoverage(c)
		}
	}
	for _, i := range o.deterministicGate(p, "s4") {
		if strings.Contains(i, "notes 为空") {
			t.Fatalf("补齐后不应再捕获: %v", issues)
		}
	}
	// 其他阶段（s5）名下为空 → s4 收口不受连坐
	_, _ = st.UpsertCoverage(&store.CoverageEntry{ProjectID: p.ID, Stage: "s5",
		Endpoint: "GET /c/", VulnClass: "泛化类C", Status: "ruled_out", Notes: ""})
	for _, i := range o.deterministicGate(p, "s4") {
		if strings.Contains(i, "notes 为空") {
			t.Fatal("跨阶段历史条目不应连坐本阶段收口")
		}
	}
}

// ---------- C：治理门精确性与可解释性 ----------

func TestV543ProfileWordBoundaryAndReadOnlyExemption(t *testing.T) {
	// ① 子串误伤修复（词边界）："payloads" 不再命中 \bpay\b——纯只读清单命令直连放行
	if hits := profileViolations("production_safe", `ls -d payloads/ && head -3 x.txt`, false); len(hits) != 0 {
		t.Fatalf("词边界后 payloads 不应命中: %v", hits)
	}
	// ② 只读豁免：引号内独立词命中 + 泛用 flag 合取，但命令纯只读 → 豁免
	cmd := `grep -d skip "pay" evidence/x.txt`
	if hits := profileViolations("production_safe", cmd, true); len(hits) != 0 {
		t.Fatalf("只读命令应豁免状态变更合取规则: %v", hits)
	}
	// ③ 非只读同命令 → 不豁免（豁免只对只读生效）
	if hits := profileViolations("production_safe", cmd, false); len(hits) == 0 {
		t.Fatal("非只读命令不应豁免")
	}
	// ④ 真实状态变更仍拦截（拦截能力零放松）
	hits := profileViolations("production_safe", `curl -X POST http://t/api/order -d '{"status":"paid"}'`, false)
	if len(hits) == 0 || hits[0].Rule != "真实订单/支付/短信状态变更" {
		t.Fatalf("真实状态变更应仍被拦: %v", hits)
	}
}

func TestV543ProfileGateMessageExplainable(t *testing.T) {
	o, _, _ := v543Orchestrator(t)
	p := &store.Project{ID: "P-V543E", ExecutionProfile: "production_safe"}
	blocked, msg := o.profileGate(p, `curl -X POST http://t/api/order -d '{"status":"paid"}'`)
	if !blocked {
		t.Fatal("真实状态变更应被 profileGate 拦截")
	}
	if !strings.Contains(msg, "真实订单/支付/短信状态变更") || !strings.Contains(msg, "命中文本") {
		t.Fatalf("拦截消息应含规则名与命中文本（可解释性）: %s", msg)
	}
	// 泛化预检命令（实战误报样本形态）→ 放行
	precheck := `mkdir -p .async evidence/oob && pwd && ( echo "=== 工具预检 ==="; for t in nmap gobuster ffuf nuclei httpx whatweb dig whois curl sqlmap jq python3 arjun interactsh-client; do command -v $t >/dev/null 2>&1 || echo "缺 $t"; done )`
	if blocked, _ := o.profileGate(p, precheck); blocked {
		t.Fatal("泛化只读预检命令不应被拦")
	}
}
