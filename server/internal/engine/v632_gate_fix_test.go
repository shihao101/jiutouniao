package engine

// v6.3.2 实战修正回归（某历史任务 S2 审计发现）：
// ①批量清单门工具域限定——wc -l/grep -l 等通用旗标不再误当目标清单参数；
// ②裸域名 TLD 纯数字过滤——searchsploit 版本号 3.7/3.7.1 不再当域名拦；
// ③被动 DNS/WHOIS 查询段豁免——shadow 资产的 dig 归属核实放行，axfr 仍拦；
// ④S2 步骤计划完整性门——缺 S2-x 子任务登记拦截收口。

import (
	"fmt"
	"strings"
	"testing"

	"jiutouniao/internal/store"
)

// ① `wc -l evidence/x.html` 不再触发批量清单范围门（实战误拦：CSS 值被当目标）。
func TestV632BatchTargetListRequiresScannerTool(t *testing.T) {
	o, _ := v48Orchestrator(t)
	p := &store.Project{ID: "P-V632-B1", Name: "工具域", Target: "a.test",
		Authorized: true, StrictScope: false, ROEAcknowledgedAt: "2026-11-23T00:00:00Z",
		StageStates: map[string]*store.StageState{"s2": {Status: "running"}}}
	_ = o.store.SaveProject(p)
	_, _ = o.exec.WriteFile(p.ID, "s2-login-body.html", "<style>min-width: 27.25rem; padding: 2.14286em;</style>")
	// wc -l / grep -l / ls -l：通用旗标不提取目标清单
	for _, cmd := range []string{
		`echo "=== script/link 引用 ==="; grep -oE '<(script|link)[^>]*' evidence/s2-login-body.html; wc -l evidence/s2-login-body.html`,
		`grep -l "register-modal" evidence/*.html | head -3`,
		`ls -l evidence/ | head`,
	} {
		if msg := o.targetListScopeIssues(p, "s2", "run_command", cmd); msg != "" {
			t.Fatalf("通用旗标命令不应误拦: %s\n=> %s", cmd, msg)
		}
	}
	// 批量扫描器的 -l 仍生效：工作区清单含 shadow 目标照拦
	_, _ = o.store.AddAsset(&store.Asset{ProjectID: p.ID, Stage: "s1", Type: "域名",
		Value: "shadow.test", ScopeStatus: "shadow_pending", Source: "CT 线索"})
	_, _ = o.exec.WriteFile(p.ID, "targets.txt", "a.test\nshadow.test\n")
	if msg := o.targetListScopeIssues(p, "s2", "run_command", "httpx -l targets.txt -title -rate-limit 20"); !strings.Contains(msg, "批量清单范围门") {
		t.Fatalf("httpx -l 仍应校验清单内容: %s", msg)
	}
	if msg := o.targetListScopeIssues(p, "s2", "run_command", "nmap -sV -Pn -iL targets.txt --top-ports 1000"); !strings.Contains(msg, "批量清单范围门") {
		t.Fatalf("nmap -iL 仍应校验清单内容: %s", msg)
	}
}

// ② TLD 纯数字候选不再当域名拦（searchsploit 版本号实战误拦修正）。
func TestV632NumericTLDBareDomainFiltered(t *testing.T) {
	if isPlausibleDomainHost("3.7") || isPlausibleDomainHost("3.7.1") {
		t.Fatalf("纯数字 TLD 应被过滤: 3.7=%v 3.7.1=%v", isPlausibleDomainHost("3.7"), isPlausibleDomainHost("3.7.1"))
	}
	for _, keep := range []string{"henetc.edu.cn", "zsgl.henetc.edu.cn", "a.test", "mail-x.163.com"} {
		if !isPlausibleDomainHost(keep) {
			t.Fatalf("真实域名不应被过滤: %s", keep)
		}
	}
	// 端到端：strict_scope 下 searchsploit 版本号命令不再被范围门拦
	o, _ := v48Orchestrator(t)
	p := &store.Project{ID: "P-V632-B2", Name: "TLD过滤", Target: "a.test",
		Authorized: true, StrictScope: true, ROEAcknowledgedAt: "2026-11-23T00:00:00Z",
		StageStates: map[string]*store.StageState{"s2": {Status: "running"}}}
	_ = o.store.SaveProject(p)
	if blocked, msg := o.scopeGate(p, `searchsploit -j "jquery 3.7.1" | jq '.RESULTS[].Title'`); blocked {
		t.Fatalf("版本号参数不应触发范围门: %s", msg)
	}
	if blocked, msg := o.scopeGate(p, `searchsploit --id "jQuery 3.7"`); blocked {
		t.Fatalf("searchsploit --id 版本号不应被拦: %s", msg)
	}
	// 真实范围外域名仍拦（不新增漏拦面）
	if blocked, _ := o.scopeGate(p, "curl -s https://stranger.test/"); !blocked {
		t.Fatalf("范围外真实域名仍应拦截")
	}
}

// ③ 被动 DNS/WHOIS 查询段豁免：shadow 资产 dig 归属核实放行；axfr 保留拦截。
func TestV632DNSQuerySegmentExempted(t *testing.T) {
	o, _ := v48Orchestrator(t)
	p := &store.Project{ID: "P-V632-B3", Name: "DNS豁免", Target: "zsgl.henetc.edu.cn",
		Authorized: true, StrictScope: false, ROEAcknowledgedAt: "2026-11-23T00:00:00Z",
		StageStates: map[string]*store.StageState{"s2": {Status: "running"}}}
	_ = o.store.SaveProject(p)
	_, _ = o.store.AddAsset(&store.Asset{ProjectID: p.ID, Stage: "s1", Type: "域名",
		Value: "henetc.edu.cn", ScopeStatus: "shadow_pending", Source: "S1 归属参考（父域）"})
	// dig 归属核实（实战 S1 被拦 8 条的同形态）→ 放行
	if blocked := o.assetTestBlockedAssets(p, "dig +noall +answer henetc.edu.cn A AAAA CNAME MX NS TXT SOA CAA"); len(blocked) != 0 {
		t.Fatalf("shadow 资产的被动 dig 查询不应拦: %v", blocked)
	}
	if blocked := o.assetTestBlockedAssets(p, "whois -h whois.cymru.com \" -v 125.219.148.5\""); len(blocked) != 0 {
		t.Fatalf("whois ASN 查询不应拦: %v", blocked)
	}
	// HTTP 主动访问 shadow 资产 → 照拦（豁免仅限 DNS/WHOIS 协议段）
	if blocked := o.assetTestBlockedAssets(p, "curl -s https://henetc.edu.cn/"); len(blocked) == 0 {
		t.Fatalf("shadow 资产 HTTP 请求仍应拦")
	}
	// dig axfr（区域传送=主动查询）不豁免
	if blocked := o.assetTestBlockedAssets(p, "dig axfr henetc.edu.cn"); len(blocked) == 0 {
		t.Fatalf("dig axfr 不应豁免")
	}
	// scopeGate 同口径：strict_scope 下 dig shadow 域放行
	o2, _ := v48Orchestrator(t)
	p2 := &store.Project{ID: "P-V632-B4", Name: "DNS豁免strict", Target: "zsgl.henetc.edu.cn",
		Authorized: true, StrictScope: true, ROEAcknowledgedAt: "2026-11-23T00:00:00Z",
		StageStates: map[string]*store.StageState{"s2": {Status: "running"}}}
	_ = o2.store.SaveProject(p2)
	if blocked, msg := o2.scopeGate(p2, "dig +noall +answer henetc.edu.cn NS"); blocked {
		t.Fatalf("strict_scope 下被动 dig 归属查询不应拦: %s", msg)
	}
}

// ④ S2 步骤计划完整性门：缺 S2-x 子任务登记拦截收口；全步骤登记放行。
func TestV632S2StepPlanCompleteness(t *testing.T) {
	o, _ := v48Orchestrator(t)
	for f, body := range s2GateFixture {
		_, _ = o.exec.WriteFile("P-V632-S1", f, body)
	}
	// 只登记 8 条（实战 某历史任务 漏排 S2-2/S2-4/S2-6 同形态）
	p := &store.Project{ID: "P-V632-S1", Name: "缺步骤", Target: "a.test",
		Authorized: true, StrictScope: false, ROEAcknowledgedAt: "2026-11-23T00:00:00Z",
		StageStates: map[string]*store.StageState{"s2": {Status: "running"}}}
	_ = o.store.SaveProject(p)
	for _, i := range []int{1, 3, 5, 7, 8, 9, 10, 11} {
		_, _ = o.store.AddSubtask(&store.Subtask{ProjectID: p.ID, Stage: "s2",
			Title: strings.TrimSpace(titleForStep(i)), Status: "finished"})
	}
	issues := o.s2ClosureIssues(p)
	if !s2GateIssuesContains(t, issues, "子任务计划缺步骤") || !s2GateIssuesContains(t, issues, "S2-2、S2-4、S2-6") {
		t.Fatalf("缺步骤应拦截并点名单: %v", issues)
	}
	// 补齐 11 条 → 步骤项消失
	registerS2StepSubtasks(t, o, p.ID)
	for _, iss := range o.s2ClosureIssues(p) {
		if strings.Contains(iss, "子任务计划缺步骤") {
			t.Fatalf("补齐后不应再拦步骤项: %v", iss)
		}
	}
}

// titleForStep 与 registerS2StepSubtasks 的标题形态一致。
func titleForStep(i int) string {
	return fmt.Sprintf("S2-%d 步骤%d", i, i)
}
