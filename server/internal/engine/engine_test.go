package engine

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"jiutouniao/internal/config"
	"jiutouniao/internal/events"
	"jiutouniao/internal/llm"
	"jiutouniao/internal/store"
	"jiutouniao/internal/tools"
)

func testApprover(t *testing.T) (*Approver, *store.Store) {
	t.Helper()
	dir := t.TempDir()
	st, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	return NewApprover(st, events.NewBus(), "manual"), st
}

func TestApproveFlow(t *testing.T) {
	ap, st := testApprover(t)
	ctx := context.Background()

	// 另一个 goroutine 里等待审批，1 秒后批准
	go func() {
		time.Sleep(time.Second)
		aps, _ := st.ListApprovals("P1")
		if len(aps) != 1 {
			t.Errorf("期望 1 条待批工单，实际 %d", len(aps))
			return
		}
		_ = ap.Decide(aps[0].ID, true, "tester")
	}()
	decision, err := ap.Request(ctx, "P1", "s5", "执行命令: sqlmap --dump", "L2")
	if err != nil || decision != "approved" {
		t.Fatalf("期望 approved，实际 %s, err=%v", decision, err)
	}
	// 人工批准留痕：mode=manual、decided_by、decided_at
	aps, _ := st.ListApprovals("P1")
	if aps[0].Mode != "manual" || aps[0].DecidedBy != "tester" || aps[0].DecidedAt == nil {
		t.Fatalf("人工批准未留痕: %+v", aps[0])
	}
}

func TestAutoApprovePolicy(t *testing.T) {
	ap, st := testApprover(t)
	ctx := context.Background()
	// 项目 P4 策略 l1：L1 自动批准（mode=auto 留痕），L2 仍人工
	if err := st.SaveProject(&store.Project{ROEAcknowledgedAt: "2026-11-22T00:00:00Z", ID: "P4", Name: "t", AutoApprove: "l1"}); err != nil {
		t.Fatal(err)
	}
	decision, err := ap.Request(ctx, "P4", "s2", "nmap 扫描", "L1")
	if err != nil || decision != "auto-approved" {
		t.Fatalf("l1 策略下 L1 应自动批准，实际 %s, err=%v", decision, err)
	}
	aps, _ := st.ListApprovals("P4")
	if len(aps) != 1 || aps[0].Mode != "auto" || aps[0].Status != "approved" || aps[0].DecidedBy != "auto-policy" {
		t.Fatalf("自动批准未留痕: %+v", aps)
	}
	// L2 仍走人工：不决策时应阻塞直到熔断
	done := make(chan error, 1)
	go func() {
		_, err := ap.Request(ctx, "P4", "s5", "高危动作", "L2")
		done <- err
	}()
	time.Sleep(300 * time.Millisecond)
	ap.CancelProject("P4")
	if err := <-done; err == nil {
		t.Fatal("l1 策略下 L2 不应自动批准")
	}
}

func TestRejectFlow(t *testing.T) {
	ap, _ := testApprover(t)
	ctx := context.Background()
	go func() {
		time.Sleep(time.Second)
		// 未拿 ID 就直接构造拒绝：通过列表再决定
	}()
	// 手动路径：先异步拒绝
	go func() {
		time.Sleep(time.Second)
		aps, _ := ap.store.ListApprovals("P2")
		if len(aps) > 0 {
			_ = ap.Decide(aps[0].ID, false, "tester")
		}
	}()
	decision, err := ap.Request(ctx, "P2", "s5", "写操作", "L1")
	if err != nil || decision != "rejected" {
		t.Fatalf("期望 rejected，实际 %s, err=%v", decision, err)
	}
}

func TestKillCancelsPending(t *testing.T) {
	ap, st := testApprover(t)
	ctx := context.Background()
	done := make(chan error, 1)
	go func() {
		_, err := ap.Request(ctx, "P3", "s5", "高危动作", "L2")
		done <- err
	}()
	time.Sleep(300 * time.Millisecond)
	ap.CancelProject("P3")
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("期望熔断返回错误")
		}
		aps, _ := st.ListApprovals("P3")
		if len(aps) != 1 || aps[0].Status != "cancelled" {
			t.Fatalf("期望工单被标记 cancelled，实际 %+v", aps)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("熔断未生效")
	}
}

func TestLoadHeads(t *testing.T) {
	heads, err := LoadHeads("../../../heads")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"main", "s1", "s2", "s3", "s4", "s5", "s6", "s7", "s8", "specA", "specB1", "specB2"}
	for _, id := range want {
		h, ok := heads[id]
		if !ok {
			t.Fatalf("缺少头: %s", id)
		}
		if h.Name == "" || h.Body == "" {
			t.Fatalf("头 %s 元数据不完整", id)
		}
	}
	pipeline := Pipeline(heads, []string{"A", "B2"})
	if len(pipeline) != 10 { // 8 主流程(s1-s8) + 2 专项
		t.Fatalf("流水线长度错误: %v", pipeline)
	}
	for _, id := range []string{"s0", "s9"} {
		for _, sid := range pipeline {
			if sid == id {
				t.Fatalf("流水线不应包含 %s", id)
			}
		}
	}
}

// v2.7.5：对话「继续」准入状态——failed（LLM 500/预算耗尽等异常中断）必须可续跑，running/done 不可。
func TestStartableStatus(t *testing.T) {
	yes := []string{"created", "paused", "killed", "failed"}
	no := []string{"running", "done", "", "unknown"}
	for _, s := range yes {
		if !startableStatus(s) {
			t.Errorf("%q 应可续跑", s)
		}
	}
	for _, s := range no {
		if startableStatus(s) {
			t.Errorf("%q 不应可续跑", s)
		}
	}
}

// v3.2.0 签名归一化：换编号的枚举式空转应并入同一签名（供窗口循环检测统计）。
func TestMonitorSignature(t *testing.T) {
	a := monitorSignature(llm.ToolCall{Name: "run_command", Arguments: `{"command":"curl -s http://target/page?i=1","reason":"probe"}`})
	b := monitorSignature(llm.ToolCall{Name: "run_command", Arguments: `{"command":"curl -s http://target/page?i=2","reason":"probe"}`})
	if a != b {
		t.Fatalf("换编号枚举应归一化为同一签名:\n%s\n%s", a, b)
	}
	c := monitorSignature(llm.ToolCall{Name: "run_command", Arguments: `{"command":"nmap -sV -p 443 target","reason":"scan"}`})
	if a == c {
		t.Fatalf("不同命令不应归并为同一签名")
	}
	long := monitorSignature(llm.ToolCall{Name: "run_command", Arguments: `{"command":"curl -s http://target/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/x","reason":"r"}`})
	if strings.Contains(long, "aaaaaaaa") {
		t.Fatalf("长 token 应被泛化: %s", long)
	}
}

// v3.3.0 窗口压缩：超预算时旧工具回执存根化，保护段与最近消息不动，事实可经证据链找回。
func TestCompactMsgs(t *testing.T) {
	big := strings.Repeat("A", 20000) // ~5000 tokens/条
	var msgs []llm.Message
	msgs = append(msgs, llm.Message{Role: "system", Content: "sys"})
	msgs = append(msgs, llm.Message{Role: "user", Content: "ctx-pack"})
	for i := 0; i < 20; i++ {
		msgs = append(msgs, llm.Message{Role: "assistant", Content: "call"})
		msgs = append(msgs, llm.Message{Role: "tool", Content: big})
		msgs = append(msgs, llm.Message{Role: "user", Content: "go on"})
	}
	out, n := compactMsgs(msgs, 30000, 6)
	if n == 0 {
		t.Fatal("超预算应触发压缩")
	}
	if estimateTokens(out) > estimateTokens(msgs) {
		t.Fatal("压缩后应变小")
	}
	// 保护段：system 与上下文包原样
	if out[0].Content != "sys" || out[1].Content != "ctx-pack" {
		t.Fatal("保护段被压缩")
	}
	// 最近 6 条不动
	for i := len(out) - 6; i < len(out); i++ {
		if out[i].Content != msgs[i].Content {
			t.Fatalf("最近消息被误压: idx=%d", i)
		}
	}
	// 存根化验证：被压的 tool 消息不再是全文
	if out[3].Content == msgs[3].Content {
		t.Fatal("旧工具回执未被存根化")
	}
	// 不超预算时不压
	_, n2 := compactMsgs(msgs, 10_000_000, 10)
	if n2 != 0 {
		t.Fatal("预算充足不应压缩")
	}
}

// v3.4.0 攻击路径缝合器：facts(links)/loot → DOT 图与边清单（确定性纯函数）。
func TestBuildAttackGraph(t *testing.T) {
	ap, st := testApprover(t)
	dir := t.TempDir()
	_ = ap
	o := &Orchestrator{store: st, exec: newTestExec(t, dir)}
	_, _ = st.UpsertFact(&store.FactRecord{ProjectID: "P1", Key: "http://t/api", Value: "primitive:AUTHZ 未鉴权遍历", Confidence: "confirmed", Links: []string{"db@t"}})
	_, _ = st.UpsertFact(&store.FactRecord{ProjectID: "P1", Key: "db@t", Value: "primitive:CRED 数据库凭据面", Confidence: "confirmed"})
	_, _ = st.AddLoot(&store.LootRecord{ProjectID: "P1", Type: "credential", Target: "db@t", Masked: "adm***23", Source: "db@t", Verified: "verified"})
	dot, md := o.buildAttackGraph(&store.Project{ROEAcknowledgedAt: "2026-11-22T00:00:00Z", ID: "P1"})
	if dot == "" {
		t.Fatal("应产出 DOT")
	}
	for _, want := range []string{`"http://t/api"`, `"db@t"`, `digraph attack`, `->`} {
		if !strings.Contains(dot, want) {
			t.Fatalf("DOT 缺少 %s:\n%s", want, dot)
		}
	}
	if !strings.Contains(md, "凭据复用") {
		t.Fatalf("边清单应含凭据复用边:\n%s", md)
	}
	// 空项目无图
	if d2, _ := o.buildAttackGraph(&store.Project{ROEAcknowledgedAt: "2026-11-22T00:00:00Z", ID: "P-none"}); d2 != "" {
		t.Fatal("无事实项目应返回空图")
	}
}

// v3.4.0 教训合规校验：拒绝目标标识，接受通用经验。
func TestLessonSanitizeCheck(t *testing.T) {
	if got := lessonSanitizeCheck("对 10.0.0.1 的测试表明 XX 有效"); got == "" {
		t.Fatal("含 IP 应被拒")
	}
	if got := lessonSanitizeCheck("参考 http://target.example.com 的绕过"); got == "" {
		t.Fatal("含 URL 应被拒")
	}
	if got := lessonSanitizeCheck("对加固站点先指纹分型再选编码变体，盲打编码变体浪费轮次"); got != "" {
		t.Fatalf("通用经验应通过: %s", got)
	}
}

// v3.4.0 错误自愈建议映射。
func TestErrorAdvice(t *testing.T) {
	if errorAdvice("命令超时（300s）") == "" {
		t.Fatal("超时应给建议")
	}
	if errorAdvice("exit 127") != "" {
		t.Fatal("127 已有 install_tool 引导，不叠加")
	}
	if errorAdvice("") != "" {
		t.Fatal("空错误无建议")
	}
}

// v3.4.0 确定性质量门：高危确证无证据引用应拦。
func TestDeterministicGate(t *testing.T) {
	_, st := testApprover(t)
	dir := t.TempDir()
	o := &Orchestrator{store: st, exec: newTestExec(t, dir), bus: events.NewBus()}
	_, _ = st.AddFinding(&store.Finding{ProjectID: "P1", Stage: "s4", Title: "未鉴权遍历", Detail: "可遍历全部用户", Severity: "高", Confidence: "确证"})
	issues := o.deterministicGate(&store.Project{ROEAcknowledgedAt: "2026-11-22T00:00:00Z", ID: "P1"}, "s4")
	if len(issues) == 0 {
		t.Fatal("高危确证无证据引用应被拦截")
	}
	// v4.4 判据抽查：有证据但未对照 evidence-standard 判据的高危确证 → 引擎降级为疑似
	_, _ = st.AddFinding(&store.Finding{ProjectID: "P1", Stage: "s4", Title: "有证据的发现", Detail: "见 evidence/s4-exp01-log.txt", Severity: "高", Confidence: "确证"})
	issues = o.deterministicGate(&store.Project{ROEAcknowledgedAt: "2026-11-22T00:00:00Z", ID: "P1"}, "s4")
	for _, iss := range issues {
		if strings.Contains(iss, "有证据的发现") && strings.Contains(iss, "未引用任何证据") {
			t.Fatalf("引用 evidence 的发现不应触发证据类拦截: %v", issues)
		}
	}
	fs, _ := st.ListFindings("P1")
	for _, f := range fs {
		if f.Title == "有证据的发现" && f.Confidence != "疑似" {
			t.Fatalf("v4.4 判据抽查：有证据但未引判据的高危确证应被降级为疑似，实际 %s", f.Confidence)
		}
	}
	// 完全合规（证据 + 判据标记）不再触发任何拦截
	_, _ = st.AddFinding(&store.Finding{ProjectID: "P1", Stage: "s4", Title: "合规确证发现", Detail: "见 evidence/s4-exp02.txt；判据：布尔差分 ≥2 组反向谓词 ×3 重放稳定", Severity: "高", Confidence: "确证"})
	issues = o.deterministicGate(&store.Project{ROEAcknowledgedAt: "2026-11-22T00:00:00Z", ID: "P1"}, "s4")
	for _, iss := range issues {
		if strings.Contains(iss, "合规确证发现") {
			t.Fatalf("证据+判据齐备的确证发现不应被拦: %v", issues)
		}
	}
}

// v3.8.5 G1 探测→发现晋升对账器：evidence/ 中含成功信号但无归档引用的孤儿结果应拦截；
// 已被发现/覆盖/交付物引用（文件名或 ≥8 字符主干）则放行；低时延噪声不拦。
func TestOrphanProbeReconciliation(t *testing.T) {
	_, st := testApprover(t)
	dir := t.TempDir()
	o := &Orchestrator{store: st, exec: newTestExec(t, dir)}
	mk := func(project, rel, content string) {
		t.Helper()
		full := filepath.Join(dir, project, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(full), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(content), 0o640); err != nil {
			t.Fatal(err)
		}
	}
	// 孤儿1：时延探针命中（TIME=3.2s）无任何归档
	mk("P9", "evidence/s4-t03-sqli-probe2.log", "===== wide P6 sleep(3) =====\nURL: http://t/x.php?id=1%bf%27\nCODE=200 SIZE=25037 TIME=3.2s\n")
	// 孤儿2：sqlmap 确证信号无归档
	mk("P9", "evidence/sqlmap-run.log", "current database: 'targetdb'\n[*] ending\n")
	// 噪声：低时延不触发
	mk("P9", "evidence/fast-baseline.log", "CODE=200 TIME=0.2s\n")
	issues := o.deterministicGate(&store.Project{ROEAcknowledgedAt: "2026-11-22T00:00:00Z", ID: "P9"}, "s4")
	hit := 0
	for _, iss := range issues {
		if strings.Contains(iss, "s4-t03-sqli-probe2.log") || strings.Contains(iss, "sqlmap-run.log") {
			hit++
		}
		if strings.Contains(iss, "fast-baseline") {
			t.Fatalf("低时延基线不应被拦: %v", issues)
		}
	}
	if hit != 2 {
		t.Fatalf("两个孤儿探测结果均应被拦截，实际命中 %d: %v", hit, issues)
	}
	// s5 同样生效
	issues = o.deterministicGate(&store.Project{ROEAcknowledgedAt: "2026-11-22T00:00:00Z", ID: "P9"}, "s5")
	if len(issues) == 0 {
		t.Fatal("s5 收口同样应执行孤儿对账")
	}
	// 归档路径1：覆盖登记 Notes 引用文件名 → 对应孤儿放行
	_, _ = st.UpsertCoverage(&store.CoverageEntry{ProjectID: "P9", Stage: "s4", Endpoint: "GET /x.php", Param: "id", VulnClass: "SQLI", Status: "vulnerable", Notes: "宽字节延时确证 见 evidence/s4-t03-sqli-probe2.log"})
	// 归档路径2：发现 Detail 引用文件名 → 对应孤儿放行
	_, _ = st.AddFinding(&store.Finding{ProjectID: "P9", Stage: "s4", Title: "SQL 注入", Detail: "sqlmap 自动化确证 见 evidence/sqlmap-run.log", Severity: "高", Confidence: "确证"})
	issues = o.deterministicGate(&store.Project{ROEAcknowledgedAt: "2026-11-22T00:00:00Z", ID: "P9"}, "s4")
	for _, iss := range issues {
		if strings.Contains(iss, "s4-t03-sqli-probe2.log") || strings.Contains(iss, "sqlmap-run.log") {
			t.Fatalf("已归档的探测结果不应再被拦: %v", issues)
		}
	}
	// 归档路径3：交付物留痕排除（引用长主干）→ 放行
	mk("P9", "evidence/http-slow-endpoint-1a2b.log", "CODE=200 TIME=2.6s\n")
	_, _ = st.AddFinding(&store.Finding{ProjectID: "P9", Stage: "s4", Title: "慢端点排除", Detail: "http-slow-endpoint-1a2b 为业务慢端点，对照基线同为秒级，排除注入", Severity: "信息", Confidence: "确证"})
	issues = o.deterministicGate(&store.Project{ROEAcknowledgedAt: "2026-11-22T00:00:00Z", ID: "P9"}, "s4")
	for _, iss := range issues {
		if strings.Contains(iss, "http-slow-endpoint-1a2b") {
			t.Fatalf("交付物/发现留痕排除后不应被拦: %v", issues)
		}
	}
}

// v3.8.6 G2 覆盖完整性收口门：checklist.json 条目必须「覆盖登记引用条目」或「显式 status 处置」；
// 延期/排除超半数追加广度不足项；无 checklist.json 时门不生效。
func TestChecklistCoverageGate(t *testing.T) {
	_, st := testApprover(t)
	dir := t.TempDir()
	o := &Orchestrator{store: st, exec: newTestExec(t, dir)}
	// 无 checklist.json → 门不生效（只看清单相关项）
	for _, iss := range checkGate(o, "PC", "s4") {
		if strings.Contains(iss, "自述清单") || strings.Contains(iss, "无覆盖登记") {
			t.Fatalf("无清单时清单门不应生效: %v", iss)
		}
	}
	mk := func(project, rel, content string) {
		t.Helper()
		full := filepath.Join(dir, project, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(full), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(content), 0o640); err != nil {
			t.Fatal(err)
		}
	}
	mk("PC", "checklist.json", `{"items":[
		{"id":"C1","item":"数字型注入","hint":"/payload/sql/number.php","class":"SQLI"},
		{"id":"C2","item":"反射性XSS","hint":"/payload/xss/reflex.php","class":"XSS"},
		{"id":"C3","item":"目录遍历","hint":"/payload/dir/dirlist.php","class":"穿越"}]}`)
	// 三个条目均无覆盖登记 → 3 条拦截
	issues := o.deterministicGate(&store.Project{ROEAcknowledgedAt: "2026-11-22T00:00:00Z", ID: "PC"}, "s4")
	if got := countContains(issues, "无覆盖登记"); got != 3 {
		t.Fatalf("3 条未覆盖条目应全部拦截，实际 %d: %v", got, issues)
	}
	// C1：覆盖登记 Notes 引用条目文本；C3：Hint 路径被 Endpoint 包含 → 均归账
	// v5.8.0 证据语义门：结论条目 Notes 需 evidence/POC/判据/请求响应 引用
	_, _ = st.UpsertCoverage(&store.CoverageEntry{ProjectID: "PC", Stage: "s4", Endpoint: "GET /payload/sql/number.php", Param: "id", VulnClass: "SQLI", Status: "vulnerable", Notes: "数字型注入延时确证，POC 见 evidence/s4/sqli.txt"})
	_, _ = st.UpsertCoverage(&store.CoverageEntry{ProjectID: "PC", Stage: "s4", Endpoint: "GET /payload/dir/dirlist.php", Param: "-", VulnClass: "穿越", Status: "no_issue_found", Notes: "基线请求响应正常（负对照留证 evidence/s4/dir.txt）"})
	issues = o.deterministicGate(&store.Project{ROEAcknowledgedAt: "2026-11-22T00:00:00Z", ID: "PC"}, "s4")
	if got := countContains(issues, "无覆盖登记"); got != 1 {
		t.Fatalf("C1/C3 归账后应仅剩 C2 未覆盖，实际 %d: %v", got, issues)
	}
	// C2 显式处置：deferred 缺 reason → 拦；补 reason 后放行
	mk("PC", "checklist.json", `{"items":[
		{"id":"C1","item":"数字型注入","hint":"/payload/sql/number.php","class":"SQLI"},
		{"id":"C2","item":"反射性XSS","hint":"/payload/xss/reflex.php","class":"XSS","status":"deferred"},
		{"id":"C3","item":"目录遍历","hint":"/payload/dir/dirlist.php","class":"穿越"}]}`)
	issues = o.deterministicGate(&store.Project{ROEAcknowledgedAt: "2026-11-22T00:00:00Z", ID: "PC"}, "s4")
	if got := countContains(issues, "缺 reason"); got != 1 {
		t.Fatalf("deferred 缺 reason 应拦截，实际 %d: %v", got, issues)
	}
	mk("PC", "checklist.json", `{"items":[
		{"id":"C1","item":"数字型注入","hint":"/payload/sql/number.php","class":"SQLI"},
		{"id":"C2","item":"反射性XSS","hint":"/payload/xss/reflex.php","class":"XSS","status":"deferred","reason":"预算耗尽移交S5"},
		{"id":"C3","item":"目录遍历","hint":"/payload/dir/dirlist.php","class":"穿越"}]}`)
	if issues := o.deterministicGate(&store.Project{ROEAcknowledgedAt: "2026-11-22T00:00:00Z", ID: "PC"}, "s4"); len(issues) != 0 {
		t.Fatalf("全部条目归宿后应放行: %v", issues)
	}
	// 延期/排除超半数 → 广度不足拦截
	mk("PC", "checklist.json", `{"items":[
		{"id":"C1","item":"数字型注入","hint":"/payload/sql/number.php","class":"SQLI"},
		{"id":"C2","item":"反射性XSS","hint":"/payload/xss/reflex.php","class":"XSS","status":"deferred","reason":"低优先"},
		{"id":"C3","item":"目录遍历","hint":"/payload/dir/dirlist.php","class":"穿越","status":"excluded","reason":"范围外"}]}`)
	issues = o.deterministicGate(&store.Project{ROEAcknowledgedAt: "2026-11-22T00:00:00Z", ID: "PC"}, "s4")
	if got := countContains(issues, "广度不足"); got != 1 {
		t.Fatalf("延期/排除超半数应触发广度不足项，实际 %d: %v", got, issues)
	}
}

// checkGate 调用确定性门（测试辅助，缩短行宽）。
func checkGate(o *Orchestrator, projectID, stage string) []string {
	return o.deterministicGate(&store.Project{ROEAcknowledgedAt: "2026-11-22T00:00:00Z", ID: projectID}, stage)
}

// countContains 统计 issues 中包含子串的条数（测试辅助）。
func countContains(issues []string, sub string) int {
	n := 0
	for _, iss := range issues {
		if strings.Contains(iss, sub) {
			n++
		}
	}
	return n
}

// v3.9.5 对账视图数据：条目归宿（covered/uncovered/deferred）+ 清单外发现计数。
func TestReconciliationPublic(t *testing.T) {
	_, st := testApprover(t)
	dir := t.TempDir()
	o := &Orchestrator{store: st, exec: newTestExec(t, dir)}
	// 无清单 → enabled=false
	out := o.ReconciliationPublic("PE")
	if out["enabled"] != false || out["beyond"] != 0 {
		t.Fatalf("无清单应 enabled=false: %v", out)
	}
	mk := func(project, rel, content string) {
		t.Helper()
		full := filepath.Join(dir, project, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(full), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(content), 0o640); err != nil {
			t.Fatal(err)
		}
	}
	mk("PE", "checklist.json", `{"items":[
		{"id":"C1","item":"数字型注入","hint":"/payload/sql/number.php","class":"SQLI"},
		{"id":"C2","item":"反射性XSS","hint":"/payload/xss/reflex.php","class":"XSS"},
		{"id":"C3","item":"目录遍历","hint":"/payload/dir/dirlist.php","class":"穿越","status":"deferred","reason":"低优先"}]}`)
	_, _ = st.UpsertCoverage(&store.CoverageEntry{ProjectID: "PE", Stage: "s4", Endpoint: "GET /payload/sql/number.php", Param: "id", VulnClass: "SQLI", Status: "vulnerable", Notes: "数字型注入 确证"})
	_, _ = st.AddFinding(&store.Finding{ProjectID: "PE", Stage: "s4", Title: "清单外发现示例", Detail: "【清单外】隐藏参数盲注", Severity: "高", Confidence: "确证"})
	_, _ = st.AddFinding(&store.Finding{ProjectID: "PE", Stage: "s4", Title: "普通发现", Detail: "无标注", Severity: "低", Confidence: "疑似"})
	out = o.ReconciliationPublic("PE")
	if out["enabled"] != true {
		t.Fatalf("有清单应 enabled=true: %v", out)
	}
	if out["covered"] != 1 || out["deferred"] != 1 || out["uncovered"] != 1 || out["total"] != 3 {
		t.Fatalf("归宿计数不符: %v", out)
	}
	if out["beyond"] != 1 || out["findingsTotal"] != 2 {
		t.Fatalf("清单外计数不符: %v", out)
	}
	items := out["items"].([]map[string]string)
	if items[0]["status"] != "covered" || items[1]["status"] != "uncovered" || items[2]["status"] != "deferred" {
		t.Fatalf("条目状态不符: %v", items)
	}
}

// v3.8.7 G3 待续清单回灌门：needs_follow_up 条目在 s7 收口时必须在交付物/报告文本中
// 引用端点关键词留痕处置；已处置（完整端点/末段路径/参数名任一命中）则放行。
func TestFollowUpDispositionGate(t *testing.T) {
	_, st := testApprover(t)
	dir := t.TempDir()
	o := &Orchestrator{store: st, exec: newTestExec(t, dir)}
	// 无 needs_follow_up → 门不生效
	if issues := checkGate(o, "PD", "s7"); len(issues) != 0 {
		t.Fatalf("无待续条目时门不应生效: %v", issues)
	}
	_, _ = st.UpsertCoverage(&store.CoverageEntry{ProjectID: "PD", Stage: "s4", Endpoint: "GET /payload/ssrf/ssrf2.php", Param: "url", VulnClass: "SSRF", Status: "needs_follow_up", Notes: "同构未逐一验证"})
	_, _ = st.UpsertCoverage(&store.CoverageEntry{ProjectID: "PD", Stage: "s4", Endpoint: "GET /members/edituser.php", Param: "userName", VulnClass: "越权", Status: "needs_follow_up", Notes: "预算耗尽"})
	// 未处置 → 两条拦截
	issues := checkGate(o, "PD", "s7")
	if got := countContains(issues, "待续清单未处置"); got != 2 {
		t.Fatalf("两条待续条目均应拦截，实际 %d: %v", got, issues)
	}
	// 交付物引用末段路径处置 ssrf2、报告引用参数名处置 edituser → 放行
	mk := func(project, rel, content string) {
		t.Helper()
		full := filepath.Join(dir, project, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(full), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(content), 0o640); err != nil {
			t.Fatal(err)
		}
	}
	mk("PD", "deliverables/s7-待续清单处置.md", "# 待续清单处置\n- ssrf2.php：本轮补测完成，update_coverage 已更新为 no_issue_found\n- userName 越权：范围外（ROE 未含账号修改），移交复测\n")
	issues = checkGate(o, "PD", "s7")
	if len(issues) != 0 {
		t.Fatalf("处置留痕后应放行: %v", issues)
	}
	// v3.9.5 留痕不带扩展名（剥 .php 等常见 Web 扩展名归账）
	_, _ = st.UpsertCoverage(&store.CoverageEntry{ProjectID: "PD", Stage: "s5", Endpoint: "GET /payload/dir/dirlist.php", Param: "path", VulnClass: "穿越", Status: "needs_follow_up", Notes: "预算耗尽"})
	mk("PD", "deliverables/s7-待续清单处置2.md", "# 待续清单处置\n- dirlist 已补测：遍历被 open_basedir 拦截，ruled_out\n")
	issues = checkGate(o, "PD", "s7")
	if got := countContains(issues, "dirlist"); got != 0 {
		t.Fatalf("无扩展名留痕应归账放行: %v", issues)
	}
	// v6.8.0 S7-① 污染反例断言：端点关键词仅出现在上游（s3-）交付物时，strict pool 不再被
	// 「天然满足」——无任何 s7 产出仍拦截（checkGate 项目无 S7 StartedAt，池=s7- 前缀+report.md）。
	_, _ = st.UpsertCoverage(&store.CoverageEntry{ProjectID: "PD", Stage: "s4", Endpoint: "GET /legacy/oldcase.php", Param: "id", VulnClass: "注入", Status: "needs_follow_up", Notes: "上游遗留"})
	mk("PD", "deliverables/s3-筛查矩阵判定表.md", "# 判定表\n- GET /legacy/oldcase.php 注入面待复核\n")
	issues = checkGate(o, "PD", "s7")
	if got := countContains(issues, "oldcase"); got != 1 {
		t.Fatalf("上游交付物不应满足处置对账（strict pool 应拦截 oldcase）: %v", issues)
	}
}

// 测试辅助：构造最小执行器（工作区指向 dir）。
func newTestExec(t *testing.T, dir string) *tools.Executor {
	t.Helper()
	f, h, m, r, se := config.DefaultGuard()
	e, err := tools.NewExecutor(dir, 10, 10240, struct {
		Forbidden, HighRisk, MedRisk, ReadOnly, Sensitive []string
	}{f, h, m, r, se})
	if err != nil {
		t.Fatal(err)
	}
	return e
}

// v3.4.2 回归：轮询类工具（poll_async/shell_read）豁免签名窗口——合法重复调用不触发预警/熔断。
func TestMonitorExemptPolling(t *testing.T) {
	_, st := testApprover(t)
	dir := t.TempDir()
	o := &Orchestrator{store: st, exec: newTestExec(t, dir), bus: events.NewBus()}
	mon := &execMonitor{}
	tc := llm.ToolCall{Name: "poll_async", Arguments: `{"job":"abc123def4"}`}
	for i := 0; i < 8; i++ {
		got := o.monitorCheck(context.Background(), &store.Project{ROEAcknowledgedAt: "2026-11-22T00:00:00Z", ID: "P1"}, "s4", mon, tc, "running")
		if strings.Contains(got, "⚠") || strings.Contains(got, "⛔") || strings.Contains(got, "导师") {
			t.Fatalf("合法轮询第 %d 次不应触发监控介入: %s", i+1, got[:60])
		}
	}
	// 非豁免工具仍受窗口检测：同一签名第 3 次应有预警
	tc2 := llm.ToolCall{Name: "run_command", Arguments: `{"command":"curl -s http://t/page?i=1"}`}
	o2 := &Orchestrator{store: st, exec: newTestExec(t, dir), bus: events.NewBus()}
	mon2 := &execMonitor{}
	hit := false
	for i := 0; i < 3; i++ {
		got := o2.monitorCheck(context.Background(), &store.Project{ROEAcknowledgedAt: "2026-11-22T00:00:00Z", ID: "P1"}, "s4", mon2, tc2, "ok")
		if strings.Contains(got, "⚠") {
			hit = true
		}
	}
	if !hit {
		t.Fatal("非豁免工具同签名第 3 次应触发预警")
	}
}

// v3.4.2 回归：已熔断项目的对话轮拿到即时取消的 ctx（Kill 后不再续转）。
func TestChatCtxKilledProject(t *testing.T) {
	_, st := testApprover(t)
	o := &Orchestrator{store: st, exec: newTestExec(t, t.TempDir())}
	p := &store.Project{ROEAcknowledgedAt: "2026-11-22T00:00:00Z", ID: "P-K", Status: "killed"}
	_ = st.SaveProject(p)
	ctx := o.chatCtx("P-K")
	select {
	case <-ctx.Done():
		// 预期：立即取消
	default:
		t.Fatal("已熔断项目的对话 ctx 应立即处于 Done 状态")
	}
	// 活跃项目正常注册
	_ = st.SaveProject(&store.Project{ROEAcknowledgedAt: "2026-11-22T00:00:00Z", ID: "P-A", Status: "running"})
	ctx2 := o.chatCtx("P-A")
	select {
	case <-ctx2.Done():
		t.Fatal("活跃项目的对话 ctx 不应取消")
	default:
	}
	o.chatTurnDone("P-A")
}

// v3.4.3 回归：豁免分支单一计数——第 2/3 次合法 poll 不再提前触发提醒（v3.4.2 双重自增缺陷）。
func TestMonitorExemptNoEarlyFire(t *testing.T) {
	o := &Orchestrator{store: st_for(t), exec: newTestExec(t, t.TempDir()), bus: events.NewBus()}
	mon := &execMonitor{}
	tc := llm.ToolCall{Name: "poll_async", Arguments: `{"job":"abc123def4"}`}
	for i := 0; i < 3; i++ {
		got := o.monitorCheck(context.Background(), &store.Project{ROEAcknowledgedAt: "2026-11-22T00:00:00Z", ID: "P1"}, "s4", mon, tc, "running")
		if strings.Contains(got, "⏳") {
			t.Fatalf("第 %d 次合法 poll 不应触发提醒（应第 4 次）", i+1)
		}
	}
	got := o.monitorCheck(context.Background(), &store.Project{ROEAcknowledgedAt: "2026-11-22T00:00:00Z", ID: "P1"}, "s4", mon, tc, "running")
	if !strings.Contains(got, "⏳") {
		t.Fatal("第 4 次连续纯 poll 应触发确定性提醒")
	}
}

// v3.4.3 回归：search_memory/list_files 豁免（压缩×重查交互）。
func TestMonitorExemptSearchAndList(t *testing.T) {
	o := &Orchestrator{store: st_for(t), exec: newTestExec(t, t.TempDir()), bus: events.NewBus()}
	for _, name := range []string{"search_memory", "list_files"} {
		mon := &execMonitor{}
		tc := llm.ToolCall{Name: name, Arguments: `{"query":"login"}`}
		for i := 0; i < 6; i++ {
			got := o.monitorCheck(context.Background(), &store.Project{ROEAcknowledgedAt: "2026-11-22T00:00:00Z", ID: "P1"}, "s4", mon, tc, "ok")
			if strings.Contains(got, "⚠") || strings.Contains(got, "⛔") {
				t.Fatalf("%s 第 %d 次不应触发窗口介入", name, i+1)
			}
		}
	}
}

// 测试辅助：独立 Store（避免与其他用例共享状态）。
func st_for(t *testing.T) *store.Store {
	t.Helper()
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return st
}

// v3.4.3 回归：技能 frontmatter id 引号剥离（00-router 曾以含引号 id 入库）。
func TestParseSkillQuotedID(t *testing.T) {
	s := parseSkill("---\nid: \"00-router\"\ntitle: 路由\n---\n# body")
	if s.ID != "00-router" {
		t.Fatalf("id 引号未剥离: %q", s.ID)
	}
}

// v3.6.0 子代理扇出：mock LLM 驱动的完整生命周期（派发→运行→收结果）+ 并发上限。
func TestSubagentLifecycle(t *testing.T) {
	dir := t.TempDir()
	st, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{}
	cfg.ApplyDefaultsForTest()
	ap, st := testApprover(t)
	_ = st
	o := &Orchestrator{store: st, exec: newTestExec(t, dir), bus: events.NewBus(), cfg: cfg, llm: llm.NewMock(), tokens: map[string]int64{}, approver: ap}
	p := &store.Project{ROEAcknowledgedAt: "2026-11-22T00:00:00Z", ID: "P-SUB", Status: "running", Target: "http://127.0.0.1:1", AutoApprove: "all"}
	_ = st.SaveProject(p)

	msg, err := o.spawnSubAgent(context.Background(), p, "s4", "测试 /news?id= 数字型 SQL 注入（布尔差判据）", 4)
	if err != nil {
		t.Fatalf("派发失败: %v", err)
	}
	if !strings.Contains(msg, "id=sub-") {
		t.Fatalf("返回应含子代理 id: %s", msg)
	}
	// 轮询至结束（mock 客户端瞬时响应，12s 足够）
	deadline := time.Now().Add(12 * time.Second)
	final := ""
	for time.Now().Before(deadline) {
		got := o.pollSubAgents(p)
		if strings.Contains(got, "finished") || strings.Contains(got, "failed") || strings.Contains(got, "killed") {
			final = got
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	if final == "" {
		t.Fatalf("子代理未在期限内结束: %s", o.pollSubAgents(p))
	}
	// 已消费的结果重复 poll 不再重复汇报
	if again := o.pollSubAgents(p); strings.Contains(again, "finished") {
		t.Fatalf("结果应标记已消费不重复汇报: %s", again)
	}
}

// v3.6.0 并发上限：达到 max_subagents 后拒绝派发。
func TestSubagentConcurrencyLimit(t *testing.T) {
	dir := t.TempDir()
	st, _ := store.Open(dir)
	cfg := &config.Config{}
	cfg.ApplyDefaultsForTest()
	cfg.Engine.MaxSubagents = 1
	o := &Orchestrator{store: st, exec: newTestExec(t, dir), bus: events.NewBus(), cfg: cfg}
	p := &store.Project{ROEAcknowledgedAt: "2026-11-22T00:00:00Z", ID: "P-L", Status: "running"}
	_ = st.SaveProject(p)
	// 直接注入一个 running 档案占满槽位
	o.subMu.Lock()
	o.subRuns = map[string]map[string]*SubAgentRun{"P-L": {"sub-fake": {ID: "sub-fake", Status: "running", Objective: "x"}}}
	o.subMu.Unlock()
	if _, err := o.spawnSubAgent(context.Background(), p, "s4", "任意目标", 0); err == nil || !strings.Contains(err.Error(), "上限") {
		t.Fatalf("超上限应拒绝: %v", err)
	}
	// 禁用开关
	cfg.Engine.MaxSubagents = 0
	if _, err := o.spawnSubAgent(context.Background(), p, "s4", "任意目标", 0); err == nil || !strings.Contains(err.Error(), "未启用") {
		t.Fatalf("禁用态应拒绝: %v", err)
	}
}

// v3.7.4 s8 报告-发现一致性质量门：R 条目多于 findings 记录 → 拦截（某真实任务 实测缺陷回归）。
func TestDeterministicGateS8ReportFindingsConsistency(t *testing.T) {
	_, st := testApprover(t)
	dir := t.TempDir()
	o := &Orchestrator{store: st, exec: newTestExec(t, dir), bus: events.NewBus(), cfg: func() *config.Config { c := &config.Config{}; c.ApplyDefaultsForTest(); return c }()}
	p := &store.Project{ROEAcknowledgedAt: "2026-11-22T00:00:00Z", ID: "P-S8"}
	_ = st.SaveProject(p)
	// 报告含 2 个 R 条目，findings 仅 1 条 → 应拦截
	// v6.0.1 C29：报告夹具含合规《覆盖边界》章节（边界门单独有专项测试 v601）
	// v6.9.0 S8-③：反向对账门要求每条 findings 在报告有归宿——「登录枚举」以《待验证》小节
	// 留痕（合法归宿形态），保证夹具只考察正向门的 R>findings 语义。
	_, _ = o.exec.WriteFile("P-S8", "report.md", "# 报告\n## 覆盖边界\n| 边界项 | 量化数据 | 解锁条件 | 来源 |\n|---|---|---|---|\n| 认证后 | 0/2 | 提供测试账号 | coverage.json |\n### R-01 明文传输\n内容\n### R-02 弱哈希\n内容\n\n## 待验证\n- 登录枚举（本轮仅弱口令线索，未实测）\n")
	_, _ = st.AddFinding(&store.Finding{ProjectID: "P-S8", Stage: "s4", Title: "登录枚举", Detail: "x", Severity: "低", Confidence: "确证"})
	issues := o.deterministicGate(p, "s8")
	if len(issues) == 0 {
		t.Fatal("R 条目(2) > findings(1) 应拦截")
	}
	// 补录至 2 条后放行
	_, _ = st.AddFinding(&store.Finding{ProjectID: "P-S8", Stage: "s5", Title: "明文传输", Detail: "HTTP 明文", Severity: "中", Confidence: "确证"})
	if issues = o.deterministicGate(p, "s8"); len(issues) != 0 {
		t.Fatalf("补录后应放行: %v", issues)
	}
}

// v3.8.1 s8 同根因双记拦截：归一化标题相同 → BLOCK（对称校验，实测双记连续两个任务进导出）。
func TestDeterministicGateS8DuplicateRoot(t *testing.T) {
	_, st := testApprover(t)
	dir := t.TempDir()
	o := &Orchestrator{store: st, exec: newTestExec(t, dir), bus: events.NewBus(), cfg: func() *config.Config { c := &config.Config{}; c.ApplyDefaultsForTest(); return c }()}
	p := &store.Project{ROEAcknowledgedAt: "2026-11-22T00:00:00Z", ID: "P-DUP"}
	_ = st.SaveProject(p)
	_, _ = st.AddFinding(&store.Finding{ProjectID: "P-DUP", Stage: "s4", Title: "登录接口无 CSRF 防护（无 token 校验）", Detail: "x", Severity: "低", Confidence: "确证"})
	// v4.6 B1：归一化标题全等的同根因在入口层即被 AddFinding 拒绝（不再留到 s8 门兜底）
	_, dupErr := st.AddFinding(&store.Finding{ProjectID: "P-DUP", Stage: "s5", Title: "登录接口无CSRF防护（无token校验）", Detail: "疑似版", Severity: "中", Confidence: "疑似"})
	if dupErr == nil || !strings.Contains(dupErr.Error(), "疑似重复发现") {
		t.Fatalf("v4.6 B1 入口判重应拒绝归一化标题全等的重复登记: %v", dupErr)
	}
	// 24 字符前缀近似（归一化后不等）的对发现仍由 s8 收口门拦截
	_, _ = st.AddFinding(&store.Finding{ProjectID: "P-DUP", Stage: "s4", Title: "登录接口无 CSRF 防护（无 token 校验）请求体单变量对照确证", Detail: "x2", Severity: "低", Confidence: "确证"})
	_, _ = st.AddFinding(&store.Finding{ProjectID: "P-DUP", Stage: "s5", Title: "登录接口无CSRF防护（无token校验）请求体单变量对照复核", Detail: "疑似版", Severity: "中", Confidence: "疑似"})
	_, _ = o.exec.WriteFile("P-DUP", "report.md", "### R-01 csrf\n### R-02 枚举\n")
	issues := o.deterministicGate(p, "s8")
	found := false
	for _, iss := range issues {
		if strings.Contains(iss, "双记") {
			found = true
		}
	}
	if !found {
		t.Fatalf("同根因双记应被拦截: %v", issues)
	}
}

// v3.8.2 回归：s8 确定性门在反思 PASS 路径也必须生效（此前仅反思失败时执行）。
// 通过 deterministicGate 直测（complete_stage 流程级验证见 TestDeterministicGate 系）。
func TestDeterministicGateS8AlwaysApplies(t *testing.T) {
	_, st := testApprover(t)
	dir := t.TempDir()
	o := &Orchestrator{store: st, exec: newTestExec(t, dir), bus: events.NewBus(), cfg: func() *config.Config { c := &config.Config{}; c.ApplyDefaultsForTest(); return c }()}
	p := &store.Project{ROEAcknowledgedAt: "2026-11-22T00:00:00Z", ID: "P-ALW"}
	_ = st.SaveProject(p)
	// 双记 + R 条目(1) < findings(2)：两类硬校验均应命中
	_, _ = o.exec.WriteFile("P-ALW", "report.md", "### R-01 明文传输\n### R-02 弱哈希\n### R-03 枚举\n")
	_, _ = st.AddFinding(&store.Finding{ProjectID: "P-ALW", Stage: "s4", Title: "未授权全量人员枚举接口未做认证校验可遍历全校人员数据表", Detail: "a", Severity: "高", Confidence: "确证"})
	_, _ = st.AddFinding(&store.Finding{ProjectID: "P-ALW", Stage: "s4", Title: "未授权全量人员枚举接口未做认证校验可遍历全校人员数据导出", Detail: "b", Severity: "高", Confidence: "确证"})
	issues := o.deterministicGate(p, "s8")
	foundDup, foundCons := false, false
	for _, iss := range issues {
		if strings.Contains(iss, "双记") {
			foundDup = true
		}
		if strings.Contains(iss, "多于 findings") {
			foundCons = true
		}
	}
	if !foundDup || !foundCons {
		t.Fatalf("双记与一致性硬校验均应命中: %v", issues)
	}
}
