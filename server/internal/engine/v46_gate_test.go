package engine

// v4.6 执行可靠性改造专项测试（对应《优化方案_全任务审计执行可靠性整改_v4.5增补层》）：
// E1 结论-证据硬校验 / E3 负结果语义 / E4 可利用性双维 / B1 入口判重 / B5 结论回写 /
// V3 收口强制清单 / R2 门禁扩容。夹具取自 2026-11 全量审计的实证误判案例形态。

import (
	"context"
	"strings"
	"testing"

	"jiutouniao/internal/config"
	"jiutouniao/internal/events"
	"jiutouniao/internal/llm"
	"jiutouniao/internal/store"
)

func v46Orchestrator(t *testing.T) (*Orchestrator, *store.Store) {
	t.Helper()
	_, st := testApprover(t)
	dir := t.TempDir()
	o := &Orchestrator{store: st, exec: newTestExec(t, dir), bus: events.NewBus(),
		cfg: func() *config.Config { c := &config.Config{}; c.ApplyDefaultsForTest(); return c }()}
	return o, st
}

func call(t *testing.T, o *Orchestrator, p *store.Project, stage, name, args string) string {
	t.Helper()
	return o.dispatch(context.Background(), p, stage, llm.ToolCall{Name: name, Arguments: args})
}

// E1-①/②：claims 判据串校验（缺失文件 / 判据串未命中 → 拒绝；命中 → 通过）
func TestV46RecordFindingClaims(t *testing.T) {
	o, _ := v46Orchestrator(t)
	p := &store.Project{ ROEAcknowledgedAt: "2026-11-22T00:00:00Z",ID: "P-V46A"}
	_ = o.store.SaveProject(p)
	_, _ = o.exec.WriteFile(p.ID, "evidence/probe.txt", "HTTP 200 94068B ofid=2 教務處")

	// ① 引用文件不存在 → 拒绝
	got := call(t, o, p, "s4", "record_finding",
		`{"title":"布尔盲注三重确证","severity":"高","confidence":"确证","claims":[{"file":"evidence/no-such.txt","must_contain":"x"}]}`)
	if !strings.Contains(got, "引用文件不存在") {
		t.Fatalf("claims 文件缺失应拒绝: %s", got)
	}
	// ② 判据串未命中 → 拒绝
	got = call(t, o, p, "s4", "record_finding",
		`{"title":"布尔盲注三重确证","severity":"高","confidence":"确证","claims":[{"file":"evidence/probe.txt","must_contain":"alert protocol version"}]}`)
	if !strings.Contains(got, "判据串未命中") {
		t.Fatalf("判据串未命中应拒绝: %s", got)
	}
	// ③ 命中 → 通过（且高危确证带 claims 合法）
	got = call(t, o, p, "s4", "record_finding",
		`{"title":"布尔盲注三重确证","severity":"高","confidence":"确证","detail":"证据 evidence/probe.txt","claims":[{"file":"evidence/probe.txt","must_contain":"94068B"}]}`)
	if !strings.Contains(got, "已登记漏洞") || !strings.Contains(got, "claims 判据 1 条已核验命中") {
		t.Fatalf("claims 命中应通过: %s", got)
	}
}

// E1-③：否定性断言 + 确证 + 无 claims → 拒绝（0935 jar 案形态）
func TestV46RecordFindingNegativeAssert(t *testing.T) {
	o, _ := v46Orchestrator(t)
	p := &store.Project{ ROEAcknowledgedAt: "2026-11-22T00:00:00Z",ID: "P-V46B"}
	_ = o.store.SaveProject(p)
	got := call(t, o, p, "s5", "record_finding",
		`{"title":"Admin 验证码绕过不依赖会话 Cookie","severity":"高","confidence":"确证","detail":"evidence/s5-exp02-jar1.txt 为空 jar，客户端未获得任何会话 Cookie"}`)
	if !strings.Contains(got, "claims 判据串") {
		t.Fatalf("否定性断言无 claims 应拒绝: %s", got)
	}
	// 降级为疑似则放行（给合规出路）
	got = call(t, o, p, "s5", "record_finding",
		`{"title":"Admin 验证码绕过不依赖会话 Cookie","severity":"高","confidence":"疑似","detail":"evidence/s5-exp02-jar1.txt 为空 jar"}`)
	if !strings.Contains(got, "已登记漏洞") {
		t.Fatalf("降级疑似应放行: %s", got)
	}
}

// E1-④：确证 与 待验证 同文 → 拒绝（1AC8 sendSMS 案形态）
func TestV46RecordFindingPendingConfidence(t *testing.T) {
	o, _ := v46Orchestrator(t)
	p := &store.Project{ ROEAcknowledgedAt: "2026-11-22T00:00:00Z",ID: "P-V46C"}
	_ = o.store.SaveProject(p)
	got := call(t, o, p, "s4", "record_finding",
		`{"title":"sendSMS 未授权可达（短信轰炸面）","severity":"中","confidence":"确证","detail":"接口可达性确证；服务端是否校验待 S4 单请求验证"}`)
	if !strings.Contains(got, "置信度「确证」与内容矛盾") {
		t.Fatalf("确证+待验证应拒绝: %s", got)
	}
}

// E4：高危 + exploitability=untested → 自动降级中级
func TestV46RecordFindingExploitabilityCap(t *testing.T) {
	o, st := v46Orchestrator(t)
	p := &store.Project{ ROEAcknowledgedAt: "2026-11-22T00:00:00Z",ID: "P-V46D"}
	_ = o.store.SaveProject(p)
	got := call(t, o, p, "s4", "record_finding",
		`{"title":"管理面隐藏路径暴露未认证会话分配","severity":"高","confidence":"疑似","exploitability":"untested","detail":"分配原语确证 e-EV001；续接/触达未验证"}`)
	if !strings.Contains(got, "自动降为「中」") {
		t.Fatalf("untested 高危应自动降级: %s", got)
	}
	fs, _ := st.ListFindings(p.ID)
	if len(fs) != 1 || fs[0].Severity != "中" || fs[0].Exploitability != "untested" {
		t.Fatalf("落库应为中/untested: %+v", fs)
	}
}

// B1：归一化标题全等 → 入口判重拒绝
func TestV46RecordFindingDedup(t *testing.T) {
	o, _ := v46Orchestrator(t)
	p := &store.Project{ ROEAcknowledgedAt: "2026-11-22T00:00:00Z",ID: "P-V46E"}
	_ = o.store.SaveProject(p)
	base := `{"title":"招生报考系统全站 HTTP 明文传输，登录凭据可被嗅探","severity":"高","confidence":"确证","detail":"evidence/p.txt"}`
	if got := call(t, o, p, "s2", "record_finding", base); !strings.Contains(got, "已登记漏洞") {
		t.Fatalf("首次登记应通过: %s", got)
	}
	if got := call(t, o, p, "s2", "record_finding", base); !strings.Contains(got, "疑似重复发现") {
		t.Fatalf("重复登记应拒绝: %s", got)
	}
}

// E3：负结果语义——非法 observed_result 拒绝；缺失自动降级；negative_valid 放行
func TestV46CoverageObservedResult(t *testing.T) {
	o, st := v46Orchestrator(t)
	p := &store.Project{ ROEAcknowledgedAt: "2026-11-22T00:00:00Z",ID: "P-V46F"}
	_ = o.store.SaveProject(p)
	// ① 显式非法
	got := call(t, o, p, "s4", "update_coverage",
		`{"endpoint":"/druid/index.html","vuln_class":"信息泄露","status":"ruled_out","notes":"三次探测全超时","observed_result":"undetermined_timeout"}`)
	if !strings.Contains(got, "不得支撑") {
		t.Fatalf("undetermined_timeout 应拒绝 ruled_out: %s", got)
	}
	// ② 缺失 → 自动降级
	got = call(t, o, p, "s4", "update_coverage",
		`{"endpoint":"/druid/index.html","vuln_class":"信息泄露","status":"ruled_out","notes":"三次探测全超时"}`)
	if !strings.Contains(got, "自动降为 needs_follow_up") {
		t.Fatalf("缺失 observed_result 应降级: %s", got)
	}
	cov, _ := st.ListCoverage(p.ID)
	if len(cov) != 1 || cov[0].Status != "needs_follow_up" {
		t.Fatalf("落库应为 needs_follow_up: %+v", cov)
	}
	// ③ negative_valid → 放行真阴性
	got = call(t, o, p, "s4", "update_coverage",
		`{"endpoint":"/druid/index.html","vuln_class":"信息泄露","status":"ruled_out","notes":"有效请求 404 原文 evidence/druid.txt","observed_result":"negative_valid"}`)
	if strings.Contains(got, "错误") {
		t.Fatalf("negative_valid 应放行: %s", got)
	}
	cov, _ = st.ListCoverage(p.ID)
	if cov[0].Status != "ruled_out" {
		t.Fatalf("落库应为 ruled_out: %+v", cov[0])
	}
	// ④ 键归一化：scheme/尾斜杠差异原地合并（V6 僵尸根因消除）
	call(t, o, p, "s5", "update_coverage", `{"endpoint":"https://www.example.com/x","vuln_class":"越权","status":"needs_follow_up","notes":"a"}`)
	got = call(t, o, p, "s5", "update_coverage", `{"endpoint":"www.example.com/x","vuln_class":"越权","status":"ruled_out","notes":"b","observed_result":"negative_valid"}`)
	if !strings.Contains(got, "累计测试 2 次") {
		t.Fatalf("同义键应原地合并: %s", got)
	}
}

// V3：s4/s5 收口强制清单
func TestV46CompleteStageForcedLists(t *testing.T) {
	o, _ := v46Orchestrator(t)
	p := &store.Project{ ROEAcknowledgedAt: "2026-11-22T00:00:00Z",ID: "P-V46G", StageStates: map[string]*store.StageState{"s4": {Status: "running", StartedAt: "2026-01-01T00:00:00Z"}}}
	_ = o.store.SaveProject(p)
	// v7.1.0 E1'：缺清单不再拦截——引擎按台账代填（收口继续，此处被实体文件门接住），
	// 代填行为入时间线可审计（旧拦截文案在 48 项目实测 93 次收口 0 次通过，runtime-audit R1）
	got := call(t, o, p, "s4", "complete_stage", `{"summary":"x"}`)
	if strings.Contains(got, "缺少必填清单") || strings.Contains(got, "V3") {
		t.Fatalf("v7.1.0 E1' 后缺清单不应拦截（引擎代填）: %s", got)
	}
	tl, _ := o.store.ListTimeline(p.ID)
	filled := false
	for _, ev := range tl {
		if strings.Contains(ev.Event, "E1' V3 引擎代填") {
			filled = true
		}
	}
	if !filled {
		t.Fatalf("E1' 引擎代填应落时间线留痕")
	}
	// 显式空数组 → 越过 V3（后续被实体文件检查拦截属正常流程）
	got = call(t, o, p, "s4", "complete_stage", `{"summary":"x","ready_but_unexecuted":[],"l2_approved_unused":[]}`)
	if strings.Contains(got, "V3") {
		t.Fatalf("显式空数组应放行 V3: %s", got)
	}
}

// B5：update_finding 结论回写（强制 reason + 修订留痕）
func TestV46UpdateFinding(t *testing.T) {
	o, st := v46Orchestrator(t)
	p := &store.Project{ ROEAcknowledgedAt: "2026-11-22T00:00:00Z",ID: "P-V46H"}
	_ = o.store.SaveProject(p)
	id, _ := st.AddFinding(&store.Finding{ProjectID: p.ID, Stage: "s2", Title: "ShellInABox 未认证会话分配", Severity: "高", Confidence: "疑似", Detail: "EV-001"})
	// 缺 reason → 拒绝
	got := call(t, o, p, "s7", "update_finding", `{"id":"`+id+`","severity":"中"}`)
	if !strings.Contains(got, "reason 必填") {
		t.Fatalf("缺 reason 应拒绝: %s", got)
	}
	// 带 reason → 修订成功
	got = call(t, o, p, "s7", "update_finding", `{"id":"`+id+`","severity":"中","exploitability":"conditional","detail_append":"R-4 续接 400 实测收窄为资源消耗","reason":"r-阶段执行报告.md:21 决定性实验"}`)
	if !strings.Contains(got, "已修订") {
		t.Fatalf("修订应成功: %s", got)
	}
	fs, _ := st.ListFindings(p.ID)
	if fs[0].Severity != "中" || fs[0].Exploitability != "conditional" || !strings.Contains(fs[0].Detail, "R-4 续接 400") {
		t.Fatalf("修订未落库: %+v", fs[0])
	}
}

// R2 门禁扩容：s8 收口层兜底（入口层漏网的旧记录也被拦）
func TestV46GateE1Backstop(t *testing.T) {
	o, st := v46Orchestrator(t)
	p := &store.Project{ ROEAcknowledgedAt: "2026-11-22T00:00:00Z",ID: "P-V46I"}
	_ = st.SaveProject(p)
	_, _ = st.AddFinding(&store.Finding{ProjectID: p.ID, Stage: "s8", Title: "X 验证码绕过不依赖会话 Cookie", Severity: "高", Confidence: "确证", Detail: "jar 为空"})
	_, _ = st.AddFinding(&store.Finding{ProjectID: p.ID, Stage: "s8", Title: "Y 未鉴权面", Severity: "低", Confidence: "", Detail: "z"})
	issues := o.deterministicGate(p, "s8")
	joined := strings.Join(issues, "\n")
	if !strings.Contains(joined, "claims 判据串") {
		t.Fatalf("否定性断言无 claims 应被门禁拦截: %v", issues)
	}
	if !strings.Contains(joined, "confidence 为空") {
		t.Fatalf("空 confidence 应被门禁拦截: %v", issues)
	}
}
