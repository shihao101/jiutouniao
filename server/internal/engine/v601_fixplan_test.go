package engine

// v6.0.1 fix-plan 20261122 验收测试：
// C27 类级处置门 / C28 候选归档门 / C31 零产出对账门 / C29 覆盖边界门 / C30 模型记录。

import (
	"strings"
	"testing"
	"time"

	"jiutouniao/internal/llm"
	"jiutouniao/internal/store"
)

// v601Project 建测试项目（工作区由 v48Orchestrator 装配对齐）。
func v601Project(t *testing.T, o *Orchestrator, id string) *store.Project {
	t.Helper()
	p := &store.Project{ ROEAcknowledgedAt: "2026-11-22T00:00:00Z",ID: id, Target: "t1.example\nt2.example"}
	if err := o.store.SaveProject(p); err != nil {
		t.Fatal(err)
	}
	return p
}

// ---------- C27 类级处置门 ----------

// 假设类零投递 → 拦截；补 coverage C 编号引用 → 对应类通过；全量对账表 → 全通过
func TestV601ClassDispositionGate(t *testing.T) {
	o, st := v48Orchestrator(t)
	p := v601Project(t, o, "P-V601C27")
	// 判定表：奇数类=假设，5 的倍数=不适用（复用 v4.8 fixture）
	_, _ = o.exec.WriteFile(p.ID, "deliverables/s3-筛查矩阵判定表.md", matrixTableFixture(nil, nil))
	issues := o.classDispositionIssues(p, "s4")
	if len(issues) == 0 || !strings.Contains(issues[0], "C27 类级处置门") {
		t.Fatalf("假设类零投递应拦截: %v", issues)
	}
	if !strings.Contains(issues[0], "C-01") {
		t.Fatalf("应点名缺失类（C-01 为假设行）: %v", issues[0])
	}
	// 补一条 coverage 引用 C-01 → C-01 从缺失清单消失
	_, _ = st.UpsertCoverage(&store.CoverageEntry{ProjectID: p.ID, Stage: "s4",
		Endpoint: "t1.example/api", VulnClass: "注入（C-01 执行卡投递）", Status: "no_issue_found", Notes: "按 C-01 执行卡投递：3 变体无差异"})
	issues = o.classDispositionIssues(p, "s4")
	if len(issues) > 0 && strings.Contains(issues[0], "C-01") {
		t.Fatalf("C-01 已留痕不应再点名: %v", issues[0])
	}
	// 写全量对账表（每行 C 编号 + 处置词）→ 全通过
	var b strings.Builder
	b.WriteString("# 27类收口对账表\n\n| 类 | 处置 | 依据 |\n|---|---|---|\n")
	for i := 1; i <= 27; i++ {
		disp := "已测"
		if i%5 == 0 {
			disp = "不适用（S3 已判）"
		} else if i%3 == 0 {
			disp = "合规豁免（no_credentials，S0 无凭据）"
		} else if i%7 == 0 {
			disp = "环境不可达（内网挂起，需跳板）"
		}
		b.WriteString("| C-" + twoDigits(i) + " | " + disp + " | evidence/s4/x.txt |\n")
	}
	_, _ = o.exec.WriteFile(p.ID, "deliverables/s6-27类收口对账表.md", b.String())
	if issues := o.classDispositionIssues(p, "s4"); len(issues) != 0 {
		t.Fatalf("全量对账表后应通过: %v", issues)
	}
	// S6 收口件门：对账表 27 行齐 → 通过
	if issues := o.reconciliationTableIssues(p); len(issues) != 0 {
		t.Fatalf("对账表齐全应通过 S6 门: %v", issues)
	}
	// 缺 3 行的对账表 → 拦截
	_, _ = o.exec.WriteFile(p.ID, "deliverables/s6-27类收口对账表.md", strings.Replace(b.String(), "| C-02 |", "| C-0X |", 1))
	if issues := o.reconciliationTableIssues(p); len(issues) == 0 || !strings.Contains(issues[0], "对账表") {
		t.Fatalf("对账表缺行应拦截: %v", issues)
	}
}

func twoDigits(i int) string {
	if i < 10 {
		return "0" + string(rune('0'+i))
	}
	return string(rune('0'+i/10)) + string(rune('0'+i%10))
}

// ---------- C28 候选归档门 ----------

func TestV601CandidateGate(t *testing.T) {
	o, _ := v48Orchestrator(t)
	p := v601Project(t, o, "P-V601C28")
	id, err := o.store.AddCandidate(&store.Candidate{ProjectID: p.ID, Stage: "s4",
		Title: "GetCaptchaImg 匿名可批量取码", Target: "rdrc.example", EvidenceRef: "evidence/s5/q5.txt"})
	if err != nil {
		t.Fatal(err)
	}
	issues := o.openCandidateIssues(p)
	if len(issues) == 0 || !strings.Contains(issues[0], "C28 候选归档门") || !strings.Contains(issues[0], id) {
		t.Fatalf("open 候选应拦截: %v", issues)
	}
	// 归位 vt → 通过
	cand, _ := o.store.GetCandidate(id)
	cand.Disposition, cand.DispositionRef = "vt", "VT-TEST0001"
	if err := o.store.SaveCandidate(cand); err != nil {
		t.Fatal(err)
	}
	if issues := o.openCandidateIssues(p); len(issues) != 0 {
		t.Fatalf("归位后应通过: %v", issues)
	}
	// 跨项目隔离：另一项目的候选不影响本项目
	id2, _ := o.store.AddCandidate(&store.Candidate{ProjectID: "P-OTHER", Stage: "s4", Title: "他项目候选"})
	p2, _ := o.store.GetCandidate(id2)
	_ = p2
	if issues := o.openCandidateIssues(p); len(issues) != 0 {
		t.Fatalf("他项目候选不应影响本项目: %v", issues)
	}
}

// ---------- C29 覆盖边界门 ----------

func TestV601CoverageBoundaryGate(t *testing.T) {
	o, _ := v48Orchestrator(t)
	p := v601Project(t, o, "P-V601C29")
	// ① 无章节 → 拦截
	_, _ = o.exec.WriteFile(p.ID, "report.md", "# 渗透测试报告\n\n## 执行摘要\n- 完成。\n")
	issues := o.coverageBoundaryIssues(p)
	if len(issues) == 0 || !strings.Contains(issues[0], "覆盖边界") {
		t.Fatalf("缺章节应拦截: %v", issues)
	}
	// ② 有章节但无量化分母 → 拦截
	_, _ = o.exec.WriteFile(p.ID, "report.md", "# 渗透测试报告\n\n## 覆盖边界\n\n- 认证后面未测：多数目标。\n")
	issues = o.coverageBoundaryIssues(p)
	if len(issues) == 0 || !strings.Contains(issues[0], "分母") {
		t.Fatalf("缺分母应拦截: %v", issues)
	}
	// ③ 有分母无解锁条件 → 拦截
	_, _ = o.exec.WriteFile(p.ID, "report.md", "# 渗透测试报告\n\n## 覆盖边界\n\n| 边界项 | 量化 |\n|---|---|\n| 认证后 | 0/64 |\n")
	issues = o.coverageBoundaryIssues(p)
	if len(issues) == 0 || !strings.Contains(issues[0], "解锁") {
		t.Fatalf("缺解锁条件应拦截: %v", issues)
	}
	// ④ 完整 → 通过
	_, _ = o.exec.WriteFile(p.ID, "report.md", "# 渗透测试报告\n\n## 覆盖边界\n\n| 边界项 | 量化数据 | 解锁条件 | 来源 |\n|---|---|---|---|\n| 认证后 | 0/64 | 客户提供测试账号 | coverage.json |\n\n## 结论\n- 完成。\n")
	if issues := o.coverageBoundaryIssues(p); len(issues) != 0 {
		t.Fatalf("完整边界应通过: %v", issues)
	}
	// 初稿含待人工确认标注（不写成测试结论）
	draft := o.coverageBoundaryDraft(p)
	if !strings.Contains(draft, "覆盖边界") || !strings.Contains(draft, "待人工确认") {
		t.Fatalf("初稿应标注待人工确认: %s", draft)
	}
}

// ---------- C30 模型生效记录与漂移 ----------

func TestV601ModelSelectionRecord(t *testing.T) {
	o, st := v48Orchestrator(t)
	p := v601Project(t, o, "P-V601C30")
	o.recordModelSel(p, "s4", "glm-test", "clientFor")
	o.recordModelSel(p, "s4", "glm-test", "clientFor") // 同阶段同模型只记一次
	events, _, _ := st.ListStream(p.ID, 0)
	n := 0
	for _, e := range events {
		if strings.Contains(e.Text, "C30 模型生效记录") {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("同阶段同模型应去重为 1 条记录，实际 %d", n)
	}
	o.recordModelSel(p, "s4", "glm-test2", "failover-takeover") // 切换另记一条
	events, _, _ = st.ListStream(p.ID, 0)
	n = 0
	for _, e := range events {
		if strings.Contains(e.Text, "C30 模型生效记录") {
			n++
		}
	}
	if n != 2 {
		t.Fatalf("模型切换应额外记录，实际 %d", n)
	}
	// 漂移告警：回报与请求不一致 → 告警一次；一致 → 无告警
	o.checkModelDrift(p, "s4", "glm-test2", llm.Usage{ProviderModel: "other-model"})
	o.checkModelDrift(p, "s4", "glm-test2", llm.Usage{ProviderModel: "other-model"}) // 去重
	o.checkModelDrift(p, "s4", "glm-test2", llm.Usage{ProviderModel: "glm-test2"})   // 一致不告警
	events, _, _ = st.ListStream(p.ID, 0)
	n = 0
	for _, e := range events {
		if strings.Contains(e.Text, "C30 漂移告警") {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("漂移告警应去重为 1 条，实际 %d", n)
	}
}

// ---------- C31 零产出对账门 ----------

func TestV601IncompleteBatchGate(t *testing.T) {
	o, _ := v48Orchestrator(t)
	p := v601Project(t, o, "P-V601C31")
	// 造一个立即结束且零输出的作业（echo 无输出 + 立即退出）
	job, err := o.exec.StartAsync(p.ID, "true", 10)
	if err != nil {
		t.Fatal(err)
	}
	deadline := 50
	for i := 0; i < deadline; i++ {
		state, _, _, _, _ := o.exec.PollAsync(p.ID, job.ID)
		if state != "running" {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	// true 无输出 → IncompleteAsyncJobs 应命中（finished + 近零产出）
	inc := o.exec.IncompleteAsyncJobs(p.ID)
	found := false
	for _, j := range inc {
		if j.ID == job.ID {
			found = true
		}
	}
	if !found {
		t.Fatalf("近零产出作业应进入未完成清单: %+v", inc)
	}
	issues := o.incompleteBatchIssues(p)
	if len(issues) == 0 || !strings.Contains(issues[0], "C31 零产出对账门") {
		t.Fatalf("零产出无留痕应拦截: %v", issues)
	}
	// 补 VT 引用 job id → 通过
	_, _ = o.store.AddVT(&store.VerificationTask{ProjectID: p.ID, Stage: "s4",
		Title: "复测 " + job.ID + "（超时/零产出）", StartConditions: "通道恢复后", Status: "pending"})
	if issues := o.incompleteBatchIssues(p); len(issues) != 0 {
		t.Fatalf("VT 留痕后应通过: %v", issues)
	}
}

// ---------- v6.0.4 P11 验收测试 ----------

// S8 成功标准对照门三态：无章节→拦截 / 有引用→通过 / 未填写→跳过
func TestV604SuccessCriteriaGate(t *testing.T) {
	o, _ := v48Orchestrator(t)
	p := v601Project(t, o, "P-V604SC")
	p.SuccessCriteria = "测试目的：验证投单系统鉴权有效性；成功标准：每条结论有可复现 POC 与影响说明"
	if err := o.store.SaveProject(p); err != nil {
		t.Fatal(err)
	}
	// ① 报告不引用成功标准 → 拦截
	_, _ = o.exec.WriteFile(p.ID, "report.md", "# 报告\n## 执行摘要\n- 完成。\n")
	issues := o.successCriteriaIssuesForTest(p)
	if len(issues) == 0 || !strings.Contains(issues[0], "P11") {
		t.Fatalf("未对照成功标准应拦截: %v", issues)
	}
	// ② 报告含对照小节 → 通过
	_, _ = o.exec.WriteFile(p.ID, "report.md", "# 报告\n## 结论对照成功标准\n- 已逐条说明。\n")
	if issues := o.successCriteriaIssuesForTest(p); len(issues) != 0 {
		t.Fatalf("含对照小节应通过: %v", issues)
	}
	// ③ 未填写成功标准 → 跳过
	p2 := v601Project(t, o, "P-V604SC2")
	_, _ = o.exec.WriteFile(p2.ID, "report.md", "# 报告\n- 完成。\n")
	if issues := o.successCriteriaIssuesForTest(p2); len(issues) != 0 {
		t.Fatalf("未填写成功标准应跳过: %v", issues)
	}
}

// cappedText 行为：多行保留 / 截断标记 / 空值占位
func TestV604CappedText(t *testing.T) {
	multi := "第一行纪律\n第二行纪律\n第三行纪律"
	got := cappedText(multi, 1500)
	if !strings.Contains(got, "第二行纪律") || !strings.Contains(got, "第三行纪律") {
		t.Fatalf("多行内容必须全量保留（firstLine 缺陷回归）: %q", got)
	}
	long := strings.Repeat("字", 2000)
	got2 := cappedText(long, 1500)
	if !strings.HasPrefix(got2, "字字字") || !strings.HasSuffix(got2, "…（余略，全文见项目档案）") || len([]rune(got2)) <= 1500 {
		t.Fatalf("截断行为不符: len=%d head=%q", len([]rune(got2)), []rune(got2)[:min(20, len([]rune(got2)))])
	}
	if cappedText("", 100) != "（未填写）" {
		t.Fatal("空值应返回占位")
	}
}

// successCriteriaIssuesForTest 测试直接调用抽出的方法
func (o *Orchestrator) successCriteriaIssuesForTest(p *store.Project) []string {
	return o.successCriteriaIssues(p)
}
