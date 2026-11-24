package engine

// v6.4.0 S4 修复方案回归测试（docs/修复方案_S4漏洞发现阶段补全_v6.4.0_20261123.md）：
// S4-① C27/对账解析单目标豁免 + 判定表/对账表行解析容差。
// 后续小节随修复项追加：S4-② 端点表生产端契约 / S4-④ access 排序键 / S4-⑤⑥ S5 移交承接 /
// S4-⑦ TH 回填对账 / S4-⑧ 逐类对账表行数 / S4-⑨ 多目标下游承接 / S4-⑩ 回环治理 /
// S4-⑪ 子代理工具面 / S4-⑫ 门禁校准。

import (
	"fmt"
	"strings"
	"testing"

	"jiutouniao/internal/store"
)

// sixColSurfaceFixture 单目标项目按 6 列标准格式输出、第 2 列误放触发面描述的判定表
// （某历史任务 实测形态——v6.4.0 S4-① 修复前 C27 会按触发面拆复合键导致必然误拦）。
// 仅 C-01（假设）与 C-08（待判定）为需投递类，其余 25 类不适用（M2 27 行完整）。
func sixColSurfaceFixture() string {
	var b strings.Builder
	b.WriteString("# 筛查矩阵判定表\n\n| 类 | 目标 | 触发面 | 判定 | 证据 | TH/卡 |\n|---|---|---|---|---|---|\n")
	b.WriteString("| C-01 | 登录面（后台管理系统登录，唯一已知登录面） | POST /login 四字段 | 假设 | 证据：evidence/s2-login-body.html | TH-01 ｜ 入口=POST /login→首探针=错误文案差分→阳性=文案差异→阴性=统一文案→停止≤6 请求 |\n")
	b.WriteString("| C-08 | 业务对象面（招生平台） | 登录后业务面 | 待判定 | 证据：S0 无凭证 | TH-07 ｜ 双假设并列：可枚举 OR 会话绑定；入口=登录后业务面→首探针=匿名 GET→阳性=200 带数据→阴性=302/401→停止≤6 请求 |\n")
	for i := 1; i <= 27; i++ {
		if i == 1 || i == 8 {
			continue
		}
		b.WriteString(fmt.Sprintf("| C-%02d | 触发面摘要 | — | 不适用 | 证据：核查无对应面 | TH-01 |\n", i))
	}
	return b.String()
}

// reconTableFixture 逐类对账表（行首格带触发面摘要的合法形态——旧 matrixClassRe 解析不到）。
// outcome 列用 C27 处置词分桶识别的标记：已测/待续/合规豁免。
func reconTableFixture() string {
	var b strings.Builder
	b.WriteString("# S4 逐类对账表\n\n| 类 | 目标 | 技能 | endpoint | 首探针 | T-xx | outcome |\n|---|---|---|---|---|---|---|\n")
	b.WriteString("| C-01 登录面 | 单目标 | auth-flow-deep | /login | 文案差分 | T-01 | 已测（coverage C-01） |\n")
	b.WriteString("| C-08 业务面 | 单目标 | api-idor | 待端点表建立 | 匿名 GET | T-02 | 待续（无凭证移交） |\n")
	for i := 1; i <= 27; i++ {
		if i == 1 || i == 8 {
			continue
		}
		b.WriteString(fmt.Sprintf("| C-%02d | 单目标 | — | — | — | — | 合规豁免（无对应面） |\n", i))
	}
	return b.String()
}

// TestV640SingleTargetCompoundKeyExemption S4-①：单目标 + 6 列触发面描述判定表，C27 按
// 项目级键对账——coverage/VT 只引 C 编号即记 tested/queued（不再要求触发面原文同现）。
func TestV640SingleTargetCompoundKeyExemption(t *testing.T) {
	o, _ := v48Orchestrator(t)
	// 单目标项目：Target 单行
	p := &store.Project{ROEAcknowledgedAt: "2026-11-22T00:00:00Z", ID: "P-V640S1",
		Target: "https://target-a.example.com"}
	_ = o.store.SaveProject(p)
	raw := writeReconJudgment(t, o, p)

	rows := parseMatrixRows(raw)
	need := matrixNeedKeys(rows, true)
	if len(need) != 2 || !need["C-01"] || !need["C-08"] {
		t.Fatalf("单目标豁免后应为 2 个项目级键: %v", keysOf(need))
	}
	for k := range need {
		if strings.Contains(k, "@") {
			t.Fatalf("单目标项目不应产生复合键: %s", k)
		}
	}

	// coverage 只引 C-01（无触发面原文）→ tested；VT 引 C-08 → queued_vt；C27 全键有归宿
	_, _ = o.store.UpsertCoverage(&store.CoverageEntry{ProjectID: p.ID, Stage: "s4",
		Endpoint: "POST /login", VulnClass: "认证", Status: "no_issue_found",
		Notes: "C-01 错误文案差分阴性", ObservedResult: "negative_valid"})
	_, _ = o.store.AddVT(&store.VerificationTask{ProjectID: p.ID, Stage: "s4",
		Title: "C-08 待判定裁决（会话后差分）", Status: "pending"})
	if issues := o.classDispositionIssues(p, "s4"); len(issues) != 0 {
		t.Fatalf("单目标 C 编号留痕应全键有归宿: %v", issues)
	}
}

// TestV640MultiTargetCompoundKeysUnchanged S4-① 防回归：多目标项目复合键行为不变。
func TestV640MultiTargetCompoundKeysUnchanged(t *testing.T) {
	raw := "| C-01 | t1.example,t2.example | 假设 | 证据 | TH-01 | 入口: /e 首探针: GET?x=probe 阳性: 差异 阴性: 无差异 停止: ≤6 请求 |\n"
	rows := parseMatrixRows(raw)
	if len(rows) != 1 || len(rows[0].targets) != 2 {
		t.Fatalf("多目标 6 列行应拆 2 个目标: %+v", rows)
	}
	need := matrixNeedKeys(rows, false)
	if !need["C-01@"+canonicalTargetKey("t1.example")] || !need["C-01@"+canonicalTargetKey("t2.example")] {
		t.Fatalf("多目标应产生复合键: %v", keysOf(need))
	}
	keys := matrixLineKeys(rows[0], false)
	if len(keys) != 2 {
		t.Fatalf("matrixLineKeys 多目标应 2 键: %v", keys)
	}
	// 单目标豁免：同一行在单目标项目坍缩为项目级键
	need1 := matrixNeedKeys(rows, true)
	if !need1["C-01"] || len(need1) != 1 {
		t.Fatalf("单目标豁免应坍缩为项目级键: %v", keysOf(need1))
	}
	if ks := matrixLineKeys(rows[0], true); len(ks) != 1 || ks[0] != "C-01" {
		t.Fatalf("单目标 matrixLineKeys 应坍缩: %v", ks)
	}
}

// TestV640MatrixClassReTolerance S4-①：行首格容差——`| C-01 登录面 |` 形态可被解析，
// 对账表处置词经交付物分桶归账（修复前这些行解析不到 → 处置词全部丢失）。
func TestV640MatrixClassReTolerance(t *testing.T) {
	if m := matrixClassRe.FindStringSubmatch("| C-01 登录面 | 单目标 | — |"); m == nil || m[1] != "C-01" {
		t.Fatalf("首格带摘要的行应被解析: %v", m)
	}
	if m := matrixClassRe.FindStringSubmatch("| C-01 | 登录面 |"); m == nil || m[1] != "C-01" {
		t.Fatalf("标准行应被解析: %v", m)
	}
	if matrixClassRe.FindStringSubmatch("备注里提到 C-01 与 C-011") != nil {
		t.Fatalf("非行首引用不应匹配")
	}
	o, _ := v48Orchestrator(t)
	p := &store.Project{ROEAcknowledgedAt: "2026-11-22T00:00:00Z", ID: "P-V640S2",
		Target: "https://target-b.example.com"}
	_ = o.store.SaveProject(p)
	_, _ = o.exec.WriteFile(p.ID, "deliverables/s3-筛查矩阵判定表.md", sixColSurfaceFixture())
	_, _ = o.exec.WriteFile(p.ID, "deliverables/s4-逐类对账表.md", reconTableFixture())
	if issues := o.classDispositionIssues(p, "s4"); len(issues) != 0 {
		t.Fatalf("对账表行首格带摘要应被分桶解析（全键有归宿）: %v", issues)
	}
}

// ---------- 通用小工具 ----------

func writeReconJudgment(t *testing.T, o *Orchestrator, p *store.Project) string {
	t.Helper()
	rel := "deliverables/s3-筛查矩阵判定表.md"
	if _, err := o.exec.WriteFile(p.ID, rel, sixColSurfaceFixture()); err != nil {
		t.Fatalf("写判定表失败: %v", err)
	}
	raw, err := o.exec.ReadFile(p.ID, rel)
	if err != nil {
		t.Fatalf("读判定表失败: %v", err)
	}
	return raw
}

func keysOf(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// ---------- S4-⑤⑥ S4→S5 移交承接 ----------

// TestV640V3StageStateHandover S4-⑤：S4 V3 两清单落 StageState → S5 无留痕拦截、
// coverage/VT 留痕后放行；S4 未收口直通。
func TestV640V3StageStateHandover(t *testing.T) {
	o, _ := v48Orchestrator(t)
	p := &store.Project{ROEAcknowledgedAt: "2026-11-22T00:00:00Z", ID: "P-V640H1",
		Target: "https://h.example.com"}
	_ = o.store.SaveProject(p)
	// S4 未收口（无 StageState）→ 直通
	if issues := o.v3HandoverIssues(p); len(issues) != 0 {
		t.Fatalf("S4 无移交项应直通: %v", issues)
	}
	p.StageStates = map[string]*store.StageState{
		"s4": {Status: "done", V3Ready: []string{"VT-AB1C2DEF3 [ready] SQLi 批量提取（四件套）"},
			V3L2: []string{"AP-XYZ 已批 sqlmap --dump 未投递"}},
	}
	_ = o.store.SaveProject(p)
	// 无 S5 留痕 → 拦截
	issues := o.v3HandoverIssues(p)
	if len(issues) == 0 || !strings.Contains(issues[0], "S4 移交承接门") {
		t.Fatalf("V3 移交项无承接留痕应拦截: %v", issues)
	}
	// S5 coverage notes 引用条目正文（≥12 rune 前缀）→ 放行
	_, _ = o.store.UpsertCoverage(&store.CoverageEntry{ProjectID: p.ID, Stage: "s5",
		Endpoint: "GET /api/user", VulnClass: "SQL注入", Status: "vulnerable",
		Notes: "VT-AB1C2DEF3 批量提取完成，banner/user/db/is-dba 四件套已回填"})
	issues = o.v3HandoverIssues(p)
	if len(issues) == 0 {
		t.Fatalf("AP 条目仍应拦截（未映射）: %v", issues)
	}
	_, _ = o.exec.WriteFile(p.ID, "deliverables/s5-移交映射.md",
		"# S5 待利用队列消费映射\n- AP-XYZ 已批 sqlmap --dump 未投递 → 显式移交（ROE 禁 dump，待续清单）")
	issues = o.v3HandoverIssues(p)
	if len(issues) != 0 {
		t.Fatalf("逐条映射后应放行: %v", issues)
	}
}

// TestV640BrowserAuthRouteHandover S4-⑥：route=browser-auth 结构化字段与旧数据文本标记
// 等价；S5 语料无 browser-auth 通道留痕拦截、留痕后放行；非 s4 阶段文本提及不误判。
func TestV640BrowserAuthRouteHandover(t *testing.T) {
	o, _ := v48Orchestrator(t)
	p := &store.Project{ROEAcknowledgedAt: "2026-11-22T00:00:00Z", ID: "P-V640H2",
		Target: "https://ba.example.com"}
	_ = o.store.SaveProject(p)
	p.StageStates = map[string]*store.StageState{"s4": {Status: "done"}}
	// ① 结构化 route
	f1, _ := o.store.AddFinding(&store.Finding{ProjectID: p.ID, Stage: "s4", Title: "后台登录 SHA1 加密协议",
		Severity: "中", Confidence: "确证", Detail: "前端加密，明文构造不可达", Route: "browser-auth"})
	// ② 旧数据文本标记（route 空）
	f2, _ := o.store.AddFinding(&store.Finding{ProjectID: p.ID, Stage: "s4", Title: "验证码接口频控缺失",
		Severity: "低", Confidence: "疑似", Detail: "标注「browser-auth 路线」移交，captcha-ocr 降级人工读码"})
	// ③ 非 s4 阶段仅文本提及 → 不等价（S5 自己的发现不得自证承接）
	_, _ = o.store.AddFinding(&store.Finding{ProjectID: p.ID, Stage: "s5", Title: "s5 阶段记录",
		Severity: "信息", Confidence: "疑似", Detail: "讨论 browser-auth 路线选型"})
	_ = f1
	_ = f2
	issues := o.v3HandoverIssues(p)
	if len(issues) == 0 || !strings.Contains(issues[0], "S4 移交承接门") {
		t.Fatalf("认证路线移交无留痕应拦截: %v", issues)
	}
	if !strings.Contains(issues[0], "SHA1 加密协议") || !strings.Contains(issues[0], "验证码接口") {
		t.Fatalf("拦截应点名两条移交项: %v", issues)
	}
	// 负向用例（方案 S4-⑥③）：仅引标题原文、无 browser-auth 通道留痕 → 仍拦截
	_, _ = o.store.UpsertCoverage(&store.CoverageEntry{ProjectID: p.ID, Stage: "s5",
		Endpoint: "POST /admin/login", VulnClass: "认证", Status: "needs_follow_up",
		Notes: "后台登录 SHA1 加密协议——重新明文构造复测一轮"})
	issues = o.v3HandoverIssues(p)
	hitAuth := false
	for _, iss := range issues {
		if strings.Contains(iss, "缺 browser-auth 通道留痕") {
			hitAuth = true
		}
	}
	if !hitAuth {
		t.Fatalf("仅引标题原文不应视为 S5-2a 承接完成: %v", issues)
	}
	// S5 语料留痕（coverage notes 引用发现标题前 12 rune + browser-auth 通道标记）
	_, _ = o.store.UpsertCoverage(&store.CoverageEntry{ProjectID: p.ID, Stage: "s5",
		Endpoint: "POST /admin/login", VulnClass: "认证", Status: "needs_follow_up",
		Notes: "browser-auth（browser-kit）通道执行：后台登录 SHA1 加密协议——已抓取 cookies"})
	_, _ = o.store.UpsertCoverage(&store.CoverageEntry{ProjectID: p.ID, Stage: "s5",
		Endpoint: "GET /verifyImg", VulnClass: "认证", Status: "needs_follow_up",
		Notes: "验证码接口频控缺失——browser-auth 人工读码协同，exit 42 路径演练完成"})
	issues = o.v3HandoverIssues(p)
	if len(issues) != 0 {
		t.Fatalf("认证路线留痕后应放行: %v", issues)
	}
}

// ---------- S4-⑦ 威胁清单回填对账门 ----------

func TestV640THBackfillGate(t *testing.T) {
	o, _ := v48Orchestrator(t)
	p := &store.Project{ROEAcknowledgedAt: "2026-11-22T00:00:00Z", ID: "P-V640TH",
		Target: "https://th.example.com"}
	_ = o.store.SaveProject(p)
	// 无威胁模型 → 直通
	if issues := o.threatBackfillIssues(p); len(issues) != 0 {
		t.Fatalf("无威胁模型应直通: %v", issues)
	}
	_, _ = o.exec.WriteFile(p.ID, "deliverables/s3-威胁模型.md",
		"# 威胁模型\nTH-01 会话固定（P2）\nTH-02 注入面（P1）\n")
	// ① 缺回填记录小节 → 拦截
	_, _ = o.exec.WriteFile(p.ID, "deliverables/s4-漏洞清单.md", "# 漏洞清单\n- R-01 注入面\n")
	issues := o.threatBackfillIssues(p)
	if len(issues) == 0 || !strings.Contains(issues[0], "威胁清单回填记录") {
		t.Fatalf("缺回填记录应拦截: %v", issues)
	}
	// ② 记录小节无动作无声明 → 拦截
	_, _ = o.exec.WriteFile(p.ID, "deliverables/s4-漏洞清单.md", "# 漏洞清单\n## 威胁清单回填记录\n（空）\n")
	issues = o.threatBackfillIssues(p)
	if len(issues) == 0 || !strings.Contains(issues[0], "三态留痕") {
		t.Fatalf("无动作无声明应拦截: %v", issues)
	}
	// ③ 「本轮无回填」声明 → 放行
	_, _ = o.exec.WriteFile(p.ID, "deliverables/s4-漏洞清单.md", "# 漏洞清单\n## 威胁清单回填记录\n本轮无回填（实测未推翻/新增清单条目）\n")
	if issues := o.threatBackfillIssues(p); len(issues) != 0 {
		t.Fatalf("显式无回填声明应放行: %v", issues)
	}
	// ④ 幻觉 TH 引用（replaces TH-99 不在清单）→ 拦截
	_, _ = o.exec.WriteFile(p.ID, "deliverables/s4-漏洞清单.md",
		"# 漏洞清单\n## 威胁清单回填记录\n- replaces TH-99：实测推翻原判定\n")
	issues = o.threatBackfillIssues(p)
	if len(issues) == 0 || !strings.Contains(issues[0], "不在威胁清单") {
		t.Fatalf("幻觉 TH 引用应拦截: %v", issues)
	}
	// ⑤ extends 真实 TH + creates 新编号 + 清单外发现 → 放行；无 creates → 拦截
	_, _ = o.store.AddFinding(&store.Finding{ProjectID: p.ID, Stage: "s4",
		Title: "报名导出接口路径穿越", Severity: "高", Confidence: "疑似",
		Detail: "【清单外】判定表 C-12 之外的导出面"})
	_, _ = o.exec.WriteFile(p.ID, "deliverables/s4-漏洞清单.md",
		"# 漏洞清单\n## 威胁清单回填记录\n- extends TH-02：注入面实测进展（sqlmap 受控确证）\n")
	issues = o.threatBackfillIssues(p)
	if len(issues) == 0 || !strings.Contains(issues[0], "creates") {
		t.Fatalf("清单外发现无 creates 留痕应拦截: %v", issues)
	}
	_, _ = o.exec.WriteFile(p.ID, "deliverables/s4-漏洞清单.md",
		"# 漏洞清单\n## 威胁清单回填记录\n- extends TH-02：注入面实测进展\n- creates TH-03：导出接口路径穿越（清单外新面）\n")
	if issues := o.threatBackfillIssues(p); len(issues) != 0 {
		t.Fatalf("creates 留痕后应放行: %v", issues)
	}
}

// ---------- S4-⑨ 批次6 阈值收敛 + S5 逐目标门 ----------

func TestV640S5TargetReconGate(t *testing.T) {
	dir := t.TempDir()
	o, st := v48Orchestrator(t)
	_ = dir
	p := &store.Project{ROEAcknowledgedAt: "2026-11-22T00:00:00Z", ID: "P-V640R1",
		Target: "a.example.com\nb.example.com"}
	_ = st.SaveProject(p)
	_, _ = st.UpsertCoverage(&store.CoverageEntry{ProjectID: p.ID, Stage: "s4",
		Endpoint: "http://a.example.com/api", VulnClass: "SQL注入", Status: "vulnerable"})
	// 2 目标项目只覆盖 1 个（matched=1/missing=1）→ s4 与 s5 均应拦截（旧阈值 matched≥2 盲区）
	issues := o.deterministicGate(p, "s4")
	hit := false
	for _, iss := range issues {
		if strings.Contains(iss, "S4 分段收口对账") && strings.Contains(iss, "b.example.com") {
			hit = true
		}
	}
	if !hit {
		t.Fatalf("2 目标 matched=1 应拦截: %v", issues)
	}
	// s5 同款逐目标对账（guard 缺省 true）
	issues = o.deterministicGate(p, "s5")
	hit = false
	for _, iss := range issues {
		if strings.Contains(iss, "S5 分段收口对账") && strings.Contains(iss, "b.example.com") {
			hit = true
		}
	}
	if !hit {
		t.Fatalf("S5 逐目标门应拦截: %v", issues)
	}
	// b 目标列入待续清单 → 放行
	_, _ = o.exec.WriteFile(p.ID, "deliverables/s5-b.example.com.md",
		"# s5 待续（b.example.com）\n- b.example.com：本轮未触达，待续")
	issues = o.deterministicGate(p, "s5")
	for _, iss := range issues {
		if strings.Contains(iss, "S5 分段收口对账") {
			t.Fatalf("待续清单归宿后不应再拦: %v", issues)
		}
	}
	// guard 显式 false → S5 回退（不跑逐目标对账）
	o.cfg.Guard.EnforceS5TargetRecon = boolPtr(false)
	_, _ = o.exec.WriteFile(p.ID, "deliverables/x.md", "placeholder")
	issues = o.deterministicGate(p, "s5")
	for _, iss := range issues {
		if strings.Contains(iss, "S5 分段收口对账") {
			t.Fatalf("guard=false 应回退旧口径: %v", issues)
		}
	}
	o.cfg.Guard.EnforceS5TargetRecon = boolPtr(true)
}

func boolPtr(b bool) *bool { return &b }

// ---------- S4-② 端点表生产端契约 ----------

func TestV640S3EndpointTableContract(t *testing.T) {
	o, _ := v48Orchestrator(t)
	p := &store.Project{ROEAcknowledgedAt: "2026-11-22T00:00:00Z", ID: "P-V640EP",
		Target: "https://ep.example.com"}
	_ = o.store.SaveProject(p)
	_, _ = o.exec.WriteFile(p.ID, "deliverables/s3-筛查矩阵判定表.md", matrixTableFixture(nil, nil))
	_, _ = o.exec.WriteFile(p.ID, "deliverables/s3-威胁模型.md", "# 威胁模型\nTH-01 会话固定（P2）\n")
	plan := "# S3 测试计划\n| T-01 | 登录面 | 审批 | 窗内 |\nS2 未产出候选清单。\n"
	_, _ = o.exec.WriteFile(p.ID, "deliverables/s3-测试计划.md", plan)
	// 无端点表且无声明 → 第⑥项拦截
	issues := o.s3ClosureIssues(p)
	hit := false
	for _, is := range issues {
		if strings.Contains(is, "端点表 evidence/s3-api-endpoints.txt 缺失") {
			hit = true
		}
	}
	if !hit {
		t.Fatalf("端点表缺失且无声明应拦截: %v", issues)
	}
	// 声明形态 → 第⑥项放行
	_, _ = o.exec.WriteFile(p.ID, "deliverables/s3-测试计划.md", plan+"未产出端点表：纯内网无 API 面\n")
	for _, is := range o.s3ClosureIssues(p) {
		if strings.Contains(is, "端点表 evidence") {
			t.Fatalf("声明形态不应再拦: %v", o.s3ClosureIssues(p))
		}
	}
	// 端点表落盘（evidence/*endpoints*.txt / 行）→ 同样放行
	_, _ = o.exec.WriteFile(p.ID, "deliverables/s3-测试计划.md", plan)
	_, _ = o.exec.WriteFile(p.ID, "evidence/s3-api-endpoints.txt", "/api/login\n/api/user\n# total=2\n")
	for _, is := range o.s3ClosureIssues(p) {
		if strings.Contains(is, "端点表 evidence") {
			t.Fatalf("端点表落盘后不应再拦: %v", o.s3ClosureIssues(p))
		}
	}
	// S4 侧兜底：端点表缺失 + 无声明 → endpointMatrixIssues 拦截；有声明放行
	p2 := &store.Project{ROEAcknowledgedAt: "2026-11-22T00:00:00Z", ID: "P-V640EP2",
		Target: "https://ep2.example.com"}
	_ = o.store.SaveProject(p2)
	if issues := o.endpointMatrixIssues(p2); len(issues) == 0 || !strings.Contains(issues[0], "端点表缺失") {
		t.Fatalf("S4 侧无表无声明应拦截: %v", issues)
	}
	_, _ = o.exec.WriteFile(p2.ID, "deliverables/s3-测试计划.md", "未产出端点表：无 API 面\n")
	if issues := o.endpointMatrixIssues(p2); len(issues) != 0 {
		t.Fatalf("S4 侧声明形态应放行: %v", issues)
	}
}

// ---------- S4-⑤ S5 上下文移交项注入块 ----------

func TestV640S5HandoverContextBlock(t *testing.T) {
	o, _ := v48Orchestrator(t)
	o.heads = map[string]*Head{}
	p := &store.Project{ROEAcknowledgedAt: "2026-11-22T00:00:00Z", ID: "P-V640H3",
		Target: "https://hb.example.com"}
	_ = o.store.SaveProject(p)
	p.StageStates = map[string]*store.StageState{
		"s4": {Status: "done", V3Ready: []string{"VT-AB1C2DEF3 [ready] SQLi 批量提取"}}}
	_ = o.store.SaveProject(p)
	_, _ = o.store.AddFinding(&store.Finding{ProjectID: p.ID, Stage: "s4",
		Title: "后台登录加密协议", Severity: "中", Confidence: "确证", Detail: "前端加密",
		Route: "browser-auth"})
	out := o.buildContextPack(p, "s5")
	if !strings.Contains(out, "### S4 移交项") {
		t.Fatalf("s5 上下文应注入移交项块")
	}
	if !strings.Contains(out, "VT-AB1C2DEF3") || !strings.Contains(out, "后台登录加密协议") {
		t.Fatalf("移交项块应含 V3 条目与认证路线移交: %.400s", out)
	}
	// s4 上下文不注入（该块仅 s5）
	outS4 := o.buildContextPack(p, "s4")
	if strings.Contains(outS4, "### S4 移交项") {
		t.Fatalf("s4 上下文不应注入移交项块")
	}
	// 无移交项不注入空块
	p2 := &store.Project{ROEAcknowledgedAt: "2026-11-22T00:00:00Z", ID: "P-V640H4",
		Target: "https://hc.example.com"}
	_ = o.store.SaveProject(p2)
	if out := o.buildContextPack(p2, "s5"); strings.Contains(out, "### S4 移交项") {
		t.Fatalf("无移交项不应注入空块")
	}
}

// ---------- S4-⑧ 逐类对账表行数完整性门 ----------

func TestV640ReconTableRowCountGate(t *testing.T) {
	o, _ := v48Orchestrator(t)
	p := &store.Project{ROEAcknowledgedAt: "2026-11-22T00:00:00Z", ID: "P-V640RC",
		Target: "https://rc.example.com"}
	_ = o.store.SaveProject(p)
	_, _ = o.exec.WriteFile(p.ID, "deliverables/s3-测试计划.md",
		"# S3 测试计划\n| T-01 | 登录面 | 审批 | 窗内 |\n| T-02 | 业务面 | — | 窗内 |\n")
	_, _ = o.exec.WriteFile(p.ID, "deliverables/s3-筛查矩阵判定表.md", sixColSurfaceFixture())
	// ① 对账表缺失 → 拦截
	issues := o.planHandoverIssues(p)
	if len(issues) == 0 || !strings.Contains(issues[0], "缺少 deliverables/s4-逐类对账表.md") {
		t.Fatalf("对账表缺失应拦截: %v", issues)
	}
	// ② 对账表缺 C-08 行 → 拦截点名缺行
	incomplete := "# S4 逐类对账表\n\n| 类 | 目标 | 技能 | endpoint | 首探针 | T-xx | outcome |\n|---|---|---|---|---|---|---|\n"
	incomplete += "| C-01 登录面 | 单目标 | auth-flow-deep | /login | 文案差分 | T-01 | 已测 |\n"
	for i := 1; i <= 27; i++ {
		if i == 1 || i == 8 {
			continue
		}
		incomplete += fmt.Sprintf("| C-%02d | 单目标 | — | — | — | — | 合规豁免（无对应面） |\n", i)
	}
	_, _ = o.exec.WriteFile(p.ID, "deliverables/s4-逐类对账表.md", incomplete)
	issues = o.planHandoverIssues(p)
	if len(issues) == 0 || !strings.Contains(issues[0], "对账表缺 1 行") || !strings.Contains(issues[0], "C-08") {
		t.Fatalf("缺 C-08 行应拦截: %v", issues)
	}
	// ③ 补齐 C-08 行 → 该门放行（T-02 若仍无归宿会被 T-xx 承接门拦——本用例 VT 移交承接）
	_, _ = o.store.AddVT(&store.VerificationTask{ProjectID: p.ID, Stage: "s4",
		Title: "C-08 待判定裁决 T-02 移交", Status: "pending"})
	_, _ = o.exec.WriteFile(p.ID, "deliverables/s4-逐类对账表.md", reconTableFixture())
	for _, iss := range o.planHandoverIssues(p) {
		if strings.Contains(iss, "逐类对账表门") {
			t.Fatalf("补行后对账表门应放行: %v", o.planHandoverIssues(p))
		}
	}
}

// ---------- S4-⑩ 回环治理 ----------

func TestV640LoopbackGovernance(t *testing.T) {
	o, st := v48Orchestrator(t)
	o.heads = map[string]*Head{"s4": {ID: "s4", Name: "漏洞发现与分析", Body: "# S4"}}
	o.cfg.Engine.LoopbackMaxRuns = 3
	o.loops = map[string][]string{}
	o.loopTotal = map[string]int{}
	p := &store.Project{ROEAcknowledgedAt: "2026-11-22T00:00:00Z", ID: "P-V640LB",
		Target: "https://lb.example.com", BudgetTokens: 1000000}
	p.StageStates = map[string]*store.StageState{
		"s4": {Status: "done"}, "s5": {Status: "running"}}
	_ = st.SaveProject(p)
	// ① 重入原因随 loopback 入队写入目标阶段（call 助手走完整 dispatch 路径）
	call(t, o, p, "s5", "loopback", `{"to_stage":"s4","reason":"新攻击面：9029 边界服务"}`)
	if p.StageStates["s4"].ReentryReason == "" {
		t.Fatalf("loopback 入队应写 ReentryReason")
	}
	// ② 重入阶段上下文注入原因块
	out := o.buildContextPack(p, "s4")
	if !strings.Contains(out, "回环重入原因") || !strings.Contains(out, "9029") {
		t.Fatalf("重入上下文应注入原因块")
	}
	// ③ 额度持久化语义：消费数落库后跨实例可恢复
	o.loops[p.ID] = []string{"s4"}
	p.LoopUsed = 2
	_ = st.SaveProject(p)
	p2, _ := st.GetProject(p.ID)
	if p2.LoopUsed != 2 {
		t.Fatalf("LoopUsed 应持久化: %d", p2.LoopUsed)
	}
	// ④ 入队时额度从持久值恢复（新 orchestrator 实例 + 历史消费 2 → 第 3 次可入队、第 4 次拒绝）
	o2, _ := v48Orchestrator(t)
	o2.cfg.Engine.LoopbackMaxRuns = 3
	o2.loops = map[string][]string{}
	o2.loopTotal = map[string]int{}
	p2.StageStates["s4"].Status = "done"
	p2.StageStates["s5"].Status = "running"
	_ = st.SaveProject(p2)
	resp := call(t, o2, p2, "s5", "loopback", `{"to_stage":"s4","reason":"第三次回环"}`)
	if !strings.Contains(resp, "已触发回环") {
		t.Fatalf("历史消费 2 后第 3 次应可入队（额度从持久值恢复）: %s", resp)
	}
	resp = call(t, o2, p2, "s5", "loopback", `{"to_stage":"s4","reason":"第四次回环"}`)
	if !strings.Contains(resp, "自动回环补跑已达上限") {
		t.Fatalf("第 4 次应超额拒绝: %s", resp)
	}
}

// TestV640S5WritebackVisibleInS4Context 方案 S4-⑩④：S5-7 失败反馈环的回写条目
// （premise_failed/patched → needs_follow_up + reason 前缀）在 S4 重入上下文可见——
// 断言锁定既有覆盖矩阵关键明细块承载该数据（s4.md 回环重入规则②的执行前提）。
func TestV640S5WritebackVisibleInS4Context(t *testing.T) {
	o, st := v48Orchestrator(t)
	o.heads = map[string]*Head{"s4": {ID: "s4", Name: "漏洞发现与分析", Body: "# S4"}}
	p := &store.Project{ROEAcknowledgedAt: "2026-11-22T00:00:00Z", ID: "P-V640WB",
		Target: "https://wb.example.com"}
	p.StageStates = map[string]*store.StageState{"s4": {Status: "done"}}
	_ = st.SaveProject(p)
	// S5-7 回写形态：premise_failed → needs_follow_up + reason=precondition_missing
	_, _ = st.UpsertCoverage(&store.CoverageEntry{ProjectID: p.ID, Stage: "s5",
		Endpoint: "POST /api/transfer", VulnClass: "业务逻辑", Status: "needs_follow_up",
		Notes: "reason=precondition_missing：利用前提缺登录态，S5-2a 移交"})
	// patched 待复测 → needs_follow_up + reason=patch_pending_retest
	_, _ = st.UpsertCoverage(&store.CoverageEntry{ProjectID: p.ID, Stage: "s5",
		Endpoint: "GET /api/export", VulnClass: "SQL注入", Status: "needs_follow_up",
		Notes: "reason=patch_pending_retest：目标侧声称已修复，待窗口复测"})
	// S4 重入上下文（含回环原因）应同时呈现两条回写条目与原因前缀
	p.StageStates["s4"].ReentryReason = "新攻击面回环"
	_ = st.SaveProject(p)
	out := o.buildContextPack(p, "s4")
	if !strings.Contains(out, "reason=precondition_missing") {
		t.Fatalf("S4 重入上下文应可见 S5 premise_failed 回写条目")
	}
	if !strings.Contains(out, "reason=patch_pending_retest") {
		t.Fatalf("S4 重入上下文应可见 S5 patched 回写条目")
	}
	if !strings.Contains(out, "回环重入原因") {
		t.Fatalf("重入上下文应含回环原因块")
	}
}

// ---------- S4-⑪ 子代理工具面扩容 ----------

func TestV640SubAgentLedgerTools(t *testing.T) {
	o, _ := v48Orchestrator(t)
	defs := o.subAgentToolDefs()
	names := map[string]bool{}
	for _, d := range defs {
		names[d.Name] = true
	}
	for _, want := range []string{"record_vt", "update_vt", "record_candidate", "update_candidate"} {
		if !names[want] {
			t.Fatalf("子代理工具面应含 %s（S4-⑪）", want)
		}
	}
	for _, banned := range []string{"complete_stage", "loopback", "plan_subtasks", "request_approval"} {
		if names[banned] {
			t.Fatalf("流程状态工具 %s 不得进入子代理工具面", banned)
		}
	}
	if !strings.Contains(subAgentCharter, "record_vt") || !strings.Contains(subAgentCharter, "record_candidate") {
		t.Fatalf("子代理守则应包含台账登记纪律")
	}
}

// ---------- S4-⑫ 门禁校准 ----------

func TestV640GateCalibration(t *testing.T) {
	o, st := v48Orchestrator(t)
	// ① endpointMatrix 精确/后缀匹配：/api/user 的覆盖登记不得被 /api/user/admin 冒名命中
	p := &store.Project{ROEAcknowledgedAt: "2026-11-22T00:00:00Z", ID: "P-V640GC",
		Target: "https://gc.example.com", BudgetTokens: 1000000}
	p.StageStates = map[string]*store.StageState{"s4": {Status: "running"}}
	_ = st.SaveProject(p)
	_, _ = o.exec.WriteFile(p.ID, "evidence/s3-api-endpoints.txt", "/api/user\n/api/user/admin\n# total=2\n")
	_, _ = st.UpsertCoverage(&store.CoverageEntry{ProjectID: p.ID, Stage: "s4",
		Endpoint: "GET /api/user/admin?id=1", VulnClass: "未授权（authz-diff）",
		Status: "no_issue_found", Notes: "negative_valid"})
	issues := o.endpointMatrixIssues(p)
	if len(issues) == 0 || !strings.Contains(issues[0], "diffed=1/total=2") {
		t.Fatalf("/api/user 应为缺口（子串误命中已修）: %v", issues)
	}
	// 补 /api/user 覆盖（含查询串形态）→ 放行
	_, _ = st.UpsertCoverage(&store.CoverageEntry{ProjectID: p.ID, Stage: "s4",
		Endpoint: "GET /api/user?id=2", VulnClass: "未授权（authz-diff）",
		Status: "no_issue_found", Notes: "negative_valid"})
	issues = o.endpointMatrixIssues(p)
	if len(issues) != 0 {
		t.Fatalf("查询串形态覆盖应命中: %v", issues)
	}
	// ② G2 fail-closed：文件存在但坏 JSON → 拦截
	p2 := &store.Project{ROEAcknowledgedAt: "2026-11-22T00:00:00Z", ID: "P-V640GC2",
		Target: "https://gc2.example.com"}
	_ = st.SaveProject(p2)
	_, _ = o.exec.WriteFile(p2.ID, "checklist.json", "{items:[broken")
	issues = o.checklistCoverageIssues(p2)
	if len(issues) == 0 || !strings.Contains(issues[0], "不可解析") {
		t.Fatalf("坏 checklist.json 应 fail-closed 拦截: %v", issues)
	}
	// ③ checklist 门⑤编号空间分离：计划只引判定表 C-01（类编号）不算条目引用
	p3 := &store.Project{ROEAcknowledgedAt: "2026-11-22T00:00:00Z", ID: "P-V640GC3",
		Target: "https://gc3.example.com"}
	_ = st.SaveProject(p3)
	_, _ = o.exec.WriteFile(p3.ID, "checklist.json", `{"items":[{"id":"C1","item":"上传附件","hint":"投单页","class":"上传绕过"}]}`)
	_, _ = o.exec.WriteFile(p3.ID, "deliverables/s3-测试计划.md",
		"# 计划\n| T-01 | C-01 认证面逐类排期（引用判定表类编号）| 审批 | 窗内 |\n")
	issues = o.s3ClosureIssues(p3)
	hit := false
	for _, is := range issues {
		if strings.Contains(is, "零条目引用") {
			hit = true
		}
	}
	if !hit {
		t.Fatalf("类编号 C-01 不应算 checklist 条目引用: %v", issues)
	}
	// 引用真实条目 id C1 → 放行
	_, _ = o.exec.WriteFile(p3.ID, "deliverables/s3-测试计划.md",
		"# 计划\n| T-01 | C1 上传附件排期 | 审批 | 窗内 |\n")
	for _, is := range o.s3ClosureIssues(p3) {
		if strings.Contains(is, "零条目引用") {
			t.Fatalf("真实条目 id 引用应放行: %v", o.s3ClosureIssues(p3))
		}
	}
}

// ---------- S4-⑤⑦ guard=false 回退（方案回归清单） ----------

func TestV640HandoverAndBackfillGuardOff(t *testing.T) {
	o, st := v48Orchestrator(t)
	p := &store.Project{ROEAcknowledgedAt: "2026-11-22T00:00:00Z", ID: "P-V640GO",
		Target: "https://go.example.com"}
	_ = st.SaveProject(p)
	// S4-⑤：S4 有 V3 移交项、S5 无留痕；guard=false → 门直通
	p.StageStates = map[string]*store.StageState{
		"s4": {Status: "done", V3Ready: []string{"VT-AB1C2DEF3 [ready] SQLi 批量提取（四件套）"}}}
	_ = st.SaveProject(p)
	o.cfg.Guard.EnforceS5V3Handover = boolPtr(false)
	if issues := o.v3HandoverIssues(p); len(issues) != 0 {
		t.Fatalf("enforce_s5_v3_handover=false 应回退直通: %v", issues)
	}
	o.cfg.Guard.EnforceS5V3Handover = boolPtr(true)
	if issues := o.v3HandoverIssues(p); len(issues) == 0 {
		t.Fatalf("guard=true 应恢复拦截")
	}
	// S4-⑦：S4 交付物缺回填记录；guard=false → 门直通
	_, _ = o.exec.WriteFile(p.ID, "deliverables/s3-威胁模型.md", "# 威胁模型\nTH-01 会话固定（P2）\n")
	_, _ = o.exec.WriteFile(p.ID, "deliverables/s4-漏洞清单.md", "# 漏洞清单\n- R-01\n")
	o.cfg.Guard.EnforceTHBackfill = boolPtr(false)
	if issues := o.threatBackfillIssues(p); len(issues) != 0 {
		t.Fatalf("enforce_th_backfill=false 应回退直通: %v", issues)
	}
	o.cfg.Guard.EnforceTHBackfill = boolPtr(true)
	if issues := o.threatBackfillIssues(p); len(issues) == 0 {
		t.Fatalf("guard=true 应恢复拦截")
	}
	// S4-②：guard=false → S3 收口门⑥直通（端点表缺失且无声明）
	_, _ = o.exec.WriteFile(p.ID, "deliverables/s3-筛查矩阵判定表.md", matrixTableFixture(nil, nil))
	_, _ = o.exec.WriteFile(p.ID, "deliverables/s3-测试计划.md", "# 计划\n| T-01 | 登录面 | 审批 | 窗内 |\n")
	o.cfg.Guard.EnforceS3EndpointTable = boolPtr(false)
	for _, is := range o.s3ClosureIssues(p) {
		if strings.Contains(is, "端点表 evidence") {
			t.Fatalf("enforce_s3_endpoint_table=false 应回退直通: %v", o.s3ClosureIssues(p))
		}
	}
	o.cfg.Guard.EnforceS3EndpointTable = boolPtr(true)
	hit := false
	for _, is := range o.s3ClosureIssues(p) {
		if strings.Contains(is, "端点表 evidence") {
			hit = true
		}
	}
	if !hit {
		t.Fatalf("guard=true 应恢复拦截")
	}
}
