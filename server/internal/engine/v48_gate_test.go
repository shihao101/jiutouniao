package engine

// v4.8 批2 专项测试：M2 筛查矩阵判定表门 / M4 交付物时间一致性门 / M5 quality-pending
// 频次监控 / R7 第二层对抗假设 pass（解析+diff+VT 登记）。对应《优化方案_v4.8_通用实战增强总案》。

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"jiutouniao/internal/config"
	"jiutouniao/internal/events"
	"jiutouniao/internal/llm"
	"jiutouniao/internal/store"
)

// v48Orchestrator 批2 测试装配：exec 工作区与 cfg.DataDir 对齐（M4 门扫描需要
// listWorkspaceFiles 命中 exec 落盘的交付物），tokens 计数表初始化（R7 accountUsage）。
func v48Orchestrator(t *testing.T) (*Orchestrator, *store.Store) {
	t.Helper()
	_, st := testApprover(t)
	dir := t.TempDir()
	cfg := &config.Config{}
	cfg.ApplyDefaultsForTest()
	cfg.DataDir = dir
	o := &Orchestrator{store: st, exec: newTestExec(t, dir), bus: events.NewBus(), cfg: cfg,
		tokens: map[string]int64{}}
	return o, st
}

// matrixTableFixture 生成 27 行判定表（可选跳过某些类的判定格）。
func matrixTableFixture(omitVerdict map[int]bool, drop []int) string {
	dropped := map[int]bool{}
	for _, d := range drop {
		dropped[d] = true
	}
	var b strings.Builder
	b.WriteString("# 筛查矩阵判定表\n\n| 类 | 触发面 | 判定 | 证据 | TH |\n|---|---|---|---|---|\n")
	for i := 1; i <= 27; i++ {
		if dropped[i] {
			continue
		}
		verdict := "假设"
		if omitVerdict[i] {
			verdict = "" // 无判定格
		} else if i%5 == 0 {
			verdict = "不适用"
		} else if i%7 == 0 {
			verdict = "待判定"
		}
		if omitVerdict[i] {
			b.WriteString(fmt.Sprintf("| C-%02d | 触发面摘要 |  | 证据指针 | TH-01 |\n", i))
		} else {
			b.WriteString(fmt.Sprintf("| C-%02d | 触发面摘要 | %s | 证据指针 | TH-01 |\n", i, verdict))
		}
	}
	return b.String()
}

// M2：判定表缺失 / 缺行 / 无判定格 / 完整通过 四分支
func TestV48MatrixGate(t *testing.T) {
	o, _ := v48Orchestrator(t)
	p := &store.Project{ID: "P-V48M"}
	_ = o.store.SaveProject(p)

	// ① 判定表缺失 → 拦截
	issues := o.matrixTableIssues(p)
	if len(issues) == 0 || !strings.Contains(issues[0], "筛查矩阵判定表") {
		t.Fatalf("判定表缺失应拦截: %v", issues)
	}
	// ② 缺行 → 拦截（少 3 行）
	_, _ = o.exec.WriteFile(p.ID, "deliverables/s3-筛查矩阵判定表.md", matrixTableFixture(nil, []int{3, 14, 25}))
	issues = o.matrixTableIssues(p)
	if len(issues) == 0 || !strings.Contains(issues[0], "缺 3 行") {
		t.Fatalf("缺行应拦截: %v", issues)
	}
	// ③ 行存在但无三态判定格 → 拦截
	_, _ = o.exec.WriteFile(p.ID, "deliverables/s3-筛查矩阵判定表.md", matrixTableFixture(map[int]bool{9: true}, nil))
	issues = o.matrixTableIssues(p)
	if len(issues) == 0 || !strings.Contains(issues[0], "无三态判定格") {
		t.Fatalf("无判定格应拦截: %v", issues)
	}
	// ④ 27 行三态完整 → 通过（且收口门路径执行同结果）
	_, _ = o.exec.WriteFile(p.ID, "deliverables/s3-筛查矩阵判定表.md", matrixTableFixture(nil, nil))
	if issues := o.matrixTableIssues(p); len(issues) != 0 {
		t.Fatalf("完整判定表应通过: %v", issues)
	}
	if issues := o.deterministicGate(p, "s3"); len(issues) != 0 {
		t.Fatalf("s3 收口门对完整判定表应放行: %v", issues)
	}
	// ⑤ 缺行形态走 deterministicGate 同样拦截
	_, _ = o.exec.WriteFile(p.ID, "deliverables/s3-筛查矩阵判定表.md", matrixTableFixture(nil, []int{5}))
	if issues := o.deterministicGate(p, "s3"); len(issues) == 0 {
		t.Fatal("deterministicGate 应拦截缺行判定表")
	}
}

// M4：日期字段必须落在任务时间窗内（早于开始 / 晚于今天拦截；窗内放行；自由文本不扫）
func TestV48DateWindow(t *testing.T) {
	o, _ := v48Orchestrator(t)
	p := &store.Project{ID: "P-V48D", CreatedAt: time.Now().Add(-48 * time.Hour)}
	_ = o.store.SaveProject(p)
	today := time.Now().Format("2006-01-02")
	early := time.Now().Add(-72 * time.Hour).Format("2006-01-02")

	_, _ = o.exec.WriteFile(p.ID, "deliverables/s3-威胁清单.md",
		fmt.Sprintf("# 威胁清单\n测试日期: %s\n报告日期：%s\n历史参考：CVE-2021-44228 于 2021-12-10 披露\n", early, today))
	issues := o.deliverableDateIssues(p)
	if len(issues) != 1 || !strings.Contains(issues[0], "早于任务开始") {
		t.Fatalf("早于任务开始的日期字段应拦截且不误伤 CVE 历史日期: %v", issues)
	}
	// 未来日期
	_, _ = o.exec.WriteFile(p.ID, "deliverables/s3-威胁清单.md", "报告日期: 2099-01-01")
	issues = o.deliverableDateIssues(p)
	if len(issues) != 1 || !strings.Contains(issues[0], "晚于今天") {
		t.Fatalf("未来日期字段应拦截: %v", issues)
	}
	// 窗内（今天）→ 放行
	_, _ = o.exec.WriteFile(p.ID, "deliverables/s3-威胁清单.md", fmt.Sprintf("测试日期: %s\n任务时间: %s", today, today))
	if issues := o.deliverableDateIssues(p); len(issues) != 0 {
		t.Fatalf("窗内日期字段应放行: %v", issues)
	}
}

// M5：反思门失败频次 → 上下文包注入修复提示
func TestV48ReflectFailureHint(t *testing.T) {
	o, _ := v48Orchestrator(t)
	o.heads = map[string]*Head{}
	p := &store.Project{ID: "P-V48Q", Target: "a.example.com", StageStates: map[string]*store.StageState{
		"s4": {Status: "done", ReflectFailures: 2},
	}}
	out := o.buildContextPack(p, "s5")
	if !strings.Contains(out, "v4.8 M5") || !strings.Contains(out, "修复提示") {
		t.Fatalf("反思门高失败应注入 M5 修复提示: %s", out)
	}
	// 低频次（1 次）且总数 <3 → 不注入
	p.StageStates["s4"].ReflectFailures = 1
	out = o.buildContextPack(p, "s5")
	if strings.Contains(out, "v4.8 M5") {
		t.Fatalf("低频失败不应注入 M5 提示")
	}
	// 总数 ≥3（跨阶段）→ 注入
	p.StageStates["s5"] = &store.StageState{Status: "done", ReflectFailures: 2}
	out = o.buildContextPack(p, "s6")
	if !strings.Contains(out, "v4.8 M5") {
		t.Fatalf("跨阶段累计 ≥3 应注入 M5 提示")
	}
}

// R7：对抗假设解析（剥离标签/证据尾巴，跳过标题与表格线，上限 10 条）
func TestV48AdversarialParse(t *testing.T) {
	text := "## 对抗假设\n- [假设] 管理后台 /admin 弱口令可达 | 证据指针: evidence/s2.txt | 类: C-01\n" +
		"- [假设] 图床接口可 SSRF 打内网元数据 | 证据指针: 纯推测（upload URL 语义未实测）| 类: C-12\n" +
		"* 无凭证注册接口可批量造号（C-06）\n" +
		"| C-13 | 表格行应跳过 |\n" +
		"# 标题应跳过\n"
	hyps := parseAdversarialHypotheses(text)
	if len(hyps) != 3 {
		t.Fatalf("应解析出 3 条假设: %+v", hyps)
	}
	if hyps[0].content != "管理后台 /admin 弱口令可达" {
		t.Fatalf("应剥离标签与证据尾巴: %q", hyps[0].content)
	}
	if !strings.Contains(hyps[0].raw, "evidence/s2.txt") {
		t.Fatalf("raw 应保留原始行: %q", hyps[0].raw)
	}
}

// normForKey：全半角归一 + 标点丢弃（R7 diff 与 B1 判重精神一致）
func TestV48NormForKey(t *testing.T) {
	a := normForKey("Admin 后台（弱口令）！")
	b := normForKey("admin 后台弱口令")
	if a != b {
		t.Fatalf("全半角/标点归一应等键: %q vs %q", a, b)
	}
	long := normForKey(strings.Repeat("长", 60))
	if len([]rune(long)) != 48 {
		t.Fatalf("应截断 48 字符: %d", len([]rune(long)))
	}
}

// fakeLLM 固定回复的桩客户端（R7 pass 全链路测试用）。
type fakeLLM struct{ reply string }

func (f *fakeLLM) Chat(_ context.Context, _ string, _ []llm.Message, _ []llm.ToolDef, _ float32, _ int) (llm.Message, llm.Usage, error) {
	return llm.Message{Role: "assistant", Content: f.reply}, llm.Usage{TotalTokens: 10}, nil
}

// R7 全链路：独立会话 → diff → 差异项 VT（pending），主清单命中的不重复登记
func TestV48AdversarialPassVT(t *testing.T) {
	o, st := v48Orchestrator(t)
	o.llm = &fakeLLM{reply: "- [假设] 图床接口可 SSRF 打内网元数据 | 证据指针: evidence/s2.txt | 类: C-12\n" +
		"- [假设] 管理后台弱口令可达 | 证据指针: evidence/s2.txt | 类: C-01\n"}
	p := &store.Project{ID: "P-V48R", CreatedAt: time.Now()}
	_ = st.SaveProject(p)
	// 主清单已含「管理后台弱口令」→ 该条应判 covered
	_, _ = o.exec.WriteFile(p.ID, "deliverables/s3-筛查矩阵判定表.md", matrixTableFixture(nil, nil))
	_, _ = o.exec.WriteFile(p.ID, "deliverables/s3-威胁清单.md", "# 威胁清单\nTH-01 管理后台弱口令可达（C-01）")

	note, deliv := o.adversarialAssumptionPass(context.Background(), p, "s3")
	if !strings.Contains(note, "对抗假设 pass") || deliv != "deliverables/s3-对抗假设审查.md" {
		t.Fatalf("R7 附注/交付物异常: note=%q deliv=%q", note, deliv)
	}
	if !strings.Contains(note, "1 条已自动 record_vt") {
		t.Fatalf("差异项应为 1 条: %s", note)
	}
	vts, _ := st.ListVTs(p.ID)
	if len(vts) != 1 || vts[0].Status != "pending" || !strings.HasPrefix(vts[0].Title, "[R7对抗]") {
		t.Fatalf("差异项应登记 pending VT: %+v", vts)
	}
	raw, _ := o.exec.ReadFile(p.ID, deliv)
	if !strings.Contains(raw, "R7") || !strings.Contains(raw, "差异项") {
		t.Fatalf("对抗假设审查交付物缺内容: %s", raw)
	}
	// 时间线留痕
	tl, _ := st.ListTimeline(p.ID)
	found := false
	for _, ev := range tl {
		if ev.Event == "R7 对抗假设" {
			found = true
		}
	}
	if !found {
		t.Fatal("应留痕 R7 时间线事件")
	}
}

// R7 非阻塞：LLM 失败不报错、不拦收口，只留痕
func TestV48AdversarialPassFailOpen(t *testing.T) {
	o, st := v48Orchestrator(t)
	o.llm = &fakeErrLLM{}
	p := &store.Project{ID: "P-V48S"}
	_ = st.SaveProject(p)
	note, deliv := o.adversarialAssumptionPass(context.Background(), p, "s3")
	if note != "" || deliv != "" {
		t.Fatalf("LLM 失败应非阻塞返回空: %q %q", note, deliv)
	}
	tl, _ := st.ListTimeline(p.ID)
	found := false
	for _, ev := range tl {
		if ev.Event == "R7 对抗假设" && strings.Contains(ev.Detail, "失败") {
			found = true
		}
	}
	if !found {
		t.Fatal("失败应留痕时间线")
	}
}

// fakeErrLLM 恒返错的桩客户端。
type fakeErrLLM struct{}

func (f *fakeErrLLM) Chat(_ context.Context, _ string, _ []llm.Message, _ []llm.ToolDef, _ float32, _ int) (llm.Message, llm.Usage, error) {
	return llm.Message{}, llm.Usage{}, fmt.Errorf("provider unavailable")
}

// W4：身份获取六轨编排门（无凭证+登录面 → 逐轨 VT 留痕）
func TestV48IdentityTracks(t *testing.T) {
	o, st := v48Orchestrator(t)
	p := &store.Project{ID: "P-V48W"}
	_ = st.SaveProject(p)
	_, _ = st.AddAsset(&store.Asset{ProjectID: p.ID, Type: "登录面", Value: "http://t/admin/login", Detail: "管理后台登录"})

	// ① 无凭证+登录面+无 VT → 拦截（缺六轨）
	issues := o.identityTrackIssues(p, "s4")
	if len(issues) == 0 || !strings.Contains(issues[0], "六轨未逐轨") {
		t.Fatalf("六轨未登记应拦截: %v", issues)
	}
	// ② 六轨全量登记 + [W4-DG] 降级评估 → 放行（v5.6.1：DG 四通道机械门）
	for i := 1; i <= 6; i++ {
		_, _ = st.AddVT(&store.VerificationTask{ProjectID: p.ID, Stage: "s4",
			Title: fmt.Sprintf("[W4-L%d] 轨道 %d 尝试", i, i), Status: "executed"})
	}
	if issues := o.identityTrackIssues(p, "s4"); len(issues) == 0 || !strings.Contains(issues[0], "[W4-DG]") {
		t.Fatalf("六轨闭环但缺 DG 评估应拦截: %v", issues)
	}
	_, _ = st.AddVT(&store.VerificationTask{ProjectID: p.ID, Stage: "s4",
		Title: "[W4-DG] 降级四通道评估", Status: "executed"})
	if issues := o.identityTrackIssues(p, "s4"); len(issues) != 0 {
		t.Fatalf("六轨+DG 全量登记应放行: %v", issues)
	}
	// ③ 已获身份（verified session loot）但无 VT 留痕 → 拦截首轨留痕（新项目避免清库）
	o3, st3 := v48Orchestrator(t)
	p3 := &store.Project{ID: "P-V48W2"}
	_ = st3.SaveProject(p3)
	_, _ = st3.AddAsset(&store.Asset{ProjectID: p3.ID, Type: "登录面", Value: "http://t/admin/login"})
	_, _ = st3.AddLoot(&store.LootRecord{ProjectID: p3.ID, Type: "session", Target: "t", Masked: "adm***23", Verified: "verified"})
	issues = o3.identityTrackIssues(p3, "s4")
	if len(issues) == 0 || !strings.Contains(issues[0], "首轨命中也应 record_vt") {
		t.Fatalf("已获身份无轨留痕应拦截: %v", issues)
	}
	// ④ 已获身份+首轨 VT 留痕 → 放行
	_, _ = st3.AddVT(&store.VerificationTask{ProjectID: p3.ID, Stage: "s4", Title: "[W4-L1] 注册面命中", Status: "executed"})
	if issues := o3.identityTrackIssues(p3, "s4"); len(issues) != 0 {
		t.Fatalf("已获身份+首轨留痕应放行: %v", issues)
	}
	// ⑤ 无登录面 → 不适用（不编造）
	o2, st2 := v48Orchestrator(t)
	p2 := &store.Project{ID: "P-V48X"}
	_ = st2.SaveProject(p2)
	if issues := o2.identityTrackIssues(p2, "s4"); len(issues) != 0 {
		t.Fatalf("无登录面应不适用: %v", issues)
	}
	// ⑥ 有凭证 → 不适用
	p.AuthInfo = "user/pass"
	if issues := o.identityTrackIssues(p, "s4"); len(issues) != 0 {
		t.Fatalf("有凭证应不适用: %v", issues)
	}
}

// W4：上下文包编排提示（无凭证+登录面 s4 注入）
func TestV48W4ContextHint(t *testing.T) {
	o, st := v48Orchestrator(t)
	o.heads = map[string]*Head{}
	p := &store.Project{ID: "P-V48Y", Target: "a.example.com"}
	_ = st.SaveProject(p)
	_, _ = st.AddAsset(&store.Asset{ProjectID: p.ID, Type: "登录面", Value: "http://t/login"})
	out := o.buildContextPack(p, "s4")
	// v5.1.1：注入文本升级——L1 评估轨 + 身份索取闭环语义锁定
	if !strings.Contains(out, "身份获取编排（v4.8 W4·v5.1 修订）") || !strings.Contains(out, "[W4-L1]") {
		t.Fatalf("无凭证+登录面应注入 W4 编排提示")
	}
	if !strings.Contains(out, "L1 为评估轨") || !strings.Contains(out, "身份索取闭环") {
		t.Fatalf("W4 编排提示应含 v5.1 L1 评估轨与索取闭环语义: %s", out[:min(len(out), 600)])
	}
	out5 := o.buildContextPack(p, "s5")
	if strings.Contains(out5, "身份获取编排（v4.8 W4）") {
		t.Fatalf("s5 不应注入 W4 编排提示")
	}
}

// W5：行为预算器（批量配额/空壳即停/冷却协议）
func TestV48BatchBudget(t *testing.T) {
	o, st := v48Orchestrator(t)
	p := &store.Project{ID: "P-V48B"}
	_ = st.SaveProject(p)
	cmd := "nuclei -u http://t -t cves/"

	// ① 前三次批量放行（配额内）
	for i := 0; i < 3; i++ {
		if note := o.batchBudgetGate(p, "s4", cmd); note != "" {
			t.Fatalf("配额内批量应放行: %s", note)
		}
	}
	// ② 空壳即停：3 次空壳结果后拒绝下一批
	for i := 0; i < 3; i++ {
		o.batchResultFeedback(p, "s4", cmd, "000 timeout", 1)
	}
	if note := o.batchBudgetGate(p, "s4", cmd); note == "" || !strings.Contains(note, "空壳即停") {
		t.Fatalf("空壳连击应拒绝: %q", note)
	}
	// ③ 配额超限 → 冷却协议（默认 12/10min）
	o2, st2 := v48Orchestrator(t)
	p2 := &store.Project{ID: "P-V48B2"}
	_ = st2.SaveProject(p2)
	for i := 0; i < o2.cfg.Engine.BatchQuotaPer10Min; i++ {
		if note := o2.batchBudgetGate(p2, "s4", cmd); note != "" {
			t.Fatalf("配额内第 %d 次应放行: %s", i, note)
		}
	}
	note := o2.batchBudgetGate(p2, "s4", cmd)
	if note == "" || !strings.Contains(note, "冷却") {
		t.Fatalf("超限应进入冷却: %q", note)
	}
	// ④ 冷却期内再拒
	if note := o2.batchBudgetGate(p2, "s4", cmd); note == "" || !strings.Contains(note, "冷却协议") {
		t.Fatalf("冷却期内应拒绝: %q", note)
	}
	// ⑤ 非批量命令恒放行
	if note := o.batchBudgetGate(p, "s4", "cat evidence/s2-endpoints.txt"); note != "" {
		t.Fatalf("非批量应恒放行: %s", note)
	}
	// ⑥ 有产出批量反馈附基线自检提醒；空壳反馈附空壳提示
	o3, st3 := v48Orchestrator(t)
	p3 := &store.Project{ID: "P-V48B3"}
	_ = st3.SaveProject(p3)
	if f := o3.batchResultFeedback(p3, "s4", cmd, strings.Repeat("hit", 100), 0); !strings.Contains(f, "批间基线自检") {
		t.Fatalf("有产出批量应附基线自检提醒: %q", f)
	}
	if f := o3.batchResultFeedback(p3, "s4", "arjun -u http://t", "", 1); !strings.Contains(f, "空壳") {
		t.Fatalf("空壳结果应附提示: %q", f)
	}
}
