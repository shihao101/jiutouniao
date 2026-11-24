package engine

// v6.8.2 核对轮回归：S5→S7 直通路径（用户创建项目未勾选 post_exploit，s6 skipped）——
// ①S7 上下文完整接收 S5 产物（s6-skipped 标注/上传落点兜底/V3 清点块/战利品）
// ②s7 收口对未清点 V3Ready 的提示级核对（零处置 → 提示；清点映射留痕 → 不再提示）
// ③deterministicGate(s7) 在 skipped 路径不崩溃不误拦。

import (
	"strings"
	"testing"

	"jiutouniao/internal/store"
)

func newSkippedProject(t *testing.T, o *Orchestrator, id string) *store.Project {
	p := &store.Project{ROEAcknowledgedAt: "2026-11-23T00:00:00Z", ID: id,
		Target: "a.example.com", PostExploit: false}
	_ = o.store.SaveProject(p)
	p.StageStates = map[string]*store.StageState{
		"s5": {Status: "done",
			Summary:  "[测试范围] a.example.com → [关键结果] V5-1 默认凭据确证",
			V3Ready:  []string{"sqlmap 四件套批量提取 a.example.com"},
			V3L2:     []string{"AP-77 已批 sqlmap --dump 未投递"}},
		"s6": {Status: "skipped", Summary: "后渗透未勾选（创建时用户决策）：提权/横向/权限维持/云逃逸/存量排查整段跳过；如需执行可在阶段流水线手动重跑 s6"},
	}
	_ = o.store.SaveProject(p)
	return p
}

func TestV682S5ToS7SkippedPathContext(t *testing.T) {
	o, _ := v48Orchestrator(t)
	p := newSkippedProject(t, o, "P-V682-SKIP")
	// S5 产物：《上传文件记录清单》（s6-skipped 时 S7-③ 兜底是唯一结构化入口）+ verified 战利品
	if _, err := o.exec.WriteFile(p.ID, "deliverables/s5-上传文件记录清单.md",
		"# 上传文件记录清单\n| 路径 | 指纹 | 建议清理命令 | 验证命令 |\n|---|---|---|---|\n| /app/jt_probe.txt | md5:ab12 | rm /app/jt_probe.txt | ls /app/jt_probe.txt |"); err != nil {
		t.Fatal(err)
	}
	_, _ = o.store.AddLoot(&store.LootRecord{ProjectID: p.ID, Stage: "s5", Type: "credential",
		Target: "a.example.com", Masked: "adm***23", Source: "sourcemap", Verified: "verified"})

	ctx := o.buildContextPack(p, "s7")
	for _, want := range []string{
		"S6 后渗透未执行",              // v6.8.1 范围标注块（s6-skipped 专属）
		"S5 上传落点",               // S7-③ 兜底指针（s6-skipped 唯一结构化入口）
		"就绪移交清点（v6.8.0 S7-⑤",   // 全阶段 V3 清点块
		"[s5 就绪未执行] sqlmap 四件套", // S5 V3Ready 在场
		"[s5 已批未用] AP-77",       // S5 V3L2 在场
		"adm***23",                // verified 战利品通用块
	} {
		if !strings.Contains(ctx, want) {
			t.Errorf("S6-skipped 路径 S7 上下文缺少 %q", want)
		}
	}
	// s7 收口门在 skipped 路径正常执行（不崩溃、无误拦本场景）
	for _, iss := range o.deterministicGate(p, "s7") {
		if strings.Contains(iss, "就绪移交清点提示") {
			t.Errorf("清点提示应为 log 提示级，不得进拦截 issues: %v", iss)
		}
	}
}

func TestV682S7V3ReadyHint(t *testing.T) {
	o, _ := v48Orchestrator(t)
	p := newSkippedProject(t, o, "P-V682-HINT")
	// 零处置 → 提示出现（log）
	_ = o.deterministicGate(p, "s7")
	streams, cursor, _ := o.store.ListStream(p.ID, 0)
	hint := false
	for _, srec := range streams {
		if strings.Contains(srec.Text, "就绪移交清点提示") {
			hint = true
		}
	}
	if !hint {
		t.Fatalf("未清点 V3Ready 应输出清点提示（stream log）")
	}
	// s7 清点映射留痕（s7- 交付物引用条目正文）→ 不再新增提示
	if _, err := o.exec.WriteFile(p.ID, "deliverables/s7-清点映射.md",
		"# S7 清点映射\n- sqlmap 四件套批量提取 a.example.com → 显式移交（待续清单）\n- AP-77 已批 sqlmap --dump 未投递 → 申报放弃（ROE 禁 dump）"); err != nil {
		t.Fatal(err)
	}
	_ = o.deterministicGate(p, "s7")
	streams2, _, _ := o.store.ListStream(p.ID, cursor)
	for _, srec := range streams2 {
		if strings.Contains(srec.Text, "就绪移交清点提示") {
			t.Errorf("s7 清点映射留痕后不应再新增提示")
		}
	}
}
