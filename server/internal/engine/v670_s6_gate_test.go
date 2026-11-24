package engine

// v6.7.0 S6 修复方案回归测试（docs/修复方案_S6后渗透阶段补全_v6.7.0_20261123.md）：
// S6-① s6 纳入反思 PASS 确定性门名单（C27 收口件/C28 在正常收口路径生效）。
// S6-② S6→S7「S6 移交项」注入块 + 提示级四元组核对。
// S6-③ S5-⑩ 上传落点指针双轨（文件名轨扩展 + 内容特征兜轨 + s8 排除）。
// S6-④ s6 逐目标对账门（guard enforce_s6_target_recon / s5- 语料排除 / 零命中提示级）。
// S6-⑥ s6 命名交付物条件核验（hasFoothold / 权限矩阵+横向路径图 / N/A 兜底）。
// S6-⑨ 回环 to_stage 上游校验。
// 后续小节随实施追加。

import (
	"context"
	"fmt"
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

// writeC27Table 写一份 27 行全处置态的《27类收口对账表》（matrixClassRe 行首 | C-xx + 豁免词）。
func writeC27Table(t *testing.T, o *Orchestrator, projectID string) {
	t.Helper()
	var b strings.Builder
	b.WriteString("# 27类收口对账表\n\n| 编号 | 类 | S3 判定 | S6 收口处置 | 测试单元与结论 | 证据指针 |\n|---|---|---|---|---|---|\n")
	for i := 1; i <= matrixTotalClasses; i++ {
		fmt.Fprintf(&b, "| C-%02d | 类%02d | 假设 | 已测 | 测试单元 TU-%02d 结论阴性有效 | evidence/s4/tu-%02d.txt |\n", i, i, i, i)
	}
	if _, err := o.exec.WriteFile(projectID, "deliverables/s6-27类收口对账表.md", b.String()); err != nil {
		t.Fatal(err)
	}
}

// TestV670S6C27HappyPath S6-①：反思 PASS 正常收口路径上，存在判定表的项目缺
// 《27类收口对账表》必须被确定性门拦截（修复前 s6 不在 PASS 名单，该门只在
// 三振/反思失败/代收口路径生效——24 判定表项目仅 2 产出对账表的实证缺口）。
func TestV670S6C27HappyPath(t *testing.T) {
	o, _ := v48Orchestrator(t)
	p := &store.Project{ROEAcknowledgedAt: "2026-11-23T00:00:00Z", ID: "P-V670-C27",
		Target: "a.example.com"}
	_ = o.store.SaveProject(p)
	// 存在 S3 判定表（reconciliationTableIssues 的触发前提）
	if _, err := o.exec.WriteFile(p.ID, "deliverables/s3-筛查矩阵判定表.md",
		"# 筛查矩阵判定表\n| C-01 | 假设 | 触发面 | 证据 |\n"); err != nil {
		t.Fatal(err)
	}
	// 未产出对账表 → 拦截（修复前返回 nil——happy path 零机械校验）
	issues := o.deterministicGate(p, "s6")
	hit := false
	for _, iss := range issues {
		if strings.Contains(iss, "C27 收口件") && strings.Contains(iss, "s6-27类收口对账表.md") {
			hit = true
		}
	}
	if !hit {
		t.Fatalf("存在判定表而缺对账表应在 s6 确定性门拦截: %v", issues)
	}
	// 补齐 27 行全处置态对账表 → C27 收口件放行
	writeC27Table(t, o, p.ID)
	issues = o.deterministicGate(p, "s6")
	for _, iss := range issues {
		if strings.Contains(iss, "C27 收口件") {
			t.Errorf("27 行齐备后 C27 收口件门应放行: %v", issues)
		}
	}
}

// TestV670S6C27NoJudgeTableExempt S6-①：无判定表（旧项目/轻量项目）走豁免路径零影响。
func TestV670S6C27NoJudgeTableExempt(t *testing.T) {
	o, _ := v48Orchestrator(t)
	p := &store.Project{ROEAcknowledgedAt: "2026-11-23T00:00:00Z", ID: "P-V670-NOJT",
		Target: "a.example.com"}
	_ = o.store.SaveProject(p)
	issues := o.deterministicGate(p, "s6")
	for _, iss := range issues {
		if strings.Contains(iss, "C27 收口件") {
			t.Errorf("无判定表项目不应要求对账表: %v", issues)
		}
	}
}

// TestV670S6C27PartialRows S6-①：对账表缺行处置态 → 逐行拦截文案点名缺失编号。
func TestV670S6C27PartialRows(t *testing.T) {
	o, _ := v48Orchestrator(t)
	p := &store.Project{ROEAcknowledgedAt: "2026-11-23T00:00:00Z", ID: "P-V670-PART",
		Target: "a.example.com"}
	_ = o.store.SaveProject(p)
	if _, err := o.exec.WriteFile(p.ID, "deliverables/s3-筛查矩阵判定表.md", "# 判定表\n"); err != nil {
		t.Fatal(err)
	}
	// 27 行缺 1 行处置词（C-02 行无豁免标记）
	var b strings.Builder
	b.WriteString("| 编号 | 类 | 处置 | 证据 |\n|---|---|---|---|\n")
	for i := 1; i <= matrixTotalClasses; i++ {
		if i == 2 {
			fmt.Fprintf(&b, "| C-%02d | 类%02d | （待补） | — |\n", i, i)
			continue
		}
		fmt.Fprintf(&b, "| C-%02d | 类%02d | 已测 | evidence/x.txt |\n", i, i)
	}
	if _, err := o.exec.WriteFile(p.ID, "deliverables/s6-27类收口对账表.md", b.String()); err != nil {
		t.Fatal(err)
	}
	issues := o.deterministicGate(p, "s6")
	hit := false
	for _, iss := range issues {
		if strings.Contains(iss, "C27 收口件") && strings.Contains(iss, "C-02") {
			hit = true
		}
	}
	if !hit {
		t.Fatalf("缺处置态行应被点名（C-02）: %v", issues)
	}
}

// TestV670S6E1Backstop S6-① 修复后效果联动验证：s6 阶段确证发现含否定性断言但无 claims →
// E1 收口兜底随 PASS 名单在 s6 生效（修复前 happy path 零机械校验，该形态漏放）。
func TestV670S6E1Backstop(t *testing.T) {
	o, st := v48Orchestrator(t)
	p := &store.Project{ROEAcknowledgedAt: "2026-11-23T00:00:00Z", ID: "P-V670-E1", Target: "a.example.com"}
	_ = st.SaveProject(p)
	_, _ = st.AddFinding(&store.Finding{ProjectID: p.ID, Stage: "s6",
		Title: "内网无可达横向面（确证）", Detail: "全部端口无响应，不存在横向可能", Confidence: "确证", Severity: "中"})
	hit := false
	for _, iss := range o.deterministicGate(p, "s6") {
		if strings.Contains(iss, "claims 判据串") {
			hit = true
		}
	}
	if !hit {
		t.Fatalf("s6 确证否定断言无 claims 应被 E1 收口兜底拦截")
	}
}

// TestV670S6OpenCandidateGate S6-①：C28 候选归档门随 PASS 名单在 s6 正常路径生效。
func TestV670S6OpenCandidateGate(t *testing.T) {
	o, _ := v48Orchestrator(t)
	p := &store.Project{ROEAcknowledgedAt: "2026-11-23T00:00:00Z", ID: "P-V670-CD",
		Target: "a.example.com"}
	_ = o.store.SaveProject(p)
	if _, err := o.store.AddCandidate(&store.Candidate{ProjectID: p.ID, Stage: "s6",
		Title: "疑似未授权接口", EvidenceRef: "evidence/x.txt"}); err != nil {
		t.Fatal(err)
	}
	issues := o.deterministicGate(p, "s6")
	hit := false
	for _, iss := range issues {
		if strings.Contains(iss, "C28 候选归档门") {
			hit = true
		}
	}
	if !hit {
		t.Fatalf("open 候选应在 s6 收口被 C28 门拦截: %v", issues)
	}
}

// ---------- S6-③ 上传落点指针双轨 ----------

// TestV670S6UploadPointerDualTrack S6-③：落点记录在「文件名不含上传」的文件中时，内容特征
// 兜轨仍应命中（修复前 48 实跑项目 0/48 命中）；s8- 前缀文件不得误命中；样本行摘录在场。
func TestV670S6UploadPointerDualTrack(t *testing.T) {
	o, _ := v48Orchestrator(t)
	p := &store.Project{ROEAcknowledgedAt: "2026-11-23T00:00:00Z", ID: "P-V670-UP",
		Target: "a.example.com", StageStates: map[string]*store.StageState{"s5": {Status: "done"}}}
	_ = o.store.SaveProject(p)
	// 真实形态：落点四元组记在《需人工清理清单》（文件名不含「上传」）
	if _, err := o.exec.WriteFile(p.ID, "deliverables/s5-需人工清理清单.md",
		"# 需人工清理清单\n\n- 探针文件 /var/www/probe.txt ｜ 指纹 JT-probe-2026 ｜ 建议清理命令 rm /var/www/probe.txt ｜ 验证命令 ls /var/www/probe.txt（应不存在）\n"); err != nil {
		t.Fatal(err)
	}
	// 跨阶段误命中源：s8 文件名含「上传」
	if _, err := o.exec.WriteFile(p.ID, "deliverables/s8-补充测试-上传面验证.md", "# s8 补充\n"); err != nil {
		t.Fatal(err)
	}
	out := o.buildContextPack(p, "s6")
	if !strings.Contains(out, "[上传落点]") || !strings.Contains(out, "s5-需人工清理清单.md") {
		t.Fatalf("内容特征兜轨应命中 s5-需人工清理清单.md:\n%s", out)
	}
	if !strings.Contains(out, "建议清理命令 rm /var/www/probe.txt") {
		t.Errorf("四元组登记行样本应摘录在场")
	}
	for _, ln := range strings.Split(out, "\n") {
		if strings.Contains(ln, "[上传落点]") && strings.Contains(ln, "s8-") {
			t.Errorf("s8- 前缀文件不应被落点指针误命中: %s", ln)
		}
	}
	// 文件名轨：独立清单文件命中且不再重复列内容兜轨
	if _, err := o.exec.WriteFile(p.ID, "deliverables/s5-上传文件记录清单.md",
		"# 上传文件记录清单\n- /var/www/shell.php ｜ 指纹 a1b2c3 ｜ 建议清理命令 rm ｜ 验证命令 ls\n"); err != nil {
		t.Fatal(err)
	}
	out = o.buildContextPack(p, "s6")
	if strings.Count(out, "[上传落点]") != 1 {
		t.Errorf("两条轨命中去重后应只有一行上传落点指针")
	}
	// 无任何四元组记录 → 零占位不报错
	o2, _ := v48Orchestrator(t)
	p2 := &store.Project{ROEAcknowledgedAt: "2026-11-23T00:00:00Z", ID: "P-V670-UP2", Target: "b.example.com"}
	_ = o2.store.SaveProject(p2)
	out2 := o2.buildContextPack(p2, "s6")
	if strings.Contains(out2, "[上传落点]") {
		t.Errorf("无落点记录不应输出上传落点指针")
	}
}

// ---------- S6-② S6→S7 移交块 ----------

// TestV670S7HandoverBlock S6-②：s6 交付物存在时，s7 上下文注入「S6 移交项」块——
// 指针分四类在场、持久化四元组登记行提取在场、存量移交项摘要在场；无 s6 交付物零占位。
func TestV670S7HandoverBlock(t *testing.T) {
	o, _ := v48Orchestrator(t)
	p := &store.Project{ROEAcknowledgedAt: "2026-11-23T00:00:00Z", ID: "P-V670-S7H",
		Target: "a.example.com\nb.example.com"}
	_ = o.store.SaveProject(p)
	_, _ = o.exec.WriteFile(p.ID, "deliverables/s6-权限矩阵.md", "# 权限矩阵\n- a.example.com web01：www-data\n")
	_, _ = o.exec.WriteFile(p.ID, "deliverables/s6-横向路径图.md", "# 横向路径图\nweb01 → db01（凭据复用）\n")
	_, _ = o.exec.WriteFile(p.ID, "deliverables/s6-存量持久化痕迹排查.md",
		"# 存量持久化痕迹排查\n\n## 登记\n- /var/spool/cron/root ｜ 指纹 legacy-cron-01 ｜ 位置 /var/spool/cron/root ｜ 疑似第三方遗留（需人工清理，只登记不处置）\n- web01:/home/ubuntu/.ssh/authorized_keys ｜ 位置 authorized_keys ｜ 指纹 legacy-key-02 ｜ 建议清理命令 sed -i '/legacy-key-02/d' ｜ 验证命令 grep -c legacy-key-02（应为 0）\n")
	out := o.buildContextPack(p, "s7")
	if !strings.Contains(out, "### S6 移交项") {
		t.Fatalf("s7 上下文应注入 S6 移交项块:\n%s", out)
	}
	for _, want := range []string{"[权限矩阵]", "[横向路径图]", "[存量持久化痕迹排查]", "[S6 持久化登记]", "[S6 存量移交]", "建议清理命令 sed -i"} {
		if !strings.Contains(out, want) {
			t.Errorf("S6 移交项块缺 %s", want)
		}
	}
	// 多目标项目：b.example.com 的登记行带 @目标 标签（本夹具登记行未含目标串，全局无标签——只验证块结构）
	// 无 s6 交付物项目 → 零占位
	o2, _ := v48Orchestrator(t)
	p2 := &store.Project{ROEAcknowledgedAt: "2026-11-23T00:00:00Z", ID: "P-V670-S7H2", Target: "c.example.com"}
	_ = o2.store.SaveProject(p2)
	out2 := o2.buildContextPack(p2, "s7")
	if strings.Contains(out2, "### S6 移交项") {
		t.Errorf("无 s6 交付物不应输出 S6 移交项块")
	}
}

// TestV670S7HandoverTargetTagging S6-② 方案测试④：多目标项目登记行含目标串 → 带 @目标
// 标签（tagHandoverTarget 要求条目以 [ 开头打标——S6-② 全面核对轮修正的拼装顺序）；单目标零标签。
func TestV670S7HandoverTargetTagging(t *testing.T) {
	o, st := v48Orchestrator(t)
	p := &store.Project{ROEAcknowledgedAt: "2026-11-23T00:00:00Z", ID: "P-V670-TAG",
		Target: "a.example.com\nb.example.com"}
	_ = st.SaveProject(p)
	_, _ = o.exec.WriteFile(p.ID, "deliverables/s6-持久化记录.md",
		"# 持久化记录\n\n- 路径 b.example.com:/tmp/persist.sh ｜ 指纹 ft-b1 ｜ 建议清理命令 rm /tmp/persist.sh ｜ 验证命令 ls /tmp/persist.sh\n")
	out := o.buildContextPack(p, "s7")
	if !strings.Contains(out, "[S6 持久化登记@b.example.com]") {
		t.Fatalf("多目标项目 b.example.com 登记行应带 @目标 标签:\n%s", out)
	}
	// 单目标：不打标零变化
	o2, st2 := v48Orchestrator(t)
	p2 := &store.Project{ROEAcknowledgedAt: "2026-11-23T00:00:00Z", ID: "P-V670-TAG2",
		Target: "b.example.com"}
	_ = st2.SaveProject(p2)
	_, _ = o2.exec.WriteFile(p2.ID, "deliverables/s6-持久化记录.md",
		"# 持久化记录\n\n- 路径 /tmp/persist.sh ｜ 指纹 ft-b1 ｜ 建议清理命令 rm ｜ 验证命令 ls\n")
	out2 := o2.buildContextPack(p2, "s7")
	if strings.Contains(out2, "[S6 持久化登记@") {
		t.Errorf("单目标项目不应打 @目标 标签")
	}
}

// TestV670S7FourTupleHint S6-②：s6 交付物存在残缺四元组登记行（有位置+指纹、缺建议清理命令
// 或验证命令）→ S7 收口输出提示级 log（不拦截）；完整行不提示。
func TestV670S7FourTupleHint(t *testing.T) {
	o, _ := v48Orchestrator(t)
	p := &store.Project{ROEAcknowledgedAt: "2026-11-23T00:00:00Z", ID: "P-V670-FT",
		Target: "a.example.com", StageStates: map[string]*store.StageState{}}
	_ = o.store.SaveProject(p)
	_, _ = o.exec.WriteFile(p.ID, "deliverables/s6-持久化记录.md",
		"# 持久化记录\n\n- 路径 /tmp/persist.sh ｜ 指纹 ft-01 ｜ 建议清理命令 rm /tmp/persist.sh ｜ 验证命令 ls /tmp/persist.sh\n- 路径 /tmp/persist2.sh ｜ 指纹 ft-02 ｜（残缺：清理与验证字段待补齐）\n")
	_ = o.deterministicGate(p, "s7")
	streams, _, err := o.store.ListStream(p.ID, 0)
	if err != nil {
		t.Fatal(err)
	}
	hint := false
	for _, s := range streams {
		if strings.Contains(s.Text, "四元组核对提示") && strings.Contains(s.Text, "s6-持久化记录.md") {
			hint = true
		}
	}
	if !hint {
		t.Fatalf("残缺四元组应输出提示级 log")
	}
	// 提示级：不进拦截 issues
	issues := o.deterministicGate(p, "s7")
	for _, iss := range issues {
		if strings.Contains(iss, "四元组核对提示") {
			t.Errorf("四元组核对应为提示级不拦截: %v", issues)
		}
	}
	// 全部完整行 → 新项目不出提示
	o2, _ := v48Orchestrator(t)
	p2 := &store.Project{ROEAcknowledgedAt: "2026-11-23T00:00:00Z", ID: "P-V670-FT2", Target: "b.example.com"}
	_ = o2.store.SaveProject(p2)
	_, _ = o2.exec.WriteFile(p2.ID, "deliverables/s6-持久化记录.md",
		"# 持久化记录\n\n- 路径 /tmp/persist.sh ｜ 指纹 ft-01 ｜ 建议清理命令 rm /tmp/persist.sh ｜ 验证命令 ls /tmp/persist.sh\n")
	_ = o2.deterministicGate(p2, "s7")
	streams2, _, _ := o2.store.ListStream(p2.ID, 0)
	for _, s := range streams2 {
		if strings.Contains(s.Text, "四元组核对提示") {
			t.Errorf("完整四元组不应出提示: %s", truncateText(s.Text, 100))
		}
	}
}

// ---------- S6-④ s6 逐目标对账门 ----------

// TestV670S6TargetRecon S6-④：多目标项目 s6 只测 A 目标 → B 被拦；B 的留痕只存在于
// s4-/s5- 分组产物 → 仍拦（s5- 语料排除生效，修复前借上游留痕放行）；B 有 s6 自身留痕 → 放行。
func TestV670S6TargetRecon(t *testing.T) {
	o, _ := v48Orchestrator(t)
	p := &store.Project{ROEAcknowledgedAt: "2026-11-23T00:00:00Z", ID: "P-V670-RECON",
		Target: "a.example.com\nb.example.com"}
	_ = o.store.SaveProject(p)
	// 上游分组产物含两目标（s4-/s5- 按 S4-9/S5 门强制产出的形态）
	_, _ = o.exec.WriteFile(p.ID, "deliverables/s4-分组结论.md", "# s4\n- a.example.com 已测\n- b.example.com 已测\n")
	_, _ = o.exec.WriteFile(p.ID, "deliverables/s5-分组结论.md", "# s5\n- a.example.com 已利用\n- b.example.com 已利用\n")
	// s6 只覆盖 A
	_, _ = o.store.UpsertCoverage(&store.CoverageEntry{ProjectID: p.ID, Stage: "s6",
		Endpoint: "http://a.example.com/internal", VulnClass: "横向移动", Status: "vulnerable"})
	issues := o.deterministicGate(p, "s6")
	hit := false
	for _, iss := range issues {
		if strings.Contains(iss, "S6 分段收口对账") && strings.Contains(iss, "b.example.com") {
			hit = true
		}
	}
	if !hit {
		t.Fatalf("S6 逐目标门应拦 b.example.com（不得借 s4-/s5- 语料放行）: %v", issues)
	}
	// B 有 s6 自身留痕（覆盖登记）→ 放行
	_, _ = o.store.UpsertCoverage(&store.CoverageEntry{ProjectID: p.ID, Stage: "s6",
		Endpoint: "http://b.example.com/internal", VulnClass: "横向移动", Status: "no_issue_found"})
	issues = o.deterministicGate(p, "s6")
	for _, iss := range issues {
		if strings.Contains(iss, "S6 分段收口对账") {
			t.Errorf("B 有 s6 留痕后应放行: %v", issues)
		}
	}
}

// TestV670S6TargetReconZeroHitHint S6-④：CIDR 目标语料不含目标串 → 提示级不拦（与 s5 同口径）。
func TestV670S6TargetReconZeroHitHint(t *testing.T) {
	o, _ := v48Orchestrator(t)
	p := &store.Project{ROEAcknowledgedAt: "2026-11-23T00:00:00Z", ID: "P-V670-RECON0",
		Target: "10.0.0.0/24\n10.1.0.0/24"}
	_ = o.store.SaveProject(p)
	_, _ = o.store.UpsertCoverage(&store.CoverageEntry{ProjectID: p.ID, Stage: "s6",
		Endpoint: "web01", VulnClass: "横向", Status: "no_issue_found"})
	issues := o.deterministicGate(p, "s6")
	for _, iss := range issues {
		if strings.Contains(iss, "S6 分段收口对账") {
			t.Errorf("零命中不应拦截（提示级）: %v", issues)
		}
	}
	streams, _, _ := o.store.ListStream(p.ID, 0)
	hint := false
	for _, s := range streams {
		if strings.Contains(s.Text, "S6 逐目标对账零命中") {
			hint = true
		}
	}
	if !hint {
		t.Errorf("零命中应输出提示级留痕（stream log）")
	}
}

// ---------- S6-⑥ 命名交付物条件核验 ----------

// TestV670S6TargetReconDisabled S6-④ 方案测试④⑤：单目标/PerTargetRounds=0 门不触发；
// guard enforce_s6_target_recon=false 门关闭。
func TestV670S6TargetReconDisabled(t *testing.T) {
	// 单目标项目 → 门不触发（targets==1）
	o, st := v48Orchestrator(t)
	p := &store.Project{ROEAcknowledgedAt: "2026-11-23T00:00:00Z", ID: "P-V670-TR1", Target: "a.example.com"}
	_ = st.SaveProject(p)
	_, _ = st.UpsertCoverage(&store.CoverageEntry{ProjectID: p.ID, Stage: "s6", Endpoint: "http://a/imp", VulnClass: "横向", Status: "vulnerable"})
	for _, iss := range o.deterministicGate(p, "s6") {
		if strings.Contains(iss, "S6 分段收口对账") {
			t.Errorf("单目标项目不应触发逐目标门: %v", iss)
		}
	}
	// 多目标但 perTargetRounds=0（禁用自适应）→ 门不触发
	o2, st2 := v48Orchestrator(t)
	o2.cfg.Engine.PerTargetRounds = 0
	p2 := &store.Project{ROEAcknowledgedAt: "2026-11-23T00:00:00Z", ID: "P-V670-TR0",
		Target: "a.example.com\nb.example.com"}
	_ = st2.SaveProject(p2)
	_, _ = st2.UpsertCoverage(&store.CoverageEntry{ProjectID: p2.ID, Stage: "s6", Endpoint: "http://a/imp", VulnClass: "横向", Status: "vulnerable"})
	for _, iss := range o2.deterministicGate(p2, "s6") {
		if strings.Contains(iss, "S6 分段收口对账") {
			t.Errorf("perTarget=0 应禁用逐目标门: %v", iss)
		}
	}
	// 多目标 + guard=false → 门关闭
	o3, st3 := v48Orchestrator(t)
	off := false
	o3.cfg.Guard.EnforceS6TargetRecon = &off
	p3 := &store.Project{ROEAcknowledgedAt: "2026-11-23T00:00:00Z", ID: "P-V670-TRG",
		Target: "a.example.com\nb.example.com"}
	_ = st3.SaveProject(p3)
	_, _ = st3.UpsertCoverage(&store.CoverageEntry{ProjectID: p3.ID, Stage: "s6", Endpoint: "http://a/imp", VulnClass: "横向", Status: "vulnerable"})
	for _, iss := range o3.deterministicGate(p3, "s6") {
		if strings.Contains(iss, "S6 分段收口对账") {
			t.Errorf("guard=false 应关闭逐目标门: %v", iss)
		}
	}
}

// TestV670S6DeliverablesGate S6-⑥：有立足点信号（s5 RCE 发现）缺权限矩阵/横向路径图 → 拦截；
// 补产出（含合并文件名形态）或写 N/A 声明 → 放行；无立足点项目零要求。
func TestV670S6DeliverablesGate(t *testing.T) {
	o, _ := v48Orchestrator(t)
	p := &store.Project{ROEAcknowledgedAt: "2026-11-23T00:00:00Z", ID: "P-V670-DLV",
		Target: "a.example.com"}
	_ = o.store.SaveProject(p)
	_, _ = o.store.AddFinding(&store.Finding{ProjectID: p.ID, Stage: "s5",
		Title: "命令执行（RCE）确证", Detail: "无害回显证明", Confidence: "确证", Severity: "高"})
	// 无 s6 交付物 → 拦截并点名两件
	issues := o.deterministicGate(p, "s6")
	hitM, hitL := false, false
	for _, iss := range issues {
		if strings.Contains(iss, "S6-⑥ 交付物核验") && strings.Contains(iss, "《权限矩阵》") {
			hitM = true
		}
		if strings.Contains(iss, "S6-⑥ 交付物核验") && strings.Contains(iss, "《横向路径图》") {
			hitL = true
		}
	}
	if !hitM || !hitL {
		t.Fatalf("有立足点缺两件交付物应被点名: %v", issues)
	}
	// 合并文件名形态（实跑最常见命名）→ 放行
	_, _ = o.exec.WriteFile(p.ID, "deliverables/s6-权限矩阵与横向路径图.md", "# 权限矩阵与横向路径图\n")
	issues = o.deterministicGate(p, "s6")
	for _, iss := range issues {
		if strings.Contains(iss, "S6-⑥ 交付物核验") {
			t.Errorf("合并文件名形态应放行: %v", issues)
		}
	}
	// N/A 声明兜底 → 放行（另一项目：只有 N/A 声明，无权限矩阵）
	o2, _ := v48Orchestrator(t)
	p2 := &store.Project{ROEAcknowledgedAt: "2026-11-23T00:00:00Z", ID: "P-V670-DLV2", Target: "b.example.com"}
	_ = o2.store.SaveProject(p2)
	_, _ = o2.exec.WriteFile(p2.ID, "deliverables/s6-不适用声明.md", "# 不适用声明\n依据：S5 收口无立足点信号，横向面不适用。\n")
	issues = o2.deterministicGate(p2, "s6")
	for _, iss := range issues {
		if strings.Contains(iss, "S6-⑥ 交付物核验") {
			t.Errorf("N/A 声明应放行: %v", issues)
		}
	}
	// 无立足点项目（无 finding/loot/初始访问）→ 零要求（即使有 s6- 不含关键词的交付物也不拦）
	o3, _ := v48Orchestrator(t)
	p3 := &store.Project{ROEAcknowledgedAt: "2026-11-23T00:00:00Z", ID: "P-V670-DLV3", Target: "c.example.com"}
	_ = o3.store.SaveProject(p3)
	_, _ = o3.store.AddFinding(&store.Finding{ProjectID: p3.ID, Stage: "s5",
		Title: "存储型 XSS", Detail: "无立足点信号", Confidence: "确证", Severity: "中"})
	issues = o3.deterministicGate(p3, "s6")
	for _, iss := range issues {
		if strings.Contains(iss, "S6-⑥ 交付物核验") {
			t.Errorf("无立足点项目不应要求命名交付物: %v", issues)
		}
	}
}

// TestV670S6DeliverablesGuardOff S6-⑥ 方案测试⑤：guard enforce_s6_deliverables=false 门关闭。
func TestV670S6DeliverablesGuardOff(t *testing.T) {
	o, st := v48Orchestrator(t)
	off := false
	o.cfg.Guard.EnforceS6Deliverables = &off
	p := &store.Project{ROEAcknowledgedAt: "2026-11-23T00:00:00Z", ID: "P-V670-DLVOFF", Target: "a.example.com"}
	_ = st.SaveProject(p)
	_, _ = st.AddFinding(&store.Finding{ProjectID: p.ID, Stage: "s5",
		Title: "命令执行（RCE）确证", Detail: "无害回显证明", Confidence: "确证", Severity: "高"})
	for _, iss := range o.deterministicGate(p, "s6") {
		if strings.Contains(iss, "S6-⑥ 交付物核验") {
			t.Errorf("guard=false 应关闭交付物核验门: %v", iss)
		}
	}
}

// ---------- S6-⑤ 反思门 S6 专项核查节 ----------

// TestV670S6ReflectSection S6-⑤：reflectStage(s6) 真实构建的审查提示词含 S6 专项核查节
//（S6-4/S6-6 红线 + 承接留痕 + 拓扑引用四问），与 s3/s7/s8 专项节同机制。
func TestV670S6ReflectSection(t *testing.T) {
	o, st := v48Orchestrator(t)
	p := &store.Project{ROEAcknowledgedAt: "2026-11-23T00:00:00Z", ID: "P-V670-RF",
		Target: "a.example.com"}
	_ = st.SaveProject(p)
	cc := &captureClient{}
	o.llm = cc
	if _, _, err := o.reflectStage(context.Background(), p, "s6"); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"S6 专项核查（后渗透红线",
		"四元组登记", "即 BLOCK",
		"只发现、只登记、不处置",
		"S5 移交项", "零承接且交付物无留痕即 BLOCK",
		"《拓扑重建》最新版",
	} {
		if !strings.Contains(cc.prompt, want) {
			t.Errorf("reflectStage(s6) 提示词缺 %q", want)
		}
	}
	// s5 阶段不受影响（节仅 s6 注入）
	cc5 := &captureClient{}
	o.llm = cc5
	if _, _, err := o.reflectStage(context.Background(), p, "s5"); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(cc5.prompt, "S6 专项核查") {
		t.Errorf("s5 阶段不应注入 S6 专项核查节")
	}
}

// ---------- S6-⑦ 上下文在场性补块 ----------

// TestV670S6ContextBlocks S6-⑦：s6 上下文注入 L2 审批工单状态块、扇出提示、K5 心跳产物
//（存在→状态在场；缺失→缺失提示）、原语图指针（存在→缺口数在场）；s7 无 K5/原语图块。
func TestV670S6ContextBlocks(t *testing.T) {
	o, st := v48Orchestrator(t)
	p := &store.Project{ROEAcknowledgedAt: "2026-11-23T00:00:00Z", ID: "P-V670-CTX",
		Target: "a.example.com"}
	_ = st.SaveProject(p)
	_, _ = st.AddApproval(&store.Approval{ProjectID: p.ID, Stage: "s6", Risk: "L2",
		Status: "approved", Action: "【提权】S6-1 SUID 枚举验证"})
	_, _ = o.exec.WriteFile(p.ID, "evidence/channel-status.json", `{"status":"ok","last":"2026-11-23T09:00:00Z"}`)
	_, _ = o.exec.WriteFile(p.ID, "deliverables/primitive-chains.md", "# 原语图\n## 缺口\n- 缺口：EXEC→PII 凑链缺 WRITE 环\n")
	out := o.buildContextPack(p, "s6")
	for _, want := range []string{
		"### 审批工单状态",
		"【提权】S6-1 SUID 枚举验证",
		"⚡ 并行扇出提示（S6 横向）",
		"📡 K5 通道心跳产物",
		"🧩 原语图缺口",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("s6 上下文缺 %q", want)
		}
	}
	// K5 心跳产物缺失 → 缺失提示（时间阈值难满足时至少验证无 panic、有产物时路径已覆盖）
	// s7 阶段不注入 K5/原语图块（s6 专属）
	out7 := o.buildContextPack(p, "s7")
	if strings.Contains(out7, "🧩 原语图缺口") || strings.Contains(out7, "📡 K5 通道心跳产物") {
		t.Errorf("s7 阶段不应注入 K5/原语图专属块")
	}
	// s4 阶段同样不注入（S6-⑦ 方案测试⑤：s4/s5 既有行为不变）
	out4 := o.buildContextPack(p, "s4")
	if strings.Contains(out4, "🧩 原语图缺口") || strings.Contains(out4, "📡 K5 通道心跳产物") {
		t.Errorf("s4 阶段不应注入 K5/原语图专属块")
	}
}

// TestV670S6K5MissingHint S6-⑦ 方案测试③缺失态：无 channel-status.json 且跨阶段空闲超限
// → 显式缺失提示（与 K5-lite 时间维度提醒互补）；s4 阶段同条件不出缺失提示（s6 专属）。
func TestV670S6K5MissingHint(t *testing.T) {
	o, st := v48Orchestrator(t)
	p := &store.Project{ROEAcknowledgedAt: "2026-11-23T00:00:00Z", ID: "P-V670-K5M", Target: "a.example.com",
		StageStates: map[string]*store.StageState{"s5": {Status: "done", EndedAt: time.Now().Add(-2 * time.Hour).Format(time.RFC3339)}}}
	_ = st.SaveProject(p)
	out := o.buildContextPack(p, "s6")
	if !strings.Contains(out, "K5 心跳产物缺失") {
		t.Errorf("心跳产物缺失且空闲超限应输出缺失提示:\n%s", out)
	}
	// 心跳产物存在 → 不出缺失提示（走在场摘要）
	_, _ = o.exec.WriteFile(p.ID, "evidence/channel-status.json", `{"status":"ok"}`)
	out = o.buildContextPack(p, "s6")
	if strings.Contains(out, "K5 心跳产物缺失") || !strings.Contains(out, "📡 K5 通道心跳产物") {
		t.Errorf("产物存在应走在场摘要而非缺失提示")
	}
	// s4 阶段不注入该块
	out4 := o.buildContextPack(p, "s4")
	if strings.Contains(out4, "K5 心跳产物缺失") {
		t.Errorf("s4 阶段不应注入 K5 缺失提示（s6 专属）")
	}
}

// TestV670LoopbackOverBudget S6-⑨ 方案测试③：额度内 3 次放行后，第 4 次超额显式拒绝
//（留痕 + 不改状态——v5.5.0 方案 D 既有语义不变）。
func TestV670LoopbackOverBudget(t *testing.T) {
	o, st := v550Orchestrator(t)
	states := map[string]*store.StageState{}
	for _, sid := range []string{"s1", "s2", "s3", "s4", "s5", "s6", "s7", "s8"} {
		states[sid] = &store.StageState{Status: "done"}
	}
	p := &store.Project{ROEAcknowledgedAt: "2026-11-23T00:00:00Z", ID: "P-V670-LBOV", StageStates: states}
	_ = st.SaveProject(p)
	for i := 0; i < 3; i++ {
		res := o.dispatch(context.Background(), p, "s6", llm.ToolCall{Name: "loopback",
			Arguments: `{"to_stage":"s4","reason":"r"}`})
		if !strings.Contains(res, "已触发回环") {
			t.Fatalf("第 %d 次额度内应放行: %s", i+1, res)
		}
	}
	res := o.dispatch(context.Background(), p, "s6", llm.ToolCall{Name: "loopback",
		Arguments: `{"to_stage":"s2","reason":"r"}`})
	if !strings.Contains(res, "自动回环补跑已达上限") {
		t.Fatalf("第 4 次应超额拒绝: %s", res)
	}
	if len(o.loops["P-V670-LBOV"]) != 3 {
		t.Errorf("超额请求不应入队: %v", o.loops["P-V670-LBOV"])
	}
	tl, _ := st.ListTimeline(p.ID)
	over := false
	for _, ev := range tl {
		if strings.Contains(ev.Event, "回环超额拒绝") {
			over = true
		}
	}
	if !over {
		t.Errorf("超额拒绝应留痕时间线")
	}
}

// TestV670S6ThreeGatePathsUnchanged S6-① 方案测试⑤（源码级）：三振降级/反思失败/auto_close
// 代收口三条既有路径对 s6 的 deterministicGate 调用保持无条件全阶段口径（防回归——有人把
// s6 分支改成仅 happy path 或仅非 happy path 即被此测试捕获）。
func TestV670S6ThreeGatePathsUnchanged(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "server/internal/engine/orchestrator.go"))
	if err != nil {
		t.Skipf("仓库文件不可达: %v", err)
	}
	code := string(raw)
	for _, call := range []string{
		"gateIssues := o.deterministicGate(p, stageID)",                  // auto_close 代收口（v5.1.3 修复①b）
		"if issues := o.deterministicGate(p, stageID); len(issues) > 0 {", // 三振降级 + 反思 PASS 名单
		"issues := o.deterministicGate(p, stageID)",                      // 反思 LLM 三连失败
	} {
		if !strings.Contains(code, call) {
			t.Errorf("deterministicGate 调用点缺失（三条既有路径防回归）: %s", call)
		}
	}
}

// ---------- v6.7.0 历史项目回放（方案验收节：不写库 dry-run deterministicGate） ----------

// TestV670S6ReplayHistoricalProjects 环境依赖测试（需 /tmp/v66-closure/jiutouniao.db 副本，
// CI 缺席自动跳过——与 TestV66ReplayHistoricalProjects 同款装配）：对全部实跑项目回放
// S6-① C27 收口件门与 S6-③ 落点指针，验证新门对存量数据的行为与拦截预期。
func TestV670S6ReplayHistoricalProjects(t *testing.T) {
	if _, err := os.Stat("/tmp/v66-closure/jiutouniao.db"); err != nil {
		t.Skip("回放库副本不存在（/tmp/v66-closure），跳过环境回放")
	}
	cfg := &config.Config{}
	cfg.ApplyDefaultsForTest()
	cfg.DataDir = "/root/jiutouniao/projects" // 交付物/证据读原工作区（只读 dry-run）
	st, err := store.Open(backfillDir())
	if err != nil {
		t.Skipf("回放库打开失败（容器持锁或副本缺失）: %v", err)
	}
	defer st.Close()
	gf, gh, gm, gr, gs := config.DefaultGuard()
	exec, err := tools.NewExecutor(cfg.DataDir, 10, 102400, struct {
		Forbidden, HighRisk, MedRisk, ReadOnly, Sensitive []string
	}{gf, gh, gm, gr, gs})
	if err != nil {
		t.Fatal(err)
	}
	o := &Orchestrator{store: st, exec: exec, bus: events.NewBus(), cfg: cfg,
		heads: map[string]*Head{}, running: map[string]context.CancelFunc{},
		tokens: map[string]int64{}, inputs: map[string][]string{}, loops: map[string][]string{},
		liveP: map[string]*store.Project{}, batchStats: map[string]*batchBudgetState{}}
	ps, err := st.ListProjects()
	if err != nil {
		t.Fatal(err)
	}
	s6done, withJudge, withTable, c27Intercept, exemptOK := 0, 0, 0, 0, 0
	uploadHits := 0
	for _, p := range ps {
		s6 := p.StageStates["s6"]
		if s6 == nil || s6.Status != "done" {
			continue
		}
		s6done++
		_, judgeErr := exec.ReadFile(p.ID, "deliverables/s3-筛查矩阵判定表.md")
		_, tableErr := exec.ReadFile(p.ID, "deliverables/s6-27类收口对账表.md")
		hasJudge := judgeErr == nil
		hasTable := tableErr == nil
		if hasJudge {
			withJudge++
		}
		if hasTable {
			withTable++
		}
		issues := o.deterministicGate(p, "s6")
		c27Hit := false
		for _, iss := range issues {
			if strings.Contains(iss, "C27 收口件") {
				c27Hit = true
			}
		}
		// 方案验收断言：判定表在 + 对账表缺 → 必拦；对账表在 → 不拦（豁免/无判定表不计）
		if hasJudge && !hasTable && !c27Hit {
			t.Errorf("回放 %s：有判定表无对账表应被 C27 门拦截", p.ID)
		}
		if hasJudge && !hasTable && c27Hit {
			c27Intercept++
		}
		if hasJudge && hasTable && !c27Hit {
			exemptOK++
		}
		// S6-③ 回放：真实落点记录（s5-需人工清理清单.md 四元组）经内容兜轨命中
		out := o.buildContextPack(p, "s6")
		if strings.Contains(out, "[上传落点]") {
			uploadHits++
		}
	}
	t.Logf("S6 回放统计：s6 done=%d，有判定表=%d，有对账表=%d，C27 拦截=%d，对账表齐放行=%d，落点指针命中=%d",
		s6done, withJudge, withTable, c27Intercept, exemptOK, uploadHits)
	// 方案验收预期（实跑统计）：判定表项目远多于对账表项目——修复后应出现实质拦截量
	if c27Intercept == 0 && withJudge > withTable {
		t.Errorf("有判定表（%d）多于有对账表（%d）但拦截为 0——C27 门在回放中未生效", withJudge, withTable)
	}
}

// ---------- S6-⑨ 回环上游校验 ----------

// TestV670LoopbackUpstreamOnly S6-⑨：s6 → 下游（s7/s8）/自身被拒并留痕；s6 → 上游（s2/s4）
// 放行入队；超额路径行为不变。
func TestV670LoopbackUpstreamOnly(t *testing.T) {
	o, st := v550Orchestrator(t)
	states := map[string]*store.StageState{}
	for _, sid := range []string{"s1", "s2", "s3", "s4", "s5", "s6", "s7", "s8"} {
		states[sid] = &store.StageState{Status: "done"}
	}
	p := &store.Project{ROEAcknowledgedAt: "2026-11-23T00:00:00Z", ID: "P-V670-LB", StageStates: states}
	_ = st.SaveProject(p)
	// 下游回环拒绝
	res := o.dispatch(context.Background(), p, "s6", llm.ToolCall{Name: "loopback",
		Arguments: `{"to_stage":"s7","reason":"t"}`})
	if !strings.Contains(res, "回环目标非法") {
		t.Fatalf("下游回环应被拒绝: %s", res)
	}
	// 自身回环拒绝
	res = o.dispatch(context.Background(), p, "s6", llm.ToolCall{Name: "loopback",
		Arguments: `{"to_stage":"s6","reason":"t"}`})
	if !strings.Contains(res, "回环目标非法") {
		t.Fatalf("自身回环应被拒绝: %s", res)
	}
	// 上游回环放行
	res = o.dispatch(context.Background(), p, "s6", llm.ToolCall{Name: "loopback",
		Arguments: `{"to_stage":"s4","reason":"新攻击面需要漏洞发现级测试"}`})
	if !strings.Contains(res, "已触发回环") {
		t.Fatalf("上游回环应放行: %s", res)
	}
	if len(o.loops["P-V670-LB"]) != 1 || o.loops["P-V670-LB"][0] != "s4" {
		t.Fatalf("回环队列应含 s4: %v", o.loops["P-V670-LB"])
	}
	// 非法请求留痕（2 条拒绝 + 未执行状态不变）
	tl, _ := st.ListTimeline(p.ID)
	illegal := 0
	for _, ev := range tl {
		if strings.Contains(ev.Event, "回环目标非法") {
			illegal++
		}
	}
	if illegal != 2 {
		t.Errorf("两条非法回环应各留痕一条: %d", illegal)
	}
}
