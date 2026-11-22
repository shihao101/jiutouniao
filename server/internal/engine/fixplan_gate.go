package engine

// fixplan_gate.go v6.0.1（fix-plan 20261122 审计修复）：
// P2/P3/P5/P6 收口确定性门 + P7 模型生效记录。全部为引擎级机械对账，
// 只拦截"无留痕"，不推断测试质量、不自动放行、不改变 production_safe/审批语义。

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"jiutouniao/internal/llm"
	"jiutouniao/internal/store"
)

// ---------- P3 · C27 类级处置门（S3 判定行 → S4/S5 投递对账） ----------

// matrixVerdictNeedRe 判定行内假设/待判定识别（不适用行无需 S4 投递）。
// 注意：不能用 matrixVerdictRe 匹配后仍判「假设」——待判定行是双假设并列，同样需要投递或豁免。
func matrixRowNeedsWork(line string) bool {
	return strings.Contains(line, "假设") || strings.Contains(line, "待判定")
}

// exemptTokenRe 显式豁免/已测标记（C27 对账表行内必须出现的处置词——结构化小节而非自由文本）。
var exemptTokenRe = regexp.MustCompile(`(已测|已投递|不适用|no_credentials|production_safe_write_prohibited|environment_unreachable|环境不可达|合规豁免)`)

// classDispositionIssues v6.0.1 C27（建议编号 S4-10，S4/S5 类级处置门）：
// M2 只校验判定表 27 行存在与三态合法，不校验"假设/待判定"类是否真被投递——
// 实证审计：18 个假设类仅约 12 类有测试单元，6 类静默跳过且交付层不可见。
// 本门要求每个假设/待判定类至少一项留痕：
//  1. coverage/VT/候选/发现文本中出现该 C 编号（强留痕：结构化记录引用）；
//  2. 交付物（含对账表）中出现该 C 编号且同行为处置词（已测/合规豁免/环境不可达等）。
// 解析失败不猜类别清单（交由 M2 在 s3 拦截）；存储读取失败按既有降级纪律留痕放行。
func (o *Orchestrator) classDispositionIssues(p *store.Project, stageID string) []string {
	raw, err := o.exec.ReadFile(p.ID, "deliverables/s3-筛查矩阵判定表.md")
	if err != nil {
		return nil // 无判定表（旧项目/mock）：M2 在 s3 收口已拦截，此处不重复报
	}
	need := map[string]bool{}
	for _, line := range strings.Split(raw, "\n") {
		if m := matrixClassRe.FindStringSubmatch(line); m != nil && matrixRowNeedsWork(line) {
			need[m[1]] = true
		}
	}
	if len(need) == 0 {
		return nil
	}
	// 强语料：结构化记录（coverage/VT/候选/发现）——C 编号出现即视为有投递关联
	var sb strings.Builder
	if cov, cerr := o.store.ListCoverage(p.ID); cerr == nil {
		for _, c := range cov {
			fmt.Fprintf(&sb, "%s\x00%s\x00%s\x00%s\x00", c.Endpoint, c.Param, c.VulnClass, c.Notes)
		}
	}
	if vts, verr := o.store.ListVTs(p.ID); verr == nil {
		for _, t := range vts {
			fmt.Fprintf(&sb, "%s\x00%s\x00%s\x00%s\x00", t.Title, t.Note, t.StartConditions, t.ResultRef)
		}
	}
	if cands, cerr := o.store.ListCandidates(p.ID); cerr == nil {
		for _, c := range cands {
			fmt.Fprintf(&sb, "%s\x00%s\x00%s\x00%s\x00", c.Title, c.Target, c.Reason, c.DispositionRef)
		}
	}
	if fs, ferr := o.store.ListFindings(p.ID); ferr == nil {
		for _, f := range fs {
			fmt.Fprintf(&sb, "%s\x00%s\x00", f.Title, f.Detail)
		}
	}
	strong := sb.String()
	// 弱语料：交付物逐行——C 编号与处置词同行（对账表为 markdown 表，一行一类）才算留痕
	handled := map[string]bool{}
	for id := range need {
		if strings.Contains(strong, id) {
			handled[id] = true
			continue
		}
	}
	for _, line := range strings.Split(o.deliverablesText(p.ID), "\n") {
		if m := matrixClassRe.FindStringSubmatch(line); m != nil && need[m[1]] && exemptTokenRe.MatchString(line) {
			handled[m[1]] = true
		}
	}
	var missing []string
	for id := range need {
		if !handled[id] {
			missing = append(missing, id)
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		return []string{fmt.Sprintf(
			"v6.0.1 C27 类级处置门：%d/%d 个假设/待判定类无任何投递留痕（%s）——三选一补齐后重新收口：①update_coverage 引用 C 编号（Endpoint/Notes）②record_vt（title/启动条件含 C 编号）③写 deliverables/s6-27类收口对账表.md 该行为「已测/合规豁免（no_credentials|production_safe_write_prohibited|environment_unreachable + 依据）/环境不可达」+ 证据指针。禁止静默跳过（实证：某任务 6/18 假设类零测试单元）",
			len(missing), len(need), truncateText(strings.Join(missing, ","), 140))}
	}
	return nil
}

// reconciliationTableIssues v6.0.1 C27 收口件（S6）：存在判定表的项目，
// S6 收口时必须已产出《27类收口对账表》且 27 行逐行有处置态——类级闭环落到交付物，
// S8 报告直接承接（产出缺失=类级对账从未显式收口）。
func (o *Orchestrator) reconciliationTableIssues(p *store.Project) []string {
	if _, err := o.exec.ReadFile(p.ID, "deliverables/s3-筛查矩阵判定表.md"); err != nil {
		return nil // 无判定表（旧项目/mock）不要求对账表
	}
	raw, err := o.exec.ReadFile(p.ID, "deliverables/s6-27类收口对账表.md")
	if err != nil {
		return []string{"v6.0.1 C27 收口件：缺少 deliverables/s6-27类收口对账表.md——按判定表 27 行逐行产出对账表（已测（附测试单元+证据指针）/合规豁免（依据枚举）/环境不可达（原因）），S8 报告承接"}
	}
	found := map[string]bool{}
	for _, line := range strings.Split(raw, "\n") {
		if m := matrixClassRe.FindStringSubmatch(line); m != nil && exemptTokenRe.MatchString(line) {
			found[m[1]] = true
		}
	}
	var missing []string
	for i := 1; i <= matrixTotalClasses; i++ {
		if id := fmt.Sprintf("C-%02d", i); !found[id] {
			missing = append(missing, id)
		}
	}
	if len(missing) > 0 {
		return []string{fmt.Sprintf("v6.0.1 C27 收口件：对账表 %d 行缺处置态（%s）——每行 C 编号须同行标注「已测/合规豁免/环境不可达」之一并附证据指针",
			len(missing), truncateText(strings.Join(missing, ","), 140))}
	}
	return nil
}

// ---------- P5 · C28 候选归档门 ----------

// openCandidateIssues v6.0.1 C28（建议编号 S5-10）：阶段收口时不得存在 open 候选——
// 「待评估」悬空 = 责任真空（实证 GetCaptchaImg 案）。三态归档：finding（附 F- 编号）/
// vt（附 VT- 编号与启动条件）/ excluded（附证据与理由）。
func (o *Orchestrator) openCandidateIssues(p *store.Project) []string {
	cands, err := o.store.ListCandidates(p.ID)
	if err != nil {
		return nil // 存储读取失败：按门降级纪律告警放行，不伪造"无候选"
	}
	var open []string
	for _, c := range cands {
		if c.Disposition == "" || c.Disposition == "open" {
			open = append(open, c.ID+"「"+truncateText(c.Title, 36)+"」")
		}
	}
	if len(open) == 0 {
		return nil
	}
	return []string{fmt.Sprintf(
		"v6.0.1 C28 候选归档门：%d 个候选仍为 open（%s）——update_candidate 三选一归位：finding（附发现编号）/ vt（附 VT 编号+启动条件）/ excluded（附证据与理由）；禁止「待评估」悬空进报告",
		len(open), truncateText(strings.Join(open, "、"), 160))}
}

// ---------- P2 · C31 后台作业零产出/超时对账门 ----------

// incompleteBatchIssues v6.0.1 C31：killed（超时终止）或近零产出的后台作业，收口时必须
// 有留痕（coverage/VT/交付物任一引用 job id）——被截杀的扫描不得洗白成阴性结论
//（实证：nuclei 整批 >5min 零产出被标 inconclusive 后 misconfig 面实质漏测；v4.6 E2 曾
// 同类事故：被杀扫描 0 findings 被写成"0 命中干净"）。
func (o *Orchestrator) incompleteBatchIssues(p *store.Project) []string {
	jobs := o.exec.IncompleteAsyncJobs(p.ID)
	if len(jobs) == 0 {
		return nil
	}
	cov, _ := o.store.ListCoverage(p.ID)
	vts, _ := o.store.ListVTs(p.ID)
	var covS, vtS strings.Builder
	for _, c := range cov {
		fmt.Fprintf(&covS, "%s\x00%s\x00%s\x00%s\x00", c.Endpoint, c.Param, c.VulnClass, c.Notes)
	}
	for _, t := range vts {
		fmt.Fprintf(&vtS, "%s\x00%s\x00%s\x00%s\x00", t.Title, t.Note, t.StartConditions, t.ResultRef)
	}
	deliv := o.deliverablesText(p.ID)
	var missing []string
	for _, j := range jobs {
		if strings.Contains(covS.String(), j.ID) || strings.Contains(vtS.String(), j.ID) || strings.Contains(deliv, j.ID) {
			continue
		}
		missing = append(missing, j.ID+"("+j.State+","+fmt.Sprintf("%dB", j.LogBytes)+")")
	}
	if len(missing) == 0 {
		return nil
	}
	return []string{fmt.Sprintf(
		"v6.0.1 C31 零产出对账门：%d 个后台作业超时终止/近零产出且无留痕（%s）——逐条 record_vt（title 含 job id，启动条件写复测前提）或 update_coverage（needs_follow_up，Notes 引 job id），未完成面不得写 ruled_out/no_issue_found",
		len(missing), truncateText(strings.Join(missing, "、"), 140))}
}

// ---------- P6 · C29 覆盖边界结构化（S8 报告门） ----------

// boundarySectionRe 覆盖边界章节定位（二级标题，兼容「覆盖边界」变体）。
var boundaryHeadingRe = regexp.MustCompile(`(?m)^#{1,3}\s*覆盖边界.*$`)

// boundaryQuantRe 量化分母：X/Y 或「共 N 个」——只有分母才能对照 coverage 分布核实。
var boundaryQuantRe = regexp.MustCompile(`(\d+\s*/\s*\d+|共\s*\d+\s*[个条站项目标])`)

// coverageBoundaryIssues v6.0.1 C29（建议编号 S8-2）：报告必须含《覆盖边界》结构化章节，
// 每条含边界项/量化分母/解锁条件/来源。实证：某任务覆盖边界（认证后 0%、10 站不可达、
// nuclei 通道 inconclusive）散落 5+ 份交付物，报告若不写足会误导"已全面覆盖"。
func (o *Orchestrator) coverageBoundaryIssues(p *store.Project) []string {
	raw, err := o.exec.ReadFile(p.ID, "report.md")
	if err != nil {
		return nil // 报告本身缺失由其他门负责
	}
	loc := boundaryHeadingRe.FindStringIndex(raw)
	if loc == nil {
		return []string{"v6.0.1 C29 覆盖边界门：report.md 缺《覆盖边界》章节——按 coverage 状态分布逐条列：边界项/量化分母（已测/总数）/解锁条件（最小代价路径）/来源；可从 /api/projects/{id}/reconciliation 的 coverage_boundary_draft 取初稿（标注「引擎统计待人工确认」）"}
	}
	// 取章节文本（到下一个二级标题或文末）
	sec := raw[loc[0]:]
	if m := regexp.MustCompile(`(?m)^##\s+`).FindStringIndex(sec[1:]); m != nil {
		sec = sec[1 : 1+m[0]]
	}
	var issues []string
	if !boundaryQuantRe.MatchString(sec) {
		issues = append(issues, "v6.0.1 C29 覆盖边界门：《覆盖边界》章节无量化分母（X/Y 或「共 N 个」）——仅写百分比无分母=不可核实，逐条补「已测/总数」")
	}
	if !strings.Contains(sec, "解锁") {
		issues = append(issues, "v6.0.1 C29 覆盖边界门：《覆盖边界》章节缺「解锁条件」——每条边界必须写最小代价解锁路径（如客户提供测试账号/WAF 白名单窗口/DNS 修复后复测）")
	}
	return issues
}

// coverageBoundaryDraft v6.0.1 C29：从 coverage 状态分布/目标清单/未完成作业自动推导
// 《覆盖边界》章节初稿（明确标注「引擎统计待人工确认」——自动统计不写成测试结论）。
// 供 /reconciliation API 与模型收口指引消费。
func (o *Orchestrator) coverageBoundaryDraft(p *store.Project) string {
	var b strings.Builder
	b.WriteString("## 覆盖边界（引擎统计待人工确认）\n\n")
	b.WriteString("> 本节由引擎从 coverage.json/后台作业状态自动推导初稿；每条须人工核对后补「解锁条件/来源」方可作为报告结论。\n\n")
	b.WriteString("| 边界项 | 量化数据 | 解锁条件 | 来源 |\n|---|---|---|---|\n")
	total := 0
	statusCnt := map[string]int{}
	if cov, err := o.store.ListCoverage(p.ID); err == nil {
		total = len(cov)
		for _, c := range cov {
			statusCnt[c.Status]++
		}
	}
	targets := splitProjectTargets(p)
	if len(targets) > 0 {
		b.WriteString(fmt.Sprintf("| 目标覆盖 | %d 目标在册，coverage 单元 %d 条（单元≠目标，逐目标处置见台账） | 客户确认未测目标归属 | coverage.json |\n", len(targets), total))
	}
	if n := statusCnt["needs_follow_up"]; n > 0 {
		b.WriteString(fmt.Sprintf("| needs_follow_up（未完成面） | 共 %d 条 / coverage 总数 %d | 按 Notes 逐条解锁（通道批复/账号/DNS 修复） | coverage.json |\n", n, total))
	}
	if n := statusCnt["waf_blocked"]; n > 0 {
		b.WriteString(fmt.Sprintf("| WAF 拦截（非阴性） | 共 %d 条 / coverage 总数 %d | 白名单出口 IP 或 WAF 例外窗口后复测 | coverage.json |\n", n, total))
	}
	if n := statusCnt["skipped"]; n > 0 {
		b.WriteString(fmt.Sprintf("| 显式跳过 | 共 %d 条 / coverage 总数 %d | 核对跳过依据是否仍成立 | coverage.json |\n", n, total))
	}
	if jobs := o.exec.IncompleteAsyncJobs(p.ID); len(jobs) > 0 {
		b.WriteString(fmt.Sprintf("| 后台作业未完成（超时/零产出） | 共 %d 个 | 逐 job 复测或登记 VT 移交 | .async/ sidecar |\n", len(jobs)))
	}
	b.WriteString("\n（未覆盖的认证后面/不可达目标/HIBP 等通道缺口：由人工补充行——引擎无法从 coverage 推导的边界必须显式填写来源与解锁条件）\n")
	return b.String()
}

// ---------- P7 · 模型生效记录与漂移告警 ----------

// recordModelSel v6.0.1 C30（M3 模型生效记录，warn-only）：配置声明值/项目覆盖/故障接管
// 属合法选择路径——记录生效原因；真正告警的是网关回报模型与请求模型不一致（漂移）。
// 同项目同阶段同模型只记一次（防 1500 次调用刷屏），模型切换额外记一条。
func (o *Orchestrator) recordModelSel(p *store.Project, stageID, effectiveModel, source string) {
	if p == nil || effectiveModel == "" {
		return
	}
	o.modelSelMu.Lock()
	if o.modelSel == nil {
		o.modelSel = map[string]bool{}
	}
	key := p.ID + "|" + stageID + "|" + effectiveModel + "|" + source
	first := !o.modelSel[key]
	o.modelSel[key] = true
	o.modelSelMu.Unlock()
	if !first {
		return
	}
	o.log(p, stageID, fmt.Sprintf("🧭 [C30 模型生效记录] effective_model=%s source=%s（configured=%s；同阶段同模型只记一次；网关回报不一致将另行漂移告警）",
		effectiveModel, source, o.cfg.LLM.Model))
}

// checkModelDrift v6.0.1 C30：网关回报的实际模型与请求模型不一致 → 告警留痕（不阻断不换模型）。
// 网关未回报（ProviderModel 空）记 unreported，不伪称一致。
func (o *Orchestrator) checkModelDrift(p *store.Project, stageID, requested string, u llm.Usage) {
	if u.ProviderModel == "" {
		return // unreported：不告警不伪称（由设置页/日志按 unreported 呈现）
	}
	if u.ProviderModel == requested {
		return
	}
	o.modelSelMu.Lock()
	if o.modelSel == nil {
		o.modelSel = map[string]bool{}
	}
	key := p.ID + "|" + stageID + "|drift|" + requested + "|" + u.ProviderModel
	first := !o.modelSel[key]
	o.modelSel[key] = true
	o.modelSelMu.Unlock()
	if !first {
		return
	}
	o.log(p, stageID, fmt.Sprintf("⚠ [C30 漂移告警] 请求模型=%s 网关回报=%s（drift_policy=warn，仅留痕不阻断；成本/能力评估请以实际回报为准）", requested, u.ProviderModel))
}
