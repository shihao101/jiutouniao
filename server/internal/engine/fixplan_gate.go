package engine

// fixplan_gate.go v6.0.1（fix-plan 20261122 审计修复）：
// P2/P3/P5/P6 收口确定性门 + P7 模型生效记录。全部为引擎级机械对账，
// 只拦截"无留痕"，不推断测试质量、不自动放行、不改变 production_safe/审批语义。

import (
	"fmt"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"jiutouniao/internal/config"
	"jiutouniao/internal/llm"
	"jiutouniao/internal/store"
)

// ---------- P3 · C27 类级处置门（S3 判定行 → S4/S5 投递对账） ----------

// exemptTokenRe 显式豁免/已测标记（C27 对账表行内必须出现的处置词——结构化小节而非自由文本）。
var exemptTokenRe = regexp.MustCompile(`(已测|已投递|不适用|待续|deferred|no_credentials|production_safe_write_prohibited|environment_unreachable|环境不可达|合规豁免)`)

// classDispositionIssues v6.0.1 C27（建议编号 S4-10，S4/S5 类级处置门）：
// M2 只校验判定表 27 行存在与三态合法，不校验"假设/待判定"类是否真被投递——
// 实证审计：18 个假设类仅约 12 类有测试单元，6 类静默跳过且交付层不可见。
// 本门要求每个假设/待判定类至少一项留痕：
//  1. coverage/VT/候选/发现文本中出现该 C 编号（强留痕：结构化记录引用）；
//  2. 交付物（含对账表）中出现该 C 编号且同行为处置词（已测/合规豁免/环境不可达等）。
//
// 解析失败不猜类别清单（交由 M2 在 s3 拦截）；存储读取失败按既有降级纪律留痕放行。
// v6.3.0 S3-②：复合键 class@target——判定表 6 列行的假设/待判定按目标拆键，类编号与
// 目标须在同一条留痕内同现（单条 coverage/VT/对账表行），A 目标的留痕不再释放 B 目标的
// 同类面；5 列旧行退化为项目级键（与旧口径/旧项目兼容）。
func (o *Orchestrator) classDispositionIssues(p *store.Project, stageID string) []string {
	raw, err := o.exec.ReadFile(p.ID, "deliverables/s3-筛查矩阵判定表.md")
	if err != nil {
		return nil // 无判定表（旧项目/mock）：M2 在 s3 收口已拦截，此处不重复报
	}
	need := matrixNeedKeys(parseMatrixRows(raw), len(splitProjectTargets(p)) <= 1)
	if len(need) == 0 {
		return nil
	}
	// v6.0.4 P8：处置分桶统计——C27 原实现只区分「有归宿/无归宿」，无法区分「已实际测试」
	// 与「仅登记处置/豁免/待续」，收口闭环可能掩盖零投递（实证：任务 A C-25 有卡零投递）。
	// 分桶优先级：tested（coverage/findings 有 C 编号投递痕迹）> queued_vt（VT/候选承接）
	// > exempted/blocked/deferred（对账表行内处置词）。
	state := map[string]string{}
	tryCover := func(text, bucket string) {
		for key := range need {
			if state[key] == "tested" || (state[key] != "" && bucket != "tested") {
				continue // tested 优先；同/低桶不覆盖高桶
			}
			if matrixKeyMatches(key, text) {
				state[key] = bucket
			}
		}
	}
	if cov, cerr := o.store.ListCoverage(p.ID); cerr == nil {
		for _, c := range cov {
			tryCover(fmt.Sprintf("%s\x00%s\x00%s\x00%s", c.Endpoint, c.Param, c.VulnClass, c.Notes), "tested")
		}
	}
	if fs, ferr := o.store.ListFindings(p.ID); ferr == nil {
		for _, f := range fs {
			tryCover(f.Title+"\x00"+f.Detail, "tested")
		}
	}
	if vts, verr := o.store.ListVTs(p.ID); verr == nil {
		for _, t := range vts {
			tryCover(t.Title+"\x00"+t.Note+"\x00"+t.StartConditions+"\x00"+t.ResultRef, "queued_vt")
		}
	}
	if cands, cerr := o.store.ListCandidates(p.ID); cerr == nil {
		for _, c := range cands {
			tryCover(c.Title+"\x00"+c.Target+"\x00"+c.Reason+"\x00"+c.DispositionRef, "queued_vt")
		}
	}
	// 交付物对账行处置词分桶（v6.3.0：按行派生键，6 列行逐目标归账）
	for _, r := range parseMatrixRows(o.deliverablesText(p.ID)) {
		var b string
		switch {
		case strings.Contains(r.line, "已测") || strings.Contains(r.line, "已投递"):
			b = "tested"
		case strings.Contains(r.line, "no_credentials") || strings.Contains(r.line, "production_safe_write_prohibited") || strings.Contains(r.line, "合规豁免"):
			b = "exempted"
		case strings.Contains(r.line, "环境不可达"):
			b = "blocked"
		case strings.Contains(r.line, "待续") || strings.Contains(r.line, "deferred"):
			b = "deferred"
		}
		if b == "" {
			continue
		}
		for _, key := range matrixLineKeys(r, len(splitProjectTargets(p)) <= 1) {
			if !need[key] {
				continue
			}
			if b == "tested" || state[key] == "" || state[key] != "tested" {
				state[key] = b
			}
		}
	}
	var missing []string
	stats := map[string]int{}
	for id := range need {
		if state[id] == "" {
			missing = append(missing, id)
			continue
		}
		if state[id] == "tested" {
			stats["tested"]++
		} else {
			stats[state[id]]++
		}
	}
	sort.Strings(missing)
	dist := fmt.Sprintf("tested=%d queued_vt=%d exempted=%d blocked=%d deferred=%d（共 %d 键；tested=coverage/findings 引用 C 编号或对账表标注已测；queued_vt/exempted/blocked/deferred 为处置/豁免/待续——不等于已实际测试）",
		stats["tested"], stats["queued_vt"], stats["exempted"], stats["blocked"], stats["deferred"], len(need))
	// v7.6.0（A3 增量）：交付物手写五态数字 vs 引擎实算的漂移提示（提示级非拦截）——实证
	// 三处手写汇总数字穿透收口（tested 20/deferred 7 vs 实算 16/9 等，实测报告 §A3）且引擎
	// 实算未回写；引擎实算已随 A3 核对注记落时间线，此处对交付物中可机械提取的
	// "tested N … deferred N" 形态做一致性提示，供 S8 复核与人工修订定位。
	o.numericDriftHint(p, stageID, stats)
	if len(missing) > 0 {
		// v7.7.0 P2 对账一枪清（docs/优化方案_实战提速五项 §一.P2）：拦截前引擎代填——
		// 从卡片账本（执行卡状态机）+ 覆盖矩阵生成对账表行（有台账依据才落行，绝不造"已测"），
		// 对齐 E1' V3 代填模式；代填后重跑门核验（不是跳过门）。双源规则：引擎代填行为
		// 权威口径，模型只能增补归因/证据不得改五态数字（A3 漂移提示继续生效）。
		if o.c27Autofill(p, stageID, missing) {
			issues2 := o.classDispositionIssues(p, stageID)
			if len(issues2) == 0 {
				o.log(p, stageID, "⚙ C27 引擎代填完成——重跑核验通过（对账表行全部来自台账）")
				return nil
			}
			// 代填后仍有缺（queued 零 dispatch 类）——保留原拦截文案，附代填说明
			return append([]string{fmt.Sprintf(
				"v7.7.0 P2：C27 引擎代填已写入台账可证的行（%d/%d 键）——剩余 %d 键缺投递留痕（零 dispatch），必须真实测试后三选一补齐：①update_coverage 引用 C 编号②record_vt（title/启动条件含 C 编号）③对账表行+证据指针。禁止静默跳过。",
				len(need)-len(issues2), len(need), len(issues2))}, issues2...)
		}
		return []string{fmt.Sprintf(
			"v6.0.4 C27 类级处置门：%d/%d 个假设/待判定键无任何投递留痕（%s）｜处置分布 %s——三选一补齐后重新收口：①update_coverage 引用 C 编号（Endpoint/Notes）②record_vt（title/启动条件含 C 编号）③写 deliverables/s6-27类收口对账表.md 该行为「已测/合规豁免（no_credentials|production_safe_write_prohibited|environment_unreachable + 依据）/环境不可达/待续」+ 证据指针。禁止静默跳过（实证：某任务 6/18 假设类零测试单元）",
			len(missing), len(need), truncateText(strings.Join(missing, ","), 140), dist)}
	}
	// v6.0.4 P8：全数处置时输出分布摘要（非阻断）——区分「已测」与「仅处置」，防闭环掩盖零投递
	o.log(p, stageID, "🧾 [C27 分布] "+dist)
	return nil
}

// reconciliationTableIssues v6.0.1 C27 收口件（S6）：存在判定表的项目，
// S6 收口时必须已产出《27类收口对账表》且 27 行逐行有处置态——类级闭环落到交付物，
// S8 报告直接承接（产出缺失=类级对账从未显式收口）。
// v6.3.0 S3-②：多目标项目追加 (类×目标) 复合键覆盖——判定表按目标拆键的假设/待判定
// 组合在对账表须逐行处置（5 列项目级行覆盖该类全部复合键；guard 关闭回退类级口径）。
func (o *Orchestrator) reconciliationTableIssues(p *store.Project) []string {
	judgeRaw, jerr := o.exec.ReadFile(p.ID, "deliverables/s3-筛查矩阵判定表.md")
	if jerr != nil {
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
	// v6.3.0（S3-②）：多目标复合键覆盖完备性；v6.4.0（S4-①）：单目标豁免与 C27 同口径
	// （单目标项目 need 全为项目级键，5 列/6 列行均按类归账）。
	if o.guardEnabled(func(g *config.GuardConfig) *bool { return g.EnforceTargetClassMatrix }) {
		need := matrixNeedKeys(parseMatrixRows(judgeRaw), len(splitProjectTargets(p)) <= 1)
		if len(need) > 0 {
			foundKeys := map[string]bool{}
			for _, r := range parseMatrixRows(raw) {
				if !exemptTokenRe.MatchString(r.line) {
					continue
				}
				keys := matrixLineKeys(r, len(splitProjectTargets(p)) <= 1)
				if len(keys) == 1 && keys[0] == r.class {
					// 5 列项目级行：覆盖该类的全部复合键与项目级键
					for key := range need {
						if key == r.class || strings.HasPrefix(key, r.class+"@") {
							foundKeys[key] = true
						}
					}
				} else {
					for _, key := range keys {
						foundKeys[key] = true
					}
				}
			}
			var missingKeys []string
			for key := range need {
				if !foundKeys[key] {
					missingKeys = append(missingKeys, key)
				}
			}
			if len(missingKeys) > 0 {
				sort.Strings(missingKeys)
				return []string{fmt.Sprintf("v6.3.0 C27 收口件：对账表 %d 个 (类×目标) 组合缺处置态（%s）——多目标项目按判定表逐组合产出处置行（已测/合规豁免/环境不可达/待续）并附证据指针",
					len(missingKeys), truncateText(strings.Join(missingKeys, ","), 160))}
			}
		}
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

// ---------- S6-⑥ 命名交付物条件核验（v6.7.0） ----------

// footholdRe 立足点信号判据：S4/S5/S6 发现标题/详情命中执行面/驻留面/会话面关键词
// （RCE 系/内存马/会话接管/命令执行/getshell）。保守取或——多判的代价只是要求
// N/A 声明（无产出风险），漏判的代价是横向面交付缺失。
var footholdRe = regexp.MustCompile(`(RCE|远程代码执行|命令执行|getshell|webshell|内存马|会话接管|接管会话|初始访问)`)

// hasFoothold v6.7.0（S6-⑥）：项目是否存在已确证的立足点信号——三路任一命中即真：
// ①S4/S5/S6 阶段发现命中 footholdRe；②verified 战利品（凭据/会话/flag 经验证）；
// ③S5 交付物含「初始访问」语义小节（s5.md 交付物清单点名件）。无立足点项目 s6 收口
// 零命名交付物要求（合法跳过），命中项目要求《权限矩阵》+《横向路径图》或 N/A 声明。
func (o *Orchestrator) hasFoothold(p *store.Project) bool {
	findings, _ := o.store.ListFindings(p.ID)
	for _, f := range findings {
		if f.Stage != "s4" && f.Stage != "s5" && f.Stage != "s6" {
			continue
		}
		if footholdRe.MatchString(f.Title + " " + f.Detail) {
			return true
		}
	}
	if loots, err := o.store.ListLoot(p.ID, 0); err == nil {
		for _, l := range loots {
			if l.Verified == "verified" {
				return true
			}
		}
	}
	if names, err := o.exec.ListDir(p.ID, "deliverables"); err == nil {
		for _, rel := range names {
			base := filepath.Base(rel)
			if !strings.HasPrefix(base, "s5-") || !strings.HasSuffix(base, ".md") {
				continue
			}
			if raw, rerr := o.exec.ReadFile(p.ID, rel); rerr == nil && strings.Contains(raw, "初始访问") {
				return true
			}
		}
	}
	return false
}

// s6DeliverableIssues v6.7.0（S6-⑥）：有立足点的项目收口要求《权限矩阵》与《横向路径图》
// （前缀匹配，兼容「s6-权限矩阵与横向路径图」实跑最常见合并命名）或 N/A 声明
// （s6-不适用* 独立文件，或任一 s6-*.md 内容含「不适用」+「依据」）——永远开放 N/A 兜底，
// 不逼模型造假产出；拦截文案即修补指引。
func (o *Orchestrator) s6DeliverableIssues(p *store.Project) []string {
	names, err := o.exec.ListDir(p.ID, "deliverables")
	if err != nil {
		return nil // 工作区读取失败：按门降级纪律放行，不伪造"无交付物"
	}
	hasMatrix, hasLateral := false, false
	naDeclared := false
	for _, rel := range names {
		base := filepath.Base(rel)
		if !strings.HasPrefix(base, "s6-") {
			continue
		}
		if strings.Contains(base, "权限矩阵") {
			hasMatrix = true
		}
		if strings.Contains(base, "横向路径图") {
			hasLateral = true
		}
		if strings.HasPrefix(base, "s6-不适用") {
			naDeclared = true
		}
		if !naDeclared && strings.HasSuffix(base, ".md") {
			if raw, rerr := o.exec.ReadFile(p.ID, rel); rerr == nil &&
				strings.Contains(raw, "不适用") && strings.Contains(raw, "依据") {
				naDeclared = true
			}
		}
	}
	if naDeclared {
		return nil
	}
	var missing []string
	if !hasMatrix {
		missing = append(missing, "《权限矩阵》")
	}
	if !hasLateral {
		missing = append(missing, "《横向路径图》")
	}
	if len(missing) == 0 {
		return nil
	}
	return []string{fmt.Sprintf(
		"v6.7.0 S6-⑥ 交付物核验：本项目已存在立足点信号，收口缺 %s——两条路径任选：①产出对应交付物（多目标项目按 deliverables/s6-<目标或组名>.md 分组，S8 报告承接合并）②写 N/A 声明（deliverables/s6-不适用声明.md 或任一 s6- 交付物内写明「不适用」+依据，如「横向面不在授权范围」）——禁止既不产出也不声明",
		strings.Join(missing, "与"))}
}

// ---------- P2 · C31 后台作业零产出/超时对账门 ----------

// incompleteBatchIssues v6.0.1 C31：killed（超时终止）或近零产出的后台作业，收口时必须
// 有留痕（coverage/VT/交付物任一引用 job id）——被截杀的扫描不得洗白成阴性结论
// （实证：nuclei 整批 >5min 零产出被标 inconclusive 后 misconfig 面实质漏测；v4.6 E2 曾
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
		return []string{"v6.0.1 C29 覆盖边界门：report.md 缺《覆盖边界》章节——按 coverage 状态分布逐条列：边界项/量化分母（已测/总数）/解锁条件（最小代价路径）/来源；上下文「关键数字与覆盖边界」块已附《覆盖边界》初稿（引擎统计待人工确认，v6.9.0 S8-⑦ 起模型侧直达），直接取材逐条人工核对"}
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

// successCriteriaIssues v6.0.4 P11：测试目的/成功标准对照检查（有输入才查）。
// 报告须引用成功标准首行原文（≥8 字符时）或含「成功标准/测试目的」对照小节，否则拦截。
func (o *Orchestrator) successCriteriaIssues(p *store.Project) []string {
	sc := strings.TrimSpace(p.SuccessCriteria)
	if len([]rune(sc)) < 8 {
		return nil
	}
	raw, rerr := o.exec.ReadFile(p.ID, "report.md")
	if rerr != nil {
		return nil // 报告缺失由其他门负责
	}
	key := firstLine(sc)
	if len([]rune(key)) < 8 {
		key = sc
	}
	if !strings.Contains(raw, key) && !strings.Contains(raw, "成功标准") && !strings.Contains(raw, "测试目的") {
		return []string{"v6.0.4 P11：report.md 未对照「测试目的/成功标准」——增加《结论对照成功标准》小节（逐条说明达成/未达成及原因）或引用成功标准原文；用户输入的测试目的必须被报告回应"}
	}
	return nil
}

// ---------- P8 · S4→S5 移交承接对账（v6.4.0 S4-⑤⑥） ----------

// browserAuthRouteTextRe 旧数据文本标记等价识别（s4.md:37「browser-auth 路线」——
// record_finding route 字段引入前的存量发现与 summary 叙述形态）。
var browserAuthRouteTextRe = regexp.MustCompile(`(?i)browser[_-]auth\s*路线`)

// findingIsBrowserAuthRoute S4-⑥：route 结构化字段优先，旧数据文本标记等价（仅 s4 阶段发现）。
func findingIsBrowserAuthRoute(f *store.Finding) bool {
	if f.Route == "browser-auth" {
		return true
	}
	return f.Stage == "s4" && browserAuthRouteTextRe.MatchString(f.Title+" "+f.Detail)
}

// handoverGlobalTag v6.5.0（S5-②）：无法归属到单一项目目标的移交条目的全局标签——
// 单目标项目不分桶（行为与 v6.4.1 一致）；多目标下命中多个/零个目标时也归全局。
const handoverGlobalTag = "全局"

// parseHandoverTarget v6.5.0（S5-②）：从移交条目标签提取目标维度（`[标签@目标] 正文` →
// 目标；无标签/无 @ 后缀 → 空串 = 全局/旧格式，回退项目级匹配）。
func parseHandoverTarget(item string) string {
	if !strings.HasPrefix(item, "[") {
		return ""
	}
	i := strings.Index(item, "]")
	if i < 0 {
		return ""
	}
	tag := item[1:i]
	if j := strings.LastIndex(tag, "@"); j >= 0 {
		return strings.TrimSpace(tag[j+1:])
	}
	return ""
}

// tagHandoverTarget v6.5.0（S5-②）：移交条目注入目标维度标签——条目正文（标签后全部文本）
// 经词边界命中唯一项目目标（canonicalTargetKey 精确键口径，与 targetCoverageRecon 同源）
// 时改写为 `[标签@<目标>] 正文`；命中多个/零个目标或单目标项目保持原条目（无标签 = 全局）。
func tagHandoverTarget(item string, targets []string) string {
	if len(targets) <= 1 {
		return item // 单目标：无分桶意义，保持无标签（全局匹配，向后兼容）
	}
	if !strings.HasPrefix(item, "[") {
		return item
	}
	i := strings.Index(item, "] ")
	if i < 0 {
		return item
	}
	body := normCovText(item[i+2:])
	tag := ""
	hits := 0
	for _, t := range targets {
		ck := normCovText(canonicalTargetKey(t))
		if ck == "" {
			continue
		}
		if wordBoundaryContains(body, ck) || strings.Contains(body, ck) && !targetHostLike(t) {
			hits++
			tag = t
		}
	}
	if hits == 1 && tag != "" {
		return item[:i] + "@" + tag + item[i:]
	}
	return item
}

// s4HandoverItems S4 移交项收集（S5 上下文「S4 移交项」注入块与 v3HandoverIssues 共用数据源）：
// ①S4 StageState V3 两清单（正常收口与代收口路径均落库，见 orchestrator complete_stage/
// 代收口）②route=browser-auth（含旧数据文本标记等价）的 S4 发现。
// v6.5.0（S5-②）：多目标项目逐条注入 @目标 标签（tagHandoverTarget）——S5 注入块按目标
// 分组呈现、承接对账按目标分桶（A 目标的留痕不释放 B 目标的同类条目）。
func (o *Orchestrator) s4HandoverItems(p *store.Project) []string {
	var items []string
	if st := p.StageStates["s4"]; st != nil {
		for _, it := range st.V3Ready {
			if strings.TrimSpace(it) == "" {
				continue
			}
			items = append(items, "[就绪未执行] "+it)
		}
		for _, it := range st.V3L2 {
			if strings.TrimSpace(it) == "" {
				continue
			}
			items = append(items, "[已批未用] "+it)
		}
	}
	if fs, err := o.store.ListFindings(p.ID); err == nil {
		for _, f := range fs {
			if !findingIsBrowserAuthRoute(f) {
				continue
			}
			tag := ""
			if f.Access != "" || f.ImpactRank > 0 {
				tag = fmt.Sprintf(" [access=%s rank=%d]", f.Access, f.ImpactRank)
			}
			items = append(items, fmt.Sprintf("[认证路线移交 S5-2a] %s%s — %s",
				truncateText(f.Title, 80), tag, truncateText(f.Detail, 160)))
		}
	}
	// v6.5.0（S5-②）：多目标项目逐条打目标标签（单目标原样返回，零行为变化）
	if targets := splitProjectTargets(p); len(targets) > 1 {
		for i := range items {
			items[i] = tagHandoverTarget(items[i], targets)
		}
	}
	return items
}

// specHandoverHintCount v6.6.0 增补（核对轮）：S5 收口对专项移交项的承接提示级核对（不拦截）。
// SP-③ 刻意把专项移交链做成呈现性注入（承接由 S7 清点门兜底，方案 SP-③ 明文），但「S5 对
// spec 移交项零承接」的失效形态此前收口不可见——本提示与 S5-① matched=0 提示级、S5-⑩
// S5→S6 承接提示同口径：只让失效形态收口可见，不改变拦截行为。语料与 v3HandoverIssues 同族
// （coverage notes + VT + 交付物），排除 s4- 与 spec 前缀交付物——spec 自身交付物（假设队列/
// 专项条目清单）含条目原文，会自匹配放行（与 v3HandoverIssues 排除 s4- 产物同款防自匹配）。
func (o *Orchestrator) specHandoverHintCount(p *store.Project) int {
	var items []string
	for _, sid := range []string{"specA", "specB1", "specB2"} {
		if sts := p.StageStates[sid]; sts != nil {
			for _, it := range sts.V3Ready {
				if strings.TrimSpace(it) != "" {
					items = append(items, it)
				}
			}
			for _, it := range sts.V3L2 {
				if strings.TrimSpace(it) != "" {
					items = append(items, it)
				}
			}
		}
	}
	if len(items) == 0 {
		return 0
	}
	var corpus strings.Builder
	if cov, cerr := o.store.ListCoverage(p.ID); cerr == nil {
		for _, c := range cov {
			fmt.Fprintf(&corpus, "%s\x00%s\x00%s\x00", c.Endpoint, c.VulnClass, c.Notes)
		}
	}
	if vts, verr := o.store.ListVTs(p.ID); verr == nil {
		for _, t := range vts {
			fmt.Fprintf(&corpus, "%s\x00%s\x00%s\x00%s\x00", t.Title, t.StartConditions, t.Note, t.ResultRef)
		}
	}
	if names, derr := o.exec.ListDir(p.ID, "deliverables"); derr == nil {
		n := 0
		for _, rel := range names {
			base := filepath.Base(rel)
			if strings.Contains(rel, "s4-") || strings.HasPrefix(base, "spec") {
				continue
			}
			if !strings.HasSuffix(rel, ".md") && !strings.HasSuffix(rel, ".txt") && !strings.HasSuffix(rel, ".json") {
				continue
			}
			if n >= 60 {
				break
			}
			if rawText, rerr := o.exec.ReadFile(p.ID, rel); rerr == nil {
				corpus.WriteString(rawText)
				corpus.WriteString("\x00")
				n++
			}
		}
	}
	nc := normCovText(corpus.String())
	unref := 0
	for _, it := range items {
		if key := handoverTraceKey(it); key != "" && !strings.Contains(nc, key) {
			unref++
		}
	}
	return unref
}

// s7V3ReadyHintCount v6.8.2（核对轮）：S7 收口对全阶段未清点 V3Ready 条目的提示级核对（不拦截）。
// S7-⑤ 清点块解决了「在场」，A2/V4 门只覆盖 VT 化与 L2 条目——纯文本 V3Ready（未 record_vt、
// 非 L2）此前收口零机械暴露。本提示与 S6-② 四元组提示、specHandoverHintCount 同口径：只让
// 失效形态收口可见。语料 = s7- 交付物（清理确认清单/需人工清理清单/待续清单处置/清点映射）+
// 全部 VT 记录；排除 s4-/s5-/spec 前缀交付物（源队列文件含条目原文，会自匹配）。注意：条目
// 若已在 S5/S6 显式移交且未在 s7 复写留痕，会误提示——提示文案已注明该豁免路径（提示级不拦，
// 偏向宁可多提示）。
func (o *Orchestrator) s7V3ReadyHintCount(p *store.Project) int {
	var items []string
	for _, sid := range []string{"s4", "s5", "specA", "specB1", "specB2"} {
		if sts := p.StageStates[sid]; sts != nil {
			for _, it := range sts.V3Ready {
				if strings.TrimSpace(it) != "" {
					items = append(items, it)
				}
			}
		}
	}
	if len(items) == 0 {
		return 0
	}
	var corpus strings.Builder
	if vts, verr := o.store.ListVTs(p.ID); verr == nil {
		for _, t := range vts {
			fmt.Fprintf(&corpus, "%s\x00%s\x00%s\x00%s\x00", t.Title, t.StartConditions, t.Note, t.ResultRef)
		}
	}
	if names, derr := o.exec.ListDir(p.ID, "deliverables"); derr == nil {
		n := 0
		for _, rel := range names {
			base := filepath.Base(rel)
			if strings.HasPrefix(base, "s4-") || strings.HasPrefix(base, "s5-") || strings.HasPrefix(base, "spec") {
				continue
			}
			if !strings.HasSuffix(rel, ".md") && !strings.HasSuffix(rel, ".txt") && !strings.HasSuffix(rel, ".json") {
				continue
			}
			if n >= 60 {
				break
			}
			if rawText, rerr := o.exec.ReadFile(p.ID, rel); rerr == nil {
				corpus.WriteString(rawText)
				corpus.WriteString("\x00")
				n++
			}
		}
	}
	nc := normCovText(corpus.String())
	unref := 0
	for _, it := range items {
		if key := handoverTraceKey(it); key != "" && !strings.Contains(nc, key) {
			unref++
		}
	}
	return unref
}

// handoverTraceKey 移交项承接留痕匹配键：剥掉行首 [标签]，取正文前 12 rune 归一化
// （与 checklistItemCovered「条目文本前 12 字符」口径一致；VT 化条目正文以 VT- 编号开头，
// S5 侧 update_vt 执行留痕天然命中）。
func handoverTraceKey(item string) string {
	s := item
	if strings.HasPrefix(s, "[") {
		if i := strings.Index(s, "] "); i >= 0 {
			s = s[i+2:]
		}
	}
	r := []rune(strings.TrimSpace(s))
	if len(r) > 12 {
		r = r[:12]
	}
	return normCovText(string(r))
}

// v3HandoverIssues S5 收口承接对账门（guard enforce_s5_v3_handover，缺省 true；guard 检查内置于函数——与 s3ClosureIssues⑥ 同款自包含口径，调用方无需重复判断）：
// S4 移交项（V3 两清单 + browser-auth 路线移交，见 s4HandoverItems）在 S5 语料
// （coverage notes / VT 台账 / S5 侧交付物，排除 s4 产物防自匹配）须有承接留痕——
// 逐条三态映射（执行/合并/显式移交）后任一形态都会在语料留下条目文本或 VT 编号引用。
// 无任何留痕的条目拦截（s5.md:14 承接反蒸发的机械对账；TH-23/24 静默蒸发实证形态）。
// S4 未收口（无移交项）直通。
func (o *Orchestrator) v3HandoverIssues(p *store.Project) []string {
	if !o.guardEnabled(func(g *config.GuardConfig) *bool { return g.EnforceS5V3Handover }) {
		return nil
	}
	items := o.s4HandoverItems(p)
	if len(items) == 0 {
		return nil
	}
	var corpus strings.Builder
	if cov, cerr := o.store.ListCoverage(p.ID); cerr == nil {
		for _, c := range cov {
			fmt.Fprintf(&corpus, "%s\x00%s\x00%s\x00", c.Endpoint, c.VulnClass, c.Notes)
		}
	}
	if vts, verr := o.store.ListVTs(p.ID); verr == nil {
		for _, t := range vts {
			fmt.Fprintf(&corpus, "%s\x00%s\x00%s\x00%s\x00", t.Title, t.StartConditions, t.Note, t.ResultRef)
		}
	}
	if names, derr := o.exec.ListDir(p.ID, "deliverables"); derr == nil {
		n := 0
		for _, rel := range names {
			// s4 产物排除（判定表/对账表/V3 影子文件等含移交项原文，会自匹配放行）
			if strings.Contains(rel, "s4-") || strings.HasPrefix(rel, "deliverables/s4-") {
				continue
			}
			if !strings.HasSuffix(rel, ".md") && !strings.HasSuffix(rel, ".txt") && !strings.HasSuffix(rel, ".json") {
				continue
			}
			if n >= 60 {
				break
			}
			if rawText, rerr := o.exec.ReadFile(p.ID, rel); rerr == nil {
				corpus.WriteString(rawText)
				corpus.WriteString("\x00")
				n++
			}
		}
	}
	nc := normCovText(corpus.String())
	// v6.5.0（S5-②）：按目标分桶对账——带 @目标 标签的条目只认「该目标自己的语料」
	//（coverage/VT/非 s4 交付物中出现该目标的行），A 目标的留痕不释放 B 目标的同类条目
	//（v5.1.3 TH-23/24 蒸发形态在多目标维度的复活路径闭合）；@全局/无标签条目（旧数据/
	// 单目标）回退项目级全局匹配（v6.4.1 行为不变）。browser-auth 通道留痕检查保持全局
	// 语料（通道标记是流程性质标记，不随目标分桶）。
	targetCorpus := map[string]string{}
	var missing []string
	for _, it := range items {
		key := handoverTraceKey(it)
		if key == "" {
			continue
		}
		tgt := parseHandoverTarget(it)
		itemCorpus := nc
		if tgt != "" && tgt != handoverGlobalTag {
			tc, ok := targetCorpus[tgt]
			if !ok {
				tc = normCovText(o.handoverTargetCorpus(p, tgt))
				targetCorpus[tgt] = tc
			}
			itemCorpus = tc
		}
		if strings.Contains(itemCorpus, key) {
			// 方案 S4-⑥③：认证路线移交项（[认证路线移交 S5-2a@...]）除条目留痕外，还须有
			// browser-auth 通道留痕（coverage notes 含 browser-auth/browserkit、VT 引用
			// 或交付物 S5-2a 执行记录）——仅引标题原文不算完成 S5-2a 承接。
			if strings.HasPrefix(it, "[认证路线移交 S5-2a") &&
				!strings.Contains(nc, "browser-auth") && !strings.Contains(nc, "browserkit") {
				missing = append(missing, truncateText(it, 100)+"〖缺 browser-auth 通道留痕〗")
			}
			continue
		}
		missing = append(missing, truncateText(it, 100))
	}
	if len(missing) == 0 {
		return nil
	}
	return []string{fmt.Sprintf(
		"v6.5.0 S4 移交承接门（按目标分桶）：%d 条 S4 移交项在 S5 无承接留痕（%s）——按 s5.md:14 逐条三态映射（执行 / 合并进新编队写明新编号 / 显式移交进待续清单）并留痕：执行=update_coverage notes 或 VT 引用条目原文（VT 化条目 update_vt 执行即可）/合并·移交=写进 S5 交付物映射表（引用条目原文前 12 字符）；多目标项目承接留痕须落在条目标注的目标名下（A 目标的留痕不释放 B 目标的同类条目）；禁止静默丢弃（v5.1.3 实证 TH-23/24 形态）",
		len(missing), truncateText(strings.Join(missing, " ｜ "), 200))}
}

// handoverTargetCorpus v6.5.0（S5-②）：单目标承接留痕语料——coverage 行（endpoint/param/
// vuln_class/notes 任一字段含目标）、VT 行（title/启动条件/备注/结果引用含目标）与
// 非 s4 交付物全文含目标的文件；供 v3HandoverIssues 对带 @目标 标签的移交项做分桶匹配。
// 口径：只做「该目标的语料」过滤（bucketing），条目匹配仍用 handoverTraceKey 前缀键。
func (o *Orchestrator) handoverTargetCorpus(p *store.Project, target string) string {
	nt := normCovText(target)
	if nt == "" {
		return ""
	}
	var b strings.Builder
	if cov, cerr := o.store.ListCoverage(p.ID); cerr == nil {
		for _, c := range cov {
			row := c.Endpoint + "\x00" + c.Param + "\x00" + c.VulnClass + "\x00" + c.Notes
			if strings.Contains(normCovText(row), nt) {
				b.WriteString(row)
				b.WriteString("\x00")
			}
		}
	}
	if vts, verr := o.store.ListVTs(p.ID); verr == nil {
		for _, t := range vts {
			row := t.Title + "\x00" + t.StartConditions + "\x00" + t.Note + "\x00" + t.ResultRef
			if strings.Contains(normCovText(row), nt) {
				b.WriteString(row)
				b.WriteString("\x00")
			}
		}
	}
	if names, derr := o.exec.ListDir(p.ID, "deliverables"); derr == nil {
		n := 0
		for _, rel := range names {
			// s4 产物排除（与 v3HandoverIssues 全局语料同口径：含移交项原文，会自匹配放行）
			if strings.Contains(rel, "s4-") || strings.HasPrefix(rel, "deliverables/s4-") {
				continue
			}
			if !strings.HasSuffix(rel, ".md") && !strings.HasSuffix(rel, ".txt") && !strings.HasSuffix(rel, ".json") {
				continue
			}
			if n >= 60 {
				break
			}
			if rawText, rerr := o.exec.ReadFile(p.ID, rel); rerr == nil {
				if strings.Contains(normCovText(rawText), nt) {
					b.WriteString(rawText)
					b.WriteString("\x00")
					n++
				}
			}
		}
	}
	return b.String()
}

// ---------- P9 · S4-10 威胁清单回填对账门（v6.4.0 S4-⑦） ----------

// threatBackfillActionRe 回填三态动作（extends/replaces/creates + TH 编号，s4.md:10 v4.8 R6）。
var threatBackfillActionRe = regexp.MustCompile(`(?i)(extends|replaces|creates)\s*(TH-\d+)`)

// threatBackfillIssues S4-⑦ 回填对账门（guard enforce_th_backfill，缺省 true；s4 收口；guard 检查内置于函数）：
// S4-10 威胁清单实测回填从提示词义务升级为引擎契约——
// ①交付物须有《威胁清单回填记录》小节，且含 ≥1 条 extends/replaces/creates 记录或显式「本轮无回填」声明（s4.md:44 交付物义务）；
// ②extends/replaces 引用的 TH 编号必须存在于 s3-威胁模型.md 威胁清单（防幻觉 TH——与 M2 证据指针核存对称：S3 拦幻觉证据路径，S4 拦幻觉 TH 引用）；creates 允许新编号（本质即入清单动作）；
// ③存在【清单外】标记发现时，回填记录须含 creates 记录（清单外→新编号入清单的既定机制）。
// 口径：只查留痕与引用可达，不判定回填内容质量。无威胁模型（旧项目）直通。
func (o *Orchestrator) threatBackfillIssues(p *store.Project) []string {
	if !o.guardEnabled(func(g *config.GuardConfig) *bool { return g.EnforceTHBackfill }) {
		return nil
	}
	thRaw, thErr := o.exec.ReadFile(p.ID, "deliverables/s3-威胁模型.md")
	if thErr != nil || !threatIDRe.MatchString(thRaw) {
		return nil // 无威胁模型/无 TH 编号（旧项目）：s3 门已拦截，此处不重复
	}
	corpus := o.deliverablesText(p.ID)
	hasRecord := strings.Contains(corpus, "威胁清单回填记录")
	hasAction := threatBackfillActionRe.MatchString(corpus)
	hasNoop := strings.Contains(corpus, "本轮无回填")
	if !hasRecord {
		return []string{"v6.4.0 威胁清单回填门：S4 交付物缺《威胁清单回填记录》小节——按 s4.md S4-10 逐条留痕（extends TH-xx 挂实测进展 / replaces TH-xx 推翻转 deprecated / creates 新编号），本轮确无回填也要显式写「本轮无回填」；回填前先 search_memory 对照原清单"}
	}
	if !hasAction && !hasNoop {
		return []string{"v6.4.0 威胁清单回填门：《威胁清单回填记录》小节既无 extends/replaces/creates 记录也无「本轮无回填」声明——按 s4.md S4-10 三态留痕后重新收口"}
	}
	// ② extends/replaces 引用 TH 可达性（creates 允许新编号）
	thSet := map[string]bool{}
	for _, id := range threatIDRe.FindAllString(thRaw, -1) {
		thSet[id] = true
	}
	var ghost []string
	for _, m := range threatBackfillActionRe.FindAllStringSubmatch(corpus, -1) {
		action, th := strings.ToLower(m[1]), m[2]
		if action == "creates" {
			continue
		}
		if !thSet[th] {
			ghost = append(ghost, action+" "+th)
		}
	}
	if len(ghost) > 0 {
		return []string{fmt.Sprintf(
			"v6.4.0 威胁清单回填门：%d 处 extends/replaces 引用的 TH 编号不在威胁清单（%s）——幻觉 TH 引用（与 M2 幻觉证据路径同源失效面），核对 deliverables/s3-威胁模型.md 的 TH 编号后修正回填记录",
			len(ghost), truncateText(strings.Join(ghost, ","), 120))}
	}
	// ③ 清单外发现处置留痕
	outlier := false
	if fs, ferr := o.store.ListFindings(p.ID); ferr == nil {
		for _, f := range fs {
			if strings.Contains(f.Title+f.Detail, "【清单外】") {
				outlier = true
				break
			}
		}
	}
	if outlier && !strings.Contains(strings.ToLower(corpus), "creates th-") {
		return []string{"v6.4.0 威胁清单回填门：发现库存在【清单外】标记发现（潜在 0day 面，s4.md S4-2）但回填记录无 creates 新编号入清单留痕——清单外发现须按 s4.md S4-10 creates 入威胁清单（或在回填记录逐条写明不移入清单的处置理由）"}
	}
	return nil
}

// c27Autofill v7.7.0 P2：C27 引擎代填——对 missing 键逐个从台账推导处置行：
// 数据源=执行卡状态机（CardStats/卡片明细）+ 覆盖矩阵（vulnerable/ruled_out/waf_blocked/
// needs_follow_up）+ 验证队列。有台账依据的键生成对账行；零依据（从未投递）的键不落行
// （返回 false 交回拦截——绝不造"已测"）。成功写入/更新 deliverables/s6-27类收口对账表.md
// 并时间线留痕。返回 true=全部 missing 键均有台账依据已代填。
func (o *Orchestrator) c27Autofill(p *store.Project, stageID string, missing []string) bool {
	covs, _ := o.store.ListCoverage(p.ID)
	vts, _ := o.store.ListVTs(p.ID)
	rows := make([]string, 0, len(missing))
	filled := 0
	for _, key := range missing {
		cls := key
		tgt := ""
		if i := strings.Index(key, "@"); i > 0 {
			cls, tgt = key[:i], key[i+1:]
		}
		// 推导 1：覆盖矩阵有该类留痕 → 按状态映射处置
		line, basis := "", ""
		for _, c := range covs {
			if !strings.Contains(c.VulnClass, cls) && !strings.Contains(c.Endpoint, cls) {
				continue
			}
			if tgt != "" && !strings.Contains(c.Endpoint, tgt) && !strings.Contains(c.Notes, tgt) {
				continue
			}
			switch c.Status {
			case "vulnerable":
				line, basis = "已测", fmt.Sprintf("coverage vulnerable %s（%s）", c.Endpoint, truncateText(c.Notes, 60))
			case "ruled_out", "no_issue_found":
				line, basis = "已测", fmt.Sprintf("coverage 真阴性 %s（%s）", c.Endpoint, truncateText(c.Notes, 60))
			case "waf_blocked":
				line, basis = "已测（被拦）", fmt.Sprintf("coverage waf_blocked %s", c.Endpoint)
			case "needs_follow_up":
				line, basis = "待续", fmt.Sprintf("coverage needs_follow_up %s（%s）", c.Endpoint, truncateText(c.Notes, 50))
			case "skipped":
				line, basis = "合规豁免（skipped + 台账登记）", fmt.Sprintf("coverage skipped %s", c.Endpoint)
			}
			if line != "" {
				break
			}
		}
		// 推导 2：VT 队列有该类承接
		if line == "" {
			for _, v := range vts {
				if !strings.Contains(v.Title, cls) && !strings.Contains(v.StartConditions, cls) {
					continue
				}
				if v.Status == "ready" || v.Status == "pending" {
					line, basis = "待续（VT 承接）", fmt.Sprintf("%s %s", v.ID, truncateText(v.Title, 50))
				} else if v.Status == "executed" {
					line, basis = "已测（VT 已执行）", fmt.Sprintf("%s %s", v.ID, truncateText(v.Title, 50))
				}
				if line != "" {
					break
				}
			}
		}
		if line == "" {
			continue // 零台账依据：不落行（防漏报——该类必须真实测试）
		}
		rows = append(rows, fmt.Sprintf("| %s | %s | %s | %s |", key, tgt, line, basis))
		filled++
	}
	if filled == 0 {
		return false
	}
	path := "deliverables/s6-27类收口对账表.md"
	// v7.7.0 十五轮核对修复：防重入护栏改为按阶段内存态（c27Tried）——十二轮的文件标记
	// 会跨阶段污染（s4 代填的表头阻断 s5 的合法代填）。语义：同一阶段一次代填机会
	//（递归重入即 false → 走原拦截）；runStage 启动时重置，回环重跑可再次代填。
	if o.c27Tried[p.ID+"|"+stageID] {
		return false
	}
	if o.c27Tried == nil {
		o.c27Tried = map[string]bool{}
	}
	o.c27Tried[p.ID+"|"+stageID] = true
	existing, rerr := o.exec.ReadFile(p.ID, path)
	var b strings.Builder
	if rerr == nil && strings.TrimSpace(existing) != "" {
		b.WriteString(existing)
		if !strings.HasSuffix(existing, "\n") {
			b.WriteString("\n")
		}
	} else {
		b.WriteString("# 27 类收口对账表\n\n> v7.7.0 P2 引擎代填（权威口径：行数据来自执行卡状态机/覆盖矩阵/验证队列，禁手写数字）；模型只增补归因与证据，不得改五态。\n\n| 键 | 目标 | 处置 | 依据 |\n|---|---|---|---|\n")
	}
	for _, r := range rows {
		b.WriteString(r + "\n")
	}
	if _, werr := o.exec.WriteFile(p.ID, path, b.String()); werr != nil {
		return false
	}
	_, _ = o.store.AddTimeline(&store.TimelineEvent{ProjectID: p.ID, Stage: stageID,
		Event:  "v7.7.0 P2 C27 引擎代填",
		Detail: fmt.Sprintf("%d/%d 缺行键有台账依据已代填（对账表路径 %s）；零依据键交回真实测试", filled, len(missing), path)})
	o.log(p, stageID, fmt.Sprintf("⚙ C27 引擎代填：%d/%d 键按台账落行（绝不造已测）", filled, len(missing)))
	return filled == len(missing)
}
