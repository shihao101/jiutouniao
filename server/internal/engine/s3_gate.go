package engine

// s3_gate.go v6.3.0（S3 修复方案 docs/修复方案_S3威胁建模阶段补全_v6.3.0_20261123.md）：
// ①s3 确定性收口门（S3-①）②判定表目标列共享解析器（S3-②，M2/C27/S6 三处同源防口径漂移）
// ④T-xx 计划承接门（S3-④）⑤端点表↔覆盖矩阵运行时门（S3-⑤，eval/gates/coverage_gate.py V8 同口径上移）。
// 口径与 s2_gate.go 一致：只拦「无产出/无留痕/指针不可达」，不推断判定质量、不自动放行、
// 不改变 production_safe/审批语义；guard 三态开关缺省 true，显式 false 才回退。

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"jiutouniao/internal/config"
	"jiutouniao/internal/store"
)

// ---------- 判定表行共享解析器（S3-②） ----------

// matrixAllTargetsRe 目标列「全目标」声明标记（全项目语义，等价 5 列旧行）。
var matrixAllTargetsRe = regexp.MustCompile(`(?i)全目标|全部目标|全项目|所有目标|all[-_ ]?targets`)

// matrixTargetSplitRe 目标列合并分隔符（中英文逗号/顿号/分号/斜杠/竖线）。
var matrixTargetSplitRe = regexp.MustCompile(`[、，,;；/|]+`)

// matrixRow 判定表行解析结果（目标列感知）。
type matrixRow struct {
	class   string   // C-xx（matrixClassRe 首列）
	targets []string // 6 列行的目标列 canonical 键集合；nil = 5 列旧行（未落目标粒度/全项目语义）
	verdict string   // 假设/不适用/待判定；"" = 无三态判定格
	line    string
}

// matrixRowCells 拆 markdown 表格行单元格（容错无尾竖线形态）。
func matrixRowCells(line string) []string {
	parts := strings.Split(line, "|")
	if len(parts) < 2 {
		return nil
	}
	if strings.TrimSpace(parts[0]) == "" {
		parts = parts[1:]
	}
	if len(parts) > 0 && strings.TrimSpace(parts[len(parts)-1]) == "" {
		parts = parts[:len(parts)-1]
	}
	cells := make([]string, len(parts))
	for i, p := range parts {
		cells[i] = strings.TrimSpace(p)
	}
	return cells
}

// parseMatrixRows 解析判定表行：首列 C-xx；≥6 列行提取第 2 列为目标列（「全目标」标记或
// 空 token 不拆分、保持全项目语义）。M2（orchestrator）/C27/S6 对账表（fixplan_gate）共用。
func parseMatrixRows(raw string) []matrixRow {
	var rows []matrixRow
	for _, line := range strings.Split(raw, "\n") {
		m := matrixClassRe.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		row := matrixRow{class: m[1], line: line}
		if vm := matrixVerdictRe.FindStringSubmatch(line); vm != nil {
			row.verdict = vm[1]
		}
		if cells := matrixRowCells(line); len(cells) >= 6 {
			for _, tok := range matrixTargetSplitRe.Split(cells[1], -1) {
				tok = strings.TrimSpace(strings.Trim(tok, "（）()"))
				if tok == "" || matrixAllTargetsRe.MatchString(tok) {
					continue
				}
				row.targets = append(row.targets, canonicalTargetKey(tok))
			}
		}
		rows = append(rows, row)
	}
	return rows
}

// matrixNeedKeys 从判定表行集推导「需投递」键集合（假设/待判定行）：
// 6 列行 → 每目标一个复合键 class@target；5 列旧行 → 项目级键 class（与 C27 旧口径兼容）。
// v6.4.0（S4-①）singleTarget 豁免：单目标项目一律坍缩为项目级键——实测单目标项目按 6 列
// 标准格式输出时第 2 列可能是触发面描述（某历史任务），按其拆复合键会让 coverage/VT
// 留痕必须同现触发面原文才记 tested，必然误拦；与 matrixTargetClassIssues 的单目标豁免
// （s3_gate.go 上方）同口径对齐，堵住「多目标有保护、C27 无保护」的豁免缺口。
func matrixNeedKeys(rows []matrixRow, singleTarget bool) map[string]bool {
	need := map[string]bool{}
	for _, r := range rows {
		if r.verdict != "假设" && r.verdict != "待判定" {
			continue
		}
		if singleTarget || len(r.targets) == 0 {
			need[r.class] = true
			continue
		}
		for _, tk := range r.targets {
			need[r.class+"@"+tk] = true
		}
	}
	return need
}

// matrixKeyMatches 复合键与语料/行文本匹配：项目级键只查类编号；复合键要求类编号与目标
// 同时出现在同一段文本（单条 coverage/VT/对账表行内同现，防 A 目标的留痕释放 B 目标的类）。
func matrixKeyMatches(key, text string) bool {
	cls, tgt := key, ""
	if i := strings.Index(key, "@"); i >= 0 {
		cls, tgt = key[:i], key[i+1:]
	}
	if !strings.Contains(text, cls) {
		return false
	}
	if tgt == "" {
		return true
	}
	return strings.Contains(normCovText(text), normCovText(tgt))
}

// matrixLineKeys 对账表/判定表行派生键：6 列行按目标列逐 token 生成复合键，5 列行项目级键。
// v6.4.0（S4-①）singleTarget 豁免：单目标项目一律项目级键（与 matrixNeedKeys 同口径）。
func matrixLineKeys(r matrixRow, singleTarget bool) []string {
	if singleTarget || len(r.targets) == 0 {
		return []string{r.class}
	}
	keys := make([]string, 0, len(r.targets))
	for _, tk := range r.targets {
		keys = append(keys, r.class+"@"+tk)
	}
	return keys
}

// matrixTargetClassIssues S3-② 多目标 (类×目标) 覆盖完备性（guard enforce_target_class_matrix）：
// 多目标项目下「假设/待判定」判定必须落到目标粒度（6 列行），每类覆盖的目标并集（含不适用
// 全目标声明）⊇ 项目目标集；目标列 token 必须可匹配项目目标。单目标项目零影响。
func matrixTargetClassIssues(p *store.Project, rows []matrixRow) []string {
	targets := splitProjectTargets(p)
	if len(targets) <= 1 {
		return nil
	}
	needTarget := map[string]bool{}
	for _, t := range targets {
		if k := canonicalTargetKey(t); k != "" {
			needTarget[k] = true
		}
	}
	covered := map[string]map[string]bool{}
	grainless := map[string]bool{}
	var unmatched []string
	for _, r := range rows {
		cm, ok := covered[r.class]
		if !ok {
			cm = map[string]bool{}
			covered[r.class] = cm
		}
		if len(r.targets) == 0 {
			if r.verdict == "假设" || r.verdict == "待判定" {
				grainless[r.class] = true // 多目标下 5 列假设行不得代表全部目标
			} else {
				for k := range needTarget {
					cm[k] = true // 不适用旧行 = 全目标声明
				}
			}
			continue
		}
		for _, tk := range r.targets {
			if !needTarget[tk] {
				unmatched = append(unmatched, r.class+"("+tk+")")
				continue
			}
			cm[tk] = true
		}
	}
	var issues []string
	if len(grainless) > 0 {
		ids := make([]string, 0, len(grainless))
		for id := range grainless {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		issues = append(issues, fmt.Sprintf(
			"v6.3.0 判定表目标列门：%d 个类的假设/待判定行未落目标粒度（%s）——多目标项目须按 6 列格式逐目标判定（同判定同证据可合并一行：目标列逗号分隔），不适用可一行全目标声明",
			len(ids), truncateText(strings.Join(ids, ","), 140)))
	}
	if len(unmatched) > 0 {
		issues = append(issues, fmt.Sprintf(
			"v6.3.0 判定表目标列门：%d 个目标列 token 无法匹配项目目标（%s）——目标列须写项目目标（可省 scheme/路径），或用「全目标」声明",
			len(unmatched), truncateText(strings.Join(unmatched, ","), 140)))
	}
	var missingPairs []string
	for cls, cm := range covered {
		var miss []string
		for k := range needTarget {
			if !cm[k] {
				miss = append(miss, k)
			}
		}
		if len(miss) > 0 {
			sort.Strings(miss)
			missingPairs = append(missingPairs, cls+" 缺 "+strings.Join(miss, ","))
		}
	}
	if len(missingPairs) > 0 {
		sort.Strings(missingPairs)
		issues = append(issues, fmt.Sprintf(
			"v6.3.0 判定表目标列门：%d 个类的 (类×目标) 覆盖不全（%s）——高信号目标的证据不得代表其余目标，逐目标补判定行（不适用须附核查证据）",
			len(missingPairs), truncateText(strings.Join(missingPairs, "；"), 160)))
	}
	return issues
}

// ---------- S3-① s3 确定性收口门 ----------

// threatIDRe TH 编号（威胁清单结构化对账键，S4-10 回填消费）。
var threatIDRe = regexp.MustCompile(`TH-\d+`)

// threatLevelRe 威胁等级标注（P1-P4 刻度或等级/级别字段，hypothesis-matrix 第六节）。
var threatLevelRe = regexp.MustCompile(`P[1-4]|等级|级别`)

// planTIDRe 测试计划条目编号。
var planTIDRe = regexp.MustCompile(`\bT-\d+\b`)

// checklistRefRe 已废弃（v6.4.0 S4-⑫）：`\bC-?\d+\b` 双编号空间共用导致计划引用判定表
// C-xx 即误放行门⑤——改为从 checklist.json 加载真实条目 id 精确匹配（s3ClosureIssues ⑤）。

// matrixEvidenceRefRe 判定表证据指针（evidence/ 路径）。
var matrixEvidenceRefRe = regexp.MustCompile(`evidence/[A-Za-z0-9_\-./]+`)

// s3ClosureIssues S3-① 收口确定性校验（complete_stage 前置门与 deterministicGate s3 分支共用）：
// ①判定表存在非空壳 ②威胁模型存在且含 TH 编号 ③测试计划存在且含 T-xx 编号与审批点
// ④候选清单承接二选一留痕 ⑤checklist.json 存在时计划须有条目引用。
// 口径：只查存在性/结构化锚点与承接留痕，不判定内容质量（质量归反思门）。
func (o *Orchestrator) s3ClosureIssues(p *store.Project) []string {
	issues := []string{}
	// ① 判定表非空壳（行格式由 M2 校验，此处与 s2 门 <40 字节口径一致补存在性双保险）
	if raw, err := o.exec.ReadFile(p.ID, "deliverables/s3-筛查矩阵判定表.md"); err != nil || len(strings.TrimSpace(raw)) < 40 {
		issues = append(issues, "收口被拦截（S3 确定性门）：缺少或内容为空：deliverables/s3-筛查矩阵判定表.md——load_skill hypothesis-matrix 按 27 类三态判定后重写（M2 门机械校验）。")
	}
	// ② 威胁模型存在 + TH 编号（S4-10 extends/replaces/creates 回填与判定表末列挂接的对账键）
	// v6.3.0 补强（S3-⑦②/S3-⑨①）：拓扑重建引用核存（S2-11 契约从提示词约定变可验证）+
	// 等级标注校验（P1-P4 刻度，PTES 威胁量化锚点——与 TH 校验合并，不单独加门）。
	thRaw, thErr := o.exec.ReadFile(p.ID, "deliverables/s3-威胁模型.md")
	if thErr != nil || len(strings.TrimSpace(thRaw)) < 40 {
		issues = append(issues, "收口被拦截（S3 确定性门）：缺少或内容为空：deliverables/s3-威胁模型.md（DFD+威胁清单）——s3.md S3-1/S3-2 产出后重收口。")
	} else {
		if !threatIDRe.MatchString(thRaw) {
			issues = append(issues, "收口被拦截（S3 确定性门）：威胁模型无 TH 编号（TH-01..TH-nn）——威胁清单未结构化，S4-10 实测回填与判定表挂接失去对账键，逐条编号后重收口。")
		}
		if _, terr := o.exec.ReadFile(p.ID, "deliverables/拓扑重建-V1.md"); terr == nil && !strings.Contains(thRaw, "拓扑重建") {
			issues = append(issues, "收口被拦截（S3 确定性门）：S2 已产出《拓扑重建-V1.md》但威胁模型未引用其作 DFD 校准输入——按 s3.md S3-1 逐组件核对四源证据（响应头/错误页/JS 内网引用/多端口差分）后在威胁模型注明校准结论。")
		}
		if threatIDRe.MatchString(thRaw) && !threatLevelRe.MatchString(thRaw) {
			issues = append(issues, "收口被拦截（S3 确定性门）：威胁清单 TH 条目无等级标注（P1-P4 刻度）——按 hypothesis-matrix 第六节刻度逐条标注（可能性 L1-L3 × 影响 I1-I3），S8 报告定级据此回溯。")
		}
	}
	// ③ 测试计划存在 + T-xx 编号 + 审批点（S3-5/S3-7 锚点）
	planRaw, planErr := o.exec.ReadFile(p.ID, "deliverables/s3-测试计划.md")
	planMissing := planErr != nil || len(strings.TrimSpace(planRaw)) < 40
	if planMissing {
		issues = append(issues, "收口被拦截（S3 确定性门）：缺少或内容为空：deliverables/s3-测试计划.md——s3.md S3-5 产出（手段/工具/AI 角色/预期输出/审批点/回滚/时间窗，条目编号 T-xx）后重收口。")
	} else {
		if !planTIDRe.MatchString(planRaw) {
			issues = append(issues, "收口被拦截（S3 确定性门）：测试计划无 T-xx 条目编号——计划条目统一编号后重收口（T-xx 由 S4 开工对账表逐条承接，planHandover 门按此对账）。")
		}
		if !strings.Contains(planRaw, "审批") {
			issues = append(issues, "收口被拦截（S3 确定性门）：测试计划无审批点标注——S3-7 L2 动作须在计划中标注审批列并用 request_approval 预请求（审批与预算竞态教训）。")
		}
	}
	// ④ 候选清单承接留痕（S3-6 兜底从「不可核验的空话」变为两种可机械区分的合法形态）
	if candRaw, cerr := o.exec.ReadFile(p.ID, "deliverables/s2-已知漏洞候选清单.md"); cerr == nil && strings.TrimSpace(candRaw) != "" {
		if !planMissing && !strings.Contains(planRaw, "CVE-") && !strings.Contains(planRaw, "候选清单") {
			issues = append(issues, "收口被拦截（S3 确定性门）：S2 已产出《已知漏洞候选清单》但测试计划无对照层（无 CVE- 引用也无「候选清单」合并记录）——按 s3.md S3-6 生成《已知漏洞测试项》编入优先级队列（禁凭记忆虚构 CVE）。")
		}
	} else if !planMissing && !strings.Contains(planRaw, "S2 未产出候选清单") {
		issues = append(issues, "收口被拦截（S3 确定性门）：S2 候选清单缺失且测试计划无显式声明行「S2 未产出候选清单」——按 s3.md S3-6 二选一：合并清单生成对照层，或写明缺失声明与原因。")
	}
	// ⑤ checklist.json（自述面覆盖下限）在排期形成点的承接留痕
	// v6.4.0（S4-⑫）编号空间分离：原 checklistRefRe `\bC-?\d+\b` 同时命中 checklist 条目 id
	//（C1/C-01）与 27 类编号（C-01..C-27）——计划引用判定表 C-xx（几乎必然）即误放行。
	// 改为加载真实条目 id 集合做精确 token 匹配，两个编号空间不再混用。
	if raw, rerr := o.exec.ReadFile(p.ID, "checklist.json"); rerr == nil && strings.TrimSpace(raw) != "" {
		if items := parseChecklistItems(raw); len(items) > 0 && !planMissing {
			ids := map[string]bool{}
			for _, it := range items {
				if id := strings.TrimSpace(it.ID); id != "" {
					ids[normCovText(id)] = true
				}
			}
			nc := normCovText(planRaw)
			ref := false
			for id := range ids {
				if strings.Contains(nc, id) {
					ref = true
					break
				}
			}
			if !ref {
				issues = append(issues, "收口被拦截（S3 确定性门）：checklist.json（目标自述面清单）存在但测试计划零条目引用——自述面是覆盖下限（S2-9），按 s3.md S3-8 逐条 read_file 排期（无法排期条目显式标 deferred），S4/S5 G2 门按此对账（引用须使用清单真实条目 id，C-01..C-27 类编号不算条目引用）。")
			}
		}
	}
	// ⑥ v6.4.0（S4-②）端点表生产端契约：evidence/*endpoints*.txt（S4 authz-diff 全量覆盖率
	// 硬门 v5.1 与 endpointMatrix 门 S3-⑤ 的唯一结构化输入）存在，或计划含显式
	// 「未产出端点表」声明——二者必居其一。原实现消费端有门、生产端无门：S3 不产出端点表时
	// v5.1 硬门静默失效（endpointMatrixIssues 对 eps==0 直接放行）。纯内网/无 API 面项目走
	// 声明形态，零误拦。
	if !planMissing && o.guardEnabled(func(g *config.GuardConfig) *bool { return g.EnforceS3EndpointTable }) {
		epsRows := 0
		epsTotal := 0 // 带 # total=N 注记的文件数（v6.4.0 S4-②：表在而无 total 注记 → 非拦截提示）
		if names, derr := o.exec.ListDir(p.ID, "evidence"); derr == nil {
			for _, rel := range names {
				if !strings.Contains(rel, "endpoints") || !strings.HasSuffix(rel, ".txt") {
					continue
				}
				if raw, rerr := o.exec.ReadFile(p.ID, rel); rerr == nil {
					hasTotal := false
					for _, line := range strings.Split(raw, "\n") {
						t := strings.TrimSpace(line)
						if strings.HasPrefix(t, "#") && endpointTotalRe.MatchString(t) {
							hasTotal = true
							continue
						}
						if strings.HasPrefix(t, "/") && !strings.HasPrefix(t, "//") {
							epsRows++
						}
					}
					if hasTotal {
						epsTotal++
					}
				}
			}
		}
		if epsRows == 0 && !strings.Contains(planRaw, "未产出端点表") {
			issues = append(issues, "收口被拦截（S3 确定性门）：端点表 evidence/s3-api-endpoints.txt 缺失且测试计划无显式声明——S4 authz-diff 全量覆盖率硬门（v5.1）与端点表↔矩阵门以此为唯一结构化输入。按 intel-factory 四件套产出端点表（/ 前缀路径+参数名，表尾 # total=N），或确无 API 面（纯内网/纯静态）时在计划写明「未产出端点表：<原因>」后重收口。")
		} else if epsRows > 0 && epsTotal == 0 {
			// 方案 S4-②①：文件在而 # total=N 缺失 → 降级为提示（不拦，与 S3-⑤ total 对账口径衔接）
			o.log(p, "s3", "💡 [端点表提示] evidence/*endpoints*.txt 已产出但无 # total=N 注记——S4 端点表↔矩阵门按行数对账，运行中新增端点行时同步更新表尾计数（intel-factory 四件套约定）")
		}
	}
	return issues
}

// ---------- S3-④ T-xx 计划承接门 ----------

// planHandoverIssues S3-④：s3-测试计划条目（T-xx）在 S4 收口前必须显式归宿——执行（coverage/
// 对账表引用）/移交（VT 引用）/作废（对账表行标注），四处语料均无引用的条目拦截。
// 兼容：计划缺失（旧项目/门关闭）放行；条目解析上限 50 防异常大表。
func (o *Orchestrator) planHandoverIssues(p *store.Project) []string {
	planRaw, err := o.exec.ReadFile(p.ID, "deliverables/s3-测试计划.md")
	if err != nil {
		return nil // 无计划（旧项目）：S3-① 在 s3 收口已拦截，此处不重复报
	}
	seen := map[string]bool{}
	var ids []string
	for _, id := range planTIDRe.FindAllString(planRaw, -1) {
		if !seen[id] {
			seen[id] = true
			ids = append(ids, id)
		}
		if len(ids) >= 50 {
			break
		}
	}
	if len(ids) == 0 {
		return nil
	}
	// v6.4.0（S4-⑧）：逐类对账表行完整性——兑现 s4.md:90「行数=假设/待判定类总数，缺行即
	// 拦截」承诺（原实现无独立校验：对账表只作为 planHandover/C27 语料被被动消费，其自身
	// 行完整性无人核对，漏类既不在表里也可能无留痕）。解析复用判定表共享解析器（含 S4-①
	// 单目标豁免与行首格容差），不新造第二套列格式假设。
	singleTarget := len(splitProjectTargets(p)) <= 1
	if judgeRaw, jerr := o.exec.ReadFile(p.ID, "deliverables/s3-筛查矩阵判定表.md"); jerr == nil {
		if need := matrixNeedKeys(parseMatrixRows(judgeRaw), singleTarget); len(need) > 0 {
			rawRecon, rerr := o.exec.ReadFile(p.ID, "deliverables/s4-逐类对账表.md")
			if rerr != nil || len(strings.TrimSpace(rawRecon)) < 40 {
				return []string{"v6.4.0 逐类对账表门：缺少 deliverables/s4-逐类对账表.md——s4.md S4-9/v6.0.5 开工对账义务（每行 `C-xx | 目标 | 技能 | endpoint | 首探针 | T-xx | outcome`，outcome 五态 tested/blocked/deferred/exempted/queued），开工对账后重收口"}
			}
			covered := map[string]bool{}
			for _, r := range parseMatrixRows(rawRecon) {
				for _, key := range matrixLineKeys(r, singleTarget) {
					covered[key] = true
				}
			}
			var missingRows []string
			for key := range need {
				if !covered[key] {
					missingRows = append(missingRows, key)
				}
			}
			if len(missingRows) > 0 {
				sort.Strings(missingRows)
				return []string{fmt.Sprintf(
					"v6.4.0 逐类对账表门：对账表缺 %d 行（%s）——行数须覆盖判定表全部假设/待判定键（s4.md:90 缺行即拦截），补行（outcome 五态）或在对账表显式标注该类归宿后重收口",
					len(missingRows), truncateText(strings.Join(missingRows, ","), 140))}
			}
		}
	}
	var corpus strings.Builder
	if raw, rerr := o.exec.ReadFile(p.ID, "deliverables/s4-逐类对账表.md"); rerr == nil {
		corpus.WriteString(raw)
		corpus.WriteString("\x00")
	}
	if cov, cerr := o.store.ListCoverage(p.ID); cerr == nil {
		for _, c := range cov {
			fmt.Fprintf(&corpus, "%s\x00%s\x00%s\x00%s\x00", c.Endpoint, c.Param, c.VulnClass, c.Notes)
		}
	}
	if vts, verr := o.store.ListVTs(p.ID); verr == nil {
		for _, t := range vts {
			fmt.Fprintf(&corpus, "%s\x00%s\x00%s\x00%s\x00", t.Title, t.StartConditions, t.Note, t.ResultRef)
		}
	}
	// 交付物语料（排除计划自身——计划文本必然含全部 T 编号，自包含会让承接门永不触发；
	// 上限 60 文件与 deliverablesText 口径一致）
	if names, derr := o.exec.ListDir(p.ID, "deliverables"); derr == nil {
		n := 0
		for _, rel := range names {
			if rel == "deliverables/s3-测试计划.md" || n >= 60 {
				continue
			}
			if !strings.HasSuffix(rel, ".md") && !strings.HasSuffix(rel, ".txt") && !strings.HasSuffix(rel, ".json") {
				continue
			}
			if rawText, rerr := o.exec.ReadFile(p.ID, rel); rerr == nil {
				corpus.WriteString(rawText)
				corpus.WriteString("\x00")
				n++
			}
		}
	}
	nc := normCovText(corpus.String())
	var missing []string
	for _, id := range ids {
		if !strings.Contains(nc, normCovText(id)) {
			missing = append(missing, id)
		}
	}
	if len(missing) == 0 {
		return nil
	}
	return []string{fmt.Sprintf(
		"v6.3.0 T-xx 计划承接门：%d/%d 条测试计划条目在 S4 无归宿留痕（%s）——逐条三选一：执行（update_coverage 或逐类对账表行引 T-xx）/移交（record_vt detail 引 T-xx）/作废（对账表该行标注作废理由）；计划条目静默蒸发与 C27 类级跳过同源（v6.0.1 实证形态）",
		len(missing), len(ids), truncateText(strings.Join(missing, ","), 140))}
}

// ---------- S3-⑤ 端点表↔覆盖矩阵运行时门 ----------

// endpointTotalRe 端点表尾 `# total=N` 完成度注记（intel-factory 四件套约定）。
var endpointTotalRe = regexp.MustCompile(`#\s*total\s*=\s*(\d+)`)

// endpointPathRe markdown 表格行内 / 前缀路径 token（与 coverage_gate.py 来源②同款）。
var endpointPathRe = regexp.MustCompile(`(/[A-Za-z0-9_][A-Za-z0-9_./-]*)`)

// endpointMatrixAuthzRe 鉴权差分矩阵类 coverage 单元判定（与 coverage_gate.py AUTHZ_CLASS_RE 同源）。
var endpointMatrixAuthzRe = regexp.MustCompile(`(?i)(鉴权|authz|未授权|越权|blsa|bfla)`)

// endpointMatrixIssues S3-⑤（guard enforce_endpoint_matrix）：v5.1 端点表 100% 入矩阵硬门的
// 运行时执行层——原实现在 eval/gates/coverage_gate.py 仅离线复盘可达，生产收口不拦。
// 口径：端点表不存在（无 API 面/旧项目）放行；total 注记与行数不符先拦；缺口行无三态
// 处置（coverage authz 单元或交付物对账语料引用）拦截。
func (o *Orchestrator) endpointMatrixIssues(p *store.Project) []string {
	if o.cfg == nil {
		return nil // 测试装配/降级态：工作区根不可得（与 M4 日期门同口径跳过）
	}
	root := o.workspaceRoot(p.ID)
	var eps []string
	// 来源①：evidence/*endpoints*.txt（含 s3-api-endpoints.txt）+/ 开头行 + total 一致性
	evFiles, _ := filepath.Glob(filepath.Join(root, "evidence", "*endpoints*.txt"))
	sort.Strings(evFiles)
	for _, fp := range evFiles {
		raw, err := os.ReadFile(fp)
		if err != nil {
			continue
		}
		rows := 0
		total := -1
		for _, line := range strings.Split(string(raw), "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "#") {
				if m := endpointTotalRe.FindStringSubmatch(line); m != nil {
					fmt.Sscanf(m[1], "%d", &total)
				}
				continue
			}
			if strings.HasPrefix(line, "/") && !strings.HasPrefix(line, "//") {
				eps = append(eps, line)
				rows++
			}
		}
		if total >= 0 && rows != total {
			return []string{fmt.Sprintf(
				"v6.3.0 端点表↔矩阵门：%s 行数与 # total 注记不符（rows=%d total=%d）——运行中新增端点行时同步更新表尾计数（intel-factory 四件套约定），补齐后重收口",
				filepath.Base(fp), rows, total)}
		}
	}
	// 来源②：deliverables/*端点表*.md / *endpoints*.md 表格行
	var mdFiles []string
	mdFiles = append(mdFiles, mustGlob(filepath.Join(root, "deliverables", "*端点表*.md"))...)
	mdFiles = append(mdFiles, mustGlob(filepath.Join(root, "deliverables", "*endpoints*.md"))...)
	sort.Strings(mdFiles)
	for _, fp := range mdFiles {
		raw, err := os.ReadFile(fp)
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(raw), "\n") {
			if !strings.HasPrefix(strings.TrimSpace(line), "|") {
				continue
			}
			for _, tok := range endpointPathRe.FindAllString(line, -1) {
				tok = strings.TrimSuffix(strings.Split(tok, "?")[0], "/")
				if strings.Count(tok, "/") >= 1 && len(tok) > 1 {
					eps = append(eps, tok)
				}
			}
		}
	}
	if len(eps) == 0 {
		// v6.4.0（S4-②）：无端点表不再静默放行——计划/交付物语料须有「未产出端点表」显式
		// 声明（S3-② 生产端契约的 S4 侧兜底；无声明 = v5.1 硬门失去输入却无人知情）。
		if strings.Contains(normCovText(o.deliverablesText(p.ID)), normCovText("未产出端点表")) {
			// 方案 S4-②②：声明形态合法豁免，但输出提示级留痕（非拦截）——下游可见豁免依据
			o.log(p, "s4", "💡 [端点表豁免] 本项目无端点表，按计划「未产出端点表」声明放行端点表↔矩阵门（v5.1 硬门无输入）")
			return nil
		}
		return []string{"v6.4.0 端点表↔矩阵门：端点表缺失且无「未产出端点表」显式声明（S3 确定性门⑥）——v5.1 全量未授权检测硬门失去输入，回 S3 补产 evidence/s3-api-endpoints.txt（/ 前缀路径+表尾 # total=N）或在测试计划写明声明后重收口"}
	}
	uniq := map[string]bool{}
	for _, e := range eps {
		uniq[normCovText(e)] = true
	}
	cov, _ := o.store.ListCoverage(p.ID)
	var authzEps []string
	for _, c := range cov {
		if endpointMatrixAuthzRe.MatchString(c.VulnClass) {
			// v6.4.0（S4-⑫）：coverage 侧同步归一（去查询串/尾斜杠）——"GET /api/user?id=1"
			// 的登记对端点表 token "/api/user" 的后缀匹配不被查询串破坏。
			ne := normCovText(store.NormCoverageEndpoint(c.Endpoint))
			if i := strings.Index(ne, "?"); i >= 0 {
				ne = ne[:i]
			}
			authzEps = append(authzEps, strings.TrimSuffix(ne, "/"))
		}
	}
	if len(authzEps) == 0 {
		return []string{fmt.Sprintf(
			"v6.3.0 端点表↔矩阵门：端点表存在（%d 行，evidence/*endpoints*.txt）但鉴权差分矩阵未执行——v5.1 全量未授权检测硬门：无 token 列纯匿名、禁止推迟/抽样（authz-diff 第五节，load_skill authz-diff）",
			len(uniq))}
	}
	var missing []string
	covered := 0
	for e := range uniq {
		hit := false
		for _, a := range authzEps {
			// v6.4.0（S4-⑫）：归一化后精确/后缀匹配——原 `strings.Contains(a, e)` 子串包含
			// 会把 /api/user 判为已被 /api/user/admin 的覆盖登记命中（缺口被低估），与
			// s1_gates.go F-14 审计弃用子串匹配的结论对齐。
			if a == e || strings.HasSuffix(a, e) {
				hit = true
				break
			}
		}
		if !hit {
			// 交付物对账语料兜底：缺口行三态处置（待续清单/对账表引用端点路径）
			if strings.Contains(normCovText(o.deliverablesText(p.ID)), e) {
				hit = true
			}
		}
		if hit {
			covered++
		} else {
			missing = append(missing, e)
		}
	}
	if len(missing) == 0 {
		return nil
	}
	sort.Strings(missing)
	shown := missing
	if len(shown) > 5 {
		shown = shown[:5]
	}
	return []string{fmt.Sprintf(
		"v6.3.0 端点表↔矩阵门：覆盖率缺口 diffed=%d/total=%d——缺如 %v（v5.1 硬门：100%% 入矩阵+diffed/total 记账，缺口行须三态处置或写入待续清单；离线门 coverage_gate.py 同口径双保险）",
		covered, len(uniq), shown)}
}

// mustGlob glob 容错封装（模式无匹配返回空切片）。
func mustGlob(pattern string) []string {
	out, err := filepath.Glob(pattern)
	if err != nil {
		return nil
	}
	return out
}
