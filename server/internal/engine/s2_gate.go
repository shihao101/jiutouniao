package engine

// s2_gate.go v6.2.0（S2 修复方案①）：s2 确定性收口门。
// S2 是 S3 威胁建模（S3-1 DFD 校准/S3-6 候选清单合并/S3-9 既有证据判定）与 S4 覆盖对账的
// 一等输入源，此前是唯一没有确定性收口门的执行阶段（反思 PASS 无条件名单 s1/s3/s4/s5/s7/s8
// 不含 s2，收口仅查「阶段内新增过文件」）。本门只拦「无产出/坏留痕/目标未归宿」，
// 不推断测试质量、不自动放行、不改变 production_safe/审批语义。
// checklist.json 特殊点：S4/S5 G2 门对坏 JSON 是 fail-open（parseChecklistItems 解析失败
// 按空清单处理、门静默失效）——本门在源头 fail-closed，坏 JSON 在 S2 收口当轮拦截。

import (
	"fmt"
	"path/filepath"
	"regexp"
	"strings"

	"jiutouniao/internal/config"
	"jiutouniao/internal/store"
	"jiutouniao/internal/tools"
)

// s2RequiredDeliverables S2 收口必查交付物（固定路径与 heads/s2.md 交付物节同源；
// v6.2.0 S2-④ 定路径）。checklist.json 为条件必做（无自述面目标合法缺失），不在此列——
// 存在时由 ② 校验可解析性。
var s2RequiredDeliverables = []string{
	"deliverables/s2-攻击面地图.md",
	"deliverables/拓扑重建-V1.md",
}

// s2ClosureIssues ①：S2 收口确定性校验：
// ①攻击面地图/拓扑重建存在且非空壳（与 s1 四件套同口径，<40 字节视为占位）；
// ②checklist.json 存在时必须可解析（fail-closed——坏 JSON 让 S4/S5 覆盖下限门静默失效）；
// ③多目标逐目标归宿对账（覆盖/资产/交付物语料，含待续清单与档案目标显式归宿）。
// 由 complete_stage 前置门与 deterministicGate（s2 进入无条件名单）共同调用。
func (o *Orchestrator) s2ClosureIssues(p *store.Project) []string {
	issues := []string{}
	for _, f := range s2RequiredDeliverables {
		raw, err := o.exec.ReadFile(p.ID, f)
		if err != nil || len(strings.TrimSpace(raw)) < 40 {
			issues = append(issues, fmt.Sprintf("收口被拦截（S2 确定性门）：缺少或内容为空：%s（须为实质内容，不接受占位空壳）——按 heads/s2.md 交付物节补齐后重试。", f))
		}
	}
	// v7.6.0（A7 覆盖度记账治理）：S2 收口最低覆盖行校验——强制纪律③「测完必记覆盖度矩阵」
	// 的机械兜底：实证某项目 S2 仅 6 行、S1 为空（反思门建议两轮未闭环，实测报告 §A7）。
	// S2 侦察动作（端口/指纹/路径普查/接口清单/CVE 预检索）每项都是 endpoint×漏洞类单元，
	// 零行=纪律未落实。
	// 触发条件收敛（测试与降级态友好）：仅当项目确有侦察活动痕迹（S1 已登记资产 或 evidence/
	// 存在 s2-* 侦察证据文件）时才校验——纯模板/无活动项目不误拦。
	hasReconActivity := false
	if assets, aerr := o.store.ListAssets(p.ID); aerr == nil && len(assets) > 0 {
		hasReconActivity = true
	}
	if !hasReconActivity {
		if evs, _ := filepath.Glob(filepath.Join(o.workspaceRoot(p.ID), "evidence", "s2-*")); len(evs) > 0 {
			hasReconActivity = true
		}
	}
	if cov, err := o.store.ListCoverage(p.ID); err == nil && hasReconActivity {
		s2Rows := 0
		for _, c := range cov {
			if c.Stage == "s2" {
				s2Rows++
			}
		}
		if s2Rows == 0 {
			issues = append(issues, "v7.6.0 S2 覆盖度矩阵为空（A7 记账治理，强制纪律③）——已执行的侦察面（端口/指纹/路径普查/接口清单/CVE 预检索）应逐项落 endpoint×漏洞类 单元。【修复示例】update_coverage{endpoint:\"tcp/443\", vuln_class:\"服务暴露\", status:\"no_issue_found\", observed_result:\"negative_valid\", notes:\"TLS 实测…\"}——按实际执行面补记后重收口")
		}
	}
	// ② checklist.json 存在时必须可解析——S2-9 自校验的引擎级兜底。
	if raw, rerr := o.exec.ReadFile(p.ID, "checklist.json"); rerr == nil && strings.TrimSpace(raw) != "" {
		if len(parseChecklistItems(raw)) == 0 {
			issues = append(issues, "收口被拦截（S2 确定性门）：checklist.json 存在但不可解析（需 {\"items\":[{\"id\",\"item\",\"class\",…}]} 或裸数组形态）——坏 JSON 会让 S4/S5 自述面对账（G2）静默失效，请按 s2.md S2-9 修复该文件（或确认无自述面时删除后重收口）。")
		}
	}
	// ③ 多目标逐目标归宿：与 S4 分段收口对账同族（targetCoverageRecon；matched>=2 才拦——
	// 整项目零覆盖是另一类失败模式，由提示词纪律与轮次止损兜底；matched>=2 说明已按目标
	// 推进过，剩余目标静默蒸发即拦截）。档案目标/待续清单在交付物语料中显式归宿即放行。
	if o.cfg == nil || o.cfg.Engine.PerTargetRounds > 0 {
		targets := splitProjectTargets(p)
		if len(targets) > 1 {
			var cb strings.Builder
			if cov, _ := o.store.ListCoverage(p.ID); len(cov) > 0 {
				for _, c := range cov {
					cb.WriteString(c.Endpoint)
					cb.WriteString("\x00")
					cb.WriteString(c.Param)
					cb.WriteString("\x00")
					cb.WriteString(c.VulnClass)
					cb.WriteString("\x00")
					cb.WriteString(c.Notes)
					cb.WriteString("\x00")
				}
			}
			if assets, _ := o.store.ListAssets(p.ID); len(assets) > 0 {
				for _, a := range assets {
					cb.WriteString(a.Value)
					cb.WriteString("\x00")
					if a.Detail != "" {
						cb.WriteString(a.Detail)
						cb.WriteString("\x00")
					}
				}
			}
			missing, matched := targetCoverageRecon(targets, cb.String(), o.deliverablesText(p.ID))
			if matched >= 2 && len(missing) > 0 {
				issues = append(issues, fmt.Sprintf(
					"S2 逐目标对账：%d/%d 个目标无覆盖登记、无资产记录、未列入交付物（含待续清单/档案目标）（%s）——多目标项目 S2 必须逐目标产出攻击面结论；确属本轮无法覆盖的写入待续清单，或按 s2.md S2-5 档案目标硬判据降级留痕，再收口",
					len(missing), len(targets), truncateText(strings.Join(missing, "、"), 120)))
			}
		}
	}
	// ④ 步骤计划完整性（v6.3.2，实战 某历史任务 缺口）：S2 开工须逐步骤建立 S2-1..S2-11
	// 子任务（含条件必做与不适用步骤——登记后显式关闭并注原因），禁止漏排。实战实证：S2-2
	// OSINT/S2-4 凭据泄露/S2-6 AI 入口漏排后整段未执行且报告出现未经尝试的受限结论。
	// 只查标题留痕不查执行质量；单条子任务可合并多步骤（标题含多个编号均可命中）。
	subs, _ := o.store.ListSubtasks(p.ID)
	joined := make([]string, 0, len(subs))
	for _, s := range subs {
		joined = append(joined, s.Title)
	}
	subTitles := strings.Join(joined, "\n")
	missingSteps := []string{}
	for i := 1; i <= 11; i++ {
		tag := fmt.Sprintf("S2-%d", i)
		if !strings.Contains(subTitles, tag) {
			missingSteps = append(missingSteps, tag)
		}
	}
	if len(missingSteps) > 0 {
		issues = append(issues, fmt.Sprintf(
			"收口被拦截（S2 确定性门）：子任务计划缺步骤 %s——按 s2.md 开工纪律用 plan_subtasks 逐步骤登记 S2-1..S2-11（含条件必做 S2-9 与不适用步骤：登记后 update_subtask 显式关闭并注明原因），禁止漏排后收口。",
			strings.Join(missingSteps, "、")))
	}
	return issues
}

// ---- ② 批量通道逐目标范围门 ----

// batchScopeToolRe 批量扫描器工具名单（与 W5 行为预算器 batchCmdRe 同族口径——
// 仅这些工具的 `-l/-iL/--file` 才视作目标清单参数）。
const batchScopeToolRe = `(?i)(?:^|[|;&]\s*)(?:httpx|nuclei|gobuster|dirsearch|ffuf|feroxbuster|masscan|arjun|wfuzz|naabu|nmap|subfinder|amass|testssl|wafw00f|whatweb)\b[^\n|;&]*?`

// batchToolTargetFileRe v6.3.2：工具域限定版目标清单提取——`httpx -l targets.txt`/`nmap -iL list`
// 匹配；`wc -l <file>`/`grep -l`/`ls -l` 等通用旗标不匹配（实战误拦修正：`-l` 后数据文件被
// 逐行当目标、CSS 值 27.25rem 被裸域名正则误判）。工具名与旗标须在同一命令段内（[^\n|;&]）。
var batchToolTargetFileRe = regexp.MustCompile(batchScopeToolRe + `(?:-l|-iL|--file)(?:[=\s]+)([^\s"']+)`)

// singleTargetScopeViolations ②：单目标按「单独命令」口径过影子资产门与 strict_scope 范围门
// ——与 run_command 逐目标语义完全对齐；返回违规描述（空=通过）。
// 影子资产门自带「原始项目目标行」豁免；strict_scope 由 scopeGate 全量复刻（含 expansion 三态）。
func (o *Orchestrator) singleTargetScopeViolations(p *store.Project, target string) string {
	// 前导空格：bareDomainRe 要求目标前有分隔字符（真实命令天然满足；逐目标伪命令是裸串）
	t := " " + strings.TrimSpace(target)
	if blocked := o.assetTestBlockedAssets(p, t); len(blocked) > 0 {
		return fmt.Sprintf("%s（影子资产门：%s）", truncateText(target, 60), strings.Join(blocked, "、"))
	}
	if sblocked, smsg := o.scopeGate(p, t); sblocked {
		return fmt.Sprintf("%s（范围门：%s）", truncateText(target, 60), truncateText(firstLine(smsg), 100))
	}
	return ""
}

// targetListScopeIssues ②：命令引用工作区目标清单文件（批量扫描器的 `-l/-iL/--file <path>`）时，
// 逐行按「单独命令」口径过影子资产门与 strict_scope 范围门——治理门只解析命令文本字面主机，
// 文件批量形态不得绕过逐目标校验（run_batch 的 targets 参数同理，由 toolRunBatch 逐目标校验）。
// v6.3.2 实战修正（某历史任务）：提取限**批量扫描器工具域**（batchScopeToolRe 名单与 W5
// 行为预算器同族）——`wc -l`/`grep -l`/`ls -l` 等通用旗标不再被误当目标清单参数读文件。
// 容器词表路径（工作区之外的绝对路径）与不存在文件不拦：前者是字典/词表非目标清单，
// 后者由执行自然失败——只对工作区内清单生效，避免把词表误当目标清单误拦。
func (o *Orchestrator) targetListScopeIssues(p *store.Project, stageID, channel, command string) string {
	if !o.guardEnabled(func(g *config.GuardConfig) *bool { return g.EnforceBatchScope }) {
		return ""
	}
	root := o.workspaceRoot(p.ID)
	violations := []string{}
	for _, m := range batchToolTargetFileRe.FindAllStringSubmatch(command, -1) {
		rawPath := strings.Trim(m[1], `"'`)
		if rawPath == "" {
			continue
		}
		var full string
		if filepath.IsAbs(rawPath) {
			full = filepath.Clean(rawPath)
			if !strings.HasPrefix(full, root+string(filepath.Separator)) {
				continue // 容器词表（/usr/share/seclists 等）不读不拦
			}
		} else {
			full = filepath.Join(root, rawPath)
		}
		rel, rerr := filepath.Rel(root, full)
		if rerr != nil || strings.HasPrefix(rel, "..") {
			continue
		}
		raw, err := o.exec.ReadFile(p.ID, rel)
		if err != nil {
			continue // 清单文件不存在：交给执行自然失败
		}
		for _, line := range strings.Split(raw, "\n") {
			t := strings.TrimSpace(line)
			if t == "" || strings.HasPrefix(t, "#") || strings.HasPrefix(t, "//") {
				continue
			}
			if v := o.singleTargetScopeViolations(p, t); v != "" {
				violations = append(violations, v)
			}
		}
	}
	if len(violations) == 0 {
		return ""
	}
	msg := fmt.Sprintf("执行被拦截（批量清单范围门）：`-l` 目标清单含未授权/范围外目标（%s）——把违规目标移出清单后重试；新发现子域先 record_asset（scope_evidence 引根域授权条目）登记为 in_scope 再纳入批量；确属范围外只记录不访问。",
		truncateText(strings.Join(violations, "；"), 300))
	_, _ = o.store.AddEvidence(&store.EvidenceRecord{ProjectID: p.ID, Stage: stageID,
		Type: "command", Input: truncateText(command, 200), Output: msg,
		Risk: tools.Forbidden, ApprovedBy: "batch-scope-gate"})
	o.log(p, stageID, fmt.Sprintf("⛔ 批量清单范围门拦截（%s 通道）：%d 项目标违规", channel, len(violations)))
	return msg
}
