package engine

// v7.1.0 PAE 自主决策框架（docs/优化方案_AI自主渗透能力增强_通用实战总案 §3）：
// 提议（propose，LLM 结构化提交）→ 裁决（本文件规则集，确定性，原因码机读）→
// 升维（同族拒 ×3 上移抽象层提示）→ 保守降级（落 VT 继续推进）。
// 零人工裁决点；账本落 bbolt autonomy 桶；治理九门与 execution profile 前置拦截不放宽——
// 本框架只改变「谁来触发裁决」，不改变「什么被允许」。

import (
	"fmt"
	"regexp"
	"strings"
	"time"

	"jiutouniao/internal/store"
)

// autonomyKinds 九种提议类型（方案 §3.1/§3.2 规则表）。
var autonomyKinds = []string{
	"loopback_focus", "budget_transfer", "replan_delta", "depth_extend",
	"mutation_campaign", "chain_plan", "explorer_mission", "lateral_edge", "retest_card",
}

// autoStr 取字符串参数。
func autoStr(args map[string]any, k string) string {
	v, _ := args[k].(string)
	return strings.TrimSpace(v)
}

// autoStrList 取字符串数组参数（evidence_refs/steps）。
func autoStrList(args map[string]any, k string) []string {
	// v7.2.0 核对修复（审计 F）：宽容解析——模型偶发把单条引用传成字符串而非数组
	//（"evidence/x.txt" 而非 ["evidence/x.txt"]），旧实现静默判空 → 误报 NO_EVIDENCE。
	if one, ok := args[k].(string); ok {
		if t := strings.TrimSpace(one); t != "" {
			return []string{t}
		}
		return nil
	}
	raw, _ := args[k].([]any)
	out := make([]string, 0, len(raw))
	for _, it := range raw {
		if s, ok := it.(string); ok && strings.TrimSpace(s) != "" {
			out = append(out, strings.TrimSpace(s))
		}
	}
	return out
}

// verifyEvidenceRefs 证据引用核存（方案 §3.1：防幻觉提议——引用不可达直接拒收）：
// 路径型引用经工作区核存；fact:/F-/VT-/CD- 型引用对记忆库核验；
// 未识别前缀记 EVIDENCE_UNVERIFIED 规则（不单独拒收，仍需 ≥1 条有效引用）。
func (o *Orchestrator) verifyEvidenceRefs(p *store.Project, refs []string) (valid []string, invalid []string, rules []string) {
	facts, _ := o.store.ListFacts(p.ID, 200)
	factKeys := map[string]bool{}
	for _, f := range facts {
		factKeys[f.Key] = true
	}
	vts, _ := o.store.ListVTs(p.ID)
	vtIDs := map[string]bool{}
	for _, v := range vts {
		vtIDs[v.ID] = true
	}
	cands, _ := o.store.ListCandidates(p.ID)
	cdIDs := map[string]bool{}
	for _, c := range cands {
		cdIDs[c.ID] = true
	}
	for _, ref := range refs {
		lc := strings.ToLower(ref)
		switch {
		case strings.HasPrefix(ref, "fact:"):
			key := strings.TrimPrefix(ref, "fact:")
			if factKeys[key] {
				valid = append(valid, ref)
			} else {
				invalid = append(invalid, ref)
			}
		case strings.HasPrefix(ref, "VT-"):
			if vtIDs[ref] {
				valid = append(valid, ref)
			} else {
				invalid = append(invalid, ref)
			}
		case strings.HasPrefix(ref, "CD-"):
			if cdIDs[ref] {
				valid = append(valid, ref)
			} else {
				invalid = append(invalid, ref)
			}
		case strings.HasPrefix(ref, "F-"), strings.Contains(ref, "/"), strings.HasPrefix(lc, "evidence/"):
			// 路径型（含 evidence/… 与 F- 编号文本引用）：F- 先对发现库核验，其余按工作区路径核存
			if strings.HasPrefix(ref, "F-") {
				if fs, err := o.store.ListFindings(p.ID); err == nil {
					found := false
					for _, f := range fs {
						if f.ID == ref {
							found = true
							break
						}
					}
					if found {
						valid = append(valid, ref)
						continue
					}
				}
				invalid = append(invalid, ref)
				continue
			}
			if _, err := o.exec.ReadFile(p.ID, ref); err == nil {
				valid = append(valid, ref)
			} else {
				invalid = append(invalid, ref)
			}
		default:
			rules = append(rules, "EVIDENCE_UNVERIFIED:"+ref)
			valid = append(valid, ref)
		}
	}
	return valid, invalid, rules
}

// toolPropose propose 工具入口：解析→校验→裁决→落账本→时间线→回执。
func (o *Orchestrator) toolPropose(p *store.Project, stageID string, args map[string]any) string {
	ac := o.cfg.Autonomy
	if !ac.IsEnabled() {
		return "自主决策框架未启用（autonomy.enabled=false）——请按常规工具路径推进，无需提议。"
	}
	// v7.4.0 核对修复（审计 T）：S1 阶段门兜底——工具面隐藏只防误用，直调（幻觉调用/旧上下文
	// 重放）仍会到达本函数；范围界定阶段无自主资源动作语义，与 toolDefsForStage 隐藏口径一致。
	if stageID == "s1" {
		return "S1 阶段（范围界定）不受理自主提议——先完成授权界定，S2 起再按九类 kind 提交。"
	}
	kind := autoStr(args, "kind")
	rationale := autoStr(args, "rationale")
	focus := autoStr(args, "focus")
	cost := autoStr(args, "cost")
	refs := autoStrList(args, "evidence_refs")

	rec := &store.AutonomyRecord{
		ProjectID: p.ID, Stage: stageID, Kind: kind,
		Rationale: rationale, Evidence: refs, Focus: focus, CostNote: cost,
	}
	now := time.Now()
	rec.CreatedAt = now // v7.4.2 时序修复：提议时刻即创建时刻——修复账本 decided_at 早于 created_at 的倒挂
	rec.DecidedAt = &now

	// ---- 公共规则 ----
	kindOK := false
	for _, k := range autonomyKinds {
		if k == kind {
			kindOK = true
			break
		}
	}
	if !kindOK {
		rec.Verdict, rec.Reason = "denied", "INVALID_KIND：kind 必须是 "+strings.Join(autonomyKinds, "/")+" 之一"
		o.autonomyRecord(rec, p, stageID, "")
		return o.autonomyReceipt(rec, "修正 kind 后重提。")
	}
	if rationale == "" {
		rec.Verdict, rec.Reason = "denied", "NO_RATIONALE：rationale 必填——一句话可证伪理由（假设+预期信号）"
		o.autonomyRecord(rec, p, stageID, "")
		return o.autonomyReceipt(rec, "补充可证伪理由后重提。")
	}
	valid, invalid, erules := o.verifyEvidenceRefs(p, refs)
	rec.Evidence = valid
	rec.Rules = append(rec.Rules, erules...)
	if len(valid) == 0 {
		// v7.4.2 收敛修复：NO_EVIDENCE 回执必须参数化（方案 §2.2/§3.2「最近可过参数」）——
		// 泛化指引下提议方拿不到可执行的修正信息，会原样重提（实战实证：同因连续两次被拒、
		// 转化率 0%）。首次被拒给五类指针格式 + 项目实时可引用示例；同因重复被拒升级为强指引。
		rec.Verdict, rec.Reason = "denied", "NO_EVIDENCE：无有效证据引用——提议必须有观察依据（hypothesis-0day 纪律），禁止空想提议"
		rec.Rules = append(rec.Rules, "NO_EVIDENCE")
		priorN := countNoEvidenceDenials(o, p.ID, stageID, kind) // 本条落账前计数（不含本条）
		o.autonomyRecord(rec, p, stageID, "")
		var extra string
		if priorN == 0 {
			extra = "evidence_refs 必填 ≥1 条可核存指针（五类任一）：fact:<黑板键> / VT-编号 / CD-编号 / F-编号 / evidence/… 文件路径。" + o.evidenceRefExamples(p)
		} else {
			extra = fmt.Sprintf("第 %d 次因 evidence_refs 缺失被拒——上次回执已给出修复参数，本次仍未携带。必须附 evidence_refs 数组（示例：%s）。两轮修正后仍无证据=该方向暂无观察依据，请保守降级 record_vt 移交后继续队列；禁止第三次原样重提。", priorN+1, o.evidenceRefExamples(p))
		}
		return o.autonomyReceipt(rec, extra)
	}
	if len(invalid) > 0 {
		rec.Rules = append(rec.Rules, "EVIDENCE_MISSING:"+strings.Join(invalid, ","))
	}

	// ---- 同族判重（方案 §3.1：同 kind+同 focus 归一化判重，非 denied 提议在场即拒重提）----
	// v7.1.0 第四轮审计修复 H：判重前移至配额递增之前——重复提议不得消耗阶段配额
	//（旧序下模型重复提交 6 次即烧光配额，把真正的新提议挤出窗外），亦不计入升维计数。
	if prior := o.duplicateProposal(p.ID, kind, focus); prior != "" {
		rec.Verdict, rec.Reason = "denied", "DUPLICATE：同 kind+同 focus 提议已在账本（"+prior+"）——按其 outcome/状态继续，勿重复提交"
		o.autonomyRecord(rec, p, stageID, "")
		return o.autonomyReceipt(rec, "")
	}

	// 提议风暴防护：每阶段提议总数上限
	o.autoMu.Lock()
	key := p.ID + "|" + stageID
	if o.autoStageN == nil {
		o.autoStageN = map[string]int{}
	}
	o.autoStageN[key]++
	stageN := o.autoStageN[key]
	o.autoMu.Unlock()
	if stageN > ac.ProposalsPerStage {
		rec.Verdict, rec.Reason = "denied", fmt.Sprintf("QUOTA_EXCEEDED：本阶段提议已达上限 %d——先消化已有队列再提议", ac.ProposalsPerStage)
		o.autonomyRecord(rec, p, stageID, "")
		return o.autonomyReceipt(rec, "")
	}
	rec.Rules = append(rec.Rules, fmt.Sprintf("STAGE_PROPOSALS:%d/%d", stageN, ac.ProposalsPerStage))

	// ---- kind 专属规则集（方案 §3.2）----
	verdict, reason := o.autonomyKindRules(p, stageID, kind, focus, args, rec)
	rec.Verdict, rec.Reason = verdict, reason

	// ---- 升维判定：同族（stage|kind）被拒 ≥3 → 升维提示（抽象层上移，非人工上报）----
	if rec.Verdict == "denied" {
		o.autoMu.Lock()
		dkey := p.ID + "|" + stageID + "|" + kind
		if o.autoDenyN == nil {
			o.autoDenyN = map[string]int{}
		}
		o.autoDenyN[dkey]++
		n := o.autoDenyN[dkey]
		o.autoMu.Unlock()
		if n >= 3 {
			rec.Reason += " | ESCALATED(×3)：同族提议已三次被拒——按升维阶梯以更高抽象层重新提议" +
				"（单点 depth_extend → chain_plan 链路 / 聚焦回环 / budget_transfer 阶段计划），或保守降级 record_vt 移交后继续队列；禁止原地第四次重提。"
		}
	}
	o.autonomyRecord(rec, p, stageID, "")
	return o.autonomyReceipt(rec, "")
}

// autonomyKindRules kind 专属确定性规则集，返回 (verdict, reason)。
func (o *Orchestrator) autonomyKindRules(p *store.Project, stageID, kind, focus string, args map[string]any, rec *store.AutonomyRecord) (string, string) {
	ac := o.cfg.Autonomy
	o.autoMu.Lock()
	if o.autoUnitDepth == nil {
		o.autoUnitDepth = map[string]int{}
		o.autoExplorer = map[string]int{}
		o.autoTransfers = map[string]int{}
		o.autoReplan = map[string]int{}
	}
	defer o.autoMu.Unlock()

	switch kind {
	case "loopback_focus":
		// 动态回环额度：聚焦回环成本 ≪ 全阶段重跑，上限由固定 3 放宽至 loopback_cap_max（默认 8）；
		// 实际排队仍由 loopback 工具按动态额度执行——本提议留价值裁决痕。
		total := p.LoopUsed
		if total >= ac.LoopbackCapMax {
			return "denied", fmt.Sprintf("QUOTA_EXCEEDED：项目累计回环已达动态上限 %d（聚焦回环口径）——请 record_vt 移交或人工在「阶段流水线」处置", ac.LoopbackCapMax)
		}
		return "approved", fmt.Sprintf("RULE:LOOPBACK_DYNAMIC_CAP（已用 %d/%d）——聚焦回环额度可用，调用 loopback(to_stage=…) 执行；聚焦范围=%s", total, ac.LoopbackCapMax, focusOrAll(focus))

	case "budget_transfer":
		if o.autoTransfers[p.ID] >= ac.BudgetTransfersPerProj {
			return "denied", fmt.Sprintf("QUOTA_EXCEEDED：项目预算转移提议已达上限 %d——由真头参谋在阶段收口统一编排", ac.BudgetTransfersPerProj)
		}
		o.autoTransfers[p.ID]++
		return "approved", "RULE:BUDGET_TRANSFER_CAP——转移建议已留账本（真头参谋/收口编排消费；源阶段强制门不受转移影响）"

	case "replan_delta":
		rkey := p.ID + "|" + stageID
		if o.autoReplan[rkey] >= 1 {
			return "denied", "QUOTA_EXCEEDED：本阶段已达自动重排上限 1 次——新增目标将按 planDelta 执行卡随下一轮对账表自动扩展"
		}
		o.autoReplan[rkey]++
		return "approved", "RULE:REPLAN_DELTA——新 live 资产将按执行卡扩展进对账表（计划版本 Bump 留痕）"

	case "depth_extend":
		unit := focusOrAll(focus)
		ukey := p.ID + "|" + unit
		if o.autoUnitDepth[ukey] >= ac.DepthUnitRoundCap {
			return "denied", fmt.Sprintf("QUOTA_EXCEEDED：该单元深化提议已达硬顶 %d 轮且无新增确证——立即 needs_follow_up 移交（防单点黑洞）", ac.DepthUnitRoundCap)
		}
		o.autoUnitDepth[ukey]++
		return "approved", fmt.Sprintf("RULE:DEPTH_EVIDENCE_GATE（单元 %d/%d）——深化由证据增量驱动：最近 2 轮无新增确证信息即停，禁止为凑轮次深挖", o.autoUnitDepth[ukey], ac.DepthUnitRoundCap)

	case "mutation_campaign":
		n := countKindProposals(o.store, p.ID, stageID, "mutation_campaign")
		if n >= ac.MutationCampaignPerStage {
			return "denied", fmt.Sprintf("QUOTA_EXCEEDED：本阶段变异攻坚提议已达上限 %d——余下单元按 waf_blocked 移交", ac.MutationCampaignPerStage)
		}
		// 前提核验：该单元已有 waf_blocked 覆盖登记 + 指纹留痕（方案 §3.2）
		covs, _ := o.store.ListCoverage(p.ID)
		wafHit := false
		for _, c := range covs {
			if c.Status != "waf_blocked" {
				continue
			}
			if focus == "" || strings.Contains(c.Endpoint, focus) || strings.Contains(focus, c.Endpoint) || strings.Contains(c.Notes, focus) {
				wafHit = true
				break
			}
		}
		if !wafHit {
			return "denied", "NO_WAF_BLOCKED：变异攻坚前提不成立——该单元须先 update_coverage=waf_blocked 并 load_skill waf-fingerprint 留指纹"
		}
		return "approved", "RULE:WAF_BLOCKED_PREMISE——变异族 ≤3、每候选 ≤6 请求、单脚本批量投递（禁逐发）；ROE 禁绕过时直接移交"

	case "chain_plan":
		// 链上每步命令预检 execution profile（与执行期同源规则；governanceGates 在执行通道仍逐条强制）
		steps := autoStrList(args, "steps")
		if len(steps) == 0 {
			if plan := autoStr(args, "plan"); plan != "" {
				steps = []string{plan}
			}
		}
		if len(steps) == 0 {
			return "denied", "INVALID_PARAMS：chain_plan 须提供 steps（每步一条命令）或 plan 文本"
		}
		if len(steps) > 6 {
			return "denied", "QUOTA_EXCEEDED：链内步骤 ≤6（方案 §3.2）——拆分为主链与续链分次提议"
		}
		profile := o.profileOf(p)
		for i, st := range steps {
			if hits := profileViolations(profile, st, false); len(hits) > 0 {
				return "denied", fmt.Sprintf("PROFILE_BLOCKED：链第 %d 步命中执行档禁项（%s）——生产档只允许存在性证明链；isolated_lab 才可完整 PoC 链", i+1, firstHitText(hits))
			}
		}
		return "approved", fmt.Sprintf("RULE:CHAIN_PROFILE_PRECHECK（%d 步通过 %s 档预检）——每步执行仍逐条过 governanceGates；每步带 abort_condition 与无害判据", len(steps), profile)

	case "explorer_mission":
		if o.autoExplorer[p.ID] >= ac.ExplorerConcurrent {
			return "denied", fmt.Sprintf("QUOTA_EXCEEDED：在途探索代理已达 %d 路——poll_subagents 收结果后再派", ac.ExplorerConcurrent)
		}
		o.autoExplorer[p.ID]++
		return "approved", fmt.Sprintf("RULE:EXPLORER_BUDGET——探索代理产出仅限 record_candidate/update_coverage，挂 W5 行为预算器，轮次 ≤%d", o.cfg.Engine.MaxSubagentRounds)

	case "lateral_edge":
		n := countKindProposals(o.store, p.ID, stageID, "lateral_edge")
		if n >= ac.LateralEdgesPerStage {
			return "denied", fmt.Sprintf("QUOTA_EXCEEDED：本阶段横向边提议已达上限 %d——余下边按拓扑向量移交", ac.LateralEdgesPerStage)
		}
		if p.ExecutionProfile != "isolated_lab" {
			// 生产档：横向探测只读可达性即可；写语义/持久化步骤命中即拒（与 profile 同源）
			if plan := autoStr(args, "plan"); plan != "" {
				if hits := profileViolations(o.profileOf(p), plan, false); len(hits) > 0 {
					return "denied", "PROFILE_BLOCKED：横向边含执行档禁项写语义——生产档只做可达性存在性证明，写步骤移交人工"
				}
			}
		}
		return "approved", "RULE:LATERAL_EDGE_CAP——单边探测请求 ≤ROE 额度，逐边留痕；凭据/信任复用须有黑板 fact 支撑"

	case "retest_card":
		return "approved", "RULE:RETEST_CARD——复测卡四要素（启动条件/步骤/预期信号/预估轮次）齐备后按价值分入 VT(ready) 队列"
	}
	return "denied", "INVALID_KIND：未实现的提议类型"
}

// autonomyRecord 落账本 + 时间线 + 执行流日志（留痕三通道之一：存储）。
func (o *Orchestrator) autonomyRecord(rec *store.AutonomyRecord, p *store.Project, stageID, _ string) {
	if _, err := o.store.AddAutonomy(rec); err != nil {
		return
	}
	_, _ = o.store.AddTimeline(&store.TimelineEvent{ProjectID: p.ID, Stage: stageID,
		Event:  "自主提议·" + rec.Verdict,
		Detail: fmt.Sprintf("%s [%s] %s → %s（%s）", rec.ID, rec.Kind, truncateText(rec.Rationale, 80), rec.Verdict, truncateText(rec.Reason, 160))})
	emoji := "🧠"
	switch rec.Verdict {
	case "denied":
		emoji = "⛔"
	case "approved", "modified":
		emoji = "✅"
	}
	o.log(p, stageID, fmt.Sprintf("%s 自主提案 %s [%s] → %s：%s", emoji, rec.ID, rec.Kind, rec.Verdict, truncateText(rec.Reason, 120)))
}

// autonomyReceipt 机读回执：裁决结论 + 原因码 + 收敛引导（denied 附最近可过参数提示）。
func (o *Orchestrator) autonomyReceipt(rec *store.AutonomyRecord, extra string) string {
	var b strings.Builder
	switch rec.Verdict {
	case "approved", "modified":
		b.WriteString(fmt.Sprintf("✅ 提议已批准（%s）\n裁决：%s\n%s\n", rec.ID, rec.Verdict, rec.Reason))
		if o.cfg.Autonomy.ShadowMode() {
			b.WriteString("⚠ shadow 模式：本次裁决仅记账（对照「引擎会怎么裁 vs 实际发生了什么」），请按常规工具路径执行。\n")
		} else {
			b.WriteString("按裁决口径执行；结果用 update_proposal(id=\"" + rec.ID + "\", outcome=…) 回写账本（产出 F-/VT-/coverage 归宿），供自主产出转化统计。\n")
		}
	case "denied":
		b.WriteString(fmt.Sprintf("⛔ 提议被拒（%s）\n裁决：denied\n原因：%s\n", rec.ID, rec.Reason))
		// v7.4.2 收敛纪律：回执点名参数 → 提议方仅修该参数重提一次，禁止原样重提。
		b.WriteString("按回执点名的参数收敛后可重提（仅修被拒字段，禁止原样重提）；同族三次被拒会触发升维提示——不要原地重试。\n")
	case "shadow_recorded":
		b.WriteString(fmt.Sprintf("📝 提议已记录（shadow，%s）\n%s\n", rec.ID, rec.Reason))
	}
	if extra != "" {
		b.WriteString(extra + "\n")
	}
	return b.String()
}

// toolUpdateProposal update_proposal：结果回写账本（自主产出转化率的分子来源）。
func (o *Orchestrator) toolUpdateProposal(p *store.Project, args map[string]any) string {
	id := autoStr(args, "id")
	outcome := autoStr(args, "outcome")
	if id == "" || outcome == "" {
		return "错误: id 与 outcome 必填（outcome 写产出归宿：F-/VT-/coverage 单元/放弃原因）"
	}
	rec, err := o.store.GetAutonomy(id)
	if err != nil || rec.ProjectID != p.ID {
		return "错误: 提议编号不存在或不属于本项目: " + id
	}
	rec.Outcome = outcome
	// v7.4.2 时序修复：结果回写不再覆盖 DecidedAt——账本三元组语义固定为
	// created_at=提议时刻、decided_at=裁决时刻、outcome=回写结果（回写时间由时间线事件承载）。
	if err := o.store.SaveAutonomy(rec); err != nil {
		return "错误: " + err.Error()
	}
	_, _ = o.store.AddTimeline(&store.TimelineEvent{ProjectID: p.ID, Stage: rec.Stage,
		Event:  "自主提议·结果回写",
		Detail: fmt.Sprintf("%s [%s] outcome：%s", rec.ID, rec.Kind, truncateText(outcome, 160))})
	o.convNote(p, rec.Stage)
	return fmt.Sprintf("已回写 %s 结果入账本：%s", id, truncateText(outcome, 120))
}

// autonomyRetrospective S8《自主决策复盘》章素材（引擎生成，禁手写——与 keyFigures 同机制）。
func (o *Orchestrator) autonomyRetrospective(projectID string) string {
	stats := o.store.AutonomyStats(projectID)
	total, _ := stats["total"].(int)
	if total == 0 {
		return ""
	}
	recs, _ := o.store.ListAutonomy(projectID)
	var b strings.Builder
	b.WriteString(fmt.Sprintf("全项目自主提案 %d 条；批准 %d；结果回写 %d；转化率 %.0f%%；升维 %d 次。\n",
		total, stats["approved"], stats["approved_with_outcome"], stats["conversion"], stats["escalations"]))
	b.WriteString("\n| 提案 | 阶段 | 类型 | 裁决 | 结果 |\n|---|---|---|---|---|\n")
	for _, r := range recs {
		b.WriteString(fmt.Sprintf("| %s | %s | %s | %s | %s |\n",
			r.ID, r.Stage, r.Kind, r.Verdict, truncateText(firstNonEmpty(r.Outcome, r.Reason), 60)))
	}
	return b.String()
}

// loopbackCap 动态回环上限（v7.1.0：自主框架启用时以 loopback_cap_max 放宽固定 3——聚焦回环成本已降一个量级）。
func (o *Orchestrator) loopbackCap() int {
	if o.cfg.Autonomy.IsEnabled() {
		return o.cfg.Autonomy.LoopbackCapMax
	}
	return o.cfg.Engine.LoopbackMaxRuns
}

// ---- 小工具 ----

// ---- v7.1.0 A2 执行卡状态机接线（P1-lite：引擎维护投影，模型零簿记） ----

var cardClassRe = regexp.MustCompile(`C-\d{1,2}`)

var cardTargetRe = regexp.MustCompile(`[（(]([^）)]*)[）)]\s*$`)

// trackCardFromCoverage update_coverage 投递即卡片推进：
// C-xx 引用解析自 endpoint+param+notes；结论态（vulnerable/ruled_out/no_issue_found）→
// dispositioned；其余状态 → dispatched（waf_blocked/needs_follow_up 记 outcome 供五态统计）；
// notes 含 EV-/evidence/ → evidence_linked。目标取 endpoint 尾括号注记（多目标复合键）。
func (o *Orchestrator) trackCardFromCoverage(p *store.Project, stageID, endpoint, param, notes, status string) {
	hay := endpoint + " " + param + " " + notes
	refs := cardClassRe.FindAllString(hay, -1)
	if len(refs) == 0 {
		return
	}
	seen := map[string]bool{}
	classes := []string{}
	for _, r := range refs {
		if !seen[r] {
			seen[r] = true
			classes = append(classes, r)
		}
	}
	target := ""
	if m := cardTargetRe.FindStringSubmatch(endpoint); m != nil {
		target = strings.TrimSpace(m[1])
	}
	state := "dispatched"
	switch status {
	case "vulnerable", "ruled_out", "no_issue_found":
		state = "dispositioned"
	default:
		if strings.Contains(notes, "EV-") || strings.Contains(notes, "evidence/") {
			state = "evidence_linked"
		}
	}
	for _, cls := range classes {
		_ = o.store.UpsertCard(&store.CardRecord{
			ProjectID: p.ID, Stage: stageID, Class: cls, Target: target,
			State: state, Outcome: status, Evidence: truncateText(notes, 120),
		})
	}
}

// trackCardFromVT record_vt 登记即建卡（queued 态）——该类已有卡时不回退状态（单调推进）。
func (o *Orchestrator) trackCardFromVT(p *store.Project, stageID, title, startConditions string) {
	hay := title + " " + startConditions
	refs := cardClassRe.FindAllString(hay, -1)
	if len(refs) == 0 {
		return
	}
	existing, _ := o.store.ListCards(p.ID)
	have := map[string]bool{}
	for _, c := range existing {
		if c.Stage == stageID {
			have[c.Class] = true
		}
	}
	seen := map[string]bool{}
	for _, cls := range refs {
		if seen[cls] || have[cls] {
			continue
		}
		seen[cls] = true
		_ = o.store.UpsertCard(&store.CardRecord{
			ProjectID: p.ID, Stage: stageID, Class: cls, Target: "",
			State: "queued", Outcome: "vt_registered",
		})
	}
}

// cardFunnelLine 状态机漏斗一行式（收口/收尾注入用）。
func (o *Orchestrator) cardFunnelLine(p *store.Project) string {
	cs := o.store.CardStats(p.ID)
	if cs["total"] == 0 {
		return ""
	}
	return fmt.Sprintf("执行卡状态机（v7.1.0 A2 直出，共 %d 张）：queued_vt=%d → dispatched=%d → evidence_linked=%d → dispositioned=%d；blocked=%d deferred=%d",
		cs["total"], cs["queued_vt"], cs["dispatched"], cs["evidence_linked"], cs["dispositioned"], cs["blocked"], cs["deferred"])
}

// ---- v7.1.0 P7 工具通道健康归因 ----

// trackToolHealth 按错误特征归类计数（project|stage → 类别 → 次数）：
// timeout/refused/dns/waf403/tool_error——冲刺预警与 stage_metrics 消费，
// 治「nuclei 174B 贫产不可归因、预算重复浪费」（optimization-proposals P7）。
func (o *Orchestrator) trackToolHealth(p *store.Project, stageID, errText string, exit int) {
	cls := ""
	switch {
	case strings.Contains(errText, "timed out") || strings.Contains(errText, "超时") || strings.Contains(errText, "deadline exceeded"):
		cls = "timeout"
	case strings.Contains(errText, "connection refused"):
		cls = "refused"
	case strings.Contains(errText, "no such host") || strings.Contains(errText, "NXDOMAIN") || strings.Contains(errText, "lookup "):
		cls = "dns"
	case strings.Contains(errText, "403") || strings.Contains(errText, "Forbidden"):
		cls = "waf403"
	case exit != 0:
		cls = "tool_error"
	}
	if cls == "" {
		return
	}
	o.healthMu.Lock()
	if o.healthStats == nil {
		o.healthStats = map[string]map[string]int{}
	}
	key := p.ID + "|" + stageID
	if o.healthStats[key] == nil {
		o.healthStats[key] = map[string]int{}
	}
	o.healthStats[key][cls]++
	o.healthMu.Unlock()
}

// toolHealthSummary 本阶段健康归因一行式（仅返回有计数的）；阈值信号：任一类 ≥3 提示换通道。
func (o *Orchestrator) toolHealthSummary(projectID, stageID string) string {
	o.healthMu.Lock()
	defer o.healthMu.Unlock()
	st := o.healthStats[projectID+"|"+stageID]
	if len(st) == 0 {
		return ""
	}
	parts := []string{}
	hot := false
	for _, cls := range []string{"timeout", "refused", "dns", "waf403", "tool_error"} {
		if n := st[cls]; n > 0 {
			parts = append(parts, fmt.Sprintf("%s=%d", cls, n))
			if n >= 3 {
				hot = true
			}
		}
	}
	if len(parts) == 0 {
		return ""
	}
	s := "tool_health（本阶段归因）: " + strings.Join(parts, ", ")
	if hot {
		s += " ——同一类 ≥3 次：先切适配通道（channel-snapshot/限速/降并发）再批量，勿同参重试（M6 先 probe 后 batch）"
	}
	return s
}

// evidenceRefExamples 项目实时可引用指针示例（v7.4.2 回执参数化）：从账本/队列/发现库/候选库
// 抓取当前真实存在的指针，让提议方「拿到示例即可过核存」，替代泛化指引（「最近可过参数」）。
func (o *Orchestrator) evidenceRefExamples(p *store.Project) string {
	ex := []string{}
	if vts, err := o.store.ListVTs(p.ID); err == nil {
		n := 0
		for _, v := range vts {
			if n >= 2 {
				break
			}
			if v.ID != "" {
				ex = append(ex, "\""+v.ID+"\"")
				n++
			}
		}
	}
	if facts, err := o.store.ListFacts(p.ID, 50); err == nil {
		n := 0
		for _, f := range facts {
			if n >= 2 {
				break
			}
			if k := truncateText(f.Key, 40); k != "" {
				ex = append(ex, "\"fact:"+k+"\"")
				n++
			}
		}
	}
	if cands, err := o.store.ListCandidates(p.ID); err == nil && len(cands) > 0 {
		ex = append(ex, "\""+cands[0].ID+"\"")
	}
	if fs, err := o.store.ListFindings(p.ID); err == nil && len(fs) > 0 {
		ex = append(ex, "\""+fs[len(fs)-1].ID+"\"")
	}
	if len(ex) == 0 {
		return "当前项目暂无现成指针：先用 write_file 在 evidence/ 落一份实测证据（如 evidence/<主题>.txt），再以该路径作为 evidence_refs 重提。"
	}
	return "当前可直接引用（示例）：" + strings.Join(ex, "、") + " ——任取其一放入 evidence_refs 即可通过核存。"
}

// countNoEvidenceDenials 同因（NO_EVIDENCE）被拒计数（同项目+同阶段+同 kind）——
// v7.4.2 收敛修复：同因重复被拒时回执升级为强指引；该类格式性拒绝不计入同族升维计数
// （升维通道留给实质分歧，格式问题在回执层收敛）。
func countNoEvidenceDenials(o *Orchestrator, projectID, stageID, kind string) int {
	recs, err := o.store.ListAutonomy(projectID)
	if err != nil {
		return 0
	}
	n := 0
	for _, r := range recs {
		if r.Kind == kind && r.Stage == stageID && r.Verdict == "denied" && strings.HasPrefix(r.Reason, "NO_EVIDENCE") {
			n++
		}
	}
	return n
}

// duplicateProposal 同族判重：存在同 kind+同 focus 的非 denied 提议 → 返回其编号。
// focus 归一化（去空白/全角括号统一）后比较；空 focus 视为通配（同 kind 未聚焦在场即判重）。
func (o *Orchestrator) duplicateProposal(projectID, kind, focus string) string {
	recs, err := o.store.ListAutonomy(projectID)
	if err != nil {
		return ""
	}
	norm := func(s string) string {
		s = strings.TrimSpace(s)
		s = strings.ReplaceAll(s, "（", "(")
		s = strings.ReplaceAll(s, "）", ")")
		return s
	}
	nf := norm(focus)
	for i := len(recs) - 1; i >= 0; i-- { // 新→旧，命中最近一条
		r := recs[i]
		if r.Kind != kind || r.Verdict == "denied" {
			continue
		}
		// v7.2.0 核对修复（审计 E）：已消费（outcome 回写）的提议不再阻塞同族新周期——
		// 执行完成并回写结果后，条件变化时同 kind+focus 重新提议是新一轮而非重复；
		// 未消费（approved 但无 outcome）仍然判重（防挂起提议被同族绕过）。
		if strings.TrimSpace(r.Outcome) != "" {
			continue
		}
		if nf == "" || norm(r.Focus) == nf {
			return r.ID
		}
	}
	return ""
}

func countKindProposals(st *store.Store, projectID, stageID, kind string) int {
	recs, err := st.ListAutonomy(projectID)
	if err != nil {
		return 0
	}
	n := 0
	for _, r := range recs {
		if r.Kind == kind && r.Stage == stageID {
			n++
		}
	}
	return n
}

func focusOrAll(focus string) string {
	if strings.TrimSpace(focus) == "" {
		return "(未指定)"
	}
	return focus
}

func firstNonEmpty(a, b string) string {
	if strings.TrimSpace(a) != "" {
		return a
	}
	return b
}

func firstHitText(hits []profileHit) string {
	if len(hits) == 0 {
		return ""
	}
	if h := hits[0].Match; h != "" {
		return h
	}
	return hits[0].Rule
}
