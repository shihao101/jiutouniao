package engine

// v7.1.0→v7.2.0 编排权批次（docs/优化方案_AI自主渗透能力增强_通用实战总案 第二批）：
// B1 真头作战参谋（本文件）：阶段收口时引擎自动调用一次 LLM 评审——输入=账本统计+覆盖
// 矩阵+VT 队列+token 用量，输出三类有限裁决建议（budget_transfer/loopback_focus/
// replan_delta），逐条转为 proposal 走 PAE 裁决器落账本。真头无执行工具（建议制），
// 否决清单硬编码于裁决器规则集；LLM 缺失/失败 fail-open 跳过（不阻塞流水线）。
// B3 planDelta：测试中新转 in_scope 的资产自动生成执行卡 + 计划版本 Bump（P2/P3 落地）。
// B4 预算账本：目标×类×深度占用一行式注入（P4-lite，防单点黑洞可视）。

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"jiutouniao/internal/llm"
	"jiutouniao/internal/store"
)

// brainSuggestion 作战参谋有限裁决建议（JSON 协议，≤3 条）。
type brainSuggestion struct {
	Type        string `json:"type"` // budget_transfer|loopback_focus|replan_delta
	Rationale   string `json:"rationale"`
	Evidence    string `json:"evidence"` // 证据引用：evidence/ 路径或 fact:/F-/VT- 编号，逗号/顿号分隔
	Focus       string `json:"focus,omitempty"`
	TargetStage string `json:"target_stage,omitempty"`
}

var brainTypes = map[string]bool{"budget_transfer": true, "loopback_focus": true, "replan_delta": true}

// gapEvidenceRefs v7.7.3：从覆盖缺口 notes 提取 evidence/ 路径（≤3 条）——参谋缺口类
// 提议的合法引用源（复用包级 evidencePathRe 正则；跨文件借用包内已声明变量）。
func gapEvidenceRefs(text string) []string {
	var out []string
	seen := map[string]bool{}
	for _, m := range evidencePathRe.FindAllString(text, 6) {
		p := strings.TrimRight(m, "，。；、)）")
		if p != "" && !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
		if len(out) >= 3 {
			break
		}
	}
	return out
}

// evidencePathRe evidence/ 路径提取（参谋缺口行附带用）。


// parseBrainSuggestions 宽容解析：提取文本中首个平衡 JSON 数组；无数组或解析失败返回空。
// 超过 3 条截断（有限裁决契约）；type 不在白名单的条目丢弃（否决清单硬编码的第一道）。
func parseBrainSuggestions(content string) []brainSuggestion {
	start := strings.Index(content, "[")
	if start < 0 {
		return nil
	}
	depth := 0
	end := -1
	inStr := false
	esc := false
	for i := start; i < len(content); i++ {
		c := content[i]
		if esc {
			esc = false
			continue
		}
		switch c {
		case '\\':
			if inStr {
				esc = true
			}
		case '"':
			inStr = !inStr
		case '[':
			if !inStr {
				depth++
			}
		case ']':
			if !inStr {
				depth--
				if depth == 0 {
					end = i + 1
				}
			}
		}
		if end > 0 {
			break
		}
	}
	if end < 0 {
		return nil
	}
	var out []brainSuggestion
	if err := json.Unmarshal([]byte(content[start:end]), &out); err != nil {
		return nil
	}
	filtered := out[:0]
	for _, s := range out {
		if brainTypes[s.Type] && strings.TrimSpace(s.Rationale) != "" {
			filtered = append(filtered, s)
		}
	}
	if len(filtered) > 3 {
		filtered = filtered[:3]
	}
	return filtered
}

// campaignBrainReview 阶段收口自动评审（每阶段至多一次，随 P9 指标点调用）。
func (o *Orchestrator) campaignBrainReview(ctx context.Context, p *store.Project, stageID string) {
	if !o.cfg.Autonomy.IsEnabled() || stageID == "s1" {
		return
	}
	cli, model := o.auxClientFor(p) // v7.5.0（E2）：参谋评审走辅助档（配置 aux_model 时；默认同主模型零变化）
	if cli == nil {
		return // 测试/无 LLM 装配：fail-open 跳过
	}
	// 评审输入：预算/执行卡漏斗/验证队列/覆盖矩阵 + 可引用实体（v7.6.1 证据实体注入）
	b := o.buildBrainProfile(p, stageID)

	sys := brainSystemPrompt()
	msgs := []llm.Message{{Role: "system", Content: sys}, {Role: "user", Content: b}}
	resp, usage2, err := cli.Chat(ctx, model, msgs, nil, o.auxTemperature(0.3), o.auxMaxTokens())
	if err != nil {
		o.log(p, stageID, "🎖 作战参谋评审不可用（LLM 失败，跳过）: "+truncateText(err.Error(), 80))
		return
	}
	o.accountUsageC(p, stageID, usage2, usageCtx{kind: "brain", msgs: msgs, resp: &resp}) // v7.5.0（A4）
	sugs := parseBrainSuggestions(resp.Content)
	if len(sugs) == 0 {
		o.auxZeroOutput(p, stageID, "brain", true) // v7.6.0（A1）零产出计数告警
		o.log(p, stageID, "🎖 作战参谋评审：无高价值编排建议（[]）")
		_, _ = o.store.AddTimeline(&store.TimelineEvent{ProjectID: p.ID, Stage: stageID,
			Event:  "作战参谋评审",
			Detail: "零建议（[]）——预算/覆盖/队列画像下无编排触发点（正常静默，留痕供审计）"})
		return
	}
	o.auxZeroOutput(p, stageID, "brain", false)
	approved, denied, skipped := 0, 0, 0
	for _, s := range sugs {
		// v7.2.0 核对修复（审计 A）：参谋建议证据预校验——引用逐条核存，全部不可达的建议
		// 直接丢弃（防幻觉提案进入裁决；可解析的子集照常透传，裁决器仍会二次核验）。
		refs := []string{}
		for _, r := range strings.FieldsFunc(s.Evidence, func(r rune) bool { return r == ',' || r == '、' || r == ';' || r == '；' }) {
			if t := strings.TrimSpace(r); t != "" {
				refs = append(refs, t)
			}
		}
		valid, _, _ := o.verifyEvidenceRefs(p, refs)
		if len(refs) == 0 || len(valid) == 0 {
			skipped++
			o.log(p, stageID, fmt.Sprintf("🎖 参谋建议丢弃（证据不可达，防幻觉）：%s | %s", s.Type, truncateText(s.Rationale, 60)))
			continue
		}
		args := map[string]any{
			"kind":      s.Type,
			"rationale": s.Rationale,
			"focus":     s.Focus,
		}
		if len(refs) > 0 {
			args["evidence_refs"] = refs
		}
		if s.Type == "loopback_focus" && s.TargetStage != "" {
			args["focus"] = strings.TrimSpace(s.Focus + " @" + s.TargetStage)
		}
		receipt := o.toolPropose(p, stageID+"-brain", args)
		if strings.Contains(receipt, "已批准") {
			approved++
		} else if strings.Contains(receipt, "被拒") {
			denied++
		}
	}
	if skipped > 0 {
		o.log(p, stageID, fmt.Sprintf("🎖 作战参谋评审：%d 条建议（批准 %d / 拒绝 %d / 证据不可达丢弃 %d）——全部落自主决策账本可审计", len(sugs), approved, denied, skipped))
	} else {
		o.log(p, stageID, fmt.Sprintf("🎖 作战参谋评审：%d 条建议入裁决（批准 %d / 拒绝 %d）——全部落自主决策账本可审计", len(sugs), approved, denied))
	}
}

// brainSystemPrompt 作战参谋系统提示词（v7.6.1 增加引用纪律节，抽为函数便于单测锚定）。
func brainSystemPrompt() string {
	return strings.Join([]string{
		"[[EXPERT:campaign-brain]]",
		"你是九头鸟的真头作战参谋。你的职责是有限的：基于给定画像，判断是否值得发起跨阶段资源编排建议（≤3 条，无高价值建议必须返回 []）。",
		"仅允许三类：budget_transfer（阶段间预算转移）、loopback_focus（聚焦回环补缺口，focus 填目标/类/端点）、replan_delta（新面纳入计划）。",
		"硬约束：只建议、不执行；不得建议越过授权范围/S1 授权门/执行档拦截/总预算；每条必须给 evidence（账本/矩阵里可查的具体依据）。",
		// v7.6.1（证据实体注入配套）：引用纪律——画像实体是唯一合法引用源，核存逐条验证。
		"引用纪律：evidence 只能从本画像中出现的编号/键选取（VT-xxx / fact:<key> / F-xxx / CD-xxx / evidence/ 路径）；「覆盖缺口」行与统计计数不可直接作为 evidence（可写入 focus 或 rationale）；引用画像之外的标识将被裁决拒绝。loopback_focus 的 focus 直接使用覆盖缺口行的 端点×类 形态，evidence 搭配相关 VT-/fact:/F- 编号。",
		"输出格式：仅一个 JSON 数组，元素字段 {type,rationale,evidence,focus,target_stage}；无建议输出 []。禁止输出数组之外的任何文字。",
	}, "\n")
}

// buildBrainProfile v7.6.1（证据实体注入，方案「参谋画像从统计升级为渗透信号」）：
// 作战参谋评审画像——统计计数与**可核存引用实体**并存。实体选取按渗透价值排序：
// open VT（可引用 VT-）→ 黑板事实（可引用 fact:<key>）→ 高危/确证发现（可引用 F-）→
// open 候选（可引用 CD-）；覆盖缺口明细**不可直接引用**（verifyEvidenceRefs 不核 endpoint
// 键），仅作 focus/rationale 素材并显式标注；战利品计数行作为 budget_transfer 价值信号。
// 修复的结构性缺陷：旧画像只有统计计数、无任何可引用 ID——参谋在「必须给 evidence」
// 约束下永远无法给出可核验引用，提议被 NO_EVIDENCE 结构性全灭（生产实证 3 收口 5/5 全拒）。
func (o *Orchestrator) buildBrainProfile(p *store.Project, stageID string) string {
	var b strings.Builder
	usage, _ := o.store.GetUsage(p.ID)
	budget := p.BudgetTokens
	if budget == 0 {
		budget = int64(o.cfg.MaxProjectTokens)
	}
	pct := ""
	if budget > 0 && usage != nil {
		pct = fmt.Sprintf("（已用 %.0f%%）", float64(usage.TotalTokens)/float64(budget)*100)
	}
	b.WriteString(fmt.Sprintf("## 预算\n- stage_tokens=%d project_total=%d/%s %s\n", usageStageTokens(usage, stageID), usageTotal(usage), humanBudget(budget), pct))
	if cs := o.store.CardStats(p.ID); cs["total"] > 0 {
		b.WriteString(fmt.Sprintf("## 执行卡漏斗\n- total=%d queued_vt=%d dispatched=%d evidence_linked=%d dispositioned=%d blocked=%d deferred=%d\n",
			cs["total"], cs["queued_vt"], cs["dispatched"], cs["evidence_linked"], cs["dispositioned"], cs["blocked"], cs["deferred"]))
	}
	// ①验证队列：计数 + open 实体（按 Priority 升序，与冲刺投递同口径）
	if vts, err := o.store.ListVTs(p.ID); err == nil {
		pending, ready := 0, 0
		var open []*store.VerificationTask
		for _, v := range vts {
			switch v.Status {
			case "pending":
				pending++
				open = append(open, v)
			case "ready":
				ready++
				open = append(open, v)
			}
		}
		b.WriteString(fmt.Sprintf("## 验证队列\n- pending=%d ready=%d\n", pending, ready))
		sort.Slice(open, func(i, j int) bool {
			if open[i].Priority != open[j].Priority {
				return open[i].Priority < open[j].Priority
			}
			return open[i].ID < open[j].ID
		})
		for i, v := range open {
			if i >= 5 {
				b.WriteString(fmt.Sprintf("- …（open 共 %d 条，引用以本清单编号为准）\n", len(open)))
				break
			}
			b.WriteString(fmt.Sprintf("- %s [%s/P%d] %s（就绪资产: %s）\n", v.ID, v.Status, v.Priority, truncateText(v.Title, 50), truncateText(v.ReadyAssets, 50)))
		}
	}
	// ②黑板事实：非 deprecated 前 5（fact:<key> 可核存引用）——确证优先、含攻击原语
	//（primitive:READ/WRITE/EXEC/SSRF/SQLI/AUTHZ/CRED）优先，渗透价值排序而非存储序。
	if facts, err := o.store.ListFacts(p.ID, 200); err == nil && len(facts) > 0 {
		var usable []*store.FactRecord
		for _, f := range facts {
			if f.Confidence == "deprecated" {
				continue
			}
			usable = append(usable, f)
		}
		factRank := func(f *store.FactRecord) int {
			r := 2
			if f.Confidence == "confirmed" {
				r -= 2
			}
			if strings.Contains(f.Value, "primitive:") {
				r -= 1
			}
			return r
		}
		sort.Slice(usable, func(i, j int) bool { return factRank(usable[i]) < factRank(usable[j]) })
		if len(usable) > 0 {
			b.WriteString("## 黑板关键事实\n")
			for i, f := range usable {
				if i >= 5 {
					break
				}
				b.WriteString(fmt.Sprintf("- fact:%s [%s] %s\n", f.Key, f.Confidence, truncateRunes(f.Value, 100)))
			}
		}
	}
	// ③高危/确证发现：确证优先、等级降序前 5（F- 可核存引用）
	if fs, err := o.store.ListFindings(p.ID); err == nil && len(fs) > 0 {
		rank := func(f *store.Finding) int {
			sv := map[string]int{"高": 0, "中": 1, "低": 2, "信息": 3}
			r, ok := sv[f.Severity]
			if !ok {
				r = 4
			}
			if f.Confidence == "确证" {
				r -= 4 // 确证优先于等级
			}
			return r
		}
		sorted := append([]*store.Finding(nil), fs...)
		sort.Slice(sorted, func(i, j int) bool { return rank(sorted[i]) < rank(sorted[j]) })
		b.WriteString("## 关键发现\n")
		for i, f := range sorted {
			if i >= 5 {
				break
			}
			b.WriteString(fmt.Sprintf("- %s [%s/%s] %s\n", f.ID, f.Severity, f.Confidence, truncateText(f.Title, 50)))
		}
	}
	// ④候选账本：open 前 3（CD- 可核存引用）
	if cands, err := o.store.ListCandidates(p.ID); err == nil {
		var open []*store.Candidate
		for _, c := range cands {
			if c.Disposition == "" || c.Disposition == "open" {
				open = append(open, c)
			}
		}
		if len(open) > 0 {
			b.WriteString(fmt.Sprintf("## 未定性候选（open %d）\n", len(open)))
			for i, c := range open {
				if i >= 3 {
					break
				}
				b.WriteString(fmt.Sprintf("- %s %s\n", c.ID, truncateText(c.Title, 50)))
			}
		}
	}
	// ⑤覆盖缺口：needs_follow_up 明细前 5——focus/rationale 素材（不可直接引用，显式标注）
	if cov, err := o.store.ListCoverage(p.ID); err == nil && len(cov) > 0 {
		nf := 0
		var gaps []*store.CoverageEntry
		for _, c := range cov {
			if c.Status == "needs_follow_up" {
				nf++
				gaps = append(gaps, c)
			}
		}
		b.WriteString(fmt.Sprintf("## 覆盖矩阵\n- units=%d needs_follow_up=%d\n", len(cov), nf))
		if len(gaps) > 0 {
			b.WriteString("### 覆盖缺口（仅作 focus/rationale 素材，不可作 evidence 引用）\n")
			for i, c := range gaps {
				if i >= 5 {
					break
				}
				line := fmt.Sprintf("- %s × %s × %s", c.Endpoint, c.VulnClass, c.Param)
				// v7.7.3 修复（某历史任务 实证）：缺口行附其自带证据指针——needs_follow_up
				// notes 内的 evidence/ 路径是可核存实体，且是"该缺口确实存在"的证明；缺失后
				// 参谋缺口类提议（聚焦回环补测）因 NO_EVIDENCE 被结构性全拒（3/3 实证）。
				if evs := gapEvidenceRefs(c.Notes); len(evs) > 0 {
					line += "（evidence: " + strings.Join(evs, ", ") + "）"
				}
				if strings.TrimSpace(c.Notes) != "" {
					line += "（" + firstLine(c.Notes) + "）"
				}
				b.WriteString(line + "\n")
			}
		}
	}
	// ⑥战利品计数（budget_transfer 价值信号：有可复用凭据时跨阶段利用更值得投入）
	if loot, err := o.store.ListLoot(p.ID, 100); err == nil && len(loot) > 0 {
		b.WriteString(fmt.Sprintf("## 战利品\n- 已登记 %d 件（掩码，跨阶段复用价值信号）\n", len(loot)))
	}
	if stats := o.store.AutonomyStats(p.ID); stats["total"] != nil && stats["total"].(int) > 0 {
		b.WriteString(fmt.Sprintf("## 提案账本\n- total=%d approved=%d escalations=%d\n", stats["total"], stats["approved"], stats["escalations"]))
	}
	return b.String()
}

// planDeltaOnScope B3：测试中新转 in_scope 的资产 → 自动执行卡（C-00 新面探针）+
// s4 计划版本 Bump + 时间线留痕。S1 初始界定不算增量；同资产幂等（已建 plan_delta 卡跳过）。
func (o *Orchestrator) planDeltaOnScope(p *store.Project, stageID, assetValue, evidence string) {
	if stageID == "s1" || strings.TrimSpace(assetValue) == "" {
		return
	}
	cards, _ := o.store.ListCards(p.ID)
	for _, c := range cards {
		if c.Outcome == "plan_delta" && c.Target == assetValue {
			return // 幂等
		}
	}
	_ = o.store.UpsertCard(&store.CardRecord{
		ProjectID: p.ID, Stage: "s4", Class: "C-00", Target: assetValue,
		State: "queued", Outcome: "plan_delta", Evidence: truncateText(evidence, 100),
	})
	if st := p.StageStates["s4"]; st != nil {
		st.PlanVersion++
	} else {
		// 桩初始化置 pending（与 Pipeline 预建口径一致，防止空 Status 被流水线误判）
		if p.StageStates == nil {
			p.StageStates = map[string]*store.StageState{}
		}
		p.StageStates["s4"] = &store.StageState{Status: "pending", PlanVersion: 1}
	}
	_ = o.store.SaveProject(p)
	_, _ = o.store.AddTimeline(&store.TimelineEvent{ProjectID: p.ID, Stage: stageID,
		Event:  "v7.2.0 planDelta",
		Detail: fmt.Sprintf("新 in_scope 资产 %s 自动生成执行卡（C-00 新面探针，queued）——s4 计划版本 Bump 至 v%d；S4 逐类对账表须扩展该行", assetValue, p.StageStates["s4"].PlanVersion)})
	o.log(p, stageID, fmt.Sprintf("🧭 planDelta：%s 转 in_scope → 自动建卡入 S4 计划（计划版本 v%d）", assetValue, p.StageStates["s4"].PlanVersion))
}

// budgetLedgerLine B4：目标×类×深度预算占用一行式（上下文注入）——
// 类覆盖直方图 + 深化单元 Top3（Count≥4 单点黑洞可视），P4-lite 确定性统计。
func budgetLedgerLine(cov []*store.CoverageEntry) string {
	if len(cov) == 0 {
		return ""
	}
	cls := map[string]int{}
	deep := map[string]int{}
	targets := map[string]bool{}
	for _, c := range cov {
		cls[c.VulnClass]++
		if c.Count >= 4 {
			deep[c.Endpoint+" | "+c.VulnClass] = c.Count
		}
		targets[extractCoverageTarget(c.Endpoint)] = true
		delete(targets, "")
	}
	type kv struct {
		k string
		v int
	}
	dl := []kv{}
	for k, v := range deep {
		dl = append(dl, kv{k, v})
	}
	sort.Slice(dl, func(i, j int) bool { return dl[i].v > dl[j].v })
	line := fmt.Sprintf("预算账本（v7.2.0 B4）：覆盖单元 %d｜目标 %d｜类 %d", len(cov), len(targets), len(cls))
	if len(dl) > 0 {
		top := []string{}
		for i, e := range dl {
			if i >= 3 {
				break
			}
			top = append(top, fmt.Sprintf("%s ×%d", e.k, e.v))
		}
		line += "｜深化单元 Top（≥4 轮，注意单点黑洞）: " + strings.Join(top, " / ")
	}
	return line
}

func extractCoverageTarget(endpoint string) string {
	if i := strings.LastIndex(endpoint, "（"); i >= 0 && strings.HasSuffix(endpoint, "）") {
		return endpoint[i+3 : len(endpoint)-3]
	}
	if i := strings.LastIndex(endpoint, "("); i >= 0 && strings.HasSuffix(endpoint, ")") {
		return endpoint[i+1 : len(endpoint)-1]
	}
	// v7.2.0 核对修复（审计 D）：@target 风格（S4 对账表/VT 常用形态，如 /login@app.test）
	if i := strings.LastIndex(endpoint, "@"); i > 0 && i < len(endpoint)-1 && !strings.Contains(endpoint[i+1:], "/") {
		return endpoint[i+1:]
	}
	return ""
}

func usageStageTokens(u *store.UsageRecord, stage string) int64 {
	if u == nil {
		return 0
	}
	return u.ByStage[stage]
}

func usageTotal(u *store.UsageRecord) int64 {
	if u == nil {
		return 0
	}
	return u.TotalTokens
}

func humanBudget(b int64) string {
	if b <= 0 {
		return "不限"
	}
	return fmt.Sprintf("%d", b)
}

// ---- v7.3.0 C3 PoC 预生成工厂（确定性导出，零 LLM）----

// pocFactory s4 收口时把发现库中自带 POC 请求/响应对的确证发现导出为就绪 PoC 文件
// （poc/PoC-<F 编号>.md）——S5 开工即全队列就绪态（治「破解率 100%、投递率 0%」的另一半：
// 就绪资产不再依赖模型手工誊写）。幂等：同编号文件重写覆盖（S4 收口幂等）。
func (o *Orchestrator) pocFactory(p *store.Project, stageID string) {
	findings, err := o.store.ListFindings(p.ID)
	if err != nil {
		return
	}
	n := 0
	for _, f := range findings {
		if len(f.POC) == 0 {
			continue
		}
		var b strings.Builder
		b.WriteString(fmt.Sprintf("# PoC · %s（%s）\n\n", f.Title, f.ID))
		b.WriteString(fmt.Sprintf("- 等级/置信度: %s / %s\n- 利用前提: %s\n- 归属目标: %s\n\n",
			f.Severity, f.Confidence, firstNonEmpty(f.Access, "未标注"), firstNonEmpty(f.TargetRef, "未标注")))
		b.WriteString("## 详情\n\n" + strings.TrimSpace(f.Detail) + "\n\n")
		if f.Remediation != "" {
			b.WriteString("## 修复建议\n\n" + strings.TrimSpace(f.Remediation) + "\n\n")
		}
		b.WriteString("## 实测请求/响应对（v5.3.6 POC 原文，投递前先在受控环境复核）\n\n")
		for i, pc := range f.POC {
			b.WriteString(fmt.Sprintf("### 第 %d 组\n\n**请求原文**\n\n```http\n%s\n```\n\n**响应原文**\n\n```http\n%s\n```\n\n", i+1, strings.TrimSpace(pc.Request), strings.TrimSpace(pc.Response)))
		}
		path := fmt.Sprintf("poc/PoC-%s.md", f.ID)
		if _, werr := o.exec.WriteFile(p.ID, path, b.String()); werr == nil {
			n++
		}
	}
	if n > 0 {
		o.log(p, stageID, fmt.Sprintf("🏭 PoC 工厂：已导出 %d 份就绪 PoC 至 poc/（S5 开工承接投递）", n))
		_, _ = o.store.AddTimeline(&store.TimelineEvent{ProjectID: p.ID, Stage: stageID,
			Event:  "v7.3.0 PoC 工厂",
			Detail: fmt.Sprintf("确证发现自带 POC 的 %d 条已导出 poc/PoC-<F 编号>.md——S5 开工队列全就绪态", n)})
	}
}

// pocReadyLine S5 上下文注入行：PoC 工厂就绪清单（数量 + 编号样本）。
func (o *Orchestrator) pocReadyLine(p *store.Project) string {
	findings, err := o.store.ListFindings(p.ID)
	if err != nil {
		return ""
	}
	ids := []string{}
	for _, f := range findings {
		if len(f.POC) > 0 {
			ids = append(ids, f.ID)
		}
	}
	if len(ids) == 0 {
		return ""
	}
	sample := ids
	if len(sample) > 8 {
		sample = sample[:8]
	}
	return fmt.Sprintf("PoC 工厂就绪（v7.3.0 C3）：poc/ 下 %d 份就绪 PoC（%s…）——开工 list_files 承接，按 access×impact-rank 队列直接投递，勿重新誊写。", len(ids), strings.Join(sample, ","))
}
