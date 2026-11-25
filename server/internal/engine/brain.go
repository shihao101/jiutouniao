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
	cli, model := o.clientFor(p)
	if cli == nil {
		return // 测试/无 LLM 装配：fail-open 跳过
	}
	// 评审输入：预算/覆盖/验证队列/提案账本的紧凑画像
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
	if vts, err := o.store.ListVTs(p.ID); err == nil {
		pending, ready := 0, 0
		for _, v := range vts {
			if v.Status == "pending" {
				pending++
			} else if v.Status == "ready" {
				ready++
			}
		}
		b.WriteString(fmt.Sprintf("## 验证队列\n- pending=%d ready=%d\n", pending, ready))
	}
	if stats := o.store.AutonomyStats(p.ID); stats["total"] != nil && stats["total"].(int) > 0 {
		b.WriteString(fmt.Sprintf("## 提案账本\n- total=%d approved=%d escalations=%d\n", stats["total"], stats["approved"], stats["escalations"]))
	}
	if cov, err := o.store.ListCoverage(p.ID); err == nil && len(cov) > 0 {
		nf := 0
		for _, c := range cov {
			if c.Status == "needs_follow_up" {
				nf++
			}
		}
		b.WriteString(fmt.Sprintf("## 覆盖矩阵\n- units=%d needs_follow_up=%d\n", len(cov), nf))
	}

	sys := strings.Join([]string{
		"[[EXPERT:campaign-brain]]",
		"你是九头鸟的真头作战参谋。你的职责是有限的：基于给定画像，判断是否值得发起跨阶段资源编排建议（≤3 条，无高价值建议必须返回 []）。",
		"仅允许三类：budget_transfer（阶段间预算转移）、loopback_focus（聚焦回环补缺口，focus 填目标/类/端点）、replan_delta（新面纳入计划）。",
		"硬约束：只建议、不执行；不得建议越过授权范围/S1 授权门/执行档拦截/总预算；每条必须给 evidence（账本/矩阵里可查的具体依据）。",
		"输出格式：仅一个 JSON 数组，元素字段 {type,rationale,evidence,focus,target_stage}；无建议输出 []。禁止输出数组之外的任何文字。",
	}, "\n")
	msgs := []llm.Message{{Role: "system", Content: sys}, {Role: "user", Content: b.String()}}
	resp, usage2, err := cli.Chat(ctx, model, msgs, nil, 0.3, 1024)
	if err != nil {
		o.log(p, stageID, "🎖 作战参谋评审不可用（LLM 失败，跳过）: "+truncateText(err.Error(), 80))
		return
	}
	o.accountUsage(p, stageID, usage2)
	sugs := parseBrainSuggestions(resp.Content)
	if len(sugs) == 0 {
		o.log(p, stageID, "🎖 作战参谋评审：无高价值编排建议（[]）")
		return
	}
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
