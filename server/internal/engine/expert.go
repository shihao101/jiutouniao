package engine

import (
	"context"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"jiutouniao/internal/llm"
	"jiutouniao/internal/store"
)

// 专家团队与执行监控（PentAGI 移植）：
// - consultExpert: 六专家单次深度会诊（adviser/pentester/coder/searcher/reflector/reporter）
// - askUser: ask_user 屏障——挂起等待人工回答，留痕于 asks 桶
// - 执行监控: 同一工具+参数连续重复调用时自动召 adviser 评审进度

// 专家人格（源自 PentAGI specialist 模板思想，结合九头鸟方法论精简）。
var expertPersonas = map[string]string{
	"adviser":   "你是资深渗透测试导师（mentor）。面对受阻的执行进度，指出当前方法的问题、给出 2-3 条具体可行的下一步替代方案，并说明各自的判据与风险等级。回答精炼、可执行，中文，不超过 300 字。",
	"pentester": "你是渗透测试专家。针对给定问题给出攻击面分析、具体测试步骤（命令级）、判据与置信度。仅限授权范围内方法，禁止破坏性操作。中文，不超过 350 字。",
	"coder":     "你是安全开发专家。针对给定需求给出可直接使用的脚本/代码（优先 Python/Bash），附带用法说明与注意事项；代码要最小化、只读优先。中文说明，不超过 350 字。",
	"searcher":  "你是 OSINT 与情报检索专家。给出检索路径：建议的搜索引擎 dork、数据源（证书透明度/测绘平台/代码库/文档站）、查询关键词组合与甄别要点。中文，不超过 300 字。",
	"reflector": "你是质量审查员（reflector）。审视给定的阶段产出：检查覆盖度缺口、证据是否支撑结论、交付物是否可复现。输出「缺口清单」+ 每条的处理建议；若质量合格则明确说「无关键缺口」。中文，不超过 300 字。",
	"reporter":  "你是报告撰写专家。把给定的发现与证据整理成结构化报告片段：标题、等级、描述、复现步骤、影响与修复建议。忠实于证据，不虚构。中文，不超过 400 字。",
}

// consultExpert 专家会诊：单次 LLM 调用（无工具面），带最小项目上下文。
func (o *Orchestrator) consultExpert(ctx context.Context, p *store.Project, stageID, role, question string) (string, error) {
	persona, ok := expertPersonas[role]
	if !ok {
		// 未知角色回退为 adviser，并告知可用角色
		persona = expertPersonas["adviser"]
		role = "adviser"
	}
	sys := strings.Join([]string{
		"[[EXPERT:" + role + "]]",
		persona,
		"授权背景：本项目已确认书面授权（范围与红线见下），你的建议仅用于该授权测试。",
	}, "\n\n")

	// 最小上下文：项目信息 + 记忆库概览 + 最近证据命令（避免 prompt 膨胀）
	findings, _ := o.store.ListFindings(p.ID)
	assets, _ := o.store.ListAssets(p.ID)
	var b strings.Builder
	b.WriteString(fmt.Sprintf("## 项目背景\n- 项目: %s\n- 目标: %s\n- 当前阶段: %s\n- 已登记资产 %d 项 / 发现 %d 项\n",
		p.Name, firstLine(p.Target), stageID, len(assets), len(findings)))
	for i, f := range findings {
		if i >= 5 {
			break
		}
		b.WriteString(fmt.Sprintf("- 发现[%s/%s] %s\n", f.Severity, f.Confidence, firstLine(f.Title)))
	}
	for i, a := range assets {
		if i >= 8 {
			break
		}
		b.WriteString(fmt.Sprintf("- 资产[%s] %s\n", a.Type, a.Value))
	}
	b.WriteString("\n## 问题\n" + question)

	cli, modelName := o.clientFor(p)
	msgs := []llm.Message{
		{Role: "system", Content: sys},
		{Role: "user", Content: b.String()},
	}
	resp, usage, err := cli.Chat(ctx, modelName, msgs, nil, 0.3, o.cfg.LLM.MaxTokens)
	if err != nil {
		return "", err
	}
	o.accountUsage(p, stageID, usage)
	if strings.TrimSpace(resp.Content) == "" {
		return "", fmt.Errorf("专家无回复")
	}
	return resp.Content, nil
}

// ---------- 向人提问（ask_user 屏障） ----------

type askWaiters struct {
	mu      sync.Mutex
	waiters map[string]chan string // askID -> 回答通道
}

func (o *Orchestrator) askWaiter(id string) chan string {
	o.askMu.Lock()
	defer o.askMu.Unlock()
	if o.asks == nil {
		o.asks = map[string]chan string{}
	}
	ch := make(chan string, 1)
	o.asks[id] = ch
	return ch
}

func (o *Orchestrator) popAskWaiter(id string) chan string {
	o.askMu.Lock()
	defer o.askMu.Unlock()
	ch, ok := o.asks[id]
	if ok {
		delete(o.asks, id)
	}
	return ch
}

// askUser 挂起提问：落库留痕 + 实时推送，阻塞等待人工回答；熔断/超时返回错误。
func (o *Orchestrator) askUser(ctx context.Context, projectID, stage, question string) (string, error) {
	rec := &store.AskRecord{ProjectID: projectID, Stage: stage, Question: truncateText(question, 1500), Status: "pending"}
	id, err := o.store.AddAsk(rec)
	if err != nil {
		return "", err
	}
	o.bus.Publish(projectID, "ask", rec)
	o.log(o.mustProject(projectID), stage, fmt.Sprintf("❓ 向人工提问[%s]：%s", id, firstLine(question)))

	// v3.4.0 屏障超时（与人工审批同源配置）：提问不再无限挂起流水线
	var timeoutCh <-chan time.Time
	if o.cfg.Engine.BarrierTimeoutSec > 0 {
		timer := time.NewTimer(time.Duration(o.cfg.Engine.BarrierTimeoutSec) * time.Second)
		defer timer.Stop()
		timeoutCh = timer.C
	}
	ch := o.askWaiter(id)
	select {
	case ans := <-ch:
		return ans, nil
	case <-ctx.Done():
		o.cancelAsk(id, "")
		return "", ctx.Err()
	case <-timeoutCh:
		o.cancelAsk(id, "等待超时")
		o.log(o.mustProject(projectID), stage, fmt.Sprintf("⏱ 提问[%s]等待超时（%d 分钟），已自动取消", id, o.cfg.Engine.BarrierTimeoutSec/60))
		return "", fmt.Errorf("提问等待超时（%d 分钟），已自动取消", o.cfg.Engine.BarrierTimeoutSec/60)
	}
}

// AnswerAsk 人工回答提问（Web 调用），唤醒等待中的执行流。
func (o *Orchestrator) AnswerAsk(id, answer, by string) error {
	rec, err := o.store.GetAsk(id)
	if err != nil {
		return err
	}
	if rec.Status != "pending" {
		return fmt.Errorf("该提问已处理")
	}
	now := time.Now()
	rec.AnsweredAt = &now
	rec.AnsweredBy = by
	rec.Status = "answered"
	// v5.6.0（审计修复高危#1）：凭据专用通道的回答不落明文——Answer 只存占位说明，
	// 原文仅经内存通道交给等待中的 request_credential 处理（入库加密/掩码摘要回写）。
	if rec.Kind == "credential" {
		rec.Answer = "（凭据专用通道：原文不落库；入库结果与掩码见凭据记录）"
	} else {
		// v5.6.1（审计 RunB#6）：普通提问的持久化答案做模式脱敏——用户误粘贴凭据时
		// 不落明文（模型通道返回原文，不影响会话内的正当使用）。
		rec.Answer = truncateText(maskSensitiveText(answer), 1500)
	}
	if err := o.store.SaveAsk(rec); err != nil {
		return err
	}
	if ch := o.popAskWaiter(id); ch != nil {
		ch <- answer
	}
	o.bus.Publish(rec.ProjectID, "ask", rec)
	o.log(o.mustProject(rec.ProjectID), rec.Stage, fmt.Sprintf("💬 提问[%s]已由 %s 回答", id, by))
	return nil
}

// askUserCredential v5.6.0 凭据专用提问通道（审计修复高危#1）：
// 问题落库（Kind=credential）→ 阻塞等待人工回答 → 回答原文只经内存通道返回 →
// 调用方（request_credential 工具）负责入加密仓库并回写掩码摘要。
// 与 askUser 的区别：AnswerAsk 对 credential 提问不落明文 Answer。
// 返回值：(askID, 原文回答, err)——原文仅存在于内存，绝不落库。
func (o *Orchestrator) askUserCredential(ctx context.Context, projectID, stage, question string) (string, string, error) {
	rec := &store.AskRecord{ProjectID: projectID, Stage: stage,
		Question: truncateText(question, 1500), Status: "pending", Kind: "credential"}
	id, err := o.store.AddAsk(rec)
	if err != nil {
		return "", "", err
	}
	o.bus.Publish(projectID, "ask", rec)
	o.log(o.mustProject(projectID), stage, fmt.Sprintf("🔐 向人工索取凭据[%s]：%s（回答经专用通道加密入库，不落明文）", id, firstLine(question)))

	var timeoutCh <-chan time.Time
	if o.cfg.Engine.BarrierTimeoutSec > 0 {
		timer := time.NewTimer(time.Duration(o.cfg.Engine.BarrierTimeoutSec) * time.Second)
		defer timer.Stop()
		timeoutCh = timer.C
	}
	ch := o.askWaiter(id)
	select {
	case ans := <-ch:
		return id, ans, nil
	case <-ctx.Done():
		o.cancelAsk(id, "")
		return id, "", ctx.Err()
	case <-timeoutCh:
		o.cancelAsk(id, "等待超时")
		o.log(o.mustProject(projectID), stage, fmt.Sprintf("⏱ 凭据索取[%s]等待超时（%d 分钟），已自动取消", id, o.cfg.Engine.BarrierTimeoutSec/60))
		return id, "", fmt.Errorf("凭据索取等待超时（%d 分钟），已自动取消", o.cfg.Engine.BarrierTimeoutSec/60)
	}
}

// saveCredentialAskSummary 回写凭据提问的掩码摘要（入库成功/失败两种形态，均无明文）。
func (o *Orchestrator) saveCredentialAskSummary(id, summary string) {
	if rec, err := o.store.GetAsk(id); err == nil {
		rec.Answer = truncateText(summary, 500)
		_ = o.store.SaveAsk(rec)
		o.bus.Publish(rec.ProjectID, "ask", rec)
	}
}

// cancelAsk 取消提问（熔断/中断时）。
func (o *Orchestrator) cancelAsk(id, reason string) {
	if rec, err := o.store.GetAsk(id); err == nil && rec.Status == "pending" {
		rec.Status = "cancelled"
		_ = o.store.SaveAsk(rec)
		if reason != "" {
			rec.Answer = reason
		}
		if ch := o.popAskWaiter(id); ch != nil {
			ch <- "（已取消：项目熔断或会话中断）"
		}
		o.bus.Publish(rec.ProjectID, "ask", rec)
	}
}

// CancelProjectAsks 熔断时取消项目全部待答提问。
func (o *Orchestrator) CancelProjectAsks(projectID string) {
	asks, err := o.store.ListAsks(projectID)
	if err != nil {
		return
	}
	for _, a := range asks {
		if a.Status == "pending" {
			o.cancelAsk(a.ID, "项目已熔断")
		}
	}
}

func (o *Orchestrator) mustProject(id string) *store.Project {
	p, err := o.store.GetProject(id)
	if err != nil {
		return &store.Project{ID: id}
	}
	return p
}

// ---------- 执行监控（PentAGI execution monitor 移植） ----------

type execMonitor struct {
	// v3.2.0 签名窗口循环检测（移植 ctf-agent 确定性循环检测 + CAI 卡壳续跑思想）：
	// 旧实现只识别「完全相同参数连续 N 次」，换一个编号/目标就能逃逸
	// （实测：2 分钟探针连续数小时的等待型空转全部绕过监控）。
	// 现改为滑动窗口内「归一化签名」计数：数字/长十六进制/base64 token 泛化后，
	// `curl http://x?i=1`、`i=2`… 的枚举式空转计入同一签名；正常批量脚本
	// （单命令带词表）不受影响。warn@3 注入换路预警（无 LLM 成本），break@5 召导师评审。
	window []string        // 最近 monitorWindowN 轮签名（FIFO）
	counts map[string]int  // 窗口内各签名出现次数
	warned map[string]bool // 已注入过预警的签名（避免重复轰炸）
	breaks map[string]int  // 已触发熔断评审的签名次数（≥2 不再召导师，改硬文本）

	// v2.x 连续完全相同指纹检测保留（连续 N 次一字不差的调用）
	lastKey    string
	sameCount  int
	intervened bool
}

const (
	monitorSameToolLimit = 4  // 连续完全相同 tool+args 第 4 次 → 导师评审（保留 v2.x 语义）
	monitorWindowN       = 12 // 签名滑动窗口大小（轮）
	monitorSigWarnAt     = 3  // 窗口内同签名第 3 次 → 注入换路预警
	monitorSigBreakAt    = 5  // 窗口内同签名第 5 次 → 召导师评审 + 强制换路
)

// monitorExemptTools v3.4.2/v3.4.3：签名窗口豁免清单（合法的重复调用模式，不构成空转信号）。
var monitorExemptTools = map[string]bool{
	"poll_async":    true, // 文档化模式：poll → 做别的 → 再 poll
	"shell_read":    true, // 交互会话增量读，天然重复
	"search_memory": true, // v3.4.3：窗口压缩可能存根化早前检索结果，重查是正确行为（查到结论应上黑板）
	"list_files":    true, // 廉价幂等读，承接文件清单常需重看
}

// monitorSignature 归一化工具调用签名：小写、折叠空白、数字与长十六进制/base64 泛化。
// 目的：把「同方法换编号」的逐条枚举统计为同一签名（该模式应脚本化批量而非逐轮空转），
// 同时不把不同的命令误并（词面差异仍保留）。
var (
	sigHexRe = regexp.MustCompile(`[0-9a-f]{16,}`)
	sigB64Re = regexp.MustCompile(`[a-z0-9+/]{32,}`)
	sigNumRe = regexp.MustCompile(`\d+`)
)

func monitorSignature(tc llm.ToolCall) string {
	s := strings.ToLower(tc.Name + "|" + tc.Arguments)
	s = sigHexRe.ReplaceAllString(s, "#id#")
	s = sigB64Re.ReplaceAllString(s, "#b64#")
	s = sigNumRe.ReplaceAllString(s, "#n#")
	return strings.Join(strings.Fields(s), " ")
}

// monitorCheck 判断是否触发循环介入；触发时把预警/导师建议并入工具结果回传。
// 注意：非并发安全——调用方在结果回填处顺序调用（与 v2.x 一致）。
func (o *Orchestrator) monitorCheck(ctx context.Context, p *store.Project, stageID string, mon *execMonitor, tc llm.ToolCall, result string) string {
	// ---- 旧检测：连续完全相同调用 → 导师评审（保留） ----
	key := tc.Name + "|" + tc.Arguments
	if key == mon.lastKey {
		mon.sameCount++
	} else {
		mon.sameCount = 0
		mon.lastKey = key
		mon.intervened = false
	}
	// v3.4.3 修复（v3.4.2 引入）：豁免分支此前在旧检测之后重复自增共享计数器，
	// 同签名第 2 次合法 poll 就提前触发提醒（应为第 4 次）。现重构：单一计数，
	// 豁免判断前置于导师评审，豁免工具只给确定性提醒、不召导师。
	if monitorExemptTools[tc.Name] {
		if mon.sameCount+1 >= monitorSameToolLimit && !mon.intervened {
			mon.intervened = true
			mon.sameCount = 0
			return fmt.Sprintf("⏳ 已连续 %d 次轮询/重查同一目标且期间无其他动作——同步等待或重复检索是反模式：先做其他子任务再回来 poll（后台任务有超时上限，不会挂死流水线）；若因上下文压缩丢失了早前结果，重查后请立即把结论 upsert_fact 上黑板防再丢。\n\n── 原结果 ──\n", monitorSameToolLimit) + result
		}
		return result
	}
	if mon.sameCount+1 >= monitorSameToolLimit && !mon.intervened {
		mon.intervened = true
		mon.sameCount = 0 // 介入后重置，避免连续轰炸
		o.log(p, stageID, "⚠ 执行监控：检测到连续重复调用 "+tc.Name+"，自动召开导师评审")
		advice, err := o.consultExpert(ctx, p, stageID, "adviser",
			fmt.Sprintf("执行监控告警：阶段[%s]连续 %d 次以相同参数调用工具 %s（参数摘要：%s），疑似陷入循环无进展。请评估当前方法是否有效，给出 2-3 条替代路径或中止建议。",
				stageID, monitorSameToolLimit, tc.Name, truncateText(tc.Arguments, 200)))
		if err != nil {
			o.log(p, stageID, "导师评审调用失败: "+err.Error())
			return "⚠ 执行监控提示：已连续多次以相同参数调用 " + tc.Name + "，请更换方法或补充信息，避免死循环。\n\n── 原结果 ──\n" + result
		}
		return "🎓 [导师评审] " + advice + "\n\n── 原工具结果 ──\n" + result
	}

	// ---- v3.2.0 签名窗口检测：warn@3 / break@5（v3.4.3：豁免工具已在上方提前返回） ----
	sig := monitorSignature(tc)
	if mon.counts == nil {
		mon.counts = map[string]int{}
		mon.warned = map[string]bool{}
		mon.breaks = map[string]int{}
	}
	mon.counts[sig]++
	mon.window = append(mon.window, sig)
	if len(mon.window) > monitorWindowN {
		old := mon.window[0]
		mon.window = mon.window[1:]
		if mon.counts[old] > 0 {
			mon.counts[old]--
		}
		if mon.counts[old] <= 0 {
			delete(mon.counts, old)
		}
	}
	c := mon.counts[sig]
	switch {
	case c >= monitorSigBreakAt:
		mon.counts[sig] = 0 // 给一条生路：清零后重新累计，避免每次都轰炸导师
		mon.breaks[sig]++
		o.log(p, stageID, fmt.Sprintf("⛔ 执行监控：签名[%s] 窗口内第 %d 次，触发熔断评审", truncateText(sig, 60), monitorSigBreakAt))
		if mon.breaks[sig] <= 2 {
			advice, err := o.consultExpert(ctx, p, stageID, "adviser",
				fmt.Sprintf("执行监控熔断：阶段[%s]工具 %s 的归一化调用签名在最近 %d 轮内出现 %d 次（参数摘要：%s），已构成确定性空转循环。请给出：1) 立即可执行的替代方法（换工具/换路径/脚本化批量）；2) 若该方向确无价值，明确建议放弃并记录覆盖度。",
					stageID, tc.Name, monitorWindowN, monitorSigBreakAt, truncateText(tc.Arguments, 200)))
			if err != nil {
				o.log(p, stageID, "导师评审调用失败: "+err.Error())
				return "⛔ 循环熔断：同一调用签名已出现第 " + strconv.Itoa(monitorSigBreakAt) + " 次。禁止原样重试：改用脚本一次性批量完成并落盘分析，或更换方法，或 update_coverage(waf_blocked/premise_failed) 后放弃该方向。\n\n── 原结果 ──\n" + result
			}
			return "⛔ [循环熔断·导师评审] " + advice + "\n\n── 原工具结果 ──\n" + result
		}
		return "⛔ 循环熔断（第 " + strconv.Itoa(mon.breaks[sig]) + " 次）：该签名已被导师评审过仍继续重复。硬性要求：下一次调用不得再出现该签名——脚本化批量、更换工具或放弃并登记覆盖度。\n\n── 原结果 ──\n" + result
	case c >= monitorSigWarnAt && !mon.warned[sig]:
		mon.warned[sig] = true
		o.log(p, stageID, "⚠ 执行监控：签名["+truncateText(sig, 60)+"] 窗口内第 "+strconv.Itoa(c)+" 次，注入换路预警")
		return fmt.Sprintf("⚠ 循环预警：同一调用签名（参数已归一化）在本阶段窗口内第 %d 次出现。若为逐条枚举，请改写为单命令脚本批量执行后统一分析（省轮次省 token）；若为反复重试同一探测，立即更换方法或路径。\n\n── 原工具结果 ──\n", c) + result
	}
	return result
}

// ---------- 反思门（PentAGI reflector 移植） ----------

// reflectStage 收口前的质量审查：检查覆盖度缺口、证据支撑与交付物可复现性。
// 输出约定：回复第一行 PASS（放行）或 BLOCK（拦截），随后为审查意见。
func (o *Orchestrator) reflectStage(ctx context.Context, p *store.Project, stageID string) (string, bool, error) {
	findings, _ := o.store.ListFindings(p.ID)
	assets, _ := o.store.ListAssets(p.ID)
	stageFindings := 0
	for _, f := range findings {
		if f.Stage == stageID {
			stageFindings++
		}
	}
	files, _ := o.listWorkspaceFiles(p.ID, "")
	cov, _ := o.store.ListCoverage(p.ID)
	covSummary := map[string]int{}
	for _, c := range cov {
		covSummary[c.Status]++
	}

	var b strings.Builder
	b.WriteString(fmt.Sprintf("## 审查对象\n阶段[%s]申请收口。\n\n", stageID))
	b.WriteString(fmt.Sprintf("- 本阶段发现 %d 条 / 全项目资产 %d 项\n- 工作区文件 %d 个\n- 覆盖度矩阵：%v\n\n", stageFindings, len(assets), len(files), covSummary))
	b.WriteString("### 最近证据（命令与结果摘要）\n")
	evs, _ := o.store.ListEvidence(p.ID)
	n := 0
	for i := len(evs) - 1; i >= 0 && n < 10; i-- {
		if evs[i].Stage != stageID {
			continue
		}
		b.WriteString(fmt.Sprintf("- $ %s → %s\n", truncateText(evs[i].Input, 100), truncateText(strings.ReplaceAll(evs[i].Output, "\n", " "), 100)))
		n++
	}
	if n == 0 {
		b.WriteString("-（本阶段暂无命令证据）\n")
	}
	b.WriteString("\n## 审查要求\n")
	b.WriteString("1) 判断该阶段是否达成了其目标且有证据支撑；2) 指出明显缺口（如：扫描未做全端口、发现无证据、交付物缺失）。\n")
	// v2.3.0：S7/S8 专项核查（实测缺陷：清理波及存量数据、报告同根因拆条抬高计数、未实测利用断言）
	// v6.8.0（S7-②）S7 节重写：旧三问停留在 v5.1.3 之前口径（问句 a 隐含「自建数据可执行删除」、
	// 问句 c 是「执行后还原」旧范式），与 v5.1.3「自建数据只登记不删除」/v5.3.0「清理确认清单仅有
	// 登记完整性核对+只读复核两类动作」单一规则直接矛盾（同文件 S6 节已按新口径，s7 是漏改点）；
	// 且旧三问未覆盖 S7-2「三件事」（四元组对账/并入移交清单/只读复核）。现按单一规则四问重写。
	if stageID == "s7" {
		b.WriteString("\n### S7 专项核查（清理铁律·v5.1.3/v5.3.0 单一规则）\n")
		b.WriteString("a) 本阶段（含时间线/交付物记录的执行动作）是否存在任何目标侧删除/修改/还原/注销类执行——rm/del/DELETE/UPDATE/DROP/TRUNCATE/reg delete/sc delete/net user /delete/atrm/schtasks /delete/服务删除/应用重启/Filter 卸载？**单一规则：智能体不执行任何目标侧清理，登记移交≠执行**（isolated_lab 项目亦以快照恢复回收，不在目标上执行清理命令）——出现即 BLOCK。\n")
		b.WriteString("b) 《需人工清理清单》是否逐项含四元组（位置/指纹/建议清理命令/验证命令），并与上下文「S6 移交项」块、《上传文件记录清单》逐项对账——上游已登记项缺并入、或四元组残缺且未补齐说明即 BLOCK；存量数据被注入载荷的行是否只登记未触碰（DELETE/UPDATE/就地中和类语句出现即 BLOCK）？\n")
		b.WriteString("c) 是否完成「测试前基线（S1 记录的资产/数据规模）vs 移交清单」的只读复核，差异逐条说明并写入《需人工清理清单》？\n")
		b.WriteString("d) 《待续清单处置》是否对 needs_follow_up 逐项真实三选一（已补测有 update_coverage 回写 / 范围外附理由 / 移交复测含启动条件·步骤·工作量三要素）——零引用条目即 BLOCK（机械门管「有没有引用」，本问管「引用是否真实处置」）？\n")
	}
	if stageID == "s8" {
		b.WriteString("\n### S8 专项核查（去重与反夸大）\n")
		b.WriteString("a) P0/P1 条目是否存在同根因拆分（同一漏洞机制+同一修复动作应合并为一条，多种表现写在条目内）？发现即 BLOCK。\n")
		// v6.9.0（S8-②）问句 b 细化：证据编号须与 findings 库 EvidenceIDs 对得上——只引不对应也视为未引用。
		b.WriteString("b) P0/P1 每条是否都引用了实测复现命令或证据文件（EV-xxx）？引用的证据编号是否与 findings 库该条目的证据对得上——只引不对应也视为未引用。仅凭数据结构推断（如「存在 reset_token 字段即可接管账号」）而无实测的，必须降为「待验证」单列。\n")
		b.WriteString("c) P0/P1/P2 计数是否等于独立根因数（非原始发现条数）？定级表是否附合并映射？\n")
		// v6.9.0（S8-⑥）问句 d：防漏并（与 a/c 的防拆条虚高对称的虚低方向）——多目标分组文件
		// 承接清单在上下文「分组交付物承接」块在场，漏一组且无说明即 BLOCK；单目标项目无该块，跳过本问。
		b.WriteString("d) 多目标项目：上下文「分组交付物承接」清单中每个 s4-/s5-/s6-/spec- 文件的已验证漏洞是否都已进《发现详情》或在盲区章说明未并入原因——漏一组且无说明即 BLOCK（单目标项目跳过本问）。\n")
		// v6.9.0（S8-②）审查素材注入——此前输入只有计数与证据摘要，三问对报告正文是盲审
		// （同根因拆条/证据引用/计数=根因数均针对定级表与发现详情，审查方看不到即无法核查）。
		// 呈现性注入不新增拦截；机械层反向对账由 deterministicGate S8-③ 门承担，两层互补。
		if raw, rerr := o.exec.ReadFile(p.ID, "report.md"); rerr == nil {
			b.WriteString("\n### 审查素材（S8 专项核查输入）\n")
			b.WriteString("#### report.md 定级表与发现详情摘录\n" + s8ReportExcerpt(raw) + "\n")
			rids := s8ReportRIDs(raw)
			if len(rids) == 0 {
				b.WriteString("#### 报告 R- 条目编号\n（report.md 未检出 ^### R- 条目——若报告以其他编号体系书写，请在意见中指出）\n")
			} else {
				b.WriteString("#### 报告 R- 条目编号\n" + strings.Join(rids, ", ") + "\n")
			}
			if len(findings) > 0 {
				// v6.9.0 第六轮核对：清单附证据编号（EvidenceIDs，引擎自动关联的 EV- 编号）——
				// 问句 b「引用的证据编号是否与 findings 库该条目的证据对得上」的核查数据源：
				// 素材只有编号/等级/标题时证据对应无法核对（与第三轮 key_figures 通道缺口同类的
				// 「承诺有执行点、数据源缺位」形态）。
				b.WriteString("#### findings 库全量清单（编号/等级/置信度/证据/标题）\n")
				for i, f := range findings {
					if i >= 50 {
						b.WriteString(fmt.Sprintf("- …（其余 %d 条截断，search_memory query=\"finding:<id>\" 可直取单条全文）\n", len(findings)-50))
						break
					}
					b.WriteString(s8FindingLine(f) + "\n")
				}
			}
		} else {
			b.WriteString("\n### 审查素材（S8 专项核查输入）\n（report.md 不可读——契约守卫会在收口前拦截/归位；请在意见中指出报告缺失）\n")
		}
	}
	// v6.3.0（S3-⑦）：S3 专项核查——兑现 s3.md S3-10「反思门会按清单抽查」的承诺：
	// R7 第一层假设缺漏审查五项清单逐项提问（此前 s3 只走通用审查，专项节仅 s7/s8）。
	if stageID == "s3" {
		b.WriteString("\n### S3 专项核查（R7 第一层假设缺漏审查，对照《假设缺漏审查留痕》）\n")
		b.WriteString("a) 筛查矩阵 27 类三态完整性：判定表 27 行齐、每行判定恰为 假设/不适用/待判定 之一且附证据指针？\n")
		b.WriteString("b) STRIDE 逐组件完备性：DFD 每组件×每元素有枚举结论（威胁模型可溯源，不留「待补」空组件）？\n")
		b.WriteString("c) 组合链覆盖：防护绕过/边界类（C-10/C-11）命中时同类面是否全部排期复测？\n")
		b.WriteString("d) 数据类映射：行业模板（K1）命中时 C-17 具象化是否落表？\n")
		b.WriteString("e) 影响等级一致性：判定表高危类与威胁清单等级/测试计划优先级是否对齐？\n")
	}
	// v6.6.0（SP-⑧）：三专项核查节——SP-② 确定性门刻意最小集起步（条目三态只查文件存在），
	// 专项条目内容质量由本节承接（与 s3 五问同款机制）；判据源自
	// docs/深度研究_专项新增条目可执行化_20261121.md 的判定纪律。
	if stageID == "specA" {
		b.WriteString("\n### 专项A 核查（AI/LLM 目标判定纪律）\n")
		b.WriteString("a) 候选验证是否配齐正/负/基线对照（缺正对照不得「确证」——Canary/mock 前置契约兑现）？\n")
		b.WriteString("b) 「注入成功」是否以对后续授权与工具行为的实际影响为准，而非模型复述恶意内容（判据对照 load_skill evidence-standard AI 节与 llm-agent-protocol-boundaries 三联判据）？发现即 BLOCK。\n")
		c := "c) 系统提示/隐藏上下文原文是否落库（违反 A3 泄露要点摘要 ≤200 字口径即 BLOCK——只允许摘要+分级留证）？\n"
		b.WriteString(c)
	}
	if stageID == "specB1" {
		b.WriteString("\n### 专项B1 核查（APP 双链判定纪律）\n")
		b.WriteString("a) 静态发现是否全部标「待动态验证」且假设队列已移交（静态直升确证 = BLOCK——静态不下最终结论）？\n")
		b.WriteString("b) 客户端检测绕过是否被单独确证为服务端授权缺陷（D1/D7 口径：客户端绕过≠服务端缺陷，判定链判据见 load_skill app-integrity-server-verify，缺服务端判定证据即 BLOCK）？\n")
		b.WriteString("c) Hook/抓包/脱壳产物是否仅用于授权测试且未分发（红线口径）？\n")
	}
	if stageID == "specB2" {
		b.WriteString("\n### 专项B2 核查（小程序判定纪律）\n")
		b.WriteString("a) 测试是否越出平台边界（微信/支付宝/抖音平台基础设施与其他租户不因目标授权自动入范围——负对照纪律见 load_skill miniapp-host-isolation，越界即 BLOCK）？\n")
		b.WriteString("b) 支付/真实用户数据操作是否全部经审批（红线口径）？\n")
		c2 := "c) 解包子包覆盖率与解析失败项是否如实记录（W1 口径：不以「成功解包」描述为完整源码恢复）？\n"
		b.WriteString(c2)
	}
	// v6.7.0（S6-⑤）：S6 专项核查——兑现 s6.md S6-4/S6-6 红线「反思门会核查」的承诺：
	// 持久化只登记不处置、存量排查只发现只登记、移交承接留痕、拓扑引用（引擎机械门查不了
	// 行为语义红线，本节补 LLM 层定向抽查——与 s7 清理铁律节同粒度，只拦关键缺口）。
	if stageID == "s6" {
		b.WriteString("\n### S6 专项核查（后渗透红线，对照 s6.md S6-4/S6-6）\n")
		b.WriteString("a) 持久化/驻留工件是否全部四元组登记（位置/指纹/建议清理命令/验证命令）且无任何删除/还原/注销类执行——时间线或交付物中出现 rm/del/atrm/schtasks /delete/net user /delete/reg delete/sc delete/服务删除/应用重启即 BLOCK（v4.8.1 口径：只记录移交，验证一条命令的影响后即停止使用该驻留）？\n")
		b.WriteString("b) S6-6 存量持久化痕迹排查是否只发现、只登记、不处置（逐项 record_finding 置信度=疑似/待查；确证第三方后门是否列入《需人工清理清单》移交——存量数据绝对不动）？\n")
		c := "c) S5 移交项（上下文「S5 移交项」块）是否按价值消费或显式移交留痕——零承接且交付物无留痕即 BLOCK（S7 清点三选一口径）？\n"
		b.WriteString(c)
		d := "d) 《权限矩阵》与《横向路径图》是否引用《拓扑重建》最新版（s6.md v5.4 拓扑引用强制——未覆盖拓扑向量逐项三态处置，禁止横向收口时拓扑向量零消费）？\n"
		b.WriteString(d)
	}
	b.WriteString("输出格式：第一行必须是 PASS 或 BLOCK；随后用不超过 5 条列出意见。宁可放行也不要吹毛求疵，只拦截「关键缺口」。")

	cli, modelName := o.clientFor(p)
	msgs := []llm.Message{
		{Role: "system", Content: "[[EXPERT:reflector]]\n" + expertPersonas["reflector"] + "\n输出格式：第一行 PASS 或 BLOCK。"},
		{Role: "user", Content: b.String()},
	}
	resp, usage, err := cli.Chat(ctx, modelName, msgs, nil, 0.2, 1024)
	if err != nil {
		return "", false, err
	}
	o.accountUsage(p, stageID, usage)
	text := strings.TrimSpace(resp.Content)
	if text == "" {
		return "", false, fmt.Errorf("反思门无回复")
	}
	blocked := strings.HasPrefix(text, "BLOCK")
	return text, blocked, nil
}

// ---------- v6.9.0（S8-②）反思门 S8 审查素材提取（确定性纯函数） ----------

// s8ReportExcerptRe 《发现详情》章节标题（定级表常见写在该章内或紧邻其前）。
var s8ReportExcerptRe = regexp.MustCompile(`(?m)^#{1,3}[^\n]*发现详情[^\n]*$`)

// s8LevelTableRe 定级表/合并映射类独立章节标题（与发现详情并列书写形态）——第七轮核对补
// 「合并映射」：定级表映射常独立成节（## 合并映射 / ## 定级表映射），映射不在素材内时问句
// a/c 的拆条与合并核对缺数据源（与证据编号同类的核查数据源闭合）。
var s8LevelTableRe = regexp.MustCompile(`(?m)^#{1,3}[^\n]*(?:漏洞定级表|定级表|合并映射)[^\n]*$`)

// s8ReportRIDRe 报告定级条目编号（^### R-001 形态，与 v3.7.4 正向门同一锚定口径）。
var s8ReportRIDRe = regexp.MustCompile(`(?m)^#{2,4}\s+(R-\d+)`)

// s8ReportSectionOf 从 loc 开始截取到下一个二级标题（不含）或文末。
func s8ReportSectionOf(raw string, loc []int) string {
	sec := raw[loc[0]:]
	if m := regexp.MustCompile(`(?m)^##\s+`).FindStringIndex(sec[1:]); m != nil {
		sec = sec[1 : 1+m[0]]
	}
	return sec
}

// s8ReportExcerpt 反思门审查素材：《发现详情》与《漏洞定级表》章节并取（重叠按起始位置去重），
// 任一缺失回退另一章，均缺失回退全文头部。rune 上限 6000（约 6k token，仅 s8 收口时一次调用），
// 截断标注「余略」。
func s8ReportExcerpt(raw string) string {
	var secs []string
	seen := map[int]bool{}
	for _, re := range []*regexp.Regexp{s8LevelTableRe, s8ReportExcerptRe} {
		if loc := re.FindStringIndex(raw); loc != nil && !seen[loc[0]] {
			seen[loc[0]] = true
			secs = append(secs, s8ReportSectionOf(raw, loc))
		}
	}
	sec := strings.Join(secs, "\n")
	if strings.TrimSpace(sec) == "" {
		sec = raw
	}
	r := []rune(sec)
	if len(r) > 6000 {
		return string(r[:6000]) + "\n…（余略，共 " + strconv.Itoa(len(r)) + " 字符）"
	}
	return sec
}

// s8ReportRIDs 提取报告 R- 条目编号清单（供审查方核对「P0/P1 全部有证据引用」「计数=根因数」）。
func s8ReportRIDs(raw string) []string {
	var out []string
	for _, m := range s8ReportRIDRe.FindAllStringSubmatch(raw, -1) {
		out = append(out, m[1])
	}
	return out
}

// s8FindingLine v6.9.0（S8-② 第六轮核对）：findings 清单行——编号/等级/置信度/证据
// （EvidenceIDs，引擎自动关联的 EV- 编号；问句 b「引用证据与 findings 库对得上」的核查
// 数据源）/标题；无证据编号时如实缺省（素材缺失即审查意见的输入）。
func s8FindingLine(f *store.Finding) string {
	ev := ""
	if len(f.EvidenceIDs) > 0 {
		ev = " 证据[" + strings.Join(f.EvidenceIDs, ",") + "]"
	}
	return fmt.Sprintf("- %s [%s/%s]%s %s", f.ID, f.Severity, f.Confidence, ev, f.Title)
}

// ---------- v4.8 R7 第二层：对抗假设 pass（引擎钩子，s3 收口时触发） ----------

// adversarialHypRe 对抗假设清单行：markdown 列表项（每行一条假设）。
var adversarialHypRe = regexp.MustCompile(`(?m)^\s*[-*]\s*(.+)$`)

// adversarialAssumptionPass s3 收口时以独立 LLM 会话做红队视角假设复查：
// 「只看攻击面证据，忽略现有清单，你会怎么打」→ 生成对抗假设清单 → 与主清单
// （s3 交付物语料）归一化 diff → 差异项自动 record_vt（status=pending，主头/人工
// 确认后转 ready）。约束（总案 §2.2）：对抗清单同样受证据溯源纪律（每条附证据指针
// 或显式标注「纯推测」）。非阻塞增强项：LLM 失败只留痕不拦收口（§七.2）。
// 返回（收口附注, 新增交付物相对路径）。
// adversarialAssumptionPass 单轮对抗假设（v7.3.0 C1 红蓝对抗环的轮次原语）：
// round=1 首轮独立复查；round≥2 携带 prior（此前轮次假设清单）专攻未覆盖角度。
// 差异 VT 登记规则升级（方案 C1）：证据指针可核存的差异项直接 status=ready
//（红蓝对抗环差异项不再等人工确认——证据在场即就绪），「纯推测」仍 pending。
func (o *Orchestrator) adversarialAssumptionPass(ctx context.Context, p *store.Project, stageID string, round int, prior []string) (string, string, []string) {
	// 主清单语料 = s3 交付物文本（判定表+威胁清单在列）
	mainCorpus := o.deliverablesText(p.ID)
	// v6.3.0（S3-② 配套修复）：diff 语料归一化不再截断——原实现 normForKey(mainCorpus)
	// 把主清单截到 48 字符，containment 只对语料开头 48 字生效（旧测试靠文件字典序碰巧
	// 通过）；改用 normCovText 全语料归一（小写/全角折叠/去空白，不截断），diff 语义回到
	// 「假设是否被主清单任何位置覆盖」的本意。
	normMain := normCovText(mainCorpus)
	corpus := mainCorpus
	if len([]rune(corpus)) > 12000 {
		corpus = string([]rune(corpus)[:12000])
	}
	assetLines, n := "", 0
	if assets, _ := o.store.ListAssets(p.ID); len(assets) > 0 {
		for _, a := range assets {
			assetLines += fmt.Sprintf("- [%s] %s %s\n", a.Type, a.Value, truncateText(a.Detail, 80))
			if n++; n >= 40 {
				break
			}
		}
	}

	prompt := fmt.Sprintf(`你是独立红队视角审查员，与主威胁建模者互不共享推理链。只看下面的攻击面证据，忽略其中已列出的威胁清单与判定表，回答一个问题：**如果是你来打这个目标，你会怎么进？**

要求：
1. 只依据攻击面证据（资产/端点/技术栈/框架特征）产出对抗假设，每行一条，格式：
   - [假设] <一句话假设> | 证据指针: <evidence/ 文件或资产引用> | 类: C-<NN>
2. 每条必须附证据指针；确实无证据但值得试的，显式标注「纯推测」并说明动机。
3. 最多 10 条，按「匿名可达×影响」排序；与既有攻击面明显重复的不要写。
4. 不确定就写「待实测裁决」，不要下确证结论。

## 攻击面证据
### 资产
%s
### 交付物语料（内含主清单，仅作证据源，不要复述其假设）
%s`, assetLines, corpus)

	// v7.3.0 C1：round≥2 注入此前轮次假设——红方第 2 轮专攻蓝方与第 1 轮都未覆盖的角度
	priorLines := ""
	if round >= 2 && len(prior) > 0 {
		priorLines = "\n## 此前轮次已覆盖的假设（禁止重复，专攻不同进入角度）\n"
		for _, h := range prior {
			priorLines += "- " + h + "\n"
		}
	}
	cli, modelName := o.clientFor(p)
	if cli == nil {
		return "", "", nil
	}
	pctx, cancel := context.WithTimeout(ctx, 120*time.Second)
	defer cancel()
	resp, usage, err := cli.Chat(pctx, modelName, []llm.Message{
		{Role: "system", Content: fmt.Sprintf("[[R7-ADVERSARIAL]] 独立红队视角审查员（红蓝对抗环第 %d 轮）：输出对抗假设清单，每条附证据指针或「纯推测」标注。", round)},
		{Role: "user", Content: prompt + priorLines},
	}, nil, 0.4, 1024)
	if err != nil {
		o.log(p, stageID, fmt.Sprintf("⚠ 红蓝对抗环 R%d 调用失败（非阻塞，留痕）: %s", round, err.Error()))
		_, _ = o.store.AddTimeline(&store.TimelineEvent{ProjectID: p.ID, Stage: stageID,
			Event: "红蓝对抗环", Detail: fmt.Sprintf("R%d 独立会话调用失败（非阻塞）: %s", round, truncateText(err.Error(), 120))})
		return "", "", nil
	}
	o.accountUsage(p, stageID, usage)
	hyps := parseAdversarialHypotheses(resp.Content)
	if len(hyps) == 0 {
		o.log(p, stageID, fmt.Sprintf("红蓝对抗环 R%d：独立会话无可解析假设（留痕）", round))
		return "", "", nil
	}

	// diff：归一化后未出现在主清单语料的 → 差异项 → record_vt（pending）
	var newItems, covered []string
	vtCreated := 0
	for _, h := range hyps {
		key := normForKey(h.content)
		if key == "" || strings.Contains(normMain, normCovText(h.content)) {
			covered = append(covered, h.raw)
			continue
		}
		note := ""
		if strings.Contains(h.raw, "纯推测") {
			note = "（对抗 pass 标注：纯推测，防噪声）"
		}
		// v7.3.0 C1 就绪规则：证据指针可核存的差异项直接 ready（不再等确认——证据在场即就绪）
		status := "pending"
		cond := fmt.Sprintf("红蓝对抗环 R%d 差异项：主头确认后转 ready", round)
		if strings.Contains(h.raw, "evidence/") {
			if _, rerr := o.exec.ReadFile(p.ID, evidenceRefIn(h.raw)); rerr == nil {
				status = "ready"
				cond = fmt.Sprintf("红蓝对抗环 R%d 差异项（证据指针已核存，自动就绪）", round)
			}
		}
		vt := &store.VerificationTask{ProjectID: p.ID, Stage: stageID,
			Title:           fmt.Sprintf("[R%d对抗] ", round) + truncateText(h.content, 90),
			StartConditions: cond,
			CostNote:        "红蓝对抗环自动登记", Priority: 3, Status: status,
			Note: note,
		}
		id, verr := o.store.AddVT(vt)
		if verr != nil {
			continue
		}
		vtCreated++
		newItems = append(newItems, h.raw+" → "+id+"（pending）")
		if vtCreated >= 5 { // 防洪水：单次最多登记 5 条差异 VT
			break
		}
	}

	// 交付物留痕：对抗假设审查记录（全量清单+处置）
	var b strings.Builder
	b.WriteString(fmt.Sprintf("# s3 对抗假设审查（v7.3.0 红蓝对抗环 R%d，独立 LLM 会话）\n\n", round))
	b.WriteString("> 红队视角独立复查；差异项已自动入验证队列（status=pending，主头/人工确认后转 ready）。\n\n")
	b.WriteString("## 对抗假设清单（独立会话原始输出）\n\n" + strings.TrimSpace(resp.Content) + "\n\n")
	b.WriteString("## 处置\n\n")
	if len(newItems) > 0 {
		b.WriteString("### 差异项（主清单未覆盖 → 已登记 VT）\n\n")
		for _, it := range newItems {
			b.WriteString("- " + it + "\n")
		}
	} else {
		b.WriteString("### 差异项：无（对抗清单全部被主清单覆盖）\n")
	}
	if len(covered) > 0 {
		b.WriteString("\n### 与主清单重合（无需重复登记）\n\n")
		for _, c := range covered {
			b.WriteString("- " + c + "\n")
		}
	}
	raw := b.String()
	delivPath := "deliverables/s3-对抗假设审查.md"
	if round >= 2 {
		delivPath = fmt.Sprintf("deliverables/s3-对抗假设审查-R%d.md", round)
	}
	if _, werr := o.exec.WriteFile(p.ID, delivPath, raw); werr != nil {
		o.log(p, stageID, "⚠ R7 对抗假设审查交付物写入失败（非阻塞）: "+werr.Error())
		delivPath = ""
	}
	o.log(p, stageID, fmt.Sprintf("🥷 红蓝对抗环 R%d：独立会话 %d 条假设，差异 %d 条入 VT（证据核存即 ready）", round, len(hyps), vtCreated))
	_, _ = o.store.AddTimeline(&store.TimelineEvent{ProjectID: p.ID, Stage: stageID,
		Event: "红蓝对抗环", Detail: fmt.Sprintf("R%d 独立会话假设 %d 条，差异项登记 VT %d 条（证据核存即 ready，纯推测 pending）", round, len(hyps), vtCreated)})
	note := fmt.Sprintf("🥷 红蓝对抗环 R%d 已执行（独立 LLM 会话）：解析假设 %d 条，diff 后差异 %d 条已自动 record_vt（证据核存即 ready，纯推测 pending）；全量记录见 %s。", round, len(hyps), vtCreated, delivPath)
	out := make([]string, 0, len(hyps))
	for _, h := range hyps {
		out = append(out, h.content)
	}
	return note, delivPath, out
}

// evidenceRefIn 从假设行提取首个 evidence/ 引用路径（就绪规则核存用）。
func evidenceRefIn(raw string) string {
	i := strings.Index(raw, "evidence/")
	if i < 0 {
		return ""
	}
	rest := raw[i:]
	end := len(rest)
	for j, c := range rest {
		if c == ' ' || c == '|' || c == '\n' || c == '\t' || c == ')' || c == ',' || c == ';' ||
			c == '，' || c == '）' || c == '。' || c == '；' {
			end = j
			break
		}
	}
	return strings.TrimRight(strings.TrimLeft(rest[:end], "（("), "。，,；)")
}

// redBlueAssumptionLoop v7.3.0 C1 红蓝对抗环：R1 独立复查 → R2 携带 R1 假设专攻剩余角度
//（2 轮迭代，替代旧一次性 R7；每轮独立留痕与 VT 登记，fail-open）。
func (o *Orchestrator) redBlueAssumptionLoop(ctx context.Context, p *store.Project, stageID string) (string, string) {
	note1, file1, hyps1 := o.adversarialAssumptionPass(ctx, p, stageID, 1, nil)
	if len(hyps1) == 0 {
		return note1, file1
	}
	note2, file2, _ := o.adversarialAssumptionPass(ctx, p, stageID, 2, hyps1)
	// v7.3.0 核对修复（审计 M）：R2 失败（note2 空）时不再拼接孤儿分号
	file := file2
	if file == "" {
		file = file1
	}
	if strings.TrimSpace(note2) == "" {
		return strings.TrimSpace(note1), file
	}
	merged := strings.TrimSpace(strings.TrimSuffix(note1, "。") + "；" + strings.TrimPrefix(note2, "🥷 "))
	return merged, file
}

// adversarialHyp 单条对抗假设：content=剥离标签/证据尾巴后的正文（diff 键与 VT 标题），
// raw=原始行（交付物留痕与「纯推测」标注检查）。
type adversarialHyp struct {
	content string
	raw     string
}

// parseAdversarialHypotheses 解析对抗假设清单行：剥离「[假设]」标签与「| 证据指针…」
// 尾巴，只留假设正文（原始全文另行留痕于交付物）。
func parseAdversarialHypotheses(text string) []adversarialHyp {
	var out []adversarialHyp
	for _, m := range adversarialHypRe.FindAllStringSubmatch(text, -1) {
		line := strings.TrimSpace(m[1])
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "|") || strings.HasPrefix(line, ">") {
			continue
		}
		raw := line
		if i := strings.Index(line, "[假设]"); i >= 0 {
			line = line[i+len("[假设]"):]
		}
		if i := strings.Index(line, "|"); i > 0 {
			line = line[:i]
		}
		line = strings.TrimSpace(strings.Trim(line, "[]（）()：: "))
		if line == "" {
			continue
		}
		out = append(out, adversarialHyp{content: line, raw: raw})
		if len(out) >= 10 {
			break
		}
	}
	return out
}

// normForKey 归一化键（R7 diff 用）：去空白/标点/全半角差异，小写，截前 48 字符——
// 与 B1「同组件×同威胁类×同机制」判重精神一致：语义等价表述命中同一键。
func normForKey(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		if r >= 0xFF00 && r <= 0xFF5E {
			r -= 0xFEE0
		}
		if isNormKeep(r) {
			b.WriteRune(r)
		}
	}
	r := []rune(b.String())
	if len(r) > 48 {
		r = r[:48]
	}
	return string(r)
}

// isNormKeep 保留字母/数字/中日韩文字，丢弃空白与标点（全半角统一后）。
func isNormKeep(r rune) bool {
	switch {
	case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
		return true
	case r >= 0x4E00 && r <= 0x9FFF: // CJK
		return true
	case r >= 'A' && r <= 'Z':
		return true
	}
	return false
}
