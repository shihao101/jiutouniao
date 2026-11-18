// v3.6.0 阶段内并行扇出（受控子代理）：
// 主头把相互独立的测试单元（多 endpoint×漏洞类、多目录枚举、多指纹验证）派发给
// 最多 N 个子代理并行推进——每个子代理独立消息链，共享同一黑板/覆盖矩阵/审批矩阵；
// 主头用 poll_subagents 收结果并整合收口。对标 strix agents_graph / CAI 并行 worker，
// 直击「严格串行 + 60 轮预算结构性不足」的吞吐瓶颈。
//
// 安全边界：
//   - 子代理工具面是主头的**子集**（无 complete_stage/loopback/plan_subtasks/ask/
//     request_approval——改变流程状态与人工屏障类动作只属于主头）；
//   - 命令仍走同一审批矩阵（项目策略），L2 高危照样拦截/留痕；
//   - 熔断级联：项目 Kill → 取消全部子代理 ctx → 在途 LLM 调用中断；
//   - 上限：每项目并发子代理 ≤ engine.max_subagents（默认 3），单轮次 ≤ engine.max_subagent_rounds（默认 12）。
package engine

import (
	"context"
	crand "crypto/rand"
	"fmt"
	"strings"
	"time"

	"jiutouniao/internal/llm"
	"jiutouniao/internal/store"
)

// SubAgentRun 一次子代理运行的档案。
type SubAgentRun struct {
	ID        string
	ProjectID string
	Stage     string
	Objective string
	Status    string // running/finished/killed/failed
	Rounds    int
	Summary   string
	StartedAt time.Time
	EndedAt   time.Time
	Attempts  int // v5.5.0（修复方案 F）：LLM 调用累计尝试次数（含重试），poll 可观测

	reported bool // poll_subagents 已向主头汇报过最终结果
	cancel   context.CancelFunc
}

// subAgentLLMRetries v5.5.0（修复方案 F）：瞬时 LLM 错误的有界重试（线性退避 2s/5s/10s）。
// 原实现单次失败即整跑 failed、产出静默蒸发（无重试+结果只在内存摘要）。
// 重试安全性：Chat 调用失败意味着本轮没有产出任何 tool_calls，不存在已执行的副作用可重放；
// 上一轮工具结果已在 msgs 中，恢复续发不会重复执行任何工具。Kill（ctx 取消）不重试。
const subAgentLLMRetries = 3

var subAgentTools = map[string]bool{
	"run_command": true, "run_async": true, "poll_async": true,
	"write_file": true, "read_file": true, "list_files": true,
	"record_finding": true, "record_asset": true, "record_timeline": true,
	"upsert_fact": true, "record_loot": true, "update_coverage": true,
	"load_skill": true, "search_memory": true, "install_tool": true, "hexstrike_command": true,
	// v5.5.0（修复方案 A/F）：带态测试进子代理工具面（角色矩阵扇出复放依赖 http_request/cred_command）；
	// 凭据管理类动作（store/revoke）仍只属于主头。
	"http_request": true, "cred_command": true, "list_credentials": true,
}

// subAgentToolDefs 主头工具面的受控子集（按白名单过滤）。
func (o *Orchestrator) subAgentToolDefs() []llm.ToolDef {
	var out []llm.ToolDef
	for _, t := range o.toolDefs() {
		if subAgentTools[t.Name] {
			out = append(out, t)
		}
	}
	return out
}

const subAgentCharter = `你是九头鸟的「子代理」：由主头派生，专责完成一个明确定义的测试目标。

## 子代理守则
1. 只做派发目标相关的工作，不要扩大攻击面；范围外资产只记录不访问。
2. 你拥有独立的轮次预算（%d 轮），到轮次将自动结束——优先完成目标内最有价值的验证。
3. 你的发现必须实时 record_finding / update_coverage / upsert_fact 入库（与主头共享黑板），不要攒到最后。
4. 全部红线与深度测试纪律见执行循环宪法（同主头）：禁破坏性、生产数据只做存在性证明、命令留证。
5. 完成或确认无法推进时，输出一段「结果简报」纯文本（做了什么/确证了什么/未完成什么），不要调用主头专属工具（如 complete_stage——不在你的工具面里，调用会报错）。`

// subagentRoundsCap v4.4：单子代理轮次硬上限从 20 提至 30（方向二D 扇出扩容：
// 多目标项目的子代理要跑完整五轨最小层，12-20 轮不够；并发上限仍由 engine.max_subagents 控制）。
const subagentRoundsCap = 30

// clampSubagentRounds v4.4：子代理轮次钳制（<=0 取默认；上限 subagentRoundsCap）——纯函数便于单测。
func clampSubagentRounds(rounds, def int) int {
	if rounds <= 0 {
		rounds = def
	}
	if rounds > subagentRoundsCap {
		rounds = subagentRoundsCap
	}
	return rounds
}

// spawnSubAgent 派发一个子代理（异步启动，立即返回 job id）。
func (o *Orchestrator) spawnSubAgent(ctx context.Context, p *store.Project, stageID, objective string, rounds int) (string, error) {
	if o.cfg.Engine.MaxSubagents <= 0 {
		return "", fmt.Errorf("并行扇出未启用（engine.max_subagents=0）")
	}
	if strings.TrimSpace(objective) == "" {
		return "", fmt.Errorf("objective 为空")
	}
	rounds = clampSubagentRounds(rounds, o.cfg.Engine.MaxSubagentRounds)
	o.subMu.Lock()
	if o.subRuns == nil {
		o.subRuns = map[string]map[string]*SubAgentRun{}
	}
	running := 0
	for _, r := range o.subRuns[p.ID] {
		if r.Status == "running" {
			running++
		}
	}
	if running >= o.cfg.Engine.MaxSubagents {
		o.subMu.Unlock()
		return "", fmt.Errorf("子代理并发已达上限（%d），请先 poll_subagents 收结果", o.cfg.Engine.MaxSubagents)
	}
	id := fmt.Sprintf("sub-%s-%d", stageID, time.Now().UnixNano()%100000)
	// v5.1.2 P1 修复：并行 spawn 同纳秒窗口取模高概率碰撞 → 注册表后写覆盖先写、
	// 旧子代理失联（不可 poll/kill/取消）；追加 2 字节随机后缀消除碰撞。
	var rb [2]byte
	if _, rerr := crand.Read(rb[:]); rerr == nil {
		id = fmt.Sprintf("%s-%x", id, rb)
	}
	run := &SubAgentRun{ID: id, ProjectID: p.ID, Stage: stageID,
		Objective: truncateText(objective, 300), Rounds: rounds,
		Status: "running", StartedAt: time.Now()}
	runCtx, cancel := context.WithCancel(ctx)
	run.cancel = cancel
	if o.subRuns[p.ID] == nil {
		o.subRuns[p.ID] = map[string]*SubAgentRun{}
	}
	o.subRuns[p.ID][id] = run
	o.subMu.Unlock()

	go o.runSubAgent(runCtx, p, run)
	o.log(p, stageID, fmt.Sprintf("🧩 子代理 %s 已派发（预算 %d 轮）：%s", id, rounds, truncateText(objective, 120)))
	return fmt.Sprintf("子代理已启动 id=%s（并发预算 %d 轮）。继续派发其他独立单元或做主头工作，稍后用 poll_subagents 收结果；收口前必须确认全部子代理已结束。", id, rounds), nil
}

// runSubAgent 子代理执行循环（独立消息链，复用主头 dispatch——审批/留证/限流全部同权）。
func (o *Orchestrator) runSubAgent(ctx context.Context, p *store.Project, run *SubAgentRun) {
	defer func() {
		run.EndedAt = time.Now()
		if run.Status == "running" {
			run.Status = "finished"
		}
		o.subMu.Lock()
		o.subMu.Unlock()
	}()
	head, ok := o.heads[run.Stage]
	headName := ""
	if ok && head != nil {
		headName = head.Name
	}
	sys := strings.Join([]string{
		"[[SUBAGENT:" + run.ID + "]]",
		o.coreLoop,
		fmt.Sprintf(subAgentCharter, run.Rounds),
		"派发你的主头阶段：" + headName,
	}, "\n\n")
	msgs := []llm.Message{
		{Role: "system", Content: sys},
		{Role: "user", Content: fmt.Sprintf("## 派发目标\n%s\n\n## 项目\n- 目标: %s\n- 授权范围与红线见下\n\n%s",
			run.Objective, firstLine(p.Target), o.buildContextPack(p, run.Stage))},
	}
	tools := o.subAgentToolDefs()
	cli, model := o.clientFor(p)
	for i := 0; i < run.Rounds; i++ {
		if ctx.Err() != nil {
			run.Status = "killed"
			return
		}
		// v5.5.0（修复方案 F）：LLM 瞬时错误有界重试（2s/5s/10s 退避）——
		// Chat 失败时本轮无 tool_calls 产出，重试不重放任何工具副作用；Kill 不重试。
		var resp llm.Message
		var usage llm.Usage
		var err error
		for attempt := 1; attempt <= subAgentLLMRetries; attempt++ {
			run.Attempts++ // 累计尝试次数（跨轮累计，poll 可观测）
			resp, usage, err = cli.Chat(ctx, model, msgs, tools, o.cfg.LLM.Temperature, o.cfg.LLM.MaxTokens)
			if err == nil {
				break
			}
			if ctx.Err() != nil {
				break
			}
			if attempt < subAgentLLMRetries {
				backoff := time.Duration(2*attempt+1) * time.Second // 2s/5s/10s 线性退避
				select {
				case <-ctx.Done():
				case <-time.After(backoff):
				}
			}
		}
		if err != nil {
			if ctx.Err() != nil {
				run.Status = "killed"
			} else {
				run.Status = "failed"
				run.Summary = fmt.Sprintf("LLM 调用失败（重试 %d 次后放弃）: %s", subAgentLLMRetries, truncateText(err.Error(), 200))
			}
			return
		}
		o.accountUsage(p, run.Stage, usage)
		if len(resp.ToolCalls) == 0 {
			// 纯文本 = 结果简报，子代理收工
			run.Summary = truncateText(strings.TrimSpace(resp.Content), 2000)
			if run.Summary == "" {
				run.Summary = "（子代理未产出简报）"
			}
			return
		}
		msgs = append(msgs, resp)
		for _, tc := range resp.ToolCalls {
			result := o.dispatch(ctx, p, run.Stage, tc)
			msgs = append(msgs, llm.Message{Role: "tool", ToolCallID: tc.ID, Content: result})
		}
	}
	run.Summary = fmt.Sprintf("（达到子代理轮次上限 %d 轮，按已入库发现/覆盖度为准；未完成部分由主头决定是否续派）", run.Rounds)
}

// pollSubAgents 收子代理结果：运行中的报进度，已结束且未汇报过的报简报并标记已消费。
func (o *Orchestrator) pollSubAgents(p *store.Project) string {
	o.subMu.Lock()
	defer o.subMu.Unlock()
	runs := o.subRuns[p.ID]
	if len(runs) == 0 {
		return "当前项目没有子代理记录。"
	}
	var b strings.Builder
	runningAll, finished := 0, 0
	for id, r := range runs {
		if r.Status == "running" {
			runningAll++
			fmt.Fprintf(&b, "🧩 [%s] running（第 %d 轮内）目标: %s\n", id, r.Rounds, truncateText(r.Objective, 100))
			continue
		}
		if r.reported {
			continue
		}
		r.reported = true
		finished++
		fmt.Fprintf(&b, "🧩 [%s] %s — %s\n", id, r.Status, truncateText(r.Summary, 800))
	}
	if b.Len() == 0 {
		return fmt.Sprintf("子代理均已收结果并整合（历史 %d 条）。", len(runs))
	}
	_ = runningAll
	_ = finished
	return strings.TrimRight(b.String(), "\n")
}

// killSubAgents 熔断/收口前终止项目全部在途子代理。
func (o *Orchestrator) killSubAgents(projectID string) int {
	o.subMu.Lock()
	defer o.subMu.Unlock()
	n := 0
	for _, r := range o.subRuns[projectID] {
		if r.Status == "running" {
			r.Status = "killed"
			if r.cancel != nil {
				r.cancel()
			}
			n++
		}
	}
	return n
}

// runningSubAgents 是否还有在途子代理（主头收口前检查）。
func (o *Orchestrator) runningSubAgents(projectID string) int {
	o.subMu.Lock()
	defer o.subMu.Unlock()
	n := 0
	for _, r := range o.subRuns[projectID] {
		if r.Status == "running" {
			n++
		}
	}
	return n
}

// SubAgentSnapshots 供 Web 只读展示：项目全部子代理档案（不标记消费）。
func (o *Orchestrator) SubAgentSnapshots(projectID string) []map[string]any {
	o.subMu.Lock()
	defer o.subMu.Unlock()
	out := []map[string]any{}
	for id, r := range o.subRuns[projectID] {
		out = append(out, map[string]any{
			"id": id, "stage": r.Stage, "objective": r.Objective,
			"status": r.Status, "rounds": r.Rounds, "summary": r.Summary,
			"started_at": r.StartedAt.Format(time.RFC3339),
		})
	}
	// 最近派发的在前
	for i := 0; i < len(out); i++ {
		for j := i + 1; j < len(out); j++ {
			if out[j]["started_at"].(string) > out[i]["started_at"].(string) {
				out[i], out[j] = out[j], out[i]
			}
		}
	}
	return out
}
