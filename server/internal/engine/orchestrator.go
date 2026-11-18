package engine

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"jiutouniao/internal/config"
	"jiutouniao/internal/credentials"
	"jiutouniao/internal/events"
	"jiutouniao/internal/llm"
	"jiutouniao/internal/store"
	"jiutouniao/internal/tools"
)

// Orchestrator 主控（真头）：驱动阶段流水线，每个阶段由对应专家头以
// 「决策→分级→审批→执行→观察→反思→记忆→停止」的执行循环推进（流程图第15页引擎 E）。
type Orchestrator struct {
	cfg      *config.Config
	store    *store.Store
	llm      llm.Client
	clientMu sync.RWMutex          // LLM 客户端热切换（Web 设置保存后即时生效）
	clients  map[string]llm.Client // 多模型注册表（id -> client）
	models   map[string]string     // id -> 模型名（Chat 的 model 参数）
	defModel string                // 默认模型 id
	exec     *tools.Executor
	approver *Approver
	bus      *events.Bus
	heads    map[string]*Head
	coreLoop string               // 执行循环宪法（prompts/loop-core.md）
	skills   *SkillRegistry       // 技能库（strix/PentesterFlow 移植）
	hex      *HexStrikeBridge     // hexstrike-ai 工具网关桥（可空）
	roe      *ROEProfile          // v4.6 T3/H：ROE Profile（nil=未启用）
	profiles *ExecutionProfiles   // v5.3.1：Execution Profile 声明（双运行模式单一事实源，逐动作强制）
	creds    *credentials.Service // v5.5.0：结构化凭据仓库（方案 A；未配置主密钥时 Enabled()=false，工具 fail closed）

	mu      sync.Mutex
	running map[string]context.CancelFunc // projectID -> 取消函数
	tokens  map[string]int64              // projectID -> 累计 token（预算熔断）

	askMu sync.Mutex
	asks  map[string]chan string // askID -> 回答通道（向人提问屏障）

	inputMu sync.Mutex
	inputs  map[string][]string // projectID -> 指挥室指令队列（运行中项目注入执行流）

	loopMu sync.Mutex
	loops  map[string][]string // projectID -> loopback 请求的回环补跑阶段（F-03 修复：原先仅改状态不重跑）

	liveMu sync.RWMutex
	liveP  map[string]*store.Project // 运行中项目的活指针（修复：运行中改策略被流水线旧快照回写覆盖）

	projMu    sync.Mutex        // v2.7 A8：项目级模型故障切换覆盖表
	projModel map[string]string // v2.7 A8：projectID -> 故障切换后接管的项目模型 id
	modelWarn map[string]bool   // v5.4.0：projectID -> 回退默认模型告警已记（去重防刷日志）

	chatMu      sync.Mutex                    // v3.4.0：对话轮取消注册表
	chatCancels map[string]context.CancelFunc // v3.4.0：projectID -> 在途对话轮 cancel

	subMu   sync.Mutex                         // v3.6.0：子代理注册表锁
	subRuns map[string]map[string]*SubAgentRun // v3.6.0：projectID -> runID -> 子代理

	// v4.8 W5 行为预算器：批量动作配额/空壳即停/冷却协议（引擎级，进程内状态）
	batchMu    sync.Mutex
	batchStats map[string]*batchBudgetState
}

// batchBudgetState 单项目批量动作预算状态（窗口时间戳 + 冷却 + 空壳连击）。
type batchBudgetState struct {
	stamps        []time.Time // 窗口内批量动作时间戳（10 分钟滑窗）
	cooldownUntil time.Time   // 冷却截止（超限触发）
	emptyStreak   int         // 连续空壳批量结果计数
}

// IsRunning 项目流水线是否在运行（决定对话消息走指令通道还是独立对话）。
func (o *Orchestrator) IsRunning(projectID string) bool {
	o.mu.Lock()
	defer o.mu.Unlock()
	_, ok := o.running[projectID]
	return ok
}

// SendInput 把指挥室指令注入运行中的执行流（PentAGI putUserInput 移植）。
func (o *Orchestrator) SendInput(projectID, msg string) {
	o.inputMu.Lock()
	o.inputs[projectID] = append(o.inputs[projectID], msg)
	o.inputMu.Unlock()
	p := o.mustProject(projectID)
	stage := ""
	for sid, st := range p.StageStates {
		if st.Status == "running" {
			stage = sid
			break
		}
	}
	_, _ = o.store.AddStream(projectID, &store.StreamRecord{Kind: "msg", Role: "user", Stage: stage, Text: "【指挥室指令】" + truncateText(msg, 2000)})
	o.bus.Publish(projectID, "stage_msg", map[string]any{"stage": stage, "role": "user", "text": msg})
	// 审批阻塞提示：循环停在待审批工单上时，「下一轮生效」永远不会到来，必须讲清楚
	if pend, _ := o.store.ListApprovals(projectID); len(pend) > 0 {
		n := 0
		for _, a := range pend {
			if a.Status == "pending" {
				n++
			}
		}
		if n > 0 {
			o.log(p, stage, fmt.Sprintf("🧑‍✈️ 指挥室指令已注入；⚠ 当前有 %d 个待审批工单阻塞执行循环，指令将在审批处理后的下一轮生效", n))
			return
		}
	}
	o.log(p, stage, "🧑‍✈️ 指挥室指令已注入（下一轮执行循环生效）")
}

// drainInputs 取走全部待注入指令（阶段循环每轮 LLM 调用前调用）。
func (o *Orchestrator) drainInputs(projectID string) []llm.Message {
	o.inputMu.Lock()
	q := o.inputs[projectID]
	o.inputs[projectID] = nil
	o.inputMu.Unlock()
	if len(q) == 0 {
		return nil
	}
	out := make([]llm.Message, 0, len(q))
	for _, m := range q {
		out = append(out, llm.Message{Role: "user", Content: "【指挥室指令（最高优先级，立即调整行动）】" + m})
	}
	return out
}

// startableStatus 可启动/续跑的项目状态（v2.7.5：补 failed——LLM 500/预算耗尽等异常中断后，
// 对话「继续」同样触发全量断点续跑，与「启动」按钮语义对齐；此前仅 created/paused/killed 可识别）。
func startableStatus(s string) bool {
	return s == "created" || s == "paused" || s == "killed" || s == "failed"
}

// startIntentRe chat 空闲期启动类指令识别（PentAGI 单一入口；锚定句首，避免误伤提问）。
var startIntentRe = regexp.MustCompile(`(?i)^\s*(帮)?(我)?(们)?(请)?(启动|开始|继续|恢复|跑起来|重新开始|start\b|resume\b|continue\b)`)

// TryStartFromChat 空闲期（未运行）项目收到启动类指令时触发断点续跑；返回（是否已处理, 回复文本）。
// created/paused/killed/failed 项目在对话工作台说「继续/启动」即全量续跑（跳过 done 阶段直至收口）。
func (o *Orchestrator) TryStartFromChat(projectID, msg string) (bool, string) {
	if o.IsRunning(projectID) || !startIntentRe.MatchString(msg) {
		return false, ""
	}
	p, err := o.store.GetProject(projectID)
	if err != nil {
		return false, ""
	}
	if !startableStatus(p.Status) {
		return false, ""
	}
	stage := p.CurrentStage
	if stage == "" {
		for _, sid := range Pipeline(o.heads, p.Specializations) {
			if st := p.StageStates[sid]; st == nil || st.Status == "pending" {
				stage = sid
				break
			}
		}
	}
	if err := o.StartProject(projectID); err != nil {
		return true, "⚠ 启动失败：" + err.Error()
	}
	o.log(p, "", "🧑‍✈️ 指挥室指令触发断点续跑（对话工作台单一入口）")
	if stage == "" {
		return true, "🚀 已触发启动，流水线开始执行。"
	}
	return true, fmt.Sprintf("🚀 已触发断点续跑（从阶段 %s 继续）。进度见执行流与仪表盘运行时长。", stage)
}

// parallelizableTool 同一轮可并发执行的工具集合（无顺序依赖、不改执行流状态）。
// complete_stage/loopback/plan_subtasks/request_* 等改变流程状态的工具不在其中——
// 混入时该轮自动退化为串行（可预期、可审计）。
var parallelizableTool = map[string]bool{
	"run_command": true, "hexstrike_command": true, "write_file": true, "read_file": true,
	"list_files": true, "load_skill": true, "search_memory": true,
	"run_async": true, "poll_async": true, "install_tool": true,
	"record_asset": true, "record_finding": true, "record_timeline": true, "update_finding": true,
	"record_vt": true, "update_vt": true,
	"update_coverage": true, "update_subtask": true,
	"upsert_fact": true, "record_loot": true, "shell_open": true, // v3.3.0 黑板/战利品/会话（bbolt 事务串行化，天然并发安全）
	"spawn_subagent": true, "poll_subagents": true, // v3.6.0 并行扇出
}

func NewOrchestrator(cfg *config.Config, st *store.Store, client llm.Client, exec *tools.Executor, ap *Approver, bus *events.Bus, headsDir, promptsDir, skillsDir string) (*Orchestrator, error) {
	heads, err := LoadHeads(headsDir)
	if err != nil {
		return nil, err
	}
	core, err := os.ReadFile(filepath.Join(promptsDir, "loop-core.md"))
	if err != nil {
		return nil, fmt.Errorf("读取执行循环宪法失败: %w", err)
	}
	skills, err := LoadSkills(skillsDir)
	if err != nil {
		return nil, fmt.Errorf("加载技能库失败: %w", err)
	}
	var roeProfile *ROEProfile
	if strings.TrimSpace(cfg.Engine.ROEProfilePath) != "" {
		rp, rerr := LoadROEProfile(cfg.Engine.ROEProfilePath)
		if rerr != nil {
			return nil, fmt.Errorf("ROE Profile 加载失败（roe_profile_path=%s）: %w", cfg.Engine.ROEProfilePath, rerr)
		}
		roeProfile = rp
		log.Printf("ROE Profile 已加载: %s（write_policy=%s）", rp.Path, rp.WritePolicy())
	}
	var hex *HexStrikeBridge
	if strings.TrimSpace(cfg.HexStrikeURL) != "" {
		hex = NewHexStrikeBridge(cfg.HexStrikeURL)
		if hh, err := hex.Health(context.Background()); err == nil {
			log.Printf("hexstrike 桥已连接: %s v%s（工具 %d 个）", hh.Status, hh.Version, hh.TotalToolsCount)
		} else {
			log.Printf("hexstrike 桥不可达（将继续运行，调用时降级报错）: %v", err)
		}
	}
	// v5.3.1 P0-1：Execution Profile 声明加载（fail-fast）——双运行模式不再只是提示词层口径
	profilesPath := strings.TrimSpace(cfg.Engine.ExecutionProfilesPath)
	if profilesPath == "" {
		profilesPath = "policies/execution-profiles.yaml"
	}
	profiles, perr := LoadExecutionProfiles(profilesPath)
	if perr != nil {
		return nil, fmt.Errorf("Execution Profile 声明加载失败（execution_profiles_path=%s）: %w", profilesPath, perr)
	}
	log.Printf("Execution Profile 声明已加载: %s（production_safe/isolated_lab 逐动作强制生效）", profiles.Path)
	// v5.5.0（修复方案 A）：结构化凭据仓库——未配置主密钥时 fail closed（不报错，工具不可用）。
	creds, cerr := credentials.New(st)
	if cerr != nil {
		return nil, fmt.Errorf("凭据仓库初始化失败: %w", cerr)
	}
	if creds.Enabled() {
		log.Printf("凭据仓库已启用（CREDENTIALS_MASTER_KEY 已配置：静态 AES-256-GCM 加密，日志/证据全程掩码）")
	} else {
		log.Printf("凭据仓库未启用（未配置 CREDENTIALS_MASTER_KEY）：store_credential/http_request 带态注入不可用，有凭证深度测试请先配置主密钥")
	}
	o := &Orchestrator{
		cfg: cfg, store: st, llm: client, exec: exec, approver: ap, bus: bus,
		heads: heads, coreLoop: string(core), skills: skills, hex: hex, roe: roeProfile, profiles: profiles, creds: creds,
		running:    map[string]context.CancelFunc{},
		tokens:     map[string]int64{},
		inputs:     map[string][]string{},
		loops:      map[string][]string{},
		liveP:      map[string]*store.Project{},
		projModel:  map[string]string{},
		batchStats: map[string]*batchBudgetState{},
	}
	chatSessions = newChatSessions(o)
	return o, nil
}
func (o *Orchestrator) Heads() map[string]*Head { return o.heads }

// SetLLMClient 设置默认客户端（单模型模式）。
func (o *Orchestrator) SetLLMClient(c llm.Client) {
	o.SetModels(map[string]llm.Client{"default": c}, map[string]string{"default": o.cfg.LLM.Model}, "default")
}

// SetModels 设置多模型注册表（Web 设置页保存后调用）。
func (o *Orchestrator) SetModels(clients map[string]llm.Client, modelNames map[string]string, def string) {
	o.clientMu.Lock()
	o.clients = clients
	o.models = modelNames
	o.defModel = def
	if c, ok := clients[def]; ok {
		o.llm = c
	} else if len(clients) > 0 {
		for _, c := range clients {
			o.llm = c
			break
		}
	}
	o.clientMu.Unlock()
}

// lastStageEnd v4.6 K5-lite：全部阶段中最晚的收口时间（无收口记录返回 nil）。
func (o *Orchestrator) lastStageEnd(p *store.Project) *time.Time {
	var max *time.Time
	for _, st := range p.StageStates {
		if st.EndedAt == "" {
			continue
		}
		if t, err := time.Parse(time.RFC3339, st.EndedAt); err == nil {
			if max == nil || t.After(*max) {
				tt := t
				max = &tt
			}
		}
	}
	return max
}

// clientFor 按项目选择模型：项目指定 > 默认 > 兜底。
func (o *Orchestrator) clientFor(p *store.Project) (llm.Client, string) {
	// v2.7 A8：项目级故障切换覆盖优先（风控/拒绝后由接管模型继续，直至项目结束）
	o.projMu.Lock()
	ov, hasOv := o.projModel[p.ID]
	o.projMu.Unlock()
	if hasOv {
		o.clientMu.RLock()
		c, ok := o.clients[ov]
		mname := o.models[ov]
		o.clientMu.RUnlock()
		if ok {
			return c, mname
		}
	}
	o.clientMu.RLock()
	defer o.clientMu.RUnlock()
	if p != nil && p.ModelID != "" {
		if c, ok := o.clients[p.ModelID]; ok {
			return c, o.models[p.ModelID]
		}
		// v5.4.0：项目指定了模型但注册表中不存在（配置已删除/旧数据）——回退默认并留痕。
		// 每项目只记一次，避免每轮 LLM 调用刷日志。
		o.projMu.Lock()
		if o.modelWarn == nil {
			o.modelWarn = map[string]bool{}
		}
		first := !o.modelWarn[p.ID]
		o.modelWarn[p.ID] = true
		o.projMu.Unlock()
		if first {
			log.Printf("[engine] 项目 %s 指定模型 %s 不在注册表，回退默认模型（model_id=%q）", p.ID, o.models[o.defModel], p.ModelID)
		}
	}
	if c, ok := o.clients[o.defModel]; ok {
		return c, o.models[o.defModel]
	}
	return o.llm, o.cfg.LLM.Model
}

// SetProjectModel v5.4.x：更新项目级模型（校验在 web 层注册表完成）；清内存故障切换覆盖避免遮蔽新值。
func (o *Orchestrator) SetProjectModel(projectID, modelID string) error {
	p, err := o.store.GetProject(projectID)
	if err != nil {
		return err
	}
	old := p.ModelID
	p.ModelID = modelID
	if err := o.store.SaveProject(p); err != nil {
		return err
	}
	o.liveMu.Lock()
	if lp, ok := o.liveP[projectID]; ok {
		lp.ModelID = modelID
	}
	o.liveMu.Unlock()
	o.projMu.Lock()
	delete(o.projModel, projectID)
	o.projMu.Unlock()
	o.log(p, "", fmt.Sprintf("🔀 项目模型已切换: %s → %s（下一轮 LLM 调用生效）", old, modelID))
	return nil
}

// setModelOverride v2.7 A8：故障切换后锁定本项目后续轮次使用接管模型（项目结束即清除）。
func (o *Orchestrator) setModelOverride(projectID, modelID string) {
	o.projMu.Lock()
	o.projModel[projectID] = modelID
	o.projMu.Unlock()
}

// chatFailover v2.7 A8：LLM 供应商内容风控/拒绝（4xx）时自动切换注册表内其他模型重试。
// 实测：DeepSeek 对"真实机构名+渗透语义"返回 400 Content Exists Risk 且重试无效——
// 切换供应商即恢复。接管模型经 setModelOverride 锁定到项目结束，全量留痕。
func (o *Orchestrator) chatFailover(ctx context.Context, p *store.Project, stageID string, msgs []llm.Message, tools []llm.ToolDef) (llm.Message, llm.Usage, error) {
	cli, model := o.clientFor(p)
	resp, usage, err := cli.Chat(ctx, model, msgs, tools, o.cfg.LLM.Temperature, o.cfg.LLM.MaxTokens)
	if err == nil || ctx.Err() != nil {
		return resp, usage, err
	}
	es := err.Error()
	if !strings.Contains(es, "LLM 返回 4") && !strings.Contains(es, "Content Exists Risk") && !strings.Contains(es, "ContentExistsRisk") {
		return resp, usage, err // 网络/超时类错误走原有重试逻辑，不做模型切换
	}
	o.log(p, stageID, "⚠ LLM 供应商拒绝（"+truncateText(es, 140)+"）→ 按注册表自动切换备用模型")
	o.clientMu.RLock()
	altIDs := make([]string, 0, len(o.clients))
	for id := range o.clients {
		if c := o.clients[id]; c != cli {
			altIDs = append(altIDs, id)
		}
	}
	sort.Strings(altIDs)
	o.clientMu.RUnlock()
	for _, id := range altIDs {
		o.clientMu.RLock()
		c, mname := o.clients[id], o.models[id]
		o.clientMu.RUnlock()
		if mname == "" {
			continue
		}
		o.log(p, stageID, fmt.Sprintf("↻ 尝试备用模型 [%s]（%s）", id, mname))
		r2, u2, e2 := c.Chat(ctx, mname, msgs, tools, o.cfg.LLM.Temperature, o.cfg.LLM.MaxTokens)
		if e2 == nil {
			o.setModelOverride(p.ID, id)
			o.accountUsage(p, stageID, u2)
			o.log(p, stageID, fmt.Sprintf("✔ 模型 [%s] 接管本阶段，后续轮次继续使用（项目结束自动还原）", id))
			return r2, u2, nil
		}
		o.log(p, stageID, fmt.Sprintf("✗ 备用模型 [%s] 亦失败: %s", id, truncateText(e2.Error(), 120)))
	}
	return resp, usage, err
}

// LLM 供各处取当前客户端（热切换安全）。
func (o *Orchestrator) LLM() llm.Client {
	o.clientMu.RLock()
	defer o.clientMu.RUnlock()
	return o.llm
}

// Approver 暴露审批器（供 Web 层人工决策）。
func (o *Orchestrator) Approver() *Approver { return o.approver }

// SetAutoApprove 更新项目审批策略（manual=全部人工 / l1=仅L1自动 / all=L1+L2自动）。
func (o *Orchestrator) SetAutoApprove(projectID, policy string) error {
	p, err := o.store.GetProject(projectID)
	if err != nil {
		return err
	}
	p.AutoApprove = policy
	if err := o.store.SaveProject(p); err != nil {
		return err
	}
	// 同步运行中项目的活指针：流水线各阶段收口会整对象回写，旧快照会把刚改的策略覆盖回去
	o.liveMu.Lock()
	if lp, ok := o.liveP[projectID]; ok {
		lp.AutoApprove = policy
	}
	o.liveMu.Unlock()
	// 策略切到 all：联动放行按旧策略挂起的存量待批工单，避免执行循环卡死在审批屏障
	if policy == "all" {
		if n := o.approver.ApprovePending(projectID, "auto-policy-change"); n > 0 {
			o.log(p, "", fmt.Sprintf("⚙ 策略已切换为全自动批准；联动放行 %d 个存量待批工单", n))
		}
	}
	o.log(p, "", fmt.Sprintf("审批策略已更新：%s", policy))
	o.bus.Publish(p.ID, "project", p)
	return nil
}

// Exec 暴露执行器（供 Web 设置层注入测绘 Key 环境变量）。
func (o *Orchestrator) Exec() *tools.Executor { return o.exec }

// ListWorkspaceFilesPublic 供 Web 层浏览工作区文件。
func (o *Orchestrator) ListWorkspaceFilesPublic(projectID, prefix string) ([]wsFile, error) {
	if _, err := o.store.GetProject(projectID); err != nil {
		return nil, err
	}
	return o.listWorkspaceFiles(projectID, prefix)
}

// ListWorkspaceFilesFilteredPublic 供 Web 层按顶层目录白名单/排除前缀浏览工作区文件。
// dirs 为空=全库；"." 代表根目录散落文件。返回（最新 cap 条, 过滤后总数）。
func (o *Orchestrator) ListWorkspaceFilesFilteredPublic(projectID string, dirs, exclude []string) ([]wsFile, int, error) {
	if _, err := o.store.GetProject(projectID); err != nil {
		return nil, 0, err
	}
	return o.listWorkspaceFilesFiltered(projectID, wsFilter{dirs: dirs, exclude: exclude}, time.Time{})
}

// ReadFilePublic 供 Web 层读取工作区文本文件。
func (o *Orchestrator) ReadFilePublic(projectID, relPath string) (string, error) {
	if _, err := o.store.GetProject(projectID); err != nil {
		return "", err
	}
	return o.exec.ReadFile(projectID, relPath)
}

// SkillList 暴露技能库（含正文，供 Web 浏览）。
func (o *Orchestrator) SkillList() []*Skill {
	if o.skills == nil {
		return nil
	}
	out := make([]*Skill, 0)
	for _, s := range o.skills.skills {
		out = append(out, s)
	}
	return out
}

// ---------- 对话指挥室 ----------

var chatSessions *ChatSessions

// v3.4.0 对话通道可熔断：chat 轮此前用 context.Background()，Kill 熔断管不到
// 对话触发的工具执行与 LLM 调用；现按项目注册可取消 ctx，熔断级联取消在途对话轮。
func (o *Orchestrator) chatCtx(projectID string) context.Context {
	if projectID == "" {
		return context.Background()
	}
	// v3.4.2 修复：Kill 后对话轮此前可每轮重新注册新 ctx 绕过熔断继续转
	// （LLM 调用照常、工具靠审批拒绝兜底，白耗 24 轮）；现查项目终态直接返回已取消 ctx。
	if p, err := o.store.GetProject(projectID); err == nil && p.Status == "killed" {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		return ctx
	}
	o.chatMu.Lock()
	defer o.chatMu.Unlock()
	if o.chatCancels == nil {
		o.chatCancels = map[string]context.CancelFunc{}
	}
	// 同项目并发轮罕见：旧轮 ctx 让位（取消旧轮，保持每项目最多一个在途轮）
	if old, ok := o.chatCancels[projectID]; ok {
		old()
	}
	ctx, cancel := context.WithCancel(context.Background())
	o.chatCancels[projectID] = cancel
	return ctx
}

// ---------- v5.2.0 P1-1：ROE/范围确定性校验（执行器级，不依赖提示词） ----------

// roeAutoRegisterDeny 返回注册类写操作是否被 ROE 禁止：YAML Profile 显式 deny，
// 或未配置 Profile（文本 ROE）时按平台默认 deny（identity-bootstrapping 一a节口径）。
func (o *Orchestrator) roeAutoRegisterDeny() bool {
	if o.roe == nil {
		return true
	}
	return o.roe.Values["identity.auto_register"] == "deny"
}

var registrationPostRe = regexp.MustCompile(`(?i)(\-X\s*POST|--request\s*POST|--data(-urlencode)?[ =]| -d | -F )`)

var registrationPathRe = regexp.MustCompile(`(?i)/(user)?(regist|signup|create_?user|user_?create|self_?register)[a-z0-9_.]*`)

// registrationGate ROE auto_register=deny 时拦截"注册端点写提交"（POST/表单）；GET 页面评估不受限。
func (o *Orchestrator) registrationGate(command string) (bool, string) {
	if !o.roeAutoRegisterDeny() {
		return false, ""
	}
	if registrationPostRe.MatchString(command) && registrationPathRe.MatchString(command) {
		return true, "ROE identity.auto_register=deny：禁止注册端点写提交（注册面评估仅限 GET 页面/协议还原）。" +
			"如客户书面授权注册测试，请在项目 ROE Profile 配置 identity.auto_register=allow 后重试。" +
			"若本命令混合了被禁的注册写与合法动作（如其他端点重试），请拆分命令、单独重试合法部分（v5.4.3）。"
	}
	return false, ""
}

// v5.2.0 P1-1b：范围确定性校验——strict_scope 项目中，命令出现的 URL/IP 目标必须落在
// 主目标域（含子域）或已登记资产内；OSINT/工具源走良性外部白名单（可经 config 扩充）。
var urlHostRe = regexp.MustCompile(`https?://([A-Za-z0-9_.:-]+)`)
var ipLitRe = regexp.MustCompile(`\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b`)

// proxyAssignRe 匹配命令文本中的代理环境变量赋值（export/env http_proxy=… https_proxy=… 等）。
// 值由部署环境或 TOOL_PROXY 注入，属传输通道配置而非测试目标——v5.7.2 安装通道分流后
// install_tool 的代理兜底命令携带代理地址（如 docker 网桥 IP），目标匹配前必须剥离，否则
// strict_scope 项目会把代理 IP 误判为范围外目标确定性拦截；loop-core 教的
// `env http_proxy=$TOOL_PROXY <cmd>` 下载前缀同理，属既有潜伏误拦面。与 v5.3.9 OSINT 白名单
// 同理：范围匹配器只应校验业务目标。
var proxyAssignRe = regexp.MustCompile(`(?i)\b[a-z_]*(https?_proxy|all_proxy|no_proxy)=\S+`)

var defaultScopeAllowlist = []string{
	"crt.sh", "github.com", "raw.githubusercontent.com", "api.github.com", "objects.githubusercontent.com",
	"nvd.nist.gov", "services.nvd.nist.gov", "nuclei.sh", "cve.mitre.org", "cve.org",
	"pypi.org", "files.pythonhosted.org", "pypi.tuna.tsinghua.edu.cn", "mirrors.tuna.tsinghua.edu.cn",
	"registry.npmmirror.com", "registry.npmjs.org", "deb.debian.org", "security.debian.org",
	"http.kali.org", "kali.download", "mirrors.ustc.edu.cn", "mirrors.aliyun.com",
	"dns.alidns.com", "223.5.5.5", "119.29.29.29", "8.8.8.8", "1.1.1.1",
	"gitee.com", // v5.3.1：install_tool git 策略的国内镜像源（installToolGitMap 第二策略）
	// v5.3.9：OSINT 数据源补全——对第三方 API 的读请求不是对目标发包，不应被目标匹配器误拦
	// （实测事故：某历史任务空间测绘四平台全被 strict_scope 拦截，OSINT 轨空转）。
	// 泄露库/测绘/代码检索与档案类数据源；recon-playbook / osint-leak-intel / history-recon 消费。
	"fofa.info", "quake.360.net", "zoomeye.org", "hunter.qianxin.com",
	"api.pwnedpasswords.com", "haveibeenpwned.com", "virustotal.com", "shodan.io", "censys.io",
	"oast.pro", "oast.live", "oast.site", "dnslog.cn", "interact.sh", "oob.interactsh.com",
	"searchsploit", "localhost", "127.0.0.1", "0.0.0.0", "example.com", "example.edu",
	"grep.app", "searchcode.com", "web.archive.org", "archive.org", "haveibeenpwned.com",
}

func hostAllowed(host string, target string, allow map[string]bool) bool {
	h := strings.ToLower(strings.TrimSuffix(strings.TrimSuffix(host, "."), ":443"))
	h = strings.TrimPrefix(h, "www.")
	if h == "" || allow[h] {
		return true
	}
	t := strings.ToLower(strings.TrimPrefix(strings.TrimPrefix(target, "https://"), "http://"))
	t = strings.TrimSuffix(strings.TrimSuffix(strings.TrimSuffix(t, "/"), "."), ":443")
	if t != "" && (h == t || strings.HasSuffix(h, "."+t)) {
		return true
	}
	return false
}

// scopeGate strict_scope=true 时对命令中的网络目标做确定性校验（资产/白名单/主目标域）。
func (o *Orchestrator) scopeGate(p *store.Project, command string) (bool, string) {
	if !p.StrictScope {
		return false, ""
	}
	// v5.7.2：代理赋值是传输通道配置而非测试目标，剥离后再做目标提取（见 proxyAssignRe 注释）
	command = proxyAssignRe.ReplaceAllString(command, "")
	allow := map[string]bool{}
	for _, a := range defaultScopeAllowlist {
		allow[strings.ToLower(a)] = true
	}
	if o.cfg != nil && len(o.cfg.Guard.ScopeAllowlist) > 0 {
		for _, a := range o.cfg.Guard.ScopeAllowlist {
			allow[strings.ToLower(a)] = true
		}
	}
	assets, _ := o.store.ListAssets(p.ID)
	for _, a := range assets {
		v := strings.ToLower(strings.TrimSpace(a.Value))
		v = strings.TrimPrefix(strings.TrimPrefix(v, "https://"), "http://")
		v = strings.TrimSuffix(strings.TrimSuffix(strings.TrimSuffix(v, "/"), "."), ":443")
		if v != "" {
			allow[v] = true
		}
	}
	bad := []string{}
	for _, h := range urlHostRe.FindAllStringSubmatch(command, -1) {
		if !hostAllowed(h[1], p.Target, allow) {
			bad = append(bad, h[1])
		}
	}
	for _, ip := range ipLitRe.FindAllStringSubmatch(command, -1) {
		if !hostAllowed(ip[1], p.Target, allow) {
			bad = append(bad, ip[1])
		}
	}
	if len(bad) == 0 {
		return false, ""
	}
	return true, fmt.Sprintf("strict_scope=true：命令引用范围外目标 %v——已确定性拦截。"+
		"如属授权范围：先 record_asset 登记该资产再重试；OSINT/工具源误拦请在 config guard.scope_allowlist 扩充。", bad)
}

// governanceGates v5.3.1 P0-2：全部命令执行通道的统一确定性门——执行档（profile）+ 注册写 + 范围。
// 此前（v5.2.0）双门只在 shell_open 生效，run_command/run_async/shell_write/hexstrike 等主通道
// 全部绕过；本函数作为唯一接线点消除断层。阻断发生在风险分级与审批之前（不烧审批槽位），
// 并统一留证（证据链可回溯每一条被拦动作）。skipProfile 供 install_tool 使用：
// 安装 mysqldump 等客户端本身是合规基建动作，profile 约束其「使用」而非「安装」。
func (o *Orchestrator) governanceGates(p *store.Project, stageID, command, channel string, skipProfile bool) string {
	if !skipProfile {
		if blocked, msg := o.profileGate(p, command); blocked {
			o.log(p, stageID, fmt.Sprintf("⛔ Execution Profile 违禁动作被拦截（v5.3.1 %s 通道）", channel))
			_, _ = o.store.AddEvidence(&store.EvidenceRecord{ProjectID: p.ID, Stage: stageID, Type: "command",
				Input: truncateText(command, 200), Output: "被治理门拦截（execution_profile=" + o.profileOf(p) + "）：" + msg,
				Risk: tools.Forbidden, ApprovedBy: "profile-gate"})
			return msg
		}
	}
	if blocked, msg := o.registrationGate(command); blocked {
		o.log(p, stageID, fmt.Sprintf("⛔ 注册写提交被 ROE 拦截（确定性校验 %s 通道）", channel))
		_, _ = o.store.AddEvidence(&store.EvidenceRecord{ProjectID: p.ID, Stage: stageID, Type: "command",
			Input: truncateText(command, 200), Output: "被治理门拦截：" + msg,
			Risk: tools.L1Write, ApprovedBy: "registration-gate"})
		return msg
	}
	if blocked, msg := o.scopeGate(p, command); blocked {
		o.log(p, stageID, fmt.Sprintf("⛔ 范围外目标被确定性拦截（strict_scope %s 通道）", channel))
		_, _ = o.store.AddEvidence(&store.EvidenceRecord{ProjectID: p.ID, Stage: stageID, Type: "command",
			Input: truncateText(command, 200), Output: "被治理门拦截：" + msg,
			Risk: tools.L1Write, ApprovedBy: "scope-gate"})
		return msg
	}
	return ""
}

// rerankSubtasks v5.3.2 P1-5：阶段内任务规划按覆盖缺口/风险/证据自调优先级。
// 依据：①覆盖账本缺口（vulnerable 未闭环 +5 / needs_follow_up +3 / waf_blocked 待复验 +2，
// 按 endpoint/param/vuln_class 与子任务文本重叠匹配）；②风险分级（L2 +2 / L1 +1）；
// ③证据（已绑定 evidence/或 EV- 引用 +2；声明「未验证/无证据/待验证」 +4 证据缺口优先）。
// 终态任务沉底。只写 Priority/PriorityWhy 字段，任务 id 与内容稳定；plan_subtasks 建档后与
// update_coverage 落账后触发，让阶段头每步拿到当前最该做的排序。
func (o *Orchestrator) rerankSubtasks(p *store.Project, stageID string) []*store.Subtask {
	all, err := o.store.ListSubtasks(p.ID)
	if err != nil {
		return nil
	}
	var subs []*store.Subtask
	for _, st := range all {
		if st.Stage == stageID {
			subs = append(subs, st)
		}
	}
	if len(subs) == 0 {
		return nil
	}
	covs, _ := o.store.ListCoverage(p.ID)
	type row struct {
		st    *store.Subtask
		score int
		why   []string
	}
	rows := make([]row, 0, len(subs))
	for _, st := range subs {
		text := strings.ToLower(st.Title + " " + st.Detail)
		score := 0
		why := []string{}
		for _, c := range covs {
			key := strings.ToLower(c.Endpoint + " " + c.Param + " " + c.VulnClass)
			if !overlapKey(text, key) {
				continue
			}
			switch c.Status {
			case "vulnerable":
				score += 8 // 确证漏洞未闭环：最高优先（压过覆盖缺口+证据缺口的叠加，确证项必须最先闭环）
				why = append(why, "覆盖[vulnerable]未闭环+8")
			case "needs_follow_up":
				score += 3
				why = append(why, "覆盖缺口+3")
			case "waf_blocked":
				score += 2
				why = append(why, "覆盖[waf_blocked]待复验+2")
			}
		}
		switch o.exec.ClassifyRisk(st.Title + " " + st.Detail) {
		case tools.L2High:
			score += 2
			why = append(why, "高危动作+2")
		case tools.L1Write:
			score += 1
			why = append(why, "写操作+1")
		}
		if strings.Contains(text, "evidence/") || strings.Contains(text, "ev-") {
			score += 2
			why = append(why, "已绑定证据+2")
		} else if strings.Contains(text, "未验证") || strings.Contains(text, "无证据") || strings.Contains(text, "待验证") {
			score += 4
			why = append(why, "证据缺口+4")
		}
		if st.Status == "finished" || st.Status == "failed" {
			score = -1
			why = append([]string{"终态"}, why...)
		}
		rows = append(rows, row{st, score, why})
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].score != rows[j].score {
			return rows[i].score > rows[j].score
		}
		return rows[i].st.ID < rows[j].st.ID
	})
	for i, r := range rows {
		r.st.Priority = i + 1
		r.st.PriorityWhy = strings.Join(r.why, "；")
		_ = o.store.SaveSubtask(r.st)
	}
	ranked := make([]*store.Subtask, 0, len(rows))
	for _, r := range rows {
		ranked = append(ranked, r.st)
	}
	return ranked
}

// overlapKey 覆盖键↔子任务文本重叠判定：键切词后仅「特异性 token」参与匹配——
// 中文词（≥1 汉字）或 ≥5 字符 ASCII 词。api/get/user 这类通用短词不参与，
// 避免 /api/user 与 /api/exec 互相误命中（实证曾致全部任务命中全部覆盖项、排序失效）。
func overlapKey(text, key string) bool {
	if strings.TrimSpace(key) == "" {
		return false
	}
	for _, tok := range strings.FieldsFunc(key, func(r rune) bool {
		return !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r >= 0x4e00 && r <= 0x9fff)
	}) {
		specific := false
		for _, r := range tok {
			if r >= 0x4e00 && r <= 0x9fff {
				specific = true
				break
			}
		}
		if !specific && len(tok) >= 5 {
			specific = true
		}
		if specific && strings.Contains(text, tok) {
			return true
		}
	}
	return false
}

// DeleteProject v5.3.5：彻底删除项目（kill 后可删）。运行中项目拒绝（先 kill）；清除内存
// 注册表（活指针/指令队列/回环请求/预算器统计/对话会话）→ bbolt 全部项目作用域记录 →
// 工作区目录（deliverables/evidence/report 等随目录一并移除）。
func (o *Orchestrator) DeleteProject(projectID string) error {
	if o.IsRunning(projectID) {
		return fmt.Errorf("项目仍在运行：请先执行 kill 再删除")
	}
	if _, err := o.store.GetProject(projectID); err != nil {
		return err
	}
	o.liveMu.Lock()
	delete(o.liveP, projectID)
	o.liveMu.Unlock()
	o.mu.Lock()
	delete(o.running, projectID)
	delete(o.tokens, projectID)
	delete(o.batchStats, projectID)
	o.mu.Unlock()
	o.inputMu.Lock()
	delete(o.inputs, projectID)
	o.inputMu.Unlock()
	o.loopMu.Lock()
	delete(o.loops, projectID)
	o.loopMu.Unlock()
	o.askMu.Lock()
	delete(o.asks, projectID)
	o.askMu.Unlock()
	o.chatMu.Lock()
	delete(o.chatCancels, projectID)
	o.chatMu.Unlock()
	chatSessions.Reset(projectID)
	o.subMu.Lock()
	delete(o.subRuns, projectID)
	o.subMu.Unlock()
	if err := o.store.DeleteProject(projectID); err != nil {
		return err
	}
	if dir := filepath.Join(o.cfg.DataDir, projectID); dir != "" && dir != o.cfg.DataDir {
		if err := os.RemoveAll(dir); err != nil {
			log.Printf("项目 %s 记录已删除但工作区目录清理失败（%s）: %v", projectID, dir, err)
		}
	}
	log.Printf("🗑 项目 %s 已彻底删除（记录+工作区）", projectID)
	return nil
}

// SetExecutionProfile v5.3.1：项目执行档切换（与 SetAutoApprove 同构——活指针同步防旧快照回写）。
func (o *Orchestrator) SetExecutionProfile(projectID, profile string) error {
	profile = strings.ToLower(strings.TrimSpace(profile))
	if profile != ProfileProductionSafe && profile != ProfileIsolatedLab {
		return fmt.Errorf("execution_profile 仅支持 production_safe / isolated_lab")
	}
	p, err := o.store.GetProject(projectID)
	if err != nil {
		return err
	}
	p.ExecutionProfile = profile
	if err := o.store.SaveProject(p); err != nil {
		return err
	}
	o.liveMu.Lock()
	if lp, ok := o.liveP[projectID]; ok {
		lp.ExecutionProfile = profile
	}
	o.liveMu.Unlock()
	o.log(p, "", fmt.Sprintf("执行档已更新：%s（逐动作强制口径随之切换）", profile))
	o.bus.Publish(p.ID, "project", p)
	return nil
}

// chatTurnDone 对话轮结束注销（Turn 结束时 defer）。
func (o *Orchestrator) chatTurnDone(projectID string) {
	if projectID == "" {
		return
	}
	o.chatMu.Lock()
	// v5.1.2 P1 修复：轮结束同时取消该轮 ctx——此前只 delete 不 cancel，
	// 经 chat 派发的子代理可在项目结项后继续执行工具污染已归档项目。
	if cancel, ok := o.chatCancels[projectID]; ok && cancel != nil {
		cancel()
	}
	delete(o.chatCancels, projectID)
	o.chatMu.Unlock()
}

// Chat 处理一轮对话（projectID 可空=咨询模式）。
func (o *Orchestrator) Chat(projectID, message string) (string, error) {
	return chatSessions.Turn(projectID, message)
}

func (o *Orchestrator) ChatHistory(projectID string) []llm.Message {
	return chatSessions.History(projectID)
}

func (o *Orchestrator) ChatReset(projectID string) { chatSessions.Reset(projectID) }

// logChatErr 对话模式错误留痕（stdout + 项目事件流）。
func (o *Orchestrator) logChatErr(projectID string, err error) {
	log.Printf("[chat %s] LLM 调用失败: %v", projectID, err)
	if projectID != "" {
		if p, gerr := o.store.GetProject(projectID); gerr == nil {
			o.log(p, "chat", "LLM 调用失败: "+err.Error())
		}
	}
}

// accountUsageChat 对话轮次记账（stage=chat）。
func (o *Orchestrator) accountUsageChat(projectID string, u llm.Usage) {
	if projectID == "" {
		return
	}
	total := int64(u.TotalTokens)
	if total <= 0 {
		return
	}
	if rec, err := o.store.AddUsage(projectID, "chat", int64(u.PromptTokens), int64(u.CompletionTokens)); err == nil {
		o.bus.Publish(projectID, "usage", rec)
	}
	o.mu.Lock()
	o.tokens[projectID] += total
	o.mu.Unlock()
}

// dispatchChat 对话模式复用阶段分发逻辑（完整审批与留证），并向 UI 发结构化工具块事件（持久化，刷新可回填）。
func (o *Orchestrator) dispatchChat(projectID string, tc llm.ToolCall) string {
	p, err := o.store.GetProject(projectID)
	if err != nil {
		return "错误: 项目不存在"
	}
	if tc.Name == "complete_stage" || tc.Name == "loopback" {
		return "对话模式下不可用（该工具属于阶段流水线）"
	}
	result := o.dispatch(o.chatCtx(p.ID), p, "chat", tc)
	// PentAGI 式工具块：{tool, args, result} 结构化推送 + 执行流落库
	o.streamTool(projectID, "chat", tc, result)
	return result
}

// streamMsg 持久化并推送一条 AI 对话消息（阶段执行中的思考/说明文本，PentAGI 式消息流）。
func (o *Orchestrator) streamMsg(projectID, stage, text string) {
	_, _ = o.store.AddStream(projectID, &store.StreamRecord{Kind: "msg", Stage: stage, Role: "assistant", Text: truncateText(text, 4000)})
	o.bus.Publish(projectID, "stage_msg", map[string]any{"stage": stage, "text": truncateText(text, 2000)})
}

// streamTool 持久化并推送一次工具调用（阶段执行与对话模式通用，刷新后可回填工具调用页签）。
func (o *Orchestrator) streamTool(projectID, stage string, tc llm.ToolCall, result string) {
	// v5.6.0 秘密卫生（审计修复高危#2）：工具参数/结果持久化前统一脱敏——
	// 原实现把 tc.Arguments 前 800 字节原样落执行流+推 UI，store_credential 的 secret
	// 参数会绕过加密仓库明文留存；现在参数走 JSON 感知脱敏、结果走模式兜底脱敏。
	rec := &store.StreamRecord{Kind: "tool", Stage: stage, Tool: tc.Name,
		Args: truncateText(maskToolArgsJSON(tc.Arguments), 800), Result: truncateText(maskSensitiveText(result), 1600)}
	_, _ = o.store.AddStream(projectID, rec)
	o.bus.Publish(projectID, "stage_tool", map[string]any{"tool": rec.Tool, "args": rec.Args, "result": rec.Result, "stage": stage})
}

// ---------- 项目生命周期 ----------

func (o *Orchestrator) CreateProject(in *store.Project) (*store.Project, error) {
	if strings.TrimSpace(in.Name) == "" {
		return nil, fmt.Errorf("项目名称必填")
	}
	p := &store.Project{
		Name: in.Name, Target: in.Target, Scope: in.Scope, ROE: in.ROE,
		TestType: in.TestType, TimeWindow: in.TimeWindow,
		Contact: in.Contact, SuccessCriteria: in.SuccessCriteria,
		AuthInfo: in.AuthInfo, StrictScope: in.StrictScope, BudgetTokens: in.BudgetTokens,
		Authorized: in.Authorized, AutoApprove: in.AutoApprove,
		// v5.4.0 修复：ModelID 此前被漏拷——创建页选择模型静默失效（32/32 项目 model_id 全空，
		// 全部回退默认模型），clientFor 读到空值不报错，用户无从察觉。补上即修复。
		ModelID:          in.ModelID,
		ExecutionProfile: in.ExecutionProfile, // v5.3.1：执行档随项目持久化（store 层缺省 production_safe）
		PostExploit:      in.PostExploit,      // v5.3.7：后渗透勾选随项目持久化
		Specializations:  in.Specializations, Status: "created",
		StageStates: map[string]*store.StageState{},
	}
	if err := o.store.CreateProject(p); err != nil {
		return nil, err
	}
	// 初始化流水线内全部阶段为 pending
	for _, id := range Pipeline(o.heads, in.Specializations) {
		p.StageStates[id] = &store.StageState{Status: "pending"}
	}
	_ = o.store.SaveProject(p)
	o.bus.Publish(p.ID, "project", p)
	return p, nil
}

// StartProject 异步启动整条流水线。
func (o *Orchestrator) StartProject(projectID string) error {
	p, err := o.store.GetProject(projectID)
	if err != nil {
		return err
	}
	if p.Status == "running" {
		return fmt.Errorf("项目已在运行")
	}
	ctx, cancel := context.WithCancel(context.Background())
	o.mu.Lock()
	o.running[projectID] = cancel
	o.mu.Unlock()

	p.Status = "running"
	if p.StartedAt == "" {
		p.StartedAt = time.Now().Format(time.RFC3339) // v2.6：首次启动时间（断点续跑保留，仪表盘运行时长基准）
	}
	_ = o.store.SaveProject(p)
	o.bus.Publish(projectID, "project", p)
	o.log(p, "", fmt.Sprintf("项目启动：目标=%s；授权范围=%s", p.Target, firstLine(p.Scope)))

	o.liveMu.Lock()
	o.liveP[projectID] = p // 注册活指针：运行中策略/字段变更直接作用于本对象
	o.liveMu.Unlock()
	go func() {
		defer cancel()
		defer o.finishRun(projectID)
		o.runPipeline(ctx, p)
	}()
	return nil
}

func (o *Orchestrator) finishRun(projectID string) {
	o.mu.Lock()
	delete(o.running, projectID)
	o.mu.Unlock()
	o.liveMu.Lock()
	delete(o.liveP, projectID)
	o.liveMu.Unlock()
	o.projMu.Lock()
	delete(o.projModel, projectID) // v2.7 A8：项目结束清除模型接管覆盖，下次运行回到默认模型
	o.projMu.Unlock()
	// v2.6：流水线结束（含暂停/失败/熔断）强制清理后台任务——孤儿进程会继续打目标，属合规风险
	if n := o.exec.KillAllAsync(projectID); n > 0 {
		o.bus.Publish(projectID, "log", map[string]string{"level": "warn", "stage": "", "text": fmt.Sprintf("🧹 流水线结束，已强制清理 %d 个后台任务（残留进程不允继续运行）", n)})
	}
}

// RunStage 手动运行单个阶段头。
func (o *Orchestrator) RunStage(projectID, stageID string) error {
	p, err := o.store.GetProject(projectID)
	if err != nil {
		return err
	}
	h, ok := o.heads[stageID]
	if !ok || h.Kind == "main" {
		return fmt.Errorf("未知阶段: %s", stageID)
	}
	if p.Status == "running" {
		return fmt.Errorf("项目运行中，勿并发触发阶段")
	}
	ctx, cancel := context.WithCancel(context.Background())
	o.mu.Lock()
	o.running[projectID] = cancel
	o.mu.Unlock()
	p.Status = "running"
	if p.StartedAt == "" {
		p.StartedAt = time.Now().Format(time.RFC3339) // v2.6：首次启动时间（手动重跑同样记录）
	}
	_ = o.store.SaveProject(p)

	o.liveMu.Lock()
	o.liveP[projectID] = p
	o.liveMu.Unlock()
	go func() {
		defer cancel()
		defer o.finishRun(projectID)
		_ = o.runStage(ctx, p, stageID)
		// v2.3.3：手动重跑的阶段若收口且全部阶段已完成 → 自动结项（done + 导出工件），
		// 不再停在「已暂停」等人工再点一次启动（实测 UX 瑕疵：冒烟项目 S8 手动重跑后停留在 paused）
		if st := p.StageStates[stageID]; st != nil && st.Status == "done" && o.allStagesSettled(p) {
			o.refreshProjectStatus(p)
			if fresh, err := o.store.GetProject(projectID); err == nil && fresh.Status == "paused" {
				fresh.Status = "done"
				fresh.FinishedAt = time.Now().Format(time.RFC3339)
				_ = o.store.SaveProject(fresh)
				o.bus.Publish(projectID, "project", fresh)
				o.log(fresh, "", "🏁 全部阶段已完成（手动重跑收口），项目自动结项")
				o.exportArtifacts(fresh)
				return
			}
		}
		o.refreshProjectStatus(p)
	}()
	return nil
}

// Kill 一键熔断：取消流水线、杀进程、撤审批。
func (o *Orchestrator) Kill(projectID, reason string) error {
	p, err := o.store.GetProject(projectID)
	if err != nil {
		return err
	}
	o.mu.Lock()
	cancel := o.running[projectID]
	o.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	o.exec.KillAll(projectID)
	o.approver.CancelProject(projectID)
	o.CancelProjectAsks(projectID)
	// v3.6.0：级联终止在途子代理
	if n := o.killSubAgents(projectID); n > 0 {
		o.log(p, "", fmt.Sprintf("🧩 已终止 %d 个在途子代理", n))
	}
	// v3.4.0：级联取消在途对话轮（chat 工具轮此前不受熔断控制）
	o.chatMu.Lock()
	if cancel, ok := o.chatCancels[projectID]; ok {
		cancel()
		delete(o.chatCancels, projectID)
	}
	o.chatMu.Unlock()

	// 同步活指针（修复：被取消的协程随后用旧快照 SaveProject 会把 killed 覆盖回 running）
	o.liveMu.Lock()
	if lp, ok := o.liveP[projectID]; ok {
		lp.Status = "killed"
		lp.KillReason = reason
		lp.FinishedAt = time.Now().Format(time.RFC3339) // v2.6：仪表盘总耗时基准
		p = lp                                          // 落库用同一对象，保证与后续协程写回一致
	} else {
		p.Status = "killed"
		p.KillReason = reason
		p.FinishedAt = time.Now().Format(time.RFC3339)
	}
	o.liveMu.Unlock()
	if err := o.store.SaveProject(p); err != nil {
		return err
	}
	o.bus.Publish(projectID, "kill", map[string]string{"reason": reason})
	o.log(p, "", "⚠️ 已一键熔断：全部自主操作中止，状态落盘，等待人工接管。")
	return nil
}

func (o *Orchestrator) refreshProjectStatus(p *store.Project) {
	fresh, err := o.store.GetProject(p.ID)
	if err != nil {
		return
	}
	if fresh.Status == "running" {
		fresh.Status = "paused"
		_ = o.store.SaveProject(fresh)
		o.bus.Publish(fresh.ID, "project", fresh)
	}
}

// LogStartupRecovery 启动恢复留痕：进程重启中断的项目置 paused 后在执行流说明。
func (o *Orchestrator) LogStartupRecovery(p *store.Project) {
	if p.StageStates != nil {
		for _, st := range p.StageStates {
			if st != nil && st.Status == "running" {
				st.Status = "pending" // 中断的运行中阶段回到待执行，重跑即续
			}
		}
	}
	_ = o.store.SaveProject(p)
	o.log(p, p.CurrentStage, "⚙ 引擎进程重启，流水线在此处中断（启动恢复：已置为待续跑）。请在「阶段流水线」手动重跑中断阶段继续，或重新启动项目（已完成的阶段会自动跳过）。")
}

// allStagesSettled 判断项目全部阶段是否都已终态（done/failed/killed/skipped），
// 无 pending/running——供手动单阶段重跑后判断能否自动结项。
func (o *Orchestrator) allStagesSettled(p *store.Project) bool {
	for _, st := range p.StageStates {
		if st == nil {
			continue
		}
		switch st.Status {
		case "done", "failed", "killed", "skipped":
		default:
			return false
		}
	}
	return len(p.StageStates) > 0
}

// runPipeline 依序执行流水线；处理回环（阶段4↔5 新线索回环）。
func (o *Orchestrator) runPipeline(ctx context.Context, p *store.Project) {
	pipeline := Pipeline(o.heads, p.Specializations)
	for _, stageID := range pipeline {
		if ctx.Err() != nil {
			return
		}
		state := p.StageStates[stageID]
		if state == nil {
			state = &store.StageState{Status: "pending"}
			p.StageStates[stageID] = state
		}
		if state.Status == "done" || state.Status == "skipped" {
			continue
		}
		// v5.3.7 后渗透勾选门：创建时未勾选 post_exploit 的项目，s6（提权/横向/权限维持/
		// 云逃逸/存量排查）整段 skipped——用户范围决策非漏测，报告侧由 s8 显式标注。
		// 工作台手动单阶段重跑 s6 不受此限制（明确意图优先）；重启续跑幂等（每次进入主循环重判）。
		if o.applyPostExploitGate(p, stageID, state) {
			continue
		}
		if err := o.runStage(ctx, p, stageID); err != nil {
			if ctx.Err() != nil {
				return
			}
			// F-04 修复：阶段失败（LLM 断连/预算耗尽等）不再继续后面的阶段——
			// 后续阶段依赖本阶段交付物，盲目推进会产出无根据的"完成"
			p.Status = "failed"
			p.CurrentStage = stageID
			p.FinishedAt = time.Now().Format(time.RFC3339)
			_ = o.store.SaveProject(p)
			o.bus.Publish(p.ID, "project", p)
			o.log(p, stageID, "⛔ 阶段异常中断，流水线停止: "+err.Error()+"（可在「阶段流水线」手动重跑该阶段后继续）")
			return
		}
		// 迭代耗尽等软失败：runStage 返回 nil 但阶段状态为 failed，同样停跑
		if st := p.StageStates[stageID]; st != nil && st.Status == "failed" {
			p.Status = "failed"
			p.FinishedAt = time.Now().Format(time.RFC3339)
			_ = o.store.SaveProject(p)
			o.bus.Publish(p.ID, "project", p)
			o.log(p, stageID, "⛔ 阶段未收口（"+st.Summary+"），流水线停止（可手动重跑该阶段后继续）")
			return
		}
		// v5.5.0（修复方案 E）：预算耗尽暂停——阶段 paused 时流水线不再推进后续阶段，
		// 等待人工提升预算/重跑（后续阶段基于半成品交付物工作比停下来更危险）。
		if st := p.StageStates[stageID]; st != nil && st.Status == "paused" {
			p.Status = "paused"
			p.CurrentStage = stageID
			_ = o.store.SaveProject(p)
			o.bus.Publish(p.ID, "project", p)
			o.log(p, stageID, "⏸ 阶段预算耗尽已暂停，流水线停止推进（"+st.Summary+"）——提升预算后在「阶段流水线」重跑该阶段继续")
			return
		}
	}
	// 回环补跑（F-03 修复）：阶段头 loopback 登记的前置阶段在此真正重跑
	o.loopMu.Lock()
	rerun := o.loops[p.ID]
	o.loops[p.ID] = nil
	o.loopMu.Unlock()
	for _, stageID := range rerun {
		if ctx.Err() != nil {
			return
		}
		if st, ok := p.StageStates[stageID]; !ok || st.Status != "pending" {
			continue // 已完成或正在跑则不重复
		}
		o.log(p, stageID, "↩ 执行回环补跑（新线索触发）")
		_ = o.runStage(ctx, p, stageID)
	}
	// 结束状态如实：任一阶段 failed → 项目 failed，不再无条件标 done
	final := "done"
	for _, st := range p.StageStates {
		if st.Status == "failed" {
			final = "failed"
			break
		}
	}
	p.Status = final
	if final == "done" || final == "failed" {
		p.FinishedAt = time.Now().Format(time.RFC3339) // v2.6：终态时间（仪表盘总耗时基准）
	}
	_ = o.store.SaveProject(p)
	o.bus.Publish(p.ID, "project", p)
	o.exportArtifacts(p)
}

// ---------- 单阶段执行循环 ----------

// applyQualityReviewConfirm v5.3.8：quality-pending 复核标记处理。返回 true=存在未确认标记
// （调用方应软提示重试）；confirm=true 时清除全部标记（Review 改写为 quality-reviewed 留痕）。
func (o *Orchestrator) applyQualityReviewConfirm(p *store.Project, confirm bool) bool {
	var pending []string
	for sid, st := range p.StageStates {
		// nil StageState 防御（v5.1.2 P1：goroutine 内无 recover，解引用即整进程崩溃）
		if st != nil && strings.Contains(st.Review, "quality-pending") {
			pending = append(pending, sid)
		}
	}
	if len(pending) == 0 {
		return false
	}
	if !confirm {
		o.log(p, "s8", fmt.Sprintf("⚠ %d 个阶段带 quality-pending 复核标记: %s——等待复核确认", len(pending), strings.Join(pending, ",")))
		return true
	}
	for _, sid := range pending {
		st := p.StageStates[sid]
		st.Review = strings.ReplaceAll(st.Review, "quality-pending", "quality-reviewed（v5.3.8 复核确认）")
	}
	_ = o.store.SaveProject(p)
	o.bus.Publish(p.ID, "project", p)
	o.log(p, "s8", "✓ 复核确认已提交——清除 "+fmt.Sprint(len(pending))+" 个阶段的 quality-pending 标记: "+strings.Join(pending, ","))
	return false
}

// applyPostExploitGate v5.3.7：s6 后渗透勾选门。创建时未勾选 post_exploit（默认）→ s6 整段
// 置 skipped（Summary 记录决策原因，工作台手动重跑 s6 不受此门限制）。返回 true=已跳过。
func (o *Orchestrator) applyPostExploitGate(p *store.Project, stageID string, state *store.StageState) bool {
	if stageID != "s6" || p.PostExploit {
		return false
	}
	state.Status = "skipped"
	state.Summary = "后渗透未勾选（创建时用户决策）：提权/横向/权限维持/云逃逸/存量排查整段跳过；如需执行可在阶段流水线手动重跑 s6"
	state.EndedAt = time.Now().Format(time.RFC3339)
	_ = o.store.SaveProject(p)
	o.bus.Publish(p.ID, "project", p)
	o.log(p, stageID, "⏭ s6 后渗透跳过（创建时未勾选 post_exploit）——范围决策非漏测")
	return true
}

func (o *Orchestrator) runStage(ctx context.Context, p *store.Project, stageID string) error {
	head := o.heads[stageID]
	if head == nil {
		return fmt.Errorf("头未注册: %s", stageID)
	}
	state := p.StageStates[stageID]
	if state == nil {
		state = &store.StageState{}
		p.StageStates[stageID] = state
	}
	state.Status = "running"
	state.Iterations = 0
	state.Summary = "" // 清空上次（失败）残留摘要
	state.StartedAt = time.Now().Format(time.RFC3339)
	_ = o.store.SaveProject(p)
	o.bus.Publish(p.ID, "stage", map[string]any{"stage": stageID, "status": "running"})
	o.log(p, stageID, fmt.Sprintf("▶ 阶段[%s] %s 启动", stageID, head.Name))

	sys := strings.Join([]string{
		"[[HEAD:" + stageID + "]]", // 头标记：供 Mock/审计识别当前阶段
		o.coreLoop,
		head.Body,
	}, "\n\n")

	msgs := []llm.Message{
		{Role: "system", Content: sys},
		{Role: "user", Content: o.buildContextPack(p, stageID)},
	}

	toolDefs := o.toolDefs()
	mon := &execMonitor{} // 执行监控：循环调用检测（PentAGI execution monitor 移植）
	// v2.3.2 阶段差异化迭代上限：报告/文档阶段（s8）写入量大且需承接全部交付物
	// v4.4 多目标自适应（方向二B）：S2/S4/S5 按目标数线性放大（base+(N-1)*perTarget，封顶 3×base）
	nTargets := countProjectTargets(p)
	budget := stageBudget(o.cfg.Engine.MaxStageIterations, stageID, nTargets, o.cfg.Engine.PerTargetRounds)
	if nTargets > 1 && o.cfg.Engine.PerTargetRounds > 0 && (stageID == "s2" || stageID == "s4" || stageID == "s5") {
		o.log(p, stageID, fmt.Sprintf("🎯 多目标轮次自适应：%d 个目标 → 本阶段预算 %d 轮（基础 %d，每增 1 目标 +%d）",
			nTargets, budget, o.cfg.Engine.MaxStageIterations, o.cfg.Engine.PerTargetRounds))
	}
	for iter := 0; iter < budget; iter++ {
		if ctx.Err() != nil {
			state.Status = "killed"
			_ = o.store.SaveProject(p)
			return ctx.Err()
		}
		// 预算护栏：项目级 BudgetTokens 优先（v3.4.0 接线原死字段），否则全局配置
		tokBudget := p.BudgetTokens
		if tokBudget <= 0 {
			tokBudget = o.cfg.MaxProjectTokens
		}
		if tokBudget > 0 && o.projectTokens(p.ID) >= tokBudget {
			state.Status = "failed"
			state.Summary = "token 预算耗尽（max_project_tokens）"
			_ = o.store.SaveProject(p)
			o.log(p, stageID, "⛔ token 预算耗尽，阶段中止（预算护栏）")
			return fmt.Errorf("token 预算耗尽")
		}
		state.Iterations = iter + 1
		// v3.3.0 输出治理③窗口压缩（pentagi window_compaction / HackSynth 滚动摘要的确定性版）：
		// 消息链估算超预算时把最旧的中段工具回执/长助手消息替换为存根——不再「只增不减」，
		// 实测 125k tokens/200 msgs 的注意力稀释与成本失控由此收敛；保护 system/上下文包/最近 N 条。
		// v5.5.0（修复方案 G）：压缩前工具回执原文先归档 receipts 桶，存根携带 receipt id，
		// search_memory query="receipt:<id>" 可取回原文——压缩不再不可逆。
		receiptArchive := func(stage, content string) string {
			// v5.6.1（审计 RunB#11）：归档前统一脱敏——Receipt 是持久化出口之一；
			// 秘密值掩码不影响上下文恢复（凭据可经 auth_ref 重新注入，无需原文）。
			content = maskSensitiveText(content)
			rid, rerr := o.store.SaveReceipt(p.ID, stage, content)
			if rerr != nil {
				log.Printf("[stage %s] 回执归档失败（存根降级为不可检索）: %v", stageID, rerr)
				return ""
			}
			return rid
		}
		if cm, nc := compactMsgsWithArchive(msgs, o.cfg.Engine.ContextBudgetTokens, o.cfg.Engine.ContextKeepRecent, receiptArchive); nc > 0 {
			msgs = cm
			o.log(p, stageID, fmt.Sprintf("🧹 上下文窗口压缩：%d 条旧消息已存根化（当前估算 %d tokens；工具回执原文已归档可按 receipt id 检索）", nc, estimateTokens(msgs)))
		}
		// 指挥室指令注入（PentAGI putUserInput 移植）：运行中项目用户可直接下达指令
		injectedN := 0
		if injected := o.drainInputs(p.ID); len(injected) > 0 {
			msgs = append(msgs, injected...)
			injectedN = len(injected)
			o.log(p, stageID, fmt.Sprintf("🧑‍✈️ 已注入 %d 条指挥室指令", injectedN))
		}
		// v2.7 A7 预算感知收口提醒（自适应提前）：剩 1/3 预算即预警收口、剩 3 轮强制收口——
		// 实测 S2 类重侦察阶段在剩 1/4 才提醒会收不完（60 轮烧尽返工一轮）
		if remain := budget - iter - 1; remain == budget/3 {
			sprintMsg := "⏳ 迭代预算预警（提前触发）：本阶段剩余约 1/3 预算。**v4.6 V2 就绪投递优先**：先清点本阶段「脚本/PoC/参数字典已就绪而未投递」的待验证项（含子任务与待利用队列），立即批量投递消耗就绪资产——不要把预算留给泛化收口。随后：多目标项目把未覆盖目标补到最小覆盖（每目标每类 1 探针）；再进入收口流程：1) 已确证未入库的结论补录 record_finding / update_coverage；2) 规划并撰写本阶段交付物（write_file），无法覆盖的目标列入「待续清单」；3) 调用 complete_stage 收口——s4/s5 必须在调用参数中携带顶层字段 ready_but_unexecuted 与 l2_approved_unused（JSON 数组，无内容传空数组 []；不要只写进 summary 文本，也不要写进交付物文件）。"
			if vts, verr := o.store.ListVTs(p.ID); verr == nil && len(vts) > 0 {
				lines := []string{}
				// v5.3.9 批次④：P1 保底——冲刺枚举按 Priority 升序（1=最高）排序，
				// 高优先级 VT 不再受 store 返回序影响被泛化收口挤掉。
				sortedVTs := append([]*store.VerificationTask(nil), vts...)
				sort.Slice(sortedVTs, func(i, j int) bool {
					if sortedVTs[i].Priority != sortedVTs[j].Priority {
						return sortedVTs[i].Priority < sortedVTs[j].Priority
					}
					return sortedVTs[i].ID < sortedVTs[j].ID
				})
				p1Count := 0
				for _, t := range sortedVTs {
					if t.Status != "ready" && t.Status != "pending" {
						continue
					}
					if t.Priority <= 1 {
						p1Count++
					}
					tag := "P" + strconv.Itoa(t.Priority)
					lines = append(lines, fmt.Sprintf("- %s[%s/%s] %s（就绪资产: %s）", t.ID, t.Status, tag, truncateText(t.Title, 50), truncateText(t.ReadyAssets, 60)))
				}
				if len(lines) > 0 {
					sprintMsg += "\n\n🧾 验证队列待消耗（引擎枚举，按 Priority 升序投递）：\n" + strings.Join(lines, "\n")
					if p1Count > 0 {
						sprintMsg += fmt.Sprintf("\n\n🛡️ P1 保底：检测到 %d 个 P1 级 VT——剩余 1/3 轮次内 P1 优先消费，禁止被泛化收口挤掉；确实无法投递的 P1 必须进 ready_but_unexecuted 由后续阶段承接。", p1Count)
					}
				}
			}
			msgs = append(msgs, llm.Message{Role: "user", Content: sprintMsg})
			o.log(p, stageID, "⏳ 迭代预算预警（剩约 1/3），已注入收口开始提醒（目标感知版）")
		} else if remain == 2 {
			msgs = append(msgs, llm.Message{Role: "user", Content: "⛔ 最终收口指令：本阶段只剩最后 3 轮，禁止再发起任何新测试（不再调用 run_command 扫描/探测）。现在立即：1) 用 write_file 把本阶段结论写成交付物（未完成项列入「待续清单」）；2) 调用 complete_stage 收口（s4/s5 携带顶层字段 ready_but_unexecuted / l2_approved_unused，无内容传空数组 []）。若反思门拦截，按意见最小修补后立即重提，不要开新工作。"})
			o.log(p, stageID, "⛔ 最终收口指令已注入（剩 3 轮）")
		}
		// v2.7 A8：供应商风控/拒绝(4xx)自动切换备用模型（接管模型锁定至项目结束）
		resp, usage, err := o.chatFailover(ctx, p, stageID, msgs, toolDefs)
		if err != nil {
			// v3.2.0 修复：熔断（Kill）触发的 ctx 取消曾把阶段误记为 failed——
			// 汇总层据此把整个项目判为 failed，与 Kill 落盘的 killed 终态互相矛盾。
			// 现按取消来源如实记录：项目熔断 → killed，真实 LLM 故障 → failed。
			if ctx.Err() != nil {
				state.Status = "killed"
				state.Summary = "项目已熔断（一键熔断/外部中止）"
				_ = o.store.SaveProject(p)
				return ctx.Err()
			}
			state.Status = "failed"
			state.Summary = "LLM 调用失败: " + err.Error()
			_ = o.store.SaveProject(p)
			o.log(p, stageID, "LLM 调用失败: "+err.Error())
			log.Printf("[stage %s] LLM 调用失败: %v", stageID, err) // stdout 留痕（docker logs 可查）
			return err
		}
		o.accountUsage(p, stageID, usage)
		if len(resp.ToolCalls) == 0 {
			// 纯文本思考：作为对话消息实时推送并落库（刷新后可回填）
			if strings.TrimSpace(resp.Content) != "" {
				o.streamMsg(p.ID, stageID, resp.Content)
			}
			msgs = append(msgs, resp)
			msgs = append(msgs, llm.Message{
				Role:    "user",
				Content: "请通过工具执行动作；本阶段完成后必须调用 complete_stage 收口。",
			})
			continue
		}
		msgs = append(msgs, resp)
		if strings.TrimSpace(resp.Content) != "" {
			o.streamMsg(p.ID, stageID, resp.Content) // 随工具调用一并输出的说明文本
		}
		finished := false
		// v2.6：同一轮多个相互独立的工具并发执行（速度纪律引擎保证）；
		// complete_stage/loopback/plan_subtasks 等改变执行流状态的工具强制走串行路径
		results := make([]string, len(resp.ToolCalls))
		parallel := o.cfg.Engine.ParallelDispatch() && len(resp.ToolCalls) > 1
		if parallel {
			for _, tc := range resp.ToolCalls {
				if !parallelizableTool[tc.Name] {
					parallel = false
					break
				}
			}
		}
		if parallel {
			var wg sync.WaitGroup
			for i, tc := range resp.ToolCalls {
				wg.Add(1)
				go func(i int, tc llm.ToolCall) {
					defer wg.Done()
					results[i] = o.dispatch(ctx, p, stageID, tc)
				}(i, tc)
			}
			wg.Wait()
		} else {
			for i, tc := range resp.ToolCalls {
				results[i] = o.dispatch(ctx, p, stageID, tc)
			}
		}
		for i, tc := range resp.ToolCalls {
			results[i] = o.monitorCheck(ctx, p, stageID, mon, tc, results[i]) // 重复调用→导师评审（execMonitor 非并发安全，顺序补跑）
			o.streamTool(p.ID, stageID, tc, results[i])                       // 工具调用留痕 + 实时推送
			msgs = append(msgs, llm.Message{Role: "tool", ToolCallID: tc.ID, Content: results[i]})
			// 仅当收口真正通过反思门放行（返回「阶段已收口」前缀）才结束阶段；
			// 被拦截/缺交付物时继续循环，让模型补齐后重提。
			// v5.1.2 P0 修复：s3 收口附 R7 对抗假设注记时返回「阶段已收口\n\n+注」，
			// 精确相等永不匹配 → 阶段永不结束 → 反复重跑对抗 pass 烧尽预算并覆盖摘要（必现 bug）。
			if tc.Name == "complete_stage" && strings.HasPrefix(results[i], "阶段已收口") {
				finished = true
			}
		}
		if injectedN > 0 {
			// v2.6 指令回执闭环：注入指令的本轮工具已执行完毕，向工作台反馈（PentAGI 指令-效果可追踪）
			o.log(p, stageID, fmt.Sprintf("🧑‍✈️ 指挥室指令已在本轮（第 %d 轮）执行完毕，后续轮次持续生效", iter+1))
		}
		if finished {
			o.log(p, stageID, fmt.Sprintf("■ 阶段[%s]完成，共 %d 轮", stageID, iter+1))
			return nil
		}
	}
	// v4.9 F2：迭代轮次耗尽 → 预算护栏自动代收口（原为硬中止）。
	// 实证：硬中止形成「停跑→手动重跑→再撞墙」死循环（兰州项目 s4 六连败共烧 ~3490 万 tokens），
	// 且收口门（V3/子代理/反思）在最后 1 轮拦截后无轮次再提交=结构性死锁。
	// 现改为：等待收割在途子代理 → 按 VT 台账代填 V3 清单 → 阶段 done+quality-pending，流水线继续
	//（S8 收口门强制复核，不无声放行；如需深化仍可手动重跑本阶段）。
	if ctx.Err() != nil {
		state.Status = "killed"
		_ = o.store.SaveProject(p)
		return ctx.Err()
	}
	if n := o.runningSubAgents(p.ID); n > 0 {
		o.log(p, stageID, fmt.Sprintf("🧹 预算护栏代收口：%d 个子代理仍在运行，最多等待 90s 收割产出", n))
		harvestDeadline := time.Now().Add(90 * time.Second)
		for o.runningSubAgents(p.ID) > 0 && time.Now().Before(harvestDeadline) && ctx.Err() == nil {
			select {
			case <-ctx.Done():
			case <-time.After(3 * time.Second):
			}
		}
		if n := o.runningSubAgents(p.ID); n > 0 {
			o.log(p, stageID, fmt.Sprintf("⚠ 预算护栏代收口：%d 个子代理超时未结束，按放弃处理（已入库产出保留，未竟项移交后续阶段承接）", n))
		}
	}
	if ctx.Err() != nil {
		state.Status = "killed"
		_ = o.store.SaveProject(p)
		return ctx.Err()
	}
	harvestedJobs := o.harvestAsyncOutputs(p, stageID) // v5.4.3 A：先收割后台作业结论（落证据链）
	readyItems, l2Items := o.harvestV3Lists(p, stageID, harvestedJobs)
	for _, pair := range []struct {
		field string
		items []string
	}{{"ready_but_unexecuted", readyItems}, {"l2_approved_unused", l2Items}} {
		if len(pair.items) > 0 {
			_, _ = o.store.AddTimeline(&store.TimelineEvent{ProjectID: p.ID, Stage: stageID,
				Event: "v4.6 V3 清单（护栏代填）", Detail: pair.field + ": " + strings.Join(pair.items, " | ")})
		}
	}
	// v5.5.0（修复方案 E）：预算耗尽不再一律把未完成阶段装作 done——默认 pause：
	// 阶段置 paused+项目暂停，人工提升预算/手动重跑后从断点继续（auto_close 档保留 v4.9 代收口旧行为）。
	// 代收口曾造成"未完成的 S4 被流水线继续推进"的结构性能力损失：后续阶段基于半成品交付物工作。
	if o.cfg.Engine.BudgetExhaustedPolicy != "auto_close" {
		state.Status = "paused"
		state.PauseReason = "token/迭代预算耗尽（可提升 max_stage_iterations 或项目 budget_tokens 后重跑续接）"
		state.EndedAt = time.Now().Format(time.RFC3339)
		if len(readyItems) > 0 || len(l2Items) > 0 {
			state.Summary = fmt.Sprintf("迭代轮次耗尽，阶段暂停（paused）等待续跑：已收割在途产出（就绪未投递 %d 项、已批未用 %d 项已登记台账），未完成部分不标记完成", len(readyItems), len(l2Items))
		} else {
			state.Summary = "迭代轮次耗尽，阶段暂停（paused）等待续跑：本阶段未收口，不标记完成"
		}
		state.Review = ""
		_ = o.store.SaveProject(p)
		o.log(p, stageID, "⏸ 迭代轮次耗尽，阶段置为 paused（修复方案 E：未完成不装作完成）——提升 max_stage_iterations/budget 后在「阶段流水线」重跑该阶段即可从断点继续")
		return nil
	}
	state.Status = "done"
	state.EndedAt = time.Now().Format(time.RFC3339)
	// v5.1.3 修复①b：代收口路径确定性门照跑（机械检查不需要 LLM）——拦截项转记 Review
	// 与时间线，供 S8 复核门逐项处理（此前代收口静默跳过全部门）。
	gateIssues := o.deterministicGate(p, stageID)
	if len(readyItems) > 0 || len(l2Items) > 0 {
		state.Summary = fmt.Sprintf("迭代轮次耗尽（原「预算耗尽」），预算护栏代收口：V3 清单已按台账代填（就绪未投递 %d 项、已批未用 %d 项）", len(readyItems), len(l2Items))
	} else {
		state.Summary = "迭代轮次耗尽（原「预算耗尽」），预算护栏代收口：台账盘点无遗留就绪未投递项"
	}
	if len(gateIssues) > 0 {
		state.Review = fmt.Sprintf("预算护栏代收口【quality-pending：确定性门拦截 %d 项——S8 收口前逐项复核】", len(gateIssues))
		for _, gi := range gateIssues {
			_, _ = o.store.AddTimeline(&store.TimelineEvent{ProjectID: p.ID, Stage: stageID,
				Event: "v5.1.3 代收口确定性门拦截项（S8 复核清单）", Detail: gi})
		}
	} else {
		state.Review = "预算护栏代收口【quality-pending：S8 收口前须复核本阶段交付物与代填清单；确定性门已通过】"
	}
	_ = o.store.SaveProject(p)
	o.log(p, stageID, "⚠ 迭代轮次耗尽，预算护栏已代收口（阶段 done+quality-pending，流水线继续；如需深化可手动重跑本阶段）")
	return nil
}

// ---------- v4.9 F1/F2：V3 清单解析与护栏代收口 ----------

// ---------- v5.4.3 A：收口执行闭环（通用机制，与漏洞类型/作业内容无关） ----------
// 失效模式：run_async 作业若执行主体未主动 poll，其结论在收口后即从结构化状态消失——
// 「启动→完成→消费」闭环缺最后一环（实证：某判别作业 finished 落盘，收口台账误标 ready_but_unexecuted）。
// 机制：收口前扫描 .async/ 状态侧车，已完成且结论未进证据链的作业 → 输出尾部自动落证据+时间线；
// V3 台账/清单生成时按作业实际状态校正"就绪未投递"标记。不读作业内容做语义判断。

// asyncJobRec 后台作业收割档案（来自 .async/ 状态侧车，字段与 tools.asyncSidecar 对齐）。
type asyncJobRec struct {
	ID      string
	Command string
	State   string
	Log     string
}

// harvestAsyncOutputs 收口前收割后台作业结论：state ∈ {finished, failed} 且证据链中无该
// job ID 引用（未被 poll_async 消费）的作业 → 输出尾部落证据+时间线。返回本轮收割清单。
func (o *Orchestrator) harvestAsyncOutputs(p *store.Project, stageID string) []asyncJobRec {
	dir := filepath.Join(o.workspaceRoot(p.ID), ".async")
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	evs, _ := o.store.ListEvidence(p.ID)
	consumed := func(jobID string) bool {
		for _, e := range evs {
			if strings.Contains(e.Input, jobID) || strings.Contains(e.Output, jobID) {
				return true // 已被 poll_async 消费（结论已进执行流）
			}
		}
		return false
	}
	var out []asyncJobRec
	for _, ent := range entries {
		if ent.IsDir() || !strings.HasPrefix(ent.Name(), "job-") || !strings.HasSuffix(ent.Name(), ".json") {
			continue
		}
		raw, rerr := os.ReadFile(filepath.Join(dir, ent.Name()))
		if rerr != nil {
			continue
		}
		var sc struct {
			ID      string `json:"id"`
			Command string `json:"command"`
			State   string `json:"state"`
			Log     string `json:"log"`
		}
		if json.Unmarshal(raw, &sc) != nil || sc.ID == "" {
			continue
		}
		if sc.State != "finished" && sc.State != "failed" {
			continue // 在途作业不收割（s7 E2 终态标记门另有兜底）
		}
		if consumed(sc.ID) {
			continue
		}
		tail := ""
		if sc.Log != "" {
			rawLog, lerr := os.ReadFile(filepath.Join(o.workspaceRoot(p.ID), sc.Log))
			if lerr == nil {
				tail = tailRawBytes(rawLog, 1200)
			}
		}
		_, _ = o.store.AddEvidence(&store.EvidenceRecord{ProjectID: p.ID, Stage: stageID,
			Type: "async", Input: "[async-harvest] " + truncateText(sc.Command, 200),
			Output: "[收口收割 v5.4.3] job=" + sc.ID + " state=" + sc.State + " log=" + sc.Log + "\n" + tail, ApprovedBy: "auto"})
		_, _ = o.store.AddTimeline(&store.TimelineEvent{ProjectID: p.ID, Stage: stageID,
			Event: "后台作业结论收割", Detail: fmt.Sprintf("job=%s state=%s cmd=%s", sc.ID, sc.State, truncateText(sc.Command, 80))})
		o.log(p, stageID, fmt.Sprintf("🧹 收口收割：后台作业 %s（%s）结论已落证据链（此前仅存 .async/ 侧车）", sc.ID, sc.State))
		out = append(out, asyncJobRec{ID: sc.ID, Command: sc.Command, State: sc.State, Log: sc.Log})
	}
	return out
}

// tailRawBytes 取原始日志尾部 n 字节（行边界对齐，engine 侧通用实现）。
func tailRawBytes(raw []byte, n int) string {
	if len(raw) <= n {
		return string(raw)
	}
	s := string(raw[len(raw)-n:])
	if i := strings.IndexByte(s, '\n'); i >= 0 && i < len(s)-1 {
		s = s[i+1:]
	}
	return s
}

// v3AssetRe V3 条目中脚本类资产路径 token（扩展名锚定，不假设用途）。
var v3AssetRe = regexp.MustCompile(`[\w./-]+\.(?:sh|py|js|rb|pl|ps1)`)

// v3ItemExecutedCheck V3 条目引用的资产是否出现在收割作业的命令中（basename 包含判定）。
// 匹配即说明该"就绪未投递"项实际已通过后台作业执行——台账与事实的偏差在此校正。
func v3ItemExecutedCheck(item string, jobs []asyncJobRec) (asyncJobRec, bool) {
	for _, tok := range v3AssetRe.FindAllString(item, -1) {
		base := filepath.Base(tok)
		if len(base) < 8 {
			continue // 过短 token 误配防护
		}
		for _, j := range jobs {
			if strings.Contains(j.Command, base) {
				return j, true
			}
		}
	}
	return asyncJobRec{}, false
}

// harvestV3Lists 预算护栏代收口时按台账代填 V3 两清单：
// ready_but_unexecuted = 本阶段 VT 验证队列中 pending/ready（尚未投递执行）条目；
// l2_approved_unused 不代填（审批请求与执行在调用路径上配对发生，引擎无法机械判定「未使用」），
// 留空并在阶段摘要/quality-pending 中交给 S8 复核。
// v5.4.3 A：jobs 非空时逐条核对——VT 就绪资产已被后台作业实际执行的，不再计入"就绪未投递"。
func (o *Orchestrator) harvestV3Lists(p *store.Project, stageID string, jobs []asyncJobRec) (ready []string, l2 []string) {
	if stageID != "s4" && stageID != "s5" {
		return nil, nil
	}
	vts, err := o.store.ListVTs(p.ID)
	if err != nil {
		return nil, nil
	}
	for _, t := range vts {
		if t.Stage != stageID {
			continue
		}
		if t.Status != "ready" && t.Status != "pending" {
			continue
		}
		if _, ok := v3ItemExecutedCheck(t.Title+" "+t.ReadyAssets, jobs); ok {
			o.log(p, stageID, fmt.Sprintf("↳ v5.4.3 校正：VT %s 的就绪资产已由后台作业实际执行，不入「就绪未投递」清单", t.ID))
			continue
		}
		line := fmt.Sprintf("%s[%s] %s", t.ID, t.Status, truncateText(t.Title, 60))
		if strings.TrimSpace(t.ReadyAssets) != "" {
			line += "（就绪资产: " + truncateText(t.ReadyAssets, 60) + "）"
		}
		ready = append(ready, line)
	}
	return ready, nil
}

// v3StringsFromArg 从 complete_stage 顶层参数提取 V3 清单：接受 JSON 数组（[]any），
// 元素取字符串（非字符串转字符串表示），空白条目丢弃；key 不存在或类型不是数组 → ok=false。
func v3StringsFromArg(v any) ([]string, bool) {
	arr, ok := v.([]any)
	if !ok {
		return nil, false
	}
	items := make([]string, 0, len(arr))
	for _, it := range arr {
		var is string
		if s, ok2 := it.(string); ok2 {
			is = s
		} else {
			is = fmt.Sprint(it)
		}
		if strings.TrimSpace(is) != "" {
			items = append(items, truncateText(is, 300))
		}
		if len(items) >= 100 {
			break
		}
	}
	return items, true
}

// parseV3ListFromText 从 summary 文本按约定字面格式解析 V3 清单（v4.9 F1 回退通道）。
// 主形态：`<field>` + 可选空白 + [:=：] + 可选空白 + `[...]`（配对中括号）；
// 宽松形态：field 后 16 字符内出现 `[`（覆盖「为空数组 []」类中文连接）。
// 括号内容为空 → 空清单；内容优先按 JSON 数组解析，失败再按分隔符宽松切分。
// 实证形态：`ready_but_unexecuted: []（本轮已全部投递）`、`ready_but_unexecuted=["VT-…","VT-…"]`。
func parseV3ListFromText(text, field string) ([]string, bool) {
	if strings.TrimSpace(text) == "" {
		return nil, false
	}
	for idx := 0; ; {
		i := strings.Index(text[idx:], field)
		if i < 0 {
			return nil, false
		}
		start := idx + i + len(field)
		// 主形态
		j := start
		for j < len(text) && (text[j] == ' ' || text[j] == '\t' || text[j] == '\n' || text[j] == '\r') {
			j++
		}
		if j < len(text) && (text[j] == ':' || text[j] == '=' || strings.HasPrefix(text[j:], "：")) {
			j++
			for j < len(text) && (text[j] == ' ' || text[j] == '\t') {
				j++
			}
			if j < len(text) && text[j] == '[' {
				if items, ok := parseBracketedList(text, j); ok {
					return items, true
				}
			}
		}
		// 宽松形态
		if k := strings.Index(text[start:min(start+16, len(text))], "["); k >= 0 {
			if items, ok := parseBracketedList(text, start+k); ok {
				return items, true
			}
		}
		idx = start
		if idx >= len(text) {
			return nil, false
		}
	}
}

// parseBracketedList 从 text[at]=='[' 起提取配对中括号内容并解析为字符串清单（上限 100 条）。
func parseBracketedList(text string, at int) ([]string, bool) {
	if at >= len(text) || text[at] != '[' {
		return nil, false
	}
	depth, end := 0, -1
	for i := at; i < len(text) && i < at+4096; i++ {
		switch text[i] {
		case '[':
			depth++
		case ']':
			depth--
			if depth == 0 {
				end = i
			}
		}
		if end >= 0 {
			break
		}
	}
	if end < 0 {
		return nil, false
	}
	inner := strings.TrimSpace(text[at+1 : end])
	if inner == "" {
		return []string{}, true
	}
	var arr []string
	if err := json.Unmarshal([]byte(inner), &arr); err == nil {
		out := make([]string, 0, len(arr))
		for _, it := range arr {
			if strings.TrimSpace(it) != "" {
				out = append(out, truncateText(it, 300))
			}
			if len(out) >= 100 {
				break
			}
		}
		return out, true
	}
	// 宽松切分：中英文逗号/顿号/分号，剥离转义引号与包裹引号
	parts := strings.FieldsFunc(inner, func(r rune) bool {
		return r == ',' || r == '、' || r == ';' || r == '；' || r == '，'
	})
	out := make([]string, 0, len(parts))
	for _, pt := range parts {
		pt = strings.TrimSpace(pt)
		pt = strings.ReplaceAll(pt, "\\\"", "")
		pt = strings.Trim(pt, "\"'“”")
		if pt != "" {
			out = append(out, truncateText(pt, 300))
		}
		if len(out) >= 100 {
			break
		}
	}
	return out, true
}

// ---------- 工具分发 ----------

// v4.6 E1 断言模式：否定性/排他性断言（审计 11 例误判的共性——结论强于所引证据）
var negativeAssertRe = regexp.MustCompile(
	`(空文件|jar\s*为空|为空|无\s*cookie|未暴露|被拒|协议版本|0\s*命中|全部.{0,6}0{2,}|不依赖|不存在|无差异|同文案|无枚举信号|未捕获|全部.{0,8}(响应|数据|端点))`)

// v4.6 E1 置信度矛盾模式：「确证」与未完成验证表述同文（sendSMS 案：零次成功请求标确证，
// 原话「服务端是否校验待 S4 单请求验证」——模式需覆盖"待…验证"中插形态）
var pendingAssertRe = regexp.MustCompile(`(待.{0,10}验证|未实测|待实测|待确认|尚未验证|未执行验证)`)

// v4.6 B4 报告/发现中 evidence 路径提取（离线门同口径，含 ~ 范围与通配）
var evidencePathRe = regexp.MustCompile(`evidence/[A-Za-z0-9_\-./~*]+`)

func (o *Orchestrator) dispatch(ctx context.Context, p *store.Project, stageID string, tc llm.ToolCall) string {
	var args map[string]any
	if err := json.Unmarshal([]byte(tc.Arguments), &args); err != nil {
		return "错误: 工具参数不是合法 JSON: " + err.Error()
	}
	s := func(k string) string { v, _ := args[k].(string); return v }

	switch tc.Name {
	case "run_command":
		return o.toolRunCommand(ctx, p, stageID, s("command"), s("reason"))
	case "run_async": // v2.6：长任务后台执行（不阻塞执行循环），审批/留证与 run_command 同级
		return o.toolRunAsync(ctx, p, stageID, s("command"), s("reason"), s("timeout"))
	case "poll_async": // v2.6：后台任务状态与输出尾部
		return o.toolPollAsync(p, stageID, s("job"))
	case "write_file":
		path, content := s("path"), s("content")
		if strings.TrimSpace(content) == "" {
			return "错误: content 为空"
		}
		full, err := o.exec.WriteFile(p.ID, path, content)
		if err != nil {
			return "错误: " + err.Error()
		}
		_, _ = o.store.AddEvidence(&store.EvidenceRecord{ProjectID: p.ID, Stage: stageID, Type: "file", Input: "写入 " + path, Output: truncateText(content, 400), ApprovedBy: "auto"})
		o.log(p, stageID, "✎ 写入文件 "+path)
		return "已写入: " + full
	case "read_file":
		content, err := o.exec.ReadFile(p.ID, s("path"))
		if err != nil {
			return "错误: " + err.Error()
		}
		return content
	case "list_files": // 交付物承接：下一阶段从文件中索取上一阶段产出，防幻觉
		root := s("dir")
		files, err := o.listWorkspaceFiles(p.ID, root)
		if err != nil {
			return "错误: " + err.Error()
		}
		if len(files) == 0 {
			return "工作区暂无文件。"
		}
		var b strings.Builder
		b.WriteString(fmt.Sprintf("工作区文件 %d 个（用 read_file 读取内容）：\n", len(files)))
		for _, f := range files {
			b.WriteString(fmt.Sprintf("- %s (%s)\n", f.Path, humanSize(f.Size)))
		}
		return b.String()
	case "record_finding":
		// v4.6 E1 结论-证据硬校验（三件套）——审计 11 例误判的入口拦截：
		// ①claims 判据串逐条命中（file 存在且含 must_contain）；
		// ②否定性断言（空/无/未暴露/被拒/0命中/全部000/不依赖…）必须带 claims，否则拒绝；
		// ③"确证"与"待验证/未实测"同文 → 拒绝（置信度与内容矛盾）。
		// ④E4 可利用性双维：exploitability=untested 的高危自动降级中级（F2320 双轨口径固化）。
		// ⑤B1 同根因判重在 store.AddFinding 内（归一化标题全等 → 拒绝）。
		title0, detail0 := s("title"), s("detail")
		conf0 := s("confidence")
		var claims []store.FindingClaim
		if rawClaims, ok := args["claims"].([]any); ok {
			for i, rc := range rawClaims {
				cm, _ := rc.(map[string]any)
				cf, _ := cm["file"].(string)
				cmcc, _ := cm["must_contain"].(string)
				if strings.TrimSpace(cf) == "" || strings.TrimSpace(cmcc) == "" {
					return fmt.Sprintf("错误: claims[%d] 缺 file 或 must_contain——判据串格式 {\"file\":\"evidence/…\",\"must_contain\":\"…\"}", i)
				}
				content, rerr := o.exec.ReadFile(p.ID, cf)
				if rerr != nil {
					return fmt.Sprintf("错误: claims[%d] 引用文件不存在或不可读（%s）——先落盘证据再登记发现", i, cf)
				}
				if !strings.Contains(content, cmcc) {
					return fmt.Sprintf("错误: claims[%d] 判据串未命中：文件 %s 中找不到 %q——断言与证据不符，核对原文或改写断言", i, cf, truncateText(cmcc, 40))
				}
				claims = append(claims, store.FindingClaim{File: cf, MustContain: cmcc})
			}
		}
		if conf0 == "确证" {
			if negativeAssertRe.MatchString(title0+detail0) && len(claims) == 0 {
				return "错误: 否定性/排他性断言（空、无、未暴露、被拒、0命中、全部000、不依赖、不存在、无差异、同文案等）置信度为确证时必须提供 claims 判据串（逐条 file+must_contain，且判据串已在证据文件中核实命中）——审计实证「空 jar」「未暴露」类断言可被自家证据反驳。或把置信度降为疑似。"
			}
			if pendingAssertRe.MatchString(title0 + detail0) {
				return "错误: 置信度「确证」与内容矛盾——detail/title 含「待验证/待实测/未实测/待确认」类表述（实测 sendSMS 案：零次成功请求仍标确证入库）。先完成验证再标确证，或改标疑似/待查。"
			}
		}
		// v4.4 批次4：access/impact_rank 可选标注（S5 待利用队列消费依据，见 s4-7/s5-1 头纪律）
		access := s("access")
		if access != "" && access != "anonymous" && access != "pre-auth" && access != "post-auth" {
			access = ""
		}
		rank := 0
		if n, err := strconv.Atoi(strings.TrimSpace(s("impact_rank"))); err == nil && n >= 1 && n <= 6 {
			rank = n
		}
		f := &store.Finding{
			ProjectID: p.ID, Stage: stageID,
			Title: title0, Severity: s("severity"), Detail: detail0, Confidence: conf0,
			CWE:    s("cwe"), // v2.7 A4：标准编号（CWE-89/CWE-79…），以检索/知识为准，不确定留空
			Access: access, ImpactRank: rank,
			Exploitability: s("exploitability"), Claims: claims, // v4.6 E1/E4
		}
		if f.Exploitability != "" && f.Exploitability != "verified" && f.Exploitability != "conditional" && f.Exploitability != "untested" {
			f.Exploitability = ""
		}
		if f.Severity == "" {
			f.Severity = "信息"
		}
		sevDowngraded := ""
		if f.Severity == "高" && f.Exploitability == "untested" {
			f.Severity = "中" // v4.6 E4：未实测可利用性的高危自动降级（报告按条件性上限分双轨呈现）
			sevDowngraded = "；原定级「高」因 exploitability=untested 自动降为「中」（补实测后在 update_finding 回写）"
		}
		// v5.3.6：evidence_ids 参数废弃——模型无渠道获知引擎内部证据编号，显式提供必然杜撰
		// （实证：某 v5.3.4 后项目 10 条 finding 12 个引用 100% 悬空），一律自动关联本阶段最近真实证据。
		// 展示层证据由 POC 自包含承载（poc 参数，Burp 式请求/响应对）+ Web 层证据回填。
		f.EvidenceIDs = o.store.LastEvidenceIDs(p.ID, stageID, 5)
		// v5.3.6：POC 接收（≤5 组，单侧 ≤16KB 截断；request/response 均必填非空——Burp 式原始文本对）
		if rawPOC, ok := args["poc"].([]any); ok && len(rawPOC) > 0 {
			if len(rawPOC) > 5 {
				return "错误: poc 最多 5 组请求/响应对——超出部分并入 detail 描述或拆分登记"
			}
			for i, it := range rawPOC {
				m, _ := it.(map[string]any)
				if m == nil {
					return fmt.Sprintf("错误: poc[%d] 格式非法——应为 {\"request\":\"原始 HTTP 请求文本\",\"response\":\"原始响应文本\"}", i)
				}
				req, _ := m["request"].(string)
				resp, _ := m["response"].(string)
				if strings.TrimSpace(req) == "" || strings.TrimSpace(resp) == "" {
					return fmt.Sprintf("错误: poc[%d] request 与 response 均必填非空（必须真实交互后登记；空壳 POC 无法支撑复现）", i)
				}
				f.POC = append(f.POC, store.FindingPOC{Request: truncateText(req, 16384), Response: truncateText(resp, 16384)})
			}
		}
		// v5.3.6：修复建议（LLM 提供；空则 UI 显示「未填写」降级）
		f.Remediation = truncateText(s("remediation"), 8000)
		id, err := o.store.AddFinding(f)
		if err != nil {
			return "错误: " + err.Error()
		}
		o.bus.Publish(p.ID, "finding", f)
		o.log(p, stageID, fmt.Sprintf("🔥 新漏洞[%s] %s", f.Severity, f.Title))
		_, _ = o.store.AddTimeline(&store.TimelineEvent{ProjectID: p.ID, Stage: stageID, Event: "漏洞收录", Detail: f.Title})
		queueNote := ""
		if rank > 0 || access != "" {
			queueNote = fmt.Sprintf("（队列标注 access=%s impact_rank=%d）", access, rank)
		}
		claimNote := ""
		if len(claims) > 0 {
			claimNote = fmt.Sprintf("；claims 判据 %d 条已核验命中", len(claims))
		}
		return "已登记漏洞 " + id + queueNote + claimNote + sevDowngraded
	case "update_finding": // v4.6 B5 结论回写：severity/confidence/exploitability/detail 增量，强制 reason（1937 ShellInABox 降级只进增量报告未回写权威库的实证修复）
		fid := s("id")
		if fid == "" {
			return "错误: id 必填（record_finding 返回的 F- 编号）"
		}
		reason := strings.TrimSpace(s("reason"))
		if reason == "" {
			return "错误: reason 必填——每次结论修订必须留痕（修订依据/证据）"
		}
		fs, _ := o.store.ListFindings(p.ID)
		var target *store.Finding
		for _, x := range fs {
			if x.ID == fid && x.ProjectID == p.ID {
				target = x
				break
			}
		}
		if target == nil {
			return "错误: 未找到发现 " + fid
		}
		before := fmt.Sprintf("severity=%s confidence=%s exploitability=%s", target.Severity, target.Confidence, target.Exploitability)
		changed := []string{}
		if v := s("severity"); v != "" {
			target.Severity = v
			changed = append(changed, "severity→"+v)
		}
		if v := s("confidence"); v != "" {
			target.Confidence = v
			changed = append(changed, "confidence→"+v)
		}
		if v := s("exploitability"); v != "" {
			if v != "verified" && v != "conditional" && v != "untested" {
				return "错误: exploitability 仅允许 verified/conditional/untested"
			}
			target.Exploitability = v
			changed = append(changed, "exploitability→"+v)
		}
		if v := s("detail_append"); v != "" {
			target.Detail += "\n【修订 v4.6】" + v
			changed = append(changed, "detail+append")
		}
		// v5.3.7：remediation 补写/修订（s8 报告与 Web 漏洞页同源字段）——空缺时补写，已有则追加
		if v := s("remediation"); v != "" {
			if strings.TrimSpace(target.Remediation) == "" {
				target.Remediation = truncateText(v, 8000)
				changed = append(changed, "remediation 补写")
			} else {
				target.Remediation = truncateText(target.Remediation+"\n【修订】"+v, 8000)
				changed = append(changed, "remediation+append")
			}
		}
		if len(changed) == 0 {
			return "错误: 未提供任何变更字段（severity/confidence/exploitability/detail_append/remediation）"
		}
		if err := o.store.UpdateFinding(target); err != nil {
			return "错误: " + err.Error()
		}
		o.log(p, stageID, fmt.Sprintf("✏ 发现修订 %s: %s", fid, strings.Join(changed, ",")))
		_, _ = o.store.AddTimeline(&store.TimelineEvent{ProjectID: p.ID, Stage: stageID,
			Event: "发现修订", Detail: fid + " " + strings.Join(changed, ",") + "（" + before + "）依据: " + truncateText(reason, 120)})
		return "已修订 " + fid + "（" + strings.Join(changed, ",") + "）并留痕时间线"
	case "record_vt": // v4.6 A2 验证队列：登记待验证项（就绪资产/启动条件/成本/优先级）
		vt := &store.VerificationTask{
			ProjectID: p.ID, Stage: stageID,
			Title: s("title"), ReadyAssets: s("ready_assets"), StartConditions: s("start_conditions"),
			CostNote: s("cost_note"), Status: s("status"),
		}
		if strings.TrimSpace(vt.Title) == "" {
			return "错误: title 必填（验证目标一句话）"
		}
		if vt.Status != "" && vt.Status != "pending" && vt.Status != "ready" {
			return "错误: 初始 status 仅允许 pending/ready（已执行/处置用 update_vt）"
		}
		if n, err := strconv.Atoi(strings.TrimSpace(s("priority"))); err == nil && n >= 1 && n <= 6 {
			vt.Priority = n
		}
		id, verr := o.store.AddVT(vt)
		if verr != nil {
			return "错误: " + verr.Error()
		}
		o.log(p, stageID, fmt.Sprintf("🧾 VT 登记[%s] %s", vt.Status, vt.Title))
		return "已登记验证任务 " + id + "（status=" + vt.Status + "；S7 收口前须三选一处置：executed/closed-roe/deferred）"
	case "update_vt": // v4.6 A2：VT 流转（executed / closed-roe / deferred），closed-roe 与 deferred 强制理由
		vid := s("id")
		if vid == "" {
			return "错误: id 必填（record_vt 返回的 VT- 编号）"
		}
		vts, _ := o.store.ListVTs(p.ID)
		var target *store.VerificationTask
		for _, x := range vts {
			if x.ID == vid && x.ProjectID == p.ID {
				target = x
				break
			}
		}
		if target == nil {
			return "错误: 未找到验证任务 " + vid
		}
		st := s("status")
		if st != "executed" && st != "closed-roe" && st != "deferred" {
			return "错误: status 仅允许 executed（已执行附 result_ref）/ closed-roe（范围外附理由）/ deferred（移交附三要素）"
		}
		reason := strings.TrimSpace(s("note"))
		if (st == "closed-roe" || st == "deferred") && reason == "" {
			return "错误: closed-roe / deferred 必须附 note 处置理由（deferred 还须在 result_ref 写移交位置与启动条件/步骤/工作量三要素）"
		}
		// v5.6.1（审计缺陷#2）：executed 必须附 result_ref（结果/证据位置）——处置≠空口声称执行
		if st == "executed" && strings.TrimSpace(s("result_ref")) == "" {
			return "错误: executed 必须附 result_ref（结果/证据位置，如 evidence/<stage>/xxx 或交付物路径）——无证据的处置不闭环"
		}
		target.Status = st
		target.ResultRef = s("result_ref")
		target.Note = reason
		if err := o.store.UpdateVT(target); err != nil {
			return "错误: " + err.Error()
		}
		o.log(p, stageID, fmt.Sprintf("🧾 VT 处置 %s → %s", vid, st))
		_, _ = o.store.AddTimeline(&store.TimelineEvent{ProjectID: p.ID, Stage: stageID, Event: "VT 处置", Detail: vid + " → " + st + " " + truncateText(reason, 80)})
		return "已处置 " + vid + " → " + st
	case "record_asset":
		a := &store.Asset{ProjectID: p.ID, Stage: stageID, Type: s("type"), Value: s("value"), Detail: s("detail")}
		id, err := o.store.AddAsset(a)
		if err != nil {
			return "错误: " + err.Error()
		}
		o.bus.Publish(p.ID, "finding", a)
		return "已登记资产 " + id
	case "record_timeline":
		_, _ = o.store.AddTimeline(&store.TimelineEvent{ProjectID: p.ID, Stage: stageID, Event: s("event"), Detail: s("detail")})
		return "已记录时间线事件"
	case "load_skill": // 移植 strix load_skill：运行时注入技能剧本
		if sk := o.skills.Get(s("id")); sk != nil {
			o.log(p, stageID, "📖 载入技能: "+sk.ID)
			// v5.3.1 P0-1：production_safe 下对 Lab Only 高危技能注入禁用横幅（知识面配套强制）
			return fmt.Sprintf("【技能 %s】%s\n\n%s%s", sk.ID, sk.Title, sk.Body, o.labOnlyBanner(p, sk.ID))
		}
		if hits := o.skills.SearchCtx(s("query"), stageID, 5); len(hits) > 0 {
			var b strings.Builder
			labOnly := false
			for _, h := range hits {
				if o.skills.LabOnly(h.ID) {
					labOnly = true
				}
				// v5.6.0（审计修复：关键词截断丢尾部补遗）：头 2500 + 尾 1200——技能尾部的
				// 工具兼容/误报排除/Execution Profile 补遗与正文头部一起保留，中间段省略。
				b.WriteString(fmt.Sprintf("【技能 %s】%s\n\n%s\n\n---\n", h.ID, h.Title, headTail(h.Body, 2500, 1200)))
			}
			if labOnly {
				b.WriteString(labOnlyBannerText())
			}
			o.log(p, stageID, fmt.Sprintf("📖 技能检索命中 %d 条", len(hits)))
			return b.String()
		}
		// v5.3.2 P1-3：无直检命中时按组合选择展开配合技能（depends_on/handoff_to）
		if hits := o.skills.Bundle(s("query"), stageID, 5); len(hits) > 0 {
			var b strings.Builder
			for _, h := range hits {
				b.WriteString(fmt.Sprintf("【技能 %s】%s（组合候选）\n\n%s\n\n---\n", h.ID, h.Title, headTail(h.Body, 2000, 900)))
			}
			o.log(p, stageID, fmt.Sprintf("📖 技能组合展开 %d 条", len(hits)))
			return b.String()
		}
		return "未找到匹配技能；可用技能索引见项目上下文。"
	case "update_coverage": // 移植 strix/PentesterFlow 覆盖账本
		status := s("status")
		// v5.3.0 P1-3：状态白名单 + 旧状态确定性映射（premise_failed/patched/inconclusive
		// 不再入库——映射规则见 policies/coverage-contract.json 单一事实源）
		statusReason := ""
		switch status {
		case "vulnerable", "no_issue_found", "ruled_out", "waf_blocked", "skipped", "needs_follow_up":
			// 规范六态
		case "premise_failed":
			status, statusReason = "needs_follow_up", "precondition_missing"
		case "inconclusive":
			status, statusReason = "needs_follow_up", "inconclusive"
		case "patched":
			// 仅当 notes 含复测通过证据关键词才映射 no_issue_found（复测有效性的判定仍由 E3 门约束）
			if strings.Contains(s("notes"), "复测通过") || strings.Contains(s("notes"), "复测有效") {
				status = "no_issue_found"
			} else {
				status, statusReason = "needs_follow_up", "patch_pending_retest"
			}
		case "":
			return "错误: status 必填（规范六态：vulnerable/no_issue_found/ruled_out/waf_blocked/skipped/needs_follow_up）"
		default:
			return fmt.Sprintf("错误: 非法 coverage status %q——规范六态见 policies/coverage-contract.json；premise_failed/patched/inconclusive 会自动映射为 needs_follow_up+reason", status)
		}
		observed := s("observed_result") // v4.6 E3 负结果语义
		// E3-1：显式非法——超时/阻断/未测试类观测不得支撑真阴性终态（14A1 Druid"未暴露（超时）"实证）
		if (status == "ruled_out" || status == "no_issue_found") && observed != "" &&
			observed != "negative_valid" {
			return fmt.Sprintf("错误: observed_result=%s 不得支撑 %s 终态——超时/阻断/未测试只能落 needs_follow_up（negative_valid=有有效请求/响应原文支撑的真阴性）", observed, status)
		}
		// E3-2：缺失降级——真阴性终态未声明负结果语义 → 自动降 needs_follow_up 并提示补声明
		downgraded := ""
		if (status == "ruled_out" || status == "no_issue_found") && observed == "" {
			status = "needs_follow_up"
			downgraded = "；原状态 " + s("status") + " 因未声明 observed_result 自动降为 needs_follow_up（E3：真阴性必须显式声明 negative_valid 且 notes 附证据摘要）"
		}
		entryNotes := s("notes")
		if statusReason != "" {
			entryNotes = strings.TrimSpace("reason=" + statusReason + " | " + entryNotes)
		}
		// v5.4.3 B：台账自描述契约——结论态条目必须附一句话依据（有状态必有依据）。
		// vulnerable/ruled_out/no_issue_found/needs_follow_up 四个结论态强制；waf_blocked/skipped 过渡态豁免。
		// 与 deterministicGate 的存量空 note 检查构成"入口拒收+收口兜底"双保险。
		if (status == "vulnerable" || status == "ruled_out" || status == "no_issue_found" || status == "needs_follow_up") &&
			strings.TrimSpace(entryNotes) == "" {
			return fmt.Sprintf("错误: %s 终态必须附 notes（一句话依据：证据摘要/命令/观察结果）——台账自描述契约（v5.4.3 B）：有状态必有依据，s8 报告与跨阶段承接直接消费结构化台账。请补充 notes 后重新提交本次 update_coverage。", status)
		}
		entry, err := o.store.UpsertCoverage(&store.CoverageEntry{
			ProjectID: p.ID, Stage: stageID,
			Endpoint: s("endpoint"), Param: s("param"), VulnClass: s("vuln_class"),
			Status: status, Notes: entryNotes, ObservedResult: observed,
		})
		if err != nil {
			return "错误: " + err.Error()
		}
		// v5.1.3 修复④：覆盖矩阵同步落盘工作区 coverage.json——离线门 coverage_gate 读文件
		// 而非 DB（此前真实项目 DB-only，V8 端点表↔矩阵对账对覆盖率形态失明）。
		if entries, lerr := o.store.ListCoverage(p.ID); lerr == nil {
			if cb, merr := json.Marshal(entries); merr == nil {
				_, _ = o.exec.WriteFile(p.ID, "coverage.json", string(cb))
			}
		}
		o.log(p, stageID, fmt.Sprintf("▦ 覆盖更新: %s %s[%s] → %s", entry.Endpoint, entry.VulnClass, entry.Param, entry.Status))
		// v5.3.2 P1-5：覆盖账本落账后重排阶段子任务优先级（覆盖缺口变化 → 排序随动，id 稳定）
		if ranked := o.rerankSubtasks(p, stageID); len(ranked) > 0 {
			return fmt.Sprintf("覆盖矩阵已更新（该单元累计测试 %d 次）: %s | %s | %s → %s%s\n（本阶段 %d 项子任务优先级已按覆盖账本重排，update_subtask 列表可查新序）",
				entry.Count, entry.Endpoint, entry.VulnClass, entry.Param, entry.Status, downgraded, len(ranked))
		}
		return fmt.Sprintf("覆盖矩阵已更新（该单元累计测试 %d 次）: %s | %s | %s → %s%s", entry.Count, entry.Endpoint, entry.VulnClass, entry.Param, entry.Status, downgraded)
	case "search_memory": // 记忆检索（pentagi/VulnBot 简化版：关键词扫描）
		rawQ := strings.TrimSpace(s("query"))
		q := strings.ToLower(rawQ)
		if q == "" {
			return "错误: query 为空"
		}
		// v5.5.0（修复方案 G）：receipt:<id> 直取压缩前归档的工具回执原文（ID 大写敏感，用 rawQ）。
		if strings.HasPrefix(strings.ToLower(rawQ), "receipt:") {
			rid := strings.TrimSpace(rawQ[len("receipt:"):])
			if rid == "" {
				return "错误: receipt id 为空（用法 query=\"receipt:rpt-XXXXXXXXXX\"）"
			}
			r, rerr := o.store.GetReceipt(rid)
			if rerr != nil || r == nil {
				return "归档中无该回执（可能早于 v5.5.0 压缩或归档失败）：" + rid
			}
			if r.ProjectID != p.ID {
				return "该回执不属于本项目，拒绝读取。"
			}
			return fmt.Sprintf("📄 回执 %s（阶段 %s，归档于 %s）原文：\n%s", r.ID, r.Stage, r.CreatedAt.Format("01-02 15:04:05"), r.Content)
		}
		var out []string
		if fs, _ := o.store.ListFindings(p.ID); len(fs) > 0 {
			for _, f := range fs {
				if strings.Contains(strings.ToLower(f.Title+f.Detail), q) {
					out = append(out, fmt.Sprintf("[漏洞/%s/%s] %s：%s", f.Severity, f.Confidence, f.Title, truncateText(f.Detail, 160)))
				}
			}
		}
		if as, _ := o.store.ListAssets(p.ID); len(as) > 0 {
			for _, a := range as {
				if strings.Contains(strings.ToLower(a.Value+a.Detail+a.Type), q) {
					out = append(out, fmt.Sprintf("[资产/%s] %s（%s）", a.Type, a.Value, truncateText(a.Detail, 120)))
				}
			}
		}
		if ts, _ := o.store.ListTimeline(p.ID); len(ts) > 0 {
			for _, t := range ts {
				if strings.Contains(strings.ToLower(t.Event+t.Detail), q) {
					out = append(out, fmt.Sprintf("[时间线] %s: %s", t.Event, truncateText(t.Detail, 120)))
				}
			}
		}
		if cov, _ := o.store.ListCoverage(p.ID); len(cov) > 0 {
			for _, c := range cov {
				if strings.Contains(strings.ToLower(c.Endpoint+c.Param+c.VulnClass+c.Status+c.Notes), q) {
					out = append(out, fmt.Sprintf("[覆盖/%s] %s × %s × %s（%s）", c.Status, c.Endpoint, c.VulnClass, c.Param, truncateText(c.Notes, 100)))
				}
			}
		}
		// v3.3.0 黑板与战利品纳入检索（凭据/事实随手可查，横向复用不再靠翻交付物）
		if fs, _ := o.store.ListFacts(p.ID, 0); len(fs) > 0 {
			for _, f := range fs {
				if strings.Contains(strings.ToLower(f.Key+f.Value+f.Note+strings.Join(f.Links, " ")), q) {
					out = append(out, fmt.Sprintf("[黑板/%s] %s: %s", f.Confidence, f.Key, truncateText(f.Value, 140)))
				}
			}
		}
		if ls, _ := o.store.ListLoot(p.ID, 0); len(ls) > 0 {
			for _, l := range ls {
				if strings.Contains(strings.ToLower(l.Type+l.Target+l.Masked+l.Source), q) {
					out = append(out, fmt.Sprintf("[战利品/%s/%s] %s @ %s（来源 %s）", l.Type, l.Verified, l.Masked, l.Target, truncateText(l.Source, 80)))
				}
			}
		}
		if len(out) == 0 {
			return "记忆库无匹配。"
		}
		if len(out) > 15 {
			out = out[:15]
		}
		return "命中 " + fmt.Sprint(len(out)) + " 条:\n" + strings.Join(out, "\n")
	case "hexstrike_command": // hexstrike-ai 网关桥：调用远端 150+ 工具
		if o.hex == nil {
			return "未配置 hexstrike_url，工具桥不可用；请直接用 run_command 本机执行。"
		}
		cmd := s("command")
		// v5.3.1 P0-2：治理门统一接线——远端工具网关执行同样受执行档与范围约束（远端 150+ 工具
		// 对目标的影响与本机命令等价，不允许成为绕过面）。
		if msg := o.governanceGates(p, stageID, cmd, "hexstrike_command", false); msg != "" {
			return msg
		}
		risk := o.exec.ClassifyRisk(cmd)
		if risk == tools.Forbidden {
			return "拒绝执行：命令命中破坏性操作禁令。"
		}
		approvedBy := "auto"
		decision, err := o.approver.Request(ctx, p.ID, stageID, fmt.Sprintf("[hexstrike] 执行命令: %s\n原因: %s", cmd, s("reason")), risk)
		if err != nil {
			return "审批异常: " + err.Error()
		}
		if decision != "approved" && decision != "auto-approved" {
			return "人工审批拒绝。"
		}
		if decision == "approved" {
			approvedBy = "human"
		} else {
			approvedBy = "auto"
		}
		out, err := o.hex.Command(ctx, cmd)
		_, _ = o.store.AddEvidence(&store.EvidenceRecord{ProjectID: p.ID, Stage: stageID, Type: "hexstrike", Input: cmd, Output: truncateText(out, 2000), Risk: risk, ApprovedBy: approvedBy})
		o.log(p, stageID, "⚡ hexstrike: "+truncateText(cmd, 100))
		if err != nil {
			return "错误: " + err.Error()
		}
		return out
	case "request_approval":
		decision, err := o.approver.Request(ctx, p.ID, stageID, s("action"), "L2")
		if err != nil {
			return "审批异常: " + err.Error()
		}
		return "审批结果: " + decision
	case "complete_stage":
		// v5.3.8 死锁修复（A+B 组合）：反思门不可用期间，多个阶段会被打 quality-pending 复核标记
		// （v4.8 设计：S8 收口前须复核），但 s8 收口门的旧实现把该标记当硬拦截项，而"清除标记"
		// 没有任何工具/API 通道——模型穷尽 8 条排查路径也无法清除（实证 JT 某医院任务 msgs=210、
		// 106k tokens/请求纯空转）。修复：①deterministicGate 不再硬拒（A）；②本处改为软提示 +
		// confirm_quality_review 显式确认参数（B）——确认后清除标记并正常收口。
		if stageID == "s8" {
			confirm := false
			switch v := args["confirm_quality_review"].(type) {
			case bool:
				confirm = v
			case string:
				confirm = v == "true"
			}
			if o.applyQualityReviewConfirm(p, confirm) {
				return "检测到部分阶段带 quality-pending 复核标记（反思门不可用期间的强制复核要求）。" +
					"请先复核这些阶段的交付物与发现（无缺口即可），然后重新调用 complete_stage 并传 \"confirm_quality_review\": true——" +
					"确认后引擎将清除标记并继续正常收口（本提示只出现一次，确认后不再拦截）。"
			}
		}
		// v5.4.3 A：收口前先收割后台作业结论（落证据链+时间线）——执行闭环核对，与作业内容无关
		harvestedJobs := o.harvestAsyncOutputs(p, stageID)
		if len(harvestedJobs) > 0 {
			o.log(p, stageID, fmt.Sprintf("🧹 收口执行闭环：收割 %d 个已完成未消费的后台作业，结论已进证据链", len(harvestedJobs)))
		}
		// v4.6 V3 收口强制清单：s4/s5 必须显式提交「就绪未执行」与「已批未用」两份清单
		//（可为空数组但不可缺失）——审计实证：nbut 对 7+5 条"脚本就绪"验证线因预算收口静默蒸发，
		// L2 已批工单从未使用也无留痕。缺失即拦截，清单登记时间线供 S7 强制清点。
		// v4.9 F1 双通道提交：①complete_stage 顶层 JSON 数组参数（schema 已同步声明）；
		// ②summary 约定字面格式回退解析——实证（兰州/重庆 2026-11）93 次 s4 收口 0 次顶层传参、
		// 92 次拦截文案零变化，模型把清单写进 summary 是高频稳定行为，只堵不导=60 轮烧尽死循环。
		if stageID == "s4" || stageID == "s5" {
			summaryText := s("summary")
			v3Lists := map[string][]string{}
			missing := []string{}
			for _, field := range []string{"ready_but_unexecuted", "l2_approved_unused"} {
				if items, ok := v3StringsFromArg(args[field]); ok {
					v3Lists[field] = items
					continue
				}
				if items, ok := parseV3ListFromText(summaryText, field); ok {
					v3Lists[field] = items
					continue
				}
				missing = append(missing, field)
			}
			if len(missing) > 0 {
				return fmt.Sprintf("收口被拦截（v4.6 V3）：缺少必填清单 %s。正确提交方式（二选一）：①在 complete_stage 调用参数中新增顶层字段 %s（JSON 数组，与 summary 同级，无内容传空数组 []）；②在 summary 文本中按字面格式写一行 %s=[] 或 %s=[\"条目\"]。ready_but_unexecuted 逐条列入有就绪脚本/PoC 而未投递的待验证项（附就绪资产路径与启动条件），l2_approved_unused 列入已批准未使用的 L2 工单——两者均无内容也必须显式传空数组 []。不要把清单写进交付物文件或时间线登记，引擎只读调用参数与 summary。", strings.Join(missing, "、"), missing[0], missing[0], missing[0])
			}
			for _, field := range []string{"ready_but_unexecuted", "l2_approved_unused"} {
				if items := v3Lists[field]; len(items) > 0 {
					corrected := make([]string, 0, len(items))
					for _, it := range items {
						// v5.4.3 A：清单条目引用的资产若已被后台作业实际执行，附加校正标记
						//（叙事交付物结论与结构化台账在此对齐，防 s8 以台账为准时漏掉结论）
						if field == "ready_but_unexecuted" {
							if j, ok := v3ItemExecutedCheck(it, harvestedJobs); ok {
								it += fmt.Sprintf(" 〖v5.4.3 校正：该资产已由后台作业 %s 执行（state=%s），结论已落证据链〗", j.ID, j.State)
							}
						}
						corrected = append(corrected, it)
					}
					_, _ = o.store.AddTimeline(&store.TimelineEvent{ProjectID: p.ID, Stage: stageID,
						Event: "v4.6 V3 清单", Detail: field + ": " + strings.Join(corrected, " | ")})
				}
			}
		}
		// v3.6.0 收口前在途子代理检查：未收结果先拦（子代理发现可能尚未整合）
		if n := o.runningSubAgents(p.ID); n > 0 {
			return fmt.Sprintf("收口被拦截：仍有 %d 个子代理在运行。先 poll_subagents 收结果（或等待其结束），整合发现后再收口；确需放弃等待请先确认其发现已入库。", n)
		}
		// 实体文件产出强制（防幻觉/防流程中断）：本阶段工作区必须新增过文件
		state := p.StageStates[stageID]
		started, _ := time.Parse(time.RFC3339, state.StartedAt)
		fresh, _ := o.listWorkspaceFilesSince(p.ID, "", started)
		if len(fresh) == 0 {
			o.log(p, stageID, "⚠ 收口被拦截：本阶段尚未产出任何实体文件")
			return "收口失败：本阶段必须先用 write_file 产出实体交付物文件（建议路径 deliverables/<阶段>-<名称>.md，报告为 report.md），把结论落到文件里。产出后再次调用 complete_stage。"
		}
		// 反思门（PentAGI reflector 移植）：收口前质量审查，每阶段最多拦截 2 次防死循环
		// v5.1.2 P1 修复：三振出局旁路显式留痕——此前第 3 次收口静默跳过全部硬门，
		// heads 承诺的「引擎硬门拦截」在该路径无痕失效。
		if state.ReviewRounds >= 2 {
			// v5.1.3 修复①：三振出局改「降级门」——LLM 反思跳过，确定性门照跑并强制通过。
			// 此前旁路静默跳过 M2/M4/G2/G3/W4 全部机械门（实战监控实证：TH-23/24 高价值
			// 候选经 S4 代收口+S5 改写静默蒸发）。机械检查不需要 LLM，旁路≠跳门。
			o.log(p, stageID, "⚠ 三振出局降级门：LLM 反思跳过，确定性门照跑并强制通过（v5.1.3）")
			if issues := o.deterministicGate(p, stageID); len(issues) > 0 {
				return "收口失败（三振出局降级门）：LLM 反思已跳过，但确定性门仍有未通过项：\n- " +
					strings.Join(issues, "\n- ") + "\n逐项修正后再次收口（确定性门逐次重跑，不消耗反思额度）。"
			}
			state.Review = strings.TrimSpace(state.Review + " [v5.1.3 三振出局降级门——LLM 反思跳过，确定性门已通过]")
			_ = o.store.SaveProject(p)
		}
		if state.ReviewRounds < 2 {
			// v4.6 R1：反思门 LLM 失败重试 ×3（原实现单次失败即走确定性门放行——审计实证
			// 「反思门调用失败…放行并留痕」高频出现）。全部失败后确定性门通过者，阶段标记
			// quality-pending，S8 收口门强制复核（不再无声放行）。
			var reviewText string
			var blocked bool
			var rerr error
			for attempt := 1; attempt <= 3; attempt++ {
				reviewText, blocked, rerr = o.reflectStage(ctx, p, stageID)
				if rerr == nil {
					break
				}
				if attempt < 3 {
					time.Sleep(2 * time.Second)
				}
			}
			if rerr != nil {
				// v3.4.0 确定性质量门兜底（原 fail-open 直接放行）：LLM 反思不可用时，
				// 用纯代码核查顶上——发现与证据关联、覆盖矩阵非空、高危条目证据引用。
				state.ReflectFailures++ // v4.8 M5：按阶段统计反思门调用失败（重试 3 次全败记 1 次）
				issues := o.deterministicGate(p, stageID)
				if len(issues) > 0 {
					state.ReviewRounds++
					_ = o.store.SaveProject(p)
					o.log(p, stageID, "⚠ 反思门调用失败（已重试 3 次），确定性质量门拦截 "+fmt.Sprint(len(issues))+" 项: "+rerr.Error())
					return "收口被确定性质量门拦截（反思门重试后仍不可用，以下为引擎硬校验结果）：\n- " + strings.Join(issues, "\n- ") + "\n\n补齐后重新调用 complete_stage。"
				}
				state.Review = "反思门调用失败（重试 3 次）；确定性质量门通过放行【quality-pending：S8 收口前须复核本阶段交付物】"
				o.log(p, stageID, "⚠ 反思门 3 次重试均失败，确定性质量门通过——本阶段标记 quality-pending（S8 强制复核）")
			} else {
				// v3.8.2 关键修复：反思 PASS 也要过确定性硬校验（s8 机械检查与 LLM 审查互补——
				// 实测报告-发现不一致/同根因双记在反思 PASS 时漏过，机械检查零 LLM 成本应无条件执行）
				// v3.8.5 扩展：s4/s5 同样无条件过硬校验（G1 探测对账器——纪律性缺口靠提示词压不住，需引擎兜底）
				// v3.8.7 扩展：s7 无条件过硬校验（G3 待续清单回灌门）
				// v4.8 扩展：s3 无条件过硬校验（M2 筛查矩阵判定表门）
				if stageID == "s8" || stageID == "s4" || stageID == "s5" || stageID == "s7" || stageID == "s3" {
					if issues := o.deterministicGate(p, stageID); len(issues) > 0 {
						state.ReviewRounds++
						_ = o.store.SaveProject(p)
						o.log(p, stageID, "⚠ 确定性质量门拦截 "+fmt.Sprint(len(issues))+" 项（反思 PASS 但硬校验未过）")
						return "收口被确定性质量门拦截（LLM 反思已通过，但以下引擎硬校验未过）：\n- " + strings.Join(issues, "\n- ") + "\n\n补齐后重新调用 complete_stage。"
					}
				}
				state.Review = truncateText(reviewText, 2000)
				o.streamMsg(p.ID, stageID, "🎓 反思门审查："+reviewText)
				if blocked {
					state.ReviewRounds++
					_ = o.store.SaveProject(p)
					o.log(p, stageID, "🎓 反思门拦截：审查未通过，要求补齐后重新收口")
					return "收口被反思门拦截，审查意见如下：\n" + reviewText + "\n\n请补齐关键缺口后重新调用 complete_stage（本阶段还剩 " + fmt.Sprint(2-state.ReviewRounds) + " 次拦截机会），或确需前置补充时用 loopback。"
				}
			}
		}
		// S8 报告契约守卫（v2.2.4）：流程宪法规定报告必须为工作区根目录 report.md，
		// 实测模型曾写入 deliverables/ 导致 /report API 与报告页显示「尚未生成」——
		// 缺失即拦截；写在 deliverables/ 则自动归位根目录。
		if stageID == "s8" {
			rootReport := filepath.Join(o.workspaceRoot(p.ID), "report.md")
			if _, err := os.Stat(rootReport); err != nil {
				nested := filepath.Join(o.workspaceRoot(p.ID), "deliverables", "report.md")
				if raw, rerr := os.ReadFile(nested); rerr == nil {
					if werr := os.WriteFile(rootReport, raw, 0o640); werr == nil {
						o.log(p, stageID, "📎 已将 deliverables/report.md 归位到工作区根目录（报告契约位置）")
					}
				} else {
					o.log(p, stageID, "⚠ 收口被拦截：阶段 8 必须产出 report.md（工作区根目录）")
					return "收口失败：阶段 8 的核心交付物是渗透测试报告，必须用 write_file 写入工作区根目录 report.md（不要放进 deliverables/ 或分片后忘记合并）。写好后再次调用 complete_stage。"
				}
			}
		}
		state.Status = "done"
		state.Summary = s("summary")
		// 交付物清单去重合并（O-5：fresh 实体文件与模型自报清单曾出现重复条目）
		seen := map[string]bool{}
		state.Deliverables = nil
		addDeliv := func(p string) {
			p = strings.TrimSpace(p)
			// v2.7 A5 口径 normalize：①剥离「（说明）」注释后缀（同一文件曾以纯路径+带注释两条重复）
			// ②仅接受交付物类路径 deliverables/、poc/、根 report.md——evidence/ 证据与 .async/ 运行产物
			// 不属于交付物清单（实测 S4 曾 48/54 条为证据文件）
			if i := strings.Index(p, "（"); i > 0 {
				p = strings.TrimSpace(p[:i])
			}
			if i := strings.Index(p, "("); i > 0 {
				p = strings.TrimSpace(p[:i])
			}
			p = strings.TrimPrefix(p, "./")
			if p == "" || seen[p] {
				return
			}
			if !strings.HasPrefix(p, "deliverables/") && !strings.HasPrefix(p, "poc/") && p != "report.md" {
				return
			}
			seen[p] = true
			state.Deliverables = append(state.Deliverables, p)
		}
		for _, f := range fresh {
			addDeliv(f.Path)
		}
		if deliv, ok := args["deliverables"].([]any); ok {
			for _, d := range deliv {
				if ds, ok := d.(string); ok {
					addDeliv(ds)
				}
			}
		}
		// v4.8 R7 第二层：对抗假设 pass（s3 收口时，引擎以独立 LLM 会话做红队视角复查）。
		// 增强项非阻塞：LLM 失败只留痕不拦收口（§七.2 成本/噪声约束——VT 需主头确认才转 ready）。
		var r7Note, r7File string
		if stageID == "s3" {
			r7Note, r7File = o.adversarialAssumptionPass(ctx, p, stageID)
			if r7File != "" {
				seen[r7File] = true
				state.Deliverables = append(state.Deliverables, r7File)
			}
		}
		state.EndedAt = time.Now().Format(time.RFC3339)
		_ = o.store.SaveProject(p)
		o.bus.Publish(p.ID, "stage", map[string]any{"stage": stageID, "status": "done", "summary": state.Summary, "deliverables": state.Deliverables})
		_, _ = o.store.AddEvidence(&store.EvidenceRecord{ProjectID: p.ID, Stage: stageID, Type: "stage", Input: "阶段收口", Output: state.Summary + "\n产出文件: " + strings.Join(freshPaths(fresh), ", "), ApprovedBy: "auto"})
		stageName := stageID
		if h := o.heads[stageID]; h != nil {
			stageName = h.Name
		}
		_, _ = o.store.AddTimeline(&store.TimelineEvent{ProjectID: p.ID, Stage: stageID, Event: "阶段完成", Detail: stageName + "：产出文件 " + fmt.Sprint(len(fresh)) + " 个"})
		o.log(p, stageID, fmt.Sprintf("■ 阶段[%s]完成，产出文件 %d 个", stageID, len(fresh)))
		if r7Note != "" {
			return "阶段已收口\n\n" + r7Note
		}
		return "阶段已收口"
	case "loopback":
		to := s("to_stage")
		st, ok := p.StageStates[to]
		if !ok || st == nil {
			return "错误: 回环目标阶段不存在: " + to
		}
		// v5.5.0（修复方案 D）：回环上限内才置 pending+排队——原实现先置 pending 再查上限，
		// 超额时状态已改但永远不入补跑队列，形成"看似已回环实则死死角"。
		o.loopMu.Lock()
		q := o.loops[p.ID]
		queued := len(q) < o.cfg.Engine.LoopbackMaxRuns
		if queued {
			o.loops[p.ID] = append(q, to)
		}
		o.loopMu.Unlock()
		if !queued {
			// 超额：不改状态（保持 done/pending 原状），持久留痕 + 显式告知未排队。
			_, _ = o.store.AddTimeline(&store.TimelineEvent{ProjectID: p.ID, Stage: stageID,
				Event:  "回环超额拒绝（v5.5.0 方案 D）",
				Detail: fmt.Sprintf("to=%s reason=%s——已达单项目自动补跑上限 %d 次，未入补跑队列；请人工在「阶段流水线」重跑 %s 或评估新线索价值后手动触发", to, s("reason"), o.cfg.Engine.LoopbackMaxRuns, to)})
			o.log(p, stageID, fmt.Sprintf("⚠ 回环请求超额未排队（上限 %d）：%s → %s（已留痕待人工处置）", o.cfg.Engine.LoopbackMaxRuns, stageID, to))
			return fmt.Sprintf("回环未执行：本项目自动回环补跑已达上限（%d 次）。本请求已持久留痕（时间线「回环超额拒绝」），状态未改动。请人工决策：①在「阶段流水线」手动重跑 %s；②调用 record_vt 登记为移交/待验证项。不要再次调用 loopback。", o.cfg.Engine.LoopbackMaxRuns, to)
		}
		st.Status = "pending" // 回环：目标阶段重开
		_ = o.store.SaveProject(p)
		o.log(p, stageID, fmt.Sprintf("↩ 新线索回环 → 阶段[%s]：%s", to, s("reason")))
		_, _ = o.store.AddTimeline(&store.TimelineEvent{ProjectID: p.ID, Stage: stageID, Event: "回环", Detail: to + ": " + s("reason")})
		return fmt.Sprintf("已触发回环至阶段[%s]；该阶段将在本项目后续轮次自动补跑，请继续当前阶段收尾。", to)
	case "plan_subtasks": // PentAGI subtask_list/patch 移植：阶段内任务分解与进度跟踪
		titles, ok := args["items"].([]any)
		if !ok || len(titles) == 0 {
			return "错误: items 必须是非空数组，每项形如 {\"title\":\"…\",\"detail\":\"…\"}"
		}
		if err := o.store.DeleteStageSubtasks(p.ID, stageID); err != nil {
			return "错误: " + err.Error()
		}
		n := 0
		var lines []string
		for _, it := range titles {
			m, _ := it.(map[string]any)
			if m == nil {
				continue
			}
			ti, _ := m["title"].(string)
			if strings.TrimSpace(ti) == "" {
				continue
			}
			de, _ := m["detail"].(string)
			sid, err := o.store.AddSubtask(&store.Subtask{ProjectID: p.ID, Stage: stageID, Title: ti, Detail: de, Status: "created"})
			if err != nil {
				return "错误: " + err.Error()
			}
			lines = append(lines, fmt.Sprintf("[%s] %s", sid, ti))
			n++
		}
		if n == 0 {
			return "错误: 未解析到有效子任务（每项需含 title）"
		}
		// v5.3.2 P1-5：建档即按覆盖缺口/风险/证据自调优先级——返回有序清单，头按序推进
		ranked := o.rerankSubtasks(p, stageID)
		if len(ranked) > 0 {
			lines = lines[:0]
			for _, st := range ranked {
				lines = append(lines, fmt.Sprintf("[%s] [P%d] %s（依据：%s）", st.ID, st.Priority, st.Title, st.PriorityWhy))
			}
		}
		o.log(p, stageID, fmt.Sprintf("🗂 子任务计划已建立（%d 项，优先级已自排）", n))
		return fmt.Sprintf("已建立 %d 项子任务计划（用方括号内的 id 调 update_subtask 同步进度；[P1] 最优先，按序推进，覆盖缺口/高危/证据缺口任务自动前置）：\n%s", n, strings.Join(lines, "\n"))
	case "update_subtask":
		id := s("id")
		st, err := o.store.GetSubtask(id)
		if err != nil || st.ProjectID != p.ID {
			// 兜底：允许按标题精确匹配（模型偶发用标题代替 id）
			if subs, _ := o.store.ListSubtasks(p.ID); len(subs) > 0 {
				for _, t := range subs {
					if t.Title == id || strings.Contains(t.Title, id) && id != "" {
						st, err = t, nil
						break
					}
				}
			}
			if err != nil || st == nil {
				return "错误: 子任务不存在（先 plan_subtasks 建立，返回值里带各子任务 id）"
			}
		}
		if v := s("status"); v != "" {
			switch v {
			case "created", "running", "waiting", "finished", "failed":
				st.Status = v
			default:
				return "错误: status 仅支持 created/running/waiting/finished/failed"
			}
		}
		if v := s("result"); v != "" {
			st.Result = truncateText(v, 2000)
		}
		if err := o.store.SaveSubtask(st); err != nil {
			return "错误: " + err.Error()
		}
		o.bus.Publish(p.ID, "subtask", st)
		o.log(p, stageID, fmt.Sprintf("🗂 子任务[%s] %s → %s", st.ID, truncateText(st.Title, 40), st.Status))
		return "已更新子任务 " + st.ID + "：" + st.Title + " → " + st.Status
	case "consult_expert": // PentAGI 专家团队移植：向专项专家做单次深度咨询
		role, question := s("role"), s("question")
		if strings.TrimSpace(question) == "" {
			return "错误: question 为空"
		}
		answer, err := o.consultExpert(ctx, p, stageID, role, question)
		if err != nil {
			return "专家咨询失败: " + err.Error()
		}
		o.log(p, stageID, fmt.Sprintf("🎓 专家[%s]会诊完成（%d 字）", role, len([]rune(answer))))
		return answer
	case "request_user_input": // PentAGI ask_user 屏障移植：挂起等待人工回答
		q := s("question")
		if strings.TrimSpace(q) == "" {
			return "错误: question 为空"
		}
		answer, err := o.askUser(ctx, p.ID, stageID, q)
		if err != nil {
			return "提问失败: " + err.Error()
		}
		return "用户回答: " + answer
	case "spawn_subagent": // v3.6.0 阶段内并行扇出：派发独立测试单元给受控子代理
		objective := s("objective")
		if strings.TrimSpace(objective) == "" {
			return "错误: objective 必填（一句话说清测试单元：目标×漏洞类×判据）"
		}
		rounds := 0
		if n, err := strconv.Atoi(strings.TrimSpace(s("rounds"))); err == nil {
			rounds = n
		}
		msg, err := o.spawnSubAgent(ctx, p, stageID, objective, rounds)
		if err != nil {
			return "错误: " + err.Error()
		}
		return msg
	case "poll_subagents": // v3.6.0 收子代理结果（已结束的报简报并标记消费）
		return o.pollSubAgents(p)
	// ---- v5.5.0 结构化凭据仓库与带态注入（修复方案 A）----
	case "store_credential":
		return o.toolStoreCredential(p, stageID, args)
	case "list_credentials":
		return o.toolListCredentials(p)
	case "revoke_credential":
		return o.toolRevokeCredential(p, stageID, args)
	case "http_request": // 结构化 HTTP + auth_ref 注入（治理/审批/留证与 run_command 同级）
		return o.toolHTTPRequest(ctx, p, stageID, args)
	case "cred_command": // 显式占位符命令模板，密文走临时文件中介（治理/审批同 run_command）
		return o.toolCredCommand(ctx, p, stageID, args)
	case "request_credential": // v5.6.0 凭据专用索取通道：回答原文不落库，直入加密仓库
		return o.toolRequestCredential(ctx, p, stageID, args)
	case "record_lesson": // v3.4.0 组织级教训库：跨项目脱敏经验（收口/失败复盘时登记）
		text, tags := s("text"), s("tags")
		if strings.TrimSpace(text) == "" {
			return "错误: text 必填"
		}
		if bad := lessonSanitizeCheck(text); bad != "" {
			return "拒绝登记（合规校验未通过）：教训必须脱敏，检测到 " + bad + "。请改写为不含目标标识的通用经验，如「对 WAF 前置目标，先指纹分型再选编码变体」。"
		}
		id, lerr := o.store.AddLesson(&store.LessonRecord{Text: truncateText(text, 500), Tags: truncateText(tags, 100),
			BehaviorClass: truncateText(s("behavior_class"), 40), // v4.6 E5/K2：行为类（rate-limited/js-challenge-waf/…）
			Stack:         truncateText(s("stack"), 60),          // v4.6 E5：技术栈
			SampleSize:    truncateText(s("sample_size"), 40),    // v4.6 E5：证据强度（单次实验→provisional）
			ValidScope:    truncateText(s("valid_scope"), 80),    // v4.6 E5：适用范围
		})
		if lerr != nil {
			return "错误: " + lerr.Error()
		}
		o.log(p, stageID, "📚 教训已入库（脱敏校验通过）")
		return "教训已登记 id=" + id + "（跨项目复用，后续项目上下文自动携带最近教训）。"
	case "upsert_fact": // v3.3.0 项目黑板：事实账本幂等写入（负结果也落库防重复试错）
		key, value, confidence := s("key"), s("value"), s("confidence")
		if strings.TrimSpace(key) == "" || strings.TrimSpace(value) == "" {
			return "错误: key 与 value 必填"
		}
		var links []string
		for _, l := range strings.Split(s("links"), ",") {
			if t := strings.TrimSpace(l); t != "" {
				links = append(links, t)
			}
		}
		f := &store.FactRecord{ProjectID: p.ID, Stage: stageID, Key: truncateText(key, 200),
			Value: truncateText(value, 1500), Confidence: confidence, Links: links, Note: s("note")}
		id, err := o.store.UpsertFact(f)
		if err != nil {
			return "错误: " + err.Error()
		}
		o.log(p, stageID, fmt.Sprintf("🧠 黑板[%s] %s（%s）", f.Confidence, f.Key, f.Note))
		return fmt.Sprintf("事实已上黑板 id=%s confidence=%s（confirmed 必须有证据；已排除/误报用 deprecated——负结果落库防止重复试错）。当前黑板用 search_memory 可查。", id, f.Confidence)
	case "record_loot": // v3.3.0 战利品库：凭据/票据/flag 掩码登记（不存明文）
		ltype, target, masked := s("type"), s("target"), s("masked")
		if strings.TrimSpace(masked) == "" {
			return "错误: masked 必填（掩码摘要，如 adm***23 / NTLM:32d***a1；禁止存明文）"
		}
		verified := s("verified")
		if verified != "verified" && verified != "invalid" {
			verified = "unverified"
		}
		id, err := o.store.AddLoot(&store.LootRecord{ProjectID: p.ID, Stage: stageID,
			Type: truncateText(ltype, 40), Target: truncateText(target, 200),
			Masked: truncateText(masked, 200), Source: truncateText(s("source"), 300), Verified: verified})
		if err != nil {
			return "错误: " + err.Error()
		}
		o.log(p, stageID, fmt.Sprintf("🪙 战利品[%s/%s] %s @ %s", ltype, verified, masked, target))
		return fmt.Sprintf("战利品已登记 id=%s verified=%s。后续阶段（横向/爆破/复用）先 search_memory 查战利品，避免重复获取。", id, verified)
	case "shell_open": // v3.3.0 持久交互会话：打开（审批与 run_command 同级）
		command, reason := s("command"), s("reason")
		if strings.TrimSpace(command) == "" {
			return "错误: command 为空"
		}
		risk := o.exec.ClassifyRisk(command)
		if risk == tools.Forbidden {
			return "拒绝执行：该命令命中破坏性操作禁令。"
		}
		// v5.3.1 P0-2：改用治理门统一入口（v5.2.0 起本通道已有双门，现并入 profile 门）
		if msg := o.governanceGates(p, stageID, command, "shell_open", false); msg != "" {
			return msg
		}
		decision, err := o.approver.Request(ctx, p.ID, stageID, fmt.Sprintf("打开交互会话: %s\n原因: %s", command, reason), risk)
		if err != nil {
			return "审批异常: " + err.Error()
		}
		if decision != "approved" && decision != "auto-approved" {
			return "人工审批拒绝打开该会话。"
		}
		sess, err := o.exec.StartShell(p.ID, command, 0)
		if err != nil {
			return "错误: 会话启动失败 " + err.Error()
		}
		_, _ = o.store.AddEvidence(&store.EvidenceRecord{ProjectID: p.ID, Stage: stageID, Type: "command",
			Input: "[shell] " + command, Output: "session=" + sess.ID, Risk: risk, ApprovedBy: "auto"})
		o.log(p, stageID, fmt.Sprintf("🔌 交互会话 %s 已打开（超时 %s）：%s", sess.ID, sess.Timeout, truncateText(command, 100)))
		return fmt.Sprintf("交互会话已打开 session=%s（stdin 管道无 TTY；超时 %s）。用法：shell_write 注入输入（enter 默认自动补换行）、shell_read 增量读输出；用完 shell_close 释放。适用 mysql/redis-cli/ssh -T/nc 监听/长驻脚本；readline 类交互工具请改 run_command 脚本化，Python 加 -u 关缓冲。", sess.ID, sess.Timeout)
	case "shell_write": // v3.3.0 向会话注入输入
		sessID, input := s("session"), s("input")
		if sessID == "" || input == "" {
			return "错误: session 与 input 必填"
		}
		// v5.1.2 P0 修复：会话注入输入与 run_command 同等受控——此前 stdin 注入完全绕过
		// 风险分级与审批（可在「只读」会话里注入破坏性 SQL/命令，违背 loop-core「经任何
		// 通道执行的修改同等受控」承诺）。L0 输入即时放行不产生摩擦；L1+ 走审批留痕。
		// v5.3.1 P0-2：治理门统一接线——交互会话里注入的 SQL/命令同样受执行档与范围约束。
		if msg := o.governanceGates(p, stageID, input, "shell_write", false); msg != "" {
			return msg
		}
		risk := o.exec.ClassifyRisk(input)
		if risk == tools.Forbidden {
			return "拒绝写入：输入命中破坏性操作禁令（交互会话通道同等受控——改用合规只读命令或走审批流程）。"
		}
		decision, aerr := o.approver.Request(ctx, p.ID, stageID, fmt.Sprintf("会话 %s 注入输入: %s", sessID, truncateText(input, 120)), risk)
		if aerr != nil {
			return "审批异常: " + aerr.Error()
		}
		if decision != "approved" && decision != "auto-approved" {
			return "人工审批拒绝该会话输入。"
		}
		if err := o.exec.WriteShell(p.ID, sessID, input, s("enter") != "false"); err != nil {
			return "错误: " + err.Error()
		}
		if risk != tools.L0ReadOnly {
			_, _ = o.store.AddEvidence(&store.EvidenceRecord{ProjectID: p.ID, Stage: stageID, Type: "command",
				Input: "[shell-write→" + sessID + "] " + truncateText(input, 200), Output: "risk=" + fmt.Sprint(risk), Risk: risk, ApprovedBy: decision})
		}
		return "已写入。用 shell_read 取回响。"
	case "shell_read": // v3.3.0 增量读会话输出
		out, ok := o.exec.ReadShell(p.ID, s("session"))
		if !ok {
			return "错误: 未知会话 id"
		}
		if strings.TrimSpace(out) == "" {
			return "（暂无新输出；稍后再读，或确认目标是否有响应）"
		}
		return out
	case "shell_close": // v3.3.0 关闭会话
		if o.exec.CloseShell(p.ID, s("session")) {
			return "会话已关闭（进程组终止，不留孤儿连目标）。"
		}
		return "错误: 未知会话 id"
	case "install_tool": // v2.5 Kali 环境：apt→pip(国内源)→git(github→gitee) 多策略自动安装
		name, purpose := s("name"), s("purpose")
		if strings.TrimSpace(name) == "" {
			return "错误: name 为空"
		}
		return o.toolInstallTool(ctx, p, stageID, name, purpose)
	default:
		return "错误: 未知工具 " + tc.Name
	}
}

func (o *Orchestrator) toolRunCommand(ctx context.Context, p *store.Project, stageID, command, reason string) string {
	if strings.TrimSpace(command) == "" {
		return "错误: command 为空"
	}
	// v4.8 W5 行为预算器前置闸：批量动作配额/冷却/空壳即停（在审批前拦截，不烧审批槽位）
	if note := o.batchBudgetGate(p, stageID, command); note != "" {
		return note
	}
	// v5.3.1 P0-2：治理门统一接线（执行档+注册写+范围）——此前主通道曾绕过确定性门
	if msg := o.governanceGates(p, stageID, command, "run_command", false); msg != "" {
		return msg
	}
	risk := o.exec.ClassifyRisk(command)
	if risk == tools.Forbidden {
		o.log(p, stageID, "⛔ 拒绝破坏性命令（红线）: "+truncateText(command, 120))
		_, _ = o.store.AddEvidence(&store.EvidenceRecord{ProjectID: p.ID, Stage: stageID, Type: "command", Input: command, Output: "被护栏拒绝（破坏性操作禁令）", Risk: risk})
		return "拒绝执行：该命令命中破坏性操作禁令。请改用最小影响方式。"
	}
	approvedBy := "auto"
	// v5.6.1（审计 RunB#8）：审批工单 Action 统一脱敏——命令含内联凭据时不再明文落审批记录
	decision, err := o.approver.Request(ctx, p.ID, stageID, fmt.Sprintf("执行命令: %s\n原因: %s", maskSensitiveText(command), maskSensitiveText(reason)), risk)
	if err != nil {
		return "审批异常: " + err.Error()
	}
	if decision != "approved" && decision != "auto-approved" {
		_, _ = o.store.AddEvidence(&store.EvidenceRecord{ProjectID: p.ID, Stage: stageID, Type: "command", Input: command, Output: "人工拒绝", Risk: risk, ApprovedBy: "human-rejected"})
		return "人工审批拒绝该命令。请说明替代方案或收口本阶段。"
	}
	if decision == "approved" {
		approvedBy = "human"
		o.log(p, stageID, "✔ 人工批准执行: "+truncateText(command, 120))
	} else {
		approvedBy = "auto"
		if risk != tools.L0ReadOnly {
			o.log(p, stageID, "⚙ 策略自动批准执行（审批工单留痕 mode=auto）: "+truncateText(command, 120))
		}
	}
	start := time.Now()
	res, err := o.exec.Run(ctx, p.ID, command, o.cfg.Engine.CommandTimeoutSec)
	dur := time.Since(start).Milliseconds()
	out := ""
	exit := 0
	if res != nil {
		out = res.Stdout
		exit = res.ExitCode
	}
	// v3.3.0 输出治理①溢出落盘（strix output_store 思想）：超阈值输出整体写工作区
	// .tool-output/，模型回执只见 head+tail+路径（grep/read_file 自取所需片段）——
	// 实测单条 200KB 直入消息链是 98% 输入占比与注意力稀释的主因。
	spilled := ""
	if o.cfg.Engine.SpillBytes > 0 && len(out) > o.cfg.Engine.SpillBytes {
		rel := fmt.Sprintf(".tool-output/%d.txt", time.Now().UnixNano())
		if _, werr := o.exec.WriteFile(p.ID, rel, out); werr == nil {
			spilled = rel
			out = tools.TruncateSmart(out, 8*1024) + fmt.Sprintf("\n📦 输出已溢出落盘: %s（用 read_file 读、或 run_command grep 该文件取片段；不要原样重跑命令）", rel)
		}
	}
	// v3.4.1 修复：stderr 并入展示流提前到证据落库之前——证据链此前只有 stdout，
	// 错误细节（报错堆栈/扫描器诊断）不在证据里，回溯与审计失真。
	if res != nil && strings.TrimSpace(res.Stderr) != "" {
		out += "\n[stderr]\n" + res.Stderr
	}
	status := "ok"
	if err != nil {
		status = "error: " + err.Error()
	}
	// v5.6.1（审计 RunB#8）：Evidence Input/Output 统一脱敏——命令回显凭据/输出含令牌时
	// 不再明文落证据链（模型实时回执不脱敏，保持测试能力）。
	_, _ = o.store.AddEvidence(&store.EvidenceRecord{
		ProjectID: p.ID, Stage: stageID, Type: "command",
		Input: maskSensitiveText(command), Output: truncateText(maskSensitiveText(out), 2000), Risk: risk,
		ApprovedBy: approvedBy, ExitCode: exit, DurationMs: dur,
	})
	if spilled != "" {
		o.log(p, stageID, "📦 大输出溢出落盘: "+spilled)
	}
	o.log(p, stageID, fmt.Sprintf("$ %s → (%s, %dms)", truncateText(command, 120), risk, dur))
	resp := fmt.Sprintf("风险等级: %s\n审批: %s\n状态: %s\n退出码: %d\n输出:\n%s", risk, approvedBy, status, exit, out)
	if err != nil {
		resp += "\n执行错误: " + err.Error()
	}
	if advice := errorAdvice(errText(err, exit, out)); advice != "" {
		resp += "\n🩹 自愈建议: " + advice // v3.4.0 错误分类→处置建议（hexstrike 错误自愈思想）
	}
	// v2.3.1 工具缺失闭环：命令不存在（127/not found）时提示 install_tool 自动安装
	if exit == 127 || strings.Contains(out, "command not found") || strings.Contains(out, "not found") {
		resp += "\n💡 提示：该命令在环境中不存在。可调用 install_tool 自动安装后重试（参数 {\"name\":\"<工具名>\",\"purpose\":\"一句话用途\"}）；安装不了时改用已有工具并如实说明。"
	}
	// v4.8 W5 行为预算器后置反馈：空壳即停 + 批间基线自检提醒
	resp += o.batchResultFeedback(p, stageID, command, out, exit)
	return resp
}

// toolRunAsync v2.6 后台执行长任务（全端口扫描/大词表枚举/批量验证）：
// 审批矩阵与证据链与 run_command 完全同级；返回 job id 后执行循环立即继续。
func (o *Orchestrator) toolRunAsync(ctx context.Context, p *store.Project, stageID, command, reason, timeoutStr string) string {
	if strings.TrimSpace(command) == "" {
		return "错误: command 为空"
	}
	// v4.8 W5 行为预算器前置闸（后台通道同样计入批量配额——对目标的流量本质相同）
	if note := o.batchBudgetGate(p, stageID, command); note != "" {
		return note
	}
	// v5.3.1 P0-2：治理门统一接线——后台长任务对目标的影响与同步命令相同，不得绕过
	if msg := o.governanceGates(p, stageID, command, "run_async", false); msg != "" {
		return msg
	}
	timeoutSec := 0
	if n, err := strconv.Atoi(strings.TrimSpace(timeoutStr)); err == nil {
		timeoutSec = n
	}
	risk := o.exec.ClassifyRisk(command)
	if risk == tools.Forbidden {
		o.log(p, stageID, "⛔ 拒绝破坏性命令（红线，后台通道同样适用）: "+truncateText(command, 120))
		_, _ = o.store.AddEvidence(&store.EvidenceRecord{ProjectID: p.ID, Stage: stageID, Type: "command", Input: "[async] " + maskSensitiveText(command), Output: "被护栏拒绝（破坏性操作禁令）", Risk: risk})
		return "拒绝执行：该命令命中破坏性操作禁令。请改用最小影响方式。"
	}
	approvedBy := "auto"
	decision, err := o.approver.Request(ctx, p.ID, stageID, fmt.Sprintf("后台执行命令: %s\n原因: %s", maskSensitiveText(command), maskSensitiveText(reason)), risk)
	if err != nil {
		return "审批异常: " + err.Error()
	}
	if decision != "approved" && decision != "auto-approved" {
		_, _ = o.store.AddEvidence(&store.EvidenceRecord{ProjectID: p.ID, Stage: stageID, Type: "command", Input: "[async] " + maskSensitiveText(command), Output: "人工拒绝", Risk: risk, ApprovedBy: "human-rejected"})
		return "人工审批拒绝该命令。请说明替代方案或收口本阶段。"
	}
	if decision == "approved" {
		approvedBy = "human"
		o.log(p, stageID, "✔ 人工批准后台执行: "+truncateText(command, 120))
	}
	job, err := o.exec.StartAsync(p.ID, command, timeoutSec)
	if err != nil {
		return "错误: 后台启动失败 " + err.Error() + "（可回退 run_command 或 nohup 约定）"
	}
	_, _ = o.store.AddEvidence(&store.EvidenceRecord{ProjectID: p.ID, Stage: stageID, Type: "command", Input: "[async] " + maskSensitiveText(command), Output: "job=" + job.ID + " log=" + job.LogPath, Risk: risk, ApprovedBy: approvedBy})
	o.log(p, stageID, fmt.Sprintf("🚀 后台任务 %s 已启动（超时 %ds，期间继续其他工作）：%s", job.ID, int(job.Timeout.Seconds()), truncateText(command, 100)))
	return fmt.Sprintf("后台任务已启动 job=%s log=%s（超时 %ds）。\n立即用 poll_async 收结果而非同步等待；期间继续其他子任务。收口前必须确认其已结束（引擎会在流水线结束时强制清理）。", job.ID, job.LogPath, int(job.Timeout.Seconds()))
}

// ---------- v4.8 W5 行为预算器（批量动作配额 + 空壳即停 + 冷却协议 + 基线自检提醒） ----------

// batchCmdRe 批量动作识别：批量枚举/扫描/爆破工具（M6「先 probe 后 batch」的工具域一致）。
var batchCmdRe = regexp.MustCompile(`(?i)\b(arjun|ffuf|gobuster|dirsearch|masscan|nuclei|hydra|sqlmap|wfuzz|feroxbuster|medusa|patator|wpscan)\b`)

// batchEmptyShellRe 空壳结果特征：极小输出 + 全 0/超时/拦截信号。
var batchEmptyShellRe = regexp.MustCompile(`(?i)(000|timeout|timed out|connection refused|429|blocked|全部失败|0 命中|no results)`)

// batchBudgetGate 批量动作前置闸：冷却期拦截 → 空壳即停拦截 → 窗口配额（超限进冷却）。
// 非批量命令恒放行；进程内状态（重启即重置，可接受——预算器是节流不是审计）。
func (o *Orchestrator) batchBudgetGate(p *store.Project, stageID, command string) string {
	if !batchCmdRe.MatchString(command) || o.cfg == nil || o.cfg.Engine.BatchQuotaPer10Min <= 0 {
		return ""
	}
	o.batchMu.Lock()
	if o.batchStats == nil {
		o.batchStats = map[string]*batchBudgetState{}
	}
	st := o.batchStats[p.ID]
	if st == nil {
		st = &batchBudgetState{}
		o.batchStats[p.ID] = st
	}
	now := time.Now()
	defer o.batchMu.Unlock()
	if now.Before(st.cooldownUntil) {
		remain := st.cooldownUntil.Sub(now).Minutes()
		o.log(p, stageID, fmt.Sprintf("🧊 行为预算器：批量动作冷却中（剩余 %.1f 分钟），拒绝: %s", remain, truncateText(command, 80)))
		return fmt.Sprintf("🧊 拒绝执行（v4.8 W5 行为预算器·冷却协议）：批量动作配额已超限，冷却中（剩余 %.1f 分钟，完全静默——不发任何对目标流量）。冷却期内改做：①整理/分析既有结果 ②非批量只读动作 ③等待冷却后先跑 1 次基线请求自检再批量。", remain)
	}
	if st.emptyStreak >= 3 {
		st.emptyStreak = 0 // 给一次机会：要求先换通道/基线自检再批量
		o.log(p, stageID, "⛔ 行为预算器：空壳即停触发（连续 3 次批量零产出），拒绝继续批量")
		return "⛔ 拒绝执行（v4.8 W5 行为预算器·空壳即停）：最近连续 3 次批量动作均为空壳结果（全 000/超时/零命中）——继续批量只会触发封锁。强制动作：①先跑 1 次基线请求做批间基线自检；②核对通道状态（channel-snapshot 重放）；③切换适配通道或改单请求手工探测；确认通道恢复后再批量。"
	}
	cut := now.Add(-10 * time.Minute)
	keep := st.stamps[:0]
	for _, t := range st.stamps {
		if t.After(cut) {
			keep = append(keep, t)
		}
	}
	st.stamps = keep
	if len(st.stamps) >= o.cfg.Engine.BatchQuotaPer10Min {
		cd := time.Duration(o.cfg.Engine.BatchCooldownMin) * time.Minute
		if cd <= 0 {
			cd = 5 * time.Minute
		}
		st.cooldownUntil = now.Add(cd)
		o.log(p, stageID, fmt.Sprintf("🧊 行为预算器：批量动作 %d 次/10min 超限，进入 %.0f 分钟静默冷却", len(st.stamps), cd.Minutes()))
		_, _ = o.store.AddTimeline(&store.TimelineEvent{ProjectID: p.ID, Stage: stageID,
			Event: "W5 行为预算器", Detail: fmt.Sprintf("批量配额超限（%d/10min）→ 冷却 %.0f 分钟（完全静默）", len(st.stamps), cd.Minutes())})
		return fmt.Sprintf("🧊 拒绝执行（v4.8 W5 行为预算器）：10 分钟窗口内批量动作已达配额（%d 次）——进入 %.0f 分钟完全静默冷却（防触发目标封锁/限速升级）。冷却期内改做非流量动作（结果分析/证据整理/交付物撰写）；冷却后先批间基线自检（1 次基线请求对比）再继续批量。", len(st.stamps), cd.Minutes())
	}
	st.stamps = append(st.stamps, now)
	return ""
}

// batchResultFeedback 批量结果反馈：空壳计数 + 基线自检提醒（非批量命令不反馈）。
func (o *Orchestrator) batchResultFeedback(p *store.Project, stageID, command, out string, exit int) string {
	if !batchCmdRe.MatchString(command) {
		return ""
	}
	shell := (exit != 0) || len(strings.TrimSpace(out)) < 120 || batchEmptyShellRe.MatchString(out)
	o.batchMu.Lock()
	if o.batchStats == nil {
		o.batchStats = map[string]*batchBudgetState{}
	}
	st := o.batchStats[p.ID]
	if st == nil {
		st = &batchBudgetState{}
		o.batchStats[p.ID] = st
	}
	if shell {
		st.emptyStreak++
	} else {
		st.emptyStreak = 0
	}
	streak := st.emptyStreak
	o.batchMu.Unlock()
	if shell {
		note := fmt.Sprintf("\n🧯 [行为预算器] 本次批量结果疑似空壳（零产出/全 000/超时，连续 %d 次）——空壳即停阈值 3 次：先做通道基线自检（channel-snapshot 重放/1 次基线请求）再继续。", streak)
		o.log(p, stageID, fmt.Sprintf("🧯 行为预算器：批量空壳 %d/3: %s", streak, truncateText(command, 80)))
		return note
	}
	return "\n🧭 [行为预算器] 批量完成：按批间基线自检口径，跑 1 次基线请求对比批量前后通道健康度（防限速/封锁在批量中被触发而不自知）。"
}

// toolPollAsync v2.6 查询后台任务：状态 + 退出码 + 输出尾部（不整量回传）。
func (o *Orchestrator) toolPollAsync(p *store.Project, stageID, jobID string) string {
	jobID = strings.TrimSpace(jobID)
	state, out, code, elapsed, ok := o.exec.PollAsync(p.ID, jobID)
	if !ok {
		return "错误: 未知 job id（应为 run_async 返回的 id）"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "job=%s 状态=%s 已运行=%s", jobID, state, elapsed)
	if state != "running" {
		fmt.Fprintf(&b, " 退出码=%d", code)
	}
	b.WriteString("\n---输出尾部---\n")
	b.WriteString(out)
	switch state {
	case "running":
		b.WriteString("\n（仍在运行：继续其他子任务，稍后再 poll_async；不要同步等待）")
	case "killed":
		b.WriteString("\n（因超时被终止：基于已有输出继续分析，或降规模重新规划，不要原样重跑）")
	case "finished":
		b.WriteString("\n（已结束：解析输出、record_* 入库、update_coverage 登记；日志全文在 " + "projects/" + p.ID + "/" + " 对应 .async/ 文件）")
	}
	return b.String()
}

// installToolMap 已知工具的源码镜像（github 失败自动切 gitee，适配网络受限环境）。
var installToolGitMap = map[string][]string{
	"sqlmap": {"https://github.com/sqlmapproject/sqlmap.git", "https://gitee.com/mirrors/sqlmap.git"},
	"nuclei": {"https://github.com/projectdiscovery/nuclei.git", "https://gitee.com/mirrors/projectdiscovery-nuclei.git"},
}

// installAttempt 单次安装尝试（通道·路径 标签 + 完整命令）。
type installAttempt struct {
	label string
	cmd   string
}

// installDomesticHostHints 国内安装源特征（直连优先）；未列出的默认按国外源处理（代理优先）。
var installDomesticHostHints = []string{
	"gitee.com", "pypi.tuna.tsinghua.edu.cn", "mirrors.tuna.tsinghua.edu.cn",
	"mirrors.aliyun.com", "mirrors.ustc.edu.cn", "mirrors.cloud.tencent.com",
	"mirrors.huaweicloud.com", "registry.npmmirror.com",
}

// installSourceDomestic 判断安装源是否国内镜像（v5.7.2 安装通道分流用）。
func installSourceDomestic(source string) bool {
	s := strings.ToLower(source)
	for _, h := range installDomesticHostHints {
		if strings.Contains(s, h) {
			return true
		}
	}
	return false
}

// gitSourceLabel 从 git 源地址提取可读标签（github.com→github），替代旧版按下标硬编码。
func gitSourceLabel(source string) string {
	h := source
	if m := urlHostRe.FindStringSubmatch(source); m != nil {
		h = m[1]
	}
	h = strings.TrimPrefix(h, "www.")
	return strings.TrimSuffix(strings.TrimSuffix(h, ".com"), ".net")
}

// buildInstallAttempts v5.7.2 安装通道分流：按源地域生成直连/代理互为兜底的尝试序列。
// 实证事故（多条历史任务）：pip 走清华源报 SSL EOF（TLS 被上游重置）、
// github 直连恒定 Connection reset——单路径策略哪条坏就整链失败。本环境实测：国内源直连可达、
// github 仅代理可达；代理链路（LLM_PROXY→上游）恰好相反。故：
//   - 通道优先级不变：apt → pip 清华源 → git（installToolGitMap 顺序，github 优先 gitee 镜像）；
//   - 国内源直连优先、国外源代理优先，每条通道主路径失败后以反向路径兜底再试一次；
//   - proxyURL 为空（公开分发默认未配 TOOL_PROXY/全局代理）时仅试直连，行为同旧版。
func buildInstallAttempts(name, proxyURL string) []installAttempt {
	// 直连前缀显式剥离代理变量（防御性：不依赖执行器 sanitizeEnv 剥离，命令级自保证）；
	// 代理前缀显式注入（命令内 export 不经 sanitizeEnv 白名单，子进程可达）
	pDirect := "unset http_proxy https_proxy HTTP_PROXY HTTPS_PROXY; "
	pProxy := ""
	if proxyURL != "" {
		pProxy = fmt.Sprintf("export http_proxy=%s https_proxy=%s; ", proxyURL, proxyURL)
	}
	aptCmd := fmt.Sprintf("mkdir -p /opt/tools; export DEBIAN_FRONTEND=noninteractive; apt-get update -qq 2>&1 | tail -2; apt-get install -y --no-install-recommends %s 2>&1 | tail -3", name)
	pipCmd := fmt.Sprintf("command -v pip3 >/dev/null 2>&1 || (export DEBIAN_FRONTEND=noninteractive; apt-get install -y --no-install-recommends python3-pip >/dev/null 2>&1); python3 -m pip install --no-cache-dir --break-system-packages -i https://pypi.tuna.tsinghua.edu.cn/simple %s 2>&1 | tail -3", name)
	var attempts []installAttempt
	attempts = append(attempts, installAttempt{"apt 包管理器(Kali)·直连", pDirect + aptCmd})
	if pProxy != "" {
		attempts = append(attempts, installAttempt{"apt 包管理器(Kali)·代理兜底", pProxy + aptCmd})
	}
	attempts = append(attempts, installAttempt{"pip 清华源·直连", pDirect + pipCmd})
	if pProxy != "" {
		attempts = append(attempts, installAttempt{"pip 清华源·代理兜底", pProxy + pipCmd})
	}
	if sources, ok := installToolGitMap[name]; ok {
		for _, src := range sources {
			gitCmd := fmt.Sprintf("git clone --depth 1 %s /opt/tools/%s 2>&1 | tail -2 && ln -sf /opt/tools/%s/%s.py /usr/local/bin/%s 2>/dev/null; chmod +x /opt/tools/%s/%s.py 2>/dev/null; true", src, name, name, name, name, name, name)
			label := "git 源码(" + gitSourceLabel(src) + ")"
			if installSourceDomestic(src) {
				attempts = append(attempts, installAttempt{label + "·直连", pDirect + gitCmd})
				if pProxy != "" {
					attempts = append(attempts, installAttempt{label + "·代理兜底", pProxy + gitCmd})
				}
			} else {
				if pProxy != "" {
					attempts = append(attempts, installAttempt{label + "·代理", pProxy + gitCmd})
				}
				attempts = append(attempts, installAttempt{label + "·直连兜底", pDirect + gitCmd})
			}
		}
	}
	return attempts
}

// toolInstallTool 自动安装缺失的安全工具（v2.5 Kali 化）：apt → pip(国内源) → git(github→gitee)。
// 安装位置 /opt/tools（持久化至容器生命周期），可执行入口符号链接到 /usr/local/bin。
// 成功/失败均写时间线与审批留痕；每工具最多尝试一次（标记文件防循环）。
// 安装类命令自动透传 TOOL_PROXY 工具代理（仅外网下载用，不作用于目标主机测试流量）。
func (o *Orchestrator) toolInstallTool(ctx context.Context, p *store.Project, stageID, name, purpose string) string {
	name = strings.ToLower(strings.TrimSpace(name))
	if !regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{1,40}$`).MatchString(name) {
		return "错误: 工具名不合法（仅允许字母数字._-）"
	}
	marker := fmt.Sprintf("/opt/tools/.installed-%s", name)
	// 已存在则直接确认可用
	chk, _ := o.exec.Run(ctx, p.ID, fmt.Sprintf("command -v %s || test -f %s", name, marker), 30)
	if chk != nil && chk.ExitCode == 0 {
		return fmt.Sprintf("工具 %s 已可用（无需安装）。直接使用即可。", name)
	}
	o.log(p, stageID, fmt.Sprintf("🛠 开始自动安装工具: %s（用途: %s）", name, truncateText(purpose, 60)))

	// v5.1.2 P0 修复：安装动作等同 L1 命令进审批矩阵（此前完全绕过审批——manual 策略下
	// 同类 apt/pip 命令必须人工批准而本工具免批，构成审批旁路+任意包名供应链写入面）。
	// auto 策略（l1 默认）下自动通过并留痕，行为不变但链路合规。
	decision, aerr := o.approver.Request(ctx, p.ID, stageID,
		fmt.Sprintf("install_tool: 安装 %s（用途: %s）", name, truncateText(purpose, 60)), tools.L1Write)
	if aerr != nil {
		return "审批异常: " + aerr.Error()
	}
	if decision != "approved" && decision != "auto-approved" {
		return "人工审批拒绝安装 " + name + "。按 loop-core 工具纪律：改用已有同类工具并把该限制如实写入交付物，禁止编造未运行的工具输出。"
	}

	// v5.7.2：代理地址解析——TOOL_PROXY 优先（部署显式配置的工具代理）；未配置时回退容器全局
	// HTTP(S)_PROXY（LLM_PROXY 经 compose 注入，本测试环境即 privoxy→上游）。两者皆空仅试直连。
	// 直连/代理互为兜底的尝试序列见 buildInstallAttempts。
	proxyURL := strings.TrimSpace(os.Getenv("TOOL_PROXY"))
	if proxyURL == "" {
		for _, k := range []string{"HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy"} {
			if v := strings.TrimSpace(os.Getenv(k)); v != "" {
				proxyURL = v
				break
			}
		}
	}
	attempts := buildInstallAttempts(name, proxyURL)

	var log strings.Builder
	installed := ""
	for _, st := range attempts {
		if ctx.Err() != nil {
			return "安装中止（项目已停止）"
		}
		// v5.3.1 P0-2：安装命令同样过治理门（安装源属良性白名单面，正常放行；未知来源确定性拦截）
		if msg := o.governanceGates(p, stageID, st.cmd, "install_tool", true); msg != "" {
			return "安装被治理门拦截：" + msg
		}
		res, err := o.exec.Run(ctx, p.ID, st.cmd, 300)
		out := ""
		if res != nil {
			out = res.Stdout
		}
		log.WriteString(fmt.Sprintf("\n[%s] 退出码=%d\n%s", st.label, map[bool]int{true: 0, false: 1}[err == nil && res != nil && res.ExitCode == 0], truncateText(out, 400)))
		// 验证安装是否成功
		verify := fmt.Sprintf("command -v %s >/dev/null 2>&1 || test -f /opt/tools/%s/%s.py", name, name, name)
		vr, _ := o.exec.Run(ctx, p.ID, verify, 15)
		if err == nil && vr != nil && vr.ExitCode == 0 {
			installed = st.label
			_, _ = o.exec.Run(ctx, p.ID, fmt.Sprintf("touch %s", marker), 15)
			break
		}
		o.log(p, stageID, fmt.Sprintf("🛠 %s 安装 %s 失败，尝试下一策略", name, st.label))
	}

	if installed == "" {
		o.log(p, stageID, fmt.Sprintf("🛠 工具 %s 安装失败（全部策略尝试完毕）", name))
		_, _ = o.store.AddTimeline(&store.TimelineEvent{ProjectID: p.ID, Stage: stageID, Event: "工具安装失败", Detail: name + "：apt/pip/git 各通道直连与代理兜底均失败或不存在该包；请改用已有工具并如实说明"})
		return "工具 " + name + " 自动安装失败（已尝试: apt/pip/git 各通道直连+代理兜底）。常见原因：网络受限或包名不存在。请改用环境中已有的同类工具完成测试，并把该限制如实写入交付物。尝试日志:\n" + truncateText(log.String(), 800)
	}
	_, _ = o.store.AddTimeline(&store.TimelineEvent{ProjectID: p.ID, Stage: stageID, Event: "工具自动安装", Detail: fmt.Sprintf("%s（via %s）用途: %s", name, installed, truncateText(purpose, 60))})
	_, _ = o.store.AddEvidence(&store.EvidenceRecord{ProjectID: p.ID, Stage: stageID, Type: "command", Input: "install_tool " + name, Output: "via " + installed + "\n" + truncateText(log.String(), 500), Risk: tools.L1Write, ApprovedBy: "auto"})
	o.log(p, stageID, fmt.Sprintf("🛠 工具 %s 安装成功（via %s）", name, installed))
	return fmt.Sprintf("工具 %s 安装成功（via %s），可直接在 run_command 中使用。验证: `%s --version`。安装日志:\n%s", name, installed, name, truncateText(log.String(), 500))
}

// ---------- 上下文与工具定义 ----------

func (o *Orchestrator) buildContextPack(p *store.Project, stageID string) string {
	head := o.heads[stageID]
	// 对话模式（stageID=chat）没有注册同名专家头，缺省用主控头名称，避免空指针
	headName := ""
	headGoal := "请按你的阶段流程执行，并产出交付物。"
	if head != nil {
		headName = head.Name
	} else {
		if main := o.heads["main"]; main != nil {
			headName = main.Name
		}
		headGoal = "你处于对话指挥室：请结合项目上下文回应或执行用户指令。"
	}
	findings, _ := o.store.ListFindings(p.ID)
	assets, _ := o.store.ListAssets(p.ID)
	timeline, _ := o.store.ListTimeline(p.ID)

	var b strings.Builder
	// v2.4.0 多目标完整呈现：逐行列出全部目标（实测原样换行会打断列表结构，导致
	// 只看得见首目标）；多目标时 S1 必须逐个登记并逐一测绘，禁止只测第一个。
	targets := strings.Split(strings.TrimSpace(p.Target), "\n")
	if len(targets) == 1 {
		b.WriteString(fmt.Sprintf("## 项目上下文\n\n- 项目: %s\n- 目标: %s\n", p.Name, strings.TrimSpace(targets[0])))
	} else {
		b.WriteString(fmt.Sprintf("## 项目上下文\n\n- 项目: %s\n- 目标（共 %d 个，全部在范围内，逐个登记与测绘）:\n", p.Name, len(targets)))
		for i, t := range targets {
			b.WriteString(fmt.Sprintf("  %d. %s\n", i+1, strings.TrimSpace(t)))
		}
		// v4.4 多目标轮次与推进纪律（方向二B/C）：随目标清单注入，头开工即见
		if pt := o.cfg.Engine.PerTargetRounds; pt > 0 && countProjectTargets(p) > 1 {
			b.WriteString(fmt.Sprintf("- 🎯 多目标推进纪律：阶段轮次已按目标数自适应放大（每增 1 目标 +%d 轮）；**目标级轮转先于类级轮转**——先全目标过最小探针层（每目标每类 1-2 轮），全部目标有首轮结论后再按信号强度排深化序；单目标消耗超自身基线（约 %d 轮）2 倍仍零确证 → 止损转 needs_follow_up，轮次让渡给未完成目标；不可达/纯静态目标降级为**档案目标**（只登记资产与交付物，不再深挖）。\n", pt, pt))
		}
	}
	b.WriteString(fmt.Sprintf("- 授权范围: %s\n- ROE 红线: %s\n- 测试类型: %s\n- 已启用专项: %s\n- 工作区: projects/%s/（write_file 路径相对该目录）\n\n",
		firstLine(p.Scope), firstLine(p.ROE), firstLine(p.TestType), strings.Join(p.Specializations, ","), p.ID))
	// 未启用专项 A：明确禁止 AI/LLM 相关动作（用户未选就不做，避免凭空出现 AI 资产专项任务）
	hasSpecA := false
	for _, s := range p.Specializations {
		if s == "A" {
			hasSpecA = true
		}
	}
	if !hasSpecA {
		b.WriteString("- ⚠ 专项A（AI/LLM 目标测试）**未启用**：禁止做 AI 入口探测、LLM 资产识别、模型接口枚举类动作，也不要建立相关子任务；本项目目标不含 AI 应用测试。\n")
	}
	if strings.TrimSpace(p.SuccessCriteria) != "" {
		b.WriteString(fmt.Sprintf("- 测试目的: %s\n", firstLine(p.SuccessCriteria)))
	}
	if p.StrictScope {
		b.WriteString("- 严格限定范围：只测给定目标；范围外线索只记录、不继续访问。\n")
	}
	if p.Authorized {
		b.WriteString("- 授权状态：已授权（创建项目时已勾选授权确认，知悉风险并确认书面授权）——直接开工，无需再等待授权文书。\n")
	} else {
		b.WriteString("- 授权状态：未确认！禁止任何主动测试动作，仅允许只读公开信息查询。\n")
	}
	if strings.TrimSpace(p.AuthInfo) != "" {
		b.WriteString(fmt.Sprintf("- 认证会话（仅用于授权测试）: %s\n", firstLine(p.AuthInfo)))
	}
	b.WriteString("\n")
	b.WriteString(fmt.Sprintf("## 当前任务\n\n你是阶段[%s]专家头：%s。%s\n\n", stageID, headName, headGoal))

	// v3.3.0 黑板与战利品随上下文包注入（CyberStrikeAI「索引自动注入对话」）：
	// confirmed 事实与可用战利品每阶段开工即在场，不再依赖模型主动 search_memory。
	facts, _ := o.store.ListFacts(p.ID, 25)
	loots, _ := o.store.ListLoot(p.ID, 10)
	memNote := ""
	if len(facts) > 0 {
		memNote = fmt.Sprintf(" / 黑板 %d 条", len(facts))
	}
	if len(loots) > 0 {
		memNote += fmt.Sprintf(" / 战利品 %d 件", len(loots))
	}
	b.WriteString(fmt.Sprintf("## 记忆库（资产 %d 项 / 漏洞 %d 项 / 时间线 %d 条%s）\n\n", len(assets), len(findings), len(timeline), memNote))
	if len(assets) > 0 {
		b.WriteString("### 已登记资产\n")
		n := 0
		for _, a := range assets {
			b.WriteString(fmt.Sprintf("- [%s] %s（%s）\n", a.Type, a.Value, a.Stage))
			if n++; n >= 30 {
				b.WriteString("- ...(截断)\n")
				break
			}
		}
	}
	if len(findings) > 0 {
		b.WriteString("### 已登记漏洞\n")
		// v4.4 批次4：S5 待利用队列按 impact-rank 升序 → 置信度 → 严重度排序消费（xalgorix 深度优先学说队列化）
		list := findings
		if stageID == "s5" {
			list = sortQueueFindings(findings)
			b.WriteString("（待利用队列已按 impact-rank 升序 → 置信度 → 严重度排序：RCE 系先打，access=anonymous 项在无凭证项目优先消费）\n")
		}
		n := 0
		for _, f := range list {
			tag := ""
			if f.Access != "" || f.ImpactRank > 0 {
				tag = fmt.Sprintf(" [access=%s rank=%d]", f.Access, f.ImpactRank)
			}
			b.WriteString(fmt.Sprintf("- [%s/%s%s] %s\n", f.Severity, f.Confidence, tag, f.Title))
			if n++; n >= 30 {
				b.WriteString("- ...(截断)\n")
				break
			}
		}
	}
	// v3.3.0 黑板（事实账本）——凑链与避免重复试错的跨阶段事实源
	if len(facts) > 0 {
		b.WriteString("### 项目黑板（事实账本，upsert_fact 维护；confirmed=有证据，deprecated=已排除勿重试）\n")
		for i, f := range facts {
			links := ""
			if len(f.Links) > 0 {
				links = " ⟶ " + strings.Join(f.Links, ",")
			}
			b.WriteString(fmt.Sprintf("- [%s] %s: %s%s\n", f.Confidence, f.Key, truncateText(f.Value, 120), links))
			if i >= 24 {
				b.WriteString("- ...(截断，search_memory 查更多)\n")
				break
			}
		}
	}
	// v3.3.0 战利品（凭据/票据掩码摘要）——S5/S6 横向复用的第一入口
	if len(loots) > 0 {
		b.WriteString("### 战利品（掩码摘要；横向/爆破前先查这里，验证状态用 search_memory 复核）\n")
		for _, l := range loots {
			b.WriteString(fmt.Sprintf("- [%s/%s] %s @ %s（来源 %s）\n", l.Type, l.Verified, l.Masked, l.Target, truncateText(l.Source, 60)))
		}
	}
	// v3.6.1 并行扇出采纳提示（实测 glm-5.3-flash 对头内"可选"指引采纳率低，
	// 评测两轮 spawn_subagent 零调用；引擎级随上下文注入显著提示）
	if stageID == "s4" || stageID == "s5" {
		b.WriteString("> ⚡ 并行扇出提示：本阶段若剩余 ≥3 个相互独立的测试单元（不同 endpoint×漏洞类/不同指纹），用 spawn_subagent 并行派发（objective 写清目标×漏洞类×判据），主头定期 poll_subagents 收结果——这是预算内的提速手段，不是可选项。\n\n")
	}
	// v4.8 W4 六轨编排提示（引擎编排层）：无凭证且有登录面时注入——逐轨尝试/逐轨 VT 化/命中轨分类处置（v5.1：L1 评估轨+索取闭环）
	// v5.6.0：状态判据从「仅看旧 AuthInfo 字段」升级为 projectHasIdentity（AuthInfo ∪ 凭据仓库 active ∪ verified Loot）——
	// 审计缺陷：store_credential 入库后 W4 仍当 S0 跑六轨，新机制与旧状态机脱节。
	if stageID == "s4" && !o.projectHasIdentity(p) && o.loginSurfacePresent(p) {
		b.WriteString("> 🪪 身份获取编排（v4.8 W4·v5.1 修订）：本项目无凭证——按 identity-bootstrapping 六轨顺序编排（L1 注册面 → L2 泄露面 → L3 默认口令 → L4 验证码逻辑 → L5 令牌伪造 → L6 会话构造），逐轨尝试并 record_vt（title 前缀 [W4-L1]..[W4-L6]，不适用轨也登记并在 start_conditions 注明「无对应面」）；**L1 为评估轨：按 ROE identity.auto_register（默认 deny）只做注册面存在性评估与流程还原，不执行注册、命中不建会话（发现本身 record_finding）**；L2-L6 任一轨取得身份（verified loot 或 store_credential 入库）即 load_skill session-state-chain 建会话；验证码轨走 captcha-ocr「取码→识别→立即提交」单会话闭环，失败降级人工读码/browser-auth；凭据面预言机探针分流（browser_oracle 无验证码面直连 / SimCaptcha 类面走会话）。全部轨未命中（或 L1 被 ROE 关闭且其余轨未命中）时：先执行 identity-bootstrapping 一a节**身份索取闭环**（request_credential 专用通道向客户索要低权+高权测试账号——回答原文不落明文），客户拒绝/超时后才六轨 VT 全量登记并按 S4-7 三行报告口径移交——禁止跳过索取直接放弃。\n\n")
	}
	// v5.6.0 凭证状态三态上下文（通用型：所有阶段按 S0/S1/S2 差异化注入，审计④-13）
	b.WriteString(o.credentialStateBlock(p))
	// v4.6 T3/H：ROE Profile 运行时含义注入（治理参数化）
	if o.roe != nil {
		b.WriteString("### ROE Profile（运行时治理参数，v4.6 §3——引擎已加载的许可口径）\n")
		b.WriteString(o.roe.Digest() + "\n\n")
	} else {
		// v5.1.3 修复⑥：项目未配置 YAML Profile（UI 文本 ROE）时注入默认从严口径——
		// 此前 Digest 仅 YAML 路径注入，auto_register/write_policy 运行时含义不可见。
		b.WriteString("### ROE 运行时默认口径（项目未配置 YAML Profile，按平台默认从严执行）\n")
		b.WriteString("- write_policy=existence-proof → 写操作仅做存在性证明（截图/计数/哈希），禁止业务数据修改\n")
		b.WriteString("- identity.auto_register=deny（平台默认） → 注册面只评估不注册，身份向客户索取（identity-bootstrapping 一a节）\n")
		b.WriteString("- 数据边界 → 生产数据只做存在性证明；自建数据一律只登记移交、不执行删除（v5.1.3 用户政策）\n\n")
	}
	// v3.4.0 组织级教训（跨项目脱敏）——避免重蹈覆辙的第一道注入点
	// v4.6 E5/K2/K5-lite 升级：①单次实验/无样本强度的教训标注 provisional；
	// ②黑板 behavior.<目标> 分型命中的行为类教训优先注入；③阶段间空闲 >30min 提醒通道基线自检。
	behaviorClass := ""
	if facts, ferr := o.store.ListFacts(p.ID, 50); ferr == nil {
		for _, fct := range facts {
			if strings.HasPrefix(fct.Key, "behavior.") && fct.Confidence == "confirmed" {
				behaviorClass = fct.Value
			}
		}
	}
	if lessons, lerr := o.store.ListLessons(8); lerr == nil && len(lessons) > 0 {
		// v5.3.9 批次④：栈指纹加权——confirmed facts 值 + behaviorClass 构成目标指纹，
		// 教训按 Stack/Tags 命中得分排序（命中前置），零命中仍全量注入（保底不丢教训）。
		fpParts := []string{}
		if fpFacts, ferr := o.store.ListFacts(p.ID, 50); ferr == nil {
			for _, fct := range fpFacts {
				if fct.Confidence == "confirmed" && strings.TrimSpace(fct.Value) != "" {
					fpParts = append(fpParts, strings.ToLower(fct.Value))
				}
			}
		}
		if behaviorClass != "" {
			fpParts = append(fpParts, strings.ToLower(behaviorClass))
		}
		fpJoined := strings.Join(fpParts, "\x00")
		type fingerprintScored struct {
			lesson *store.LessonRecord
			score  int
		}
		scoredLessons := make([]fingerprintScored, 0, len(lessons))
		splitAny := func(s, seps string) []string {
			return strings.FieldsFunc(s, func(r rune) bool { return strings.ContainsRune(seps, r) })
		}
		for _, l := range lessons {
			score := 0
			if behaviorClass != "" && l.BehaviorClass == behaviorClass {
				score += 2
			}
			for _, tok := range splitAny(l.Stack, "/,，； ") {
				if tok != "" && strings.Contains(fpJoined, strings.ToLower(tok)) {
					score += 1
				}
			}
			for _, tok := range splitAny(l.Tags, ",， ") {
				if len([]rune(tok)) >= 2 && strings.Contains(fpJoined, strings.ToLower(tok)) {
					score += 1
				}
			}
			scoredLessons = append(scoredLessons, fingerprintScored{lesson: l, score: score})
		}
		sort.Slice(scoredLessons, func(i, j int) bool {
			if scoredLessons[i].score != scoredLessons[j].score {
				return scoredLessons[i].score > scoredLessons[j].score
			}
			return scoredLessons[i].lesson.ID < scoredLessons[j].lesson.ID
		})
		b.WriteString("### 组织级教训（跨项目脱敏经验，record_lesson 登记；栈指纹命中前置）\n")
		fingerprintHits := 0
		for _, sl := range scoredLessons {
			text := sl.lesson.Text
			if behaviorClass != "" && sl.lesson.BehaviorClass == behaviorClass {
				text = fmt.Sprintf("【行为类命中 %s】", behaviorClass) + text
			}
			if sl.score > 0 && sl.lesson.Stack != "" {
				fingerprintHits++
				text = fmt.Sprintf("【栈指纹命中 %s】", sl.lesson.Stack) + text
			}
			if strings.Contains(sl.lesson.SampleSize, "单次") || sl.lesson.SampleSize == "" {
				text += "【provisional：样本强度未标注/单次实验——跨目标使用前须 ≥3 样本复验（E5）】"
			}
			b.WriteString("- " + text + "\n")
		}
		if fingerprintHits == 0 && behaviorClass != "" {
			b.WriteString("- 本目标 fingerprint 无栈命中教训，按对应 playbook 谨慎推进\n")
		}
		b.WriteString("\n")
	}
	// v4.6 K5-lite 空闲提醒：跨阶段空闲 >30min（对抗环境通道状态可能已变化——5739 曾 8h 空窗无人检测）
	if maxEnd := o.lastStageEnd(p); maxEnd != nil {
		if gap := time.Since(*maxEnd); gap > 30*time.Minute && (stageID == "s2" || stageID == "s4" || stageID == "s5" || stageID == "s6") {
			b.WriteString(fmt.Sprintf("> ⏱ 空闲提醒（K5-lite）：距上一阶段收口已空闲 %.1f 小时——对抗类目标（限速/WAF）通道状态可能已变化，开工先做通道基线自检（登录页 dump-dom 字节数 / channel-snapshot 重放），不要沿用上一阶段通道结论。\n\n", gap.Hours()))
		}
	}
	// v4.8 M5 quality-pending 频次监控：按阶段统计反思门失败，持续高失败 → 注入修复提示。
	// 机械门只查留痕不查质量——频次高失败说明「自查不可靠」，提示模型回到结构化清单自检。
	failTotal := 0
	failStage := ""
	for sid, st := range p.StageStates {
		if st != nil && st.ReflectFailures > 0 {
			failTotal += st.ReflectFailures
			if st.ReflectFailures >= 2 {
				failStage = sid
			}
		}
	}
	if failStage != "" || failTotal >= 3 {
		note := fmt.Sprintf("> 🔁 修复提示（v4.8 M5）：本项目反思门（收口质量自查）已累计 %d 次调用失败", failTotal)
		if failStage != "" {
			note += fmt.Sprintf("（阶段 %s 失败 ≥2 次）", failStage)
		}
		note += "——引擎已降级确定性门兜底，但机械门只查留痕不查质量。收口前对照 loop-core v4.6 执行可靠性纪律与《筛查矩阵判定表》格式要求逐项自检（K3 技能第五节清单），确保一次通过，不要依赖兜底放行。\n\n"
		b.WriteString(note)
	}
	if len(timeline) > 0 {
		b.WriteString("### 最近时间线\n")
		start := 0
		if len(timeline) > 15 {
			start = len(timeline) - 15
		}
		for _, t := range timeline[start:] {
			b.WriteString(fmt.Sprintf("- %s %s: %s\n", t.CreatedAt.Format("15:04:05"), t.Event, t.Detail))
		}
	}
	// 既往阶段交付物
	if p.StageStates != nil {
		b.WriteString("\n### 既往阶段交付物\n")
		for _, id := range Pipeline(o.heads, p.Specializations) {
			if st, ok := p.StageStates[id]; ok && st.Status == "done" && id != stageID {
				b.WriteString(fmt.Sprintf("- [%s] %s\n", id, st.Summary))
			}
		}
	}
	// 覆盖度摘要（移植自 strix/PentesterFlow：回答“测过什么、还没测什么”）
	if cov, _ := o.store.ListCoverage(p.ID); len(cov) > 0 {
		statCount := map[string]int{}
		for _, c := range cov {
			statCount[c.Status]++
		}
		b.WriteString(fmt.Sprintf("\n### 覆盖度矩阵（共 %d 单元）\n", len(cov)))
		for _, st := range []string{"vulnerable", "no_issue_found", "ruled_out", "waf_blocked", "needs_follow_up", "skipped"} {
			if statCount[st] > 0 {
				b.WriteString(fmt.Sprintf("- %s: %d\n", st, statCount[st]))
			}
		}
		// 明细：vulnerable/needs_follow_up 是收口与重跑最需要的事实来源（防阶段重跑重复劳动/丢结论）
		if statCount["vulnerable"] > 0 || statCount["needs_follow_up"] > 0 {
			b.WriteString("\n#### 关键覆盖明细\n")
			for _, c := range cov {
				if c.Status == "vulnerable" || c.Status == "needs_follow_up" {
					line := fmt.Sprintf("- [%s] %s × %s × %s", c.Status, c.Endpoint, c.VulnClass, c.Param)
					if strings.TrimSpace(c.Notes) != "" {
						line += "（" + firstLine(c.Notes) + "）"
					}
					b.WriteString(line + "\n")
				}
			}
		}
		b.WriteString("（测试前先用 search_memory/覆盖矩阵决定下一步，避免重复打同一单元）\n")
	}
	// 子任务树（PentAGI 双层任务模型移植：让阶段头始终看到计划与进度）
	if subs, _ := o.store.ListSubtasks(p.ID); len(subs) > 0 {
		b.WriteString("\n### 当前子任务计划（用 plan_subtasks 重建 / update_subtask 同步进度）\n")
		for _, st := range subs {
			mark := map[string]string{"created": "○", "running": "◐", "waiting": "◔", "finished": "●", "failed": "✗"}[st.Status]
			if mark == "" {
				mark = "○"
			}
			b.WriteString(fmt.Sprintf("- %s [%s] %s（%s）\n", mark, st.ID, st.Title, st.Status))
		}
	}
	// 反思门意见（上一轮收口审查）
	if state, ok := p.StageStates[stageID]; ok && state != nil && state.Review != "" {
		b.WriteString(fmt.Sprintf("\n### 反思门审查意见（上轮，拦截 %d 次）\n%s\n", state.ReviewRounds, firstLine(state.Review)))
	}
	// 技能索引（strix 移植：按需 load_skill 注入剧本，不占常驻上下文）
	b.WriteString("\n### 技能库索引（load_skill 按需载入）\n")
	b.WriteString(o.skills.Index())
	// 空间测绘能力声明：Key 已注入命令环境，但智能体不知道就不会用（S2 曾误报「无 Key 已跳过」）
	if names := o.exec.ExtraEnvNames(); len(names) > 0 {
		b.WriteString("\n### 空间测绘能力（已注入命令环境，可直接在 run_command 中用 $变量 引用）\n")
		for _, n := range names {
			b.WriteString("- $" + n + "\n")
		}
		b.WriteString("用法参考 load_skill(query=侦察) 的「空间测绘」章节；查询结果仅作线索，须本机验证后才可确证。\n")
	}
	// v2.5 工具代理声明：运行环境为 Kali Linux，缺的工具可直接 apt 安装或调 install_tool；
	// 外网下载类命令可显式走 $TOOL_PROXY，但对目标目标主机的流量禁止走代理（保持测试真实性）
	if tp := strings.TrimSpace(os.Getenv("TOOL_PROXY")); tp != "" {
		b.WriteString(fmt.Sprintf("\n### 运行环境与工具代理\n运行环境为 Kali Linux Rolling（数千款渗透工具可用 apt 安装；缺失时优先 install_tool，也可 run_command 自行 `export DEBIAN_FRONTEND=noninteractive; apt-get install -y <工具>`，apt 安装类命令按审批矩阵走 L1 人工批准）。环境已注入工具代理 $TOOL_PROXY=%s——需要外网下载（apt/pip/git/curl -O 等）时可加前缀 `env http_proxy=$TOOL_PROXY https_proxy=$TOOL_PROXY <命令>`；**对目标目标主机的扫描/利用流量严禁走代理**，保持直连以保测试真实性。\n", tp))
	}
	// 工作区文件清单（实体交付物承接：上一阶段的产出文件是本阶段的事实来源）
	// v2.3.2：每文件附首段摘要——实测 S8 曾逐个全文精读 17 份交付物耗尽 60 轮（read_file×102），
	// 有摘要后模型只需精读 2-3 个关键文件，其余以摘要为事实来源。
	if files, _ := o.listWorkspaceFiles(p.ID, ""); len(files) > 0 {
		b.WriteString("\n### 工作区文件（含内容摘要；仅精读与当前任务直接相关的 2-3 个文件，其余以下方摘要为事实来源，禁止凭记忆虚构）\n")
		for _, f := range files {
			line := fmt.Sprintf("- %s (%s)", f.Path, humanSize(f.Size))
			if raw, err := os.ReadFile(filepath.Join(o.workspaceRoot(p.ID), f.Path)); err == nil {
				summary := strings.FieldsFunc(strings.TrimSpace(string(raw)), func(r rune) bool { return r == '\n' || r == '\r' })
				first := strings.Join(summary, " ")
				first = strings.TrimSpace(regexpReplace(first))
				if len(first) > 200 {
					first = first[:200] + "…"
				}
				if first != "" {
					line += "｜摘要: " + first
				}
			}
			b.WriteString(line + "\n")
		}
	} else {
		b.WriteString("\n### 工作区文件\n（暂无；本阶段结束前必须 write_file 产出实体交付物）\n")
	}
	return b.String()
}

// regexpReplace 折叠多余空白（摘要单行化），独立函数避免内联过长。
func regexpReplace(s string) string {
	re := regexp.MustCompile(`[ \t#*|` + "`" + `]+`)
	return re.ReplaceAllString(s, " ")
}

func (o *Orchestrator) toolDefs() []llm.ToolDef {
	obj := func(props map[string]any, required ...string) map[string]any {
		m := map[string]any{"type": "object", "properties": props}
		if len(required) > 0 {
			m["required"] = required
		}
		return m
	}
	str := func(desc string) map[string]any { return map[string]any{"type": "string", "description": desc} }
	arr := func(itemProps map[string]any, desc string) map[string]any {
		return map[string]any{"type": "array", "description": desc, "items": map[string]any{"type": "object", "properties": itemProps}}
	}
	// v5.3.6 注记：曾为 evidence_ids 增设的 arrStr（原始类型元素数组）随参数废弃移除。
	// 历史教训保留：对象数组助手 arr() 不得用于原始类型元素——items 被再包一层 object
	// 会产生裸字符串 schema 节点，严格校验的供应商直接 400 拒绝（v5.3.4 实证）。
	return []llm.ToolDef{
		{Name: "run_command", Description: "在项目工作区（bash）执行任意命令。命令将先做风险分级：只读侦察自动执行；写操作/高危命令需人工审批；破坏性命令被直接拒绝。", Parameters: obj(map[string]any{
			"command": str("要执行的 shell 命令"), "reason": str("执行原因（展示给审批人）"),
		}, "command", "reason")},
		{Name: "run_async", Description: "后台执行预计超过 10 分钟的长任务（全端口扫描/大词表枚举/批量验证）：立即返回 job id 不阻塞执行循环，期间继续其他子任务；用 poll_async 收结果。审批/留证与 run_command 同级；流水线结束或熔断时后台任务被强制清理。", Parameters: obj(map[string]any{
			"command": str("要后台执行的 shell 命令（输出重定向不必写，自动落 .async/job-<id>.log）"), "reason": str("执行原因（展示给审批人）"),
			"timeout": str("超时秒数，可空（默认 3600，上限 7200）"),
		}, "command", "reason")},
		{Name: "poll_async", Description: "查询后台任务：返回 running/finished/killed、退出码与输出尾部。仍在运行时继续其他工作，不要同步等待。", Parameters: obj(map[string]any{
			"job": str("run_async 返回的 job id"),
		}, "job")},
		{Name: "write_file", Description: "在项目工作区写入文件（PoC 脚本、笔记、报告等）。", Parameters: obj(map[string]any{
			"path": str("相对工作区路径"), "content": str("文件内容"),
		}, "path", "content")},
		{Name: "read_file", Description: "读取项目工作区文件。", Parameters: obj(map[string]any{"path": str("相对工作区路径")}, "path")},
		{Name: "list_files", Description: "列出工作区文件清单（含各阶段交付物），开工第一步先 list_files + read_file 承接上一阶段产出。", Parameters: obj(map[string]any{
			"dir": str("相对目录过滤，如 deliverables；可空"),
		})},
		{Name: "record_asset", Description: "登记资产到记忆库。", Parameters: obj(map[string]any{
			"type": str("类型：域名/IP/服务/AI应用/APP/小程序等"), "value": str("资产值"), "detail": str("详情"),
		}, "type", "value")},
		{Name: "record_finding", Description: "登记一条漏洞/风险。仅收录有证据支撑、有实际影响的漏洞（写明利用条件与影响）；侦察结论、无实际影响的观察写入交付物与时间线，不要调用本工具。高危项定级「确证」前必须 load_skill evidence-standard 对照该类判据并在 detail 引用判据项（反思门判据抽查：未引判据的高危确证会被引擎自动降级为疑似）。v5.3.6 契约：登记时提供 poc（实测的原始 HTTP 请求/响应对，Burp 式原文——你发出什么请求、收到什么响应，逐字誊写，≤5 组）与 remediation（修复建议：针对性修复措施+验证方法，面向修复方可执行）；证据编号由引擎自动关联，无需也无法显式提供。", Parameters: obj(map[string]any{
			"title": str("标题"), "severity": str("等级：高/中/低/信息"),
			"detail": str("漏洞详情：简单介绍该漏洞成因与影响面（复现过程由 poc 承载）"), "confidence": str("置信度：确证/疑似/待查"),
			"cwe":            str("标准编号（可选）：如 CWE-89 SQL 注入 / CWE-79 XSS / CWE-22 路径穿越 / CWE-98 CSRF；不确定则留空"),
			"access":         str("利用前提（可选，无凭证项目必标）：anonymous=匿名可利用 / pre-auth=需注册或低权 / post-auth=需认证后"),
			"impact_rank":    str("影响排序（可选，1-6）：1=RCE系 2=认证绕过/接管 3=SQLi可提数 4=SSRF可达元数据/内网 5=上传落点可控 6=其余；S5 按 rank 升序消费"),
			"exploitability": str("v4.6 E4 可利用性（可选）：verified（已实测利用）/ conditional（条件性，schema 未知等）/ untested（未投递）；高危+untested 会被引擎自动降级中级，实测后 update_finding 回写"),
			"claims":         arr(map[string]any{"file": str("证据文件相对路径（evidence/…）"), "must_contain": str("该文件中必须存在的判据串")}, "v4.6 E1 结论-证据判据串：确证 + 否定性/排他性断言（空、无、未暴露、被拒、0命中、全部000、不依赖、不存在、无差异、同文案）时必填；引擎逐条核验 file 存在且含 must_contain，未命中拒绝登记"),
			"remediation":    str("v5.3.6 修复建议：针对性修复措施（配置/代码/架构层面）+ 修复后验证方法，面向修复方可执行"),
			"poc":            arr(map[string]any{"request": str("原始 HTTP 请求文本（逐字誊写你发出的请求：方法行/头/体）"), "response": str("原始响应文本（逐字誊写收到的响应：状态行/头/体关键部分）")}, "v5.3.6 POC：实测请求/响应对（Burp 式原文，≤5 组）——登记前必须真实交互，禁止编造"),
		}, "title", "severity", "detail")},
		{Name: "update_finding", Description: "v4.6 B5 结论回写：修订已有发现的 severity/confidence/exploitability 或追加 detail（强制 reason，时间线留痕）。实测升级/降级、影响收窄后回写权威库——禁止只写进增量报告。v5.3.7：remediation 可补写/修订（修复建议缺失时补写，已有则追加）。", Parameters: obj(map[string]any{
			"id": str("record_finding 返回的 F- 编号"), "reason": str("修订依据（必填，含证据）"),
			"severity": str("新等级（可选）"), "confidence": str("新置信度（可选）"), "exploitability": str("verified/conditional/untested（可选）"),
			"detail_append": str("追加到 detail 的修订说明（可选）"),
			"remediation":   str("v5.3.7 修复建议（可选）：空缺时补写，已有则追加修订段"),
		}, "id", "reason")},
		{Name: "record_vt", Description: "v4.6 A2 验证队列：登记待验证项（线索→可调度资产）。脚本/PoC/参数字典就绪后立即登记（status=ready），S7 收口前必须逐条三选一处置。", Parameters: obj(map[string]any{
			"title": str("验证目标一句话"), "ready_assets": str("就绪资产路径（分号分隔）"), "start_conditions": str("启动条件"),
			"cost_note": str("预估成本（轮次/时间）"), "priority": str("1-6（对齐 impact-rank，可空）"), "status": str("pending/ready（默认 pending）"),
		}, "title")},
		{Name: "update_vt", Description: "v4.6 A2 验证队列流转：executed（已执行，附 result_ref）/ closed-roe（范围外，强制 note 理由）/ deferred（移交，强制 note + result_ref 写启动条件/步骤/工作量三要素）。", Parameters: obj(map[string]any{
			"id": str("record_vt 返回的 VT- 编号"), "status": str("executed/closed-roe/deferred"),
			"result_ref": str("结果/证据/移交位置"), "note": str("处置理由"),
		}, "id", "status")},
		{Name: "record_timeline", Description: "记录攻击时间线事件。", Parameters: obj(map[string]any{
			"event": str("事件名"), "detail": str("详情"),
		}, "event")},
		{Name: "request_approval", Description: "向人工发起专项审批（写操作/RCE/横向等高风险动作）。", Parameters: obj(map[string]any{
			"action": str("请求批准的动作描述"),
		}, "action")},
		{Name: "complete_stage", Description: "本阶段完成，提交收口。必须提供阶段摘要与交付物清单；s4/s5 还必须在调用参数中提供顶层字段 ready_but_unexecuted 与 l2_approved_unused（JSON 数组，无内容传空数组 []，不要只写进 summary 文本）。若收口提示存在 quality-pending 复核标记：先复核相关阶段交付物，确认无缺口后重新调用并传 \"confirm_quality_review\": true（引擎清除标记并继续收口）。", Parameters: obj(map[string]any{
			"summary": str("阶段摘要"), "deliverables": map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "交付物清单"},
			"ready_but_unexecuted":   map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "s4/s5 必填：有就绪脚本/PoC 而未投递的待验证项（每条含就绪资产路径与启动条件）；无内容传空数组 []"},
			"l2_approved_unused":     map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "s4/s5 必填：已批准但未使用的 L2 审批工单；无内容传空数组 []"},
			"confirm_quality_review": map[string]any{"type": "boolean", "description": "v5.3.8（仅 s8 需要时）：收口提示存在 quality-pending 复核标记时，复核相关阶段交付物后传 true——引擎清除标记并继续收口"},
		}, "summary", "deliverables")},
		{Name: "loopback", Description: "发现新攻击面需要前置阶段补充分析时触发回环（如回退到 s4 漏洞发现）。", Parameters: obj(map[string]any{
			"to_stage": str("目标阶段 id，如 s4"), "reason": str("回环原因"),
		}, "to_stage", "reason")},
		{Name: "plan_subtasks", Description: "把本阶段工作拆解为可跟踪的子任务计划（全量重建）。开工后第一步建议先建立 3-8 项子任务，随执行用 update_subtask 同步状态。", Parameters: obj(map[string]any{
			"items": map[string]any{"type": "array", "description": "子任务数组，每项 {\"title\":\"…\",\"detail\":\"…\"}", "items": map[string]any{"type": "object"}},
		}, "items")},
		{Name: "update_subtask", Description: "同步子任务进度：status ∈ created/running/waiting/finished/failed；finished 必须带 result 摘要。", Parameters: obj(map[string]any{
			"id": str("子任务 id（见上下文包子任务计划）"), "status": str("目标状态"), "result": str("结果摘要（finished 时必填）"),
		}, "id", "status")},
		{Name: "consult_expert", Description: "向专项专家做单次深度会诊（adviser 导师/pentester 渗透/coder 开发/searcher 情报/reflector 审查/reporter 报告）。卡壳、需要第二意见或专业方案时调用。", Parameters: obj(map[string]any{
			"role": str("专家角色：adviser/pentester/coder/searcher/reflector/reporter"), "question": str("要咨询的问题（含必要的上下文与目标）"),
		}, "role", "question")},
		{Name: "request_user_input", Description: "需要人工决策/二选一路线/非敏感信息补充时向用户提问，挂起等待回答后继续。⚠ 禁止用于索取凭据（密码/令牌/口令/Cookie）——回答会明文落库；凭据索取必须用 request_credential 专用通道（原文加密入库不落明文）。", Parameters: obj(map[string]any{
			"question": str("要问用户的问题（具体、可一句话回答）"),
		}, "question")},
		{Name: "install_tool", Description: "环境中缺失某个安全工具时自动安装（通道优先级：Kali apt 官方源 → pip 清华源 → git 源码 github/gitee 双源；v5.7.2 起每条通道国内源直连优先、github 等国外源代理优先，主路径失败自动以反向路径兜底——Kali 仓库数千款渗透工具均可装）。当 run_command 返回 command not found（退出码127）时调用本工具，安装成功后直接重试原命令；安装失败则改用已有工具并如实说明。", Parameters: obj(map[string]any{
			"name": str("工具名（如 sqlmap/whatweb/hydra）"), "purpose": str("一句话说明为什么需要它（写入审批与时间线留痕）"),
		}, "name", "purpose")},
		{Name: "load_skill", Description: "按 id 或关键词从技能库载入攻击剧本/清单（注入本次对话），先查技能再动手。", Parameters: obj(map[string]any{
			"id": str("技能 id（可选）"), "query": str("关键词（可选，如 越权/LLM01/nmap 用法）"),
		})},
		{Name: "update_coverage", Description: "更新覆盖度矩阵（每测完一个 endpoint×参数×漏洞类单元必调）：status ∈ vulnerable/no_issue_found/ruled_out/waf_blocked/skipped/needs_follow_up；ruled_out 与 needs_follow_up 必须填 notes 证据。v4.6 E3：ruled_out/no_issue_found 必须同时传 observed_result=negative_valid（有有效请求/响应原文支撑的真阴性）——缺失会被自动降级 needs_follow_up；超时/阻断/未测试类观测只能落 needs_follow_up。", Parameters: obj(map[string]any{
			"endpoint": str("如 GET /api/user；无 HTTP 语境填目标名"), "param": str("参数名，可空"),
			"vuln_class": str("漏洞类：注入/XSS/越权/认证/SSRF/LLM01提示注入 等"), "status": str("见上述枚举"),
			"notes":           str("证据摘要（必填于 ruled_out/needs_follow_up）"),
			"observed_result": str("v4.6 E3 负结果语义：negative_valid（真阴性）/undetermined_timeout/blocked_ratelimit/blocked_waf/not_tested；ruled_out 与 no_issue_found 必传 negative_valid"),
		}, "endpoint", "vuln_class", "status")},
		{Name: "search_memory", Description: "关键词检索项目记忆库（漏洞/资产/时间线），避免重复劳动。", Parameters: obj(map[string]any{
			"query": str("关键词"),
		}, "query")},
		{Name: "hexstrike_command", Description: "经 hexstrike-ai 网关执行安全工具（150+ 工具远端可用）；同样受审批矩阵约束。未配置网关时改用 run_command。", Parameters: obj(map[string]any{
			"command": str("工具命令行"), "reason": str("执行原因"),
		}, "command", "reason")},
		// ---- v3.3.0 项目黑板 / 战利品库 / 交互会话 ----
		{Name: "upsert_fact", Description: "把可复用的结构化事实写入项目黑板（幂等，同 key 覆盖）：服务指纹、接口行为、凭据存在性、绕过路径、组件版本等。confidence ∈ confirmed（有证据）/ tentative（线索）/ deprecated（已排除或误报——负结果也必须落库，防止后续重复试错）。同一事实有新证据时再次调用即更新。", Parameters: obj(map[string]any{
			"key":        str("事实键，如 http://target:8080/login 或 svc.db.mysql.cred"),
			"value":      str("事实内容（发现按能力原语标注，如 primitive:CRED + 说明）"),
			"confidence": str("confirmed/tentative/deprecated，默认 tentative"),
			"links":      str("关联事实键或发现 ID，逗号分隔（凑链图边，可选）"),
			"note":       str("证据摘要或排除原因（可选）"),
		}, "key", "value")},
		{Name: "record_loot", Description: "登记战利品（凭据/票据/flag/hash/cookie/token/key/session）的掩码摘要与来源位置，供 S5/S6 横向复用。只存掩码（如 adm***23），禁止存明文；verified ∈ unverified/verified/invalid。", Parameters: obj(map[string]any{
			"type":     str("credential/flag/hash/token/cookie/key/session"),
			"target":   str("归属目标（主机/服务/账号）"),
			"masked":   str("掩码摘要（必填，禁止明文）"),
			"source":   str("来源位置（路径/接口/转储文件）"),
			"verified": str("unverified/verified/invalid，默认 unverified"),
		}, "type", "target", "masked")},
		{Name: "shell_open", Description: "打开持久交互会话（审批与 run_command 同级）：适用于 mysql/redis-cli/ssh -T/nc 监听/长驻脚本等需要多轮交互的场景。stdin 管道无 TTY；readline 类工具（msfconsole）改用 run_command 脚本化，Python 加 -u。", Parameters: obj(map[string]any{
			"command": str("启动会话的命令"), "reason": str("执行原因（展示给审批人）"),
		}, "command", "reason")},
		{Name: "shell_write", Description: "向交互会话注入输入（enter 默认自动补换行）。", Parameters: obj(map[string]any{
			"session": str("shell_open 返回的 session id"), "input": str("要写入的内容"),
			"enter": str("是否自动补换行，默认 true；传 \"false\" 不补"),
		}, "session", "input")},
		{Name: "shell_read", Description: "增量读取会话自上次读取后的新输出（至多 8KB/次）。", Parameters: obj(map[string]any{
			"session": str("session id"),
		}, "session")},
		{Name: "shell_close", Description: "关闭交互会话（进程组终止）。收口前必须关闭全部会话（引擎在流水线结束/熔断时也会强制清理）。", Parameters: obj(map[string]any{
			"session": str("session id"),
		}, "session")},
		{Name: "record_lesson", Description: "登记组织级教训（跨项目复用，自动脱敏校验）：本次任务中什么打法有效/无效、什么坑要避开。必须去标识化——禁止目标域名/IP/单位名/真实凭据，写通用经验。收口前或关键失败复盘时调用。", Parameters: obj(map[string]any{
			"text": str("一句话教训（脱敏）"), "tags": str("类别标签，如 方法论/工具/风控/报告"),
		}, "text")},
		// ---- v3.6.0 阶段内并行扇出 ----
		{Name: "spawn_subagent", Description: "把相互独立的测试单元派发给并行子代理（如：3 个 endpoint×漏洞类单元同时测）。子代理有独立轮次预算与受限工具面，共享黑板/覆盖矩阵/审批矩阵；主头继续其他工作，用 poll_subagents 收结果。收口前必须确认全部子代理已结束。", Parameters: obj(map[string]any{
			"objective": str("测试单元目标（一句话：目标×漏洞类×成功判据）"),
			"rounds":    str(fmt.Sprintf("轮次预算，可空（默认 engine.max_subagent_rounds=%d，上限 %d）", o.cfg.Engine.MaxSubagentRounds, subagentRoundsCap)),
		}, "objective")},
		{Name: "poll_subagents", Description: "收取子代理结果：运行中的报进度，已结束的报简报（结果已实时入黑板/覆盖矩阵/发现库）。", Parameters: obj(map[string]any{})},
		// ---- v5.5.0 结构化凭据仓库与带态注入（修复方案 A：有凭证深度测试的地基）----
		{Name: "store_credential", Description: "把凭据（令牌/口令/Cookie/会话）录入加密凭据仓库（AES-256-GCM 静态加密；日志/证据/回执全程只显掩码，明文不落库）。多身份测试（角色矩阵）必须逐身份录入——同一身份的多个会话用 identity 命名区分（如 operator/session-2）。向用户索取凭据时优先用 request_credential 专用通道（回答不落明文）。", Parameters: obj(map[string]any{
			"identity":       str("身份名（必填，如 operator/viewer/admin；多会话用 operator/session-2）"),
			"kind":           str("凭据类型：bearer/token/basic/cookie/header（header 时 secret 为完整 \"Name: value\"）"),
			"secret":         str("凭据明文（仅入库瞬间存在，落库即密文；禁止在其他工具参数/文本中复写）"),
			"target":         str("归属目标（主机/URL/账号；记录后凭据将绑定该 host，http_request 跨 host 使用会被拒绝）"),
			"role":           str("角色标注（可空，如 admin/user）"),
			"username":       str("用户名（basic 场景必填，可空）"),
			"source_loot_id": str("关联 Loot 编号（可空）"),
			"origin":         str("来源：real（默认，客户提供真实凭据）/forged（伪造构造，如 JWT none/alg 混淆产物）/derived（由真实凭据推导还原）"),
			"parent_id":      str("父凭据 cred-<id>（forged/derived 时填写，构成来源谱系）"),
			"method":         str("伪造/派生方法（forged/derived 时填写，如 jwt-none、alg-confusion、cookie-forge、token-relay）"),
		}, "identity", "kind", "secret")},
		{Name: "request_credential", Description: "v5.6.0 凭据专用索取通道：向用户索取凭据时必须用本工具而非普通提问——用户回答的原文经内存直入加密仓库（AskRecord/执行流/回执只含掩码，全程不落明文）。basic 凭据用户粘贴 `用户名:口令`，header 凭据粘贴 `头名: 头值`，其余直接粘贴原文。", Parameters: obj(map[string]any{
			"question": str("索取说明（为什么需要、用于哪个身份/场景）"),
			"identity": str("身份名（入库用，如 operator）"),
			"kind":     str("bearer/token/basic/cookie/header"),
			"target":   str("归属目标（可空；建议填写，绑定 host）"),
			"role":     str("角色标注（可空）"),
			"username": str("用户名提示（basic 场景可空——用户粘贴串里带）"),
			"origin":   str("real/forged/derived（可空默认 real）"),
		}, "question", "identity", "kind")},
		{Name: "list_credentials", Description: "列出本项目已入库凭据（掩码投影，明文不可检索）。authz-diff/api-idor 角色矩阵开工前先调用本工具盘点可用身份。", Parameters: obj(map[string]any{})},
		{Name: "revoke_credential", Description: "撤销一条凭据（后续注入直接拒绝；测试结束/凭据失效时调用）。", Parameters: obj(map[string]any{
			"id": str("cred- 编号"),
		}, "id")},
		{Name: "http_request", Description: "结构化 HTTP 请求工具（带态测试首选）：auth_ref 注入 Authorization/Cookie 后发送；治理/审批/留证与 run_command 同级（写方法至少 L1）。请求行/响应头/body 落证据（凭据掩码）；大响应自动溢出落盘。角色矩阵对比 = 对同一请求切换 auth_ref 分别发送再 diff。", Parameters: obj(map[string]any{
			"url":      str("完整 URL（http/https）"),
			"method":   str("GET/POST/PUT/DELETE/PATCH/HEAD/OPTIONS，默认 GET"),
			"headers":  map[string]any{"type": "object", "description": "附加请求头（JSON 对象，如 {\"Content-Type\":\"application/json\"}）", "additionalProperties": map[string]any{"type": "string"}},
			"body":     str("请求体（可空）"),
			"auth_ref": str("凭据引用：cred-<id> 或 identity:<身份名>（可空=匿名请求）"),
			"timeout":  str("超时秒数（默认 30，上限 300）"),
		}, "url")},
		{Name: "cred_command", Description: "带凭据命令模板执行：模板中用 ${CRED_USERNAME}/${CRED_SECRET}/${CRED_TOKEN}/${CRED_PASSWORD} 占位（hydra/curl/ffuf 等命令行工具带凭据时使用）。占位符用裸形态或整段单引号形态（'${CRED_SECRET}'）；禁止把占位符写在含其他内容的单引号串内（引擎会确定性拒绝——单引号内命令替换不生效）。密文经临时文件中介注入，命令文本/审批/证据/日志全程无明文，执行后临时文件即删。治理与审批与 run_command 完全同级。", Parameters: obj(map[string]any{
			"template":       str("命令模板（含 ${CRED_*} 占位符，如 hydra -l ${CRED_USERNAME} -p ${CRED_SECRET} …）"),
			"credential_ref": str("凭据引用：cred-<id> 或 identity:<身份名>"),
			"reason":         str("执行原因（展示给审批人）"),
		}, "template", "credential_ref", "reason")},
	}
}

// ---------- 工具函数 ----------

func (o *Orchestrator) log(p *store.Project, stage, text string) {
	o.bus.Publish(p.ID, "log", map[string]string{"stage": stage, "text": text, "ts": time.Now().Format("15:04:05")})
	_, _ = o.store.AddStream(p.ID, &store.StreamRecord{Kind: "log", Stage: stage, Text: text})
}

// accountUsage 记账（deadend SessionMetrics 移植）：按阶段分账 + 估算成本 + 预算累计。
func (o *Orchestrator) accountUsage(p *store.Project, stage string, u llm.Usage) {
	total := int64(u.TotalTokens)
	if total <= 0 {
		return
	}
	if rec, err := o.store.AddUsage(p.ID, stage, int64(u.PromptTokens), int64(u.CompletionTokens)); err == nil {
		o.bus.Publish(p.ID, "usage", rec)
	}
	o.mu.Lock()
	o.tokens[p.ID] += total
	o.mu.Unlock()
}

func (o *Orchestrator) projectTokens(projectID string) int64 {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.tokens[projectID]
}

// exportArtifacts 结项导出（strix/shannon 移植）：findings.json + findings.sarif 2.1.0。
func (o *Orchestrator) exportArtifacts(p *store.Project) {
	// v3.4.1 修复：攻击路径缝合器不再被「无漏洞早退」挡住——只有黑板事实/战利品
	// 而暂无 findings 的项目（如情报链完备、利用队列待验证）同样需要攻击图。
	if dot, md := o.buildAttackGraph(p); dot != "" {
		_, _ = o.exec.WriteFile(p.ID, "deliverables/attack-graph.dot", dot)
		_, _ = o.exec.WriteFile(p.ID, "deliverables/attack-graph.md", md)
		// v3.7.0：graphviz 可用时同步渲染 SVG（报告页直接嵌入；不可用则静默跳过，UI 回退 md）
		if dotPath, err := exec.LookPath("dot"); err == nil {
			ctxDot, cancelDot := context.WithTimeout(context.Background(), 20*time.Second)
			cmdDot := exec.CommandContext(ctxDot, dotPath, "-Tsvg")
			cmdDot.Stdin = strings.NewReader(dot)
			svg, rerr := cmdDot.Output()
			cancelDot()
			if rerr == nil && len(svg) > 0 {
				_, _ = o.exec.WriteFile(p.ID, "deliverables/attack-graph.svg", string(svg))
			}
		}
		o.log(p, "", "🕸 已生成攻击路径图 deliverables/attack-graph.dot|.md")
	}
	findings, err := o.store.ListFindings(p.ID)
	if err != nil || len(findings) == 0 {
		return
	}
	fj, _ := json.MarshalIndent(findings, "", "  ")
	_ = os.WriteFile(filepath.Join(o.cfg.DataDir, p.ID, "findings.json"), fj, 0o640)

	type sarifLoc struct {
		PhysicalLocation struct {
			ArtifactLocation struct {
				URI string `json:"uri"`
			} `json:"artifactLocation"`
		} `json:"physicalLocation"`
	}
	type sarifResult struct {
		RuleID  string `json:"ruleId"`
		Level   string `json:"level"`
		Message struct {
			Text string `json:"text"`
		} `json:"message"`
		Locations  []sarifLoc     `json:"locations"`
		Properties map[string]any `json:"properties,omitempty"`
	}
	var results []sarifResult
	for _, f := range findings {
		lvl := "note"
		if f.Severity == "高" {
			lvl = "error"
		} else if f.Severity == "中" {
			lvl = "warning"
		}
		r := sarifResult{RuleID: f.ID, Level: lvl, Properties: map[string]any{"severity": f.Severity, "confidence": f.Confidence, "stage": f.Stage}}
		r.Message.Text = f.Title + "：" + f.Detail
		var loc sarifLoc
		loc.PhysicalLocation.ArtifactLocation.URI = f.Stage
		r.Locations = []sarifLoc{loc}
		results = append(results, r)
	}
	sarif := map[string]any{
		"version": "2.1.0",
		"$schema": "https://json.schemastore.org/sarif-2.1.0.json",
		"runs": []any{map[string]any{
			"tool":    map[string]any{"driver": map[string]any{"name": "九头鸟（鬼車）", "version": "1.1.0", "informationUri": "https://github.com/DaoYiSec"}},
			"results": results,
		}},
	}
	sb, _ := json.MarshalIndent(sarif, "", "  ")
	_ = os.WriteFile(filepath.Join(o.cfg.DataDir, p.ID, "findings.sarif"), sb, 0o640)
	o.log(p, "", fmt.Sprintf("📦 已导出 findings.json / findings.sarif（%d 条漏洞）", len(findings)))
}

// buildAttackGraph 从黑板事实与战利品构建攻击图：节点=事实键/战利品，边=links/凭据复用。
// 返回（DOT 空串表示无图可画）。确定性纯函数，便于单测。
func (o *Orchestrator) buildAttackGraph(p *store.Project) (string, string) {
	facts, _ := o.store.ListFacts(p.ID, 0)
	if len(facts) == 0 {
		return "", ""
	}
	node := func(k string) string {
		k = strings.ReplaceAll(k, `"`, `'`)
		return k
	}
	var b strings.Builder
	b.WriteString("digraph attack {\n  rankdir=LR;\n  node [shape=box, style=rounded, fontname=\"sans\"];\n")
	seen := map[string]bool{}
	entries := 0
	var edges []string
	for _, f := range facts {
		if seen[f.Key] {
			continue
		}
		seen[f.Key] = true
		color := "black"
		if f.Confidence == "confirmed" {
			color = "darkgreen"
		} else if f.Confidence == "deprecated" {
			color = "gray"
		}
		fmt.Fprintf(&b, "  %q [label=\"%s\\n[%s]\", color=\"%s\"];\n", node(f.Key), node(truncateText(f.Value, 60)), f.Confidence, color)
		entries++
		for _, l := range f.Links {
			if strings.TrimSpace(l) == "" {
				continue
			}
			edges = append(edges, fmt.Sprintf("  %q -> %q;\n", node(f.Key), node(l)))
			if !seen[l] {
				seen[l] = true
				fmt.Fprintf(&b, "  %q [label=\"%s\"];\n", node(l), node(l))
				entries++
			}
		}
	}
	loots, _ := o.store.ListLoot(p.ID, 0)
	for _, l := range loots {
		if l.Verified == "invalid" {
			continue
		}
		key := "loot:" + l.Target
		if !seen[key] {
			seen[key] = true
			fmt.Fprintf(&b, "  %q [label=\"战利品 %s\\n%s [%s]\", shape=note];\n", node(key), node(l.Target), node(l.Masked), l.Verified)
			entries++
		}
		if strings.TrimSpace(l.Source) != "" && seen[l.Source] {
			edges = append(edges, fmt.Sprintf("  %q -> %q [label=\"凭据复用\", style=dashed];\n", node(l.Source), node(key)))
		}
	}
	for _, e := range edges {
		b.WriteString(e)
	}
	b.WriteString("}\n")
	if entries == 0 {
		return "", ""
	}
	var m strings.Builder
	m.WriteString(fmt.Sprintf("# 攻击路径图（%d 节点）\n\n> 由黑板事实（links=边）与战利品（凭据复用=虚线边）确定性缝合；DOT 源文件：attack-graph.dot，可用 graphviz 渲染。\n\n", entries))
	for _, e := range edges {
		m.WriteString("- " + strings.NewReplacer("\"", "", "  ", "", "->", "→", ";", "").Replace(strings.TrimSpace(e)) + "\n")
	}
	if len(loots) > 0 {
		m.WriteString("\n## 战利品节点\n")
		for _, l := range loots {
			m.WriteString(fmt.Sprintf("- [%s/%s] %s @ %s（来源 %s）\n", l.Type, l.Verified, l.Masked, l.Target, truncateText(l.Source, 80)))
		}
	}
	return b.String(), m.String()
}

// ---------- v4.8 W4 身份获取六轨编排（引擎编排层：逐轨 VT 化 + 移交链完整性） ----------

// loginSurfaceRe 登录面资产特征（资产类型/值/详情任一命中）。
var loginSurfaceRe = regexp.MustCompile(`(?i)登录|login|后台|admin|sso|auth`)

// loginSurfacePresent 项目是否登记过登录面资产（无面不编造——与筛查矩阵口径一致）。
func (o *Orchestrator) loginSurfacePresent(p *store.Project) bool {
	assets, _ := o.store.ListAssets(p.ID)
	for _, a := range assets {
		if loginSurfaceRe.MatchString(a.Type + " " + a.Value + " " + a.Detail) {
			return true
		}
	}
	return false
}

// sessionObtained 战利品中是否存在已验证的会话/凭据类条目（首轨命中的机器可判信号）。
func (o *Orchestrator) sessionObtained(p *store.Project) bool {
	loots, _ := o.store.ListLoot(p.ID, 50)
	for _, l := range loots {
		if l.Verified == "verified" {
			switch l.Type {
			case "credential", "session", "cookie", "token", "key":
				return true
			}
		}
	}
	return false
}

// w4Tracks 六轨定义（title 前缀 [W4-Ln] 为 VT 登记协议）。
var w4Tracks = []string{"L1 注册面", "L2 泄露面", "L3 默认口令", "L4 验证码逻辑", "L5 令牌伪造", "L6 会话构造"}

// identityTrackIssues v4.8 W4 s4 收口门：无凭证且存在登录面时，身份获取六轨必须逐轨 VT 留痕。
// 口径：已获身份（verified loot / v5.6.0 凭据仓库 active）只需首轨 VT 留痕；未获身份需六轨全量登记（不适用轨也登记，
// start_conditions 注明「无对应面」——与筛查矩阵三态口径一致），保证全轨失败时移交链完整。
// v5.6.0（审计修复）：①状态判据升级为 projectHasIdentity（凭据仓库 active 不再被当 S0）；
// ②六轨 VT 不仅要求存在，还必须处置（executed/closed-roe/deferred）——审计实证：引擎此前只查标题，
// 记一条 pending VT 即满足存在性，失败原因/移交四元组从不被校验。
func (o *Orchestrator) identityTrackIssues(p *store.Project, stageID string) []string {
	// v5.6.0：AuthInfo（legacy 有凭证）或无登录面 → 不适用；注意 verified loot / 凭据仓库
	// active 属「已获身份但仍需首轨留痕」口径，不能在此早退（v48 实测回归）。
	if strings.TrimSpace(p.AuthInfo) != "" || !o.loginSurfacePresent(p) {
		return nil
	}
	vts, _ := o.store.ListVTs(p.ID)
	registered := map[string]bool{}
	undisposed := map[string]bool{}
	for _, t := range vts {
		for _, tk := range w4Tracks {
			id := strings.Split(tk, " ")[0]
			if strings.Contains(t.Title, "[W4-"+id+"]") {
				registered[id] = true
				if t.Status != "executed" && t.Status != "closed-roe" && t.Status != "deferred" {
					undisposed[id] = true
				}
			}
		}
	}
	// v5.6.0（审计修复）：已获身份口径扩展——verified loot ∪ 凭据仓库 active 记录。
	if o.hasActiveCredentials(p) || o.sessionObtained(p) {
		if len(registered) == 0 {
			return []string{"v4.8 W4：身份已获取但六轨尝试无 VT 留痕——首轨命中也应 record_vt 登记（title 前缀 [W4-Ln]），供审计与跨任务复用"}
		}
		return undisposedIssues(undisposed)
	}
	var missing []string
	for _, tk := range w4Tracks {
		if !registered[strings.Split(tk, " ")[0]] {
			missing = append(missing, tk)
		}
	}
	if len(missing) > 0 {
		return []string{fmt.Sprintf("v4.8 W4：无凭证且存在登录面，身份获取六轨未逐轨 VT 登记（缺 %s）——按 identity-bootstrapping 逐轨尝试并 record_vt（title 前缀 [W4-L1]..[W4-L6]；不适用轨也登记并在 start_conditions 注明「无对应面」），保证全轨失败时 VT 移交链完整",
			truncateText(strings.Join(missing, "、"), 120))}
	}
	// v5.6.1（审计缺陷#4）：降级四通道机械门——六轨闭环后仍须 [W4-DG] VT 登记
	// observable-degradation 四通道（可观测降级/浏览器代执行/身份复用面/索取复访）逐项评估留痕
	dgRegistered := false
	for _, t := range vts {
		if strings.Contains(t.Title, "[W4-DG]") {
			dgRegistered = true
			break
		}
	}
	if !dgRegistered {
		return []string{"v4.8 W4：六轨已闭环但缺 [W4-DG] 降级四通道评估 VT——按 observable-degradation 对四通道（可观测降级证据/浏览器代执行/身份复用面/索取复访）逐项评估并 record_vt（title 含 [W4-DG]），全部不适用也要登记说明"}
	}
	return undisposedIssues(undisposed)
}

// undisposedIssues v5.6.0：六轨 VT 未处置（pending/ready）的收口问题。
func undisposedIssues(undisposed map[string]bool) []string {
	if len(undisposed) == 0 {
		return nil
	}
	ids := make([]string, 0, len(undisposed))
	for id := range undisposed {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return []string{fmt.Sprintf("v4.8 W4：六轨 VT 已登记但未处置（pending/ready：%s）——每轨必须 update_vt 三选一处置（executed 附 result_ref / closed-roe 附理由 / deferred 附移交三要素），失败原因与移交四元组随处置落库，收口前逐轨闭环",
		strings.Join(ids, ","))}
}

// deterministicGate 确定性质量门（v3.4.0）：反思门 LLM 不可用时的硬校验兜底。
// 返回问题清单；空=通过。
// deliverablesText v4.4 批次6：读取 deliverables/ 下全部文本文件拼接（S4 分段收口对账语料，
// 含待续清单/档案目标/分组交付物）。上限 30 个文件——对账够用，防大文件拖慢收口。
func (o *Orchestrator) deliverablesText(projectID string) string {
	names, err := o.exec.ListDir(projectID, "deliverables")
	if err != nil || len(names) == 0 {
		return ""
	}
	var b strings.Builder
	n := 0
	for _, rel := range names {
		if n >= 30 {
			break
		}
		if !strings.HasSuffix(rel, ".md") && !strings.HasSuffix(rel, ".txt") && !strings.HasSuffix(rel, ".json") {
			continue
		}
		if raw, rerr := o.exec.ReadFile(projectID, rel); rerr == nil {
			b.WriteString(raw)
			b.WriteString("\x00")
			n++
		}
	}
	return b.String()
}

// ---------- v4.8 批2 确定性门（M2 筛查矩阵判定表 / M4 交付物时间窗） ----------

// matrixClassRe 筛查矩阵判定表行首列：C-<两位编号>（C-01..C-27）。
var matrixClassRe = regexp.MustCompile(`^\|\s*(C-\d{2})\s*\|`)

// matrixVerdictRe 三态判定格：恰为 假设/不适用/待判定 之一的表格单元格。
var matrixVerdictRe = regexp.MustCompile(`\|\s*(假设|不适用|待判定)\s*\|`)

// matrixTotalClasses 筛查矩阵类数（v4.8 §一 27 类）。
const matrixTotalClasses = 27

// matrixTableIssues v4.8 M2 s3 收口门：判定表存在且 27 行三态留痕完整。
// 口径：只查留痕不查内容——不检查假设关键词命中，杜绝诱导式编造。
func (o *Orchestrator) matrixTableIssues(p *store.Project) []string {
	raw, err := o.exec.ReadFile(p.ID, "deliverables/s3-筛查矩阵判定表.md")
	if err != nil {
		return []string{"v4.8 M2：缺少《筛查矩阵判定表》deliverables/s3-筛查矩阵判定表.md——load_skill hypothesis-matrix 按 27 类逐类三态判定后重写并重新收口（判定基于既有证据，零新增主动流量）"}
	}
	found := map[string]bool{}
	for _, line := range strings.Split(raw, "\n") {
		if m := matrixClassRe.FindStringSubmatch(line); m != nil {
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
		return []string{fmt.Sprintf("v4.8 M2：判定表缺 %d 行三态留痕（%s）——27 类逐类补判定（假设/不适用/待判定 + 证据指针，无对应面输出「不适用」+核查证据，不许编造）",
			len(missing), truncateText(strings.Join(missing, ","), 140))}
	}
	noVerdict := 0
	for _, line := range strings.Split(raw, "\n") {
		if matrixClassRe.MatchString(line) && !matrixVerdictRe.MatchString(line) {
			noVerdict++
		}
	}
	if noVerdict > 0 {
		return []string{fmt.Sprintf("v4.8 M2：判定表 %d 行无三态判定格（判定列应为 | 假设 | / | 不适用 | / | 待判定 | 之一）——补判定后重新收口", noVerdict)}
	}
	return nil
}

// deliverableDateRe v4.8 M4 日期字段：标签（测试/执行/报告/评估/任务/收口/开工/结束）+ 日期。
// 只查带标签的日期字段，不扫自由文本——避免误伤 CVE/证书等历史日期引用。
var deliverableDateRe = regexp.MustCompile(`(测试|执行|报告|评估|任务|收口|开工|结束)(日期|时间)[：:]\s*(\d{4})[-/年](\d{1,2})[月/-](\d{1,2})`)

// v5.1.3 修复⑤：年份级日期幻觉补拦（实战监控实证 S1 交付物「日期：2025（本阶段执行日）」
// 漏过完整日期正则）——标签后仅跟 4 位年份同样入窗校验；后随字符须为非数字（防误吃紧凑形态）。
var deliverableYearRe = regexp.MustCompile(`(测试|执行|报告|评估|任务|收口|开工|结束)(日期|时间)[：:]\s*((?:20|19)\d{2})([^\d\-/年月]|$)`)

// deliverableDateIssues v4.8 M4：交付物日期字段必须落在任务时间窗内（防日期幻觉）。
// 时间窗 = [项目启动日（无启动记录用创建日）, 今天]。逐交付物文件 + report.md 扫描。
func (o *Orchestrator) deliverableDateIssues(p *store.Project) []string {
	if o.cfg == nil { // 测试装配/降级态：工作区根不可得，M4 跳过（确定性门其余检查照常）
		return nil
	}
	start := time.Now()
	if p.StartedAt != "" {
		if t, err := time.Parse(time.RFC3339, p.StartedAt); err == nil {
			start = t
		}
	} else if !p.CreatedAt.IsZero() {
		start = p.CreatedAt
	}
	startDay := time.Date(start.Year(), start.Month(), start.Day(), 0, 0, 0, 0, time.Local)
	now := time.Now()
	today := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.Local)
	atoi := func(s string) int {
		n, _ := strconv.Atoi(strings.TrimSpace(s))
		return n
	}
	var issues []string
	scanText := func(path, content string) {
		for _, m := range deliverableDateRe.FindAllStringSubmatch(content, -1) {
			d := time.Date(atoi(m[3]), time.Month(atoi(m[4])), atoi(m[5]), 0, 0, 0, 0, time.Local)
			if d.Before(startDay) {
				issues = append(issues, fmt.Sprintf("v4.8 M4：%s 日期字段「%s%s: %04d-%02d-%02d」早于任务开始（%s）——日期幻觉，改为任务时间窗内的真实日期",
					path, m[1], m[2], atoi(m[3]), atoi(m[4]), atoi(m[5]), startDay.Format("2006-01-02")))
			} else if d.After(today) {
				issues = append(issues, fmt.Sprintf("v4.8 M4：%s 日期字段「%s%s」晚于今天（%s）——未来日期幻觉，改为真实日期",
					path, m[1], m[2], today.Format("2006-01-02")))
			}
		}
		// v5.1.3 修复⑤：年份级日期入窗校验
		for _, m := range deliverableYearRe.FindAllStringSubmatch(content, -1) {
			y := atoi(m[3])
			if y < startDay.Year() || y > today.Year() {
				issues = append(issues, fmt.Sprintf("v4.8 M4：%s 年份级日期「%s%s: %d」落在任务时间窗（%d-%d 年）之外——日期幻觉，改为真实日期",
					path, m[1], m[2], y, startDay.Year(), today.Year()))
			}
		}
	}
	files, _ := o.listWorkspaceFiles(p.ID, "deliverables")
	for _, f := range files {
		if !strings.HasSuffix(f.Path, ".md") && !strings.HasSuffix(f.Path, ".txt") {
			continue
		}
		if raw, err := o.exec.ReadFile(p.ID, f.Path); err == nil {
			scanText(f.Path, raw)
		}
		if len(issues) >= 5 {
			break // 最多报 5 条，防刷屏
		}
	}
	if raw, err := o.exec.ReadFile(p.ID, "report.md"); err == nil {
		scanText("report.md", raw)
	}
	return issues
}

// evidenceCriteriaIssues v4.4 批次4 反思门判据抽查（确定性规则，非 LLM）：// 本阶段「高危+确证」发现若 detail 未引用 evidence-standard 判据（技能名或「判据」字样），
// 引擎直接降级为疑似并在 detail 注明补证路径——把「LLM 觉得打到了」挡在利用队列与报告之外。
// 合规路径：loop-core 纪律 12 要求确证前对照 evidence-standard 并在 detail 引用判据项。
func (o *Orchestrator) evidenceCriteriaIssues(p *store.Project, stageID string) []string {
	var issues []string
	findings, _ := o.store.ListFindings(p.ID)
	for _, f := range findings {
		if f.Stage != stageID || !evidenceCriteriaMissing(f) {
			continue
		}
		f.Confidence = "疑似"
		f.Detail += "\n【引擎降级 v4.4】高危确证未引用 evidence-standard 判据——load_skill evidence-standard 对照该类判据补证（孪生对比/双主体差异/三重时延取中位等对照实验）后，在 detail 引用判据项可重新确证。"
		if uerr := o.store.UpdateFinding(f); uerr == nil {
			if o.bus != nil {
				o.bus.Publish(p.ID, "finding", f)
				o.log(p, stageID, "⚖ 判据抽查降级："+truncateText(f.Title, 40)+"（确证→疑似，未引 evidence-standard 判据）")
			}
			issues = append(issues, fmt.Sprintf("高危确证发现「%s」未引用 evidence-standard 判据，已自动降级为疑似——补证（detail 引用判据项）后重新登记确证", truncateText(f.Title, 40)))
		}
	}
	// v5.4.3 B：本阶段覆盖台账自描述核对——名下结论态条目 notes 为空 → 拦截（入口拒收的收口兜底）。
	// 只核对本收口阶段名下的条目：跨阶段历史条目不在本门范围（避免旧数据连坐阻断）。
	if cov, cerr := o.store.ListCoverage(p.ID); cerr == nil {
		emptyNote := 0
		for _, c := range cov {
			if c.Stage != stageID {
				continue
			}
			if (c.Status == "vulnerable" || c.Status == "ruled_out" || c.Status == "no_issue_found" || c.Status == "needs_follow_up") &&
				strings.TrimSpace(c.Notes) == "" {
				emptyNote++
			}
		}
		if emptyNote > 0 {
			issues = append(issues, fmt.Sprintf("本阶段覆盖台账 %d 个结论态条目 notes 为空（台账自描述契约 v5.4.3）——用 update_coverage 逐条补一句话依据（证据摘要/命令/观察结果）后重新收口", emptyNote))
		}
	}
	return issues
}

func (o *Orchestrator) deterministicGate(p *store.Project, stageID string) []string {
	var issues []string
	findings, _ := o.store.ListFindings(p.ID)
	stageFindings := 0
	for _, f := range findings {
		if f.Stage == stageID {
			stageFindings++
			// v4.6 E1 门禁扩容（收口层兜底，入口层 record_finding 已拦新记录）：
			// ①否定性断言无 claims；②确证+待验证矛盾；③confidence 为空。
			if f.Confidence == "确证" && negativeAssertRe.MatchString(f.Title+f.Detail) && len(f.Claims) == 0 {
				issues = append(issues, fmt.Sprintf("发现「%s」含否定性/排他性断言但无 claims 判据串（审计 jar 案同类）——补 claims（file+must_contain）或降级疑似", truncateText(f.Title, 40)))
			}
			if f.Confidence == "确证" && pendingAssertRe.MatchString(f.Title+f.Detail) {
				issues = append(issues, fmt.Sprintf("发现「%s」置信度「确证」与内容矛盾（含待验证/未实测表述）——完成验证或降级", truncateText(f.Title, 40)))
			}
			if f.Confidence == "" {
				issues = append(issues, fmt.Sprintf("发现「%s」confidence 为空（审计 14A1 同案）——补 确证/疑似/待查", truncateText(f.Title, 40)))
			}
			// 高危确证条目必须引用证据（EV- 编号或 evidence/ 文件）——T3MP3ST 引证校验思想
			if (f.Severity == "高") && f.Confidence == "确证" {
				d := f.Title + f.Detail
				if !strings.Contains(d, "EV-") && !strings.Contains(d, "evidence/") && !strings.Contains(d, "poc/") {
					issues = append(issues, fmt.Sprintf("高危确证发现「%s」未引用任何证据（EV- 编号 / evidence/ / poc/ 路径）", truncateText(f.Title, 40)))
				}
			}
		}
	}
	// v4.8 M2 s3 收口门：筛查矩阵判定表存在且 27 行三态留痕完整（只查留痕，不查内容——防诱导式编造）
	if stageID == "s3" {
		issues = append(issues, o.matrixTableIssues(p)...)
	}
	// v4.8 M4 交付物时间一致性门：日期字段必须落在任务时间窗内（防日期幻觉）
	issues = append(issues, o.deliverableDateIssues(p)...)
	// v4.6 E2 门禁扩容（s7 收口）：后台任务日志必须全部带终态标记（nuclei 部分扫描被洗白案）
	if stageID == "s7" && o.cfg != nil {
		asyncDir := filepath.Join(o.workspaceRoot(p.ID), ".async")
		if entries, rerr := os.ReadDir(asyncDir); rerr == nil {
			noMark := []string{}
			for _, en := range entries {
				if !strings.HasSuffix(en.Name(), ".log") {
					continue
				}
				raw, lerr := os.ReadFile(filepath.Join(asyncDir, en.Name()))
				if lerr == nil && !bytes.Contains(raw, []byte("[JT-JOB-END]")) {
					noMark = append(noMark, en.Name())
				}
			}
			if len(noMark) > 0 {
				issues = append(issues, fmt.Sprintf("%d 个后台任务日志无终态标记 [JT-JOB-END]（%s）——被截杀/中断的任务其覆盖单元不得标 ruled_out/no_issue_found，请逐个核对并在待续清单如实登记部分覆盖", len(noMark), truncateText(strings.Join(noMark, ","), 100)))
			}
		}
		// v4.6 V6 收口回填门：同义单元（归一化键相同）同时存在终态与 needs_follow_up → 僵尸 NF，要求合并回填
		if cov, cerr := o.store.ListCoverage(p.ID); cerr == nil {
			groups := map[string][]*store.CoverageEntry{}
			order := []string{}
			for _, c := range cov {
				k := store.NormCoverageEndpoint(c.Endpoint) + "\x00" + c.Param + "\x00" + c.VulnClass
				if _, seen := groups[k]; !seen {
					order = append(order, k)
				}
				groups[k] = append(groups[k], c)
			}
			for _, k := range order {
				g := groups[k]
				raw := map[string]bool{}
				states := map[string]bool{}
				for _, c := range g {
					raw[c.Endpoint] = true
					states[c.Status] = true
				}
				if len(raw) > 1 && (states["ruled_out"] || states["no_issue_found"] || states["vulnerable"]) && states["needs_follow_up"] {
					issues = append(issues, fmt.Sprintf("覆盖矩阵同义单元键漂移产生僵尸 needs_follow_up（%s | %s，%d 个原始键）——归一化合并并把已闭环单元的终态回填（0935 案形态）", truncateText(g[0].Endpoint, 50), g[0].VulnClass, len(raw)))
				}
			}
		}
		// v4.6 A2 VT 清点门：开放状态（pending/ready）的验证任务必须三选一处置
		vts, _ := o.store.ListVTs(p.ID)
		open := 0
		vtMentions := ""
		for _, t := range vts {
			if t.Status == "pending" || t.Status == "ready" {
				open++
			}
			vtMentions += t.ResultRef + "\n" + t.Note + "\n"
		}
		if open > 0 {
			issues = append(issues, fmt.Sprintf("%d 个验证任务（VT）仍为开放状态——S7 必须逐条三选一处置（update_vt → executed / closed-roe 附理由 / deferred 附移交三要素），禁止静默蒸发", open))
		}
		// v4.6 V4 L2 已批未用比对：已批准的 L2 工单若既无使用痕迹（时间线/交付物/VT 引用），
		// 也未在 s4/s5 收口清单（l2_approved_unused）申报——视为静默流失，拦截清点
		corp := o.deliverablesText(p.ID) + vtMentions
		if tl, terr := o.store.ListTimeline(p.ID); terr == nil {
			for _, ev := range tl {
				corp += ev.Event + "\n" + ev.Detail + "\n"
			}
		}
		if aps, aerr := o.store.ListApprovals(p.ID); aerr == nil {
			for _, a := range aps {
				if a.Risk != "L2" || a.Status != "approved" {
					continue
				}
				if strings.Contains(corp, a.ID) {
					continue
				}
				declared := false
				if tl2, _ := o.store.ListTimeline(p.ID); tl2 != nil {
					for _, ev := range tl2 {
						if strings.Contains(ev.Event, "V3 清单") && strings.Contains(ev.Detail, a.ID) {
							declared = true
							break
						}
					}
				}
				if declared {
					continue
				}
				issues = append(issues, fmt.Sprintf("L2 工单 %s 已批准但既无使用痕迹也未在收口清单申报（V4）——确认后要么投递使用、要么在 l2_approved_unused 申报放弃理由", a.ID))
			}
		}
	}
	// v4.6 R1 质量挂起复核门 + B4 报告引用核验（s8）
	// v5.3.8 修复：quality-pending 标记不再在此硬拒——旧实现生成"忽略本条说明"式 issue 但
	// issues 为硬拒绝且清除标记无任何工具/API 通道，构成死锁（实证：模型 8 条路径穷尽仍被
	// 永久拦截）。标记处理改为 complete_stage 入口的软提示 + confirm_quality_review 显式确认。
	if stageID == "s8" {
		if raw, rerr := o.exec.ReadFile(p.ID, "report.md"); rerr == nil {
			for _, m := range evidencePathRe.FindAllString(raw, -1) {
				rel := strings.TrimRight(m, ".,;、）)")
				if _, rerr2 := o.exec.ReadFile(p.ID, rel); rerr2 != nil {
					issues = append(issues, fmt.Sprintf("报告引用的证据文件缺失: %s（5D5B frpc 案形态）——修正引用或补齐文件", rel))
				}
			}
		}
	}
	if stageID == "s4" || stageID == "s5" {
		if cov, _ := o.store.ListCoverage(p.ID); len(cov) == 0 && stageFindings == 0 {
			issues = append(issues, "覆盖矩阵与本阶段发现均为空——按 loop-core 深度测试纪律补测或如实说明前提不成立")
		}
		// v4.4 批次4 反思门判据抽查：高危确证未引用 evidence-standard 判据 → 引擎直接降级疑似（evidenceCriteriaIssues 内部变更并留痕）
		issues = append(issues, o.evidenceCriteriaIssues(p, stageID)...)
		// v4.4 批次6 S4 分段收口对账（方向二E）：多目标且 ≥2 个目标已被真实覆盖（说明按目标推进过）时，
		// 未覆盖且未列入待续清单/档案目标的目标 → 拦截；分组产出约定 deliverables/s4-<目标或组名>.md。
		// matched<2 不拦（整目标零覆盖是另一类失败模式，由提示词纪律与轮次止损兜底，mock 演示亦不触发）。
		if stageID == "s4" && (o.cfg == nil || o.cfg.Engine.PerTargetRounds > 0) {
			if targets := splitProjectTargets(p); len(targets) > 1 {
				if cov, _ := o.store.ListCoverage(p.ID); len(cov) > 0 {
					var cb strings.Builder
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
					missing, matched := targetCoverageRecon(targets, cb.String(), o.deliverablesText(p.ID))
					if matched >= 2 && len(missing) > 0 {
						issues = append(issues, fmt.Sprintf(
							"S4 分段收口对账：%d/%d 个目标既无覆盖登记也未列入待续清单/档案目标（%s）——按目标分组补测，或将未测目标写入待续清单（分组交付物约定 deliverables/s4-<目标或组名>.md，S8 报告承接合并），再收口",
							len(missing), len(targets), truncateText(strings.Join(missing, "、"), 120)))
					}
				}
			}
		}
		// v3.8.5 G1 探测→发现晋升对账器：evidence/ 中的成功信号必须归档（发现/覆盖/事实/交付物任一引用），
		// 防「探测成功但漏斗漏液」（实测某任务宽字节/base64 延时探针命中却未晋升为发现）。
		issues = append(issues, o.orphanProbeIssues(p)...)
		// v3.8.6 G2 覆盖完整性收口门：目标自述面清单（checklist.json，S2-9 产出）条目必须逐条有归宿
		//（覆盖登记引用条目 / 显式 status 处置），防成片题目零触达仍正常收口。
		issues = append(issues, o.checklistCoverageIssues(p)...)
		// v4.8 W4 身份获取六轨编排门：无凭证且存在登录面 → 逐轨 VT 留痕（移交链完整性）
		if stageID == "s4" {
			issues = append(issues, o.identityTrackIssues(p, stageID)...)
		}
	}
	// v3.7.4 s8 报告-发现一致性（某真实任务 实测缺陷：报告定级 4 条，findings 导出仅 3 条
	// 且缺传输层/配置类入库——SARIF/findings.json 是平台导入数据源，缺项=交付缺项）：
	// 报告「### R-」定级条目数必须 ≤ findings 记录数，否则存在确证发现未 record_finding 入库。
	if stageID == "s8" {
		if raw, rerr := o.exec.ReadFile(p.ID, "report.md"); rerr == nil {
			rCount := len(regexp.MustCompile(`(?m)^### R-\d+`).FindAllString(raw, -1))
			fCount := len(findings)
			if rCount > 0 && fCount < rCount {
				issues = append(issues, fmt.Sprintf(
					"报告定级 R 条目（%d）多于 findings 记录（%d）——存在确证发现未入库（实测高频漏项：传输层/配置类如明文传输、弱哈希）。为每条 R-xx 补 record_finding（原始发现已在定级表映射的，记录 detail 注明「映射 R-xx」）后重新收口。",
					rCount, fCount))
			}
		}
	}
	// v3.8.1 s8 同根因双记拦截（对称校验；实测连续两个任务出现同根因双记进导出）：
	// 归一化标题（去空白/全角转半角/小写）前 24 字符相同的两条发现 → 疑似双记，要求合并。
	if stageID == "s8" && len(findings) > 1 {
		norm := func(t string) string {
			var b strings.Builder
			for _, r := range strings.ToLower(t) {
				if r >= 0xFF00 && r <= 0xFF5E { // 全角 → 半角
					r -= 0xFEE0
				}
				if r != ' ' && r != '\t' && r != '　' {
					b.WriteRune(r)
				}
			}
			r := []rune(b.String())
			if len(r) > 24 {
				r = r[:24]
			}
			return string(r)
		}
		seen := map[string]string{}
		for i := 0; i < len(findings); i++ {
			key := norm(findings[i].Title)
			if key == "" {
				continue
			}
			if prev, dup := seen[key]; dup {
				issues = append(issues, fmt.Sprintf("疑似同根因双记：「%s」与「%s」标题归一化后相同——按定级表合并为一条独立根因（另一条 detail 标注「映射 R-xx」或删除），S8 反夸大纪律：同根因不拆条。",
					truncateText(findings[i].Title, 40), truncateText(prev, 40)))
			} else {
				seen[key] = findings[i].Title
			}
		}
	}
	// v3.8.7 G3 待续清单回灌门：前序阶段遗留的 needs_follow_up 在 s7 收口时必须逐项处置
	//（已补测 / 范围外 / 移交复测，均需在 s7 交付物或报告文本中引用端点关键词留痕），
	// 防「待续清单原样传递四个阶段无人执行」。
	if stageID == "s7" {
		issues = append(issues, o.followUpDispositionIssues(p)...)
	}
	// 交付物存在性由 complete_stage 的「阶段内新增文件」硬校验承担，此处不重复
	return issues
}

// ---------- v3.8.5 G1 探测→发现晋升对账器（确定性，零 LLM 成本） ----------

// orphanTimingRe 时延探针成功信号：TIME= 值 ≥2.5s（sleep 类探测命中；对照基线通常 <0.5s）。
var orphanTimingRe = regexp.MustCompile(`TIME=(\d+(?:\.\d+)?)s`)

// orphanToolRe 通用工具确证信号（sqlmap 类输出关键词，跨目标通用）。
var orphanToolRe = regexp.MustCompile(`(?i)(is vulnerable|current database:|current user:|is DBA|injection point|back-end DBMS)`)

// orphanEvidenceCap 扫描证据文件数上限（防超大证据库拖慢收口；按字母序截断）。
const orphanEvidenceCap = 120

// orphanDelivCap 交付物文本读取数上限。
const orphanDelivCap = 60

// archiveTextPool 归档文本池：发现 + 覆盖矩阵 + 黑板事实 + 交付物文件内容。
// 孤儿判定 = 证据文件名（含扩展名，或 ≥8 字符的文件名主干）在池中零引用。
func (o *Orchestrator) archiveTextPool(p *store.Project) string {
	var pool strings.Builder
	add := func(ss ...string) {
		for _, s := range ss {
			pool.WriteString(s)
			pool.WriteByte('\n')
		}
	}
	if fs, err := o.store.ListFindings(p.ID); err == nil {
		for _, f := range fs {
			add(f.Title, f.Detail, strings.Join(f.EvidenceIDs, "\n"))
		}
	}
	if cov, err := o.store.ListCoverage(p.ID); err == nil {
		for _, c := range cov {
			add(c.Endpoint, c.Param, c.VulnClass, c.Status, c.Notes)
		}
	}
	if facts, err := o.store.ListFacts(p.ID, 300); err == nil {
		for _, f := range facts {
			add(f.Key, f.Value, f.Note)
		}
	}
	if files, err := o.exec.ListDir(p.ID, "deliverables"); err == nil {
		if len(files) > orphanDelivCap {
			files = files[:orphanDelivCap]
		}
		for _, rel := range files {
			if raw, rerr := o.exec.ReadFile(p.ID, rel); rerr == nil {
				pool.WriteString(raw)
				pool.WriteByte('\n')
			}
		}
	}
	return pool.String()
}

// orphanProbeIssues 扫描 evidence/ 下的成功信号（时延命中/工具确证关键词），
// 交叉比对归档文本池；「有信号、无归档」的孤儿探测结果列出并拦截收口。
// 拦截信息给出三条归档路径：record_finding / update_coverage / 交付物留痕排除。
func (o *Orchestrator) orphanProbeIssues(p *store.Project) []string {
	files, err := o.exec.ListDir(p.ID, "evidence")
	if err != nil || len(files) == 0 {
		return nil
	}
	if len(files) > orphanEvidenceCap {
		files = files[:orphanEvidenceCap]
	}
	pool := o.archiveTextPool(p)
	var issues []string
	total := 0
	for _, rel := range files {
		base := path.Base(rel)                // 含扩展名引用形态
		ext := path.Ext(base)                 // .log 等
		stem := strings.TrimSuffix(base, ext) // 主干（短主干易碰撞，仅取 ≥8 字符的）
		matched := strings.Contains(pool, base)
		if !matched && len([]rune(stem)) >= 8 {
			matched = strings.Contains(pool, stem)
		}
		if matched {
			continue
		}
		raw, rerr := o.exec.ReadFile(p.ID, rel)
		if rerr != nil {
			continue
		}
		signal := ""
		for _, m := range orphanTimingRe.FindAllStringSubmatch(raw, 3) {
			if v, perr := strconv.ParseFloat(m[1], 64); perr == nil && v >= 2.5 {
				signal = "TIME=" + m[1] + "s 时延命中"
				break
			}
		}
		if signal == "" {
			if m := orphanToolRe.FindString(raw); m != "" {
				signal = "工具确证信号「" + m + "」"
			}
		}
		if signal == "" {
			continue
		}
		total++
		if total <= 8 {
			issues = append(issues, fmt.Sprintf(
				"探测结果疑似未归档：evidence/%s 含成功信号（%s）但未关联任何发现/覆盖登记/事实/交付物——补 record_finding 或 update_coverage（Notes 引用 evidence/%s），或在交付物留痕排除理由（引用该文件名）。",
				rel, signal, rel))
		}
	}
	if total > 8 {
		issues = append(issues, fmt.Sprintf("另有 %d 个孤儿探测结果未列出——逐一归档后重新收口。", total-8))
	}
	return issues
}

// ---------- v3.8.6 G2 覆盖完整性收口门（目标自述面清单对账，确定性） ----------

// checklistItem 目标自述面清单条目（S2-9 产出 workspace 根目录 checklist.json）。
type checklistItem struct {
	ID     string `json:"id"`     // 条目编号（C1/C2…，可空）
	Item   string `json:"item"`   // 条目文本（如「数字型注入」「用户列表」）
	Hint   string `json:"hint"`   // 位置提示（路径/菜单名，可空）
	Class  string `json:"class"`  // 漏洞类推断（可空）
	Status string `json:"status"` // 显式处置：covered/deferred/excluded/skipped/out_of_scope（可空）
	Reason string `json:"reason"` // 处置理由（deferred/excluded 类必填）
}

// normCovText 覆盖字段归一化：小写 + 全角转半角 + 去空白（G2/G3 共用）。
func normCovText(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		if r >= 0xFF00 && r <= 0xFF5E { // 全角 → 半角
			r -= 0xFEE0
		}
		if r != ' ' && r != '\t' && r != '　' && r != '\n' && r != '\r' {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// parseChecklistItems 宽容解析 checklist.json：兼容 {"items":[…]} 与裸数组两种形态；解析失败按空清单处理（门不生效）。
func parseChecklistItems(raw string) []checklistItem {
	var wrapped struct {
		Items []checklistItem `json:"items"`
	}
	if err := json.Unmarshal([]byte(raw), &wrapped); err == nil && len(wrapped.Items) > 0 {
		return wrapped.Items
	}
	var arr []checklistItem
	if err := json.Unmarshal([]byte(raw), &arr); err == nil {
		return arr
	}
	return nil
}

// checklistCoverageIssues G2 主检查：清单条目必须满足其一——①自身带 status 处置（deferred/excluded 类必须附 reason）；
// ②覆盖矩阵引用（Endpoint/Param/VulnClass/Notes 归一化后包含条目文本前 12 字符，或原文包含条目 ID/Hint）。
// 另外：deferred/excluded 比例 >50% 时追加广度不足项（预算应先做一轮广度探针再收口）。
func (o *Orchestrator) checklistCoverageIssues(p *store.Project) []string {
	raw, rerr := o.exec.ReadFile(p.ID, "checklist.json")
	if rerr != nil || strings.TrimSpace(raw) == "" {
		return nil // 无自述面清单 → 门不生效（通用目标无自述面时零打扰）
	}
	items := parseChecklistItems(raw)
	if len(items) == 0 {
		return nil
	}
	cov, _ := o.store.ListCoverage(p.ID)
	norms := buildCovNorms(cov)
	var issues []string
	dispositioned, uncovered := 0, 0
	for _, it := range items {
		if strings.TrimSpace(it.Status) != "" {
			if it.Status != "covered" && strings.TrimSpace(it.Reason) == "" {
				issues = append(issues, fmt.Sprintf("自述清单条目 %s「%s」标注 status=%s 但缺 reason——在 checklist.json 补写处置理由后重新收口", it.ID, it.Item, it.Status))
			}
			if it.Status != "covered" {
				dispositioned++
			}
			continue
		}
		if !checklistItemCovered(it, norms) {
			uncovered++
			if uncovered <= 8 {
				issues = append(issues, fmt.Sprintf(
					"自述清单条目 %s「%s」无覆盖登记——测试时用 update_coverage 在 Endpoint/Notes 引用条目文本或 %s，或无法测试时在 checklist.json 该条目标注 status=deferred/excluded 并附 reason",
					it.ID, it.Item, it.ID))
			}
		}
	}
	if uncovered > 8 {
		issues = append(issues, fmt.Sprintf("另有 %d 条自述清单条目无覆盖登记——逐条归宿后重新收口。", uncovered-8))
	}
	if len(items) > 0 && float64(dispositioned)/float64(len(items)) > 0.5 {
		issues = append(issues, fmt.Sprintf(
			"自述清单 %d 条中 %d 条被处置为延期/排除（占比超 50%%）——广度不足，先对可测条目做一轮广度探针（每类最小探针）再收口；确属范围外请逐条写明理由。",
			len(items), dispositioned))
	}
	return issues
}

// covNorms 覆盖条目归一化视图（G2 收口门与 Web 对账视图共用）。
type covNorms struct {
	ep, param, class, notes, rawJoin string
}

func buildCovNorms(cov []*store.CoverageEntry) []covNorms {
	norms := make([]covNorms, 0, len(cov))
	for _, c := range cov {
		norms = append(norms, covNorms{
			ep: normCovText(c.Endpoint), param: normCovText(c.Param),
			class: normCovText(c.VulnClass), notes: normCovText(c.Notes),
			rawJoin: c.Endpoint + "\x00" + c.Param + "\x00" + c.VulnClass + "\x00" + c.Notes,
		})
	}
	return norms
}

// checklistItemCovered 条目归宿判定（三路）：①条目文本归一化前 12 字符被覆盖字段包含；
// ②条目 ID 在覆盖字段原文中出现；③Hint 路径被 Endpoint 包含。短条目（<4 字符）仅按 ID 归账。
func checklistItemCovered(it checklistItem, norms []covNorms) bool {
	probe := []rune(normCovText(it.Item))
	if len(probe) > 12 {
		probe = probe[:12]
	}
	probeText := string(probe)
	hintNorm := normCovText(it.Hint)
	if len(probe) >= 4 {
		for _, n := range norms {
			if strings.Contains(n.ep, probeText) || strings.Contains(n.param, probeText) ||
				strings.Contains(n.class, probeText) || strings.Contains(n.notes, probeText) {
				return true
			}
			if it.ID != "" && strings.Contains(n.rawJoin, it.ID) {
				return true
			}
			if hintNorm != "" && len([]rune(hintNorm)) >= 4 && strings.Contains(n.ep, hintNorm) {
				return true
			}
		}
		return false
	}
	if it.ID != "" {
		for _, n := range norms {
			if strings.Contains(n.rawJoin, it.ID) {
				return true
			}
		}
	}
	return false
}

// ReconciliationPublic v3.9.5 对账视图数据（Web API /api/projects/{id}/reconciliation）：
// 自述面清单条目归宿明细（covered/deferred/excluded/uncovered）+ 清单外发现计数
// （【清单外】标注 = 潜在 0day 面的指挥室可见度量）。checklist.json 不存在时 enabled=false。
func (o *Orchestrator) ReconciliationPublic(projectID string) map[string]any {
	out := map[string]any{"enabled": false, "items": []map[string]string{}, "beyond": 0}
	if raw, rerr := o.exec.ReadFile(projectID, "checklist.json"); rerr == nil && strings.TrimSpace(raw) != "" {
		if items := parseChecklistItems(raw); len(items) > 0 {
			cov, _ := o.store.ListCoverage(projectID)
			norms := buildCovNorms(cov)
			recon := make([]map[string]string, 0, len(items))
			covered, deferred := 0, 0
			for _, it := range items {
				st := "uncovered"
				switch {
				case strings.TrimSpace(it.Status) != "":
					st = it.Status
					if st != "covered" {
						deferred++
					}
				case checklistItemCovered(it, norms):
					st = "covered"
					covered++
				}
				recon = append(recon, map[string]string{
					"id": it.ID, "item": it.Item, "hint": it.Hint, "status": st, "reason": it.Reason,
				})
			}
			out["enabled"] = true
			out["items"] = recon
			out["total"] = len(items)
			out["covered"] = covered
			out["deferred"] = deferred
			out["uncovered"] = len(items) - covered - deferred
		}
	}
	findings, _ := o.store.ListFindings(projectID)
	beyond := 0
	for _, f := range findings {
		if strings.Contains(f.Title+" "+f.Detail, "【清单外】") {
			beyond++
		}
	}
	out["beyond"] = beyond
	out["findingsTotal"] = len(findings)
	return out
}

// ---------- v3.8.7 G3 待续清单回灌门（s7 收口硬校验，确定性） ----------

// followUpDispositionIssues 收集全项目覆盖矩阵中 status=needs_follow_up 的条目，
// 要求 s7 交付物（deliverables/）或报告（report.md）文本中逐项引用端点关键词留痕处置
// （已补测 / 范围外附理由 / 移交复测建议）。零引用 = 未处置 = 拦截。
func (o *Orchestrator) followUpDispositionIssues(p *store.Project) []string {
	cov, err := o.store.ListCoverage(p.ID)
	if err != nil {
		return nil
	}
	var pending []*store.CoverageEntry
	for _, c := range cov {
		if c.Status == "needs_follow_up" {
			pending = append(pending, c)
		}
	}
	if len(pending) == 0 {
		return nil
	}
	var pool strings.Builder
	if files, ferr := o.exec.ListDir(p.ID, "deliverables"); ferr == nil {
		for _, rel := range files {
			if raw, rerr := o.exec.ReadFile(p.ID, rel); rerr == nil {
				pool.WriteString(raw)
				pool.WriteByte('\n')
			}
		}
	}
	if raw, rerr := o.exec.ReadFile(p.ID, "report.md"); rerr == nil {
		pool.WriteString(raw)
	}
	poolText := normCovText(pool.String())
	unmatched := 0
	var issues []string
	for _, c := range pending {
		if dispositionTokenMatched(c, poolText) {
			continue
		}
		unmatched++
		if unmatched <= 8 {
			issues = append(issues, fmt.Sprintf(
				"待续清单未处置：覆盖条目「%s」（%s，%s 阶段遗留）在 s7 交付物/报告中零引用——在《待续清单处置》逐项标注：已补测（update_coverage 更新状态）/ 范围外（附理由）/ 移交复测建议，并引用端点关键词留痕。",
				c.Endpoint, c.VulnClass, c.Stage))
		}
	}
	if unmatched > 8 {
		issues = append(issues, fmt.Sprintf("另有 %d 项待续条目未处置——逐项留痕后重新收口。", unmatched-8))
	}
	return issues
}

// dispositionTokenMatched 处置留痕匹配：待续条目的端点关键词（完整归一化端点 / 末段路径 /
// 末段路径剥常见 Web 扩展名 / 参数名≥4字符）任一出现在处置文本中即视为已处置。
func dispositionTokenMatched(c *store.CoverageEntry, poolText string) bool {
	candidates := []string{}
	if ep := normCovText(c.Endpoint); ep != "" {
		candidates = append(candidates, ep)
		if i := strings.LastIndex(ep, "/"); i >= 0 && i+1 < len(ep) {
			seg := ep[i+1:]
			candidates = append(candidates, seg)
			// v3.9.5 处置留痕常不带扩展名（如「ssrf2 已补测」）——剥常见 Web 扩展名补一路候选
			for _, ext := range []string{".php", ".jsp", ".asp", ".aspx", ".html", ".htm", ".do", ".action"} {
				if strings.HasSuffix(seg, ext) {
					trimmed := strings.TrimSuffix(seg, ext)
					if len([]rune(trimmed)) >= 4 {
						candidates = append(candidates, trimmed)
					}
					break
				}
			}
		}
	}
	if param := normCovText(c.Param); len([]rune(param)) >= 4 {
		candidates = append(candidates, param)
	}
	for _, tok := range candidates {
		if len([]rune(tok)) >= 4 && strings.Contains(poolText, tok) {
			return true
		}
	}
	return false
}

// errorAdvice v3.4.0 错误自愈（hexstrike 错误分类思想）：按错误特征给处置建议。
func errorAdvice(errText string) string {
	low := strings.ToLower(errText)
	switch {
	case strings.Contains(low, "命令超时"):
		return "同步命令超时——改 run_async 后台化、降规模（top 端口/短词表/--min-rate）或提高 -T 分级；不要原样重跑。"
	case strings.Contains(low, "connection refused"):
		return "端口拒绝——先确认开放性（nmap -sV -p <port>）与服务指纹，再换协议/路径。"
	case strings.Contains(low, "no route to host"), strings.Contains(low, "i/o timeout") && strings.Contains(low, "connect"):
		return "网络不可达——核对授权范围与路由（tunnel-pivot），确认目标存活（nmap -sn）。"
	case strings.Contains(low, "could not resolve"), strings.Contains(low, "no such host"):
		return "DNS 解析失败——改用 IP、指定 --dns-server，或确认目标域名是否在授权范围内。"
	case strings.Contains(low, "permission denied"):
		return "权限不足——非特权方式重试或申请授权提升；勿暴力重试。"
	case strings.Contains(low, "403") && strings.Contains(low, "forbidden"):
		return "403——可能是 WAF/路径保护：load_skill waf-fingerprint 分型后再定策略，别连续硬试。"
	}
	return ""
}

// errText 汇总执行错误文本（错误 + stderr 尾部 + 退出码语义）。
func errText(err error, exit int, out string) string {
	var b strings.Builder
	if err != nil {
		b.WriteString(err.Error())
	}
	if exit == 124 {
		b.WriteString(" 命令超时")
	}
	if len(out) > 0 {
		b.WriteString(" ")
		b.WriteString(truncateText(out, 400))
	}
	return b.String()
}

// lessonSanitizeCheck 教训合规校验：拒绝含目标标识的内容（IP/URL/域名/凭据形态）。
func lessonSanitizeCheck(text string) string {
	if ipRe.MatchString(text) {
		return "IP 地址"
	}
	if urlRe.MatchString(text) {
		return "URL/域名"
	}
	return ""
}

var (
	ipRe  = regexp.MustCompile(`\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b`)
	urlRe = regexp.MustCompile(`(?i)\b(?:https?://|www\.)[a-z0-9.-]+|\b[a-z0-9-]+\.(?:com|cn|net|org|edu|gov|io|top|xyz)\b`)
)

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	if len(s) > 120 {
		s = s[:120] + "…"
	}
	return s
}

func truncateText(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "…"
}
