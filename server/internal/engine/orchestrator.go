package engine

import (
	"bytes"
	"context"
	"crypto/sha256"
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
	"jiutouniao/internal/version"
	"runtime/debug"
)

// Orchestrator 主控（真头）：驱动阶段流水线，每个阶段由对应专家头以
// 「决策→分级→审批→执行→观察→反思→记忆→停止」的执行循环推进（流程图第15页引擎 E）。
type Orchestrator struct {
	cfg        *config.Config
	store      *store.Store
	llm        llm.Client
	clientMu   sync.RWMutex          // LLM 客户端热切换（Web 设置保存后即时生效）
	clients    map[string]llm.Client // 多模型注册表（id -> client）
	models     map[string]string     // id -> 模型名（Chat 的 model 参数）
	defModel   string                // 默认模型 id
	exec       *tools.Executor
	approver   *Approver
	bus        *events.Bus
	heads      map[string]*Head
	coreLoop   string               // 执行循环宪法（prompts/loop-core.md）
	skills     *SkillRegistry       // 技能库（strix/PentesterFlow 移植）
	hex        *HexStrikeBridge     // hexstrike-ai 工具网关桥（可空）
	roe        *ROEProfile          // v4.6 T3/H：ROE Profile（nil=未启用）
	roeRuntime *ROERuntimeEnforcer  // v6.1.0（方案⑧）：ROE 限定参数运行时执行器（nil=未启用）
	profiles   *ExecutionProfiles   // v5.3.1：Execution Profile 声明（双运行模式单一事实源，逐动作强制）
	creds      *credentials.Service // v5.5.0：结构化凭据仓库（方案 A；未配置主密钥时 Enabled()=false，工具 fail closed）
	oob        *OOBCoord            // v7.0.0：OOB 回连通道管理器（三模式+auto 回退链；盲态类前置门与 ruled_out 降级的判据源）

	mu      sync.Mutex
	running map[string]context.CancelFunc // projectID -> 取消函数
	tokens  map[string]int64              // projectID -> 累计 token（预算熔断）

	askMu sync.Mutex
	asks  map[string]chan string // askID -> 回答通道（向人提问屏障）

	inputMu sync.Mutex
	inputs  map[string][]string // projectID -> 指挥室指令队列（运行中项目注入执行流）

	loopMu    sync.Mutex
	loops     map[string][]string // projectID -> loopback 请求的回环补跑阶段（F-03 修复：原先仅改状态不重跑）
	loopTotal map[string]int      // v5.9.0：projectID -> 项目级累计回环消费数（不清零，LoopbackMaxRuns 的真实口径）

	liveMu sync.RWMutex
	liveP  map[string]*store.Project // 运行中项目的活指针（修复：运行中改策略被流水线旧快照回写覆盖）

	projMu    sync.Mutex        // v2.7 A8：项目级模型故障切换覆盖表
	projModel map[string]string // v2.7 A8：projectID -> 故障切换后接管的项目模型 id
	modelWarn map[string]bool   // v5.4.0：projectID -> 回退默认模型告警已记（去重防刷日志）

	// v6.0.1 C30（fix-plan 20261122 P7）：模型生效记录/漂移告警去重
	//（key = project|stage|model|source 或 project|stage|drift|req|actual；防 1500 次调用刷屏）
	modelSelMu sync.Mutex
	modelSel   map[string]bool

	chatMu      sync.Mutex                    // v3.4.0：对话轮取消注册表
	chatCancels map[string]context.CancelFunc // v3.4.0：projectID -> 在途对话轮 cancel

	subMu   sync.Mutex                         // v3.6.0：子代理注册表锁
	subRuns map[string]map[string]*SubAgentRun // v3.6.0：projectID -> runID -> 子代理

	// v7.5.0（E1）：混合压缩摘要 LRU（sha256 语料 → 摘要，100 条；同输入不重复烧 aux 调用）
	sumMu    sync.Mutex
	sumCache map[string]string
	sumKeys  []string

	// v4.8 W5 行为预算器：批量动作配额/空壳即停/冷却协议（引擎级，进程内状态）
	batchMu    sync.Mutex
	batchStats map[string]*batchBudgetState

	// v7.1.0 PAE 自主决策框架进程内状态（提议配额/深化硬顶/升维计数——账本事实在 bbolt autonomy 桶）
	autoMu        sync.Mutex
	autoStageN    map[string]int // project|stage -> 本阶段已提交提议数
	autoUnitDepth map[string]int // project|focus -> 单元深化提议计数（depth_extend）
	autoDenyN     map[string]int // project|stage|kind -> 同族被拒次数（≥3 触发升维提示）
	autoExplorer  map[string]int // project -> 在途 explorer_mission 数
	autoTransfers map[string]int // project -> budget_transfer 提议数
	autoReplan    map[string]int // project|stage -> replan_delta 提议数

	healthMu    sync.Mutex                // v7.1.0 P7 工具通道健康归因（进程内计数，stage_metrics/冲刺注入消费）
	healthStats map[string]map[string]int // project|stage -> 类别(timeout/refused/dns/waf403/tool_error) -> 次数

	// v7.7.0 P1 收敛驱动收口（docs/优化方案_实战提速五项 §一.P1）
	convMu     sync.Mutex
	convIdle   map[string]int    // project|stage -> 连续无新增确证产出的轮数
	convFired  map[string]bool   // project|stage -> 本阶段收敛信号已注入（每阶段至多 1 次）
	convMsgs   map[string]string // project|stage -> 待注入收敛信号文本
	c27Tried   map[string]bool   // v7.7.0 P2：C27 引擎代填防重入（project|stage -> 已尝试；runStage 启动重置）
	blHintSeen map[string]bool   // v7.8.0 优化④：基线类引用提醒防抖（project|endpoint|class -> 已提醒）

	auxZeroMu     sync.Mutex     // v7.6.0（A1）：辅助线零有效产出连续计数
	auxZeroStreak map[string]int // project|stage|kind -> 连续零产出次数（≥2 触发时间线告警）

	skillLoads map[string]int // v7.6.0（D3）：project|stage -> load_skill 实际载入次数（收口硬字段数据源）
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
	text := "【指挥室指令】" + truncateText(msg, 2000)
	// v6.3.2：WS 推送携带 seq 且与落库同文本——此前 WS 副本无前缀无 seq，实时显示后
	// 8s 轮询增量（seq 权威）再投一遍，执行流出现重复指令
	seq, _ := o.store.AddStream(projectID, &store.StreamRecord{Kind: "msg", Role: "user", Stage: stage, Text: text})
	o.bus.Publish(projectID, "stage_msg", map[string]any{"stage": stage, "role": "user", "text": text, "seq": seq})
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
	"run_async": true, "poll_async": true, "install_tool": true, "run_batch": true, // v6.0.1 P2
	"record_asset": true, "record_finding": true, "record_timeline": true, "update_finding": true,
	"record_vt": true, "update_vt": true,
	"record_candidate": true, "update_candidate": true, // v6.0.1 P5
	"update_coverage": true, "update_subtask": true,
	"upsert_fact": true, "record_loot": true, "shell_open": true, // v3.3.0 黑板/战利品/会话（bbolt 事务串行化，天然并发安全）
	"spawn_subagent": true, "poll_subagents": true, // v3.6.0 并行扇出
	"oob_check": true, "oob_poll": true, // v7.0.0 OOB 回连通道（只读查询，天然并发安全）
}

func NewOrchestrator(cfg *config.Config, st *store.Store, client llm.Client, exec *tools.Executor, ap *Approver, bus *events.Bus, headsDir, promptsDir, skillsDir string) (*Orchestrator, error) {
	// v7.6.0（E2① 构建一致性观测）：启动即留痕运行二进制版本与 git 修订号——防「优化方案
	// 已合入源码、容器仍跑旧构建」的静默滞后（实证：v7.5.2 修复随 19:27 重启才带入运行实例，
	// 实测报告 §E2）；vcs.revision 由 go build 注入（非 git 构建时留空）。
	rev, dirty := "", ""
	if bi, ok := debug.ReadBuildInfo(); ok {
		for _, st := range bi.Settings {
			switch st.Key {
			case "vcs.revision":
				if st.Value != "" {
					rev = st.Value
					if len(rev) > 12 {
						rev = rev[:12]
					}
				}
			case "vcs.modified":
				if st.Value == "true" {
					dirty = "（含未提交修改）"
				}
			}
		}
	}
	log.Printf("[engine] 启动：版本 %s %s%s（构建一致性以本日志与 CHANGELOG 顶端条目比对为准）", version.App, rev, dirty)
	// v7.6.0（E2① 构建一致性自动校验）：data_dir 落构建戳——与上次运行版本不一致时响亮
	// 告警（「源码已更新、容器仍旧构建」的部署滞后可直接被发现，v7.5.2 延迟生效的教训）。
	stampPath := ".engine-build"
	if strings.TrimSpace(cfg.DataDir) != "" {
		stampPath = filepath.Join(cfg.DataDir, ".engine-build")
	}
	if prev, err := os.ReadFile(stampPath); err == nil {
		if last := strings.TrimSpace(string(prev)); last != "" && last != version.App {
			log.Printf("[engine] ⚠ 构建一致性警告（E2）：上次运行版本 %s，本次 %s——请确认新构建已完整部署（源码变更是否全部进入本二进制）", last, version.App)
		}
	}
	_ = os.WriteFile(stampPath, []byte(version.App), 0o600)
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
	// v6.1.0（S1 修复方案⑧）：ROE 运行时执行器——windows/max_conn_per_s/cooldown 进程内确定性
	// 消费；rotation 未接入出口层前仅登记（启动日志诚实披露 unenforced 清单）。
	var roeRuntime *ROERuntimeEnforcer
	if roeProfile != nil {
		roeRuntime = NewROERuntimeEnforcer(roeProfile)
		if une := roeRuntime.UnenforcedFields(); len(une) > 0 {
			log.Printf("ROE 运行时门已启用（windows/max_conn_per_s/cooldown 强制）；未强制字段: %v", une)
		} else {
			log.Printf("ROE 运行时门已启用（windows/max_conn_per_s/cooldown 进程内强制）")
		}
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
		heads: heads, coreLoop: string(core), skills: skills, hex: hex, roe: roeProfile, roeRuntime: roeRuntime, profiles: profiles, creds: creds,
		running:    map[string]context.CancelFunc{},
		tokens:     map[string]int64{},
		inputs:     map[string][]string{},
		loops:      map[string][]string{},
		liveP:      map[string]*store.Project{},
		projModel:  map[string]string{},
		batchStats: map[string]*batchBudgetState{},
	}
	// v7.0.0：OOB 回连通道管理器（ROE oob_callback=deny 时外部通道自动跳过，仅 A2 本地监听可用）
	o.oob = NewOOBCoord(cfg.OOB, exec, func(pp *store.Project, stage, text string) {
		if pp != nil {
			o.log(pp, stage, text)
		} else {
			log.Printf("[oob] %s", text)
		}
	}, func() bool {
		return o.roe != nil && strings.EqualFold(o.roe.Values["oob_callback"], "deny")
	})
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

// beginStageRun v5.9.3：阶段进入（首跑/重跑同口径）统一时间语义——
// StartedAt 首启保护（v5.9.1：重入/断点续跑不覆盖，耗时图反映真实起点）；
// 重入即清残留 EndedAt（旧收口时间对本次运行无效——不清则首页对账把旧区间重复计入）；
// LastActiveAt 刷新为本段起点。
func beginStageRun(state *store.StageState) {
	now := time.Now()
	if state.StartedAt == "" {
		state.StartedAt = now.Format(time.RFC3339)
	}
	state.EndedAt = ""
	state.LastActiveAt = now.Format(time.RFC3339)
}

// endStageRun v5.9.3：阶段离开 running（done/paused/failed/killed 统一口径）必须落收口时间。
// 此前 failed/killed 路径从不写 EndedAt——该阶段在首页阶段耗时图与总时长对账中永远缺角。
func endStageRun(state *store.StageState) {
	state.EndedAt = time.Now().Format(time.RFC3339)
	state.LastActiveAt = state.EndedAt
}

// clientFor 按项目选择模型：项目指定 > 默认 > 兜底。
// clientForStage v7.7.0 P5 思考分档（docs/优化方案_实战提速五项 §一.P5）：主循环按阶段
// 路由模型——stage_models[stageID] 在注册表内则用之，否则回退 clientFor（项目覆盖/默认）。
// 次序：projModel 覆盖（failover 接管）> stage_models[stageID] > 项目 ModelID > 默认。
// 仅主循环（chatFailover）使用；aux 调用保持 aux_model 独立路由。
func (o *Orchestrator) clientForStage(p *store.Project, stageID string) (llm.Client, string) {
	o.projMu.Lock()
	_, hasFailover := o.projModel[p.ID]
	o.projMu.Unlock()
	if !hasFailover {
		if m := o.cfg.LLM.StageModels[stageID]; m != "" {
			o.clientMu.RLock()
			c, ok := o.clients[m]
			name := o.models[m]
			o.clientMu.RUnlock()
			if ok && name != "" {
				return c, name
			}
		}
	}
	return o.clientFor(p)
}

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
	cli, model := o.clientForStage(p, stageID) // v7.7.0 P5：主循环按阶段路由（failover 接管仍最优先）
	// v6.0.1 C30：生效模型记录（同阶段同模型只记一次；配置声明值/项目覆盖/failover 接管均为合法路径，标注来源）
	o.recordModelSel(p, stageID, model, "clientFor")
	resp, usage, err := cli.Chat(ctx, model, msgs, tools, o.cfg.LLM.Temperature, o.cfg.LLM.MaxTokens)
	if err == nil || ctx.Err() != nil {
		if err == nil {
			// v6.0.1 C30：网关回报模型与请求模型不一致 → 漂移告警（warn-only，留痕不阻断）
			o.checkModelDrift(p, stageID, model, usage)
		}
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
			// v6.0.1 C30：failover 接管是合法切换路径——记录来源与前后模型
			o.recordModelSel(p, stageID, mname, "failover-takeover")
			o.checkModelDrift(p, stageID, mname, u2)
			// v7.5.0（A1）：此处不再入账——usage 随返回值交调用方统一入账（原 failover 内外
			// 各记一次=双重计账，账本虚增 2 倍并扭曲预算熔断时点）。
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

// SetPreApproved v6.0.0（用户决策③）：项目预批准档切换（与 SetExecutionProfile 同构——活指针同步防旧快照回写）。
// none（默认人工）/all（全通过——含提权/横向及后续新增类别）/类别逗号列表（privesc,lateral,persistence）。
// 切到 all 时联动放行存量待批工单（与 SetAutoApprove→all 同语义，避免执行循环卡死在审批屏障）。
func (o *Orchestrator) SetPreApproved(projectID, mode string) error {
	mode = store.NormalizePreApproved(mode) // none=显式关闭预批（合法档）；全无效值也归 none（fail-closed）
	p, err := o.store.GetProject(projectID)
	if err != nil {
		return err
	}
	p.PreApproved = mode
	if err := o.store.SaveProject(p); err != nil {
		return err
	}
	o.liveMu.Lock()
	if lp, ok := o.liveP[projectID]; ok {
		lp.PreApproved = mode
	}
	o.liveMu.Unlock()
	if mode == "all" {
		if n := o.approver.ApprovePending(projectID, "pre-approved-policy-change"); n > 0 {
			o.log(p, "", fmt.Sprintf("⚙ 预批准已切换为全通过；联动放行 %d 个存量待批工单", n))
		}
	}
	o.log(p, "", fmt.Sprintf("预批准档已更新：%s（仅自动签人工核签环节；治理门照常前置）", mode))
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
// urlHostRe v7.8.1（授权扩展识别修正⑨/补强⑪）：URL host 提取——
// ① scheme 集扩展到网络对端 scheme 全族（http(s)/ftp(s)/sftp/ssh/scp/telnet/ws/wss/tcp/udp
//    + ⑪补全 DB/同步协议 postgres(ql)/mysql/mariadb/mongodb(+srv)/redis(s)/mssql/ldap(s)/
//    git/svn/rsync，(?i) 大小写不敏感）：原实现只认 https?://，实测 ftp://files…、
//    telnet://backdoor…:4444、ssh://git@…、wss://c2… 对 strict_scope 全部静默放行（绕过面）；
//    ⑪ 实测 postgres://admin:pw@files…/db、mongodb+srv://c2…、git://…、rsync://… 同样静默
//    放行（IP 形态靠 ipLitRe 侥幸命中，域名形态完全不可见）。scheme 锚定无误报面。
//    bareDomainRe 前导边界类不含 '/'，scheme 后 host 走裸域名路径亦不可见——绕过双路成立。
// ② 可选 userinfo 组（非捕获，至首个 '@'）：原实现 host 类含 ':' 不含 '@'，实测
//    http://admin:pw@9.9.9.9/ 把 userinfo 误提取为目标 [admin:pw 9.9.9.9]（凭据字样若曾
//    出现于证据链会误开授权扩展工单；userinfo 恰在白名单时形成真绕过）。
// ③ host 类含 '[]'：IPv6 括号 host 由本正则主循环捕获（配合 hostAllowed/修正⑦ 归一）。
// 注意：无 scheme 的 ssh admin@host 形态由 ⑩ 上下文锚定提取（'@' 入裸域名边界会把命令中
// email 一律误判为网络目标——v7.6.0 B4 误拦教训，不取此平衡）；IP 形态由 ipLitRe 兜底。
// file:// 本地路径不属网络对端，不入 scheme 集。
var urlHostRe = regexp.MustCompile(`(?i)\b(?:https?|ftps?|sftp|ssh|scp|telnet|ws|wss|tcp|udp|git|svn|rsync|mariadb|mysql|postgres(?:ql)?|mongodb(?:\+srv)?|redis(?:s)?|mssql|ldaps?)://(?:[A-Za-z0-9._%~:\-]{1,128}@)?([A-Za-z0-9_.:\[\]-]+)`)
var ipLitRe = regexp.MustCompile(`\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b`)

// v5.9.0（方案 P0-1）：裸域名提取——命令中无 scheme 直接出现的域名字面量（如
// `nmap example.com`）。Go regexp 不支持前瞻，用捕获组捕获域名本体（group 1），
// 边界字符在 group 2 中匹配但不消费歧义——匹配后取 group 1。要求含点且非纯数字。
var bareDomainRe = regexp.MustCompile(`[\s'"(;|&=,]([A-Za-z0-9][A-Za-z0-9-]*(?:\.[A-Za-z0-9-]+)+)[\s'"();|&,]?`)

// proxyAssignRe 匹配命令文本中的代理环境变量赋值（export/env http_proxy=… https_proxy=… 等）。
// 值由部署环境或 TOOL_PROXY 注入，属传输通道配置而非测试目标——v5.7.2 安装通道分流后
// install_tool 的代理兜底命令携带代理地址（如 docker 网桥 IP），目标匹配前必须剥离，否则
// strict_scope 项目会把代理 IP 误判为范围外目标确定性拦截；loop-core 教的
// `env http_proxy=$TOOL_PROXY <cmd>` 下载前缀同理，属既有潜伏误拦面。与 v5.3.9 OSINT 白名单
// 同理：范围匹配器只应校验业务目标。
var proxyAssignRe = regexp.MustCompile(`(?i)\b[a-z_]*(https?_proxy|all_proxy|no_proxy)=\S+`)

// proxyFlagRe v7.8.1（授权扩展识别修正⑤）：内联代理旗标赋值剥离——curl -x/--proxy、
// httpx -http-proxy 等旗标携带的代理 URL 与 proxyAssignRe 覆盖的 env 赋值形态同一性质：
// 传输通道配置而非测试目标。实测形态 `-x http://proxy:3128` 的代理 host 会被 urlHostRe
// 提取为「范围外目标」误拦；若代理地址曾出现于证据链还会走 expansion 通道误开授权扩展
// 工单。仅剥离 scheme 锚定值（http/socks 前缀）——grep -x 等非代理旗标的无 scheme 参数
// 不受影响，不新增漏拦面；无 scheme 的 host:port 代理值维持原状（残余观察项，宁误拦
// 不漏拦）。
var proxyFlagRe = regexp.MustCompile(`(?i)\s(?:-[a-z]{0,10}-proxy\b|--proxy[a-z-]*\b|-x\b)[=\s]+(?:https?|socks[45][ah]?)://\S+`)

// ipv6LitRe v7.8.1（授权扩展识别补强⑥）：括号 IPv6 字面量捕获（含括号）——urlHostRe
// 字符类不含 '['，http://[fd00::5]/ 括号 host 形态此前对范围门完全不可见。捕获体由
// isIPv6Body 复核（≥2 冒号 + 纯十六进制），防止数组下标/切片/十六进制词等代码形态误报。
var ipv6LitRe = regexp.MustCompile(`\[([0-9A-Fa-f:]+)\]`)

// sshKeywordRe / atHostRe v7.8.1（授权扩展识别补强⑩）：ssh/scp/sftp 命令的裸 user@host
// 形态提取——'@' 不入 bareDomainRe 边界类（会把命令中 email 一律误判为网络目标，
// v7.6.0 B4 消灭 51 次误拦的教训），改为命令词上下文锚定：仅当命令含 ssh/scp/sftp
// 关键词时，提取 user@host token 的 host 部分参与范围校验（ssh 类命令中出现 email
// 形态参数可忽略）。实测 `ssh admin@evil-lab.test` 此前对 strict_scope 静默放行
// （IP 形态已由 ipLitRe 兜底；scheme 形 ssh:// 已由 ⑨ 覆盖）。
var sshKeywordRe = regexp.MustCompile(`(?i)\b(?:ssh|scp|sftp)\b`)
var atHostRe = regexp.MustCompile(`\b([A-Za-z0-9._%\-]{1,64})@([A-Za-z0-9.\[\]:\-]+)`)

var defaultScopeAllowlist = []string{
	"crt.sh", "github.com", "raw.githubusercontent.com", "api.github.com", "objects.githubusercontent.com",
	"nvd.nist.gov", "services.nvd.nist.gov", "nuclei.sh", "cve.mitre.org", "cve.org",
	"pypi.org", "files.pythonhosted.org", "pypi.tuna.tsinghua.edu.cn", "mirrors.tuna.tsinghua.edu.cn",
	"registry.npmmirror.com", "registry.npmjs.org", "deb.debian.org", "security.debian.org",
	"http.kali.org", "kali.download", "mirrors.ustc.edu.cn", "mirrors.aliyun.com",
	"dns.alidns.com", "223.5.5.5", "119.29.29.29", "8.8.8.8", "1.1.1.1",
	"gitee.com", // v5.3.1：install_tool git 策略的国内镜像源（installToolGitMap 第二策略）
	// v7.6.0（B5）：RDAP 协议族入白名单——RDAP 是 ICANN 标准的 WHOIS 替代协议，属被动
	// 注册数据查询（实证 某实战项目：rdap.verisign.com 被判「非被动源」拦截，损失归属数据点）。
	"rdap.org", "rdap.verisign.com", "data.iana.org", "www.iana.org",
	// v5.3.9：OSINT 数据源补全——对第三方 API 的读请求不是对目标发包，不应被目标匹配器误拦
	// （实测事故：某历史任务空间测绘四平台全被 strict_scope 拦截，OSINT 轨空转）。
	// 泄露库/测绘/代码检索与档案类数据源；recon-playbook / osint-leak-intel / history-recon 消费。
	"fofa.info", "quake.360.net", "zoomeye.org", "hunter.qianxin.com",
	// v6.3.2：OSINT 备援源补全（实战 某历史任务：crt.sh 5/5 故障时 certspotter 免 key CT
	// 备援被拦、ZoomEye v2 API 域被拦——对第三方数据源的读请求不是对目标发包）。
	"api.certspotter.com", "api.zoomeye.org",
	"api.pwnedpasswords.com", "haveibeenpwned.com", "virustotal.com", "shodan.io", "censys.io",
	"oast.pro", "oast.live", "oast.site", "dnslog.cn", "interact.sh", "oob.interactsh.com",
	"searchsploit", "localhost", "127.0.0.1", "0.0.0.0", "::1", // v7.8.1（补强⑥）：IPv6 回环与 127.0.0.1 同信任级
	"example.com", "example.edu",
	"grep.app", "searchcode.com", "web.archive.org", "archive.org", "haveibeenpwned.com",
}

// hostAllowed v6.1.0（S1 修复方案②㉒）重写：目标清单逐行精确匹配（v2.4.0 起多目标逐行），
// 通配授权只能由目标/资产中显式书写的 *.example.test 条目表达；**删除主域子域后缀自动放行**
// （原 HasSuffix(h, "."+t) 使影子资产"只登记不测试"承诺形同虚设）。allow 仅含 in_scope 资产
// 与外部源白名单——子域测试须经 ② 的资产范围门以授权依据入账。
func hostAllowed(host string, target string, allow map[string]bool) bool {
	h0 := strings.ToLower(strings.TrimSuffix(strings.TrimSuffix(host, "."), ":443"))
	h0 = strings.TrimSuffix(strings.TrimPrefix(h0, "["), "]") // v7.8.1（补强⑥）：括号 IPv6 归一（[fd00::5] ≡ fd00::5）
	// v7.8.1（授权扩展识别修正④）：保留未剥 www. 的原始 host（h0）双形态精确校验——原实现
	// 对查询 host 无条件剥 www. 前缀，授权目标/资产/工单登记为 www.* 域名时永远匹配不上：
	// 实测主目标 www.example-lab.test 自身访问被判「范围外」硬拦（主目标天然大量出现于证据链，
	// 次命中即对已授权目标误开授权扩展工单），且批准登记 allow["www.…"] 后仍查剥前缀形态
	// → 批准不生效、目标持续被拦，「批准即登记资产放行」闭环在 www.* 形态断裂。双形态均
	// 只做精确匹配/显式通配，仅放行已授权形态，无新增绕过面（host 裸域 x 对授权 www.x 仍拦）。
	h := strings.TrimPrefix(h0, "www.")
	if h == "" || allow[h] || allow[h0] {
		return true
	}
	for _, line := range strings.Split(target, "\n") {
		t := strings.ToLower(strings.TrimSpace(line))
		t = strings.TrimPrefix(strings.TrimPrefix(t, "https://"), "http://")
		if i := strings.IndexAny(t, "/?#"); i >= 0 {
			t = t[:i]
		}
		t = strings.TrimSuffix(strings.TrimSuffix(t, "/"), ".")
		t = strings.TrimSuffix(t, ":443")
		if t == "" {
			continue
		}
		tBare := strings.TrimSuffix(strings.TrimPrefix(t, "["), "]") // v7.8.1（补强⑥）：目标行括号 IPv6 归一
		if h == t || h0 == t || h == tBare || h0 == tBare {
			return true
		}
		// 显式通配授权条目：*.example.test 覆盖其子域（含自身域可选——通配只承诺子域，自身域须单独列出）
		if strings.HasPrefix(t, "*.") && (strings.HasSuffix(h, t[1:]) || strings.HasSuffix(h0, t[1:])) {
			return true
		}
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
	// v7.8.1（修正⑤）：内联代理旗标值同口径剥离（见 proxyFlagRe 注释）
	command = proxyFlagRe.ReplaceAllString(command, " ")
	// v6.3.2：被动 DNS/WHOIS 查询段豁免——dig/host/nslookup/whois 协议本身不接触目标服务
	// （与 s1ActionGate 同一哲学；实战 S1 影子父域 dig 归属查询被拦 8 条），axfr 保留拦截。
	command = stripDNSQuerySegments(command)
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
	// v6.1.0（S1 修复方案②㉒）：strict_scope 资产 allowlist 只承认「有授权依据的 in_scope 资产」
	// ——shadow_pending/out_of_scope/conditional/unknown（含旧库无字段数据）一律不再登记即放行；
	// 影子/待确认资产的测试流量由 shadowAssetGate 在本门之前确定性拦截。
	for _, a := range assets {
		if o.guardEnabled(func(g *config.GuardConfig) *bool { return g.EnforceAssetScope }) {
			if a.EffectiveScope() != "in_scope" || strings.TrimSpace(a.ScopeEvidence) == "" {
				continue
			}
		}
		v := strings.ToLower(strings.TrimSpace(a.Value))
		v = strings.TrimPrefix(strings.TrimPrefix(v, "https://"), "http://")
		v = strings.TrimSuffix(strings.TrimSuffix(strings.TrimSuffix(v, "/"), "."), ":443")
		v = strings.TrimSuffix(strings.TrimPrefix(v, "["), "]") // v7.8.1（补强⑥）：括号 IPv6 归一
		if v != "" {
			allow[v] = true
		}
	}
	bad := []string{}
	for _, h := range urlHostRe.FindAllStringSubmatch(command, -1) {
		tgt := h[1]
		// v7.8.1（⑨）：IPv6 括号 host 去括号取裸形（[::1]:8080 → ::1）——括号后端口不并入：
		// 与端口直接拼接会产生 ::1:8080 歧义串，且 IPv6 授权为 host 级（与 ⑥ 裸形工单/
		// 资产登记口径一致，幂等）。域名/裸 IP 的 host:port 整串口径不变。
		if strings.HasPrefix(tgt, "[") {
			if i := strings.Index(tgt, "]"); i > 0 {
				tgt = tgt[1:i]
			} else {
				tgt = strings.Replace(strings.Replace(tgt, "[", "", 1), "]", "", 1)
			}
		}
		if !hostAllowed(tgt, p.Target, allow) {
			bad = append(bad, tgt)
		}
	}
	// v7.8.1（授权扩展识别修正③）：IP 字面量在剥掉 URL host 段后的文本上提取——
	// urlHostRe 与 ipLitRe 对 URL 内嵌 IP 双重命中，拦截/工单消息出现重复目标
	// （实测 [9.9.9.9 9.9.9.9]）；URL 形态已由上方 urlHostRe 逐个校验不漏，host:port
	// 整串校验与工单目标一致（批准登记后 hostAllowed 精确放行）。
	urlStripped := urlHostRe.ReplaceAllString(command, " ")
	for _, ip := range ipLitRe.FindAllStringSubmatch(urlStripped, -1) {
		if !hostAllowed(ip[1], p.Target, allow) {
			bad = append(bad, ip[1])
		}
	}
	// v7.8.1（授权扩展识别补强⑥）：括号 IPv6 字面量提取——urlHostRe 字符类不含 '['，
	// http://[fd00::5]/ 形态此前完全不可见（范围门漏拦面：范围外 IPv6 目标静默直连，不走
	// expansion 通道不留痕）。IPv4 字面量先提取（::ffff:1.2.3.4 映射形的 v4 部分按 IPv4
	// 目标校验，语义等价更严）；host 以去括号裸形入账，与资产/工单登记形态一致。
	// isIPv6Body 要求 ≥2 冒号 + 纯十六进制——排除数组下标 [0]、切片 [1:2]、十六进制词
	// [abc] 等代码形态误报。
	for _, m := range ipv6LitRe.FindAllStringSubmatch(urlStripped, -1) {
		host6 := strings.ToLower(m[1])
		if !isIPv6Body(host6) {
			continue
		}
		if !hostAllowed(host6, p.Target, allow) {
			bad = append(bad, host6)
		}
	}
	// v5.9.0（方案 P0-1）：裸域名检查（审计 P1：nmap example.com 漏网）——先剥 URL/IP
	// 命中段避免重复误报，再按裸域名边界提取
	stripped := ipv6LitRe.ReplaceAllString(ipLitRe.ReplaceAllString(urlStripped, " "), " ")
	for _, d := range bareDomainRe.FindAllStringSubmatch(stripped, -1) {
		if !isPlausibleDomainHost(d[1]) || isNonTargetBareToken(stripped, d[1]) {
			continue // v6.3.2：TLD 纯数字（版本号 3.7/3.7.1 类）非域名候选；v7.6.0 B4：文件名/属性访问非网络目标
		}
		dom := strings.ToLower(strings.TrimSuffix(d[1], "."))
		// 白名单域名的子域/自身在 hostAllowed 里处理；此处只拦完全未登记的
		if !hostAllowed(dom, p.Target, allow) && !allow[dom] {
			bad = append(bad, dom)
		}
	}
	// v7.8.1（补强⑩）：ssh/scp/sftp 上下文锚定的裸 user@host 提取——见 sshKeywordRe 注释。
	// host 部分去括号（[fd00::5] → fd00::5）与去 scp 路径尾冒号（host:/path → host）后，
	// 走统一 hostAllowed 校验；与 URL/IP/裸域名命中经下方去重合流。
	if sshKeywordRe.MatchString(command) {
		for _, m := range atHostRe.FindAllStringSubmatch(command, -1) {
			h := strings.ToLower(m[2])
			if strings.HasPrefix(h, "[") {
				if i := strings.Index(h, "]"); i > 0 {
					h = h[1:i]
				} else {
					h = strings.Replace(strings.Replace(h, "[", "", 1), "]", "", 1)
				}
			}
			h = strings.TrimSuffix(h, ":")
			if h == "" || h == "localhost" || h == "127.0.0.1" {
				continue
			}
			if !hostAllowed(h, p.Target, allow) {
				bad = append(bad, h)
			}
		}
	}
	// v7.8.1（修正③）：三路提取（URL host/IP/IPv6/裸域名/ssh user@host）汇总后统一归一去重——
	// ⑦ host 大小写不敏感，urlHostRe 捕获原始大小写会使工单幂等查重（精确比较）被
	// 击穿：实测 EXAMPLE-LAB.test / example-lab.test 两次命中开出 2 张工单。归一后
	// 拦截消息/工单目标/资产登记（allow 构建同口径小写）全链路一致。
	for i := range bad {
		bad[i] = strings.ToLower(bad[i])
	}
	bad = dedupeStrings(bad)
	if len(bad) == 0 {
		return false, ""
	}
	// v6.0.0（用户决策①）expansion 接线——发现驱动授权扩展，替代「范围外一律静默放弃」：
	//   deny（默认）       → 维持硬拦（原口径不变）；
	//   auto               → 立足点已发现的目标直接放行并留痕；
	//   auto-with-approval → 立足点已发现的目标生成《授权扩展工单》，批准即登记资产放行。
	//   未发现目标在任何非 deny 档下维持硬拦——范围门不因 expansion 变橡皮章。
	mode := o.expansionMode(p)
	if mode != "deny" {
		discovered := o.filterDiscoveredTargets(p, bad)
		if len(discovered) > 0 {
			unknown := subsetDiff(bad, discovered)
			if mode == "auto" {
				o.log(p, "", fmt.Sprintf("🔓 范围外目标放行（ROE expansion=auto，留痕）：%v", discovered))
				if len(unknown) > 0 {
					return true, fmt.Sprintf("strict_scope=true：范围外且未发现目标 %v 已拦截；已发现目标 %v 按 expansion=auto 放行——请拆分命令只含放行目标后重试。", unknown, discovered)
				}
				return false, ""
			}
			ticketed, firstID, rejectedT := o.ensureScopeExtensionTickets(p, discovered)
			msgTail := ""
			if len(ticketed) > 0 {
				msgTail = fmt.Sprintf("范围外目标 %v 属立足点发现（expansion=auto-with-approval）——授权扩展工单 %s 已生成/在批，批准后自动登记资产并放行，请先继续其他动作", ticketed, firstID)
			}
			if len(rejectedT) > 0 {
				// v7.8.1（修正⑧）：拒绝粘滞提示——被拒目标不再进入「已生成/在批」话术
				if msgTail != "" {
					msgTail += "；"
				}
				msgTail += fmt.Sprintf("目标 %v 的授权扩展工单此前已被拒绝——按工单口径维持「只记录不访问」，请勿重试访问；如确需放行请走 record_asset 人工登记（须附授权依据）", rejectedT)
			}
			if len(unknown) > 0 {
				if msgTail != "" {
					msgTail += "；"
				}
				msgTail += fmt.Sprintf("未发现目标 %v 维持拦截", unknown)
			}
			return true, "strict_scope=true：" + msgTail + "。"
		}
	}
	return true, fmt.Sprintf("strict_scope=true：命令引用范围外目标 %v——已确定性拦截。"+
		"如属授权范围：先 record_asset 登记该资产再重试；OSINT/工具源误拦请在 config guard.scope_allowlist 扩充。", bad)
}

// effectiveWritePolicy v6.0.0（通用型三层治理参数）：写策略生效值。
// ① 部署级 ROE YAML（roe_profile_path 配置时）最高——部署 owner 显式选择，全项目生效（⚠ 混合
//
//	生产/靶场部署慎用 full：会波及 production_safe 项目）；
//
// ② 未配置 YAML 时按项目执行档派生：isolated_lab→full（快照回滚保障，零配置实战可用）；
//
//	production_safe→"unset"（写门不武装——生产写操作按审批矩阵管控，与 v5.9.0 前历史行为一致，
//	不因升级给生产项目新增确定性拦截面）；
//
// ③ 未知档 → unset（fail-safe：不新增拦截面）。"unset" 时 governanceGates 跳过写门。
func (o *Orchestrator) effectiveWritePolicy(p *store.Project) string {
	if o.roe != nil {
		return o.roe.WritePolicy()
	}
	if o.profileOf(p) == ProfileIsolatedLab {
		return "full"
	}
	return "unset"
}

// expansionMode v6.0.0（通用型三层治理参数）：范围扩展语义生效值。roe.go schema 于 v4.6 定义了
// auto / auto-with-approval / deny 三档，此前从未被消费（死参数）——本函数接线。
// ① 部署级 YAML 配置了 expansion → 全项目按该值生效；
// ② YAML 未配置 expansion → 未发现目标维持硬拦的 deny；YAML 配置但值非法 → deny；
// ③ 未配置部署级 YAML → 按执行档派生：isolated_lab→auto-with-approval（授权跟着发现走，实战型）、
//
//	production_safe→deny（生产缺省收紧）。未发现目标在任何档下维持硬拦。
func (o *Orchestrator) expansionMode(p *store.Project) string {
	if o.roe != nil {
		m := strings.ToLower(strings.TrimSpace(o.roe.Values["expansion"]))
		if m == "auto" || m == "auto-with-approval" {
			return m
		}
		return "deny"
	}
	if o.profileOf(p) == ProfileIsolatedLab {
		return "auto-with-approval"
	}
	return "deny"
}

// filterDiscoveredTargets v6.0.0：判定范围外目标是否属「立足点发现」——在证据链/发现库/时间线
// 文本中出现过的 host/IP 才可走 expansion 通道（授权跟着发现走；凭空目标不可申请扩展）。
// v7.8.1（授权扩展识别修正①②）：治理/人工操作回执不并入发现语料 + 边界约束匹配。
func (o *Orchestrator) filterDiscoveredTargets(p *store.Project, targets []string) []string {
	if len(targets) == 0 {
		return nil
	}
	var sb strings.Builder
	if evs, err := o.store.ListEvidence(p.ID); err == nil {
		for i, e := range evs {
			if i >= 400 {
				break // 扫描上限：防超大证据链拖慢逐命令校验
			}
			if isGovernanceReceipt(e) {
				continue // v7.8.1 修正①：回执 Input 含命令原文，并入即自反馈误识别（见函数注释）
			}
			sb.WriteString(e.Input + "\n" + e.Output + "\n")
		}
	}
	if fs, err := o.store.ListFindings(p.ID); err == nil {
		for _, f := range fs {
			sb.WriteString(f.Title + "\n" + f.Detail + "\n")
		}
	}
	if tls, err := o.store.ListTimeline(p.ID); err == nil {
		for i, t := range tls {
			if i >= 400 {
				break
			}
			sb.WriteString(t.Event + "\n")
		}
	}
	hay := strings.ToLower(sb.String())
	out := []string{}
	for _, t := range targets {
		if t != "" && discoveredHitBoundary(hay, strings.ToLower(t)) {
			out = append(out, t)
		}
	}
	return out
}

// isGovernanceReceipt v7.8.1（授权扩展识别修正①）：证据记录是否为治理/人工操作回执——
// 各确定性门拦截留证（ApprovedBy=<name>-gate：scope/profile/registration/shadow/batch-scope/
// roe-*/s1-*/authorization/engine-introspection）、人工拒绝（human-rejected）、人工一次性放行
// （roe-ack）的 Input 都是命令原文，可能携带范围外目标，但本质是治理动作产物而非立足点发现。
// 此前并入发现语料造成自反馈：目标首次被拦（留证含目标）→ 次命中即被误判「立足点发现」自动
// 生成授权扩展工单（实测 9.9.9.9 从未被立足点发现，首拦留证后次命中即开单）——「未发现目标
// 维持硬拦」仅首命中成立，人工拒绝过的目标也翻脸成扩展候选。回执一律排除；误排方向
// fail-closed（目标维持硬拦，可经 record_asset/scope_allowlist 人工放行，不会误开工单）。
func isGovernanceReceipt(e *store.EvidenceRecord) bool {
	if strings.HasSuffix(e.ApprovedBy, "-gate") {
		return true
	}
	return e.ApprovedBy == "human-rejected" || e.ApprovedBy == "roe-ack"
}

// discoveredHitBoundary v7.8.1（授权扩展识别修正②）：发现匹配的边界约束——语料（已小写化）
// 中存在一处命中、且命中位置前后均非 host 连续字符（[a-z0-9._-]）才算该目标真实出现。
// 纯 strings.Contains 子串误判：证据 172.33.0.40 会验证从未出现的 172.33.0.4（实测凭空目标
// 误开工单）、sub.evil.com 会验证 evil.com。收紧方向：宁可不开工单维持硬拦（漏判可经
// record_asset/scope_allowlist 人工放行），不可凭子串误判放行凭空目标。
func discoveredHitBoundary(hay, needle string) bool {
	if needle == "" {
		return false // v7.8.1 防御性护栏：空 needle 语义未定义（调用方已过滤，双保险防误真）
	}
	isHostByte := func(c byte) bool {
		return c == '.' || c == '-' || c == '_' || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')
	}
	start := 0
	for {
		i := strings.Index(hay[start:], needle)
		if i < 0 {
			return false
		}
		idx := start + i
		beforeOK := idx == 0 || !isHostByte(hay[idx-1])
		end := idx + len(needle)
		afterOK := end >= len(hay) || !isHostByte(hay[end])
		if beforeOK && afterOK {
			return true
		}
		start = idx + 1
	}
}

// subsetDiff 返回 targets 中不在 subset 里的项（保持原序）。
func subsetDiff(targets, subset []string) []string {
	m := map[string]bool{}
	for _, s := range subset {
		m[s] = true
	}
	out := []string{}
	for _, t := range targets {
		if !m[t] {
			out = append(out, t)
		}
	}
	return out
}

// dedupeStrings v7.8.1（授权扩展识别修正③）：保序去重——范围门 bad 列表同时供拦截/工单
// 消息与工单目标遍历消费，重复项只制造噪音（实测 [9.9.9.9 9.9.9.9]）。
func dedupeStrings(in []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

// isIPv6Body v7.8.1（补强⑥）：括号内 IPv6 体复核——已小写的纯十六进制/冒号且 ≥2 冒号
// （IPv6 最短形 "::" 亦含 2 冒号；数组下标 [0] 零冒号、切片 [1:2] 单冒号、十六进制词
// [abc] 零冒号均被排除，不产生误报目标）。
func isIPv6Body(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || c == ':') {
			return false
		}
	}
	return strings.Count(s, ":") >= 2
}

// ensureScopeExtensionTickets v6.0.0：为目标生成《授权扩展工单》（每目标一张，幂等——已有
// pending 工单直接复用）。批准回调 ApplyScopeExtension 登记资产 → scopeGate 白名单自动纳入。
// v7.8.1（授权扩展识别修正⑧）：拒绝粘滞——工单文案承诺「拒绝则该目标维持只记录不访问」，
// 此前仅查重 pending，人工拒绝后次命中立即重开新单绕过拒绝（实测语义翻脸）。返回：
// ticketed=本次应走「已生成/在批」话术的目标（新建或复用 pending）；rejected=已有被拒工单、
// 按粘滞口径不再开单的目标；firstID=新建首张工单 ID（无新建时为占位提示）。
func (o *Orchestrator) ensureScopeExtensionTickets(p *store.Project, targets []string) (ticketed []string, firstID string, rejected []string) {
	for _, t := range targets {
		pendingDup, rejectedDup := false, false
		if aps, err := o.store.ListApprovals(p.ID); err == nil {
			for _, ap := range aps {
				if ap.Kind != "scope_extension" || ap.Target != t {
					continue
				}
				if ap.Status == "pending" {
					pendingDup = true
				} else if ap.Status == "rejected" {
					rejectedDup = true
				}
			}
		}
		if pendingDup {
			ticketed = append(ticketed, t)
			continue
		}
		if rejectedDup {
			rejected = append(rejected, t)
			continue
		}
		ap := &store.Approval{
			ProjectID: p.ID, Stage: "s6", Risk: "L2", Status: "pending", Mode: "manual",
			Kind: "scope_extension", Target: t,
			Action: fmt.Sprintf("【授权扩展】允许访问范围外目标 %s（expansion=auto-with-approval；该目标已在立足点发现证据中出现）。批准即登记资产并放行后续访问；拒绝则该目标维持「只记录不访问」。", t),
		}
		if id, err := o.store.AddApproval(ap); err == nil {
			// v7.8.1（⑮）：确定性门内 WS 广播 nil-bus 防护——同 v6.6.0 o.log 加固理由：
			// 测试装配/部分构造场景 bus 缺失不得 SIGSEGV，落库与工单生成已先行完成。
			if o.bus != nil {
				o.bus.Publish(p.ID, "approval", ap)
			}
			o.log(p, "", fmt.Sprintf("🎫 已生成授权扩展工单 %s：目标 %s（批准后自动登记资产放行）", id, t))
			if firstID == "" {
				firstID = id
			}
		}
		ticketed = append(ticketed, t)
	}
	if firstID == "" {
		firstID = "(已有在批工单)"
	}
	return ticketed, firstID, rejected
}

// ApplyScopeExtension v6.0.0：授权扩展工单批准回调——目标登记资产台账（scopeGate 白名单
// 自动纳入 ListAssets），时间线留痕；重复登记无害（Asset 为追加式台账）。
func (o *Orchestrator) ApplyScopeExtension(projectID, target string) error {
	p, err := o.store.GetProject(projectID)
	if err != nil {
		return err
	}
	target = strings.TrimSpace(target)
	if target == "" {
		return fmt.Errorf("扩展目标为空")
	}
	if _, err := o.store.AddAsset(&store.Asset{
		ProjectID: projectID, Stage: "s6", Type: "scope-extension", Value: target,
		Detail: "v6.0.0 授权扩展工单批准登记——scopeGate 白名单自动纳入",
		// v6.1.0（S1 修复方案㉒）：扩展批准=有授权依据的 in_scope——批准记录即 ScopeEvidence，
		// 普通 record_asset 不能自我批准（in_scope 必须附可追溯依据）。
		ScopeStatus: "in_scope", ScopeEvidence: "授权扩展工单批准（ApplyScopeExtension 回调）",
		Source: "scope-extension-approval",
	}); err != nil {
		return err
	}
	o.log(p, "", fmt.Sprintf("🔓 授权扩展生效：目标 %s 已登记资产，后续访问不再被范围门拦截", target))
	// v7.8.1（⑮）：批准回调同口径 nil-bus 防护（登记已落库，广播失败不回滚授权）
	if o.bus != nil {
		o.bus.Publish(p.ID, "project", p)
	}
	return nil
}

// writePolicyGate v5.9.0（方案 P0-1）：ROE 写策略确定性门（existence-proof 档）。
// 命中"写语义"命令模式时拦截——与 profileGate 互补：profile 管违禁动作类别，
// 本门管 ROE 写影响上限。full 档不走此门。GET/HEAD/OPTIONS 只读请求豁免。
func (o *Orchestrator) writePolicyGate(p *store.Project, stageID, command, channel string) (bool, string) {
	lc := strings.ToLower(command)
	// 只读豁免：GET/HEAD/OPTIONS 类 HTTP（curl -X GET、GET /path、http_request method=GET）
	readOnly := strings.Contains(lc, "-x get") || strings.Contains(lc, "get http") ||
		strings.Contains(lc, "curl -s") && !strings.Contains(lc, "-d") && !strings.Contains(lc, "--data") && !strings.Contains(lc, "-x")
	if readOnly {
		return false, ""
	}
	writePatterns := []string{
		"-x post", "-x put", "-x delete", "-x patch", "--data", "--data-raw", "--data-binary",
		"insert into", "delete from", "drop table", "drop database",
		"> /etc/", ">> /etc/", "useradd", "usermod", "reg add",
		"sc create", "schtasks /create", "wmic ", "net user ", "net localgroup",
		"rm -rf", "mkfs", "dd if=", "> /dev/",
	}
	for _, wp := range writePatterns {
		if strings.Contains(lc, wp) {
			o.log(p, stageID, fmt.Sprintf("⛔ ROE 写策略拦截（write_policy=existence-proof，%s 通道）：命令含写语义", channel))
			_, _ = o.store.AddEvidence(&store.EvidenceRecord{ProjectID: p.ID, Stage: stageID, Type: "command",
				Input:  truncateText(command, 200),
				Output: "被 ROE 写策略门拦截（write_policy=existence-proof：写操作仅做存在性证明）。isolated_lab 档自动获得 full 写策略（v6.0.0 派生）；部署级 YAML 可显式覆盖。",
				Risk:   tools.L1Write, ApprovedBy: "roe-write-policy-gate"})
			return true, fmt.Sprintf("ROE 写策略拦截（write_policy=existence-proof）：该命令含写语义（命中 %s）。写操作仅做存在性证明；如属隔离靶场请切换执行档（isolated_lab 自动获得 full 写策略），或由部署级 ROE YAML 显式覆盖。", wp)
		}
	}
	return false, ""
}

// governanceGates v5.3.1 P0-2：全部命令执行通道的统一确定性门——执行档（profile）+ 注册写 + 范围。
// 此前（v5.2.0）双门只在 shell_open 生效，run_command/run_async/shell_write/hexstrike 等主通道
// 全部绕过；本函数作为唯一接线点消除断层。阻断发生在风险分级与审批之前（不烧审批槽位），
// 并统一留证（证据链可回溯每一条被拦动作）。skipProfile 供 install_tool 使用：
// 安装 mysqldump 等客户端本身是合规基建动作，profile 约束其「使用」而非「安装」。
// guardEnabled v6.1.0（S1 修复方案）：治理硬门三态开关统一读取——o.cfg 为 nil（极简测试环境）
// 时按缺省 true，不因配置缺席降级；显式 false 才回退（回滚须留配置变更与重启审计）。
func (o *Orchestrator) guardEnabled(get func(*config.GuardConfig) *bool) bool {
	if o.cfg == nil {
		return true
	}
	return config.FlagOrDefault(get(&o.cfg.Guard), true)
}

// governanceGates 统一命令治理链（v6.1.0 起第一道为授权门）。
func (o *Orchestrator) governanceGates(p *store.Project, stageID, command, channel string, skipProfile bool) string {
	// v6.1.0（S1 修复方案①）：授权校验早于写门、风险分级与审批——原链路授权状态只是上下文
	// 提示，非 Web 入口可启动未授权项目并让 L0 网络命令自动批准。显式 false 仅用于事故回滚。
	if o.guardEnabled(func(g *config.GuardConfig) *bool { return g.EnforceAuthorization }) && !p.Authorized {
		msg := "执行被拦截：项目授权未确认；补充书面授权并重新创建项目后重试。"
		_, _ = o.store.AddEvidence(&store.EvidenceRecord{ProjectID: p.ID, Stage: stageID,
			Type: "command", Input: truncateText(command, 200), Output: msg,
			Risk: tools.Forbidden, ApprovedBy: "authorization-gate"})
		o.log(p, stageID, fmt.Sprintf("⛔ 授权门拦截（%s 通道）：项目未确认书面授权", channel))
		return msg
	}
	// v6.1.0（S1 修复方案⑩）：ROE 红线确认门——授权复选框只证明创建时提交了书面授权，
	// 操作红线（范围/禁止项/频率/数据边界）仍须 S1 复述并经 request_user_input(purpose=roe_ack)
	// 确认；确认前任何阶段任何命令通道拦截（回滚 guard.require_s1_roe_ack=false，须审计）。
	if o.guardEnabled(func(g *config.GuardConfig) *bool { return g.RequireS1ROEAck }) && strings.TrimSpace(p.ROEAcknowledgedAt) == "" {
		msg := "执行被拦截（ROE 红线确认）：本项目 ROE 红线四要素尚未确认——请先向用户复述①测试范围②禁止项③频率限制④数据边界，并调用 request_user_input(purpose=roe_ack) 取得明确 yes；确认前可梳理资料/登记资产/写交付物，任何命令与外部请求不放行。"
		_, _ = o.store.AddEvidence(&store.EvidenceRecord{ProjectID: p.ID, Stage: stageID,
			Type: "command", Input: truncateText(command, 200), Output: msg,
			Risk: tools.Forbidden, ApprovedBy: "roe-ack-gate"})
		o.log(p, stageID, fmt.Sprintf("⛔ ROE 红线确认门拦截（%s 通道）：四要素未确认", channel))
		return msg
	}
	// v6.1.0（S1 修复方案③）：S1 阶段门——仅被动查询；扫描器动词/目标侧 HTTP 一律拒（置于
	// 授权门之后、写门之前；工具面过滤只是引导，本门是安全边界，直调/绕道仍拦）。
	if stageID == "s1" && o.guardEnabled(func(g *config.GuardConfig) *bool { return g.EnforceS1L0 }) {
		if msg := o.s1ActionGate(p, stageID, command, channel); msg != "" {
			return msg
		}
	}
	// v6.1.0（S1 修复方案⑧）：ROE 运行时门——时间窗/连接预算/冷却在审批前确定性判定；
	// rotation 未接入出口层前仅登记（UnenforcedFields 诚实披露，不伪装已强制）。
	if o.guardEnabled(func(g *config.GuardConfig) *bool { return g.EnforceROERuntime }) && o.roeRuntime != nil {
		if msg := o.roeRuntime.Check(stageID, command, time.Now().UTC()); msg != "" {
			_, _ = o.store.AddEvidence(&store.EvidenceRecord{ProjectID: p.ID, Stage: stageID,
				Type: "command", Input: truncateText(command, 200), Output: msg,
				Risk: tools.Forbidden, ApprovedBy: "roe-runtime-gate"})
			o.log(p, stageID, fmt.Sprintf("⛔ ROE 运行时门拦截（%s 通道）", channel))
			return msg
		}
	}
	// v5.9.0（方案 P0-1）/ v6.0.0（通用型三层治理参数）：ROE WritePolicy 确定性写门——
	// 生效值取 effectiveWritePolicy（部署级 YAML > 执行档派生 > unset）。existence-proof 档下
	// 命令含写语义时在审批前确定性拦截（审批策略配 all 时不再被架空）；full/unset 档不走此门
	// （unset=未注册部署级写策略，生产写操作按审批矩阵管控，历史行为不变）。
	if wpEff := o.effectiveWritePolicy(p); wpEff != "full" && wpEff != "unset" {
		if blocked, msg := o.writePolicyGate(p, stageID, command, channel); blocked {
			return msg
		}
	}
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
	// v7.6.0（B7 引擎自省治理）：引擎本体/内部实现属运行时资产——实证 某实战项目 S4
	// 收口期 grep 引擎二进制找 endpoint_enc、探引擎 API、读其他项目解题脚本（auto-approved
	// 灰色行为，实测报告《优化方案》§B7）。门校验规则以拦截回执给出的期望样例与 diff 为准，
	// 读取引擎内部实现不是合规修复路径；配合 A2 的自解释门报错消除逆向动机。
	if msg := o.engineIntrospectionBlocked(command); msg != "" {
		_, _ = o.store.AddEvidence(&store.EvidenceRecord{ProjectID: p.ID, Stage: stageID,
			Type: "command", Input: truncateText(command, 200), Output: msg,
			Risk: tools.Forbidden, ApprovedBy: "engine-introspection-gate"})
		o.log(p, stageID, fmt.Sprintf("⛔ 引擎自省被拦截（v7.6.0 B7 %s 通道）", channel))
		return msg
	}
	// v6.1.0（S1 修复方案②）：影子资产门——已登记未授权测试资产（shadow_pending/out_of_scope/
	// conditional/unknown）在任何通道、任何 strict_scope 配置下先于范围门拦截并留证。
	if msg := o.shadowAssetGate(p, stageID, command, channel); msg != "" {
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

// accountUsageChat 对话轮次记账（stage=chat）。v7.5.0（A3/A4）：种类分账 + 零 usage 估算兜底。
func (o *Orchestrator) accountUsageChat(projectID string, u llm.Usage, msgs []llm.Message, resp *llm.Message) {
	if projectID == "" {
		return
	}
	p := o.mustProject(projectID)
	o.accountUsageC(p, "chat", u, usageCtx{kind: "chat", msgs: msgs, resp: resp})
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
// v6.3.2：WS 副本携带 seq——执行流双通道（WS 实时 + 8s 轮询增量）以 seq 权威去重，
// 此前 WS 副本不推进 lastSeq，同一条消息被轮询再投一遍造成前端重复显示。
func (o *Orchestrator) streamMsg(projectID, stage, text string) {
	text = truncateText(text, 4000)
	seq, _ := o.store.AddStream(projectID, &store.StreamRecord{Kind: "msg", Stage: stage, Role: "assistant", Text: text})
	o.bus.Publish(projectID, "stage_msg", map[string]any{"stage": stage, "text": truncateText(text, 2000), "seq": seq})
}

// streamTool 持久化并推送一次工具调用（阶段执行与对话模式通用，刷新后可回填工具调用页签）。
// v6.3.2：WS 副本携带 seq（双通道 seq 权威去重，同 streamMsg）。
func (o *Orchestrator) streamTool(projectID, stage string, tc llm.ToolCall, result string) {
	// v5.6.0 秘密卫生（审计修复高危#2）：工具参数/结果持久化前统一脱敏——
	// 原实现把 tc.Arguments 前 800 字节原样落执行流+推 UI，store_credential 的 secret
	// 参数会绕过加密仓库明文留存；现在参数走 JSON 感知脱敏、结果走模式兜底脱敏。
	rec := &store.StreamRecord{Kind: "tool", Stage: stage, Tool: tc.Name,
		Args: truncateText(maskToolArgsJSON(tc.Arguments), 800), Result: truncateText(maskSensitiveText(result), 1600)}
	seq, _ := o.store.AddStream(projectID, rec)
	o.bus.Publish(projectID, "stage_tool", map[string]any{"tool": rec.Tool, "args": rec.Args, "result": rec.Result, "stage": stage, "seq": seq})
}

// ---------- 项目生命周期 ----------

func (o *Orchestrator) CreateProject(in *store.Project) (*store.Project, error) {
	if strings.TrimSpace(in.Name) == "" {
		return nil, fmt.Errorf("项目名称必填")
	}
	// v6.1.0（S1 修复方案①）：授权硬门第一级——创建即拒绝未授权项目（Web 层校验之外的
	// 内部 API/历史路径不再能制造可运行未授权项目）。返回错误不落库，无需留证。
	if o.guardEnabled(func(g *config.GuardConfig) *bool { return g.EnforceAuthorization }) && !in.Authorized {
		return nil, fmt.Errorf("创建被拒绝：必须确认已获得书面授权后才能创建项目")
	}
	p := &store.Project{
		Name: in.Name, Target: in.Target, Scope: in.Scope, ROE: in.ROE,
		TestType: in.TestType, TimeWindow: in.TimeWindow,
		Contact: in.Contact, SuccessCriteria: in.SuccessCriteria,
		AuthInfo: in.AuthInfo, StrictScope: in.StrictScope, BudgetTokens: in.BudgetTokens,
		Authorized: in.Authorized, AutoApprove: in.AutoApprove,
		OOBRequired: in.OOBRequired, // v6.1.0（方案⑪）：OOB 需求声明随项目持久化
		PreApproved: in.PreApproved, // v6.0.0：预批准档随项目持久化（store 层归一化，缺省 none）
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
// grantResumeBudget v7.7.2：手动续跑预算授予——failed 阶段 summary 含「token 预算耗尽」时，
// 授予幅度 = 上限 × ResumeGrantPct（默认 25%）记入 p.BudgetGrants（持久化），护栏
// （runStage）读取上限+授予。每次手动续跑可再次授予（用户点击=追加消费授权）；
// ResumeGrantPct=0 关闭。副作用：log + 时间线留痕。
func (o *Orchestrator) grantResumeBudget(p *store.Project) {
	if p.Status != "failed" {
		return
	}
	for sid, st := range p.StageStates {
		if st == nil || st.Status != "failed" || !strings.Contains(st.Summary, "token 预算耗尽") {
			continue
		}
		base := p.BudgetTokens
		if base <= 0 {
			base = o.cfg.MaxProjectTokens
		}
		pct := o.cfg.Engine.ResumeGrantPct
		if pct <= 0 {
			return // 0=关闭授予（续跑前须手动提额）
		}
		grant := base * int64(pct) / 100
		if grant <= 0 {
			grant = base / 4
		}
		p.BudgetGrants += grant
		_, _ = o.store.AddTimeline(&store.TimelineEvent{ProjectID: p.ID, Stage: sid,
			Event:  "v7.7.2 续跑预算授予",
			Detail: fmt.Sprintf("failed 阶段（token 预算耗尽）手动续跑 → 授予增量预算 +%d tokens（累计授予 %d）；护栏上限 = %d + 授予", grant, p.BudgetGrants, base)})
		o.log(p, sid, fmt.Sprintf("🪙 续跑预算授予：+%d tokens（累计 %d）——手动继续视为追加消费授权", grant, p.BudgetGrants))
		break // 每次续跑只授一次
	}
}

func (o *Orchestrator) StartProject(projectID string) error {
	p, err := o.store.GetProject(projectID)
	if err != nil {
		return err
	}
	// v6.1.0（S1 修复方案①）：授权硬门第二级——历史未授权项目（含旧库 false 值）禁止续跑；
	// fail-closed 预期，补授权须重新创建/补录，严禁批量迁移为 true。
	if o.guardEnabled(func(g *config.GuardConfig) *bool { return g.EnforceAuthorization }) && !p.Authorized {
		_, _ = o.store.AddEvidence(&store.EvidenceRecord{ProjectID: p.ID, Stage: "",
			Type: "lifecycle", Input: "StartProject", Output: "启动被拒绝：项目授权未确认",
			Risk: tools.Forbidden, ApprovedBy: "authorization-gate"})
		o.log(p, "", "⛔ 授权门拦截：历史项目授权未确认，拒绝启动")
		return fmt.Errorf("启动被拒绝：项目授权未确认；补充授权并重新创建项目")
	}
	if p.Status == "running" {
		return fmt.Errorf("项目已在运行")
	}
	ctx, cancel := context.WithCancel(context.Background())
	o.mu.Lock()
	o.running[projectID] = cancel
	o.mu.Unlock()

	// v7.7.2 修复（用户实报 某历史任务）：token 预算耗尽的 failed 项目手动续跑时
	// 自动授予预算增量——旧路径无任何增量，runStage 首次预算检查立即再失败，"手动继续"
	// 语义悬空。用户点击继续 = 追加消费授权（时间线留痕可审计；熔断语义不变）。
	o.grantResumeBudget(p)
	p.Status = "running"
	p.FinishedAt = "" // v5.9.3：重跑/续跑清残留终态时间（实证：finished_at 残留上次收口，首页总时长被冻结成 36m14s 且误显示 ⏱）
	if p.StartedAt == "" {
		p.StartedAt = time.Now().Format(time.RFC3339) // v2.6：首次启动时间（断点续跑保留，仪表盘运行时长基准）
	}
	_ = o.store.SaveProject(p)
	o.bus.Publish(projectID, "project", p)
	o.log(p, "", fmt.Sprintf("项目启动：目标=%s；授权范围=%s", p.Target, cappedText(p.Scope, 1500)))

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
	// v7.0.0：OOB 回连通道随项目结束回收（interactsh-client/监听器由引擎守护，不进 run_async 任务池）
	if o.oob != nil {
		o.oob.Stop(projectID)
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
	p.FinishedAt = "" // v5.9.3：手动重跑同样清残留终态时间（与 Start 同口径）
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
	o.log(p, p.CurrentStage, "⚙ 引擎进程重启，流水线在此处中断（启动恢复：已置为待续跑）。请在「阶段流水线」手动重跑中断阶段继续，或重新启动项目（已完成的阶段会自动跳过）。v7.6.0 B1：后台作业重跑优先按落盘点续接（逐行落盘 + resume 跳过已完行，实测矩阵 resume_skip 模式），禁止无脑从头重算。")
}

// isRerunRoot v5.8.0：该阶段是否为 loopback 直接目标（非下游连带）。
func isRerunRoot(rerun []string, stageID string) bool {
	for _, r := range rerun {
		if r == stageID {
			return true
		}
	}
	return false
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
		// v7.6.0（B2③ 用户决策②）：首耗尽自动收割-续跑一次——收割在途产出后以同额增量
		// 预算自动续跑（预算数学由 runStage 本地 iter 计，重入即新预算）；第二次耗尽仍走
		// pause 等人工。显式配置 budget_auto_resume=false 恢复旧行为。
		if st := p.StageStates[stageID]; st != nil && st.Status == "paused" {
			if strings.Contains(st.PauseReason, "预算耗尽") && config.FlagOrDefault(o.cfg.Engine.BudgetAutoResume, true) && st.BudgetResumes < 1 {
				st.BudgetResumes++
				_ = o.store.SaveProject(p)
				o.log(p, stageID, fmt.Sprintf("🔄 预算自动续跑（v7.6.0 B2③ 第 %d/%d 次）：在途产出已收割落账，授予同额增量预算从断点继续；再次耗尽将暂停等待人工", st.BudgetResumes, 1))
				if err := o.runStage(ctx, p, stageID); err != nil {
					if ctx.Err() != nil {
						return
					}
					p.Status = "failed"
					p.CurrentStage = stageID
					p.FinishedAt = time.Now().Format(time.RFC3339)
					_ = o.store.SaveProject(p)
					o.bus.Publish(p.ID, "project", p)
					o.log(p, stageID, "⛔ 自动续跑异常中断，流水线停止: "+err.Error())
					return
				}
				st2 := p.StageStates[stageID]
				if st2 != nil && st2.Status == "done" {
					continue // 自动续跑收口成功，推进后续阶段
				}
				if st2 != nil && st2.Status == "failed" {
					// v7.6.0 复核修复：自动续跑后阶段 failed——按失败停跑口径，不得误标 paused
					p.Status = "failed"
					p.CurrentStage = stageID
					p.FinishedAt = time.Now().Format(time.RFC3339)
					_ = o.store.SaveProject(p)
					o.bus.Publish(p.ID, "project", p)
					o.log(p, stageID, "⛔ 自动续跑后阶段未收口（"+st2.Summary+"），流水线停止（可手动重跑该阶段后继续）")
					return
				}
				// 续跑后仍 paused（第二次耗尽）：落入下方 paused 停推处理
			}
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
	// v5.9.0（方案 P0-2）：项目级累计回环额度——旧实现消费后清零，上限（默认 3）变成
	// "每批 3 次"而非全项目 3 次；现保留已消费记录，loopback 登记时按累计值判断超额。
	// rerun 列表本身仍清空（本轮已展开消费）。
	o.loops[p.ID] = nil
	o.loopMu.Unlock()
	o.loopMu.Lock()
	if o.loopTotal == nil {
		o.loopTotal = map[string]int{}
	}
	o.loopTotal[p.ID] += len(rerun)
	o.loopMu.Unlock()
	// v6.4.0（S4-⑩）：消费数持久化到项目记录——回环上限口径跨重启成立。
	if len(rerun) > 0 {
		p.LoopUsed = o.loopTotal[p.ID]
		_ = o.store.SaveProject(p)
	}
	// v5.8.0（审计 Top#4）：回环补跑后自动重跑下游阶段——s4 补跑产生的新发现必须
	// 进入利用（s5）与报告（s8）链，否则新线索静默丢失（审计实证断链）。
	stageIdx := map[string]int{}
	for i, sid := range pipeline {
		stageIdx[sid] = i
	}
	// 展开补跑集合：目标阶段 + 流水线顺序中位于其后、且产出链依赖它的下游（s5/s7/s8 等）
	rerunSet := map[string]bool{}
	for _, stageID := range rerun {
		rerunSet[stageID] = true
		if idx, ok := stageIdx[stageID]; ok {
			for _, sid := range pipeline[idx+1:] {
				// spec 头是并列专项不是下游；s7/s8 是全局收口必跟；s5/s6 是利用链
				if strings.HasPrefix(sid, "spec") {
					continue
				}
				rerunSet[sid] = true
			}
		}
	}
	// 按流水线顺序重跑（v5.9.0 方案 P0-2：与主流水线完全对齐——postExploitGate、
	// failed 停跑、paused 停跑三语义统一，此前回放分支绕过门且 paused 被误收 done）
	for _, stageID := range pipeline {
		if ctx.Err() != nil {
			return
		}
		if !rerunSet[stageID] {
			continue
		}
		st, ok := p.StageStates[stageID]
		if ok && st.Status == "running" {
			continue // 正在跑则不重复
		}
		if st == nil {
			st = &store.StageState{Status: "pending"}
			p.StageStates[stageID] = st
		}
		if st.Status == "skipped" {
			continue // skipped（含 postExploit 范围决策）不因回环重开
		}
		// v5.9.0：与主流水线同款 s6 勾选门（明确意图优先，但回放不越权打开用户未勾选的 s6）
		if o.applyPostExploitGate(p, stageID, st) {
			continue
		}
		downstream := stageIdx[stageID] > 0 && !isRerunRoot(rerun, stageID)
		o.log(p, stageID, "↩ 执行回环补跑（新线索触发"+map[bool]string{true: "·下游连带", false: ""}[downstream]+"）")
		if err := o.runStage(ctx, p, stageID); err != nil && ctx.Err() == nil {
			// v5.9.0：与主流水线同款 failed 停跑
			p.Status = "failed"
			p.CurrentStage = stageID
			p.FinishedAt = time.Now().Format(time.RFC3339)
			_ = o.store.SaveProject(p)
			o.bus.Publish(p.ID, "project", p)
			o.log(p, stageID, "⛔ 回环补跑阶段异常中断，流水线停止: "+err.Error())
			return
		}
		// v5.9.0：与主流水线同款 paused 停跑（预算耗尽不假装完成）
		if st := p.StageStates[stageID]; st != nil && st.Status == "failed" {
			p.Status = "failed"
			p.FinishedAt = time.Now().Format(time.RFC3339)
			_ = o.store.SaveProject(p)
			o.log(p, stageID, "⛔ 回环补跑阶段未收口，流水线停止")
			return
		}
		if st := p.StageStates[stageID]; st != nil && st.Status == "paused" {
			p.Status = "paused"
			p.CurrentStage = stageID
			_ = o.store.SaveProject(p)
			o.bus.Publish(p.ID, "project", p)
			o.log(p, stageID, "⏸ 回环补跑阶段预算耗尽暂停，流水线停止（"+st.Summary+"）")
			return
		}
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

// ensureReportContract v6.9.0 S8-①（第四轮核对扩接）：report.md 契约归位——complete_stage
// 前置守卫与预算代收口（auto_close，不经 complete_stage 直接跑确定性门）两条收口路径共用。
// 根目录已存在=通过；仅存在于 deliverables/ 自动归位后再通过；两处皆无=拦截（complete_stage
// 路径返回拦截文案；代收口路径返回 false 由调用方把缺报告转记 S8 复核清单）。错位写入在
// 所有 s8 收口路径上都先归位再过内容门，杜绝「内容门读不到报告即空转」的路径级绕过。
func (o *Orchestrator) ensureReportContract(p *store.Project, stageID string) (bool, string) {
	if stageID != "s8" {
		return true, ""
	}
	rootReport := filepath.Join(o.workspaceRoot(p.ID), "report.md")
	if _, err := os.Stat(rootReport); err == nil {
		return true, ""
	}
	nested := filepath.Join(o.workspaceRoot(p.ID), "deliverables", "report.md")
	if raw, rerr := os.ReadFile(nested); rerr == nil {
		if werr := os.WriteFile(rootReport, raw, 0o640); werr == nil {
			o.log(p, stageID, "📎 已将 deliverables/report.md 归位到工作区根目录（报告契约位置）")
			return true, ""
		}
	}
	o.log(p, stageID, "⚠ 收口被拦截：阶段 8 必须产出 report.md（工作区根目录）")
	return false, "收口失败：阶段 8 的核心交付物是渗透测试报告，必须用 write_file 写入工作区根目录 report.md（不要放进 deliverables/ 或分片后忘记合并）。写好后再次调用 complete_stage。"
}

// applyPostExploitGate v5.3.7：s6 后渗透勾选门。创建时未勾选 post_exploit（默认）→ s6 整段
// 置 skipped（Summary 记录决策原因，工作台手动重跑 s6 不受此门限制）。返回 true=已跳过。
func (o *Orchestrator) applyPostExploitGate(p *store.Project, stageID string, state *store.StageState) bool {
	if stageID != "s6" || p.PostExploit {
		return false
	}
	state.Status = "skipped"
	state.Summary = "后渗透未勾选（创建时用户决策）：提权/横向/权限维持/云逃逸/存量排查整段跳过；如需执行可在阶段流水线手动重跑 s6"
	// v5.9.1：skipped 不赋 StartedAt/EndedAt——跳过不是运行（此前 ended 有值 started 为空，
	// 首页阶段耗时图对该阶段显示 0/NaN）。
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
	// v7.5.1 修复（用户实报）：续跑轮次累计——旧实现每次启动清零且按本次运行写入，
	// 预算耗尽→手动继续后 UI 轮数从 0 重计，丢失上一遍工作量。Iterations 语义改为
	// 跨续跑累计（预算数学仍按本次运行的本地 iter 计，手动续跑授予新预算为设计行为）。
	state.Summary = "" // 清空上次（失败）残留摘要
	// v6.5.0（S5-⑥）：冲刺预警标记复位——重跑/回环重入可再次触发，同一次运行内去重
	state.SprintNotified = false
	// v7.7.0 P2：C27 代填防重入按阶段重置——重跑/回环重入恢复一次代填机会
	if o.c27Tried != nil {
		delete(o.c27Tried, p.ID+"|"+stageID)
	}
	// v7.6.0（C7 双预算对称化）：续跑/重跑语义显式化——轮次预算按运行重置（设计行为），
	// token 护栏为项目级持久计数不随重启重置（v7.5.0 A2）；显式标注防「预算语义模糊导致
	// 的重复投递」（实测 某实战项目 S4 矩阵重做轮，实测报告 §C7）。
	if strings.Contains(state.PauseReason, "预算") {
		o.log(p, stageID, "ℹ️ 预算语义提示（v7.6.0 C7）：本次运行授予全新轮次预算（历史轮次已累计入 iterations 展示值）；项目级 token 护栏为持久计数不随重启重置——已投递的探测勿因续跑重复发起（回放拦截 + 异步落盘兜底）")
	}
	// v5.9.1 首启保护 + v5.9.3 重跑清残留收口时间（beginStageRun 统一口径：StartedAt 不覆盖，
	// 旧 EndedAt 即刻作废——否则重跑期间阶段带旧收口时间，首页对账把旧区间重复计入）。
	beginStageRun(state)
	_ = o.store.SaveProject(p)
	o.bus.Publish(p.ID, "stage", map[string]any{"stage": stageID, "status": "running"})
	o.log(p, stageID, fmt.Sprintf("▶ 阶段[%s] %s 启动", stageID, head.Name))
	// v7.0.0 核对加固⑨（方案 §4.4「warmup 启动」的确定性落地）：声明 OOBRequired 的项目
	// 在 S1 启动时引擎自动预建回连通道——懒启动的确定性前移，不再依赖模型记得调 oob_check；
	// 结果由 OOBCoord 落 evidence/oob/channel.txt（S1 收口门⑪直接核验）并落执行流日志；
	// 预建失败不阻塞开工，盲态门按真实通道状态裁决。
	if stageID == "s1" && p.OOBRequired && o.guardEnabled(func(g *config.GuardConfig) *bool { return g.RequireS1OOBChannel }) {
		_ = o.oob.Ensure(p, stageID)
	}
	// v7.6.0（F3 时间线机械底稿）：s7 开工时引擎从 timeline 桶直出逐事件底稿（时间戳精确）
	// ——实证 某实战项目 S5 利用时间线手写漂移 2-4 分钟且两行顺序颠倒（实测报告 §F3）：
	// 时间戳类交付物以机械导出为底稿，模型只做分析层润色。
	if stageID == "s7" {
		o.writeTimelineDraft(p, stageID)
	}
	// v7.7.0 P3②：S4 收口前自述面差距表（checklist 存在时；台账投影零模型轮次）
	if stageID == "s4" {
		o.writeChecklistGap(p, stageID)
	}
	// v7.7.0 P3③：S8 开工 report.md 骨架（keyFigures+findings 预填；已有则不覆盖）
	if stageID == "s8" {
		o.writeReportSkeleton(p, stageID)
	}

	sys := strings.Join([]string{
		"[[HEAD:" + stageID + "]]", // 头标记：供 Mock/审计识别当前阶段
		o.coreLoop,
		head.Body,
	}, "\n\n")

	msgs := []llm.Message{
		{Role: "system", Content: sys},
		{Role: "user", Content: o.buildContextPack(p, stageID)},
	}

	toolDefs := o.toolDefsForStage(stageID) // v6.1.0（方案③）：阶段感知工具面——S1 隐藏执行/交互/子代理类工具
	mon := &execMonitor{}                   // 执行监控：循环调用检测（PentAGI execution monitor 移植）
	// v2.3.2 阶段差异化迭代上限：报告/文档阶段（s8）写入量大且需承接全部交付物
	// v4.4 多目标自适应（方向二B）：按目标数线性放大（base+(N-1)*perTarget，封顶 3×base；v6.1.0 方案⑤ s1 纳入、v6.3.0 S3-② s3 纳入；v6.6.0 SP-① specA/specB1/specB2 纳入；v6.7.0 S6-⑩ s6 纳入；v6.9.0 S8-④ s8 纳入——名单 s1/s2/s3/s4/s5/s6/s8/specA/specB1/specB2）
	nTargets := countProjectTargets(p)
	budget := stageBudget(o.cfg.Engine.MaxStageIterations, stageID, nTargets, o.cfg.Engine.PerTargetRounds)
	if nTargets > 1 && o.cfg.Engine.PerTargetRounds > 0 && (stageID == "s1" || stageID == "s2" || stageID == "s3" || stageID == "s4" || stageID == "s5" || stageID == "s6" || stageID == "s8" || stageID == "specA" || stageID == "specB1" || stageID == "specB2") { // v6.1.0 方案⑤ s1 纳入；v6.3.0 S3-② s3 纳入；v6.6.0 SP-① 三专项纳入；v6.7.0 S6-⑩ s6 纳入；v6.9.0 S8-④ s8 纳入 stageBudget 与上下文承诺同名单
		o.log(p, stageID, fmt.Sprintf("🎯 多目标轮次自适应：%d 个目标 → 本阶段预算 %d 轮（基础 %d，每增 1 目标 +%d）",
			nTargets, budget, o.cfg.Engine.MaxStageIterations, o.cfg.Engine.PerTargetRounds))
	}
	for iter := 0; iter < budget; iter++ {
		if ctx.Err() != nil {
			state.Status = "killed"
			endStageRun(state) // v5.9.3：熔断收口时间落盘（此前 killed 无 EndedAt，首页对账缺角）
			_ = o.store.SaveProject(p)
			return ctx.Err()
		}
		// 预算护栏：项目级 BudgetTokens 优先（v3.4.0 接线原死字段），否则全局配置
		// v7.7.2：护栏上限 += 手动续跑授予累计（BudgetGrants）——授予在 StartProject 注入
		tokBudget := p.BudgetTokens
		if tokBudget <= 0 {
			tokBudget = o.cfg.MaxProjectTokens
		}
		tokBudget += p.BudgetGrants
		if tokBudget > 0 && o.projectTokens(p.ID) >= tokBudget {
			state.Status = "failed"
			state.Summary = "token 预算耗尽（max_project_tokens）"
			endStageRun(state) // v5.9.3：失败收口时间落盘（此前 failed 无 EndedAt，首页对账缺角）
			_ = o.store.SaveProject(p)
			o.log(p, stageID, "⛔ token 预算耗尽，阶段中止（预算护栏）")
			return fmt.Errorf("token 预算耗尽")
		}
		state.Iterations++ // v7.5.1：跨续跑累计（本轮预算由本地 iter 计）
		// v7.6.3（用户实报 某历史任务）：运行中阶段周期性落盘——旧实现轮次只在特定
		// 事件（后台任务/审批）落盘，长时间纯 LLM 往返的运行（实证 s4 跑 111min）UI 轮数
		// 恒显 0，用户无法判断阶段是否健康推进。每 5 轮同步一次（含 LastActiveAt）。
		if iter%5 == 4 {
			endStageRun(state)
			_ = o.store.SaveProject(p)
		}
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
		compacted := false // v7.6.0（C1）：本轮发生压缩 → 记账打 cache_reset 标记（前缀缓存命中率归因）
		// v7.6.0（C1 集中式压缩）：触发线=ContextBudgetTokens，裁剪目标=CompactionTargetPct%
		//（默认 70）——单次加深裁剪减少触发频次，直接对准「压缩×缓存打架」的 3.5M 全价浪费。
		c1Floor := o.cfg.Engine.ContextBudgetTokens * o.cfg.Engine.CompactionTargetPct / 100
		if cm, nc := compactMsgsWithArchiveFloor(msgs, o.cfg.Engine.ContextBudgetTokens, c1Floor, o.cfg.Engine.ContextKeepRecent, receiptArchive); nc > 0 {
			msgs = cm
			compacted = true
			est := estimateTokens(msgs)
			o.log(p, stageID, fmt.Sprintf("🧹 上下文窗口压缩（集中式，目标 %d%%）：%d 条旧消息已存根化（当前估算 %d tokens；工具回执原文已归档可按 receipt id 检索）", o.cfg.Engine.CompactionTargetPct, nc, est))
			// v7.6.0（C2）：上下文水位分项观测——压缩后仍超 120K 说明稳定头占比过高
			//（实测 main 单次输入 171K 峰值的机制性来源）；分项数字供工具面/上下文包瘦身定位。
			if est > 120_000 {
				sysTok := 0
				if len(msgs) > 0 && msgs[0].Role == "system" {
					sysTok = estimateTokens(msgs[:1])
				}
				toolTok := estToolTokens(toolDefs)
				o.log(p, stageID, fmt.Sprintf("⚠ 上下文水位 %d tokens 超 120K 观测线（分项：system/宪法头≈%d 工具面≈%d 运行消息≈%d——C2 水位治理对象）", est, sysTok, toolTok, est-sysTok-toolTok))
			}
			// v7.5.0（E1 混合压缩）：仅在真实发生压缩时注入结构化历史摘要（aux 模型 + sha256
			// LRU 去重）——治纯存根丢中段语义诱发的重复检索/重跑；失败静默回退纯存根口径。
			if hybrid := compactHybrid(msgs, o.cfg.Engine.ContextKeepRecent, o.compactionSummarizer(p, stageID)); hybrid != "" {
				msgs = append(msgs, llm.Message{Role: "user", Content: hybrid})
				o.log(p, stageID, "🧹 混合压缩：已注入结构化历史摘要（存根细节可按 receipt id 检索原文）")
			}
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
		// v6.5.0（S5-⑥）：触发判式抽为 shouldInjectSprint 纯函数——进入「剩 ≤1/3」区间
		// 首轮触发一次（旧 remain == budget/3 精确等于在 budget 非 3 的倍数时永不命中，
		// 多目标放大后 s4/s5 的 V3 就绪投递引导整段丢失）。
		if remain := budget - iter - 1; shouldInjectSprint(budget, remain, state.SprintNotified) {
			state.SprintNotified = true
			_ = o.store.SaveProject(p)
			// v7.6.0（B2② 用户决策②「预警不收紧」）：1/3 预警降级为纯信息注入——旧文本把
			// "立即批量投递+进入收口流程"写成了事实指令，实测诱发模型在预算尚裕时提前转入
			// 簿记收口（某实战项目 S5 60 轮内收口动作占比过高）。现仅同步预算态势与
			// 就绪资产清单，收口动作推迟到「剩 10 轮」指令（下方 remain==9 分支）。
			sprintMsg := "ℹ️ 预算态势同步（仅信息，不要求改变当前工作）：本阶段剩余约 1/3 预算。供参考的就绪资产盘点如下（无需立即转入收口；测试工作按原计划推进，收口安排以「剩 10 轮」指令为准）。"
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
				vtCap := o.cfg.Engine.SprintVTCap // v7.5.0（C3）：冲刺枚举设顶（默认 15，与上下文包 VT 块同口径）
				if vtCap <= 0 {
					vtCap = 15
				}
				for _, t := range sortedVTs {
					if t.Status != "ready" && t.Status != "pending" {
						continue
					}
					if t.Priority <= 1 {
						p1Count++
					}
					if len(lines) >= vtCap {
						continue // 计数照走（P1 保底口径不变），枚举行设顶防全量注入
					}
					tag := "P" + strconv.Itoa(t.Priority)
					lines = append(lines, fmt.Sprintf("- %s[%s/%s] %s（就绪资产: %s）", t.ID, t.Status, tag, truncateText(t.Title, 50), truncateText(t.ReadyAssets, 60)))
				}
				if len(lines) > 0 {
					totalVT := 0
					for _, t := range sortedVTs {
						if t.Status == "ready" || t.Status == "pending" {
							totalVT++
						}
					}
					sprintMsg += "\n\n🧾 验证队列待消耗（引擎枚举，按 Priority 升序投递）：\n" + strings.Join(lines, "\n")
					if totalVT > len(lines) {
						sprintMsg += fmt.Sprintf("\n- …（其余 %d 条见 record_vt/update_vt 与工作台验证队列页，本枚举已设顶 %d 条）", totalVT-len(lines), vtCap)
					}
					if p1Count > 0 {
						sprintMsg += fmt.Sprintf("\n\n🛡️ P1 保底：检测到 %d 个 P1 级 VT——剩余 1/3 轮次内 P1 优先消费，禁止被泛化收口挤掉；确实无法投递的 P1 必须进 ready_but_unexecuted 由后续阶段承接。", p1Count)
					}
				}
			}
			// v7.1.0 P7/A2：冲刺指令随附通道健康归因与执行卡漏斗（引擎直出，模型零翻找）
			if hs := o.toolHealthSummary(p.ID, stageID); hs != "" {
				sprintMsg += "\n\n🩺 " + hs
			}
			if cf := o.cardFunnelLine(p); cf != "" {
				sprintMsg += "\n🃏 " + cf
			}
			msgs = append(msgs, llm.Message{Role: "user", Content: sprintMsg})
			o.log(p, stageID, "ℹ️ 预算态势同步已注入（剩约 1/3，仅信息——v7.6.0 B2② 预警不收紧）")
		} else if remain == 9 {
			// v7.6.0（B2②）：收口指令从「剩 3 轮」前移到「剩 10 轮」——预算放宽后单阶段绝对
			// 轮数更大，3 轮收口窗对 240 轮级阶段过窄（实测收口门多轮拦截需要修复轮次）；
			// 10 轮窗给足门修复往返，同时仍保有硬截止语义。
			msgs = append(msgs, llm.Message{Role: "user", Content: "⛔ 收口指令：本阶段剩最后 10 轮，禁止再发起新的测试面（不再开启新目标/新漏洞类的首轮探测；已开始的验证可完成）。现在按序推进：1) 已确证未入库的结论补录 record_finding / update_coverage；2) 用 write_file 撰写本阶段交付物（未完成项列入「待续清单」）；3) 调用 complete_stage 收口（s4/s5/三专项携带顶层字段 ready_but_unexecuted / l2_approved_unused，无内容传空数组 []）。若收口门拦截，按拦截意见最小修补后立即重提，不要开新工作。"})
			o.log(p, stageID, "⛔ 收口指令已注入（剩 10 轮，v7.6.0 B2② 前移）")
		}
		// v7.7.0 P1 收敛驱动收口（docs/优化方案_实战提速五项 §一.P1）：轮尾判定——本轮无
		// 产出则 idle+1（W5 冷却期豁免，方案防误收敛条款），三重条件（27 类执行卡无 queued
		// + 候选账本无 open + 连续 ConvergenceRounds 轮无产出）满足且预算已耗 30% → 注入一次
		// 收敛收口指令（不强制代收口，全部硬门照过；每阶段至多 1 次；s1 排除=范围界定无收敛语义，
		// s8 排除=报告阶段天然无"确证产出"口径）。
		// v7.7.0 十四轮核对修正（方案保真）：收敛信号收窄到 s4/s5——方案定义的适用域是
		// 「满预算重执行阶段」（实证 s4≈110/120 轮）。s2 侦察的产出=资产登记（不在产出
		// 事件集内，idle 会累积→误砍侦察广度）；s3 假设生成期同理。s6/s7 产出语义亦不同。
		if o.cfg.Engine.ConvergenceRounds > 0 && (stageID == "s4" || stageID == "s5") {
			o.convMarkIdle(p, stageID)
			if convMsg, fired := o.convMaybeFire(p, stageID, iter, budget); fired && convMsg != "" {
				msgs = append(msgs, llm.Message{Role: "user", Content: convMsg})
			}
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
				endStageRun(state) // v5.9.3
				_ = o.store.SaveProject(p)
				return ctx.Err()
			}
			state.Status = "failed"
			state.Summary = "LLM 调用失败: " + err.Error()
			endStageRun(state) // v5.9.3
			_ = o.store.SaveProject(p)
			o.log(p, stageID, "LLM 调用失败: "+err.Error())
			log.Printf("[stage %s] LLM 调用失败: %v", stageID, err) // stdout 留痕（docker logs 可查）
			return err
		}
		// v7.5.0（A3/A4）：记账带种类与上下文——零 usage 估算兜底 + 逐调用明细落库
		o.accountUsageC(p, stageID, usage, usageCtx{kind: "main", msgs: msgs, tools: toolDefs, resp: &resp, cacheReset: compacted})
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
		// v7.5.0（D4）重复调用拦截回放：同工具+同参数（逐字节）第 3 次直接回放上次结果，
		// 不再真实重发（PentAGI ≥3 次回放同款；完全重复调用对测试零增益）。豁免清单见
		// replayExemptTools（合法轮询 + 交互式非幂等 + 流程状态类）。
		replayOn := config.FlagOrDefault(o.cfg.Engine.ReplayIntercept, true)
		replayHit := make([]bool, len(resp.ToolCalls))
		if replayOn {
			for i, tc := range resp.ToolCalls {
				if text, hit := mon.replayCheck(tc.Name, tc.Arguments); hit {
					replayHit[i] = true
					results[i] = text
					o.log(p, stageID, "♻ 重复调用拦截回放："+tc.Name)
				}
			}
		}
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
				if replayHit[i] {
					continue
				}
				wg.Add(1)
				go func(i int, tc llm.ToolCall) {
					defer wg.Done()
					results[i] = o.dispatch(ctx, p, stageID, tc)
				}(i, tc)
			}
			wg.Wait()
		} else {
			for i, tc := range resp.ToolCalls {
				if replayHit[i] {
					continue
				}
				results[i] = o.dispatch(ctx, p, stageID, tc)
			}
		}
		for i, tc := range resp.ToolCalls {
			// v7.5.0（D4）：真实执行结果登记为回放源
			if replayOn && !replayHit[i] {
				mon.replayRecord(tc.Name, tc.Arguments, results[i])
			}
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
			// v7.2.0 B1 真头作战参谋：收口自动评审一次，三类有限裁决建议经 PAE 裁决器落账本
			o.campaignBrainReview(ctx, p, stageID)
			// v7.3.0 C3 PoC 预生成工厂：s4 收口把自带 POC 的确证发现导出为就绪 PoC 文件
			if stageID == "s4" {
				o.pocFactory(p, stageID)
			}
			// v7.1.0 P9 stage_metrics：阶段收口结构化指标（轮次/token/自主提案/引擎代填次数）——
			// runtime-audit R1 的可观测数据面（效率与自主产出转化的基线），时间线留痕供 S8/审计消费。
			stageTokens := int64(0)
			if u, err := o.store.GetUsage(p.ID); err == nil {
				stageTokens = u.ByStage[stageID]
			}
			proposals, e1Fills := 0, 0
			if recs, err := o.store.ListAutonomy(p.ID); err == nil {
				for _, r := range recs {
					if r.Stage == stageID {
						proposals++
					}
				}
			}
			if tl, err := o.store.ListTimeline(p.ID); err == nil {
				for _, ev := range tl {
					if ev.Stage == stageID && strings.Contains(ev.Event, "E1' V3 引擎代填") {
						e1Fills++
					}
				}
			}
			metrics := fmt.Sprintf("rounds=%d stage_tokens=%d proposals=%d e1_autofill=%d（口径：rounds=本次运行轮次；iterations=跨续跑累计，见 StageState；stage_tokens=本阶段累计——v7.6.0 A8 单一事实源标注）", iter+1, stageTokens, proposals, e1Fills)
			if hs := o.toolHealthSummary(p.ID, stageID); hs != "" {
				metrics += " " + hs
			}
			_, _ = o.store.AddTimeline(&store.TimelineEvent{ProjectID: p.ID, Stage: stageID,
				Event:  "v7.1.0 stage_metrics",
				Detail: metrics})
			// v7.6.0（B3）：收口成功清空门连击状态
			state.GateFP, state.GateStreak, state.FirstGateBlockAt = "", 0, ""
			// v7.6.0（A3/E3）：库内实算核对注记（权威数字源）+ 阶段决策留痕聚合落账本
			if note := o.stageChecknote(p, stageID); note != "" {
				_, _ = o.store.AddTimeline(&store.TimelineEvent{ProjectID: p.ID, Stage: stageID,
					Event: "v7.6.0 引擎核对注记（A3）", Detail: note})
				o.streamMsg(p.ID, stageID, "🧮 引擎核对注记（库内实算，权威口径）："+note)
			}
			o.stageDecisionDigest(p, stageID)
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
		endStageRun(state) // v5.9.3
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
		endStageRun(state) // v5.9.3
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
	// v6.4.0（S4-⑤）：代收口路径的 V3 两清单同样落 StageState（护栏代填与正常收口同源，
	// S5 移交项注入块与 v3HandoverIssues 对账不区分收口路径）。
	state.V3Ready = readyItems
	state.V3L2 = l2Items
	// v5.5.0（修复方案 E）：预算耗尽不再一律把未完成阶段装作 done——默认 pause：
	// 阶段置 paused+项目暂停，人工提升预算/手动重跑后从断点继续（auto_close 档保留 v4.9 代收口旧行为）。
	// 代收口曾造成"未完成的 S4 被流水线继续推进"的结构性能力损失：后续阶段基于半成品交付物工作。
	if o.cfg.Engine.BudgetExhaustedPolicy != "auto_close" {
		state.Status = "paused"
		state.PauseReason = "token/迭代预算耗尽（可提升 max_stage_iterations 或项目 budget_tokens 后重跑续接）"
		endStageRun(state)
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
	// v6.9.0 S8-① 第四轮核对：代收口先归位报告契约再跑门（与 complete_stage 同源助手）——
	// 代收口不经 complete_stage，旧实现错位写入在该路径仍绕过全部内容门；无报告可归位时缺项
	// 转记 S8 复核清单（代收口非交互路径，不中断但缺项可见）。
	if ok, _ := o.ensureReportContract(p, stageID); !ok {
		_, _ = o.store.AddTimeline(&store.TimelineEvent{ProjectID: p.ID, Stage: stageID,
			Event: "v5.1.3 代收口确定性门拦截项（S8 复核清单）", Detail: "报告契约守卫（v6.9.0 S8-①）：report.md 缺失（工作区根目录与 deliverables/ 均无）——S8 复核时必须补写渗透测试报告后再交付"})
	}
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
	// v6.4.0（S4-⑩）：代收口（auto_close）同为收口终态——回环重入原因随收口清空，
	// 与 complete_stage 成功路径同口径（paused 路径不清空：阶段未完成，重跑仍需原因在场）。
	state.ReentryReason = ""
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
	// iarg v7.5.0（C2）：数字参数读取（read_file offset/limit 分段；JSON 数字可能是 float64）
	iarg := func(src map[string]any, k string) int {
		switch v := src[k].(type) {
		case float64:
			return int(v)
		case int:
			return v
		case string:
			n, _ := strconv.Atoi(strings.TrimSpace(v))
			return n
		}
		return 0
	}
	// v7.5.0（B2 配套）：S1 工具硬门（双模生效，防御纵深）——治理门只覆盖命令执行通道，
	// http_request/cred_command/spawn_subagent/propose 等非命令通道此前在 S1 直调会被真实
	// 执行（trimmed 模式仅隐藏 schema，隐藏≠拦截）。本门与 s1HiddenTools 单源对齐，兑现
	// stable 模式「本阶段调用将被拒绝」的描述承诺；trimmed 模式同为兜底（直调仍拦）。
	if stageID == "s1" && s1HiddenTools()[tc.Name] {
		o.log(p, stageID, "⛔ S1 工具门拦截："+tc.Name)
		_, _ = o.store.AddEvidence(&store.EvidenceRecord{ProjectID: p.ID, Stage: stageID,
			Type: "command", Input: truncateText(tc.Name+" "+tc.Arguments, 200),
			Output: "S1 阶段工具门拦截：被动侦察阶段禁用 " + tc.Name, Risk: tools.Forbidden, ApprovedBy: "s1-tool-gate"})
		return "执行被拦截（S1 阶段工具门）：" + tc.Name + " 不属于 S1 被动侦察阶段——目标侧探测/执行/子代理/提议类动作统一在 S2 及以后按授权与审批执行；本阶段请使用被动查询通道（CT/DNS/WHOIS/测绘）。"
	}

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
		// v7.6.0（E7 通道对齐）：可执行脚本内容与 run_command 同口径过影子/范围/自省门——
		// 实证教训「先 write_file 落脚本再执行（该通道不做目标字符串扫描）」曾成为绕行惯例
		//（实测报告 §E7/B4）；交付物（.md 等）不扫描（影子清单等合法含范围外域名），
		// 仅脚本类落盘（扩展名或 shebang）做同口径校验，堵住「写脚本绕过文本扫描」通道。
		if isExecutableScriptPath(path) || strings.HasPrefix(strings.TrimSpace(content), "#!") {
			if msg := o.shadowAssetGate(p, stageID, content, "write_file"); msg != "" {
				return msg
			}
			if blocked, msg := o.scopeGate(p, content); blocked {
				o.log(p, stageID, "⛔ 范围外目标被确定性拦截（strict_scope write_file 脚本内容）")
				_, _ = o.store.AddEvidence(&store.EvidenceRecord{ProjectID: p.ID, Stage: stageID,
					Type: "file", Input: "写入 " + truncateText(path, 120), Output: "脚本内容触发范围门：" + msg,
					Risk: tools.L1Write, ApprovedBy: "scope-gate"})
				return msg
			}
			if msg := o.engineIntrospectionBlocked(content); msg != "" {
				return msg
			}
		}
		full, err := o.exec.WriteFile(p.ID, path, content)
		if err != nil {
			return "错误: " + err.Error()
		}
		_, _ = o.store.AddEvidence(&store.EvidenceRecord{ProjectID: p.ID, Stage: stageID, Type: "file", Input: "写入 " + path, Output: truncateText(content, 400), ApprovedBy: "auto"})
		o.log(p, stageID, "✎ 写入文件 "+path)
		return "已写入: " + full
	case "read_file":
		// v7.5.0（C2）read_file 溢出治理：与 run_command 同口径——>16KB 走 .tool-output/
		// 落盘 + 头尾截断 + 分段指针（原 200KB 直入消息链是 S8 十倍离群的机制性根因）；
		// offset/limit 分段参数保证内容一字不丢（可精确定位续读）。能力无损：完整内容仍
		// 可经分段读/grep 取回，只是单次进链量受控。
		path := s("path")
		content, err := o.exec.ReadFile(p.ID, path)
		if err != nil {
			return "错误: " + err.Error()
		}
		if off, lim := iarg(args, "offset"), iarg(args, "limit"); off > 0 || lim > 0 {
			lines := strings.Split(content, "\n")
			start := off
			if start > 0 {
				start-- // 1-based 行号，工具语义对齐 sed -n 'N,Mp'
			}
			if start > len(lines) {
				start = len(lines)
			}
			end := len(lines)
			if lim > 0 && start+lim < end {
				end = start + lim
			}
			content = fmt.Sprintf("[行 %d-%d / 共 %d 行]\n%s", start+1, end, len(lines), strings.Join(lines[start:end], "\n"))
		}
		if o.cfg.Engine.SpillBytes > 0 && config.FlagOrDefault(o.cfg.Engine.ReadFileSpill, true) && len(content) > o.cfg.Engine.SpillBytes {
			rel := fmt.Sprintf(".tool-output/read-%d-%s.txt", time.Now().UnixNano(), strings.ReplaceAll(path, "/", "_"))
			if _, werr := o.exec.WriteFile(p.ID, rel, content); werr == nil {
				content = tools.TruncateSmart(content, 8*1024) +
					fmt.Sprintf("\n📦 文件已溢出落盘: %s（该文件 >16KB：用 read_file 的 offset/limit 分段读取、或 run_command grep 该溢出文件取片段；完整内容一字未丢）", rel)
			}
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
		// v6.4.0（S4-⑥）：route 移交路线可选标注——认证类受阻项按 s4.md:37 标 browser-auth
		// 正式移交 S5-2a（不再只靠 detail 自由文本）；非法值静默置空与 access 同口径。
		route := s("route")
		if route != "" && route != "browser-auth" && route != "cli" && route != "manual" {
			route = ""
		}
		// v6.9.0（S8-⑤）：target_ref 逐目标归属（可选）——多目标项目建议填写，供报告按目标
		// 组织与反向对账分组（S8-③ 字段优先于标题词边界回退）；空=全局/单目标，与 Asset.TargetRef 同源。
		targetRef := strings.TrimSpace(s("target_ref"))
		rank := 0
		if n, err := strconv.Atoi(strings.TrimSpace(s("impact_rank"))); err == nil && n >= 1 && n <= 6 {
			rank = n
		}
		f := &store.Finding{
			ProjectID: p.ID, Stage: stageID,
			Title: title0, Severity: s("severity"), Detail: detail0, Confidence: conf0,
			CWE:    s("cwe"), // v2.7 A4：标准编号（CWE-89/CWE-79…），以检索/知识为准，不确定留空
			Access: access, ImpactRank: rank, Route: route,
			TargetRef:      targetRef,                           // v6.9.0 S8-⑤ 逐目标归属
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
		// v7.6.0（A5 写后读回快照）：回执带回权威库终态字段——实证 confidence 两任务各漏传
		// 一轮（timeline 原话「引擎回执未确认」，实测报告 §A5）；回执确认链闭环后模型无需
		// 二次确认，漏传在录入即暴露。
		o.convNote(p, stageID)
		return fmt.Sprintf("已登记漏洞 %s%s%s%s\n[引擎回执快照] severity=%s confidence=%s exploitability=%s（权威库终态，漏传字段此处为空即未入库）",
			id, queueNote, claimNote, sevDowngraded, f.Severity, f.Confidence, f.Exploitability)
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
		// v6.9.0（S8-⑤）：target_ref 逐目标归属修正——登记定性、修正留痕（与 severity/confidence
		// 同款纪律；空值=全局/单目标）。
		if v := strings.TrimSpace(s("target_ref")); v != "" {
			if v != target.TargetRef {
				target.TargetRef = v
				changed = append(changed, "target_ref→"+v)
			}
		}
		if len(changed) == 0 {
			return "错误: 未提供任何变更字段（severity/confidence/exploitability/detail_append/remediation/target_ref）"
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
		// v7.1.0 A2 执行卡状态机：VT 登记即建卡（queued 态，已有卡不降级）
		o.trackCardFromVT(p, stageID, vt.Title, vt.StartConditions)
		o.log(p, stageID, fmt.Sprintf("🧾 VT 登记[%s] %s", vt.Status, vt.Title))
		o.convNote(p, stageID)
		return "已登记验证任务 " + id + "（status=" + vt.Status + "；S7 收口前须三选一处置：executed/closed-roe/deferred）"
	case "update_vt": // v4.6 A2：VT 流转（ready / executed / closed-roe / deferred），closed-roe 与 deferred 强制理由
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
		if st != "ready" && st != "executed" && st != "closed-roe" && st != "deferred" {
			return "错误: status 仅允许 ready（确认就绪，v6.3.0 S3-③）/ executed（已执行附 result_ref）/ closed-roe（范围外附理由）/ deferred（移交附三要素）"
		}
		reason := strings.TrimSpace(s("note"))
		// v6.3.0（S3-③）：pending→ready 通道兑现 R7 对抗 VT「主头/人工确认后转 ready」契约
		//（原实现无 ready 态，对抗差异项滞留 pending 到 S7 清点）；ready 强制确认理由。
		if st == "ready" && reason == "" {
			return "错误: ready 必须附 note 确认理由（R7 对抗 VT 主头确认 / S3 排期确认）"
		}
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
		if st == "ready" {
			o.convNote(p, stageID) // v7.7.0 P1：VT 转就绪=产出事件
		}
		return "已处置 " + vid + " → " + st
	case "record_candidate": // v6.0.1 P5 C28：未定性候选登记——「待评估/未定性」线索必须入账本，禁止只写交付物文本
		c := &store.Candidate{ProjectID: p.ID, Stage: stageID,
			Title: s("title"), Target: s("target"), EvidenceRef: s("evidence_ref")}
		if strings.TrimSpace(c.Title) == "" {
			return "错误: title 必填（候选一句话描述）"
		}
		id, cerr := o.store.AddCandidate(c)
		if cerr != nil {
			return "错误: " + cerr.Error()
		}
		o.log(p, stageID, fmt.Sprintf("🧾 候选登记[open] %s", c.Title))
		o.convNote(p, stageID)
		return "已登记候选 " + id + "（status=open；S4/S5 收口前必须 update_candidate 三选一归位：finding/vt/excluded，禁止「待评估」悬空进报告）"
	case "update_candidate": // v6.0.1 P5 C28：候选归位流转
		cid := s("id")
		if cid == "" {
			return "错误: id 必填（record_candidate 返回的 CD- 编号）"
		}
		cand, cerr := o.store.GetCandidate(cid)
		if cerr != nil || cand.ProjectID != p.ID {
			return "错误: 未找到候选 " + cid
		}
		disp := s("disposition")
		ref := strings.TrimSpace(s("disposition_ref"))
		reason := strings.TrimSpace(s("reason"))
		switch disp {
		case "finding":
			if ref == "" {
				return "错误: disposition=finding 必须附 disposition_ref（record_finding 返回的 F- 编号）"
			}
		case "vt":
			if ref == "" {
				return "错误: disposition=vt 必须附 disposition_ref（record_vt 返回的 VT- 编号，启动条件写复测前提）"
			}
		case "excluded":
			if ref == "" || reason == "" {
				return "错误: disposition=excluded 必须附 disposition_ref（证据文件/EV- 编号）与 reason（排除理由）——无证据的排除不算闭环"
			}
		default:
			return "错误: disposition 仅允许 finding / vt / excluded（open 只能由 record_candidate 创建）"
		}
		cand.Disposition, cand.DispositionRef, cand.Reason = disp, ref, reason
		if err := o.store.SaveCandidate(cand); err != nil {
			return "错误: " + err.Error()
		}
		o.log(p, stageID, fmt.Sprintf("🧾 候选归位 %s → %s", cid, disp))
		return "候选已归位 " + cid + " → " + disp
	case "run_batch": // v6.0.1 P2：批量任务逐目标隔离（模板 {{TARGET}} 拆分，单目标失败不取消其余）
		return o.toolRunBatch(ctx, p, stageID, s("command"), s("targets"), s("timeout"), s("reason"))
	case "record_asset":
		// v6.1.0（S1 修复方案②⑳）：范围状态/目标归属/来源/类型化台账字段入账——
		// 「登记线索」≠「测试授权」：非 in_scope 资产由 shadowAssetGate 拦截测试流量。
		a := &store.Asset{ProjectID: p.ID, Stage: stageID, Type: s("type"), Value: s("value"), Detail: s("detail"),
			TargetRef: s("target_ref"), ScopeStatus: strings.ToLower(strings.TrimSpace(s("scope_status"))),
			ScopeEvidence: s("scope_evidence"), Source: s("source")}
		switch a.ScopeStatus {
		case "in_scope", "shadow_pending", "out_of_scope", "conditional", "":
			// 合法枚举；空 = unknown（EffectiveScope fail-closed）
		default:
			return "错误: scope_status 仅允许 in_scope/shadow_pending/out_of_scope/conditional（空=unknown）；请修正后重新登记"
		}
		if a.ScopeStatus == "in_scope" && strings.TrimSpace(a.ScopeEvidence) == "" {
			return "错误: scope_status=in_scope 必须附 scope_evidence（授权清单/授权书条目/扩展工单 ID 等可追溯依据）"
		}
		// v6.1.0（方案⑳）：metadata 只收字符串键值；禁存明文凭据（密钥仅 *_ref 指针键）。
		if rawMeta, ok := args["metadata"].(map[string]any); ok && len(rawMeta) > 0 {
			meta := map[string]string{}
			for k, v := range rawMeta {
				key := strings.TrimSpace(k)
				vs, _ := v.(string)
				if assetMetadataKeyLooksSecret(key) {
					return "错误: metadata 禁止存放凭据类字段（" + key + "）；密钥请只登记 *_ref 指针（如 secret_ref/authorization_ref 指向凭据仓库 ID）"
				}
				meta[key] = strings.TrimSpace(vs)
			}
			a.Metadata = meta
		}
		// v6.1.0（方案⑳）：类型化最小字段集校验（guard.asset_metadata_validation，缺省 true；
		// 仅约束新建记录，旧库不动）——字段值可填 unknown，但键必须存在（保证台账可核对唯一标识）。
		if o.guardEnabled(func(g *config.GuardConfig) *bool { return g.AssetMetadataValidation }) {
			if missing := missingAssetTypeFields(a.Type, a.Metadata); len(missing) > 0 {
				return "错误: " + a.Type + " 资产缺少类型化台账字段 " + strings.Join(missing, "/") + "——按 s1.md S1-1 字段规范补齐（暂无信息可填 unknown）后重新登记"
			}
		}
		id, err := o.store.AddAsset(a)
		if err != nil {
			return "错误: " + err.Error()
		}
		// v7.2.0 B3 planDelta：测试中新登记的 in_scope 资产（非 S1 初始界定）自动建卡入 S4 计划
		if a.EffectiveScope() == "in_scope" {
			o.planDeltaOnScope(p, stageID, a.Value, "record_asset 直接登记 in_scope（"+truncateText(a.ScopeEvidence, 60)+"）")
		}
		o.bus.Publish(p.ID, "finding", a)
		return "已登记资产 " + id + "（scope_status=" + a.EffectiveScope() + "）"
	case "update_asset":
		// v6.1.0（S1 修复方案②）：范围状态流转——人工核实/授权扩展批准后由模型回写台账。
		// 流转方向确定性校验：unknown/shadow_pending/conditional/out_of_scope → in_scope 必须附依据；
		// in_scope → 降级（如发现误标）允许但强制 reason 留痕。
		aid := s("asset_id")
		a, err := o.store.GetAsset(p.ID, aid)
		if err != nil {
			return "错误: " + err.Error()
		}
		newStatus := strings.ToLower(strings.TrimSpace(s("scope_status")))
		switch newStatus {
		case "in_scope", "shadow_pending", "out_of_scope", "conditional", "unknown":
		default:
			return "错误: scope_status 仅允许 in_scope/shadow_pending/out_of_scope/conditional/unknown"
		}
		if newStatus == "in_scope" && strings.TrimSpace(s("scope_evidence")) == "" {
			return "错误: 流转为 in_scope 必须附 scope_evidence（授权文书/扩展工单批准记录等可追溯依据）——普通登记不能自我批准"
		}
		reason := strings.TrimSpace(s("reason"))
		if reason == "" {
			return "错误: update_asset 必须附 reason（谁在什么依据下做的状态变更）"
		}
		old := a.EffectiveScope()
		a.ScopeStatus = newStatus
		a.ScopeEvidence = s("scope_evidence")
		_ = o.store.UpdateAsset(a)
		_, _ = o.store.AddTimeline(&store.TimelineEvent{ProjectID: p.ID, Stage: stageID,
			Event: fmt.Sprintf("资产范围状态变更 %s：A-%s %s→%s", aid, aid, old, newStatus), Detail: reason})
		// v7.2.0 B3 planDelta：流转为 in_scope（非 S1、非原 in_scope）→ 自动建卡入 S4 计划
		if newStatus == "in_scope" && old != "in_scope" {
			o.planDeltaOnScope(p, stageID, a.Value, "update_asset 流转（"+truncateText(s("scope_evidence"), 60)+"）")
		}
		return "资产 " + aid + " 范围状态已更新：" + old + " → " + newStatus
	case "record_timeline":
		_, _ = o.store.AddTimeline(&store.TimelineEvent{ProjectID: p.ID, Stage: stageID, Event: s("event"), Detail: s("detail")})
		return "已记录时间线事件"
	case "build_s1_subdomain_input": // v6.1.0（方案⑫）：S1 专用本地候选合并器（零网络）
		if stageID != "s1" {
			return "错误: build_s1_subdomain_input 仅限 S1 阶段调用"
		}
		out, err := o.buildS1SubdomainInput(p)
		if err != nil {
			return "错误: " + err.Error()
		}
		return out
	case "load_skill": // 移植 strix load_skill：运行时注入技能剧本
		if sk := o.skills.Get(s("id")); sk != nil {
			// v7.0.0 盲态前置门：盲态类技能在 OOB 通道不可用时拒绝注入（防"无回连盲测"白烧轮次）
			if msg := o.blindSkillGate(p, sk.ID); msg != "" {
				o.log(p, stageID, "🚫 盲态技能门拦截: "+sk.ID)
				return msg
			}
			o.log(p, stageID, "📖 载入技能: "+sk.ID)
			o.noteSkillLoad(p.ID, stageID, sk.ID) // v7.6.0（D3）载入计数
			// v5.3.1 P0-1：production_safe 下对 Lab Only 高危技能注入禁用横幅（知识面配套强制）
			return fmt.Sprintf("【技能 %s】%s\n\n%s%s", sk.ID, sk.Title, sk.Body, o.labOnlyBanner(p, sk.ID))
		}
		// v5.8.0（审计 Top#1 组合检索死路径修复）：主命中后立即扩展 depends_on/handoff_to——
		// 原 Bundle 只在零命中才触发且用同一查询（永远拿不到主命中之外的展开），
		// 配套技能实际从未被注入；弱模型因此漏掉 evidence-standard/handoff 等关键链路技能。
		if hits := o.skills.Bundle(s("query"), stageID, 5); len(hits) > 0 {
			o.noteSkillLoad(p.ID, stageID, "bundle:"+s("query")) // v7.6.0（D3）载入计数
			var b strings.Builder
			labOnly := false
			// v5.9.0（方案 P2-5）：主命中与配套的边界由 Bundle 声明（主命中数 = 检索 top-N，
			// 其后才是 depends_on/handoff_to 扩展）；展开总量上限 10 项防上下文膨胀。
			mainN := o.skills.LastMainHitCount()
			for i, h := range hits {
				// v7.0.0 盲态前置门：Bundle 配套中的盲态技能同样拦截（占位说明替代正文）
				if msg := o.blindSkillGate(p, h.ID); msg != "" {
					b.WriteString(fmt.Sprintf("【技能 %s 未注入】%s\n\n---\n", h.ID, msg))
					continue
				}
				if o.skills.LabOnly(h.ID) {
					labOnly = true
				}
				tag := ""
				if i >= mainN {
					tag = "（配套：depends_on/handoff_to 自动扩展）"
				}
				b.WriteString(fmt.Sprintf("【技能 %s】%s%s\n\n%s\n\n---\n", h.ID, h.Title, tag, headTail(h.Body, 2500, 1200)))
			}
			if labOnly {
				b.WriteString(labOnlyBannerText())
			}
			o.log(p, stageID, fmt.Sprintf("📖 技能检索命中 %d 条（含组合扩展 %d 条）", len(hits), len(hits)))
			return b.String()
		}
		return "未找到匹配技能；可用技能索引见项目上下文。"
	case "oob_check": // v7.0.0：OOB 回连通道健康自检（三模式 auto 回退链；结果自动落 evidence/oob/channel.txt）
		return o.oob.CheckText(p)
	case "oob_poll": // v7.0.0：收取 OOB 回连记录（按 case-id 过滤；命中=D3 语义验证判据）
		return o.oob.PollText(p, s("case_id"))
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
		// v7.6.0（A7 覆盖度状态机校验）：vulnerable 与 negative_valid 语义互斥——
		// 实证 某实战项目 入库 9 行 vulnerable+observed_result=negative_valid（阳性命中
		// 搭配真阴性观测，状态字段语义混乱，实测报告 §A7）。
		if status == "vulnerable" && observed == "negative_valid" {
			return "错误: status=vulnerable 与 observed_result=negative_valid 语义互斥——vulnerable=阳性命中，negative_valid=有请求/响应原文支撑的真阴性。确认命中：去掉 observed_result 或改用阳性观测描述；确认阴性：改 status=ruled_out/no_issue_found"
		}
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
		// v7.0.0 OOB 深度门（方案 oob-channel-optimization.md §4.3）：盲态类（盲 SSRF/XXE/盲注/
		// 反序列化）的真阴性终态必须 depth≥D2 且 OOB 通道健康——D2=差分对照、D3=OOB 回连确证；
		// 通道不可用（某历史任务 盲 SSRF/XXE 悬置实证）或深度不足时自动降级 needs_follow_up，
		// 禁止把"WAF 拦了/没回连"写成阴性（负结果语义保真，与 E3 同向收紧而非放松）。
		depthStr := normalizeOOBDepth(s("depth"))
		vulnClass0 := s("vuln_class")
		if config.FlagOrDefault(o.cfg.OOB.RequireChannelForBlind, true) &&
			(status == "ruled_out" || status == "no_issue_found") && IsBlindVulnClass(vulnClass0) {
			if ok, reason := o.oob.BlindGateReady(p, vulnClass0); !ok {
				status = "needs_follow_up"
				downgraded += "；盲态类 OOB 门：" + reason + "（无健康回连通道的真阴性不可采信——先 oob_check 修复通道，或保持 needs_follow_up）"
			} else if depthNum(depthStr) < 2 {
				status = "needs_follow_up"
				depthLabel := depthStr
				if depthLabel == "" {
					depthLabel = "未声明"
				}
				downgraded += "；盲态类深度门：ruled_out 要求 depth≥D2（D3=OOB 回连确证），当前 depth=" + depthLabel
			}
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
			Depth: depthStr,
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
		// v7.1.0 A2 执行卡状态机：C-xx 引用即卡片推进（引擎维护投影，模型零簿记）
		o.trackCardFromCoverage(p, stageID, entry.Endpoint, entry.Param, entry.Notes, entry.Status)
		// v7.7.0 P1：vulnerable 结论或新增单元算产出（收敛信号源）
		if entry.Status == "vulnerable" || entry.Count <= 1 {
			o.convNote(p, stageID)
		} else if o.baselineTierUnit(entry) {
			// v7.7.1 红队模式：基线类（C-24/C-25）一轮探针已登记，深化/重复登记不再计产出
			//（收敛 idle 累积→预算让渡认证/越权/注入/逻辑高价值族）；vulnerable 在任何类都是
			// 产出（上行分支已计）。仅记账引导，不拦截——合规模式（probe_tiering=false）回旧口径。
			o.log(p, stageID, fmt.Sprintf("🧭 基线类一轮口径（v7.7.1 红队模式）：%s 已达基线探针深度，深化不再计产出——预算让渡认证/越权/注入/逻辑高价值族（合规模式设 probe_tiering=false）", entry.VulnClass))
		} else if o.baselineTierRefHint(entry) {
			// v7.8.0 优化④：基线类语义但未引用 C-xx——回执附一行引用提醒（同单元只提醒一次，
			// 防抖：不拦截不重复）。引用后基线降档机制对合规类普遍生效。
			o.log(p, stageID, fmt.Sprintf("💡 该单元属基线类（%s）——请在 VulnClass 或 Endpoint 引用 C-24/C-25 编号以启用降档口径", entry.VulnClass))
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
		// v6.9.0（S8-③）：finding:<id> 直取单条完整记录——s8 报告须引用 finding 库 detail/poc/
		// remediation 三字段（v5.3.6 契约），此前无任何工具能取回 poc/remediation 原文。与
		// receipt:<id> 同机制；大小写不敏感，仅限本项目。
		if strings.HasPrefix(strings.ToLower(rawQ), "finding:") {
			fid := strings.TrimSpace(rawQ[len("finding:"):])
			if fid == "" {
				return "错误: finding id 为空（用法 query=\"finding:F-xxxxxxxxxx\"）"
			}
			fs, _ := o.store.ListFindings(p.ID)
			for _, f := range fs {
				if !strings.EqualFold(f.ID, fid) {
					continue
				}
				var fb strings.Builder
				fmt.Fprintf(&fb, "📄 发现 %s（阶段 %s，%s/%s）\n标题: %s\n详情: %s\n",
					f.ID, f.Stage, f.Severity, f.Confidence, f.Title, f.Detail)
				if f.TargetRef != "" {
					fmt.Fprintf(&fb, "目标归属: %s\n", f.TargetRef)
				}
				if strings.TrimSpace(f.Remediation) != "" {
					fmt.Fprintf(&fb, "修复建议: %s\n", f.Remediation)
				}
				if len(f.POC) > 0 {
					fmt.Fprintf(&fb, "POC %d 组:\n", len(f.POC))
					for i, pc := range f.POC {
						fmt.Fprintf(&fb, "── 请求原文 %d ──\n%s\n── 响应原文 %d ──\n%s\n", i+1, pc.Request, i+1, pc.Response)
					}
				}
				if len(f.EvidenceIDs) > 0 {
					fmt.Fprintf(&fb, "证据: %s\n", strings.Join(f.EvidenceIDs, ","))
				}
				return fb.String()
			}
			return "记忆库无该发现：" + fid
		}
		var out []string
		// v6.0.6 A（P0）：教训库扫描——原 search_memory 覆盖 findings/assets/timeline/coverage/
		// facts/loot 唯独不含 lessons，模型唯一知识检索工具永远查不到教训库（三重锁死之三）。
		// 教训命中置于最前，防被项目内多源数据挤出 15 条截断。
		if ls, _ := o.store.ListLessons(0); len(ls) > 0 {
			out = append(out, searchLessonsScan(ls, q)...)
		}
		if fs, _ := o.store.ListFindings(p.ID); len(fs) > 0 {
			for _, f := range fs {
				if strings.Contains(strings.ToLower(f.Title+f.Detail), q) {
					// v6.9.0（S8-③）：命中行附 poc 首组请求行与 remediation 首句摘要——s8 报告
					// 三字段同源引用不再需要逐个翻文件（完整原文 finding:<id> 直取）。
					out = append(out, fmt.Sprintf("[漏洞/%s/%s] %s：%s\n  %s",
						f.Severity, f.Confidence, f.Title, truncateText(f.Detail, 160), findingExcerptLine(f)))
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
		// v6.3.0（S3-③）：检索域补全验证队列与候选账本——原实现唯一知识检索工具查不到
		// VT/C28 候选，「是否登记过验证任务/待评估线索」无查询通道。
		if vts, verr := o.store.ListVTs(p.ID); verr == nil {
			for _, t := range vts {
				if strings.Contains(strings.ToLower(t.Title+t.ReadyAssets+t.StartConditions+t.Note+t.Status+t.ResultRef), q) {
					out = append(out, fmt.Sprintf("[验证任务/%s/P%d] %s %s（%s）", t.Status, t.Priority, t.ID, t.Title, truncateText(t.Note+t.ReadyAssets, 90)))
				}
			}
		}
		if cands, cerr := o.store.ListCandidates(p.ID); cerr == nil {
			for _, c := range cands {
				if strings.Contains(strings.ToLower(c.Title+c.Target+c.Reason+c.Disposition), q) {
					out = append(out, fmt.Sprintf("[候选/%s] %s %s（%s）", c.Disposition, c.ID, c.Title, truncateText(c.Reason+c.EvidenceRef, 90)))
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
		// v6.6.0（SP-③）：三专项（specA/specB1/specB2）纳入同一强制——专项是 s4 与 s5 之间
		// 就绪资产的高发生产点（specB1 静态链假设队列/specA oracle），清单落 StageState 供
		// S5「专项就绪移交」小节与 S7 清点消费；双通道提交机制复用零新逻辑。
		// v4.9 F1 双通道提交：①complete_stage 顶层 JSON 数组参数（schema 已同步声明）；
		// ②summary 约定字面格式回退解析——实证（兰州/重庆 2026-11）93 次 s4 收口 0 次顶层传参、
		// 92 次拦截文案零变化，模型把清单写进 summary 是高频稳定行为，只堵不导=60 轮烧尽死循环。
		if stageID == "s4" || stageID == "s5" || isSpecStage(stageID) {
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
				// v7.1.0 E1'（runtime-audit R1：实证 93 次 s4 收口 0 次顶层传参、92 次拦截文案
				// 零变化烧尽预算）——由「拦截重试拉锯」改为「引擎代填 + 留痕」：
				// ready_but_unexecuted 按台账代填（harvestV3Lists 既有口径：本阶段 pending/ready
				// VT 扣除已被后台作业执行项）；l2_approved_unused 无法机械判定「已批未用」，
				// 代填空数组并显式记账（S8 质量注记承接）。模型跳过 V3 显式提交的行为入时间线可审计。
				readyAuto, _ := o.harvestV3Lists(p, stageID, harvestedJobs)
				for _, field := range missing {
					if field == "ready_but_unexecuted" {
						v3Lists[field] = readyAuto
					} else {
						v3Lists[field] = []string{}
					}
					_, _ = o.store.AddTimeline(&store.TimelineEvent{ProjectID: p.ID, Stage: stageID,
						Event:  "v7.1.0 E1' V3 引擎代填",
						Detail: fmt.Sprintf("%s 既未传参也未按字面格式写入 summary → 引擎按台账代填 %d 条；模型应改为显式提交（顶层参数或 summary 字面格式）", field, len(v3Lists[field]))})
					o.log(p, stageID, fmt.Sprintf("⚙ v7.1.0 E1'：%s 引擎代填 %d 条（模型跳过 V3 显式提交已记账）", field, len(v3Lists[field])))
				}
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
					v3Lists[field] = corrected
				}
			}
			// v6.4.0（S4-⑤）：V3 两清单结构化落 StageState——S5「S4 移交项」注入块与
			// v3HandoverIssues 承接对账的数据源（时间线仅最近 15 条窗口可能挤出；
			// 影子交付物文件形态引擎不读，s5.md:14 承接反蒸发由此获得机械对账依据）。
			if v3State := p.StageStates[stageID]; v3State != nil {
				v3State.V3Ready = v3Lists["ready_but_unexecuted"]
				v3State.V3L2 = v3Lists["l2_approved_unused"]
			}
		}
		// v3.6.0 收口前在途子代理检查：未收结果先拦（子代理发现可能尚未整合）
		if n := o.runningSubAgents(p.ID); n > 0 {
			return fmt.Sprintf("收口被拦截：仍有 %d 个子代理在运行。先 poll_subagents 收结果（或等待其结束），整合发现后再收口；确需放弃等待请先确认其发现已入库。", n)
		}
		// 实体文件产出强制（防幻觉/防流程中断）：本阶段工作区必须新增过文件
		state := p.StageStates[stageID]
		started, _ := time.Parse(time.RFC3339, state.StartedAt)
		// v6.1.0（S1 修复方案④⑤⑪）：S1 确定性收口门在通用「任意新文件」检查之前——
		// 四件套逐件核验+逐目标对账+条件 OOB 门，空工作区也返回确切缺失项（拦截文案固定可验收）。
		if stageID == "s1" && o.guardEnabled(func(g *config.GuardConfig) *bool { return g.EnforceS1Closure }) {
			if issues := o.s1ClosureIssues(p); len(issues) > 0 {
				o.log(p, stageID, fmt.Sprintf("⚠ S1 确定性门拦截 %d 项", len(issues)))
				return strings.Join(issues, "\n- ") + "\n\n补齐后重新调用 complete_stage。"
			}
		}
		// v6.2.0（S2 修复方案①）：S2 确定性收口门前置——攻击面地图/拓扑重建非空壳 + checklist.json
		// 可解析（fail-closed，坏 JSON 不得流入 S4/S5 G2）+ 多目标逐目标归宿；在通用「任意新文件」
		// 检查之前给出确切缺失项（拦截文案固定可验收），反思 PASS/失败/三振路径经 deterministicGate 同门兜底。
		if stageID == "s2" && o.guardEnabled(func(g *config.GuardConfig) *bool { return g.EnforceS2Closure }) {
			if issues := o.s2ClosureIssues(p); len(issues) > 0 {
				o.log(p, stageID, fmt.Sprintf("⚠ S2 确定性门拦截 %d 项", len(issues)))
				return strings.Join(issues, "\n- ") + "\n\n补齐后重新调用 complete_stage。"
			}
		}
		// v6.3.0（S3-①）：S3 确定性收口门前置——威胁模型/测试计划存在性 + 候选清单/checklist
		// 承接留痕；在通用「任意新文件」检查之前给出确切缺失项，反思 PASS/失败/三振路径经
		// deterministicGate 同门兜底（与 s1/s2 同机制）。
		if stageID == "s3" && o.guardEnabled(func(g *config.GuardConfig) *bool { return g.EnforceS3Closure }) {
			if issues := o.s3ClosureIssues(p); len(issues) > 0 {
				o.log(p, stageID, fmt.Sprintf("⚠ S3 确定性门拦截 %d 项", len(issues)))
				return strings.Join(issues, "\n- ") + "\n\n补齐后重新调用 complete_stage。"
			}
		}
		// v6.6.0（SP-②）：专项确定性收口门前置——前置契约登记+点名交付物+条目三态清单存在性
		//（豁免分支内置于函数：无适用资产走前提不成立路径只留提示）；在通用「任意新文件」检查
		// 之前给出确切缺失项，反思 PASS/三振/auto_close 路径经 deterministicGate 同门兜底
		//（与 s1/s2/s3 同机制）。
		if isSpecStage(stageID) && o.guardEnabled(func(g *config.GuardConfig) *bool { return g.EnforceSpecClosure }) {
			if issues := o.specClosureIssues(p, stageID); len(issues) > 0 {
				o.log(p, stageID, fmt.Sprintf("⚠ %s 确定性门拦截 %d 项", stageID, len(issues)))
				return strings.Join(issues, "\n- ") + "\n\n补齐后重新调用 complete_stage。"
			}
		}
		fresh, _ := o.listWorkspaceFilesSince(p.ID, "", started)
		if len(fresh) == 0 {
			o.log(p, stageID, "⚠ 收口被拦截：本阶段尚未产出任何实体文件")
			return "收口失败：本阶段必须先用 write_file 产出实体交付物文件（建议路径 deliverables/<阶段>-<名称>.md，报告为 report.md），把结论落到文件里。产出后再次调用 complete_stage。"
		}
		// S8 报告契约守卫（v2.2.4 引入；v6.9.0 S8-① 前置）：流程宪法规定报告必须为工作区根目录
		// report.md——缺失即拦截；写在 deliverables/ 则自动归位根目录。
		// v6.9.0 前置动机：旧实现位于反思门/确定性门之后，report.md 错位写入 deliverables/ 时
		// deterministicGate s8 分支的四个内容门（证据核存/C29/P11/R 计数）因 ReadFile("report.md")
		// 失败全部静默空转，随后本守卫归位放行——单次收口绕过全部内容核验（v2.2.4 注释承认该
		// 写入路径实测发生过）。前置后归位发生在所有门之前，内容门读到的即根目录报告。
		// v6.9.0 第四轮核对：归位逻辑抽为 ensureReportContract——complete_stage 与预算代收口
		// （auto_close，不经 complete_stage 直接跑确定性门）两条收口路径共用，堵住代收口侧的同款绕过。
		if ok, msg := o.ensureReportContract(p, stageID); !ok {
			return msg
		}
		// 反思门（PentAGI reflector 移植）：收口前质量审查，每阶段最多拦截 2 次防死循环
		// v5.1.2 P1 修复：三振出局旁路显式留痕——此前第 3 次收口静默跳过全部硬门，
		// heads 承诺的「引擎硬门拦截」在该路径无痕失效。
		var b3Debt string // v7.6.0（B3）：时间盒超时债务文本（各门路径转人工通道后随 Review 落账）
		if state.ReviewRounds >= 2 {
			// v5.1.3 修复①：三振出局改「降级门」——LLM 反思跳过，确定性门照跑并强制通过。
			// 此前旁路静默跳过 M2/M4/G2/G3/W4 全部机械门（实战监控实证：TH-23/24 高价值
			// 候选经 S4 代收口+S5 改写静默蒸发）。机械检查不需要 LLM，旁路≠跳门。
			o.log(p, stageID, "⚠ 三振出局降级门：LLM 反思跳过，确定性门照跑并强制通过（v5.1.3）")
			if issues := o.deterministicGate(p, stageID); len(issues) > 0 {
				mentorNote, debt, timedOut := o.gateBlockCtx(ctx, p, stageID, issues)
				if timedOut {
					b3Debt = debt // v7.6.0（B3）：时间盒超时——债务随 Review 落账，不再阻塞
				} else {
					return "收口失败（三振出局降级门）：LLM 反思已跳过，但确定性门仍有未通过项：\n- " +
						strings.Join(issues, "\n- ") + mentorNote + "\n逐项修正后再次收口（确定性门逐次重跑，不消耗反思额度）。"
				}
			}
			state.Review = strings.TrimSpace(state.Review + " [v5.1.3 三振出局降级门——LLM 反思跳过，确定性门已通过]")
			if b3Debt != "" {
				state.Review = strings.TrimSpace(state.Review + " " + b3Debt)
			}
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
					mentorNote, debt, timedOut := o.gateBlockCtx(ctx, p, stageID, issues)
					if timedOut {
						// v7.6.0（B3）：时间盒超时——债务转 quality-pending 落 Review，不再阻塞
						state.Review = fmt.Sprintf("反思门调用失败（重试 3 次）；确定性门仍有 %d 项未过——%s", len(issues), debt)
						o.log(p, stageID, "⏱ B3 收口时间盒超时（反思失败路径）——债务转 quality-pending 落账")
					} else {
						_ = o.store.SaveProject(p)
						o.log(p, stageID, "⚠ 反思门调用失败（已重试 3 次），确定性质量门拦截 "+fmt.Sprint(len(issues))+" 项: "+rerr.Error())
						return "收口被确定性质量门拦截（反思门重试后仍不可用，以下为引擎硬校验结果）：\n- " + strings.Join(issues, "\n- ") + mentorNote + "\n\n补齐后重新调用 complete_stage。"
					}
				} else {
					state.Review = "反思门调用失败（重试 3 次）；确定性质量门通过放行【quality-pending：S8 收口前须复核本阶段交付物】"
				}
				if state.Review != "" && !strings.Contains(state.Review, "B3") {
					o.log(p, stageID, "⚠ 反思门 3 次重试均失败——确定性门结果落 Review（quality-pending 语义）")
				}
			} else {
				// v3.8.2 关键修复：反思 PASS 也要过确定性硬校验（s8 机械检查与 LLM 审查互补——
				// 实测报告-发现不一致/同根因双记在反思 PASS 时漏过，机械检查零 LLM 成本应无条件执行）
				// v3.8.5 扩展：s4/s5 同样无条件过硬校验（G1 探测对账器——纪律性缺口靠提示词压不住，需引擎兜底）
				// v3.8.7 扩展：s7 无条件过硬校验（G3 待续清单回灌门）
				// v4.8 扩展：s3 无条件过硬校验（M2 筛查矩阵判定表门）
				if stageID == "s1" || stageID == "s8" || stageID == "s4" || stageID == "s5" || stageID == "s7" || stageID == "s3" || stageID == "s2" || stageID == "s6" || isSpecStage(stageID) { // v6.1.0（方案④）：s1 加入反思 PASS 无条件确定性门名单；v6.2.0（S2-①）：s2 补齐——S2 是 S3/S4 一等输入源，交付物与逐目标归宿须机械核验；v6.6.0（SP-②）：三专项纳入——专项收口最小产出机械核验；v6.7.0（S6-①）：s6 纳入——s6 分支确定性门（C27 收口件/C28/S6-④⑥）此前仅三振/反思失败/代收口路径生效，正常 PASS 路径零机械校验（实证：24 判定表项目仅 2 产出对账表）
					if issues := o.deterministicGate(p, stageID); len(issues) > 0 {
						state.ReviewRounds++
						mentorNote, debt, timedOut := o.gateBlockCtx(ctx, p, stageID, issues)
						if timedOut {
							// v7.6.0（B3）：时间盒超时——债务随 Review 落账（PASS 审查文本之后拼接），不再阻塞
							b3Debt = debt
						} else {
							_ = o.store.SaveProject(p)
							o.log(p, stageID, "⚠ 确定性质量门拦截 "+fmt.Sprint(len(issues))+" 项（反思 PASS 但硬校验未过）")
							return "收口被确定性质量门拦截（LLM 反思已通过，但以下引擎硬校验未过）：\n- " + strings.Join(issues, "\n- ") + mentorNote + "\n\n补齐后重新调用 complete_stage。"
						}
					}
				}
				state.Review = truncateText(reviewText, 2000)
				if b3Debt != "" {
					state.Review = strings.TrimSpace(state.Review + " [B3 时间盒转人工通道 " + b3Debt + "]")
					o.log(p, stageID, "⏱ B3 收口时间盒超时——确定性门剩余项随 Review 转 quality-pending（债务留痕）")
				}
				o.streamMsg(p.ID, stageID, "🎓 反思门审查："+reviewText)
				if blocked {
					state.ReviewRounds++
					_ = o.store.SaveProject(p)
					o.log(p, stageID, "🎓 反思门拦截：审查未通过，要求补齐后重新收口")
					return "收口被反思门拦截，审查意见如下：\n" + reviewText + "\n\n请补齐关键缺口后重新调用 complete_stage（本阶段还剩 " + fmt.Sprint(2-state.ReviewRounds) + " 次拦截机会），或确需前置补充时用 loopback。"
				}
			}
		}
		// v6.9.0 S8-①：报告契约守卫已前置到通用文件检查之后、反思门/确定性门之前——
		// 归位先于全部 s8 内容门执行（原位置在反思门之后，错位写入会绕过内容门后放行）。
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
			// v7.3.0 C1 红蓝对抗环：R1 独立复查 + R2 专攻剩余角度（2 轮迭代替代旧一次性 R7）
			r7Note, r7File = o.redBlueAssumptionLoop(ctx, p, stageID)
			if r7File != "" {
				seen[r7File] = true
				state.Deliverables = append(state.Deliverables, r7File)
			}
		}
		endStageRun(state)
		// v6.4.0（S4-⑩）：回环重入原因随收口清空（消费完毕，避免重跑后重复注入旧线索）。
		state.ReentryReason = ""
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
	case "propose": // v7.1.0 PAE：自主决策提议 → 引擎裁决（规则集见 autonomy.go，账本全程留痕）
		return o.toolPropose(p, stageID, args)
	case "update_proposal": // v7.1.0 PAE：提议结果回写账本（自主产出转化统计来源）
		return o.toolUpdateProposal(p, args)
	case "loopback":
		to := s("to_stage")
		st, ok := p.StageStates[to]
		if !ok || st == nil {
			return "错误: 回环目标阶段不存在: " + to
		}
		// v6.7.0（S6-⑨）：回环目标只允许上游阶段（assignOrder 序严格小于当前阶段）——
		// 此前只查目标 StageState 存在，s6→s7/s8/s6 等下游/自身回环也会被接受并置 pending；
		// 下游回环无补跑语义（下游重跑不能补上游缺口，反而打乱「补跑=连同下游自动重跑」
		// 的展开语义）。拒绝并时间线留痕，不重复提交。
		if cur, ok1 := o.heads[stageID]; ok1 && cur != nil {
			if tgt, ok2 := o.heads[to]; ok2 && tgt != nil && tgt.Order >= cur.Order {
				_, _ = o.store.AddTimeline(&store.TimelineEvent{ProjectID: p.ID, Stage: stageID,
					Event:  "回环目标非法（v6.7.0 S6-⑨）",
					Detail: fmt.Sprintf("to=%s——回环仅允许上游阶段（%s 序 %d ≥ %s 序 %d），请改用上游阶段或人工在「阶段流水线」处置", to, to, tgt.Order, stageID, cur.Order)})
				o.log(p, stageID, fmt.Sprintf("⚠ 回环目标非法：to=%s 不是 %s 的上游阶段", to, stageID))
				return fmt.Sprintf("回环目标非法：%s 不是 %s 的上游阶段（回环仅允许回退前置阶段）。本请求已留痕未执行，请改用上游阶段（如 s2/s4）或调用 record_vt 登记移交；不要再次调用 loopback 指向同一目标。", to, stageID)
			}
		}
		// v5.5.0（修复方案 D）：回环上限内才置 pending+排队——原实现先置 pending 再查上限，
		// 超额时状态已改但永远不入补跑队列，形成"看似已回环实则死死角"。
		o.loopMu.Lock()
		q := o.loops[p.ID]
		// v5.9.0（方案 P0-2）：项目级累计额度（当前批次 + 历史已消费）。
		// v6.4.0（S4-⑩）：额度持久化——p.LoopUsed 为事实源，内存 map 退化为缓存
		//（服务重启后额度延续，不再重置为 3 次）。
		if o.loopTotal == nil {
			o.loopTotal = map[string]int{}
		}
		if _, ok := o.loopTotal[p.ID]; !ok {
			o.loopTotal[p.ID] = p.LoopUsed
		}
		total := o.loopTotal[p.ID] + len(q)
		// v7.1.0：自主框架启用时上限放宽至动态额度 loopback_cap_max（默认 8）——聚焦回环成本
		// 已降一个量级，固定 3 是多目标 needs_follow_up 沉淀的成因之一（实拍项目 34 项）。
		loopCap := o.loopbackCap()
		queued := total < loopCap
		if queued {
			o.loops[p.ID] = append(q, to)
			// v6.4.0（S4-⑩）：重入原因随回环登记写入目标阶段——重跑阶段开工由上下文包
			//「回环重入原因」块直击线索（原实现 reason 只落时间线，S4 重入须自行翻找）。
			// v7.1.0 B2：focus 参数（目标/类/端点聚焦范围）随重入原因下发——聚焦回环成本
			// 降一个量级的载体，重入阶段不再全量重扫。
			reentry := s("reason")
			if f := s("focus"); f != "" {
				reentry += "｜聚焦范围: " + f
			}
			if st2 := p.StageStates[to]; st2 != nil {
				st2.ReentryReason = reentry
			}
			// v7.4.2 修复（用户实报的某多目标实战项目）：聚焦传导到下游——补跑语义=目标+全部下游，
			// 但 ReentryReason 此前只写目标阶段，下游（s5-s8）重入拿不到聚焦范围 → 全量重扫观感。
			// 将重入原因（含聚焦范围）沿下游链传播，各下游头按阶段语义只补聚焦缺口。
			if tgt := o.heads[to]; tgt != nil {
				var downstream []string
				for sid, h := range o.heads {
					if h != nil && h.Order > tgt.Order {
						downstream = append(downstream, sid)
					}
				}
				sort.Strings(downstream)
				for _, sid := range downstream {
					if dst := p.StageStates[sid]; dst != nil {
						dst.ReentryReason = "承接聚焦回环（" + to + " 重入）：" + reentry
					}
				}
			}
		}
		o.loopMu.Unlock()
		if !queued {
			// 超额：不改状态（保持 done/pending 原状），持久留痕 + 显式告知未排队。
			_, _ = o.store.AddTimeline(&store.TimelineEvent{ProjectID: p.ID, Stage: stageID,
				Event:  "回环超额拒绝（v5.5.0 方案 D）",
				Detail: fmt.Sprintf("to=%s reason=%s——已达单项目自动补跑上限 %d 次，未入补跑队列；请人工在「阶段流水线」重跑 %s 或评估新线索价值后手动触发", to, s("reason"), loopCap, to)})
			o.log(p, stageID, fmt.Sprintf("⚠ 回环请求超额未排队（上限 %d）：%s → %s（已留痕待人工处置）", loopCap, stageID, to))
			return fmt.Sprintf("回环未执行：本项目自动回环补跑已达上限（%d 次）。本请求已持久留痕（时间线「回环超额拒绝」），状态未改动。可先用 propose(kind=loopback_focus) 登记价值提议再评估，或人工决策：①在「阶段流水线」手动重跑 %s；②调用 record_vt 登记为移交/待验证项。不要再次调用 loopback。", loopCap, to)
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
		// v7.4.3 归档化重建：旧计划转入 subtask_archive（只挪不删）——回环/重进阶段的
		// 历史计划不再蒸发，前端子任务面板随 detail 展示归档区。
		moved, err := o.store.MoveStageSubtasksToArchive(p.ID, stageID)
		if err != nil {
			return "错误: " + err.Error()
		}
		if moved > 0 {
			o.log(p, stageID, fmt.Sprintf("🗂 子任务计划重建：原 %d 项已归档（subtask_archive，可追溯）", moved))
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
		// v6.1.0（S1 修复方案⑩）：purpose=roe_ack——ROE 红线四要素确认专用通道。
		// 明确按钮值语义（yes/no），不让模型解释长文本；yes 持久化 ROEAcknowledgedAt 并
		// 落时间线与证据，非 yes/超时不置位（命令通道保持拦截）。
		if s("purpose") == "roe_ack" {
			return o.requestROEAck(ctx, p, stageID, q)
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
		// v7.6.0（C3 任务书瘦身强制）：objective 超 20KB 拒绝——实证子代理平均输入 51-55K
		//（main 的 57-60%，未达 ≤25K 验收线，实测报告 §C3）：任务书=最小事实集+文件指针，
		// 全文粘贴上游交付物会被确定性拒绝。
		if len(objective) > 20*1024 {
			return fmt.Sprintf("错误: objective %d 字节超 20KB 上限（C3 任务书瘦身）——任务书=最小事实集+文件指针。【期望形态】objective 含测试单元一句话+关键事实（编号/端点/判据）+证据指针（evidence/ 路径、F-/VT- 编号）；【修复示例】\"验证 F-XXXX 疑似 IDOR：端点 /api/user/{id}，证据 evidence/s4-authz.tsv 第 12 行，判据=差异响应\"，全文背景让子代理 read_file 自取", len(objective))
		}
		// v7.3.0 C2 探索代理模板（role=explorer）：与执行卡队列并行的异常猎手——
		// 目标函数=单位轮次异常产出最大化，产出仅走 record_candidate/update_coverage。
		if s("role") == "explorer" {
			objective = "【探索任务 role=explorer】目标函数：最大化单位轮次的异常产出（响应长度/时延/状态码跳变、报错片段、同类参数处理不一致）。不限于执行卡队列；每轮结束把异常走 record_candidate 登记（禁止自判 finding）；范围门与 W5 行为预算器照常；禁 L2。【原目标】" + objective
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
		// v7.4.0 D1 质量门：结构化锚点强校验——stack 与 behavior_class 双空的方法论纯文本拒收
		//（lessons-audit 实证：406/406 条结构化字段全空、96.3% 方法论型，stack 指纹检索结构性失灵）。
		// 纯方法论沉淀请进技能库/loop-core，教训库只收可检索的结构化经验。
		bc, st := truncateText(s("behavior_class"), 40), truncateText(s("stack"), 60)
		if strings.TrimSpace(bc) == "" && strings.TrimSpace(st) == "" {
			return "拒绝登记（v7.4.0 D1 质量门）：缺少结构化锚点——stack（技术栈，如 spring/php）与 behavior_class（行为类，如 rate-limited/js-challenge-waf）至少填一项。纯方法论经验请沉淀进对应技能剧本（load_skill 可检索），教训库只收按 stack+行为类可召回的实战经验。"
		}
		// v7.4.0 D1 判重：归一化文本等值拒收（防同义教训反复入库稀释检索）
		if dup := o.duplicateLesson(text); dup != "" {
			return "拒绝登记（v7.4.0 D1 判重）：与既有教训 " + dup + " 归一化等值——同源经验请在原教训语境下复核后增量使用，勿重复入库。"
		}
		id, lerr := o.store.AddLesson(&store.LessonRecord{Text: truncateText(text, 500), Tags: truncateText(tags, 100),
			BehaviorClass: bc,
			Stack:         st,
			SampleSize:    truncateText(s("sample_size"), 40), // v4.6 E5：证据强度（单次实验→provisional）
			ValidScope:    truncateText(s("valid_scope"), 80), // v4.6 E5：适用范围
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
	// v6.2.0（S2-②）：工作区 `-l` 目标清单逐行过影子资产/范围门——文件批量形态不得绕过逐目标校验
	if msg := o.targetListScopeIssues(p, stageID, "run_command", command); msg != "" {
		return msg
	}
	risk := o.exec.ClassifyRisk(command)
	if risk == tools.Forbidden {
		o.log(p, stageID, "⛔ 拒绝破坏性命令（红线）: "+truncateText(command, 120))
		_, _ = o.store.AddEvidence(&store.EvidenceRecord{ProjectID: p.ID, Stage: stageID, Type: "command", Input: command, Output: "被护栏拒绝（破坏性操作禁令）", Risk: risk, ApprovedBy: "forbidden-gate"})
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
	// v7.1.0 P7 工具通道健康归因：错误特征分类计数（timeout/refused/dns/waf403/tool_error）
	o.trackToolHealth(p, stageID, errText(err, exit, out), exit)
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
	// v7.0.0 核对加固⑩（244 分钟烧毁形态的结构性修复）：回连通道进程禁止进 run_async 任务池——
	// async 超时必杀与长命通道语义冲突（实证：interactsh-client 后台任务 3600s 超时被杀纯烧
	// 244 分钟）。通道由引擎托管：oob_check 预置、finishRun 回收；收取用 oob_poll。
	if strings.Contains(strings.ToLower(command), "interactsh-client") {
		return "错误: 回连通道进程禁止经 run_async 起后台任务（历史实证 3600s 超时被杀纯烧 244 分钟）——通道由引擎托管：调 oob_check 即自动预置（生命周期=项目生命周期，收口自动回收），回连收取用 oob_poll。"
	}
	// v4.8 W5 行为预算器前置闸（后台通道同样计入批量配额——对目标的流量本质相同）
	if note := o.batchBudgetGate(p, stageID, command); note != "" {
		return note
	}
	// v5.3.1 P0-2：治理门统一接线——后台长任务对目标的影响与同步命令相同，不得绕过
	if msg := o.governanceGates(p, stageID, command, "run_async", false); msg != "" {
		return msg
	}
	// v6.2.0（S2-②）：后台通道同样校验工作区 `-l` 目标清单（与 run_command 同级，不因后台化绕过）
	if msg := o.targetListScopeIssues(p, stageID, "run_async", command); msg != "" {
		return msg
	}
	timeoutSec := 0
	if n, err := strconv.Atoi(strings.TrimSpace(timeoutStr)); err == nil {
		timeoutSec = n
	}
	risk := o.exec.ClassifyRisk(command)
	if risk == tools.Forbidden {
		o.log(p, stageID, "⛔ 拒绝破坏性命令（红线，后台通道同样适用）: "+truncateText(command, 120))
		_, _ = o.store.AddEvidence(&store.EvidenceRecord{ProjectID: p.ID, Stage: stageID, Type: "command", Input: "[async] " + maskSensitiveText(command), Output: "被护栏拒绝（破坏性操作禁令）", Risk: risk, ApprovedBy: "forbidden-gate"})
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

// batchRiskRank 风险序（用于批量拆分前后风险一致性校验：Forbidden > L2 > L1 > L0）。
func batchRiskRank(r string) int {
	switch r {
	case tools.Forbidden:
		return 3
	case "L2":
		return 2
	case "L1":
		return 1
	default:
		return 0
	}
}

// toolRunBatch v6.0.1 P2（fix-plan 20261122）：批量任务逐目标隔离投递。
// 治理语义：模板与每个 {{TARGET}} 拆分实例都过 ClassifyRisk——任一实例风险升级即拒绝整批
// （要求逐目标单独投递）；模板整体走与 run_async 相同的治理门/预算器/审批链，一次批准覆盖本批
// （工单描述列出目标数），拆分不绕过任何校验。每目标独立进程组/超时/日志，fail-continue。
func (o *Orchestrator) toolRunBatch(ctx context.Context, p *store.Project, stageID, command, targetsStr, timeoutStr, reason string) string {
	if strings.TrimSpace(command) == "" {
		return "错误: command（含 {{TARGET}} 占位符的模板）为空"
	}
	var targets []string
	for _, t := range strings.Split(targetsStr, "\n") {
		if t = strings.TrimSpace(t); t != "" {
			targets = append(targets, t)
		}
	}
	if len(targets) == 0 {
		return "错误: targets 为空（每行一个目标，单批上限 100）"
	}
	// v4.8 W5 行为预算器：整批计一次批量动作（对目标流量本质相同，不得因拆分绕过配额）
	if note := o.batchBudgetGate(p, stageID, command); note != "" {
		return note
	}
	// v5.3.1 P0-2：治理门统一接线（与 run_async 同级，不因拆分绕过）
	if msg := o.governanceGates(p, stageID, command, "run_async", false); msg != "" {
		return msg
	}
	// v6.2.0（S2-②）：批量实例逐目标范围校验——模板含 {{TARGET}} 无字面主机，治理门对模板文本
	// 恒放行；每个目标按「单独命令」口径补过影子资产门与 strict_scope 范围门（不许借批量绕过
	// 「登记线索≠测试授权」；违规拒整批并列出目标，与下方风险升级拒整批语义一致）。
	if o.guardEnabled(func(g *config.GuardConfig) *bool { return g.EnforceBatchScope }) {
		violations := []string{}
		for _, t := range targets {
			if v := o.singleTargetScopeViolations(p, t); v != "" {
				violations = append(violations, v)
			}
		}
		if len(violations) > 0 {
			msg := fmt.Sprintf("拒绝整批：批量目标清单含未授权/范围外目标（%s）——把违规目标从本批移除后重提；新发现子域先 record_asset（scope_evidence 引根域授权条目）登记为 in_scope 再纳入批量；确属范围外只记录不访问。",
				truncateText(strings.Join(violations, "；"), 300))
			_, _ = o.store.AddEvidence(&store.EvidenceRecord{ProjectID: p.ID, Stage: stageID, Type: "command",
				Input: "[batch] " + maskSensitiveText(command), Output: msg, Risk: tools.Forbidden, ApprovedBy: "batch-scope-gate"})
			o.log(p, stageID, fmt.Sprintf("⛔ 批量逐目标范围校验拒整批（%d/%d 目标违规）", len(violations), len(targets)))
			return msg
		}
	}
	timeoutSec := 0
	if n, err := strconv.Atoi(strings.TrimSpace(timeoutStr)); err == nil {
		timeoutSec = n
	}
	// 模板与逐目标实例风险一致性：仅目标 token 替换不得改变风险分级
	templateRisk := o.exec.ClassifyRisk(command)
	if templateRisk == tools.Forbidden {
		o.log(p, stageID, "⛔ 拒绝破坏性批量模板（红线，批量通道同样适用）: "+truncateText(command, 120))
		return "拒绝执行：该批量模板命中破坏性操作禁令。请改用最小影响方式。"
	}
	for _, t := range targets {
		inst := strings.ReplaceAll(command, "{{TARGET}}", "'"+strings.ReplaceAll(t, "'", `'\''`)+"'")
		if instRisk := o.exec.ClassifyRisk(inst); batchRiskRank(instRisk) > batchRiskRank(templateRisk) {
			o.log(p, stageID, fmt.Sprintf("⛔ 批量拆分风险升级（目标 %s: %s > 模板 %s）——拒绝整批", t, instRisk, templateRisk))
			return fmt.Sprintf("拒绝整批：目标 %s 的拆分实例风险升级（%s > 模板 %s）——该目标可能命中敏感模式，请把它从本批移除并单独走 run_command 审批投递（不许借批量绕过分级）。", t, instRisk, templateRisk)
		}
	}
	desc := fmt.Sprintf("批量后台执行（%d 目标，逐目标隔离）: %s\n原因: %s", len(targets), maskSensitiveText(command), maskSensitiveText(reason))
	decision, err := o.approver.Request(ctx, p.ID, stageID, desc, templateRisk)
	if err != nil {
		return "审批异常: " + err.Error()
	}
	if decision != "approved" && decision != "auto-approved" {
		_, _ = o.store.AddEvidence(&store.EvidenceRecord{ProjectID: p.ID, Stage: stageID, Type: "command",
			Input: "[batch] " + maskSensitiveText(command), Output: "人工拒绝（" + strconv.Itoa(len(targets)) + " 目标）", Risk: templateRisk, ApprovedBy: "human-rejected"})
		return "人工审批拒绝该批量任务。请说明替代方案或收口本阶段。"
	}
	approvedBy := "auto"
	if decision == "approved" {
		approvedBy = "human"
		o.log(p, stageID, fmt.Sprintf("✔ 人工批准批量执行（%d 目标）", len(targets)))
	}
	batch, err := o.exec.StartBatch(p.ID, command, targets, timeoutSec)
	if err != nil {
		return "错误: 批量启动失败 " + err.Error()
	}
	var ids []string
	startFail := 0
	for _, tr := range batch.Targets {
		if tr.Err != "" {
			startFail++
			continue
		}
		ids = append(ids, tr.JobID)
	}
	_, _ = o.store.AddEvidence(&store.EvidenceRecord{ProjectID: p.ID, Stage: stageID, Type: "command",
		Input: "[batch] " + maskSensitiveText(command), Output: fmt.Sprintf("batch=%s targets=%d jobs=%v started_fail=%d", batch.ID, len(batch.Targets), ids, startFail), Risk: templateRisk, ApprovedBy: approvedBy})
	o.log(p, stageID, fmt.Sprintf("🚀 批量任务 %s 已启动（%d/%d 目标，逐目标隔离超时 %ds）", batch.ID, len(ids), len(batch.Targets), batch.PerTargetTimeout))
	return fmt.Sprintf("批量任务已启动 batch=%s（%d/%d 目标成功派发，逐目标独立超时 %ds；启动失败 %d 个已记录）。\n逐 job 用 poll_async 收结果（job id 见 batch-%s sidecar/证据记录）；单目标失败/超时不影响其余。poll 结果零产出或 killed 时必须 record_vt 登记（title 含 job id），不得写阴性结论。", batch.ID, len(ids), len(batch.Targets), batch.PerTargetTimeout, startFail, batch.ID)
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
		// v6.1.0（S1 修复方案⑧）：ROE cooldown_protocol=full-silence 与 W5 冷却联动——
		// ROE 声明完全静默时，冷却期结束前所有目标流量通道二次拦截（roe-runtime-gate）。
		if o.roeRuntime != nil {
			o.roeRuntime.NoteCooldown(now)
		}
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
// v6.0.1 P4：新增 log_bytes/last_output_at 实时观测（区分「运行中无输出」与「日志损坏」）；
// v6.0.1 P2：killed/零产出时强制 VT/coverage 留痕提示（收口由 C31 门机械对账）。
func (o *Orchestrator) toolPollAsync(p *store.Project, stageID, jobID string) string {
	jobID = strings.TrimSpace(jobID)
	state, out, code, elapsed, ok := o.exec.PollAsync(p.ID, jobID)
	if !ok {
		return "错误: 未知 job id（应为 run_async/run_batch 返回的 id）"
	}
	logBytes, lastOut, _ := o.exec.AsyncLogStats(p.ID, jobID)
	var b strings.Builder
	fmt.Fprintf(&b, "job=%s 状态=%s 已运行=%s", jobID, state, elapsed)
	if state != "running" {
		fmt.Fprintf(&b, " 退出码=%d", code)
	}
	fmt.Fprintf(&b, " log_bytes=%d", logBytes)
	if lastOut != "" {
		fmt.Fprintf(&b, " last_output=%s", lastOut)
	}
	b.WriteString("\n---输出尾部---\n")
	b.WriteString(out)
	switch state {
	case "running":
		if logBytes == 0 && elapsed > 90*time.Second {
			b.WriteString("\n🧯 [P4 观测] 运行超 90s 且日志零字节——检查命令是否被管道缓冲（如 `| tail` 会缓冲到结束才落盘，改用 tee 或去掉管道）；任务本身仍在运行，不要同步等待。")
		} else {
			b.WriteString("\n（仍在运行：继续其他子任务，稍后再 poll_async；不要同步等待）")
		}
	case "killed":
		// v7.1.0 P7 核对补线（第四轮审计 J）：后台任务被杀/超时同样计入通道健康归因
		o.trackToolHealth(p, stageID, "timed out (async job killed)", 1)
		b.WriteString("\n⚠ [P2 对账] 因超时被终止——产出不完整：必须 record_vt 登记（title 含本 job id，启动条件写复测前提），覆盖单元不得写 ruled_out/no_issue_found；收口时 C31 门会机械核对 job id 留痕。")
	case "finished":
		if logBytes < 32 {
			b.WriteString("\n⚠ [P2 对账] 已结束但近零产出——若属批量扫描器结果，必须 record_vt 登记（title 含本 job id）并 update_coverage 用 needs_follow_up 登记未完成面，不得写阴性结论；收口时 C31 门会机械核对 job id 留痕。")
		} else {
			b.WriteString("\n（已结束：解析输出、record_* 入库、update_coverage 登记；日志全文在 " + "projects/" + p.ID + "/" + " 对应 .async/ 文件）")
		}
	}
	return b.String()
}

// installToolMap 已知工具的源码镜像（github 失败自动切 gitee，适配网络受限环境）。
var installToolGitMap = map[string][]string{
	"sqlmap": {"https://github.com/sqlmapproject/sqlmap.git", "https://gitee.com/mirrors/sqlmap.git"},
	"nuclei": {"https://github.com/projectdiscovery/nuclei.git", "https://gitee.com/mirrors/projectdiscovery-nuclei.git"},
}

// installProbeCmd v5.7.3 存在性探测命令：PATH 命中 + /root/go/bin 显式探测 + 安装标记三路。
// 背景（实证事故）：exec.Run 用 bash -lc 登录 shell，Kali /etc/profile 重置 PATH
// 剥掉 /root/go/bin——interactsh-client 明明随底座预装于 ~/go/bin，command -v 探测不到 →
// install_tool 误判缺失，走 apt/pip/git 必败安装链（Kali 无此包/PyPI 无发行版/git 未注册）。
func installProbeCmd(name, marker string) string {
	return fmt.Sprintf("command -v %s || test -x /root/go/bin/%s || test -f %s", name, name, marker)
}

// installVerifyCmd 安装成功校验命令（与探测同口径，含 /root/go/bin 显式路径）。
func installVerifyCmd(name string) string {
	return fmt.Sprintf("command -v %s >/dev/null 2>&1 || test -x /root/go/bin/%s || test -f /opt/tools/%s/%s.py", name, name, name, name)
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
	chk, _ := o.exec.Run(ctx, p.ID, installProbeCmd(name, marker), 30)
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
		verify := installVerifyCmd(name)
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

// s5UploadRegistry v6.8.0（S7-③）：S5 上传落点登记双轨检测（v6.7.0 S6-③ 判据提取复用，
// s6/s7 两处消费同源零漂移）——①文件名轨：s5- 前缀且含「上传/落点」（排除 s8- 跨阶段误命中）；
// ②内容特征兜轨：s5-*.md 含「建议清理命令」+「验证命令」双特征行（四元组登记行必写要素）
// 即命中并摘录 ≤5 行样本（返回截断后的行文本，不带列表符——由调用方按上下文格式渲染）。
// 消费端：s6「S5 移交项」块（承接复用面）与 s7「S6 移交项」块 S5 兜底小节（S7-2 清理对账
// 第一数据入口；s6-skipped 项目唯一结构化通道）。
func (o *Orchestrator) s5UploadRegistry(p *store.Project) (files []string, samples []string) {
	names, err := o.exec.ListDir(p.ID, "deliverables")
	if err != nil {
		return nil, nil
	}
	seen := map[string]bool{}
	for _, rel := range names {
		base := filepath.Base(rel)
		if !strings.HasSuffix(base, ".md") {
			continue
		}
		if strings.HasPrefix(base, "s5-") && (strings.Contains(base, "上传") || strings.Contains(base, "落点")) {
			files = append(files, rel)
			seen[rel] = true
		}
	}
	for _, rel := range names {
		base := filepath.Base(rel)
		if !strings.HasSuffix(base, ".md") || seen[rel] || !strings.Contains(base, "s5-") {
			continue
		}
		raw, rerr := o.exec.ReadFile(p.ID, rel)
		if rerr != nil || !strings.Contains(raw, "建议清理命令") || !strings.Contains(raw, "验证命令") {
			continue
		}
		files = append(files, rel)
		seen[rel] = true
		n := 0
		for _, ln := range strings.Split(raw, "\n") {
			if strings.Contains(ln, "建议清理命令") && strings.Contains(ln, "验证命令") {
				samples = append(samples, truncateText(strings.TrimSpace(ln), 160))
				if n++; n >= 5 {
					break
				}
			}
		}
	}
	return files, samples
}

// buildContextPack 上下文包总装。
// v7.5.0（C6）：pack_budget_mode=strict 时低优先级块（候选账本/L2 审批工单/组织级教训/
// 最近时间线）在包体超 60KB 的二次渲染中省略（完整内容均可在工作台页签与 search_memory
// 取回；治理口径/ROE/移交块/覆盖矩阵/黑板永保）；legacy（默认）恒为完整包（现行口径）。
func (o *Orchestrator) buildContextPack(p *store.Project, stageID string) string {
	pack := o.buildContextPackMode(p, stageID, false)
	threshold := o.cfg.Engine.PackStrictBytes
	if threshold <= 0 {
		threshold = 60 * 1024
	}
	if o.cfg.Engine.PackBudgetMode == "strict" && len(pack) > threshold {
		if lean := o.buildContextPackMode(p, stageID, true); len(lean) < len(pack) {
			o.log(p, stageID, fmt.Sprintf("📦 严格预算模式：上下文包 %.0fKB 超阈值，低优先级块（候选/审批/教训/时间线）已省略（可查回）", float64(len(pack))/1024))
			return lean + "\n> （严格预算模式：候选账本/L2 工单/教训/时间线块本包省略——工作台对应页签与 search_memory 可查；治理口径/移交/覆盖/黑板不受影响）\n"
		}
	}
	return pack
}

func (o *Orchestrator) buildContextPackMode(p *store.Project, stageID string, lowPriOff bool) string {
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
	// v2.4.0 多目标完整呈现 + v6.1.0（方案⑱）：上下文/预算/收口复用同一目标事实源
	// splitProjectTargets（trim+跳空行）——修复「上下文 raw split 计空行、预算跳空行」
	// 的计数漂移；多目标纪律块只对实际参与自适应放大的阶段（s1/s2/s3/s4/s5；v6.1.0 方案⑤纳入 s1、v6.3.0 S3-② 纳入 s3）宣称放大，
	// 其余阶段改为不含预算承诺的目标清单呈现（不向模型撒谎）。
	targets := splitProjectTargets(p)
	if len(targets) == 0 {
		if stageID == "s1" {
			return "## 项目上下文\n\n项目目标为空：S1 不可开始，请补充目标清单后重试。"
		}
		b.WriteString(fmt.Sprintf("## 项目上下文\n\n- 项目: %s\n- 目标: （未配置）\n", p.Name))
	} else if len(targets) == 1 {
		b.WriteString(fmt.Sprintf("## 项目上下文\n\n- 项目: %s\n- 目标: %s\n", p.Name, targets[0]))
	} else {
		b.WriteString(fmt.Sprintf("## 项目上下文\n\n- 项目: %s\n- 目标（共 %d 个，逐个登记与测绘；范围状态以《范围边界表》逐项判定为准）:\n", p.Name, len(targets)))
		for i, t := range targets {
			b.WriteString(fmt.Sprintf("  %d. %s\n", i+1, t))
		}
		// v4.4 多目标轮次与推进纪律（方向二B/C；v6.1.0 方案⑤只对自适应名单阶段承诺放大；
		// v6.3.0 S3-② 将 s3 纳入自适应名单——判定工作量随目标数线性增长；
		// v6.6.0 SP-① 将三个专项纳入——多 APP/多小程序/多 AI 资产项目解包/反编译/动态链与
		// A1-A14/W1-W10 条目判定同样随目标数线性增长）
		if pt := o.cfg.Engine.PerTargetRounds; pt > 0 {
			// v6.7.0（S6-⑩ 选项 A）：s6 纳入多目标自适应——多目标项目 S6 工作量随目标数（立足点
			// 数）线性增长（逐主机枚举/逐凭据复放/权限矩阵与横向路径图逐目标撰写），固定 base 会把
			// 横向深度挤压成 needs_follow_up 让渡；封顶 3×base 防预算爆炸，文案与 stageBudget 同名单。
			// v6.9.0（S8-④）：s8 纳入——多目标报告按目标组织（s8.md 分组合并条款逐组 read_file+
			// 核对合并）工作量随目标数线性增长，固定 base 会把报告合并挤压成静默省略→代收口连锁。
			adaptive := stageID == "s1" || stageID == "s2" || stageID == "s3" || stageID == "s4" || stageID == "s5" || stageID == "s6" || stageID == "s8" || stageID == "specA" || stageID == "specB1" || stageID == "specB2"
			if adaptive {
				if stageID == "s8" {
					// s8 专用纪律——报告阶段的工作量在分组合并与逐章撰写，「探针层/确证」语言不适用，
					// 同预算承诺换报告侧推进口径（不向模型撒谎：预算确已放大）。
					b.WriteString(fmt.Sprintf("- 🎯 多目标推进纪律：本阶段轮次已按目标数自适应放大（每增 1 目标 +%d 轮，封顶 3×基准）；**分组承接先于正文撰写**——开工先按「分组交付物承接」清单逐组核对（每组 1-2 轮：读分组文件+定级映射），全部目标有归属结论后再按等级排报告章节撰写序；单组消耗超自身基线（约 %d 轮）2 倍仍未成稿 → 止损：未合并组在报告「待续/盲区」章如实说明，轮次让渡给未完成组；零发现目标按覆盖矩阵口径一句带过，不展开。\n", pt, pt))
				} else {
					b.WriteString(fmt.Sprintf("- 🎯 多目标推进纪律：本阶段轮次已按目标数自适应放大（每增 1 目标 +%d 轮，封顶 3×基准）；**目标级轮转先于类级轮转**——先全目标过最小探针层（每目标每类 1-2 轮），全部目标有首轮结论后再按信号强度排深化序；单目标消耗超自身基线（约 %d 轮）2 倍仍零确证 → 止损转 needs_follow_up，轮次让渡给未完成目标；不可达/纯静态目标降级为**档案目标**（只登记资产与交付物，不再深挖）。\n", pt, pt))
				}
			} else {
				b.WriteString("- 🎯 多目标推进纪律：本阶段轮次不随目标数放大（自适应仅 s1/s2/s3/s4/s5/s6/s8/specA/specB1/specB2 名单内阶段）——按信号强度排优先级，逐目标结论落到台账/覆盖矩阵，未触达目标显式列 needs_follow_up。\n")
			}
		}
	}
	// v6.0.4 P11（用户输入全量接线）：治理字段由 firstLine（仅首行）改为全文注入——
	// 实证：多行授权范围/ROE 第二行起从未到达模型（BC19 ROE 第二行「验证码人机协同」全程丢失）。
	// 每字段 rune 上限截断防上下文膨胀，截断标注「余略见项目档案」。
	b.WriteString(fmt.Sprintf("- 授权范围: %s\n- ROE 红线（全文）: %s\n- 测试类型: %s\n- 已启用专项: %s\n- 工作区: projects/%s/（write_file 路径相对该目录）\n",
		cappedText(p.Scope, 1500), cappedText(p.ROE, 1500), cappedText(p.TestType, 200), strings.Join(p.Specializations, ","), p.ID))
	b.WriteString("\n")
	// 未启用专项 A：明确禁止 AI/LLM 相关动作（用户未选就不做，避免凭空出现 AI 资产专项任务）
	hasSpecA := false
	for _, s := range p.Specializations {
		if s == "A" {
			hasSpecA = true
		}
	}
	if !hasSpecA {
		// v6.1.0（S1 修复方案⑥）：AI 被动盘点（范围发现）与专项 A 主动测试拆分——未启用 A 仍必须完成 S1-2 被动识别与登记，禁止的只是主动探测/接口枚举/提示注入。
		b.WriteString("- 专项A（AI/LLM 目标测试）未启用：允许按 S1 被动来源（客户清单/公开文档/CT/DNS）识别并登记 AI 资产（record_asset，scope_status 按授权事实标注）；禁止入口主动探测、模型接口枚举、提示注入及任何 AI 专项测试任务——主动测试仅在专项 A 启用且授权满足的后续阶段执行。\n")
	}
	if strings.TrimSpace(p.SuccessCriteria) != "" {
		b.WriteString(fmt.Sprintf("- 测试目的/成功标准（全文，S8 报告必须对照回应）: %s\n", cappedText(p.SuccessCriteria, 800)))
	}
	if p.StrictScope {
		b.WriteString("- 严格限定范围：只测给定目标；范围外线索只记录、不继续访问。\n")
	}
	if p.Authorized {
		// v6.1.0（S1 修复方案⑩）：创建确认≠操作红线确认——删除「直接开工」表述。
		if strings.TrimSpace(p.ROEAcknowledgedAt) != "" {
			b.WriteString(fmt.Sprintf("- 授权状态：已授权（创建时已确认书面授权）；ROE 红线四要素已于 %s 经 request_user_input 确认——命令通道已放行。\n", p.ROEAcknowledgedAt))
		} else {
			b.WriteString("- 授权状态：项目创建时已确认书面授权。此确认不替代 S1 的 ROE 红线确认；可以梳理项目资料并展示四要素，任何工具命令或外部请求必须等用户明确确认本项目范围、禁止项、频率和数据边界后再执行（request_user_input(purpose=roe_ack)，回答 yes 即放行）。\n")
		}
	} else {
		b.WriteString("- 授权状态：未确认！禁止任何主动测试动作，仅允许只读公开信息查询。\n")
	}
	if strings.TrimSpace(p.AuthInfo) != "" {
		b.WriteString(fmt.Sprintf("- 认证会话（仅用于授权测试）: %s\n", cappedText(p.AuthInfo, 1000)))
	}
	b.WriteString("\n")
	b.WriteString(fmt.Sprintf("## 当前任务\n\n你是阶段[%s]专家头：%s。%s\n\n", stageID, headName, headGoal))
	// v6.4.0（S4-⑩）：回环重入原因——loopback 入队时写入目标阶段 StageState.ReentryReason，
	// 重跑阶段开工注入本块（原实现 reason 只落时间线，重入阶段须自行翻最近 15 条窗口；
	// 注入后 S4 第一轮即对准回环线索，收口成功后清空）。
	if st := p.StageStates[stageID]; st != nil && strings.TrimSpace(st.ReentryReason) != "" {
		b.WriteString(fmt.Sprintf("> ↩ **回环重入原因**（上游阶段 loopback 移交）：%s——本阶段收口前优先补测/裁决该线索（结合覆盖矩阵中 reason=precondition_missing/patch_pending_retest 的 S5 回写条目），并在交付物中留痕处置结论。\n\n", truncateText(st.ReentryReason, 300)))
		// v7.4.2 修复（缺口②）：重入承接包——本阶段上一轮交付物清单。既往阶段摘要块只含
		// done+skipped，重入中的自身（running/pending）不在其中；上轮产出若不可见，
		// 模型易把聚焦补测当全量首测。列名即承接入口（read_file 取全文）。
		if len(st.Deliverables) > 0 {
			b.WriteString("> **本阶段上一轮交付物**（重入承接：read_file 承接后按回环聚焦范围补测，已确证结论勿重做/勿重复登记）：")
			for i, d := range st.Deliverables {
				if i >= 15 {
					b.WriteString(fmt.Sprintf("…（其余 %d 份 list_files 查看）", len(st.Deliverables)-15))
					break
				}
				b.WriteString(d + "；")
			}
			b.WriteString("\n\n")
		}
	}

	// v3.3.0 黑板与战利品随上下文包注入（CyberStrikeAI「索引自动注入对话」）：
	// confirmed 事实与可用战利品每阶段开工即在场，不再依赖模型主动 search_memory。
	// v6.5.0（S5-⑩）：战利品注入上限 10→20——凭据复用矩阵（S5-5）与横向移动（S6-2
	// 「横向前先查战利品」）都以战利品库为第一入口，凭据密集项目 10 条不够扫一眼；
	// 超出仍 search_memory 兜底。
	facts, _ := o.store.ListFacts(p.ID, 25)
	loots, _ := o.store.ListLoot(p.ID, 20)
	memNote := ""
	if len(facts) > 0 {
		memNote = fmt.Sprintf(" / 黑板 %d 条", len(facts))
	}
	if len(loots) > 0 {
		memNote += fmt.Sprintf(" / 战利品 %d 件", len(loots))
	}
	b.WriteString(fmt.Sprintf("## 记忆库（资产 %d 项 / 漏洞 %d 项 / 时间线 %d 条%s）\n\n", len(assets), len(findings), len(timeline), memNote))
	if len(assets) > 0 {
		// v6.3.0（S3-⑧）：上限 30→60 + 类型分布摘要——大项目资产截断时 AI/凭据类资产
		// 不再随机丢失，且分布行让模型知道全貌（未显示项经 search_memory 可查）。
		if len(assets) > 60 {
			typeCnt := map[string]int{}
			for _, a := range assets {
				typeCnt[a.Type]++
			}
			var parts []string
			for t, n := range typeCnt {
				parts = append(parts, fmt.Sprintf("%s=%d", t, n))
			}
			sort.Strings(parts)
			b.WriteString(fmt.Sprintf("### 已登记资产（共 %d 项：types %s；仅显示前 60 条，其余 search_memory 查询）\n", len(assets), strings.Join(parts, ",")))
		} else {
			b.WriteString("### 已登记资产\n")
		}
		n := 0
		for _, a := range assets {
			b.WriteString(fmt.Sprintf("- [%s] %s（%s）\n", a.Type, a.Value, a.Stage))
			if n++; n >= 60 {
				b.WriteString("- ...(截断)\n")
				break
			}
		}
	}
	if len(findings) > 0 {
		b.WriteString("### 已登记漏洞\n")
		// v4.4 批次4：S5 待利用队列按 impact-rank 升序 → 置信度 → 严重度排序消费（xalgorix 深度优先学说队列化）
		// v6.4.0（S4-④）：无凭证项目 access=anonymous 项第 0 排序键置前（sortQueueFindings 兑现
		// 本行声明；有凭证项目不显示该承诺——「不向模型撒谎」纪律）。
		list := findings
		if stageID == "s5" {
			anonymousFirst := !o.projectHasIdentity(p)
			list = sortQueueFindings(findings, anonymousFirst)
			if anonymousFirst {
				b.WriteString("（待利用队列已按 access=anonymous 优先 → impact-rank 升序 → 置信度 → 严重度排序：RCE 系先打，无凭证项目匿名项优先消费）\n")
			} else {
				b.WriteString("（待利用队列已按 impact-rank 升序 → 置信度 → 严重度排序：RCE 系先打）\n")
			}
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
	// v6.4.0（S4-⑤⑥）：S5「S4 移交项」专属注入块——S4 收口/代收口的 V3 两清单（StageState
	// 结构化字段，见 store.StageState）+ route=browser-auth（含旧数据 detail 文本标记等价）
	// 的认证路线移交项。原实现只落时间线（上下文 15 条窗口可能挤出）与影子交付物文件（引擎不读），
	// s5.md:14「承接反蒸发」三态映射无在场依据。条目上限 20，超出提示 search_memory。
	if stageID == "s5" {
		handover := o.s4HandoverItems(p)
		if len(handover) > 0 {
			b.WriteString("### S4 移交项（承接反蒸发 v5.1.3：改写本清单必须逐条三态映射——执行 / 合并进新编队（写明新编号）/ 显式移交（进待续清单）；禁止静默丢弃，S8 复核按此对账；收口时引擎逐条对账承接留痕——**逐条映射按目标进行，A 目标的留痕不释放 B 目标的同类条目**）\n")
			// 方案 S4-⑤②：块首附 S4 收口摘要（三态映射的背景事实——S4 按什么结论移交）
			if s4st := p.StageStates["s4"]; s4st != nil && strings.TrimSpace(s4st.Summary) != "" {
				b.WriteString(fmt.Sprintf("> S4 收口摘要：%s\n", truncateText(strings.TrimSpace(s4st.Summary), 300)))
			}
			// v6.5.0（S5-②）：多目标项目按条目标签 @目标 分组呈现（组序=项目目标顺序在前、
			// 全局殿后；异常标签殿后追加防丢组）；单组时不出小节保持上下文紧凑（单目标项目零形态变化）。
			groups := map[string][]string{}
			var order []string // 首现序（防丢组 + 防御尾部保持确定性）
			seen := map[string]bool{}
			for _, it := range handover {
				t := parseHandoverTarget(it)
				if t == "" {
					t = handoverGlobalTag
				}
				if !seen[t] {
					seen[t] = true
					order = append(order, t)
				}
				groups[t] = append(groups[t], it)
			}
			var groupOrder []string
			for _, t := range targets {
				if seen[t] {
					groupOrder = append(groupOrder, t)
					seen[t] = false
				}
			}
			if seen[handoverGlobalTag] {
				groupOrder = append(groupOrder, handoverGlobalTag)
				seen[handoverGlobalTag] = false
			}
			for _, t := range order { // 防御：标签目标不在项目目标清单（异常数据）——殿后追加防丢组
				if seen[t] {
					groupOrder = append(groupOrder, t)
				}
			}
			n := 0
			authStarted := false
			for _, t := range groupOrder {
				if len(order) > 1 {
					b.WriteString(fmt.Sprintf("\n**目标：%s**\n", t))
				}
				for _, it := range groups[t] {
					// 方案 S4-⑥②：认证路线移交项单列小节（S5-2a 承接指引随小节给出）
					// v6.5.0（S5-②）：前缀放宽到标签主体——条目现可带 @目标 后缀
					if strings.HasPrefix(it, "[认证路线移交 S5-2a") && !authStarted {
						b.WriteString("\n**S4 认证路线移交（S5-2a 承接：browser-kit 登录链 + S4 已还原前置知识见 detail）**\n")
						authStarted = true
					}
					b.WriteString("- " + it + "\n")
					if n++; n >= 20 {
						b.WriteString("- ...（移交项超 20 条截断，search_memory 查更多）\n")
						break
					}
				}
				if n >= 20 {
					break
				}
			}
			b.WriteString("\n")
		}
		// v6.6.0（SP-③）：S5「专项就绪移交」小节——三个专项（specA/specB1/specB2）收口的
		// V3 ready_but_unexecuted 清单在此呈现（SP-③ 起专项收口同样强制 V3 双清单，落
		// StageState.V3Ready/V3L2）。专项是流水线上 s4 与 s5 之间的就绪资产高发生产点
		//（specB1 静态链假设队列/specA oracle 与基线用例），此前无结构化通道——本块只置顶
		// 在场（呈现性注入，不新增拦截——承接质量由 S7 VT 清点门与 s8 报告门兜底）。
		// 条目上限 10，超出提示 search_memory；@目标 标签沿用 tagHandoverTarget（多目标分桶对账）。
		// v6.6.0 增补（核对轮）：spec 的 V3L2（已批未用）与 V3Ready 一同呈现——SP-③ 方案
		// 「为什么修复」第 3 点指出的 L2 悬空窗口在 S5 层补上可见性（S4→S5「S4 移交项」块
		// 两清单同呈，本块对齐同款口径；L2 承接同样走 S7 清点对账）。
		var specLines []string
		for _, sid := range []string{"specA", "specB1", "specB2"} {
			if sts := p.StageStates[sid]; sts != nil {
				for _, it := range sts.V3Ready {
					if strings.TrimSpace(it) == "" {
						continue
					}
					specLines = append(specLines, fmt.Sprintf("[%s 就绪未执行] %s", sid, it))
				}
				for _, it := range sts.V3L2 {
					if strings.TrimSpace(it) == "" {
						continue
					}
					specLines = append(specLines, fmt.Sprintf("[%s 已批未用] %s", sid, it))
				}
			}
		}
		if len(specLines) > 0 {
			hoTargets := splitProjectTargets(p)
			b.WriteString("\n**专项就绪移交（v6.6.0 SP-③：specA/specB1/specB2 收口的就绪未投递资产——承接 = 执行 / 显式移交待续清单二选一留痕；禁止静默丢弃，S7 清点三选一口径）**\n")
			n := 0
			for _, it := range specLines {
				b.WriteString("- " + tagHandoverTarget(it, hoTargets) + "\n")
				if n++; n >= 10 {
					b.WriteString("- ...（专项移交项超 10 条截断，search_memory 查更多）\n")
					break
				}
			}
		}
	}
	// v6.5.0（S5-⑩）：S6「S5 移交项」专属注入块——S4→S5 有结构化移交双件套（注入块+
	// 承接对账门），S5→S6 此前只有通用摘要通道：S5 收口的 V3 两清单无任何下游消费者
	//（无 StageStates["s5"] V3 读取方）、verified 战利品可能被通用块上限挤出、上传落点
	// 四元组与《初始访问》文件指针全靠模型翻工作区。本块把 S6 开工承接需要的事实置顶
	// 在场（呈现性注入，不新增拦截——承接质量仍由 s6.md 开工承接行约束）。
	if stageID == "s6" {
		if st5 := p.StageStates["s5"]; st5 != nil {
			var lines []string
			// v6.5.0（S5-⑩+S5-② 同源）：S5 V3 条目复用 @目标 标签打标（多目标项目按目标
			// 呈现承接维度；单目标不打标零变化）——与 S4→S5 移交块同一 tagHandoverTarget 数据源。
			hoTargets := splitProjectTargets(p)
			for _, it := range st5.V3Ready {
				if strings.TrimSpace(it) != "" {
					lines = append(lines, "- "+tagHandoverTarget("[S5 就绪未执行] "+it, hoTargets)+"（S6 按价值消费或显式移交——S7 清点三选一口径）")
				}
			}
			for _, it := range st5.V3L2 {
				if strings.TrimSpace(it) != "" {
					lines = append(lines, "- "+tagHandoverTarget("[S5 已批未用] "+it, hoTargets)+"（S6 按价值消费或显式移交——S7 清点三选一口径）")
				}
			}
			// verified 战利品增量：通用战利品块（前 20 条按 ListLoot 返回序）之外的 verified 项
			seen := map[string]bool{}
			for _, l := range loots {
				seen[l.Masked] = true
			}
			if all, aerr := o.store.ListLoot(p.ID, 0); aerr == nil {
				nLoot := 0
				for _, l := range all {
					if l.Verified != "verified" || seen[l.Masked] {
						continue
					}
					lines = append(lines, fmt.Sprintf("- [verified 战利品·通用块外] [%s] %s @ %s（来源 %s）",
						l.Type, l.Masked, l.Target, truncateText(l.Source, 50)))
					if nLoot++; nLoot >= 10 {
						break
					}
				}
			}
			// s5 交付物指针：《初始访问》《上传文件记录清单》（→S7 对接）与逐目标分组文件
			// v6.7.0（S6-③）：上传落点指针双轨——旧实现只按「文件名含上传」grep，48 实跑项目
			// 0 命中（真实落点记录在 s5-需人工清理清单.md 等文件名下，唯一命中是 s8 文件）。
			// ①文件名轨：s5- 前缀且含「上传/落点」（排除 s8- 跨阶段误命中）；②内容特征兜轨：
			// 逐个 s5-*.md 读内容，命中「建议清理命令」+「验证命令」双特征（四元组登记行必写
			// 要素）即列入指针并摘录 ≤5 行样本——无论落点记在哪个文件名下，四元组行逃不掉。
			// v6.8.0（S7-③）：双轨判据提取为 s5UploadRegistry——s6/s7 两处消费同源零漂移。
			if names, derr := o.exec.ListDir(p.ID, "deliverables"); derr == nil {
				var s5Deliv []string
				for _, rel := range names {
					base := filepath.Base(rel)
					if strings.HasSuffix(base, ".md") && strings.Contains(base, "s5-") {
						s5Deliv = append(s5Deliv, rel)
					}
				}
				if len(s5Deliv) > 0 {
					lines = append(lines, "- [S5 交付物] 已验证漏洞/初始访问/利用时间线与逐目标分组文件："+strings.Join(s5Deliv, "、")+"——开工 read_file 承接")
				}
				uploadFiles, uploadSamples := o.s5UploadRegistry(p)
				if len(uploadFiles) > 0 {
					ln := "- [上传落点] 落点四元组（路径/指纹/建议清理命令/验证命令）记录于 " + strings.Join(uploadFiles, "、") + "——S6 承接复用面/S7 清理确认逐项对账，不执行任何删除/还原"
					if len(uploadSamples) > 0 {
						ln += "；登记行样本：\n"
						for _, s := range uploadSamples {
							ln += "  - " + s + "\n"
						}
					}
					lines = append(lines, ln)
				}
			}
			if len(lines) > 0 {
				b.WriteString("### S5 移交项（S6 开工承接：①S5 就绪未执行/已批未用按价值消费或显式移交 ②verified 战利品横向前复核 ③s5 交付物与上传落点四元组 read_file 承接——与 S4→S5 移交块同族口径，本块只置顶在场）\n")
				for i, ln := range lines {
					if i >= 20 {
						b.WriteString("- ...（移交项超 20 条截断，read_file/search_memory 查更多）\n")
						break
					}
					b.WriteString(ln + "\n")
				}
				b.WriteString("\n")
			}
		}
		// v6.6.1 核对轮增补：专项 V3 条目在 S6 独立小节保持在场——spec 就绪资产此前只在
		// S5「专项就绪移交」块可见，S5 收口后进入 S6 即再次"下架"（s6 移交块此前只读 s5
		// StageState），可见性窗口从 S5 单阶段扩展为 S5+S6 贯穿；独立小节不与 S5 行清单
		// 竞争 20 条截断窗口，且不依赖 s5 是否收口。承接口径与 S5 块一致（消费或显式移交；
		// L2 由 s7 V4 比对面逐单核对——V4 遍历全项目 approved L2 工单对照时间线 V3 申报，
		// 与来源阶段无关；VT 化条目由 s7 VT 清点门核对）。
		var specS6Lines []string
		for _, sid := range []string{"specA", "specB1", "specB2"} {
			if sts := p.StageStates[sid]; sts != nil {
				for _, it := range sts.V3Ready {
					if strings.TrimSpace(it) != "" {
						specS6Lines = append(specS6Lines, fmt.Sprintf("- [%s 就绪未执行] %s（承接 = 执行 / 显式移交——S7 清点三选一口径）", sid, it))
					}
				}
				for _, it := range sts.V3L2 {
					if strings.TrimSpace(it) != "" {
						specS6Lines = append(specS6Lines, fmt.Sprintf("- [%s 已批未用] %s（s7 V4 比对面逐单核对）", sid, it))
					}
				}
			}
		}
		if len(specS6Lines) > 0 {
			b.WriteString("**专项就绪移交（v6.6.1 核对轮：specA/specB1/specB2 收口条目在 S6 保持在场）**\n")
			n6 := 0
			for _, ln := range specS6Lines {
				b.WriteString(ln + "\n")
				if n6++; n6 >= 10 {
					b.WriteString("- ...（专项移交项超 10 条截断，search_memory 查更多）\n")
					break
				}
			}
			b.WriteString("\n")
		}
	}
	// v6.7.0（S6-②）：S7「S6 移交项」注入块——S4→S5 有「S4 移交项」块+承接对账门、S5→S6 有
	// 「S5 移交项」块+承接提示，S6→S7 此前是三个接缝中唯一无结构化移交的一段：S7 只能靠
	// 「既往阶段交付物」摘要行与工作区文件 200 字摘要翻找《权限矩阵》《横向路径图》《持久化
	// 记录》《存量持久化痕迹排查》，s7.md「缺登记即拦截」无任何机械数据入口（实跑最佳案例
	// 某历史任务 的「S6 增量 0」是模型翻完文件的人工结论，不是引擎保证）。本块只置顶在场
	//（呈现性注入，不新增拦截——残缺四元组由 deterministicGate s7 分支提示级核对，S6-⑤）：
	// ①s6 交付物指针分四类 ②《持久化记录》四元组登记行提取在场 ③存量排查移交项摘要。
	if stageID == "s7" {
		hoTargets := splitProjectTargets(p)
		// v6.8.1：s6-skipped 范围标注块——S5→S7 直通（用户未勾选 post_exploit，实跑 15/44）
		// 时 S7 上下文此前零「后渗透未执行」信号（既往阶段交付物只认 done）：S7-1 影响量化
		// 可能以 S5 证据外推横向影响、S7-2 存量排查「未排查」可能不被如实标注。本块只置顶
		// 在场（呈现性，与 s8.md v5.3.7 报告侧范围标注同源），不新增拦截。
		if s6st := p.StageStates["s6"]; s6st != nil && s6st.Status == "skipped" {
			b.WriteString("> ⏭ **S6 后渗透未执行**（创建时未勾选 post_exploit——用户范围决策，非漏测）：提权/横向/权限维持/云逃逸/存量持久化痕迹排查整段未执行。S7-1《影响评估》必须据此标注影响面边界（后渗透面未验证，不得以 S5 证据外推横向/提权影响）；S7-2《需人工清理清单》如实标注「存量排查未执行（用户范围决策）」；确需补做请在阶段流水线手动重跑 s6 后重跑本阶段。\n\n")
		}
		// v6.8.0（S7-③）：S5 上传落点兜底（s5UploadRegistry 与 s6 块同源双轨）——S5-⑩ 指针
		// 此前只注入 s6 上下文（scoping 在 if stageID=="s6" 内），S7 拿不到；s6-skipped
		//（实跑 15/44）或 S6 未复记四元组行时，这里是 S7-2 清理对账唯一结构化数据入口。
		// persistRows 为空注入指针+≤5 行样本（@目标 标签），非空只出指针行防重复占上下文。
		uploadFiles, uploadSamples := o.s5UploadRegistry(p)
		if names, derr := o.exec.ListDir(p.ID, "deliverables"); derr == nil {
			var catMatrix, catLateral, catData, catLegacy, catOther, persistRows, legacyHandover []string
			for _, rel := range names {
				base := filepath.Base(rel)
				if !strings.HasPrefix(base, "s6-") || !strings.HasSuffix(base, ".md") {
					continue
				}
				switch {
				case strings.Contains(base, "权限矩阵"):
					catMatrix = append(catMatrix, rel)
				case strings.Contains(base, "横向路径图"):
					catLateral = append(catLateral, rel)
				case strings.Contains(base, "数据访问"):
					catData = append(catData, rel)
				case strings.Contains(base, "存量") || strings.Contains(base, "持久化痕迹"):
					catLegacy = append(catLegacy, rel)
				default:
					catOther = append(catOther, rel)
				}
				raw, rerr := o.exec.ReadFile(p.ID, rel)
				if rerr != nil {
					continue
				}
				isLegacy := strings.Contains(base, "存量") || strings.Contains(base, "持久化痕迹")
				for _, ln := range strings.Split(raw, "\n") {
					ln = strings.TrimSpace(ln)
					if ln == "" {
						continue
					}
					// 四元组登记行（含位置+指纹特征）直接在场，S7-2 逐项对账免翻文件
					if (strings.Contains(ln, "位置") || strings.Contains(ln, "路径")) && strings.Contains(ln, "指纹") {
						persistRows = append(persistRows, "- "+tagHandoverTarget("[S6 持久化登记] "+ln, hoTargets))
						if len(persistRows) >= 10 {
							break
						}
					}
					// 存量排查的移交语义行（第三方后门/需人工清理）单独摘要
					if isLegacy && (strings.Contains(ln, "第三方") || strings.Contains(ln, "需人工清理") || strings.Contains(ln, "移交")) {
						legacyHandover = append(legacyHandover, "- "+tagHandoverTarget("[S6 存量移交] "+ln, hoTargets))
						if len(legacyHandover) >= 10 {
							break
						}
					}
				}
				if len(persistRows) >= 10 && len(legacyHandover) >= 10 {
					break
				}
			}
			var ptr []string
			if len(catMatrix) > 0 {
				ptr = append(ptr, "- [权限矩阵] "+strings.Join(catMatrix, "、"))
			}
			if len(catLateral) > 0 {
				ptr = append(ptr, "- [横向路径图] "+strings.Join(catLateral, "、"))
			}
			if len(catData) > 0 {
				ptr = append(ptr, "- [数据访问证明] "+strings.Join(catData, "、"))
			}
			if len(catLegacy) > 0 {
				ptr = append(ptr, "- [存量持久化痕迹排查] "+strings.Join(catLegacy, "、"))
			}
			if len(catOther) > 0 {
				ptr = append(ptr, "- [其他 s6 交付物] "+strings.Join(catOther, "、"))
			}
			hasS6Content := len(ptr) > 0 || len(persistRows) > 0 || len(legacyHandover) > 0
			if hasS6Content || len(uploadFiles) > 0 {
				if hasS6Content {
					b.WriteString("### S6 移交项（S7 开工承接 v6.7.0：①对照本块逐项核对《上传文件记录清单》与《持久化记录》四元组完整，缺登记补登记 ②逐项并入《需人工清理清单》③只读复核驻留在位——S7-2 三件事的数据入口，本块只置顶在场）\n")
				} else {
					b.WriteString("### S6 移交项（本项目无 s6 交付物——s6 skipped 或未产出登记；S7-2 数据入口为下方 S5 上传落点兜底，v6.8.0 S7-③）\n")
				}
				for _, ln := range ptr {
					b.WriteString(ln + "\n")
				}
				for i, ln := range persistRows {
					if i >= 10 {
						b.WriteString("- ...（持久化登记行超 10 条截断，read_file 查更多）\n")
						break
					}
					b.WriteString(ln + "\n")
				}
				for i, ln := range legacyHandover {
					if i >= 10 {
						b.WriteString("- ...（存量移交项超 10 条截断，read_file 查更多）\n")
						break
					}
					b.WriteString(ln + "\n")
				}
				// v6.8.0（S7-③）：S5 上传落点兜底小节——persistRows 非空（S6 已复记）时只出
				// 指针行；为空时注入 ≤5 行四元组样本（@目标 标签），s6-skipped 项目唯一入口。
				if len(uploadFiles) > 0 {
					ln := "- [S5 上传落点] 落点四元组（位置/指纹/建议清理命令/验证命令）记录于 " + strings.Join(uploadFiles, "、") + "——S7-2 逐项对账（缺登记补登记），不执行任何删除/还原"
					if len(persistRows) == 0 && len(uploadSamples) > 0 {
						ln += "；登记行样本（≤5）：\n"
						for i, s := range uploadSamples {
							if i >= 5 {
								break
							}
							ln += "- " + tagHandoverTarget("[S5 上传落点样本] "+s, hoTargets) + "\n"
						}
					}
					b.WriteString(ln)
				}
				b.WriteString("\n")
			}
		}
	}
	// v6.8.0（S7-⑤）：S7「就绪移交清点」小节——V3 就绪条目（s4/s5/三专项 StageState）
	// 此前可见性止于 S5/S6 上下文块，非 VT 化条目在 S7 既无在场也无门（A2 门只覆盖 VT 化
	// 部分，V3Ready 非条目到不了清点出口）——「显式移交」止步 S6 即成无底洞（大项目实跑
	// 某历史任务 逐条处置 R-1..R-8/AP-1..AP-5 是模型纪律不是引擎保证）。本节把全阶段
	// V3 两清单逐行置顶（呈现性注入不新增拦截，清点拦截仍由 A2/V4 门承担），S7 清点三选一
	// 有了逐条在场的执行清单。
	if stageID == "s7" {
		hoTargets := splitProjectTargets(p)
		var readyLines []string
		for _, sid := range []string{"s4", "s5", "specA", "specB1", "specB2"} {
			if sts := p.StageStates[sid]; sts != nil {
				for _, it := range sts.V3Ready {
					if strings.TrimSpace(it) != "" {
						readyLines = append(readyLines, "- ["+sid+" 就绪未执行] "+tagHandoverTarget(it, hoTargets)+"（S7 清点三选一：update_vt 执行 / closed-roe 附理由 / deferred 移交三要素）")
					}
				}
				for _, it := range sts.V3L2 {
					if strings.TrimSpace(it) != "" {
						readyLines = append(readyLines, "- ["+sid+" 已批未用] "+tagHandoverTarget(it, hoTargets)+"（S7 清点：投递使用或申报放弃理由）")
					}
				}
			}
		}
		if len(readyLines) > 0 {
			b.WriteString("### 就绪移交清点（v6.8.0 S7-⑤：全阶段 V3 两清单逐条在场——S7 清点三选一口径，本节只置顶在场不新增拦截）\n")
			for i, ln := range readyLines {
				if i >= 15 {
					b.WriteString(fmt.Sprintf("- ...（共 %d 条截断，search_memory 查更多）\n", len(readyLines)))
					break
				}
				b.WriteString(ln + "\n")
			}
			b.WriteString("\n")
		}
	}
	// v6.6.0（SP-⑦）：specA「S4 AI 面移交」定向注入块——S5 有「S4 移交项」块、S6 有「S5 移交项」块，
	// specA 此前依赖通用通道（findings 前 30 条 + 资产前 60 条），AI 密集项目可能被截断挤出；
	// AI:specA 契约（S3 判定表 AI 行 + S4-5 逐项排查登记）的消费端是 specA 开工。本块只置顶在场
	//（呈现性注入，不新增拦截）：①AI 面发现（vuln_class/title/detail 含 llm/AI/LLM0x）②AI 类资产
	//（含 scope_status——非 in_scope 显式标注「登记≠授权」）③s3 判定表 AI:specA 行指针。
	if stageID == "specA" {
		var aiLines []string
		for _, f := range findings {
			t := strings.ToLower(f.Title + " " + f.Detail)
			if strings.Contains(t, "llm") || strings.Contains(f.Title, "AI") ||
				strings.Contains(f.Title, "LLM0") || strings.Contains(f.Detail, "LLM0") ||
				strings.Contains(f.CWE, "AI") {
				tag := ""
				if f.Access != "" || f.ImpactRank > 0 {
					tag = fmt.Sprintf(" [access=%s rank=%d]", f.Access, f.ImpactRank)
				}
				aiLines = append(aiLines, fmt.Sprintf("- [%s/%s%s] %s", f.Severity, f.Confidence, tag, truncateText(f.Title, 70)))
				if len(aiLines) >= 15 {
					break
				}
			}
		}
		if len(aiLines) > 0 {
			b.WriteString(fmt.Sprintf("### S4 AI 面移交（v6.6.0 SP-⑦：S4-5 已排查登记的 AI 面发现 %d 条——开工先承接复用，不重复面测；深度利用按 A1-A14 口径推进）\n", len(aiLines)))
			for _, ln := range aiLines {
				b.WriteString(ln + "\n")
			}
			b.WriteString("\n")
		}
		var aiAssets []string
		for _, a := range assets {
			t := strings.ToLower(a.Type)
			if strings.Contains(t, "ai") || strings.Contains(t, "llm") || strings.Contains(t, "agent") || strings.Contains(a.Type, "模型") {
				scopeNote := ""
				if a.EffectiveScope() != "in_scope" {
					scopeNote = "——登记≠授权：非 in_scope 资产不得发起主动测试"
				}
				aiAssets = append(aiAssets, fmt.Sprintf("- [%s] %s（%s；scope_status=%s%s）", a.Type, a.Value, a.Stage, a.EffectiveScope(), scopeNote))
				if len(aiAssets) >= 20 {
					break
				}
			}
		}
		if len(aiAssets) > 0 {
			b.WriteString("### AI 类资产（本专项适用面）\n")
			for _, ln := range aiAssets {
				b.WriteString(ln + "\n")
			}
			b.WriteString("\n")
		}
		// s3 判定表 AI:specA 行指针（文件缺失跳过不报错；只过滤行不改内容）
		if names, derr := o.exec.ListDir(p.ID, "deliverables"); derr == nil {
			for _, rel := range names {
				base := filepath.Base(rel)
				if !strings.Contains(base, "判定表") || !strings.HasSuffix(base, ".md") {
					continue
				}
				if raw, rerr := o.exec.ReadFile(p.ID, rel); rerr == nil {
					var rows []string
					for _, ln := range strings.Split(raw, "\n") {
						if strings.Contains(ln, "AI:specA") {
							rows = append(rows, strings.TrimSpace(ln))
							if len(rows) >= 10 {
								break
							}
						}
					}
					if len(rows) > 0 {
						b.WriteString(fmt.Sprintf("### S3 判定表 AI:specA 承接行（%s）\n", base))
						for _, ln := range rows {
							b.WriteString("- " + truncateText(ln, 120) + "\n")
						}
						b.WriteString("\n")
					}
					break // 只取首份判定表
				}
			}
		}
	}
	// v6.3.0（S3-③）：验证队列与候选账本全阶段在场——原实现仅预算剩 1/3 冲刺消息单点注入，
	// S2-10 P1 架构信号 VT 绕过 S3 排期、R7 对抗 VT 滞留 pending 到 S7 才被清点、C28 候选
	// 登记后模型自己看不到账本。open VT 按 Priority 升序（与冲刺消息同口径）。
	if vts, verr := o.store.ListVTs(p.ID); verr == nil && len(vts) > 0 {
		var open []*store.VerificationTask
		for _, t := range vts {
			if t.Status == "pending" || t.Status == "ready" {
				open = append(open, t)
			}
		}
		if len(open) > 0 {
			sort.Slice(open, func(i, j int) bool {
				if open[i].Priority != open[j].Priority {
					return open[i].Priority < open[j].Priority
				}
				return open[i].ID < open[j].ID
			})
			b.WriteString(fmt.Sprintf("### 验证队列（open %d/%d，按 Priority 升序；S3 排期承接 / S4·S5 投递 / S7 清点三选一处置）\n", len(open), len(vts)))
			for i, t := range open {
				if i >= 15 {
					b.WriteString(fmt.Sprintf("- ...（open 共 %d 条，search_memory query=<关键词> 查更多）\n", len(open)))
					break
				}
				b.WriteString(fmt.Sprintf("- %s [%s/P%d] %s（就绪资产: %s）\n", t.ID, t.Status, t.Priority, truncateText(t.Title, 60), truncateText(t.ReadyAssets, 50)))
			}
			b.WriteString("\n")
		}
	}
	// v6.3.0（S3-③）：候选账本 open 项在场——「待评估」线索登记后每轮可见，及时三态归位
	// v7.5.0（C6 strict）：低优先级块，超预算二次渲染时可省略（工作台候选页签可查）
	if !lowPriOff {
		if cands, cerr := o.store.ListCandidates(p.ID); cerr == nil {
			var open []*store.Candidate
			for _, c := range cands {
				if c.Disposition == "" || c.Disposition == "open" {
					open = append(open, c)
				}
			}
			if len(open) > 0 {
				b.WriteString(fmt.Sprintf("### 候选账本（open %d——待评估线索，收口前须 update_candidate 三态归位 finding/vt/excluded）\n", len(open)))
				for i, c := range open {
					if i >= 10 {
						b.WriteString(fmt.Sprintf("- ...（open 共 %d 条）\n", len(open)))
						break
					}
					b.WriteString(fmt.Sprintf("- %s %s（证据: %s）\n", c.ID, truncateText(c.Title, 60), truncateText(c.EvidenceRef, 40)))
				}
				b.WriteString("\n")
			}
		}
	}
	// v6.3.0（S3-⑥）：审批工单状态随上下文在场——兑现 s3.md S3-7「S5 开工确认关键审批已
	// 就绪或已拒」承诺（原实现无任何注入通道，S3 预批工单状态对 S5 不可见，expired 单造成
	// 「按计划已获批」错觉执行）。expired/pending 单显式标注处置路径。
	// v6.7.0（S6-⑦）：s6 纳入——S6 是 L2 审批最密集阶段（提权/横向/持久化），此前看不到
	// pending/expired 工单状态，只能盲发新单或翻时间线（与 s4/s5 同一失效形态）。
	// v6.8.0（S7-⑤）：s7 纳入——S7 负责全项目 L2 清点（V4 比对面）却看不到工单清单，只能靠
	// V4 拦截文案逐单反推；清点需要清单（s7 视角纪律：只清点不再发起新工单）。
	// v7.5.0（C6 strict）：L2 审批工单块为低优先级块（工单状态可经审批页/request_approval
	// 回执查回），超预算二次渲染时省略；治理拦截本身在执行通道照常强制，不受注入省略影响。
	if !lowPriOff && (stageID == "s4" || stageID == "s5" || stageID == "s6" || stageID == "s7") {
		if aps, aerr := o.store.ListApprovals(p.ID); aerr == nil && len(aps) > 0 {
			var l2 []*store.Approval
			for _, a := range aps {
				if a.Risk == "L2" {
					l2 = append(l2, a)
				}
			}
			if len(l2) > 0 {
				sort.Slice(l2, func(i, j int) bool { return l2[i].RequestedAt.After(l2[j].RequestedAt) })
				if stageID == "s7" {
					b.WriteString("### 审批工单状态（L2 近 15 条，新→旧；S7 清点纪律 v6.8.0：本阶段只清点不再发起新工单——approved 未用逐单核对投递/申报放弃理由，pending/expired·rejected 如实写进《待续清单处置》移交，禁止静默省略）\n")
				} else {
					b.WriteString("### 审批工单状态（L2 近 15 条，新→旧；开工逐单核对：approved 按批准范围投递并引用 AP 编号 / pending 催办或改序 / expired·rejected 重新发起 request_approval 或说明替代方案）\n")
				}
				n := 0
				for _, a := range l2 {
					if n >= 15 {
						break
					}
					n++
					decided := ""
					if a.DecidedAt != nil {
						decided = a.DecidedAt.Format("01-02 15:04")
					}
					b.WriteString(fmt.Sprintf("- %s [%s] %s：%s（%s %s）\n", a.ID, a.Status, a.Stage, truncateText(a.Action, 60), truncateText(a.DecidedBy, 20), decided))
				}
				b.WriteString("\n")
			}
		}
	}
	// v3.6.1 并行扇出采纳提示（实测 glm-5.3-flash 对头内"可选"指引采纳率低，
	// 评测两轮 spawn_subagent 零调用；引擎级随上下文注入显著提示）
	if stageID == "s4" || stageID == "s5" {
		b.WriteString("> ⚡ 并行扇出提示：本阶段若剩余 ≥3 个相互独立的测试单元（不同 endpoint×漏洞类/不同指纹；多目标项目按目标×漏洞类分单元——v6.5.0 S5-⑧），用 spawn_subagent 并行派发（objective 写清目标×漏洞类×判据），主头定期 poll_subagents 收结果——这是预算内的提速手段，不是可选项。\n\n")
	} else if stageID == "s2" && len(splitProjectTargets(p)) > 1 {
		// v6.2.0（S2-⑥）：s2 多目标项目同样注入扇出提示——多目标侦察是最典型可并行单元
		// （逐目标存活/端口/指纹探针与 anon-attack-surface 逐族普查相互独立）；v3.6.1 实证
		// 「头内可选指引采纳率低」，引擎级随上下文注入显著提示（与 s4/s5 同款机制）。
		b.WriteString("> ⚡ 并行扇出提示（S2 多目标）：各目标的存活/端口/指纹探针与 anon-attack-surface 逐族普查相互独立——按目标（或目标×探针族）派 spawn_subagent 并行（objective 写清目标×探针族×判据），主头定期 poll_subagents 收结果并并入攻击面地图——这是预算内的提速手段，不是可选项。\n\n")
	} else if stageID == "s6" {
		// v6.7.0（S6-⑦）：s6 扇出提示——多主机横向的天然并行单元（逐主机枚举/逐凭据复放/
		// 逐实例差分）；限速目标不扇出（loop-core「限速优先于速度」纪律不变）。
		b.WriteString("> ⚡ 并行扇出提示（S6 横向）：多主机/多实例场景的逐主机枚举、逐凭据复放、同构实例差分相互独立——按主机（或凭据×主机）派 spawn_subagent 并行（objective 写清目标×判据），主头定期 poll_subagents 收结果并并入《横向路径图》——限速目标不扇出（限速优先于速度），这是预算内的提速手段，不是可选项。\n\n")
	}
	// v4.8 W4 六轨编排提示（引擎编排层）：无凭证且有登录面时注入——逐轨尝试/逐轨 VT 化/命中轨分类处置（v5.1：L1 评估轨+索取闭环）
	// v5.6.0：状态判据从「仅看旧 AuthInfo 字段」升级为 projectHasIdentity（AuthInfo ∪ 凭据仓库 active ∪ verified Loot）——
	// 审计缺陷：store_credential 入库后 W4 仍当 S0 跑六轨，新机制与旧状态机脱节。
	if stageID == "s4" && !o.projectHasIdentity(p) && o.loginSurfacePresent(p) {
		b.WriteString("> 🪪 身份获取编排（v4.8 W4·v5.1 修订）：本项目无凭证——按 identity-bootstrapping 六轨顺序编排（L1 注册面 → L2 泄露面 → L3 默认口令 → L4 验证码逻辑 → L5 令牌伪造 → L6 会话构造），逐轨尝试并 record_vt（title 前缀 [W4-L1]..[W4-L6]，不适用轨也登记并在 start_conditions 注明「无对应面」）；**L1 为评估轨：按 ROE identity.auto_register（默认 deny）只做注册面存在性评估与流程还原，不执行注册、命中不建会话（发现本身 record_finding）**；L2-L6 任一轨取得身份（verified loot 或 store_credential 入库）即 load_skill session-state-chain 建会话；验证码轨走自动打码三级链（v7.6.0 B6 用户决策①：本地 OCR captcha-ocr → 多模态读图兜底 → 行为型滑块/点选走浏览器轨迹模拟）「取码→识别→同会话立即提交」闭环（长驻会话单例，禁止两段式重跑取码），连续 3 次识别失败或风控升级信号即停止尝试按四元组移交——不再回退人工读码；凭据面预言机探针分流（browser_oracle 无验证码面直连 / SimCaptcha 类面走会话）。全部轨未命中（或 L1 被 ROE 关闭且其余轨未命中）时：按 v5.8.0 口径直接六轨 VT 全量登记并按 S4-7 三行报告口径移交（不主动向用户询问身份——有则用、无则默认无；用户中途主动提供凭据时经 request_credential 入库即转带态测试）。\n\n")
	}
	// v5.6.0 凭证状态三态上下文（通用型：所有阶段按 S0/S1/S2 差异化注入，审计④-13）
	b.WriteString(o.credentialStateBlock(p))
	// v6.0.0（用户决策④）治理口径贯通：注入项目实际执行档与范围扩展语义。此前引擎知道
	// p.ExecutionProfile 而上下文从未携带——模型按 loop-core「默认 production_safe」自我设限
	// （实证：两个 isolated_lab 项目全程自称 production_safe、把允许动作标「禁止」、s6 提权 0 次
	// 评估级）。注入后模型行为与引擎门同源；引擎门照旧逐动作强制，本块只是消除信息差，不是放松限制。
	prof := o.profileOf(p)
	var wpNote string
	switch o.effectiveWritePolicy(p) {
	case "full":
		wpNote = "写操作允许（受控；审批与留证照常，收尾快照恢复）"
	case "existence-proof":
		wpNote = "写操作仅做存在性证明（截图/计数/哈希），禁止业务数据修改"
	default:
		wpNote = "未注册部署级写策略 → 写操作按审批矩阵管控（L1/L2 逐项审批留痕；FORBIDDEN 拒绝）"
	}
	switch prof {
	case ProfileIsolatedLab:
		b.WriteString("### 治理口径（引擎实际生效·v6.0.0——模型行为以此为准，勿自我设限）\n")
		b.WriteString("- execution_profile=**isolated_lab**（项目创建时显式声明）→ 本项目允许完整 PoC 链与受控写操作（收尾以快照恢复为准）；仅禁向公网分发测试产物与接触生产数据。loop-core 规则 6 与各头「默认 production_safe」的保守口径在本项目**不适用**——不要把允许的动作标成「禁止」或只做评估级推演。\n")
	default:
		b.WriteString("### 治理口径（引擎实际生效·v6.0.0——模型行为以此为准）\n")
		b.WriteString("- execution_profile=**production_safe** → 生产口径：只做存在性证明（无害回显/随机标记/受控 OOB）；植入/持久化/隧道/新增账号/上传可执行/批量导出/数据修改在全部通道被引擎逐动作确定性拦截。\n")
	}
	b.WriteString(fmt.Sprintf("- write_policy=**%s** → %s（v6.0.0 三层治理参数：部署级 YAML > 执行档派生 > unset 缺省）\n", o.effectiveWritePolicy(p), wpNote))
	switch o.expansionMode(p) {
	case "auto":
		b.WriteString("- expansion=auto → 范围外但立足点已发现的目标：可直接访问，引擎留痕；未发现目标仍拦截\n")
	case "auto-with-approval":
		b.WriteString("- expansion=auto-with-approval → 范围外但立足点已发现的目标：命令被拦时引擎自动生成《授权扩展工单》，批准后自动登记资产放行——**不要**把这类目标直接标记「范围外放弃」，按工单流程推进\n")
	default:
		b.WriteString("- expansion=deny（默认） → 范围外目标只记录不访问（三态处置登记移交）\n")
	}
	b.WriteString("\n")
	// v4.6 T3/H：ROE Profile 运行时含义注入（治理参数化）
	if o.roe != nil {
		b.WriteString("### ROE Profile（运行时治理参数，v4.6 §3——引擎已加载的许可口径）\n")
		b.WriteString(o.roe.Digest() + "\n\n")
	} else {
		// v6.0.0：未配置部署级 YAML——write_policy/expansion 已在上方治理口径块按执行档派生注入
		// （v5.1.3 修复⑥的 write_policy 行上移）；此处仅补 identity.auto_register 平台默认与数据边界。
		b.WriteString("### ROE 运行时默认（未配置部署级 YAML Profile）\n")
		b.WriteString("- identity.auto_register=deny（平台默认） → 注册面只评估不注册（v5.8.0：不主动向用户询问身份——有则用、无则默认无）\n")
		b.WriteString("- 数据边界 → 生产数据只做存在性证明；自建数据一律只登记移交、不执行删除（v5.1.3 用户政策）\n\n")
	}
	// v3.4.0 组织级教训（跨项目脱敏）——避免重蹈覆辙的第一道注入点
	// v4.6 E5/K2/K5-lite 升级：①单次实验/无样本强度的教训标注 provisional；
	// ②黑板 behavior.<目标> 分型命中的行为类教训优先注入；③阶段间空闲 >30min 提醒通道基线自检。
	// v6.1.0（S1 修复方案⑮）：行为类按目标读取——黑板键 behavior.<目标> 本就有目标维度，
	// 旧实现遍历取「最后一个 confirmed」全局单值，多目标混合行为类时 A 目标吃到 B 目标的
	// 教训（诱导错选工具/通道）。单目标语义不变；多目标逐目标注入（guard.lesson_behavior_per_target）。
	behaviorByTarget := map[string]string{}
	factsList, _ := o.store.ListFacts(p.ID, 50)
	for _, fct := range factsList {
		if strings.HasPrefix(fct.Key, "behavior.") && fct.Confidence == "confirmed" {
			tk := canonicalTargetKey(strings.TrimPrefix(fct.Key, "behavior."))
			if tk != "" {
				behaviorByTarget[tk] = fct.Value
			}
		}
	}
	behaviorClass := ""
	if len(behaviorByTarget) == 1 {
		for _, v := range behaviorByTarget {
			behaviorClass = v // 单目标：等价旧行为
		}
	} else if len(behaviorByTarget) == 0 {
		// 兼容旧数据：键可能不带目标形态（如 behavior.global）——回退最后一个 confirmed
		for _, fct := range factsList {
			if strings.HasPrefix(fct.Key, "behavior.") && fct.Confidence == "confirmed" {
				behaviorClass = fct.Value
			}
		}
	}
	perTargetLessons := o.guardEnabled(func(g *config.GuardConfig) *bool { return g.LessonBehaviorPerTarget }) && len(splitProjectTargets(p)) > 1 && len(behaviorByTarget) > 0
	// v7.5.0（C6 strict）：教训块为低优先级块（search_memory 跨项目可检索），超预算二次渲染时省略
	if lessonsAll, lerr := o.store.ListLessons(0); !lowPriOff && lerr == nil && len(lessonsAll) > 0 {
		// v6.0.6 A+B（P0 修复）：全库打分选取——原 ListLessons(8) 先按时间截断再打分，
		// 指纹只对窗口内 8 条生效，窗口外教训永久不可达（实证：LS-4DD9BCB0E6 排 31/406
		// 被截 → 9427 漏测 exportIOS 中危）。现改为：全库打分 → 命中优先（相关性排序）
		// → 最近补齐（保底 ≥2 条）——窗口外的方法论/栈教训可被 facts 指纹召回。
		// 指纹池：confirmed facts 值 + behaviorClass（教训打分输入，保留原 v5.3.9 设计）
		fpParts := []string{}
		// v6.1.0（方案⑮）：共享指纹池排除 behavior.* 值（其他目标的行为类不得为当前目标
		// 的一般指纹——否则 A/B 两类教训都会在每段命中）；当前目标行为类在 renderLessons 内追加。
		if fpFacts, ferr := o.store.ListFacts(p.ID, 50); ferr == nil {
			for _, fct := range fpFacts {
				if fct.Confidence == "confirmed" && strings.TrimSpace(fct.Value) != "" && !strings.HasPrefix(fct.Key, "behavior.") {
					fpParts = append(fpParts, strings.ToLower(fct.Value))
				}
			}
		}
		if behaviorClass != "" {
			fpParts = append(fpParts, strings.ToLower(behaviorClass))
		}
		fpJoined := strings.Join(fpParts, "\x00")
		renderLessons := func(header string, class string, limit int) {
			clsFp := fpJoined
			if class != "" && perTargetLessons {
				clsFp = fpJoined + "\x00" + strings.ToLower(class)
			}
			// v6.1.0（方案⑮）：逐目标段输入过滤——其他目标专属行为类（BehaviorClass 非空且
			// ≠当前类）的教训不得经「最近保底」漏进本段（A 段标题下出现 B 的教训=误导选型）；
			// 无行为类的通用教训可正常保底共享。
			pool := lessonsAll
			if perTargetLessons && class != "" {
				pool = []*store.LessonRecord{}
				for _, l := range lessonsAll {
					if strings.TrimSpace(l.BehaviorClass) != "" && l.BehaviorClass != class {
						continue
					}
					pool = append(pool, l)
				}
			}
			selected, totalLessons, hitCount := selectLessonsForContext(pool, clsFp, class, limit)
			b.WriteString(fmt.Sprintf("%s（库共 %d 条，注入 %d 条，指纹/行为命中 %d 条——检索更多：search_memory query=<关键词>）\n", header, totalLessons, len(selected), hitCount))
			for _, sl := range selected {
				text := sl.lesson.Text
				if class != "" && sl.lesson.BehaviorClass == class {
					text = fmt.Sprintf("【行为类命中 %s】", class) + text
				}
				if sl.score > 0 {
					// v6.0.6 A：命中标注覆盖全部命中来源（原实现只标 Stack 命中——Tags/行为类
					// 命中的教训不计数也不标注，口径不一致，codex 审计 §1 修正项）
					tag := sl.lesson.Stack
					if tag == "" {
						tag = sl.lesson.Tags
					}
					if tag != "" {
						text = fmt.Sprintf("【相关字段命中 %s】", truncateText(tag, 40)) + text
					}
				}
				if note := lessonEvidenceNote(sl.lesson); note != "" {
					text += note
				}
				b.WriteString("- " + text + "\n")
			}
			if hitCount == 0 && class != "" {
				b.WriteString("- 本目标指纹/行为类无命中教训，按对应 playbook 谨慎推进\n")
			}
			b.WriteString("\n")
		}
		if perTargetLessons {
			// v6.1.0（方案⑮）：多目标逐目标注入（总条数封顶防 token 膨胀——每目标 ≤3 条，
			// 命中行为类教训优先；找不到目标行为类不伪造默认值）
			const perTargetCap = 3
			for _, t := range splitProjectTargets(p) {
				cls := behaviorByTarget[canonicalTargetKey(t)]
				if cls == "" {
					b.WriteString(fmt.Sprintf("### 组织级教训 · 目标 %s（行为类未分型——S1 承接时先 upsert_fact behavior.<目标>）\n", t))
					b.WriteString("- 该目标暂无分型——不伪造默认行为类；命中教训见全局段\n\n")
					continue
				}
				renderLessons(fmt.Sprintf("### 组织级教训 · 目标 %s（行为类 %s）", t, cls), cls, perTargetCap)
			}
		} else if !perTargetLessons || len(behaviorByTarget) <= 1 {
			cls := behaviorClass
			renderLessons("### 组织级教训（跨项目脱敏经验）", cls, 8)
		}
	} // v6.1.0（方案⑮）：结束 if lessonsAll 块（renderLessons 闭包化重构）
	// v6.7.0（S6-⑦）：K5 心跳产物在场块 + 原语图指针块（s6 专属）——s6.md「通道状态按 K5
	// 心跳产物判定」「原语图缺口项按 impact 顺序消耗」此前零引擎引用（不读/不注入/不设门），
	// 两份文件淹没在工作区文件 200 字摘要里；S5 忘排心跳则 s6 永远无从感知。本块只置顶在场
	//（呈现性注入）：心跳产物存在 → 状态摘要注入；缺失且跨阶段空闲超限 → 显式缺失提示
	//（与下方 K5-lite 时间维度提醒互补：一个管文件维度、一个管时间维度）。
	if stageID == "s6" {
		if raw, rerr := o.exec.ReadFile(p.ID, "evidence/channel-status.json"); rerr == nil && strings.TrimSpace(raw) != "" {
			b.WriteString(fmt.Sprintf("> 📡 K5 通道心跳产物（evidence/channel-status.json，S5 预排）：%s——横向前按此判定通道状态，异常先做基线自检。\n\n", truncateText(strings.ReplaceAll(strings.TrimSpace(raw), "\n", " "), 300)))
		} else if maxEnd := o.lastStageEnd(p); maxEnd != nil && time.Since(*maxEnd) > 30*time.Minute {
			b.WriteString("> 📡 K5 心跳产物缺失（evidence/channel-status.json 不存在——S5 未预排心跳）且距上一阶段收口已空闲较久：横向前先做通道基线自检（登录页 dump-dom 字节数 / channel-snapshot 重放），再开始横向动作。\n\n")
		}
		if pcRaw, pcErr := o.exec.ReadFile(p.ID, "deliverables/primitive-chains.md"); pcErr == nil && strings.TrimSpace(pcRaw) != "" {
			gapLines := 0
			for _, ln := range strings.Split(pcRaw, "\n") {
				if strings.Contains(ln, "缺口") {
					gapLines++
				}
			}
			b.WriteString(fmt.Sprintf("> 🧩 原语图缺口（deliverables/primitive-chains.md，S5 收口产物，缺口行 %d 处）：%s——按 impact 顺序消耗缺口项（record_vt 登记 / 本阶段凑链），正向扩展与反向回推缺口见文件全文。\n\n", gapLines, truncateText(strings.ReplaceAll(strings.TrimSpace(pcRaw), "\n", " "), 300)))
		}
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
	// v7.5.0（C6 strict）：时间线为低优先级块（时间线页/search_memory 可查），超预算省略
	if !lowPriOff && len(timeline) > 0 {
		b.WriteString("### 最近时间线\n")
		start := 0
		if len(timeline) > 15 {
			start = len(timeline) - 15
		}
		for _, t := range timeline[start:] {
			b.WriteString(fmt.Sprintf("- %s %s: %s\n", t.CreatedAt.Format("15:04:05"), t.Event, t.Detail))
		}
	}
	// v6.8.0（S7-④）：S7→S8 结构化移交块——四条接缝（S4→S5/S5→S6/S6→S7）均有注入块，
	// S7→S8 是最后补齐的一条：S7 五件交付物此前只经 200 字工作区摘要到达 S8，而 s8 有
	// 「禁止逐个通读历史交付物」效率纪律，清理移交与待续处置恰是报告附录/存量风险/盲区章
	// 的承重输入。本块只置顶在场（呈现性注入，不新增拦截）：①五件交付物指针+报告承接落点
	// 标注 ②needs_follow_up 处置统计（与 S7-① strict pool 同口径）③VT/L2 清点结果
	//（非 0 显式标注「S7 未清完」，与 A2/V4/G3 三门共同构成残缺双层暴露）。
	if stageID == "s8" {
		var s7ptr []string
		if names, derr := o.exec.ListDir(p.ID, "deliverables"); derr == nil {
			for _, rel := range names {
				base := filepath.Base(rel)
				if !strings.HasPrefix(base, "s7-") || !strings.HasSuffix(base, ".md") {
					continue
				}
				switch {
				case strings.Contains(base, "影响评估"):
					s7ptr = append(s7ptr, "- [影响评估] "+rel+"（→报告执行摘要/测试范围章素材）")
				case strings.Contains(base, "清理确认"):
					s7ptr = append(s7ptr, "- [清理确认清单] "+rel+"（→测试范围与方法：收尾口径与审批矩阵执行情况）")
				case strings.Contains(base, "需人工清理"):
					s7ptr = append(s7ptr, "- [需人工清理清单] "+rel+"（→移交附件说明：四元组移交人工执行，智能体不执行清理）")
				case strings.Contains(base, "攻击时间线"):
					s7ptr = append(s7ptr, "- [完整攻击时间线] "+rel+"（→报告附录）")
				case strings.Contains(base, "待续清单处置"):
					s7ptr = append(s7ptr, "- [待续清单处置] "+rel+"（→清单外发现与盲区章：逐项三选一处置结论）")
				default:
					s7ptr = append(s7ptr, "- [其他 s7 交付物] "+rel)
				}
			}
		}
		var stats []string
		if cov, cerr := o.store.ListCoverage(p.ID); cerr == nil {
			totalNF, doneNF := 0, 0
			poolText := normCovText(o.s7DispositionCorpus(p))
			for _, c := range cov {
				if c.Status != "needs_follow_up" {
					continue
				}
				totalNF++
				if dispositionTokenMatched(c, poolText) {
					doneNF++
				}
			}
			if totalNF > 0 {
				stats = append(stats, fmt.Sprintf("- needs_follow_up 处置统计：%d/%d 已留痕（口径与 S7 G3 门一致）", doneNF, totalNF))
			}
		}
		if vts, verr := o.store.ListVTs(p.ID); verr == nil {
			open := 0
			for _, t := range vts {
				if t.Status == "pending" || t.Status == "ready" {
					open++
				}
			}
			if open > 0 {
				stats = append(stats, fmt.Sprintf("- ⚠ VT 清点：%d 个验证任务仍为开放状态——S7 未清完，报告须如实呈现不得静默省略", open))
			}
		}
		if n := o.countUnusedApprovedL2(p); n > 0 {
			stats = append(stats, fmt.Sprintf("- ⚠ L2 清点：%d 个已批准工单无使用痕迹且未申报——S7 未清完，报告须如实呈现不得静默省略", n))
		}
		if len(s7ptr) > 0 || len(stats) > 0 {
			b.WriteString("\n### S7 收口移交（S8 开工承接 v6.8.0 S7-④：报告承接落点逐件标注 + 收口清点统计——本块只置顶在场，不新增拦截）\n")
			for _, ln := range s7ptr {
				b.WriteString(ln + "\n")
			}
			for _, ln := range stats {
				b.WriteString(ln + "\n")
			}
			b.WriteString("\n")
		}
		// v6.9.0（S8-⑥）：分组交付物承接清单（呈现性注入，不新增拦截）——s8.md「任一分组文件的
		// 已验证漏洞未进报告即交付缺项」此前零观测面：上游四道逐目标门（s4/s5/s6/spec
		// targetCoverageRecon）保证分组文件存在，「存在→已合并」这段靠模型自觉。本块列出全部
		// s4-/s5-/s6-/spec*- 前缀交付物（存在才列）供收口前逐行核对；仅多目标项目注入（单目标
		// 零占位——顺带消除「read 不存在的 s4-<目标>.md」空转指令）。拦截由反思门 S8 问句 d 承担。
		if len(targets) > 1 {
			var groupLines []string
			if names, derr := o.exec.ListDir(p.ID, "deliverables"); derr == nil {
				for _, rel := range names {
					base := filepath.Base(rel)
					if !strings.HasSuffix(base, ".md") {
						continue
					}
					for _, pf := range []string{"s4-", "s5-", "s6-", "specA-", "specB1-", "specB2-"} {
						if strings.HasPrefix(base, pf) {
							groupLines = append(groupLines, fmt.Sprintf("- %s（→ 已并入报告章节：<收口前逐行核对填写；未并入的在盲区章说明原因）", rel))
							break
						}
					}
				}
			}
			if len(groupLines) > 0 {
				// v6.9.0 第五轮核对：截断上限 60（与 deliverablesText 60 文件上限同口径）——超大
				// 目标数项目（实证库 99 目标）s4-/s5-/s6- 分组文件可达数百个，无上限会把 s8 上下文
				// 撑爆；显式截断标注剩余数量（不向模型撒谎），全量按覆盖矩阵/search_memory 核对。
				const groupCap = 60
				b.WriteString("\n### 分组交付物承接（v6.9.0 S8-⑥：多目标按目标组织——收口前逐行核对每个文件的已验证漏洞已进《发现详情》，漏一组即交付缺项）\n")
				for i, ln := range groupLines {
					if i >= groupCap {
						b.WriteString(fmt.Sprintf("- …（其余 %d 个分组文件截断——按目标分组逐组核对，覆盖矩阵与 search_memory 可查全量）\n", len(groupLines)-groupCap))
						break
					}
					b.WriteString(ln + "\n")
				}
				b.WriteString("\n")
			}
		}
		// v6.9.0（S8-⑦）第三轮核对补齐：关键数字与覆盖边界块——s8.md「关键数字表禁止手写」承诺
		// 的模型侧数据通道（模型不能调 HTTP API，key_figures/覆盖边界初稿此前只对 reconciliation
		// API 可达）。统计与 API 共用 keyFigures 零漂移；《覆盖边界》初稿同块在场——C29 门拦截文案
		// 「可从 API 取初稿」的通道缺口一并闭合。呈现性注入不新增拦截。
		if kf := o.keyFigures(p.ID); len(kf) > 0 {
			b.WriteString("\n### 关键数字与覆盖边界（v6.9.0 S8-⑦：引擎统计待人工确认——报告关键数字从此誊写，禁止手写；引擎未覆盖的维度人工补充）\n")
			b.WriteString(fmt.Sprintf("- 端点数（去重）: %d\n- 覆盖矩阵单元数: %d\n- 发现数: %d\n- 证据文件数: %d\n- 时间线事件数: %d\n- 资产数: %d\n",
				kf["endpoints"], kf["coverage_units"], kf["findings"], kf["evidence_files"], kf["timeline_events"], kf["assets"]))
			// v6.9.0 第六轮核对：分布按键排序渲染（Go map 遍历序不稳定——稳定输出利于报告
			// 誊写一致性与审计 diff；API 侧仍为 map 由 JSON 消费方自行处理）。
			if dist, ok := kf["findings_dist"].(map[string]int); ok && len(dist) > 0 {
				keys := make([]string, 0, len(dist))
				for k := range dist {
					keys = append(keys, k)
				}
				sort.Strings(keys)
				parts := make([]string, 0, len(keys))
				for _, k := range keys {
					parts = append(parts, fmt.Sprintf("%s×%d", k, dist[k]))
				}
				b.WriteString(fmt.Sprintf("- 发现分布（等级/置信度）: %s\n", strings.Join(parts, ", ")))
			}
			if draft := o.coverageBoundaryDraft(p); strings.TrimSpace(draft) != "" {
				b.WriteString("\n《覆盖边界》初稿（直接取材，逐条人工核对后补「解锁条件/来源」）:\n" + draft + "\n")
			}
			b.WriteString("\n")
		}
		// v7.1.0（S8 复盘章）：自主决策复盘素材——引擎统计（账本同源禁手写），报告固定章节
		//《自主决策复盘》从此誊写；本块只在 s8 注入（呈现性，不新增拦截）。
		if stageID == "s8" {
			if retro := o.autonomyRetrospective(p.ID); strings.TrimSpace(retro) != "" {
				b.WriteString("\n### 自主决策复盘（v7.1.0：引擎统计——报告《自主决策复盘》章从此誊写，禁止手写）\n" + retro + "\n")
			}
		}
		// v6.9.0（S8-⑤）：发现逐目标归属登记率（一行呈现）——报告按目标组织章节与反向对账
		// 分组（S8-③）的结构化事实源覆盖度；未登记条目收口前用 update_finding target_ref 补登，
		// 反向对账对未登记条目回退标题词边界匹配（与 v6.8.0 行为一致）。
		if fs, ferr := o.store.ListFindings(p.ID); ferr == nil && len(fs) > 0 {
			owned := 0
			for _, f := range fs {
				if strings.TrimSpace(f.TargetRef) != "" {
					owned++
				}
			}
			b.WriteString(fmt.Sprintf("\n### 发现逐目标归属（v6.9.0 S8-⑤）：已登记 %d/%d 条 target_ref——报告按目标组织时以此为分组事实源；未登记条目收口前 update_finding 补登\n", owned, len(fs)))
		}
	}
	// 既往阶段交付物
	// v6.8.1：摘要行纳入 skipped 阶段——s6 被 applyPostExploitGate 跳过（用户范围决策）时，
	// 其「后渗透未勾选…整段跳过」摘要此前对下游完全不可见（循环只认 done）：S7 无从知晓
	// 存量排查/横向未执行、s8.md v5.3.7「后渗透范围标注」规则无机械依据（实证：44 项目中
	// 15 个 s6-skipped，S7 上下文零 skipped 信号）。skipped 行原样携带范围决策摘要，
	// S7-1 影响评估据此标注边界、S8 报告据此执行范围标注规则。
	if p.StageStates != nil {
		b.WriteString("\n### 既往阶段交付物\n")
		sumCap := o.cfg.Engine.PackSummaryCap // v7.5.0（C3）：Summary 设顶（默认 800 字符保骨架）
		for _, id := range Pipeline(o.heads, p.Specializations) {
			if st, ok := p.StageStates[id]; ok && (st.Status == "done" || st.Status == "skipped") && id != stageID {
				sum := st.Summary
				if sumCap > 0 && len([]rune(sum)) > sumCap {
					// 完整摘要在该阶段交付物文件内（工作区清单/文件承接可取），包内只保骨架
					sum = truncateRunes(sum, sumCap) + "…（已截断，read_file 该阶段交付物可取完整摘要）"
				}
				b.WriteString(fmt.Sprintf("- [%s] %s\n", id, sum))
			}
		}
	}
	// 覆盖度摘要（移植自 strix/PentesterFlow：回答“测过什么、还没测什么”）
	// v7.3.0 C3/C4：PoC 就绪行与横向决策图注入——依赖 findings/交付物而非覆盖矩阵，
	// 置于覆盖守卫之外（无覆盖单元的项目同样可见）
	if stageID == "s5" {
		if line := o.pocReadyLine(p); line != "" {
			b.WriteString(line + "\n")
		}
	}
	if stageID == "s6" {
		// v7.3.0 核对修复（审计 L）：按需生成——旧序文件只在结项存在，注入恒为空
		o.ensureAttackGraph(p, false)
		if g, gerr := o.exec.ReadFile(p.ID, "deliverables/attack-graph.md"); gerr == nil && strings.TrimSpace(g) != "" {
			b.WriteString("\n### 横向决策图（v7.3.0 C4：attack-path-stitcher 产物，图上做路径规划）\n")
			b.WriteString(headTail(g, 1600, 400) + "\n")
			b.WriteString("（消费纪律：每条候选边经 propose(kind=lateral_edge) 提议-裁决后执行；凭据/信任复用边优先查战利品库与黑板 fact 支撑；拓扑向量未覆盖面三态处置。）\n")
		}
		if line := o.pocReadyLine(p); line != "" {
			b.WriteString(line + "\n")
		}
	}

	// v7.3.0 核对修复（审计 P-1）：planDelta 注入移出覆盖守卫——依赖 cards/StageState 而非覆盖矩阵
	// v7.2.0 B3 planDelta：新面承接卡注入（S4 逐类对账表须扩展行）
	if stageID == "s4" {
		if cards, err := o.store.ListCards(p.ID); err == nil {
			var pd []string
			for _, c := range cards {
				if c.Outcome == "plan_delta" && c.State == "queued" {
					pd = append(pd, c.Target+"（依据："+c.Evidence+"）")
				}
			}
			if len(pd) > 0 {
				b.WriteString(fmt.Sprintf("\n**planDelta 新面承接（v7.2.0 B3，计划版本 v%d）**：以下资产在测试中转 in_scope，已自动建卡——逐类对账表扩展该行并按最小探针层纳入轮转：\n", p.StageStates["s4"].PlanVersion))
				for _, t := range pd {
					b.WriteString("- " + t + "\n")
				}
			}
		}
	}

	if cov, _ := o.store.ListCoverage(p.ID); len(cov) > 0 {
		statCount := map[string]int{}
		for _, c := range cov {
			statCount[c.Status]++
		}
		b.WriteString(fmt.Sprintf("\n### 覆盖度矩阵（共 %d 单元）\n", len(cov)))
		// v7.2.0 B4 预算账本：s4/s5 注入目标×类×深度占用一行式（防单点黑洞可视，P4-lite）
		if stageID == "s4" || stageID == "s5" {
			if line := budgetLedgerLine(cov); line != "" {
				b.WriteString(line + "\n")
			}
		}
		for _, st := range []string{"vulnerable", "no_issue_found", "ruled_out", "waf_blocked", "needs_follow_up", "skipped"} {
			if statCount[st] > 0 {
				b.WriteString(fmt.Sprintf("- %s: %d\n", st, statCount[st]))
			}
		}
		// 明细：vulnerable/needs_follow_up 是收口与重跑最需要的事实来源（防阶段重跑重复劳动/丢结论）
		// v7.5.0（C3）：明细条数设顶（默认 30）——多目标大项目曾无上限全量注入（包体 100KB 级）；
		// 完整矩阵在覆盖度页/coverage.json 与 search_memory 可查，此处保优先级最高的前 N 条。
		if statCount["vulnerable"] > 0 || statCount["needs_follow_up"] > 0 {
			b.WriteString("\n#### 关键覆盖明细\n")
			covCap := o.cfg.Engine.PackCoverageCap
			if covCap <= 0 {
				covCap = 30
			}
			n := 0
			for _, c := range cov {
				if c.Status == "vulnerable" || c.Status == "needs_follow_up" {
					if n >= covCap {
						break
					}
					line := fmt.Sprintf("- [%s] %s × %s × %s", c.Status, c.Endpoint, c.VulnClass, c.Param)
					if strings.TrimSpace(c.Notes) != "" {
						line += "（" + firstLine(c.Notes) + "）"
					}
					b.WriteString(line + "\n")
					n++
				}
			}
			if statCount["vulnerable"]+statCount["needs_follow_up"] > n {
				b.WriteString(fmt.Sprintf("- …（其余 %d 条明细见覆盖度页与 coverage.json，本注入设顶 %d 条）\n", statCount["vulnerable"]+statCount["needs_follow_up"]-n, covCap))
			}
		}
		b.WriteString("（测试前先用 search_memory/覆盖矩阵决定下一步，避免重复打同一单元）\n")
	}
	// 子任务树（PentAGI 双层任务模型移植：让阶段头始终看到计划与进度）
	// v7.5.0（C3）：条数设顶（默认 25）——完整计划在工作台子任务页/plan_subtasks 可查。
	if subs, _ := o.store.ListSubtasks(p.ID); len(subs) > 0 {
		b.WriteString("\n### 当前子任务计划（用 plan_subtasks 重建 / update_subtask 同步进度）\n")
		subCap := o.cfg.Engine.PackSubtaskCap
		if subCap <= 0 {
			subCap = 25
		}
		for i, st := range subs {
			if i >= subCap {
				b.WriteString(fmt.Sprintf("- …（其余 %d 项见工作台子任务页，本注入设顶 %d 条）\n", len(subs)-subCap, subCap))
				break
			}
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
	// v7.5.0（C1）：分阶注入——默认 full（全量索引，现行口径）；staged 模式只注入阶段相关
	// ≤30 行 + 核心路由技能恒在，低置信度自动回退全量（须过 eval 盲挖回归后开启）。
	b.WriteString("\n### 技能库索引（load_skill 按需载入）\n")
	b.WriteString(o.skillIndexFor(stageID))
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
		{Name: "poll_async", Description: "查询后台任务：返回 running/finished/killed、退出码、log_bytes 实时日志字节数与输出尾部。仍在运行时继续其他工作，不要同步等待。killed/零产出时必须按提示 record_vt 留痕（C31 收口对账）。", Parameters: obj(map[string]any{
			"job": str("run_async/run_batch 返回的 job id"),
		}, "job")},
		{Name: "run_batch", Description: "批量任务逐目标隔离：command 为含 {{TARGET}} 占位符的模板，targets 每行一个目标；引擎拆成逐目标独立进程组/超时/日志（单目标失败/超时不影响其余），一次审批覆盖本批（模板与逐目标实例风险一致性校验，升级即拒整批）。多主机 nuclei/httpx/ffuf 类扫描与同构批量利用/验证（同一 PoC/探针/受控提取跨目标投递）必须用本工具而非逐目标单进程循环——防单个挂起主机拖死整批与轮次按目标数线性折损。零产出/killed 须 record_vt 留痕。", Parameters: obj(map[string]any{
			"command": str("含 {{TARGET}} 占位符的命令模板（引擎逐目标替换并单引号安全引用）"),
			"targets": str("目标清单，换行分隔（单批上限 100）"),
			"timeout": str("每目标超时秒数，可空（默认同 run_async）"),
			"reason":  str("执行原因（展示给审批人）"),
		}, "command", "targets")},
		{Name: "write_file", Description: "在项目工作区写入文件（PoC 脚本、笔记、报告等）。", Parameters: obj(map[string]any{
			"path": str("相对工作区路径"), "content": str("文件内容"),
		}, "path", "content")},
		{Name: "read_file", Description: "读取项目工作区文件；>16KB 大文件自动溢出落盘并回头尾+指针——用 offset/limit 分段读或 grep 溢出文件取片段（完整内容一字不丢）。", Parameters: obj(map[string]any{
			"path":   str("相对工作区路径"),
			"offset": map[string]any{"type": "integer", "description": "起始行号（1-based，配合 limit 分段读大文件；可选）"},
			"limit":  map[string]any{"type": "integer", "description": "本次读取行数（可选）"},
		}, "path")},
		{Name: "list_files", Description: "列出工作区文件清单（含各阶段交付物），开工第一步先 list_files + read_file 承接上一阶段产出。", Parameters: obj(map[string]any{
			"dir": str("相对目录过滤，如 deliverables；可空"),
		})},
		{Name: "record_asset", Description: "登记资产到记忆库（v6.1.0 起必须携带范围状态：授权清单内资产 scope_status=in_scope 并附 scope_evidence（如「项目授权清单」）；CT/DNS 发现的未核实线索 scope_status=shadow_pending——登记线索不等于测试授权，shadow_pending/unknown 资产在任何通道发起测试流量都会被确定性拦截；需再授权的标 conditional）。", Parameters: obj(map[string]any{
			"type": str("类型：域名/IP/服务/AI应用/APP/小程序等"), "value": str("资产值"), "detail": str("详情"),
			"scope_status":   str("v6.1.0 范围状态（必填）：in_scope（授权清单内）/shadow_pending（待人工核实）/out_of_scope（范围外）/conditional（需再授权）；缺省按 unknown 处理（fail-closed 不放行）"),
			"scope_evidence": str("授权依据（in_scope 必填）：授权清单/授权书条目/扩展工单 ID 等可追溯来源"),
			"target_ref":     str("归属的原始目标行（多目标项目建议填写，供逐目标对账）"),
			"source":         str("来源：客户清单/CT日志/DNS/测绘平台等"),
			"metadata":       map[string]any{"type": "object", "description": "v6.1.0 类型化台账字段（APP：platform/store_url/package_id/version/backend_api；小程序：platform/app_id/version/backend_api/cloud_env_id；云账号：provider/tenant_id/role/region/authorization_ref；API：base_url/业务归属/认证方式类型）——禁止存明文凭据，密钥只允许 *_ref 指针键", "additionalProperties": map[string]any{"type": "string"}},
		}, "type", "value")},
		{Name: "update_asset", Description: "更新已登记资产的范围状态（v6.1.0）：人工核实归属或授权扩展批准后，将 shadow_pending/conditional/out_of_scope/unknown 资产流转为 in_scope；必须附 scope_evidence（授权文书/工单批准记录）与 reason——普通登记不能自我批准。", Parameters: obj(map[string]any{
			"asset_id":       str("资产 ID（A-xxxx）"),
			"scope_status":   str("新范围状态：in_scope/shadow_pending/out_of_scope/conditional/unknown"),
			"scope_evidence": str("授权依据（转 in_scope 必填）：授权文书条目/扩展工单批准记录等"),
			"reason":         str("变更原因（必填）：谁在什么依据下做的状态变更"),
		}, "asset_id", "scope_status", "reason")},
		{Name: "record_finding", Description: "登记一条漏洞/风险。仅收录有证据支撑、有实际影响的漏洞（写明利用条件与影响）；侦察结论、无实际影响的观察写入交付物与时间线，不要调用本工具。高危项定级「确证」前必须 load_skill evidence-standard 对照该类判据并在 detail 引用判据项（反思门判据抽查：未引判据的高危确证会被引擎自动降级为疑似）。契约：登记时提供 poc（实测的原始 HTTP 请求/响应对，Burp 式原文——你发出什么请求、收到什么响应，逐字誊写，≤5 组）与 remediation（修复建议：针对性修复措施+验证方法，面向修复方可执行）；证据编号由引擎自动关联，无需也无法显式提供。", Parameters: obj(map[string]any{
			"title": str("标题"), "severity": str("等级：高/中/低/信息"),
			"detail": str("漏洞详情：简单介绍该漏洞成因与影响面（复现过程由 poc 承载）"), "confidence": str("置信度：确证/疑似/待查"),
			"cwe":            str("标准编号（可选）：如 CWE-89 SQL 注入 / CWE-79 XSS / CWE-22 路径穿越 / CWE-98 CSRF；不确定则留空"),
			"access":         str("利用前提（可选，无凭证项目必标）：anonymous=匿名可利用 / pre-auth=需注册或低权 / post-auth=需认证后"),
			"route":          str("v6.4.0 移交路线（可选）：browser-auth=认证受阻（前端加密/验证码/UA 指纹）移交 S5-2a 浏览器通道 / cli=签名 oracle 已就绪转 CLI 投递器 / manual=需人工读码等协同；S5 按 route 承接并机械对账"),
			"impact_rank":    str("影响排序（可选，1-6）：1=RCE系 2=认证绕过/接管 3=SQLi可提数 4=SSRF可达元数据/内网 5=上传落点可控 6=其余；S5 按 rank 升序消费"),
			"exploitability": str("v4.6 E4 可利用性（可选）：verified（已实测利用）/ conditional（条件性，schema 未知等）/ untested（未投递）；高危+untested 会被引擎自动降级中级，实测后 update_finding 回写"),
			"target_ref":     str("v6.9.0 逐目标归属（可选）：归属的原始项目目标行（多目标项目建议填写，供报告按目标组织与反向对账分组；单目标可空）"),
			"claims":         arr(map[string]any{"file": str("证据文件相对路径（evidence/…）"), "must_contain": str("该文件中必须存在的判据串")}, "v4.6 E1 结论-证据判据串：确证 + 否定性/排他性断言（空、无、未暴露、被拒、0命中、全部000、不依赖、不存在、无差异、同文案）时必填；引擎逐条核验 file 存在且含 must_contain，未命中拒绝登记"),
			"remediation":    str("v5.3.6 修复建议：针对性修复措施（配置/代码/架构层面）+ 修复后验证方法，面向修复方可执行"),
			"poc":            arr(map[string]any{"request": str("原始 HTTP 请求文本（逐字誊写你发出的请求：方法行/头/体）"), "response": str("原始响应文本（逐字誊写收到的响应：状态行/头/体关键部分）")}, "v5.3.6 POC：实测请求/响应对（Burp 式原文，≤5 组）——登记前必须真实交互，禁止编造"),
		}, "title", "severity", "detail")},
		{Name: "update_finding", Description: "v4.6 B5 结论回写：修订已有发现的 severity/confidence/exploitability 或追加 detail（强制 reason，时间线留痕）。实测升级/降级、影响收窄后回写权威库——禁止只写进增量报告。v5.3.7：remediation 可补写/修订（修复建议缺失时补写，已有则追加）。v6.9.0：target_ref 可修正发现的目标归属（留痕）。", Parameters: obj(map[string]any{
			"id": str("record_finding 返回的 F- 编号"), "reason": str("修订依据（必填，含证据）"),
			"severity": str("新等级（可选）"), "confidence": str("新置信度（可选）"), "exploitability": str("verified/conditional/untested（可选）"),
			"detail_append": str("追加到 detail 的修订说明（可选）"),
			"remediation":   str("v5.3.7 修复建议（可选）：空缺时补写，已有则追加修订段"),
			"target_ref":    str("v6.9.0 目标归属修正（可选）：归属的原始项目目标行"),
		}, "id", "reason")},
		{Name: "record_vt", Description: "v4.6 A2 验证队列：登记待验证项（线索→可调度资产）。脚本/PoC/参数字典就绪后立即登记（status=ready），S7 收口前必须逐条三选一处置。", Parameters: obj(map[string]any{
			"title": str("验证目标一句话"), "ready_assets": str("就绪资产路径（分号分隔）"), "start_conditions": str("启动条件"),
			"cost_note": str("预估成本（轮次/时间）"), "priority": str("1-6（对齐 impact-rank：1=RCE系 2=认证绕过/接管 3=SQLi可提数 4=SSRF 5=上传落点 6=其余；v6.4.0 档位与 s4.md 归一），可空"), "status": str("pending/ready（默认 pending）"),
		}, "title")},
		{Name: "update_vt", Description: "v4.6 A2 验证队列流转：ready（v6.3.0 确认就绪，强制 note 确认理由——R7 对抗 VT 主头确认/S3 排期确认）/ executed（已执行，附 result_ref）/ closed-roe（范围外，强制 note 理由）/ deferred（移交，强制 note + result_ref 写启动条件/步骤/工作量三要素）。", Parameters: obj(map[string]any{
			"id": str("record_vt 返回的 VT- 编号"), "status": str("ready/executed/closed-roe/deferred"),
			"result_ref": str("结果/证据/移交位置"), "note": str("处置理由"),
		}, "id", "status")},
		{Name: "record_candidate", Description: "v6.0.1 C28 未定性候选登记：任何「待评估/未定性」线索（如可批量取码的验证码端点、契约未还原的接口、被 WAF 拦截待窗口的注入面）必须登记本账本——禁止只写进交付物文本（实证：GetCaptchaImg「待评估」悬空成三不管，收口无人负责）。登记后 S4/S5 收口前必须 update_candidate 三选一归位。", Parameters: obj(map[string]any{
			"title": str("候选一句话描述"), "target": str("相关目标/端点"),
			"evidence_ref": str("证据位置（evidence/… 或 EV- 编号）"),
		}, "title")},
		{Name: "update_candidate", Description: "v6.0.1 C28 候选归位：finding（附 F- 编号）/ vt（附 VT- 编号+启动条件）/ excluded（附证据+理由）三选一；open 候选会拦截 S4/S5 收口。", Parameters: obj(map[string]any{
			"id": str("record_candidate 返回的 CD- 编号"), "disposition": str("finding/vt/excluded"),
			"disposition_ref": str("F-/VT- 编号或排除证据文件"), "reason": str("归位理由（excluded 强制）"),
		}, "id", "disposition")},
		{Name: "record_timeline", Description: "记录攻击时间线事件。", Parameters: obj(map[string]any{
			"event": str("事件名"), "detail": str("详情"),
		}, "event")},
		{Name: "request_approval", Description: "向人工发起专项审批（写操作/RCE/横向等高风险动作）。", Parameters: obj(map[string]any{
			"action": str("请求批准的动作描述"),
		}, "action")},
		{Name: "complete_stage", Description: "本阶段完成，提交收口。必须提供阶段摘要与交付物清单——摘要按结构化格式：`[测试范围] 已测端点/类 → [关键结果] 每条含 endpoint、假设、阳性/阴性信号、当前状态、下个动作`（结构化摘要，供下游阶段与报告直接消费）；s4/s5 与三专项（specA/specB1/specB2）还必须在调用参数中提供顶层字段 ready_but_unexecuted 与 l2_approved_unused（JSON 数组，无内容传空数组 []，不要只写进 summary 文本）。若收口提示存在 quality-pending 复核标记：先复核相关阶段交付物，确认无缺口后重新调用并传 \"confirm_quality_review\": true（引擎清除标记并继续收口）。", Parameters: obj(map[string]any{
			"summary": str("阶段摘要"), "deliverables": map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "交付物清单"},
			"ready_but_unexecuted":   map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "s4/s5/三专项必填：有就绪脚本/PoC 而未投递的待验证项（每条含就绪资产路径与启动条件）；无内容传空数组 []"},
			"l2_approved_unused":     map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "s4/s5/三专项必填：已批准但未使用的 L2 审批工单；无内容传空数组 []"},
			"confirm_quality_review": map[string]any{"type": "boolean", "description": "v5.3.8（仅 s8 需要时）：收口提示存在 quality-pending 复核标记时，复核相关阶段交付物后传 true——引擎清除标记并继续收口"},
		}, "summary", "deliverables")},
		{Name: "loopback", Description: "发现新攻击面需要前置阶段补充分析时触发回环（如回退到 s4 漏洞发现）。v7.1.0 B2：focus 填聚焦范围（目标/类/端点，如 \"C-13@login\"）——聚焦回环只补该范围，重入阶段不全量重扫，动态额度（默认 8）内高价值回环即用，勿囤积。", Parameters: obj(map[string]any{
			"to_stage": str("目标阶段 id，如 s4"), "reason": str("回环原因"), "focus": str("聚焦范围（可选）：目标/类/端点——重入阶段按此收窄，不全量重扫"),
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
		{Name: "request_user_input", Description: "需要人工决策/二选一路线/非敏感信息补充时向用户提问，挂起等待回答后继续。⚠ 禁止用于索取凭据（密码/令牌/口令/Cookie）——回答会明文落库；凭据索取必须用 request_credential 专用通道（原文加密入库不落明文）。v6.1.0：purpose=roe_ack 为 ROE 红线四要素确认专用（S1 开工第一步：复述①范围②禁止项③频率④数据边界后调用，用户回答 yes 即放行命令通道）。", Parameters: obj(map[string]any{
			"purpose":  str("提问用途（可选）：roe_ack=ROE 红线四要素确认（S1 开工第一步必用）"),
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
			"depth":           str("v7.0.0 深度阶梯（可空）：D0 存在/D1 基线探针/D2 差分对照/D3 语义验证(OOB 回连命中)/D4 影响证明；盲态类（盲 SSRF/XXE/盲注/反序列化）真阴性必填且 ≥D2，否则自动降级 needs_follow_up"),
		}, "endpoint", "vuln_class", "status")},
		{Name: "search_memory", Description: "关键词检索项目记忆库（漏洞/资产/时间线），避免重复劳动。", Parameters: obj(map[string]any{
			"query": str("关键词"),
		}, "query")},
		{Name: "oob_check", Description: "v7.0.0 OOB 回连通道健康自检（三模式：本机自建/公共/用户自设，auto 自动回退；ROE oob_callback=deny 时仅本地监听可用）。盲态类（盲 SSRF/XXE/盲注/反序列化）开测前必调；通道不可用时盲态类禁止开测、相关单元落 needs_follow_up。S1 环境准备时调用一次即完成通道预置（结果自动落 evidence/oob/channel.txt，S1 收口门⑪直接核验）。", Parameters: obj(map[string]any{})},
		{Name: "oob_poll", Description: "收取 OOB 回连记录（按 case-id 过滤，最近 20 条）：回连命中=盲态类 D3 语义验证判据（可支撑确证）；0 条≠阴性——保持 needs_follow_up，禁止无回连命中的盲态 ruled_out。命中后立即落 evidence/oob/ 并引用 EV-（公共通道记录留存短，落证勿延迟）。", Parameters: obj(map[string]any{
			"case_id": str("回连 case-id（命名=漏洞类-目标-序号，如 ssrf-aode-01）；空=最近全部"),
		})},
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
		{Name: "record_lesson", Description: "登记组织级教训（跨项目复用，自动脱敏校验）：本次任务中什么打法有效/无效、什么坑要避开。必须去标识化——禁止目标域名/IP/单位名/真实凭据，写通用经验。收口前或关键失败复盘时调用。v7.4.0 D1 质量门：stack（技术栈）与 behavior_class（行为类）至少填一项——双空的方法论纯文本拒收（实证：406/406 条结构化字段全空致指纹检索结构性失灵；纯方法论请沉淀进对应技能剧本）。同义教训会被归一化判重拒绝，增量经验请复核后换个角度表述。", Parameters: obj(map[string]any{
			"text": str("一句话教训（脱敏）——背景+做法+判据尽量完整，超长会被截断"), "tags": str("类别标签，逗号分隔：方法论/工具/风控/报告/前端情报…（tags 决定未来项目能否命中本教训）"),
			"stack":          str("可选·相关技术栈/组件/厂商产品名，逗号分隔（如 nextjs,spring,hylib）；纯方法论跨栈教训可留空"),
			"behavior_class": str("可选·行为类，如 rate-limited/js-challenge-waf/closed-site/appliance-mgmt"),
			"sample_size":    str("可选·证据强度：'1'=单次实验、'3+'=多样本复验；缺失会被标记为证据强度未记录"),
			"valid_scope":    str("可选·适用边界与反例（不含目标标识）"),
		}, "text")},
		// ---- v3.6.0 阶段内并行扇出 ----
		{Name: "spawn_subagent", Description: "把相互独立的测试单元派发给并行子代理（如：3 个 endpoint×漏洞类单元同时测）。子代理有独立轮次预算与受限工具面，共享黑板/覆盖矩阵/审批矩阵；主头继续其他工作，用 poll_subagents 收结果。收口前必须确认全部子代理已结束。v7.3.0 C2：role=explorer 为探索代理模板——目标函数是异常产出最大化（候选经 record_candidate 入账本，禁自判 finding），适合后台扫描等待期/收口前空隙的并行探索。", Parameters: obj(map[string]any{
			"objective": str("测试单元目标（一句话：目标×漏洞类×成功判据）"),
			"rounds":    str(fmt.Sprintf("轮次预算，可空（默认 engine.max_subagent_rounds=%d，上限 %d）", o.cfg.Engine.MaxSubagentRounds, subagentRoundsCap)),
			"role":      str("可空；explorer=探索代理模板（异常猎手，产出仅 record_candidate）"),
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
		// ---- v7.1.0 PAE 自主决策框架（提议-裁决-升维，零人工裁决点，账本全程留痕）----
		{Name: "propose", Description: "自主决策提议：跨单元资源动作（聚焦回环/预算转移/可达性重排/深化扩展/WAF 变异攻坚/链路计划/探索任务/横向边/复测卡）经本工具提交结构化提议，引擎按确定性规则集即时裁决（无人工等待）。提议三要素：rationale 一句话可证伪理由 + evidence_refs 证据引用（evidence/ 路径或 fact:/F-/VT-/CD- 编号，必须真实可达——空想提议被拒收）+ focus 聚焦范围。被拒（denied）后动作绑定：解析回执原因码 → 仅修回执点名参数（如 NO_EVIDENCE=补 evidence_refs 数组，回执尾附当前可引用示例）→ 立即重提一次，禁止原样重提；同族三次被拒触发升维提示（以更高抽象层重新提议或保守降级 record_vt）。批准后执行，结果用 update_proposal 回写账本。", Parameters: obj(map[string]any{
			"kind":          str("提议类型：loopback_focus（聚焦回环额度）/budget_transfer（阶段间预算转移）/replan_delta（新 live 资产重排）/depth_extend（单单元深化扩展）/mutation_campaign（WAF 变异攻坚，前提=已登记 waf_blocked）/chain_plan（链路级计划，steps 每步一条命令）/explorer_mission（探索代理任务）/lateral_edge（横向决策边）/retest_card（复测卡入队）"),
			"rationale":     str("一句话可证伪理由（假设+预期信号）"),
			"evidence_refs": map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "证据引用（≥1 必填）：evidence/… 路径 / fact:键名 / F-/VT-/CD- 编号"},
			"focus":         str("聚焦范围（目标/类/端点，如 C-13 或 api/user）"),
			"cost":          str("成本预估（轮次/请求/token，可空）"),
			"steps":         map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "chain_plan 专用：链上每步命令（≤6 步，逐条过执行档预检）"},
			"plan":          str("chain_plan/lateral_edge 专用：计划文本（steps 缺省时用）"),
		}, "kind", "rationale", "evidence_refs")},
		{Name: "update_proposal", Description: "v7.1.0 提议结果回写：按批准提议执行后，把产出归宿回写自主决策账本（如「产出 F-3」「coverage vulnerable C-13@target」「转 VT-7」）——这是自主产出转化率的分子来源，S8《自主决策复盘》章按此统计，禁止漏写。", Parameters: obj(map[string]any{
			"id":      str("propose 返回的 PR- 编号"),
			"outcome": str("产出归宿（F-/VT-/coverage 单元/放弃原因）"),
		}, "id", "outcome")},
	}
}

// ---------- 工具函数 ----------

func (o *Orchestrator) log(p *store.Project, stage, text string) {
	// v6.3.2：WS 副本携带 seq（双通道 seq 权威去重，同 streamMsg）——防 8s 轮询再投重复日志
	seq, _ := o.store.AddStream(p.ID, &store.StreamRecord{Kind: "log", Stage: stage, Text: text})
	// v6.6.0 核对轮加固：bus 为 nil（测试装配/部分构造场景）时跳过 WS 广播——落库已先行完成，
	// 不得让确定性门内的提示级日志（spec 豁免提示/逐目标零命中/承接提示）因 bus 缺失 SIGSEGV。
	if o.bus != nil {
		o.bus.Publish(p.ID, "log", map[string]any{"stage": stage, "text": text, "ts": time.Now().Format("15:04:05"), "seq": seq})
	}
}

// usageCtx v7.5.0（A3/A4）：记账上下文——供零 usage 估算兜底与调用种类分账。
type usageCtx struct {
	kind       string // main|subagent|reflect|mentor|brain|adversary|summary|chat（A4 种类分账）
	msgs       []llm.Message
	tools      []llm.ToolDef
	resp       *llm.Message
	cacheReset bool // v7.6.0（C1）：本次调用前发生上下文压缩——明细行打 cache_reset 标记供命中率归因
}

// accountUsage 记账（deadend SessionMetrics 移植）：按阶段分账 + 估算成本 + 预算累计。
func (o *Orchestrator) accountUsage(p *store.Project, stage string, u llm.Usage) {
	o.accountUsageC(p, stage, u, usageCtx{kind: "main"})
}

// accountUsageC v7.5.0 记账扩展：
// ① A3 零 usage 估算兜底——网关不回传 usage 时按消息链/工具面/回复体估算入账并打
//
//	Estimate 标记，熔断护栏不再被「免费搭车」绕过（估算偏保守高估，只多记不少记）；
//
// ② A4 cache 分账——cache_read/write 进 UsageRecord，逐调用明细行落 usage_calls 桶；
// ③ 种类分账——主线/子代理/反思/导师/参谋/对抗/摘要/chat 分开归因。
func (o *Orchestrator) accountUsageC(p *store.Project, stage string, u llm.Usage, uc usageCtx) {
	in, out := int64(u.PromptTokens), int64(u.CompletionTokens)
	total := int64(u.TotalTokens)
	estimated := false
	if uc.kind == "" {
		uc.kind = "main"
	}
	if total <= 0 && config.FlagOrDefault(o.cfg.Engine.UsageEstimateFallback, true) {
		in = int64(estimateTokens(uc.msgs) + estToolTokens(uc.tools))
		if uc.resp != nil {
			out = int64(estimateTokens([]llm.Message{*uc.resp}))
		}
		total = in + out
		estimated = total > 0
	}
	if total <= 0 {
		return
	}
	if rec, err := o.store.AddUsageExt(p.ID, stage, in, out, int64(u.CacheReadTokens), int64(u.CacheWriteTokens)); err == nil && o.bus != nil {
		o.bus.Publish(p.ID, "usage", rec)
	}
	_ = o.store.SaveUsageCall(&store.UsageCallRecord{ProjectID: p.ID, Kind: uc.kind, Stage: stage,
		Model: u.ProviderModel, InTokens: in, OutTokens: out,
		CacheRead: int64(u.CacheReadTokens), Estimate: estimated, CacheReset: uc.cacheReset, At: time.Now()})
	o.mu.Lock()
	o.tokens[p.ID] += total
	o.mu.Unlock()
}

// projectTokens v7.5.0（A2）：预算护栏计数改读 bbolt 账本（持久化）——原纯内存 map 在
// 引擎重启后归零，项目可再烧满整个 max_project_tokens 额度（重启护栏失效）。账本缺失
// （旧项目/异常）时回退内存计数，口径不回退。
func (o *Orchestrator) projectTokens(projectID string) int64 {
	if u, err := o.store.GetUsage(projectID); err == nil && u != nil && u.TotalTokens > 0 {
		return u.TotalTokens
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.tokens[projectID]
}

// auxZeroOutput v7.6.0（A1②）：辅助线零有效产出连续计数与告警——四条辅助智能线（反思/
// 红蓝环/参谋/导师）每次零产出调用一次；同线连续 ≥2 次零产出 → 时间线告警打标（实测
// v7.5.2 前 27 次调用系统性空转、S2-S4 review 非实质结论的教训：故障要被计数并显性化，
// 而非逐次静默降级）。成功调用自动清零。quality-pending 转人工由既有三振降级门承担。
func (o *Orchestrator) auxZeroOutput(p *store.Project, stageID, kind string, zero bool) {
	key := p.ID + "|" + stageID + "|" + kind
	o.auxZeroMu.Lock()
	if o.auxZeroStreak == nil {
		o.auxZeroStreak = map[string]int{}
	}
	if !zero {
		delete(o.auxZeroStreak, key)
		o.auxZeroMu.Unlock()
		return
	}
	o.auxZeroStreak[key]++
	streak := o.auxZeroStreak[key]
	o.auxZeroMu.Unlock()
	if streak >= 2 {
		_, _ = o.store.AddTimeline(&store.TimelineEvent{ProjectID: p.ID, Stage: stageID,
			Event:  "v7.6.0 A1 辅助线零产出告警",
			Detail: fmt.Sprintf("%s 线连续 %d 次零有效产出——疑似 aux 预算/模型故障（实证 v7.5.2 前 1024 截断形态）；该线产出在本阶段按不可用口径对待，quality-pending 复核负债照常挂账", kind, streak)})
		o.log(p, stageID, fmt.Sprintf("⚠ A1 辅助线零产出告警：%s 连续 %d 次零有效产出", kind, streak))
	}
}

// noteSkillLoad v7.6.0（D3）：load_skill 成功注入计数——S4 收口「技能载入硬字段」的数据源
// （实证 某实战项目 S4 零 load_skill，实测报告 §D3：技能列只写引用名未实际载入）。
func (o *Orchestrator) noteSkillLoad(projectID, stageID, skillID string) {
	o.mu.Lock()
	if o.skillLoads == nil {
		o.skillLoads = map[string]int{}
	}
	o.skillLoads[projectID+"|"+stageID]++
	o.mu.Unlock()
}

// skillLoadIssues v7.6.0（D3②）：S4 收口技能载入硬字段——本阶段 load_skill 实际载入 0 次
// 且交付物无「技能豁免」声明 → 拦截（对账表「技能」列引用名 ≠ 实际载入）。
func (o *Orchestrator) skillLoadIssues(p *store.Project, stageID string) []string {
	o.mu.Lock()
	n := o.skillLoads[p.ID+"|"+stageID]
	o.mu.Unlock()
	if n > 0 {
		return nil
	}
	if strings.Contains(normCovText(o.deliverablesText(p.ID)), "技能豁免") {
		return nil // 显式豁免声明在案
	}
	return []string{"v7.6.0 本阶段零 load_skill（D3 技能载入硬字段）——「动手前先查技能库」纪律的机械兜底：开工时上下文包已注入分阶技能索引，本阶段应按指纹/漏洞类载入对应剧本（≥1 次）或在交付物受限项节写明「技能豁免：理由」。【修复示例】load_skill{id:\"evidence-standard\"} 或对账表受限项节追加 \"技能豁免——本阶段全部动作已有 S3 执行卡内联方法，无新增剧本需求\""}
}

// auxClientFor v7.5.0（E2）：辅助调用（反思门/导师/参谋/压缩摘要器）路由——配置 aux_model
// 时用主 client 指向辅助档模型；未配置时与主模型完全一致（零行为变化）。
func (o *Orchestrator) auxClientFor(p *store.Project) (llm.Client, string) {
	if m := strings.TrimSpace(o.cfg.LLM.AuxModel); m != "" {
		return o.LLM(), m
	}
	return o.clientFor(p)
}

// auxMaxTokens v7.5.0（C5/E2）引入；v7.5.2 修复（用户实报 某实战项目/某实战项目）：
// 默认 1024→4096——思考型模型（glm-5.3/DeepSeek-R1 类）会把预算全部耗在 reasoning_content
// 上，1024 下正文恒为空 → 红蓝环/参谋/反思/导师四条辅助智能线系统性空转（"所有任务零
// 自主决策"的总根因）。非思考模型多出的配额不会实际产生成本（按量计费以实际 token 为准）。
func (o *Orchestrator) auxMaxTokens() int {
	if v := o.cfg.LLM.AuxMaxTokens; v > 0 {
		return v
	}
	return 4096
}

// auxTemperature v7.5.0（E2）：辅助调用温度——配置 aux_temperature>0 时统一覆盖，
// 未配置（0，默认）保持各调用点原温度（零行为变化）。
func (o *Orchestrator) auxTemperature(def float32) float32 {
	if v := o.cfg.LLM.AuxTemperature; v > 0 {
		return v
	}
	return def
}

// skillIndexFor v7.5.0（C1）：技能索引注入策略——full（默认）全量；staged 分阶 ≤30 行，
// 低置信度回退全量（宁可多注入不漏技能）。
func (o *Orchestrator) skillIndexFor(stageID string) string {
	if o.skills == nil {
		return "（技能库为空）"
	}
	if o.cfg.Engine.SkillIndexMode == "staged" {
		if sel, ok := o.skills.IndexForStage(stageID, 30); ok {
			return sel
		}
	}
	return o.skills.Index()
}

// buildSubagentPack v7.5.0（D1 子代理精简模式）：派发切片上下文包——目标/授权红线/
// 治理口径/相关黑板事实/分阶技能提示/工作区文件清单，替代全量 buildContextPack
// （合规相关块不减；完整大图景由主头持有）。默认关闭（subagent_lite=false）。
func (o *Orchestrator) buildSubagentPack(p *store.Project, objective, stageID string) string {
	var b strings.Builder
	b.WriteString("### 派发切片上下文（子代理精简模式：只带与本任务相关的切片，完整大图景由主头持有）\n")
	b.WriteString(fmt.Sprintf("- 项目: %s\n- 派发目标: %s\n- 目标资产: %s\n", p.Name, truncateText(objective, 300), firstLine(p.Target)))
	if strings.TrimSpace(p.Scope) != "" {
		b.WriteString("- 授权范围: " + truncateRunes(p.Scope, 800) + "\n")
	}
	if strings.TrimSpace(p.ROE) != "" {
		b.WriteString("- ROE 红线: " + truncateRunes(p.ROE, 500) + "\n")
	}
	if p.ExecutionProfile != "" {
		b.WriteString("- Execution Profile: " + p.ExecutionProfile + "（治理口径与生产安全禁令照常强制）\n")
	}
	// 黑板事实 Top10（deprecated 不注入）
	if facts, err := o.store.ListFacts(p.ID, 10); err == nil && len(facts) > 0 {
		b.WriteString("\n### 项目黑板（Top 10）\n")
		for _, f := range facts {
			if f.Confidence == "deprecated" {
				continue
			}
			b.WriteString(fmt.Sprintf("- [%s] %s: %s\n", f.Confidence, f.Key, truncateRunes(f.Value, 120)))
		}
	}
	// 分阶技能提示（≤20 行；load_skill query 检索全库通道不变）
	if sel, ok := o.skills.IndexForStage(stageID, 20); ok {
		b.WriteString("\n### 本任务相关技能（load_skill 按需载入）\n" + sel)
	}
	// 工作区文件清单（20 个文件名，承接用）
	if files, err := o.listWorkspaceFiles(p.ID, ""); err == nil && len(files) > 0 {
		b.WriteString("\n### 工作区文件（前 20）\n")
		for i, f := range files {
			if i >= 20 {
				break
			}
			b.WriteString("- " + f.Path + "\n")
		}
	}
	return b.String()
}

// compactionSummarizer v7.5.0（E1 混合压缩）：返回窗口压缩的摘要回调——aux 模型生成
// ≤8KB 结构化历史摘要，sha256 LRU 100 条去重（PentAGI GetSummarizeResultHandler 同款），
// 60s 超时，失败返回空串静默回退纯存根口径。开关关闭（默认）时返回 nil（零额外调用）。
func (o *Orchestrator) compactionSummarizer(p *store.Project, stageID string) func(corpus string) string {
	if !config.FlagOrDefault(o.cfg.Engine.HybridCompaction, false) {
		return nil
	}
	return func(corpus string) string {
		key := fmt.Sprintf("%x", sha256.Sum256([]byte(corpus)))
		o.sumMu.Lock()
		if v, ok := o.sumCache[key]; ok {
			o.sumMu.Unlock()
			return v
		}
		o.sumMu.Unlock()
		cli, model := o.auxClientFor(p)
		if cli == nil {
			return ""
		}
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		// 语料超 32KB 头尾截断（PentAGI msgSummarizerLimit 同口径）
		if len(corpus) > 32*1024 {
			corpus = tools.TruncateSmart(corpus, 32*1024)
		}
		msgs := []llm.Message{
			{Role: "system", Content: "你是渗透测试流水线的压缩摘要器。把给定执行过程语料压成结构化摘要：①关键发现与结论（含编号）②已执行命令与结果要点 ③证据指针（EV-/receipt:/文件路径）④未完成事项。技术细节（参数/路径/编号）高优先级保留；≤8KB，中文。"},
			{Role: "user", Content: corpus},
		}
		resp, usage, err := cli.Chat(ctx, model, msgs, nil, o.auxTemperature(0.2), o.auxMaxTokens())
		if err != nil || strings.TrimSpace(resp.Content) == "" {
			return ""
		}
		o.accountUsageC(p, stageID, usage, usageCtx{kind: "summary", msgs: msgs, resp: &resp})
		sum := strings.TrimSpace(resp.Content)
		o.sumMu.Lock()
		if o.sumCache == nil {
			o.sumCache = map[string]string{}
		}
		o.sumCache[key] = sum
		o.sumKeys = append(o.sumKeys, key)
		if len(o.sumKeys) > 100 { // LRU 淘汰最旧
			for len(o.sumKeys) > 100 {
				old := o.sumKeys[0]
				o.sumKeys = o.sumKeys[1:]
				delete(o.sumCache, old)
			}
		}
		o.sumMu.Unlock()
		return sum
	}
}

// exportArtifacts 结项导出（strix/shannon 移植）：findings.json + findings.sarif 2.1.0。
// baselineTierUnit v7.7.1 红队模式：低产出合规类的深化/重复登记判定——
// 非 vulnerable、Count>=2（一轮基线已登记过）、vuln_class/endpoint/param 命中基线类清单
// （默认 C-24 TLS/邮件安全 + C-25 安全头）。命中 → 该单元不再重置收敛 idle。
func (o *Orchestrator) baselineTierUnit(entry *store.CoverageEntry) bool {
	if !config.FlagOrDefault(o.cfg.Engine.ProbeTiering, true) || entry == nil || entry.Status == "vulnerable" || entry.Count < 2 {
		return false
	}
	hay := entry.VulnClass + " " + entry.Endpoint + " " + entry.Param
	for _, cls := range o.cfg.Engine.BaselineTierClasses {
		if cls != "" && strings.Contains(hay, cls) {
			return true
		}
	}
	return false
}

// baselineTierRefHint v7.8.0 优化④：基线类语义但未引用 C-xx 编号 → 提醒（防抖：同单元只一次）。
// 通用性：关键词清单从 BaselineTierClasses 派生（可配置），对清单内任何类自动生效。
func (o *Orchestrator) baselineTierRefHint(entry *store.CoverageEntry) bool {
	if !config.FlagOrDefault(o.cfg.Engine.ProbeTiering, true) || entry == nil || entry.Count > 1 {
		return false // 首轮才提醒（二轮起已是降档口径）
	}
	hay := entry.VulnClass + " " + entry.Endpoint + " " + entry.Param
	hits := false
	for _, cls := range o.cfg.Engine.BaselineTierClasses {
		// 关键词语义匹配（TLS/安全头/邮件安全——从类编号派生的中文关键词 + 编号本身）
		if cls != "" && strings.Contains(hay, cls) {
			hits = true
			break
		}
	}
	if !hits {
		return false
	}
	// 已引用 C 编号 → 不需要提醒
	for _, cls := range o.cfg.Engine.BaselineTierClasses {
		if strings.Contains(hay, cls) {
			return false
		}
	}
	// 防抖：同单元只提醒一次
	key := entry.ProjectID + "|" + entry.Endpoint + "|" + entry.VulnClass
	if o.blHintSeen == nil {
		o.blHintSeen = map[string]bool{}
	}
	if o.blHintSeen[key] {
		return false
	}
	o.blHintSeen[key] = true
	return true
}

// convNote v7.7.0 P1：产出事件计数（收敛信号源）——五类产出清零 idle：record_finding
// （新登记）/ update_coverage（vulnerable 或新单元）/ update_vt→ready / update_proposal /
// record_candidate。
func (o *Orchestrator) convNote(p *store.Project, stageID string) {
	o.convMu.Lock()
	if o.convIdle == nil {
		o.convIdle = map[string]int{}
	}
	o.convIdle[p.ID+"|"+stageID] = 0
	o.convMu.Unlock()
}

// convIdleRounds 读当前 idle 轮数。
func (o *Orchestrator) convIdleRounds(p *store.Project, stageID string) int {
	o.convMu.Lock()
	defer o.convMu.Unlock()
	return o.convIdle[p.ID+"|"+stageID]
}

// convMarkIdle v7.7.0 P1：本轮无产出 → idle+1；冷却豁免（W5 行为预算器静默/限速窗口
// 不是"无产出"——方案 §一.P1 防误收敛条款）。
func (o *Orchestrator) convMarkIdle(p *store.Project, stageID string) {
	o.convMu.Lock()
	defer o.convMu.Unlock()
	if o.convIdle == nil {
		o.convIdle = map[string]int{}
	}
	key := p.ID + "|" + stageID
	if st := o.batchStats[p.ID]; st != nil && st.cooldownUntil.After(time.Now()) {
		o.convIdle[key] = 0
		return
	}
	o.convIdle[key]++
}

// convMaybeFire v7.7.0 P1：三重条件判定 + 一次性信号注入，返回信号文本（空=不触发）。
// ①执行卡五态无 queued（C27 状态机直出；多目标=全部目标无积压——保守方向）
// ②候选账本无 open（C28）
// ③连续 convergence_rounds 轮无新增确证产出
func (o *Orchestrator) convMaybeFire(p *store.Project, stageID string, iter, budget int) (string, bool) {
	n := o.cfg.Engine.ConvergenceRounds
	if n <= 0 || o.convFired[p.ID+"|"+stageID] {
		return "", false
	}
	// v7.7.0 十四轮核对修正：适用域下沉到本函数（防御纵深）——仅 s4/s5（满预算重执行
	// 阶段，方案实证域）。s2 侦察产出=资产登记（不在事件集）、s3 假设生成期、s6/s7 产出
	// 语义不同——在这些阶段 idle 会因"产出不计"而累积，误触发=砍侦察广度/假设生成。
	if stageID != "s4" && stageID != "s5" {
		return "", false
	}
	if iter < budget*3/10 {
		return "", false
	}
	if o.convIdleRounds(p, stageID) < n {
		return "", false
	}
	if cs := o.store.CardStats(p.ID); cs["total"] > 0 && cs["queued_vt"] > 0 {
		return "", false
	}
	if cands, err := o.store.ListCandidates(p.ID); err == nil {
		for _, c := range cands {
			if c.Disposition == "" { // v7.7.0 P1：C28 悬空候选（未归位）禁止收敛
				return "", false
			}
		}
	}
	// v7.7.0 十三轮核对补充（防过早触发）：在途后台任务/子代理未归位 → 不收敛。
	// 长扫描的 poll 轮无即时产出会累积 idle——但扫描结论尚未落地，此时收敛=砍掉
	// 最重要的异步产出（实证：nmap 全端口 25min job）。收敛语义=「全部在途工作已归位
	// 且无新增确证」，而非「暂时没看到发现」。
	if jobs := o.pendingAsyncJobs(p.ID); len(jobs) > 0 {
		return "", false
	}
	if o.runningSubAgents(p.ID) > 0 {
		return "", false
	}
	msg := fmt.Sprintf("🪃 收敛信号（v7.7.0 P1）：27 类执行卡无排队积压、候选账本无悬空，且连续 %d 轮无新增确证产出——广度与深度已达当前证据下的收敛点。**立即进入收口流程**：①按 impact-rank 确认无遗漏高危消费；②write_file 完成交付物；③complete_stage 收口（全部确定性门照常核验）。不要再发起新测试——剩余预算可由真头参谋经 propose 编排转移。", n)
	o.log(p, stageID, fmt.Sprintf("🪃 收敛信号触发（连续 %d 轮无新增确证 + 无积压）——注入收敛收口指令", n))
	_, _ = o.store.AddTimeline(&store.TimelineEvent{ProjectID: p.ID, Stage: stageID,
		Event:  "v7.7.0 P1 收敛信号",
		Detail: fmt.Sprintf("第 %d/%d 轮触发（连续 %d 轮无新增确证产出，执行卡无 queued，候选无 open）", iter+1, budget, n)})
	o.convMu.Lock()
	if o.convFired == nil {
		o.convFired = map[string]bool{}
	}
	o.convFired[p.ID+"|"+stageID] = true
	o.convMu.Unlock()
	return msg, true
}

// pendingAsyncJobs v7.7.0 十三轮核对：列出在途（running）后台任务——收敛守卫的数据源，
// 复用 harvestAsyncOutputs 的 .async/ 侧车扫描（state=running/pending 视为在途）。
func (o *Orchestrator) pendingAsyncJobs(projectID string) []asyncJobRec {
	dir := filepath.Join(o.workspaceRoot(projectID), ".async")
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
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
			ID    string `json:"id"`
			State string `json:"state"`
		}
		if json.Unmarshal(raw, &sc) != nil {
			continue
		}
		if sc.State != "finished" && sc.State != "failed" && sc.State != "killed" {
			out = append(out, asyncJobRec{ID: sc.ID, State: sc.State})
		}
	}
	return out
}

// ensureAttackGraph v7.3.0 核对修复（审计 L）：攻击路径缝合器按需生成——旧实现只在——旧实现只在
// 结项导出时写 attack-graph.md，S6 横向决策图注入（C4）在阶段执行期永远读不到（死代码）。
// S6 上下文构建按需调用；结项导出复用同一实现（withSVG 时渲染 SVG）。
func (o *Orchestrator) ensureAttackGraph(p *store.Project, withSVG bool) {
	dot, md := o.buildAttackGraph(p)
	if dot == "" {
		return
	}
	_, _ = o.exec.WriteFile(p.ID, "deliverables/attack-graph.dot", dot)
	_, _ = o.exec.WriteFile(p.ID, "deliverables/attack-graph.md", md)
	if withSVG {
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
	}
	o.log(p, "", "🕸 已生成攻击路径图 deliverables/attack-graph.dot|.md")
}

func (o *Orchestrator) exportArtifacts(p *store.Project) {
	// v7.1.0：自主决策账本导出（autonomy.json——Web「自主决策」页与 S8 复盘章的数据同源，
	// 供外部平台/审计消费；零提案时跳过避免空文件噪声）
	if recs, err := o.store.ListAutonomy(p.ID); err == nil && len(recs) > 0 {
		export := map[string]any{
			"version": "7.1.0",
			"model":   "PAE（提议-裁决-升维）：LLM 提议 → 引擎确定性裁决 → 升维/保守降级，全程无人工裁决点",
			"stats":   o.store.AutonomyStats(p.ID),
			"records": recs,
		}
		aj, _ := json.MarshalIndent(export, "", "  ")
		_ = os.WriteFile(filepath.Join(o.cfg.DataDir, p.ID, "autonomy.json"), aj, 0o640)
		o.log(p, "", fmt.Sprintf("📦 已导出 autonomy.json（%d 条自主决策记录）", len(recs)))
	}
	// v3.4.1 修复：攻击路径缝合器不再被「无漏洞早退」挡住——只有黑板事实/战利品
	// 而暂无 findings 的项目（如情报链完备、利用队列待验证）同样需要攻击图。
	// v7.3.0 核对修复（审计 L）：改走 ensureAttackGraph（与 S6 按需生成共用一份实现）
	o.ensureAttackGraph(p, true)
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
		props := map[string]any{"severity": f.Severity, "confidence": f.Confidence, "stage": f.Stage}
		if f.TargetRef != "" { // v6.9.0 S8-⑤：逐目标归属随导出携带（平台导入侧按目标分派修复责任）
			props["target"] = f.TargetRef
		}
		r := sarifResult{RuleID: f.ID, Level: lvl, Properties: props}
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
// 含待续清单/档案目标/分组交付物）。
// v6.3.0（S3-⑧）：上限 30→60 文件 + 对账关键文件优先（判定表/对账表/待续/收口/威胁模型/
// 测试计划类文件名关键词），其余按 mtime 倒序——大项目（35+ 交付物实证）C27/R7/逐目标
// 对账语料不再被非关键文件挤出（处置写在对账表却被截断→误拦/漏判两类噪声消除）。
func (o *Orchestrator) deliverablesText(projectID string) string {
	return o.deliverablesTextExcluding(projectID, "")
}

// deliverablesTextExcluding v6.5.0（S5-①）：deliverables 语料拼接（可排除文件名含指定
// 子串的文件）——s5 逐目标对账排除 s4- 产物：S4 分组交付物按 S4-9 门强制逐目标产出，
// 混入 S5 语料会让未动目标借 S4 留痕自动放行（与 v3HandoverIssues 的 s4 排除口径同源，
// fixplan_gate.go「含移交项原文，会自匹配放行」注释）。空 excludeSubstr 行为与
// deliverablesText 完全一致（全量拼接）。v6.7.0：多排除子串变体（S6-④ s6 语料需同时
// 排除 s4-/s5- 上游分组产物——两阶段分组交付物都按门强制逐目标产出，任一混入都会让
// 未动目标借上游留痕放行），excludeSubstr 含 "," 时按多子串拆分。
func (o *Orchestrator) deliverablesTextExcluding(projectID, excludeSubstr string) string {
	names, err := o.exec.ListDir(projectID, "deliverables")
	if err != nil || len(names) == 0 {
		return ""
	}
	excludes := []string{}
	if excludeSubstr != "" {
		for _, ex := range strings.Split(excludeSubstr, ",") {
			if ex = strings.TrimSpace(ex); ex != "" {
				excludes = append(excludes, ex)
			}
		}
	}
	excluded := func(base string) bool {
		for _, ex := range excludes {
			if strings.Contains(base, ex) {
				return true
			}
		}
		return false
	}
	priority := func(rel string) bool {
		base := filepath.Base(rel)
		for _, kw := range []string{"判定表", "对账表", "待续", "收口", "威胁模型", "测试计划"} {
			if strings.Contains(base, kw) {
				return true
			}
		}
		return false
	}
	var pri, rest []string
	for _, rel := range names {
		if excluded(filepath.Base(rel)) {
			continue
		}
		if !strings.HasSuffix(rel, ".md") && !strings.HasSuffix(rel, ".txt") && !strings.HasSuffix(rel, ".json") {
			continue
		}
		if priority(rel) {
			pri = append(pri, rel)
		} else {
			rest = append(rest, rel)
		}
	}
	root := ""
	if o.cfg != nil { // 测试装配/降级态：无 cfg 时跳过 mtime 排序（保持 ListDir 序），不影响语料内容
		root = o.workspaceRoot(projectID)
	}
	mod := func(rel string) time.Time {
		if root != "" {
			if fi, serr := os.Stat(filepath.Join(root, rel)); serr == nil {
				return fi.ModTime()
			}
		}
		return time.Time{}
	}
	sort.Slice(rest, func(i, j int) bool {
		ti, tj := mod(rest[i]), mod(rest[j])
		if !ti.Equal(tj) {
			return ti.After(tj)
		}
		return rest[i] < rest[j]
	})
	ordered := append(append([]string{}, pri...), rest...)
	var b strings.Builder
	n := 0
	for _, rel := range ordered {
		if n >= 60 {
			break
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

// evidenceRefRe v5.9.0（方案 P1-3）：结构化证据引用——evidence/ 路径、EV- 编号、
// 或 "POC: " 前缀（record_finding poc 参数登记时的约定标记）。禁止裸子串（"POC 未执行"
// 曾骗过子串匹配）。
var evidenceRefRe = regexp.MustCompile(`evidence/[A-Za-z0-9_\-./]+|\bEV-[0-9A-Za-z\-]+|(?i)poc\s*[:：]`)

// matrixClassRe 筛查矩阵判定表/逐类对账表行首列：C-<两位编号>（C-01..C-27）。
// v6.4.0（S4-①）行首格容差：兼容 `| C-01 |` 与 `| C-01 登录面 |` 两种合法形态（实测项目
// 某历史任务 对账表首格带触发面摘要，旧正则要求 C 编号后紧跟竖线导致交付物分桶解析不到）。
// 词边界锚定防 C-011 类误匹配。
var matrixClassRe = regexp.MustCompile(`^\s*\|\s*(C-\d{2})\b`)

// matrixVerdictRe 三态判定格：恰为 假设/不适用/待判定 之一的表格单元格。
var matrixVerdictRe = regexp.MustCompile(`\|\s*(假设|不适用|待判定)\s*\|`)

// matrixTotalClasses 筛查矩阵类数（v4.8 §一 27 类）。
const matrixTotalClasses = 27

// matrixTableIssues v4.8 M2 s3 收口门：判定表存在且 27 行三态留痕完整。
// 口径：只查留痕不查内容——不检查假设关键词命中，杜绝诱导式编造。
// v6.3.0 增强：①证据指针核存（S3-①：evidence/ 路径逐个验存在，幻觉路径拦截——只验指针
// 可达不验内容语义）；②执行卡逐行校验且口径统一（S3-②：假设+待判定均须卡——待判定是
// s4 双假设裁决投递单元，guard 关闭回退旧口径）；③多目标 (类×目标) 覆盖完备性（S3-②）。
func (o *Orchestrator) matrixTableIssues(p *store.Project) []string {
	raw, err := o.exec.ReadFile(p.ID, "deliverables/s3-筛查矩阵判定表.md")
	if err != nil {
		return []string{"v4.8 M2：缺少《筛查矩阵判定表》deliverables/s3-筛查矩阵判定表.md——load_skill hypothesis-matrix 按 27 类逐类三态判定后重写并重新收口（判定基于既有证据，零新增主动流量）"}
	}
	rows := parseMatrixRows(raw)
	// ① 27 类齐全（按 C 编号去重，行重复不影响）
	found := map[string]bool{}
	for _, r := range rows {
		found[r.class] = true
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
	// ② 每行三态判定格
	noVerdict := 0
	for _, r := range rows {
		if r.verdict == "" {
			noVerdict++
		}
	}
	if noVerdict > 0 {
		return []string{fmt.Sprintf("v4.8 M2：判定表 %d 行无三态判定格（判定列应为 | 假设 | / | 不适用 | / | 待判定 | 之一）——补判定后重新收口", noVerdict)}
	}
	// ③ v6.3.0（S3-①）证据指针核存：判定表引用的 evidence/ 路径必须真实落盘（上限 40 个防大表拖慢）。
	// 通配引用（evidence/s2-*）与带后缀截断（.tool-output 作业日志）按 glob 命中即视为可达。
	evidenceChecked := map[string]bool{}
	var evidenceMissing []string
	refsChecked := 0
	globRefExists := func(ref string) bool {
		if o.cfg == nil {
			return false
		}
		hits, _ := filepath.Glob(filepath.Join(o.workspaceRoot(p.ID), ref) + "*")
		return len(hits) > 0
	}
	for _, ref := range matrixEvidenceRefRe.FindAllString(raw, -1) {
		ref = strings.TrimRight(ref, "./")
		if ref == "" || evidenceChecked[ref] {
			continue
		}
		evidenceChecked[ref] = true
		if refsChecked >= 40 {
			break
		}
		refsChecked++
		if _, rerr := o.exec.ReadFile(p.ID, ref); rerr != nil && !globRefExists(ref) {
			evidenceMissing = append(evidenceMissing, ref)
		}
	}
	if len(evidenceMissing) > 0 {
		return []string{fmt.Sprintf("v6.3.0 证据指针门：判定表 %d 个 evidence/ 指针指向不存在的文件（%s）——判定表证据必须来自真实落盘文件（先落盘再引用，防幻觉证据过门；非 evidence/ 引用形态不核存）",
			len(evidenceMissing), truncateText(strings.Join(evidenceMissing, ","), 140))}
	}
	// ④ 执行卡逐行校验（行 + 紧随 ≤3 非空行为卡上下文；同类多行逐行校验——修复旧实现
	// 「重复 C 编号行只保留最后一行」的漏检）。口径 guard 感知：开启=假设+待判定均须卡
	// （v6.3.0 S3-② 统一，与 s3.md/hypothesis-matrix 表述一致）；关闭=旧口径（仅含「假设」字样行）。
	targetMatrixOn := o.guardEnabled(func(g *config.GuardConfig) *bool { return g.EnforceTargetClassMatrix })
	cardMarkers := []string{"入口", "探针", "阳性", "阴性", "停止"}
	lines := strings.Split(raw, "\n")
	type rowCtxT struct{ ctx []string }
	rowCtxs := make([]rowCtxT, 0, len(rows))
	for _, line := range lines {
		if matrixClassRe.MatchString(line) {
			rowCtxs = append(rowCtxs, rowCtxT{ctx: []string{line}})
			continue
		}
		if len(rowCtxs) > 0 && strings.TrimSpace(line) != "" && len(rowCtxs[len(rowCtxs)-1].ctx) < 4 {
			last := &rowCtxs[len(rowCtxs)-1]
			last.ctx = append(last.ctx, line)
		}
	}
	var missingCards []string
	seenCard := map[string]bool{}
	for i, r := range rows {
		if i >= len(rowCtxs) {
			break
		}
		joined := strings.Join(rowCtxs[i].ctx, "\n")
		var needsCard bool
		if targetMatrixOn {
			needsCard = r.verdict == "假设" || r.verdict == "待判定"
		} else {
			needsCard = matrixVerdictRe.FindStringSubmatch(joined) != nil && strings.Contains(joined, "假设")
		}
		if !needsCard {
			continue
		}
		hit := 0
		for _, mk := range cardMarkers {
			if strings.Contains(joined, mk) {
				hit++
			}
		}
		if hit < 3 && !seenCard[r.class] { // 至少 3/5 标记（大小写/别名的宽容下限），不足=执行卡缺失
			seenCard[r.class] = true
			missingCards = append(missingCards, r.class)
		}
	}
	if len(missingCards) > 0 {
		return []string{fmt.Sprintf("v5.9.0 执行卡门：判定=假设/待判定 的 %d 行缺执行卡要素（%s）——每条假设/待判定附一行式执行卡（入口定位→首探针→阳性信号→阴性信号→停止阈值≤6 请求/候选），s4 按卡直接投递",
			len(missingCards), truncateText(strings.Join(missingCards, ","), 120))}
	}
	// ⑤ v6.3.0（S3-②）多目标 (类×目标) 覆盖完备性：多目标项目假设/待判定须落目标粒度，
	// 每类覆盖目标并集 ⊇ 项目目标集（单目标项目零影响）。
	if targetMatrixOn {
		if issues := matrixTargetClassIssues(p, rows); len(issues) > 0 {
			return issues
		}
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

// idorCandidateIssues v5.9.0（方案 P1-3）：IDOR candidate 禁直升——
// 覆盖矩阵中存在 candidate_idor_anonomous/needs_follow_up 的 IDOR 候选端点时，
// 同端点的「确证」IDOR 发现降级为疑似（对象归属二次确认前置：owner-grep 采集/
// 双账号差分/业务预期核对三选一后才可确证）。
func (o *Orchestrator) idorCandidateIssues(p *store.Project) []string {
	cov, _ := o.store.ListCoverage(p.ID)
	candEndpoints := map[string]bool{}
	for _, c := range cov {
		if c.Status == "needs_follow_up" && strings.Contains(strings.ToLower(c.Notes), "candidate") {
			candEndpoints[c.Endpoint] = true
		}
	}
	if len(candEndpoints) == 0 {
		return nil
	}
	findings, _ := o.store.ListFindings(p.ID)
	var issues []string
	for _, f := range findings {
		if f.Stage == "s4" && f.Confidence == "确证" &&
			(strings.Contains(f.Title, "IDOR") || strings.Contains(f.Title, "越权") || strings.Contains(strings.ToLower(f.Title), "idor")) {
			for ep := range candEndpoints {
				if strings.Contains(f.Detail, ep) {
					f.Confidence = "疑似"
					_ = o.store.UpdateFinding(f)
					issues = append(issues, fmt.Sprintf("发现 %s（%s）降级疑似：其端点在覆盖矩阵为 IDOR 候选（缺对象归属二次确认）——owner-grep/双账号差分/业务核对三选一后 update_finding 升级", f.ID, truncateText(f.Title, 50)))
					break
				}
			}
		}
	}
	return issues
}

// vulnerableEvidenceIssues v5.8.0（审计 Top#9）：覆盖矩阵 vulnerable/no_issue_found 条目
// 必须能关联证据（notes 引用 evidence/ 路径或 POC/判据字样）——"留痕齐全、测试不充分"的
// 格式过门被升级为语义检查：无证据支撑的结论条目在收口时列拦截项。
func (o *Orchestrator) vulnerableEvidenceIssues(p *store.Project, stageID string) []string {
	cov, _ := o.store.ListCoverage(p.ID)
	evs, _ := o.store.ListEvidence(p.ID)
	var issues []string
	checked := 0
	for _, c := range cov {
		if c.Status != "vulnerable" && c.Status != "no_issue_found" {
			continue
		}
		checked++
		// v5.9.0（方案 P1-3）：去子串化——"POC 未执行"类文字曾骗过子串匹配。
		// 结构化三选一：①evidence/ 路径引用 ②EV- 编号引用 ③POC: 前缀（记录时登记）。
		notes := c.Notes
		hasRef := evidenceRefRe.MatchString(notes)
		if hasRef {
			continue
		}
		// 证据库兜底：该 endpoint 出现在任一 evidence Input/Output 中
		linked := false
		for _, e := range evs {
			if e.ProjectID == p.ID && (strings.Contains(e.Input, c.Endpoint) || strings.Contains(e.Output, c.Endpoint)) {
				linked = true
				break
			}
		}
		if !linked {
			// v7.6.0（A2 自解释契约）：报错从「缺失项列表」升级为「期望形态样例 + 当前值 diff +
			// 修复示例」三元组——实证 某实战项目 S4 收口期模型对同类报错盲猜 8 轮甚至逆向
			// 引擎二进制（实测报告 §A2）；报错自解释是消除门搏斗的根修。
			issues = append(issues, fmt.Sprintf("覆盖条目 [%s] %s × %s 结论无证据关联——"+
				"【期望形态】notes 含 evidence 文件指针或 POC 引用，且该端点出现在证据库（evidence.Input/Output）中；"+
				"【当前值】notes=%q，证据库无 %s 记录；"+
				"【修复示例】补测留证（evidence/s4-<主题>.txt 落盘后 update_coverage notes 追加 \"证据: evidence/s4-<主题>.txt\"），或将该条改判 needs_follow_up",
				c.Status, truncateText(c.Endpoint, 60), truncateText(c.VulnClass, 30), truncateText(c.Notes, 80), truncateText(c.Endpoint, 40)))
			if len(issues) >= 12 {
				break
			}
		}
	}
	_ = checked
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

// nucleiTrackIssues v7.6.0（A6）：S4 自动化扫描轨状态硬字段——交付物语料（含受限项/盲区节）
// 须出现 nuclei 轨道状态声明（执行/豁免/deferred 任一形态），杜绝「双轨制之①静默消失」。
func (o *Orchestrator) nucleiTrackIssues(p *store.Project) []string {
	text := normCovText(o.deliverablesText(p.ID))
	if strings.Contains(text, "nuclei") {
		return nil // 已声明（执行结果/豁免理由/deferred 任一形态均算在案）
	}
	return []string{"v7.6.0 自动化扫描轨状态未声明（A6 双轨留痕强制）——文档 §四 S4 双轨制之①（nuclei 自动化扫描）须三选一显式写入交付物「受限项/盲区」节：" +
		"①已执行（附证据文件指针）；②豁免（理由 + 替代覆盖说明）；③deferred（条件 + 启动时机）。" +
		"【修复示例】在 s4-逐类对账表.md 受限项节追加一行：\"nuclei 轨：豁免——理由 X，替代覆盖 Y\""}
}

// stageChecknote v7.6.0（A3）：收口时引擎直出库内实算统计——实证三处交付物手写汇总数字
// 穿透收口（五态 20/7 vs 实算 16/9、处置 4+3 vs 5+2、映射 19 vs 18，实测报告 §A3）且引擎
// 已算出的实算值未回写。本注记是权威数字源：交付物手写统计与其分歧时以注记为准，S8 复核
// 按注记对账。
func (o *Orchestrator) stageChecknote(p *store.Project, stageID string) string {
	if cov, err := o.store.ListCoverage(p.ID); err == nil {
		statusCount := map[string]int{}
		stageRows := 0
		for _, c := range cov {
			if c.Stage == stageID {
				stageRows++
				statusCount[c.Status]++
			}
		}
		findings, _ := o.store.ListFindings(p.ID)
		stageFindings := 0
		for _, f := range findings {
			if f.Stage == stageID {
				stageFindings++
			}
		}
		subs, _ := o.store.ListSubtasks(p.ID)
		subDone, subTotal := 0, 0
		for _, t := range subs {
			if t.Stage == stageID {
				subTotal++
				if t.Status == "finished" || t.Status == "done" {
					subDone++
				}
			}
		}
		vts, _ := o.store.ListVTs(p.ID)
		vtStat := map[string]int{}
		for _, t := range vts {
			vtStat[t.Status]++
		}
		return fmt.Sprintf("coverage[%s]=%d 行 %v；findings[%s]=%d（全库 %d）；subtasks[%s]=%d/%d finished；vt=%v（全库）——库内实算权威口径，交付物手写汇总与此分歧时以本注记为准（A3）",
			stageID, stageRows, statusCount, stageID, stageFindings, len(findings), stageID, subDone, subTotal, vtStat)
	}
	return ""
}

// stageDecisionDigest v7.6.0（E3）：阶段自主决策留痕聚合落 autonomy 账本——实证 propose
// 通道零使用时 autonomy 桶 0 记录、决策散落 7 类存储无单一回放面、S8 复盘章无米下锅
// （实测报告 §E3）。聚合层与 propose 账本互补：propose 未用也有阶段级决策摘要可回放。
func (o *Orchestrator) stageDecisionDigest(p *store.Project, stageID string) {
	subs, _ := o.store.ListSubtasks(p.ID)
	subDone, subTotal := 0, 0
	for _, t := range subs {
		if t.Stage == stageID {
			subTotal++
			if t.Status == "finished" || t.Status == "done" {
				subDone++
			}
		}
	}
	approvals, _ := o.store.ListApprovals(p.ID)
	facts, _ := o.store.ListFacts(p.ID, 0)
	lessons, _ := o.store.ListLessons(0)
	rec := &store.AutonomyRecord{
		ProjectID: p.ID,
		Stage:     stageID,
		Kind:      "stage_digest", // v7.6.0 E3 扩展枚举：引擎聚合的阶段决策摘要（非模型 propose）
		Rationale: fmt.Sprintf("阶段决策留痕聚合：子任务 %d/%d finished、审批单 %d、事实 %d、教训 %d——决策明细按 stream/timeline/vts/facts/lessons 关联键回放", subDone, subTotal, len(approvals), len(facts), len(lessons)),
		Verdict:   "shadow_recorded",
		Reason:    "engine_aggregated_digest（E3：决策散落存储的单一回放面，propose 账本的互补层）",
	}
	if _, err := o.store.AddAutonomy(rec); err != nil {
		o.log(p, stageID, "⚠ E3 决策摘要落账失败: "+err.Error())
	}
}

// writeChecklistGap v7.7.0 P3②：checklist 自述面差距表（台账投影）——checklist.json ×
// coverage 逐条对照：已引用登记（引用条目文本/C 编号）→ 状态；无归宿 → 差距行（G2 门数据
// 的可读投影，不替代 G2 门）。S4 收口时生成。
func (o *Orchestrator) writeChecklistGap(p *store.Project, stageID string) {
	raw, err := o.exec.ReadFile(p.ID, "checklist.json")
	if err != nil {
		return
	}
	var ck struct {
		Items []struct {
			ID     string `json:"id"`
			Item   string `json:"item"`
			Class  string `json:"class"`
			Status string `json:"status"`
		} `json:"items"`
	}
	if json.Unmarshal([]byte(raw), &ck) != nil || len(ck.Items) == 0 {
		return
	}
	covs, _ := o.store.ListCoverage(p.ID)
	var b strings.Builder
	b.WriteString("# 自述面差距表（v7.7.0 P3 引擎生成——checklist × coverage 投影，数字禁手写）\n\n| 条目 | 类 | 覆盖状态 | 差距 |\n|---|---|---|---|\n")
	gaps := 0
	for _, it := range ck.Items {
		status, where := "未覆盖", ""
		if it.Status == "deferred" || it.Status == "excluded" {
			status, where = "显式处置", it.Status
		} else {
			for _, c := range covs {
				hay := c.Endpoint + " " + c.VulnClass + " " + c.Notes
				if strings.Contains(hay, it.ID) || (it.Item != "" && strings.Contains(hay, truncateText(it.Item, 30))) {
					status = "已覆盖登记"
					where = fmt.Sprintf("%s/%s → %s", c.Endpoint[:min(30, len(c.Endpoint))], c.VulnClass, c.Status)
					break
				}
			}
		}
		if status == "未覆盖" {
			gaps++
		}
		b.WriteString(fmt.Sprintf("| %s %s | %s | %s | %s |\n", it.ID, truncateText(it.Item, 30), it.Class, status, where))
	}
	b.WriteString(fmt.Sprintf("\n差距合计：%d 条未覆盖（G2 门口径照常核验——本表只是投影）\n", gaps))
	_, _ = o.exec.WriteFile(p.ID, "deliverables/s4-自述面差距表.md", b.String())
	o.log(p, stageID, fmt.Sprintf("📋 自述面差距表已生成（未覆盖 %d/%d 条——G2 门照常核验）", gaps, len(ck.Items)))
}

// writeReportSkeleton v7.7.0 P3③：S8 开工生成 report.md 骨架（keyFigures + findings 分组 +
// 章节头）——模型只填充正文（守卫兼容：骨架先落根目录即满足 report 契约）。
func (o *Orchestrator) writeReportSkeleton(p *store.Project, stageID string) {
	if _, err := o.exec.ReadFile(p.ID, "report.md"); err == nil {
		return // 已有（重入）不覆盖
	}
	kf := o.keyFigures(p.ID)
	findings, _ := o.store.ListFindings(p.ID)
	var b strings.Builder
	b.WriteString("# 渗透测试报告（v7.7.0 P3 骨架——引擎生成，数字禁手写；模型填充正文）\n\n")
	b.WriteString("## 执行摘要\n\n（模型填充：整体风险、关键数字引用下表、最需关注三件事）\n\n")
	b.WriteString("## 测试范围与方法\n\n（模型填充）\n\n")
	b.WriteString("## 关键数字（引擎统计——直接引用，禁止手写）\n\n")
	if len(kf) > 0 {
		b.WriteString(fmt.Sprintf("- 端点数（去重）: %v\n- 覆盖矩阵单元数: %v\n- 发现数: %v\n- 证据文件数: %v\n- 时间线事件数: %v\n- 资产数: %v\n", kf["endpoints"], kf["coverage_units"], kf["findings"], kf["evidence_files"], kf["timeline_events"], kf["assets"]))
	}
	b.WriteString("\n## 发现详情\n\n")
	bySev := map[string][]*store.Finding{}
	var order []string
	for _, f := range findings {
		if _, ok := bySev[f.Severity]; !ok {
			order = append(order, f.Severity)
		}
		bySev[f.Severity] = append(bySev[f.Severity], f)
	}
	for _, sev := range []string{"高", "中", "低", "信息"} {
		for _, f := range bySev[sev] {
			b.WriteString(fmt.Sprintf("### %s（%s/%s，%s）\n\n%s\n\n复现：见 POC 原文对（poc/PoC-%s.md 或 detail 内嵌）\n\n", f.Title, sev, f.Confidence, f.ID, truncateText(f.Detail, 160), f.ID))
		}
	}
	b.WriteString("\n## 修复建议清单（带优先级——按 remediation 分组，缺失项待模型 update_finding 补写）\n\n")
	for _, sev := range []string{"高", "中", "低", "信息"} {
		for _, f := range bySev[sev] {
			if f.Remediation != "" {
				b.WriteString(fmt.Sprintf("- [%s] %s → %s\n", sev, truncateText(f.Title, 40), truncateText(f.Remediation, 80)))
			} else {
				b.WriteString(fmt.Sprintf("- [%s] %s →（remediation 缺失，待 update_finding 补写）\n", sev, truncateText(f.Title, 40)))
			}
		}
	}
	b.WriteString("\n## 清单外发现与盲区\n\n（模型填充：coverage 【清单外】条目 + deferred/needs_follow_up）\n\n")
	b.WriteString("## 汇报要点\n\n（模型填充：一页纸口径）\n")
	if _, werr := o.exec.WriteFile(p.ID, "report.md", b.String()); werr == nil {
		o.log(p, stageID, fmt.Sprintf("📄 report.md 骨架已生成（findings %d 条预填——模型填充正文）", len(findings)))
	}
}

// writeTimelineDraft v7.6.0（F3）：timeline 桶机械导出底稿（时间戳逐字保留、按时间正序）。
// 模型撰写攻击时间线/利用时间线时必须以本底稿为时间戳来源，人工叙述层只做归并与解读。
func (o *Orchestrator) writeTimelineDraft(p *store.Project, stageID string) {
	tl, err := o.store.ListTimeline(p.ID)
	if err != nil || len(tl) == 0 {
		return
	}
	sort.Slice(tl, func(i, j int) bool { return tl[i].CreatedAt.Before(tl[j].CreatedAt) })
	var b strings.Builder
	b.WriteString("# s7-时间线底稿（引擎机械导出 v7.6.0 F3）\n\n")
	b.WriteString("> 时间戳逐字取自引擎 timeline 桶（+08/+00 原样），按时间正序；本文件为攻击时间线/利用时间线的唯一时间戳来源，人工撰写的成稿与本底稿冲突时以本底稿为准。\n\n")
	b.WriteString("| # | 时间戳 | 阶段 | 事件 | 摘要 |\n|---|---|---|---|---|\n")
	for i, ev := range tl {
		b.WriteString(fmt.Sprintf("| %d | %s | %s | %s | %s |\n",
			i+1, ev.CreatedAt.Format("2006-01-02T15:04:05Z07:00"),
			strings.TrimSpace(ev.Stage), truncateText(ev.Event, 60), truncateText(strings.ReplaceAll(strings.ReplaceAll(ev.Detail, "\n", " "), "|", "\\|"), 120)))
	}
	rel := "deliverables/s7-时间线底稿-引擎导出.md"
	if full, werr := o.exec.WriteFile(p.ID, rel, b.String()); werr == nil {
		o.log(p, stageID, "🕰 时间线机械底稿已导出（F3，时间戳零漂移来源）: "+full)
		_, _ = o.store.AddTimeline(&store.TimelineEvent{ProjectID: p.ID, Stage: stageID,
			Event: "v7.6.0 F3 时间线底稿导出", Detail: fmt.Sprintf("%s（%d 事件，机械导出）", rel, len(tl))})
	}
}

// fiveStateRe v7.6.0（A3 增量）：交付物五态统计行的可机读形态（tested/deferred 相邻出现）。
var fiveStateRe = regexp.MustCompile(`tested\s*[=:]?\s*(\d+)[^\n]{0,24}deferred\s*[=:]?\s*(\d+)`)

// numericDriftHint v7.6.0（A3 增量）：交付物手写五态数字与引擎实算不一致时落时间线提示
// （提示级非拦截——拦截形态待 coverage-contract schema 固化后再启，见优化方案 A3 遗留项）。
func (o *Orchestrator) numericDriftHint(p *store.Project, stageID string, stats map[string]int) {
	text := o.deliverablesText(p.ID)
	matches := fiveStateRe.FindAllStringSubmatch(text, -1)
	if len(matches) == 0 {
		return
	}
	var driftMatches [][]string
	for _, m := range matches {
		tc, dc := m[1], m[2]
		if tc == strconv.Itoa(stats["tested"]) && dc == strconv.Itoa(stats["deferred"]) {
			return // 任一处与实算一致即视为已同步
		}
		// v7.6.0 复核修复：仅比对「C27/五态/处置分布」语境的统计行——对账表存在多套
		// tested/deferred 口径（逐类对账表行数 vs C27 类分布），无语境守卫会对不同维度
		// 数字误报漂移（幻觉噪音防控）。
		idx := strings.Index(text, m[0])
		lo, hi := idx-40, idx+len(m[0])+40
		if lo < 0 {
			lo = 0
		}
		if hi > len(text) {
			hi = len(text)
		}
		ctxText := text[lo:hi]
		if !strings.Contains(ctxText, "C27") && !strings.Contains(ctxText, "五态") && !strings.Contains(ctxText, "处置分布") {
			continue
		}
		driftMatches = append(driftMatches, m)
	}
	if len(driftMatches) == 0 {
		return
	}
	m := driftMatches[0]
	detail := fmt.Sprintf("交付物手写五态 tested=%s deferred=%s 与引擎实算 tested=%d deferred=%d 不一致（A3）——S8 报告与质量复核以引擎实算/核对注记为权威口径，建议修订交付物汇总行", m[1], m[2], stats["tested"], stats["deferred"])
	_, _ = o.store.AddTimeline(&store.TimelineEvent{ProjectID: p.ID, Stage: stageID,
		Event: "v7.6.0 A3 数字漂移提示（非拦截）", Detail: truncateText(detail, 400)})
	o.log(p, stageID, "⚠ A3 数字漂移提示：交付物五态手写值与引擎实算不一致（详见时间线，非拦截）")
}

// isExecutableScriptPath v7.6.0（E7）：脚本类落盘路径判定（扩展名白名单，通用形态规则）。
func isExecutableScriptPath(path string) bool {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".sh", ".bash", ".py", ".pl", ".rb":
		return true
	}
	return false
}

// findingRevRe v7.6.0（A4）：交付物中「修订要求 + F- 编号」同句形态（非贪婪间隔 ≤12 字符——贪婪会把首个 F- 编号吞进间隔误捕获后续编号，单测实证后修正）。
var findingRevRe = regexp.MustCompile(`(?:修订|改写|修正|更新|回写|根因修正)[^。\n]{0,12}?(F-[0-9A-Fa-f]{6,12})`)

// findingSyncIssues v7.6.0（A4 权威库同步）：交付物要求修订某 finding 而时间线无「发现修订」
// 回写记录 → 收口拦截——实证 F-F6D2DD02C6 被差分抽样交付物明确要求修订却未回写（S8 按库
// 写报告将失实，实测报告 §A4）。豁免口径：交付物同文出现「维持原判」+ 该编号。
func (o *Orchestrator) findingSyncIssues(p *store.Project, stageID string) []string {
	// v7.6.0 复核修复：语料限定本阶段交付物（排除上游阶段产物）——上游交付物中的历史
	// 修订表述不构成对当前阶段的回写要求，全量语料会造成跨阶段误报。
	excl := map[string][]string{"s5": {"s4-"}, "s6": {"s4-", "s5-"}, "s7": {"s4-", "s5-", "s6-"}, "s8": {"s4-", "s5-", "s6-", "s7-"}}
	text := o.deliverablesTextExcluding(p.ID, strings.Join(excl[stageID], ","))
	matches := findingRevRe.FindAllStringSubmatch(text, -1)
	if len(matches) == 0 {
		return nil
	}
	tl, _ := o.store.ListTimeline(p.ID)
	seen := map[string]bool{}
	var issues []string
	for _, m := range matches {
		fid := strings.ToUpper(m[1])
		if seen[fid] {
			continue
		}
		seen[fid] = true
		revised := false
		for _, ev := range tl {
			if ev.Event == "发现修订" && strings.Contains(strings.ToUpper(ev.Detail), fid) {
				revised = true
				break
			}
		}
		if revised {
			continue
		}
		if strings.Contains(text, "维持原判") && strings.Contains(text, fid) {
			continue // 显式维持原判声明在案
		}
		issues = append(issues, fmt.Sprintf("v7.6.0 A4 权威库同步：交付物要求修订 %s，但时间线无「发现修订」回写记录——执行 update_finding{id:%q, reason:\"<实测证据>\"}，或在交付物同句显式写「维持原判：理由」后重收口", fid, fid))
	}
	return issues
}

// gateBlockCtx v7.6.0（B3）：收口确定性门连击追踪与时间盒裁决。
// 返回 (债务文本, 导师会诊注, 时间盒超时)。同指纹连续 ≥2 轮 → 拦截消息附导师会诊（自动触发，
// 复用 consultExpert/adviser）；首次拦截起 15 分钟仍未收敛 → 转 quality-pending 人工通道
// （债务全量落时间线+Review 由调用方拼接，不再阻塞流水线——对照 某实战项目 S4 收口
// 搏斗 30.9 分钟的实测教训，实测报告 §B3）。
func (o *Orchestrator) gateBlockCtx(ctx context.Context, p *store.Project, stageID string, issues []string) (string, string, bool) {
	fp := fmt.Sprintf("%x", sha256.Sum256([]byte(strings.Join(issues, "\n"))))[:12]
	state := p.StageStates[stageID]
	if state == nil {
		return "", "", false
	}
	now := time.Now()
	if state.FirstGateBlockAt == "" {
		state.FirstGateBlockAt = now.Format(time.RFC3339)
	}
	if state.GateFP == fp {
		state.GateStreak++
	} else {
		state.GateFP = fp
		state.GateStreak = 1
	}
	_ = o.store.SaveProject(p)
	if t0, err := time.Parse(time.RFC3339, state.FirstGateBlockAt); err == nil && now.Sub(t0) > 15*time.Minute {
		debt := fmt.Sprintf("B3 收口时间盒超时（首拦 %s 起 >15m 未收敛）转人工通道【quality-pending：确定性门仍有 %d 项——S8 收口前逐项复核】：%s",
			state.FirstGateBlockAt, len(issues), truncateText(strings.Join(issues, "；"), 400))
		_, _ = o.store.AddTimeline(&store.TimelineEvent{ProjectID: p.ID, Stage: stageID,
			Event: "v7.6.0 B3 收口时间盒转人工通道", Detail: truncateText(debt, 600)})
		o.log(p, stageID, "⏱ B3 收口时间盒超时——确定性门剩余项转 quality-pending 人工通道（债务留痕，不再阻塞）")
		return debt, "", true
	}
	note := ""
	if state.GateStreak >= 2 {
		note = o.gateMentorNote(ctx, p, stageID, issues)
	}
	return "", note, false
}

// gateMentorNote v7.6.0（B3）：连击 ≥2 自动导师会诊（adviser 角色，25s 超时，失败静默）。
func (o *Orchestrator) gateMentorNote(ctx context.Context, p *store.Project, stageID string, issues []string) string {
	cctx, cancel := context.WithTimeout(ctx, 25*time.Second)
	defer cancel()
	ans, err := o.consultExpert(cctx, p, stageID, "adviser",
		"收口确定性门连续 2 轮拦截同一组问题，请给出每项的最小修复路径与常见错误形态（按拦截项逐条，可执行）：\n- "+strings.Join(issues, "\n- "))
	if err != nil {
		return ""
	}
	o.log(p, stageID, "🧑‍🏫 B3 连击自动导师会诊完成")
	return truncateText(ans, 800)
}

func (o *Orchestrator) deterministicGate(p *store.Project, stageID string) []string {
	var issues []string
	// v6.1.0（S1 修复方案④⑤⑪）：S1 确定性门并入 deterministicGate——反思 PASS 名单、
	// 三振降级路径与 budget auto_close 路径共用同一机械校验（四件套/逐目标/OOB 条件门）。
	if stageID == "s1" && o.guardEnabled(func(g *config.GuardConfig) *bool { return g.EnforceS1Closure }) {
		issues = append(issues, o.s1ClosureIssues(p)...)
	}
	// v6.2.0（S2 修复方案①）：S2 确定性门并入 deterministicGate——与 s1 同机制（反思 PASS 名单、
	// 三振降级路径与 budget auto_close 路径共用同一机械校验）：攻击面地图/拓扑重建非空壳、
	// checklist.json 可解析（fail-closed）、多目标逐目标归宿。
	if stageID == "s2" && o.guardEnabled(func(g *config.GuardConfig) *bool { return g.EnforceS2Closure }) {
		issues = append(issues, o.s2ClosureIssues(p)...)
	}
	// v6.6.0（SP-①）专项逐目标对账门：多目标项目 specA/specB1/specB2 收口时 targetCoverageRecon
	//（与 S4-9/S5 批次6 同口径——修复前专项是逐目标漏测的对账盲区）。语料=本专项阶段 coverage notes
	// + 交付物（deliverablesTextExcluding 排除 s4- 产物防自匹配，与 S5-① 同款）；matched=0 提示级
	// 留痕不拦（CIDR/描述性目标合法），matched≥1 且有 missing → 拦截，文案即修补指引。
	if stageID == "specA" || stageID == "specB1" || stageID == "specB2" {
		// v6.6.0（SP-②）专项确定性收口门并入 deterministicGate——与 s1/s2 同机制（反思 PASS 名单、
		// 三振降级路径与 budget auto_close 路径共用同一机械校验）。
		if o.guardEnabled(func(g *config.GuardConfig) *bool { return g.EnforceSpecClosure }) {
			issues = append(issues, o.specClosureIssues(p, stageID)...)
		}
		if o.guardEnabled(func(g *config.GuardConfig) *bool { return g.EnforceSpecTargetRecon }) && (o.cfg == nil || o.cfg.Engine.PerTargetRounds > 0) {
			if targets := splitProjectTargets(p); len(targets) > 1 {
				var cb strings.Builder
				if cov, cerr := o.store.ListCoverage(p.ID); cerr == nil {
					for _, c := range cov {
						if c.Stage != stageID {
							continue
						}
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
				missing, matched := targetCoverageRecon(targets, cb.String(), o.deliverablesTextExcluding(p.ID, "s4-"))
				if matched == 0 {
					o.log(p, stageID, fmt.Sprintf("⚠ %s 逐目标对账零命中：%d 个目标的覆盖/交付物语料均未出现目标串——若目标以 CIDR/描述形态登记，请在覆盖 notes 或交付物显式写「目标-实例映射」，否则逐目标门对本项目不生效", stageID, len(targets)))
				} else if matched >= 1 && len(missing) > 0 && len(missing) < len(targets) {
					issues = append(issues, fmt.Sprintf(
						"%s 分段收口对账：%d/%d 个目标既无覆盖登记也未列入待续清单/档案目标（%s）——按目标分组补测，或将未测目标写入待续清单（分组交付物约定 deliverables/%s-<目标或组名>.md，S8 报告承接合并），再收口",
						stageID, len(missing), len(targets), truncateText(strings.Join(missing, "、"), 120), stageID))
				}
			}
		}
	}
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
	// v6.3.0（S3-①）：S3 确定性收口门并入——威胁模型/测试计划存在性 + 上游承接留痕
	//（complete_stage 前置门与反思 PASS/三振/auto_close 路径共用同一机械门，与 s1/s2 同机制）
	if stageID == "s3" {
		if o.guardEnabled(func(g *config.GuardConfig) *bool { return g.EnforceS3Closure }) {
			issues = append(issues, o.s3ClosureIssues(p)...)
		}
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
		// v6.0.1 C29 覆盖边界门（fix-plan 20261122 P6）：报告必须含结构化《覆盖边界》章节
		//（边界项/量化分母/解锁条件/来源），防"已全面覆盖"式误导（实证：认证后 0%、
		// 10 站不可达等边界散落 5+ 份交付物，报告层无从核对）。
		issues = append(issues, o.coverageBoundaryIssues(p)...)
		// v6.0.4 P11：测试目的/成功标准对照——用户在创建页输入的「测试目的/成功标准」必须被
		// 报告回应（原实现仅一行进上下文、S8 门不校验=用户输入无着落）。有输入且报告既不引用
		// 原文也无对照小节 → 拦截，指引补《结论对照成功标准》小节。
		issues = append(issues, o.successCriteriaIssues(p)...)
	}
	// v4.4 批次4 反思门判据抽查：高危确证未引用 evidence-standard 判据 → 引擎直接降级疑似
	//（evidenceCriteriaIssues 内部变更并留痕）。v6.6.0（SP-⑥）：从 s4/s5 上移为含三专项——
	// record_finding 工具描述向全员承诺「未引判据的高危确证会被引擎自动降级为疑似」，而本门此前
	// 仅 s4/s5 执行（承诺面与执行面不一致）；specA 的高危确证（A4 注入成功/A7 工具滥用）恰是
	// 自评膨胀高发面，vulnerableEvidenceIssues（v5.8.0 Top#9 语义门）同批扩名单。
	if stageID == "s4" || stageID == "s5" || isSpecStage(stageID) {
		issues = append(issues, o.evidenceCriteriaIssues(p, stageID)...)
		issues = append(issues, o.vulnerableEvidenceIssues(p, stageID)...) // v5.8.0 Top#9 语义门
	}
	if stageID == "s4" || stageID == "s5" {
		if cov, _ := o.store.ListCoverage(p.ID); len(cov) == 0 && stageFindings == 0 {
			issues = append(issues, "覆盖矩阵与本阶段发现均为空——按 loop-core 深度测试纪律补测或如实说明前提不成立")
		}
		// v5.9.0（方案 P1-3）：IDOR candidate 禁直升——覆盖矩阵存在 candidate_idor_anonomous
		// 候选时，对应端点的 IDOR「确证」发现降级疑似（对象归属二次确认前置）。
		issues = append(issues, o.idorCandidateIssues(p)...)
		// v4.4 批次6 S4/S5 分段收口对账（v6.4.0 S4-⑨ 阈值收敛 + S5 逐目标门）：
		// 多目标且至少 1 个目标已被真实覆盖（说明按目标推进过）时，未覆盖且未列入待续清单/
		// 档案目标的目标 → 拦截。v6.4.0 阈值由 matched≥2 收敛为 matched≥1 且 missing<总数：
		// 修复 2 目标项目 matched=1/missing=1 的旧盲区（目标数越小缝隙占比越大）；
		// 全零覆盖仍由零产出门兜底，避免对语料完全无法匹配的边缘项目误拦——拦截文案即修补
		// 指引（补测或写入待续清单），补写语料后门即放行，误拦自愈。
		// 分组产出约定 deliverables/s4-<目标或组名>.md（S8 报告承接合并）。
		if o.cfg == nil || o.cfg.Engine.PerTargetRounds > 0 {
			reconOn := stageID == "s4" ||
				(stageID == "s5" && o.guardEnabled(func(g *config.GuardConfig) *bool { return g.EnforceS5TargetRecon }))
			if reconOn {
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
						// v6.5.0（S5-①）：s5 语料排除 s4- 交付物——S4 分组交付物按 S4-9 门强制
						// 逐目标产出，混入 S5 语料会让未动目标借 S4 留痕自动放行（同族问题
						// v3HandoverIssues 已排除 s4 产物，本门补齐同款口径）；s4 门消费自己的
						// 交付物语料不变。
						deliv := o.deliverablesText(p.ID)
						if stageID == "s5" {
							deliv = o.deliverablesTextExcluding(p.ID, "s4-")
						}
						missing, matched := targetCoverageRecon(targets, cb.String(), deliv)
						if matched == 0 {
							// v6.5.0（S5-①）：逐目标零命中从静默放行改为提示级留痕（不拦截）——
							// 语料完全不含目标串（CIDR/描述性目标常态）时门失效形态收口可见，
							// 提示模型显式写目标-实例映射后门即恢复生效。
							o.log(p, stageID, fmt.Sprintf("⚠ %s 逐目标对账零命中：%d 个目标的覆盖/交付物语料均未出现目标串——若目标以 CIDR/描述形态登记，请在覆盖 notes 或交付物显式写「目标-实例映射」（如「10.0.0.0/24 → 逐 IP」），否则逐目标门对本项目不生效", strings.ToUpper(stageID), len(targets)))
						} else if matched >= 1 && len(missing) > 0 && len(missing) < len(targets) {
							issues = append(issues, fmt.Sprintf(
								"%s 分段收口对账：%d/%d 个目标既无覆盖登记也未列入待续清单/档案目标（%s）——按目标分组补测，或将未测目标写入待续清单（分组交付物约定 deliverables/%s-<目标或组名>.md，S8 报告承接合并），再收口",
								strings.ToUpper(stageID), len(missing), len(targets), truncateText(strings.Join(missing, "、"), 120), stageID))
						}
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
		// v6.0.1（fix-plan 20261122）三个新门：类级处置（C27）/候选归档（C28）/零产出对账（C31）
		issues = append(issues, o.classDispositionIssues(p, stageID)...)
		issues = append(issues, o.openCandidateIssues(p)...)
		issues = append(issues, o.incompleteBatchIssues(p)...)
		// v7.6.0（A4 权威库同步）：交付物修订要求 ↔ update_finding 回写对账——实证
		// F-F6D2DD02C6 被交付物要求修订但权威库未回写（S8 按库写报告将失实，实测报告 §A4）。
		if stageID == "s5" || stageID == "s6" || stageID == "s7" || stageID == "s8" {
			issues = append(issues, o.findingSyncIssues(p, stageID)...)
		}
		// v6.3.0（S3-④/S3-⑤，仅 s4）：T-xx 计划承接门（S3 测试计划条目收口前显式归宿）+
		// 端点表↔覆盖矩阵运行时门（v5.1 硬门从 eval 离线层上移；S3 端点表是 Authz-Diff 直接输入）
		if stageID == "s4" {
			if o.guardEnabled(func(g *config.GuardConfig) *bool { return g.EnforcePlanHandover }) {
				issues = append(issues, o.planHandoverIssues(p)...)
			}
			if o.guardEnabled(func(g *config.GuardConfig) *bool { return g.EnforceEndpointMatrix }) {
				issues = append(issues, o.endpointMatrixIssues(p)...)
			}
			// v7.6.0（A6 nuclei 双轨留痕强制）：文档 §四 S4 双轨制之①（自动化扫描）的轨道状态
			// 必须在交付物语料中显式声明——实证 某实战项目 nuclei 静默跳过零留痕、
			// 某实战项目 豁免理由只在执行流文本未进交付物受限项节（实测报告 §A6）。
			issues = append(issues, o.nucleiTrackIssues(p)...)
			// v7.6.0（D3② 技能载入硬字段）：「动手前先查技能库」的机械兜底——实证 S4 零载入。
			issues = append(issues, o.skillLoadIssues(p, stageID)...)
			// v6.4.0（S4-⑦，仅 s4）：威胁清单回填对账门（S4-10 extends/replaces/creates 留痕 +
			// TH 引用防幻觉 + 清单外发现处置留痕；guard 检查内置于函数）
			issues = append(issues, o.threatBackfillIssues(p)...)
		}
		// v6.4.0（S4-⑤⑥，仅 s5）：S4 移交承接门——V3 两清单（正常收口/代收口双路径落
		// StageState）+ route=browser-auth 认证路线移交项在 S5 语料须有承接留痕
		//（s5.md:14 承接反蒸发三态映射的机械对账；guard 检查内置于函数）。
		if stageID == "s5" {
			issues = append(issues, o.v3HandoverIssues(p)...)
			// v6.6.0 增补（核对轮）：spec 移交项承接提示级核对（不拦截，与 S5-①/S5-⑩ 提示级同口径）——
			// SP-③ 专项移交块为呈现性注入（承接由 S7 清点兜底），本提示只让「S5 对 spec 移交项
			// 零承接」的失效形态在收口时可见。
			if n := o.specHandoverHintCount(p); n > 0 {
				o.log(p, stageID, fmt.Sprintf("💡 专项移交承接提示：%d 条 specA/specB1/specB2 收口的就绪未投递/已批未用条目在 S5 语料无承接留痕——按「专项就绪移交」清单执行或显式移交待续清单（S7 清点三选一口径），承接留痕写进 S5 交付物映射表", n))
			}
		}
	}
	// v6.0.1 C27 收口件（s6）：存在判定表的项目必须已产出《27类收口对账表》且 27 行有处置态
	if stageID == "s6" {
		issues = append(issues, o.reconciliationTableIssues(p)...)
		issues = append(issues, o.openCandidateIssues(p)...) // open 候选同样不得带进 S6
		// v6.7.0（S6-④）：s6 逐目标对账门（多目标）——targetCoverageRecon 此前接线 s4/s5/specs
		// 唯独缺 s6：多目标项目 S6 只测 A 目标横向、B/C 零承接也能干净收口。语料 = s6 阶段覆盖
		// notes + 交付物语料排除 s4-/s5- 上游分组产物（S5-① 教训对称：两阶段分组交付物都按门
		// 强制逐目标产出，混入 s6 语料会让未动目标借上游留痕自动放行）。阈值与 s5 完全对齐：
		// matched≥1 且 missing<总数 → 拦截（文案即修补指引：补测或写 s6 分组待续清单）；
		// matched=0 → 提示级留痕不拦（CIDR/描述性目标合法）。
		if o.guardEnabled(func(g *config.GuardConfig) *bool { return g.EnforceS6TargetRecon }) &&
			(o.cfg == nil || o.cfg.Engine.PerTargetRounds > 0) {
			if targets := splitProjectTargets(p); len(targets) > 1 {
				var cb strings.Builder
				if cov, cerr := o.store.ListCoverage(p.ID); cerr == nil {
					for _, c := range cov {
						if c.Stage != "s6" {
							continue
						}
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
				deliv := o.deliverablesTextExcluding(p.ID, "s4-,s5-")
				missing, matched := targetCoverageRecon(targets, cb.String(), deliv)
				if matched == 0 {
					o.log(p, stageID, fmt.Sprintf("⚠ S6 逐目标对账零命中：%d 个目标的覆盖/交付物语料均未出现目标串——若目标以 CIDR/描述形态登记，请在覆盖 notes 或交付物显式写「目标-实例映射」，否则逐目标门对本项目不生效", len(targets)))
				} else if matched >= 1 && len(missing) > 0 && len(missing) < len(targets) {
					issues = append(issues, fmt.Sprintf(
						"S6 分段收口对账：%d/%d 个目标既无覆盖登记也未列入待续清单/档案目标（%s）——按目标分组补测，或将未测目标写入待续清单（分组交付物约定 deliverables/s6-<目标或组名>.md，含承接自 s5-<目标>.md 的待续项，S8 报告承接合并），再收口",
						len(missing), len(targets), truncateText(strings.Join(missing, "、"), 120)))
				}
			}
		}
		// v6.7.0（S6-⑥）：s6 命名交付物条件核验——hasFoothold（S4/S5/S6 确证立足点信号）的项目
		// 收口要求《权限矩阵》与《横向路径图》（兼容合并文件名形态）或 N/A 声明；无立足点项目
		// 零要求（20/48 零 s6 交付物中的合法跳过者行为不变）。永远开放 N/A 兜底，不逼造假产出。
		if o.guardEnabled(func(g *config.GuardConfig) *bool { return g.EnforceS6Deliverables }) && o.hasFoothold(p) {
			issues = append(issues, o.s6DeliverableIssues(p)...)
		}
		// v6.5.0（S5-⑩，方案标注「可选」项在本批补齐）：S5→S6 承接提示级留痕（不拦截）——
		// S5 收口的 V3 两清单非空且 S6 语料（s6 阶段覆盖 notes + s6- 交付物）对条目零引用时
		// 输出提示，指引按价值消费或显式移交；承接质量仍由 s7 VT 清点门与 s8 报告门兜底，
		// 本门只让「零承接」形态收口可见（与 S5-① matched=0 提示级口径一致）。
		if st5 := p.StageStates["s5"]; st5 != nil && (len(st5.V3Ready) > 0 || len(st5.V3L2) > 0) {
			var corpus strings.Builder
			if cov, cerr := o.store.ListCoverage(p.ID); cerr == nil {
				for _, c := range cov {
					if c.Stage == "s6" {
						fmt.Fprintf(&corpus, "%s\x00%s\x00%s\x00", c.Endpoint, c.VulnClass, c.Notes)
					}
				}
			}
			if names, derr := o.exec.ListDir(p.ID, "deliverables"); derr == nil {
				for _, rel := range names {
					base := filepath.Base(rel)
					if !strings.HasPrefix(base, "s6-") {
						continue
					}
					if !strings.HasSuffix(rel, ".md") && !strings.HasSuffix(rel, ".txt") && !strings.HasSuffix(rel, ".json") {
						continue
					}
					if raw, rerr := o.exec.ReadFile(p.ID, rel); rerr == nil {
						corpus.WriteString(raw)
						corpus.WriteString("\x00")
					}
				}
			}
			nc := normCovText(corpus.String())
			unref := 0
			for _, items := range [][]string{st5.V3Ready, st5.V3L2} {
				for _, it := range items {
					if strings.TrimSpace(it) == "" {
						continue
					}
					if key := handoverTraceKey(it); key != "" && !strings.Contains(nc, key) {
						unref++
					}
				}
			}
			if unref > 0 {
				o.log(p, stageID, fmt.Sprintf("💡 S5→S6 承接提示：%d 条 S5 收口 V3 清单条目在 S6 语料（s6 覆盖 notes / s6- 交付物）无引用——按价值消费（横向/凭据复用/横向路径图）或显式移交（S7 清点三选一口径），承接留痕写进 s6 交付物", unref))
			}
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
	// v6.9.0（S8-③）反向对账门：报告条目 ↔ findings 库 1:1 的另一半。正向门（上方 R 条目数
	// ≤findings）拦「报告多记」；本门拦「发现漏报」——逐条 findings 检查其归一化标题前 24 字符
	// 或 F- 编号是否出现在 report.md。语料只认报告本身，不吃上游交付物（规避 v6.8.0 S7-① 同款
	// 语料污染：上游文件天然含端点关键词，会让对账被「天然满足」）。未命中=报告/定级表无归宿
	// 留痕，列出漏项清单（补 R-xx / 列入《待验证》小节 / 定级表映射注明「并入 R-xx」——同根因
	// 合并合法）。guard enforce_s8_finding_report_recon（默认 true；false 回退旧口径仅正向门）。
	if stageID == "s8" && o.guardEnabled(func(g *config.GuardConfig) *bool { return g.EnforceS8FindingReportRecon }) {
		if raw, rerr := o.exec.ReadFile(p.ID, "report.md"); rerr == nil {
			reportNorm := normCovText(raw)
			var unmapped []string
			for _, f := range findings {
				if f.ID == "" {
					continue
				}
				nt := normCovText(f.Title)
				key := nt
				if r := []rune(key); len(r) > 24 { // 与双记门同口径：前 24 归一化字符（对称半边）
					key = string(r[:24])
				}
				if key != "" && strings.Contains(reportNorm, key) {
					continue
				}
				if strings.Contains(reportNorm, strings.ToLower(f.ID)) { // F- 编号直引（映射表/待验证小节合法归宿）
					continue
				}
				unmapped = append(unmapped, f.ID+" "+truncateText(f.Title, 40))
			}
			if len(unmapped) > 0 {
				issues = append(issues, fmt.Sprintf(
					"反向对账（v6.9.0 S8-③）：%d 条 findings 在 report.md 无归宿留痕（%s）——为每条漏项补 R-xx 条目 / 列入《待验证》小节 / 在定级表合并映射注明「并入 R-xx」（同根因合并合法），禁止静默省略",
					len(unmapped), truncateText(strings.Join(unmapped, "；"), 240)))
			}
			// v6.9.0 S8-⑤ 消费（字段优先、文本回退）：已登记 target_ref 的发现，其目标串
			//（canonicalTargetKey 归一化——scheme/路径差异不误拦）须在报告中呈现——报告按目标
			// 组织章节时该目标整组缺失即「漏并目标分组」的字段级观测；未登记 target_ref 的发现
			// 不受影响（归宿仍走上方标题/F- 编号文本匹配）。guard 同 S8-③ 总开关。
			seenTgt := map[string]bool{}
			var missingTgt []string
			for _, f := range findings {
				t := strings.TrimSpace(f.TargetRef)
				if t == "" {
					continue
				}
				tk := normCovText(canonicalTargetKey(t))
				if tk == "" || seenTgt[tk] {
					continue
				}
				seenTgt[tk] = true
				if !strings.Contains(reportNorm, tk) {
					missingTgt = append(missingTgt, t)
				}
			}
			if len(missingTgt) > 0 {
				issues = append(issues, fmt.Sprintf(
					"反向对账·目标呈现（v6.9.0 S8-⑤ 字段优先）：%d 个已归属目标在 report.md 无呈现（%s）——报告按目标组织章节须含该目标（或在定级表映射/盲区章说明未呈现原因），禁止静默省略",
					len(missingTgt), truncateText(strings.Join(missingTgt, "；"), 200)))
			}
		}
	}
	// v3.8.7 G3 待续清单回灌门：前序阶段遗留的 needs_follow_up 在 s7 收口时必须逐项处置
	//（已补测 / 范围外 / 移交复测，均需在 s7 交付物或报告文本中引用端点关键词留痕），
	// 防「待续清单原样传递四个阶段无人执行」。
	if stageID == "s7" {
		issues = append(issues, o.followUpDispositionIssues(p)...)
		// v6.8.0（S7-⑥）：C28 open 候选归位门扩名 s7——候选账本「open 不出阶段」口径贯穿
		// s4/s5/s6/s7 四个执行阶段（此前 s7 收口可留 open 候选无声进终态）；s7 工具面完整
		//（update_candidate 可用），收口前三态归位（finding/vt/excluded）成本极低。
		issues = append(issues, o.openCandidateIssues(p)...)
		// v6.7.0（S6-②）：提示级四元组完整性核对（不拦截）——s6 交付物中存在四元组登记语义行
		//（位置/路径 + 指纹 双特征）但该行缺「建议清理命令」或「验证命令」字段时输出 💡 提示，
		// 让残缺四元组在 S7 收口时可见（拦截由反思门 S6-⑤ 节与人工兜底，机械层只做提示级——
		// 自由文本格式差异大，硬拦会产生格式误拦）。
		if names, derr := o.exec.ListDir(p.ID, "deliverables"); derr == nil {
			for _, rel := range names {
				base := filepath.Base(rel)
				if !strings.HasPrefix(base, "s6-") || !strings.HasSuffix(base, ".md") {
					continue
				}
				raw, rerr := o.exec.ReadFile(p.ID, rel)
				if rerr != nil {
					continue
				}
				missClean, missVerify := 0, 0
				for _, ln := range strings.Split(raw, "\n") {
					ln = strings.TrimSpace(ln)
					if ln == "" || !strings.Contains(ln, "指纹") ||
						(!strings.Contains(ln, "位置") && !strings.Contains(ln, "路径")) {
						continue
					}
					if !strings.Contains(ln, "建议清理命令") {
						missClean++
					}
					if !strings.Contains(ln, "验证命令") {
						missVerify++
					}
				}
				if missClean+missVerify > 0 {
					o.log(p, stageID, fmt.Sprintf("💡 四元组核对提示（S6-② 提示级）：%s 存在疑似残缺的持久化/驻留登记行——缺「建议清理命令」%d 行、缺「验证命令」%d 行——S7-2 逐项核对补齐后再并入《需人工清理清单》", base, missClean, missVerify))
				}
			}
		}
	}
	// v6.8.2（核对轮）：S7 收口对全阶段未清点 V3Ready 条目的提示级核对（不拦截）——
	// S7-⑤ 清点块解决「在场」，A2 门只覆盖 VT 化条目、V4 门只覆盖 L2 工单，纯文本 V3Ready
	//（未 record_vt、非 L2）此前收口零机械暴露；本提示与 S6-② 四元组提示、S5 spec 承接提示
	// 同口径，只让失效形态收口可见。若条目已在 S5/S6 显式移交且未在 s7 复写留痕，属可豁免
	// 误提示（提示文案已注明）。
	if stageID == "s7" {
		if n := o.s7V3ReadyHintCount(p); n > 0 {
			o.log(p, stageID, fmt.Sprintf("💡 就绪移交清点提示：%d 条 V3Ready 条目（s4/s5/三专项）在 s7 语料（清点映射/待续处置/清理清单/VT 台账）无处置留痕——按「就绪移交清点」清单三选一处置并留痕；若已在 S5/S6 显式移交可忽略本提示，或补一行清点映射防重复提示", n))
		}
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
// v6.2.0 备注：fail-open 缺口已在源头补齐——s2ClosureIssues（S2 收口确定性门）对存在但不可解析的
// checklist.json 在 S2 收口当轮拦截，坏 JSON 不再能流到本函数静默失效。
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
		// v6.4.0（S4-⑫）fail-closed 补口：文件存在但 JSON 解析失败/无条目 → 拦截（原实现
		// return nil 静默放行=自述面覆盖下限失效）。v6.2.0 已在 S2 收口门堵源头（坏 JSON
		// 出不了 S2），本口兜住「S2 门关闭/清单收口后被改坏」的组合路径。
		return []string{"v6.4.0 G2 门：checklist.json 存在但不可解析或无条目——自述面覆盖下限失效（S2-9 产出契约），修复 JSON（{items:[{id,item,…}]} 或数组）或确认清单作废并移除文件后重新收口"}
	}
	cov, _ := o.store.ListCoverage(p.ID)
	norms := buildCovNorms(cov)
	var issues []string
	dispositioned, uncovered := 0, 0
	for _, it := range items {
		// v7.4.2 状态归一化：covered 同义态（tested/executed/done…）按 covered 计，仅显式
		// 处置态计入延期/排除——旧实现把一切非 covered 字面值整桶计入「延期/排除」，诱导
		// 执行侧改写状态过门（字段整容对抗）；归一化后门只认语义，实测结论无需改写即可过门。
		switch cls := checklistStatusClass(it.Status); cls {
		case "covered":
			continue
		case "dispositioned":
			if strings.TrimSpace(it.Reason) == "" {
				issues = append(issues, fmt.Sprintf("自述清单条目 %s「%s」标注 status=%s 但缺 reason——在 checklist.json 补写处置理由后重新收口", it.ID, it.Item, it.Status))
			}
			dispositioned++
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

// checklistStatusClass 自述清单 status 语义归一化（v7.4.2）：
// 返回 "covered"（covered 及其同义实测态）/ "dispositioned"（显式延期/排除/阻断类处置态）/
// ""（空值或未知值——回落覆盖矩阵对账，实测事实优先于标签）。
var coveredStatusSynonyms = map[string]bool{
	"covered": true, "tested": true, "executed": true, "done": true,
	"verified": true, "measured": true, "completed": true, "pass": true, "passed": true,
}

var dispositionedStatusSynonyms = map[string]bool{
	"deferred": true, "excluded": true, "skipped": true, "out_of_scope": true, "blocked": true,
}

func checklistStatusClass(status string) string {
	s := strings.ToLower(strings.TrimSpace(status))
	if s == "" {
		return ""
	}
	if coveredStatusSynonyms[s] {
		return "covered"
	}
	if dispositionedStatusSynonyms[s] {
		return "dispositioned"
	}
	return ""
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
	// v6.9.0（S8-⑦）：关键数字表（引擎统计待人工确认）——s8.md「关键数字表禁止手写」承诺的
	// 数据来源。审计实证手写数字与台账偏差（128/124、26/23、69/73 三案）：报告执行摘要/定级表
	// 引用的数字从此处誊写，与台账同源可复核；引擎未覆盖的维度由人工补充。
	// 统计实现抽为 keyFigures——Web API（本函数）与 s8 上下文块（模型消费）共用，防口径漂移。
	out["key_figures"] = o.keyFigures(projectID)
	// v6.0.1 C29：覆盖边界初稿（引擎统计待人工确认）——供操作者/模型写 report.md《覆盖边界》章节
	if p, perr := o.store.GetProject(projectID); perr == nil {
		out["coverage_boundary_draft"] = o.coverageBoundaryDraft(p)
	}
	return out
}

// keyFigures v6.9.0（S8-⑦）：关键数字六维统计（引擎统计待人工确认）——纯统计无副作用，
// ReconciliationPublic（Web/API 对人）与 buildContextPack s8 分支（上下文对模型）共用同一实现。
// 模型不能调 HTTP API：只落在 reconciliation 的数字对模型不可达，s8.md「禁止手写」仍是空承诺——
// 上下文块是模型侧的真实数据通道（S8-⑦ 第三轮核对补齐）。
func (o *Orchestrator) keyFigures(projectID string) map[string]any {
	findings, _ := o.store.ListFindings(projectID)
	covAll, _ := o.store.ListCoverage(projectID)
	epSet := map[string]bool{}
	for _, c := range covAll {
		epSet[store.NormCoverageEndpoint(c.Endpoint)] = true
	}
	sevConf := map[string]int{}
	for _, f := range findings {
		sevConf[f.Severity+"/"+f.Confidence]++
	}
	evFiles := 0
	if evNames, eerr := o.exec.ListDir(projectID, "evidence"); eerr == nil {
		evFiles = len(evNames)
	}
	tl, _ := o.store.ListTimeline(projectID)
	assets, _ := o.store.ListAssets(projectID)
	return map[string]any{
		"note":            "引擎统计待人工确认——报告关键数字以此为誊写来源；引擎未覆盖的维度人工补充",
		"endpoints":       len(epSet),
		"coverage_units":  len(covAll),
		"findings":        len(findings),
		"findings_dist":   sevConf,
		"evidence_files":  evFiles,
		"timeline_events": len(tl),
		"assets":          len(assets),
	}
}

// ---------- v3.8.7 G3 待续清单回灌门（s7 收口硬校验，确定性） ----------

// s7DispositionCorpus v6.8.0（S7-①④）：G3 处置对账语料池（strict pool 三轨）——
// ①s7- 前缀交付物（覆盖《待续清单处置》《影响评估》等合并书写形态）②S7 本轮开工时间戳
// 之后新增/修改的交付物（兜住不带前缀的自定义文件名；StartedAt 有 v5.9.1 首启保护，回环
// 重跑不丢历史 s7 产出）③report.md（拦截文案既允许的双载体）。旧口径（guard
// enforce_s7_strict_followup_pool=false）回退 deliverables 全目录。followUpDispositionIssues
// （s7 收口硬校验）与 s8「S7 收口移交」块处置统计（S7-④）共用本池，防两处口径漂移。
// strict pool 动机：needs_follow_up 条目正是上游阶段测出来的，其端点关键词几乎必然出现在
// s3/s4/s5/s6 交付物里——全目录入池会让门被上游语料「天然满足」（实跑反例 某历史任务 /
// 某历史任务：s7 文件零处置语义、现存 6/10 条 NF 却正常收口）。
func (o *Orchestrator) s7DispositionCorpus(p *store.Project) string {
	strict := o.guardEnabled(func(g *config.GuardConfig) *bool { return g.EnforceS7StrictFollowUpPool })
	fresh := map[string]bool{}
	if strict {
		if st := p.StageStates["s7"]; st != nil && strings.TrimSpace(st.StartedAt) != "" {
			if started, perr := time.Parse(time.RFC3339, st.StartedAt); perr == nil {
				if fs, ferr := o.listWorkspaceFilesSince(p.ID, "deliverables", started); ferr == nil {
					for _, f := range fs {
						fresh[f.Path] = true
					}
				}
			}
		}
	}
	var pool strings.Builder
	if files, ferr := o.exec.ListDir(p.ID, "deliverables"); ferr == nil {
		for _, rel := range files {
			if strict && !strings.HasPrefix(filepath.Base(rel), "s7-") && !fresh[rel] {
				continue
			}
			if raw, rerr := o.exec.ReadFile(p.ID, rel); rerr == nil {
				pool.WriteString(raw)
				pool.WriteByte('\n')
			}
		}
	}
	if raw, rerr := o.exec.ReadFile(p.ID, "report.md"); rerr == nil {
		pool.WriteString(raw)
	}
	return pool.String()
}

// countUnusedApprovedL2 v6.8.0（S7-④）：已批准 L2 工单中「无使用痕迹且未 V3 申报」的计数
// （与 deterministicGate s7 V4 门同判据，供 s8「S7 收口移交」块清点统计呈现——拦截仍由门本体承担）。
func (o *Orchestrator) countUnusedApprovedL2(p *store.Project) int {
	corp := o.deliverablesText(p.ID)
	if vts, err := o.store.ListVTs(p.ID); err == nil {
		for _, t := range vts {
			corp += t.ResultRef + "\n" + t.Note + "\n"
		}
	}
	if tl, terr := o.store.ListTimeline(p.ID); terr == nil {
		for _, ev := range tl {
			corp += ev.Event + "\n" + ev.Detail + "\n"
		}
	}
	n := 0
	aps, aerr := o.store.ListApprovals(p.ID)
	if aerr != nil {
		return 0
	}
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
		if !declared {
			n++
		}
	}
	return n
}

// followUpDispositionIssues 收集全项目覆盖矩阵中 status=needs_follow_up 的条目，
// 要求处置留痕（已补测 / 范围外附理由 / 移交复测建议）出现在 S7 本阶段的产出文本中，
// 逐项引用端点关键词。零引用 = 未处置 = 拦截。语料池见 s7DispositionCorpus（S7-① strict pool）。
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
	poolText := normCovText(o.s7DispositionCorpus(p))
	unmatched := 0
	var issues []string
	for _, c := range pending {
		if dispositionTokenMatched(c, poolText) {
			continue
		}
		unmatched++
		if unmatched <= 8 {
			issues = append(issues, fmt.Sprintf(
				"待续清单未处置：覆盖条目「%s」（%s，%s 阶段遗留）在 S7 本阶段产出（s7- 前缀交付物/本轮新增文件/报告）中零引用——在《待续清单处置》（deliverables/s7-*.md）或报告中逐项标注：已补测（update_coverage 更新状态）/ 范围外（附理由）/ 移交复测建议，并引用端点关键词留痕。",
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

// findingExcerptLine v6.9.0（S8-③）：search_memory 发现命中行的 poc/remediation 摘要行——
// 各取首行 ≤120 字；两者皆空时如实标注「未登记」让缺失在检索层可见（s8 三字段同源承诺的核对入口）。
func findingExcerptLine(f *store.Finding) string {
	pocPart := "poc 未登记"
	if len(f.POC) > 0 {
		pocPart = "poc首组: " + truncateText(firstLine(f.POC[0].Request), 120)
	}
	remPart := "remediation 未登记"
	if strings.TrimSpace(f.Remediation) != "" {
		remPart = "remediation: " + truncateText(firstLine(f.Remediation), 120)
	}
	return fmt.Sprintf("↳ %s；%s（完整原文 query=\"finding:%s\" 直取）", pocPart, remPart, f.ID)
}

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

// cappedText v6.0.4 P11：项目治理字段全文注入（保留多行），按 rune 数上限截断防上下文膨胀。
// 与 firstLine（首行+120 字符截断）相对——用户在 UI 输入的每一行治理语义都必须到达模型。
func cappedText(s string, maxRunes int) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return "（未填写）"
	}
	r := []rune(s)
	if len(r) <= maxRunes {
		return s
	}
	return string(r[:maxRunes]) + "…（余略，全文见项目档案）"
}

func truncateText(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "…"
}
