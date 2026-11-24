// Package config 定义九头鸟引擎的全局配置。
package config

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// Config 顶层配置，对应 config.json。
type Config struct {
	Listen  string       `json:"listen"`   // HTTP 监听地址，如 ":8787"（绑定全部网卡）
	DataDir string       `json:"data_dir"` // 项目工作区根目录
	WebDir  string       `json:"web_dir"`  // 前端静态资源目录
	Paths   PathsConfig  `json:"paths"`    // v6.1.0（方案㉑）：引擎资源目录（heads/prompts/skills）——相对路径以 config 文件所在目录为基准解析
	LLM     LLMConfig    `json:"llm"`
	Engine  EngineConfig `json:"engine"`
	Guard   GuardConfig  `json:"guard"`
	OOB     OOBConfig    `json:"oob"` // v7.0.0：OOB 回连通道三模式（盲态类 D3 语义验证基础设施）

	// ---- 移植模块配置 ----
	AuthToken         string  `json:"auth_token"`          // API 直连令牌（脚本/CI 用；Web 走账号密码+验证码）
	AdminUser         string  `json:"admin_user"`          // Web 登录账号
	AdminPassword     string  `json:"admin_password"`      // Web 登录密码
	AdminPasswordHash string  `json:"admin_password_hash"` // 可选：sha256("jiutouniao$v1:"+密码) 十六进制；设置后 admin_password 不参与校验（推荐，配置中不存明文口令）
	DebugCaptcha      bool    `json:"debug_captcha"`       // 调试：验证码回显明文（仅联调用，生产必须 false）
	HexStrikeURL      string  `json:"hexstrike_url"`       // hexstrike-ai HTTP 网关（如 http://127.0.0.1:9023），空=禁用工具桥
	MaxProjectTokens  int64   `json:"max_project_tokens"`  // 项目 token 预算上限（0=不限制），超限自动熔断
	PricePer1MInput   float64 `json:"price_per_1m_input"`  // 成本核算：输入价（$/1M tokens）
	PricePer1MOutput  float64 `json:"price_per_1m_output"` // 成本核算：输出价（$/1M tokens）
	AutoApprove       string  `json:"auto_approve"`        // 全局默认审批策略：manual（默认，L1+ 全人工——未知命令不进自动通道）/l1（仅 L0/L1 自动批准并留痕）/all（L1+L2 自动批准），项目可覆盖

	inlineSecrets bool `json:"-"` // v6.1.0（方案⑨）：Load 时记录「配置文件原文是否含明文凭据」（env 注入前的文件态）——迁移提示判定依据，不把 env 注入值误报为文件明文
}

// PathsConfig v6.1.0（S1 修复方案㉑）：引擎资源目录定位——空=默认相对路径（保持既有
// 「cwd 下 heads/prompts/skills」兼容）；相对路径以 config 文件所在目录为基准解析，
// 绝对路径直接使用。资源定位仅作部署解耦，不允许借路径配置关闭治理门。
type PathsConfig struct {
	HeadsDir   string `json:"heads_dir"`   // 阶段头目录（默认 heads）
	PromptsDir string `json:"prompts_dir"` // 宪法目录（默认 prompts）
	SkillsDir  string `json:"skills_dir"`  // 技能库目录（默认 skills）
}

// LLMConfig 模型接入：支持 OpenAI 协议（官方/中转站/本地推理）与 Anthropic 协议双栈。
type LLMConfig struct {
	Protocol    string  `json:"protocol"` // "openai"（默认）| "anthropic"
	BaseURL     string  `json:"base_url"` // OpenAI: …/v1；Anthropic: 网关根地址（自动拼 /v1/messages）
	APIKey      string  `json:"api_key"`
	Model       string  `json:"model"`
	Mock        bool    `json:"mock"` // true 时使用内置 Mock 客户端（无 Key 也可跑通全流程）
	Temperature float32 `json:"temperature"`
	MaxTokens   int     `json:"max_tokens"`

	// v6.0.1 P1（fix-plan 20261122）：LLM 请求时限与重试参数化。
	// 实证事故：原 900s 硬编码总超时下，网关静默 911s 时项目主循环冻结 15 分钟
	// （msgs=234 大上下文请求，两处阶段切换被延误）；该值此前既不可配置也无请求级
	// deadline 观测。默认 300s 显著低于旧硬编码值，大上下文项目可显式调高。
	RequestTimeoutSec int   `json:"request_timeout_sec"` // 单次 LLM 请求总预算秒数（默认 300；<=0 视为默认）
	MaxRetries        int   `json:"max_retries"`         // 可重试错误（网络/5xx/429/超时）的重试次数（默认 4，总尝试 5 次）
	RetryBaseSec      int   `json:"retry_base_sec"`      // 重试指数退避基值秒数（默认 2）
	RetryMaxSec       int   `json:"retry_max_sec"`       // 重试退避上限秒数（默认 20）
	ResponseMaxBytes  int64 `json:"response_max_bytes"`  // 响应体读取上限字节（默认 32MiB；防异常超大响应拖垮内存）
}

// EngineConfig 执行循环与并发控制。
// v7.0.0 OOB 回连通道三模式（盲态类 D3 语义验证基础设施）：
// local=A 本机自建（A1 自托管 interactsh-server / A2 本地监听器）、public=B 公共 interactsh、
// custom=C 用户自设（interactsh|dnslog|webhook）。auto=回退链 A1→C→A2→B→盲态禁测。
// 所有模式只收回连记录（存在性证明口径），不投递破坏载荷——与 production_safe 零冲突。
type OOBConfig struct {
	Mode                   string          `json:"mode"`                      // auto|local|public|custom|off（默认 auto）
	Local                  OOBLocalConfig  `json:"local"`                     // A 本机自建
	Public                 OOBCustomConfig `json:"public"`                    // B 公共通道（Server=逗号分隔候选，自动健康序）
	Custom                 OOBCustomConfig `json:"custom"`                    // C 用户自设
	RequireChannelForBlind *bool           `json:"require_channel_for_blind"` // 盲态类前置门：无健康通道禁止派发盲态技能且 ruled_out 自动降级（默认 true）
	PollIntervalSec        int             `json:"poll_interval_sec"`         // 回连轮询间隔秒（默认 30；公共通道记录留存短，勿超 60）
}

// OOBLocalConfig A 本机自建：A1=自托管 interactsh-server（有公网入站+自有域时首选，
// 回连域名可伪装业务域、交互不出第三方）；A2=本地 HTTP/DNS 监听器（内网/靶场，目标可直连本机）。
type OOBLocalConfig struct {
	SubMode   string `json:"sub_mode"`         // auto|interactsh|listener（默认 auto：配置了 server_url 走 A1，否则 A2 监听器）
	ServerURL string `json:"server_url"`       // A1：自托管 interactsh-server URL（空=A2 本地监听器）
	Secret    string `json:"secret"`           // A1：server secret/token（可空）
	HTTPPort  int    `json:"listen_http_port"` // A2 本地 HTTP 回连监听端口（默认 8899）
	DNSPort   int    `json:"listen_dns_port"`  // A2 本地 DNS 回连监听端口（0=不启；需 root 且 53 常被占用）
}

// OOBCustomConfig B/C 共用：B（public）只填 Server 候选；C（custom）按 Kind 接线
// interactsh（自托管 server）/ dnslog（dnslog.cn 兼容 API）/ webhook（通用收集器，写 URL+读 API）。
type OOBCustomConfig struct {
	Server    string `json:"server"`     // B：公共 interactsh server 候选，逗号分隔（默认 oast.pro,oast.me,oast.live）
	Kind      string `json:"kind"`       // C：interactsh|dnslog|webhook
	ServerURL string `json:"server_url"` // C：通道服务地址
	Secret    string `json:"secret"`     // C：token/cookie/API key（可空）
}

type EngineConfig struct {
	MaxStageIterations int `json:"max_stage_iterations"` // 每阶段 Agent 循环上限（预算封顶）
	MaxConcurrentExec  int `json:"max_concurrent_exec"`  // 每项目并发命令执行上限
	CommandTimeoutSec  int `json:"command_timeout_sec"`  // 单条命令默认超时
	MaxOutputBytes     int `json:"max_output_bytes"`     // 命令输出截断阈值
	ChatToolRounds     int `json:"chat_tool_rounds"`     // 对话指挥室单次回复的内部工具轮次上限（默认 24）

	// v2.6 速度纪律引擎保证
	CmdHardCapSec        int   `json:"cmd_hard_cap_sec"`       // 同步命令硬上限秒数（默认 1800=30min）；超出被钳制，长任务应走 run_async
	AsyncHardCapSec      int   `json:"async_hard_cap_sec"`     // 后台任务硬上限秒数（默认 7200=2h）
	ParallelToolDispatch *bool `json:"parallel_tool_dispatch"` // 同一轮多个可并行工具并发执行（默认 true；显式 false 恢复严格串行）
	// v3.2.0 修复：run_async 未传 timeout 时曾回退到同步 command_timeout_sec（300s），
	// 后台深扫 5 分钟即被杀，与工具文档「默认 3600」相悖；现取独立默认值。
	AsyncTimeoutSec int `json:"async_timeout_sec"` // run_async 未显式传 timeout 时的默认超时（默认 3600=1h）

	// v3.3.0 输出治理：溢出落盘阈值 + 消息链窗口预算（确定性压缩，零额外 LLM 调用）
	SpillBytes          int `json:"spill_bytes"`           // 工具输出超此字节数溢出落盘 .tool-output/（默认 16384；0=禁用）
	ContextBudgetTokens int `json:"context_budget_tokens"` // 阶段消息链估算 token 预算（默认 100000，超限压缩最旧中段）
	ContextKeepRecent   int `json:"context_keep_recent"`   // 压缩时保护的最近消息条数（默认 10）

	// v3.4.0 韧性：人工屏障超时（审批与向人提问共用）——实证 manual 策略下
	// 单个未读工单曾让流水线空等 115 分钟且无 wall-clock 预算
	BarrierTimeoutSec int `json:"barrier_timeout_sec"` // 人工审批/提问等待上限秒数（默认 1800=30min；<=0 视为默认）

	// v3.6.0 阶段内并行扇出（受控子代理）
	MaxSubagents      int `json:"max_subagents"`       // 每项目并发子代理上限（默认 3；0=禁用扇出）
	MaxSubagentRounds int `json:"max_subagent_rounds"` // 单个子代理轮次预算（默认 12，硬上限 30）

	// v4.4 多目标轮次自适应（方向二B）：s1/s2/s3/s4/s5/s6/s8 阶段预算 = base + (目标数-1)*PerTargetRounds，封顶 3×base（v6.1.0 方案⑤ s1 纳入、v6.3.0 S3-② s3 纳入、v6.7.0 S6-⑩ s6 纳入、v6.9.0 S8-④ s8 纳入——多目标报告按目标组织，分组合并工作量随目标数线性增长；s7 不入选：收尾按条目不按目标）
	PerTargetRounds int `json:"per_target_rounds"` // 每增 1 个目标追加的轮次（默认 10；<=0 视为默认）

	// v5.5.0 能力修复（docs/repair-plan-capability-20261118.md 方案 D/E）：
	BudgetExhaustedPolicy string `json:"budget_exhausted_policy"` // 阶段预算耗尽策略：pause（默认，阶段置 paused+项目暂停，可提升预算/手动重跑续跑；不再把未完成阶段装作 done）/auto_close（v4.9 旧行为：代收口 done+quality-pending，流水线继续）
	LoopbackMaxRuns       int    `json:"loopback_max_runs"`       // 单项目自动回环补跑上限（默认 3；超额的 loopback 请求显式拒绝并留痕，不再"置 pending 却不排队"成死角）

	// v4.6 K7 命令空闲护栏：同步命令连续 N 秒无输出 → 终止进程组（实测 searchsploit 更新
	// 网络挂死烧掉 91 分钟窗口）。<=0 视为默认 120；显式 -1 禁用。长静默任务应走 run_async。
	CommandIdleTimeoutSec int `json:"command_idle_timeout_sec"`

	// v4.8 W5 行为预算器：批量动作配额与冷却（完全静默冷却协议）——防批量空转浪费轮次
	// 并触发目标封锁（arjun/httpx 类教训的引擎级兜底）。<=0 视为默认。
	BatchQuotaPer10Min int `json:"batch_quota_per_10min"` // 每 10 分钟批量动作上限（默认 12）
	BatchCooldownMin   int `json:"batch_cooldown_min"`    // 超限冷却时长分钟（默认 5）

	// v4.6 T3/H：ROE Profile 路径（治理参数化，§3）——引擎加载校验并把运行时含义注入上下文包；
	// 非法即启动失败（fail-fast）。空=未启用（默认护栏口径）。
	ROEProfilePath string `json:"roe_profile_path"`

	// v5.3.1：Execution Profile 声明文件路径——双运行模式（production_safe/isolated_lab）的
	// 单一事实源，引擎逐动作强制校验。空=默认 policies/execution-profiles.yaml；
	// 缺失或非法即启动失败（fail-fast，与 ROE Profile 同口径）。
	ExecutionProfilesPath string `json:"execution_profiles_path"`

	// v3.7.7 重启自愈：引擎重启后对被中断（paused）的项目自动断点续跑
	AutoResume *bool `json:"auto_resume"` // 默认 true；显式 false 关闭（启动恢复后仍需人工续跑）
}

// ParallelDispatch 同一轮工具是否并发执行（nil=默认并发）。
func (e EngineConfig) ParallelDispatch() bool {
	return e.ParallelToolDispatch == nil || *e.ParallelToolDispatch
}

// GuardConfig 护栏：风险分级正则与禁令（对应流程图「审批矩阵」「破坏性操作禁令」）。
type GuardConfig struct {
	Forbidden      []string `json:"forbidden"`       // 默认禁止（匹配即拒绝执行）
	HighRisk       []string `json:"high_risk"`       // L2：必须人工批准
	MedRisk        []string `json:"med_risk"`        // L1：写操作，需人工批准
	ReadOnly       []string `json:"read_only"`       // L0：可自动执行的只读命令前缀（v3.2.0 起为段首词锚定语义）
	Sensitive      []string `json:"sensitive"`       // v3.2.0：敏感面特征（命中即从 L0 降级为 L1，防引擎自身密钥/凭据被只读白名单读出）
	ScopeAllowlist []string `json:"scope_allowlist"` // v5.2.0：strict_scope 范围校验的良性外部白名单扩充

	// v6.1.0（S1 修复方案）：治理硬门开关（三态 *bool：nil 经 applyDefaults 归一为 true，
	// 显式 false 才回退——回滚是事故手段，须记录配置变更与重启时间，缺字段不允许静默关闭）。
	EnforceAuthorization *bool `json:"enforce_authorization"` // ①授权硬门：创建/启动/命令三级拒绝未授权项目
	BlockShadowAssets    *bool `json:"block_shadow_assets"`   // ②影子资产门：shadow_pending/unknown 资产在任何通道拦截测试流量
	EnforceAssetScope    *bool `json:"enforce_asset_scope"`   // ㉒/②资产范围门：strict_scope 资产 allowlist 只收有依据的 in_scope
	EnforceS1L0          *bool `json:"enforce_s1_l0"`         // ③S1 阶段门：仅被动查询，目标侧探测一律拒绝
	EnforceS1Closure     *bool `json:"enforce_s1_closure"`    // ④/⑤S1 确定性收口门：四件套+逐目标对账
	EnforceS2Closure     *bool `json:"enforce_s2_closure"`    // v6.2.0 S2-①S2 确定性收口门：攻击面地图/拓扑重建+checklist 可解析+多目标逐目标归宿
	EnforceBatchScope    *bool `json:"enforce_batch_scope"`   // v6.2.0 S2-②批量通道范围门：run_batch 逐目标与工作区 -l 清单过影子资产/范围校验
	EnforceS3Closure     *bool `json:"enforce_s3_closure"`    // v6.3.0 S3-①S3 确定性收口门：威胁模型/测试计划存在性+上游承接留痕+判定表证据指针核存
	EnforceTargetClassMatrix *bool `json:"enforce_target_class_matrix"` // v6.3.0 S3-②判定表目标列复合键：多目标 (类×目标) 覆盖完备+执行卡口径统一（false 回退单目标旧口径）
	EnforcePlanHandover  *bool `json:"enforce_plan_handover"` // v6.3.0 S3-④T-xx 计划承接门：s3-测试计划条目在 S4 收口前须显式归宿
	EnforceEndpointMatrix *bool `json:"enforce_endpoint_matrix"` // v6.3.0 S3-⑤端点表↔覆盖矩阵运行时门：diffed/total+total=N 一致性（原 eval 离线门上移）
	EnforceS5V3Handover   *bool `json:"enforce_s5_v3_handover"`   // v6.4.0 S4-⑤⑥S4 移交承接门：S4 V3 清单+browser-auth 路线移交项在 S5 收口前须有承接留痕（承接反蒸发机械对账）
	EnforceTHBackfill     *bool `json:"enforce_th_backfill"`      // v6.4.0 S4-⑦威胁清单回填对账门：S4 交付物须有《威胁清单回填记录》小节+extends/replaces 引用真实 TH 编号
	EnforceS3EndpointTable *bool `json:"enforce_s3_endpoint_table"` // v6.4.0 S4-②端点表生产端契约：S3 收口时端点表存在或计划含「未产出端点表」声明
	EnforceS5TargetRecon  *bool `json:"enforce_s5_target_recon"`   // v6.4.0 S4-⑨S5 逐目标对账门：多目标项目 S5 收口时 targetCoverageRecon（与 S4 批次6 同口径）
	EnforceSpecTargetRecon *bool `json:"enforce_spec_target_recon"` // v6.6.0 SP-①专项逐目标对账门：多目标项目 specA/specB1/specB2 收口时 targetCoverageRecon（与 S4-9/S5 同口径，语料=本专项覆盖 notes+交付物）
	EnforceS6TargetRecon  *bool `json:"enforce_s6_target_recon"`   // v6.7.0 S6-④s6 逐目标对账门：多目标项目 S6 收口时 targetCoverageRecon（与 S4-9/S5 同口径，语料=s6 覆盖 notes+交付物排除 s4-/s5- 上游分组产物）
	EnforceS6Deliverables *bool `json:"enforce_s6_deliverables"`  // v6.7.0 S6-⑥s6 命名交付物条件核验：有立足点信号的项目收口要求权限矩阵+横向路径图或 N/A 声明（无立足点零要求）
	EnforceS7StrictFollowUpPool *bool `json:"enforce_s7_strict_followup_pool"` // v6.8.0 S7-①G3 待续清单回灌门 strict pool：处置池=s7- 前缀交付物∪s7 开工后新增/修改文件∪report.md（false 回退 deliverables 全目录旧池口径——上游交付物端点关键词不再天然满足处置对账）
	EnforceS8FindingReportRecon *bool `json:"enforce_s8_finding_report_recon"` // v6.9.0 S8-③反向对账门：逐条 findings 的归一化标题前缀或 F- 编号须在 report.md 有归宿留痕（R- 条目/待验证小节/定级表映射并入 R-xx）——报告↔findings 1:1 的另一半（正向门 R≤findings 只拦多记，本门拦漏报；false 回退旧口径仅正向门）
	EnforceSpecClosure    *bool `json:"enforce_spec_closure"`     // v6.6.0 SP-②专项确定性收口门：前置契约登记+点名交付物+条目三态清单存在性（豁免：无适用资产走前提不成立路径）
	EnforceROERuntime    *bool `json:"enforce_roe_runtime"`   // ⑧ROE 运行时门：时间窗/连接预算/冷却（rotation 未接入时标注 unenforced）
	RequireS1ROEAck      *bool `json:"require_s1_roe_ack"`    // ⑩ROE 红线确认门：确认前任何命令通道拒绝
	RequireS1OOBChannel  *bool `json:"require_s1_oob_channel"` // ⑪OOB 条件收口门：项目要求 OOB 时核验 channel 产物
	LessonBehaviorPerTarget *bool `json:"lesson_behavior_per_target"` // ⑮教训行为类逐目标检索（false 恢复全局单值旧排序）
	AssetMetadataValidation *bool `json:"asset_metadata_validation"` // ⑳资产台账字段校验（APP/小程序/云账号按类型必填最小字段集）
}

// FlagOrDefault 三态布尔取值：nil=默认值；显式 false 才回退（v6.1.0 配置约定）。
func FlagOrDefault(p *bool, def bool) bool {
	if p == nil {
		return def
	}
	return *p
}

// DefaultGuard 返回默认护栏特征库（Forbidden/HighRisk/MedRisk/ReadOnly/Sensitive）。
// 供测试与审计直接引用生产默认值，避免测试用迷你清单绕过真实规则。
func DefaultGuard() (forbidden, highRisk, medRisk, readOnly, sensitive []string) {
	return defaultForbidden, defaultHighRisk, defaultMedRisk, defaultReadOnly, defaultSensitive
}

// ApplyDefaultsForTest 供测试构造默认配置（Load 的零值路径）。
func (c *Config) ApplyDefaultsForTest() {
	if c.LLM.MaxTokens == 0 {
		c.LLM.MaxTokens = 1024
	}
	if c.Engine.MaxStageIterations == 0 {
		c.Engine.MaxStageIterations = 3
	}
	c.applyDefaults()
}

// Load 从 JSON 文件读取配置；环境变量可覆盖同名项（Docker 部署友好）。
func Load(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("读取配置失败: %w", err)
	}
	c := &Config{}
	if err := json.Unmarshal(b, c); err != nil {
		return nil, fmt.Errorf("解析配置失败: %w", err)
	}
	// v6.1.0（方案⑨）：在 applyEnv 之前记录文件态明文凭据存在性——env 注入的值不属于
	// "配置文件明文"，不得误报迁移提示。
	c.inlineSecrets = c.LLM.APIKey != "" || c.AuthToken != "" || c.AdminPassword != ""
	c.applyDefaults()
	c.applyEnv()
	if err := c.validateSecrets(); err != nil {
		return nil, err
	}
	return c, nil
}

// validateSecrets v6.1.0（S1 修复方案⑨）：启动前凭据存在性校验（fail-fast）。
// ①管理员凭据（密码或哈希）缺失 → 拒绝启动（公开默认口令不再回填）；
// ②配置文件仍存明文凭据 → 输出迁移提示（不含值，不回显原文）并继续——硬拒绝会破坏
// 已部署环境，明文风险由「移除默认回填 + README 迁移指引 + env 覆盖」渐进收敛。
func (c *Config) validateSecrets() error {
	if strings.TrimSpace(c.AdminPassword) == "" && strings.TrimSpace(c.AdminPasswordHash) == "" {
		return fmt.Errorf("管理员凭据未配置：请设置 ADMIN_PASSWORD_HASH（推荐，sha256(jiutouniao$v1:密码)）或 ADMIN_PASSWORD 环境变量后启动")
	}
	return nil
}

// HasInlineSecrets v6.1.0：配置**文件原文**是否含明文凭据（env 注入不算——供启动日志
// 迁移提示判定，不打印值）。
func (c *Config) HasInlineSecrets() bool {
	return c.inlineSecrets
}

// applyEnv 环境变量覆盖：AUTH_TOKEN / HEXSTRIKE_URL / MAX_PROJECT_TOKENS /
// LLM_BASE_URL / LLM_API_KEY / LLM_MODEL / LLM_MOCK / PRICE_IN / PRICE_OUT。
func (c *Config) applyEnv() {
	setStr := func(dst *string, key string) {
		if v := strings.TrimSpace(os.Getenv(key)); v != "" {
			*dst = v
		}
	}
	setStr(&c.AuthToken, "AUTH_TOKEN")
	setStr(&c.AdminUser, "ADMIN_USER")
	setStr(&c.AdminPassword, "ADMIN_PASSWORD")
	// v6.1.0（S1 修复方案⑨）：管理员密码哈希环境变量注入——配置文件不落明文口令。
	setStr(&c.AdminPasswordHash, "ADMIN_PASSWORD_HASH")
	setStr(&c.HexStrikeURL, "HEXSTRIKE_URL")
	setStr(&c.AutoApprove, "AUTO_APPROVE")
	setStr(&c.LLM.BaseURL, "LLM_BASE_URL")
	setStr(&c.LLM.APIKey, "LLM_API_KEY")
	setStr(&c.LLM.Model, "LLM_MODEL")
	setStr(&c.LLM.Protocol, "LLM_PROTOCOL")
	if v := strings.TrimSpace(os.Getenv("LLM_MOCK")); v != "" {
		c.LLM.Mock = v == "true" || v == "1" || v == "yes"
	}
	if v := strings.TrimSpace(os.Getenv("MAX_PROJECT_TOKENS")); v != "" {
		var n int64
		if _, err := fmt.Sscanf(v, "%d", &n); err == nil {
			c.MaxProjectTokens = n
		}
	}
	if v := strings.TrimSpace(os.Getenv("PRICE_IN")); v != "" {
		if _, err := fmt.Sscanf(v, "%f", &c.PricePer1MInput); err == nil {
		}
	}
	if v := strings.TrimSpace(os.Getenv("PRICE_OUT")); v != "" {
		if _, err := fmt.Sscanf(v, "%f", &c.PricePer1MOutput); err == nil {
		}
	}
}

func (c *Config) applyDefaults() {
	if c.Listen == "" {
		c.Listen = ":8787"
	}
	if c.DataDir == "" {
		c.DataDir = "./projects"
	}
	if c.WebDir == "" {
		c.WebDir = "./web"
	}
	if c.LLM.Model == "" {
		c.LLM.Model = "gpt-4o"
	}
	if strings.TrimSpace(c.LLM.Protocol) == "" {
		c.LLM.Protocol = "openai"
	}
	if c.LLM.MaxTokens == 0 {
		c.LLM.MaxTokens = 4096
	}
	// v6.0.1 P1：LLM 时限/重试默认值（fix-plan 默认参数表：300s/4 次/2s/20s/32MiB）。
	// 配置无效或缺失时取安全默认并继续——不得退化为无限等待（fail-safe 而非 fail-open）。
	if c.LLM.RequestTimeoutSec <= 0 {
		c.LLM.RequestTimeoutSec = 300
	}
	if c.LLM.MaxRetries <= 0 {
		c.LLM.MaxRetries = 4
	}
	if c.LLM.RetryBaseSec <= 0 {
		c.LLM.RetryBaseSec = 2
	}
	if c.LLM.RetryMaxSec <= 0 {
		c.LLM.RetryMaxSec = 20
	}
	if c.LLM.ResponseMaxBytes <= 0 {
		c.LLM.ResponseMaxBytes = 32 << 20
	}
	if c.Engine.MaxStageIterations == 0 {
		c.Engine.MaxStageIterations = 40
	}
	if c.Engine.MaxConcurrentExec == 0 {
		c.Engine.MaxConcurrentExec = 4
	}
	if c.Engine.CommandTimeoutSec == 0 {
		c.Engine.CommandTimeoutSec = 300
	}
	if c.Engine.MaxOutputBytes == 0 {
		c.Engine.MaxOutputBytes = 200 * 1024
	}
	if len(c.Guard.Forbidden) == 0 {
		c.Guard.Forbidden = defaultForbidden
	}
	if len(c.Guard.HighRisk) == 0 {
		c.Guard.HighRisk = defaultHighRisk
	}
	if len(c.Guard.MedRisk) == 0 {
		c.Guard.MedRisk = defaultMedRisk
	}
	if len(c.Guard.ReadOnly) == 0 {
		c.Guard.ReadOnly = defaultReadOnly
	}
	if len(c.Guard.Sensitive) == 0 {
		c.Guard.Sensitive = defaultSensitive
	}
	if c.Engine.ChatToolRounds <= 0 {
		c.Engine.ChatToolRounds = 24
	}
	if c.Engine.AsyncTimeoutSec <= 0 {
		c.Engine.AsyncTimeoutSec = 3600 // v3.2.0：run_async 默认超时与工具文档口径一致
	}
	if c.Engine.SpillBytes == 0 {
		c.Engine.SpillBytes = 16 * 1024 // v3.3.0：16KB 以上输出溢出落盘
	}
	if c.Engine.ContextBudgetTokens <= 0 {
		c.Engine.ContextBudgetTokens = 100000 // v3.3.0：消息链预算（实测 125k+ 注意力稀释/超限硬失败的收敛线）
	}
	if c.Engine.ContextKeepRecent <= 0 {
		c.Engine.ContextKeepRecent = 10
	}
	// v7.0.0：OOB 回连通道默认值（mode=auto 回退链；轮询 30s；A2 HTTP 监听 8899；B 候选健康序）
	if strings.TrimSpace(c.OOB.Mode) == "" {
		c.OOB.Mode = "auto"
	}
	c.OOB.Mode = strings.ToLower(strings.TrimSpace(c.OOB.Mode))
	switch c.OOB.Mode {
	case "auto", "local", "public", "custom", "off":
	default:
		c.OOB.Mode = "auto"
	}
	if c.OOB.PollIntervalSec <= 0 {
		c.OOB.PollIntervalSec = 30
	}
	if c.OOB.PollIntervalSec < 5 {
		c.OOB.PollIntervalSec = 5 // 限频下限：公共通道轮询不得打爆 API
	}
	if strings.TrimSpace(c.OOB.Local.SubMode) == "" {
		c.OOB.Local.SubMode = "auto"
	}
	if c.OOB.Local.HTTPPort <= 0 {
		c.OOB.Local.HTTPPort = 8899
	}
	if strings.TrimSpace(c.OOB.Public.Server) == "" {
		c.OOB.Public.Server = "oast.pro,oast.me,oast.live,webhook.site"
	}
	if strings.TrimSpace(c.OOB.Custom.Kind) == "" {
		c.OOB.Custom.Kind = "interactsh"
	}
	if c.Engine.BarrierTimeoutSec <= 0 {
		c.Engine.BarrierTimeoutSec = 1800 // v3.4.1 修复：默认必须真实生效（此前未配置时=0 即无限等待，与文档承诺相悖）
	}
	// v4.6 K7：空闲护栏默认 120s；-1 显式禁用
	if c.Engine.CommandIdleTimeoutSec == 0 {
		c.Engine.CommandIdleTimeoutSec = 120
	}
	if c.Engine.CommandIdleTimeoutSec < 0 {
		c.Engine.CommandIdleTimeoutSec = 0
	}
	if c.Engine.MaxSubagents == 0 {
		c.Engine.MaxSubagents = 3 // v3.6.0：默认 3 路并发扇出（0 会被此处覆盖为 3，禁用请设负数语义不支持——如需禁用置 max_subagents=-1 视为 0）
	}
	if c.Engine.MaxSubagents < 0 {
		c.Engine.MaxSubagents = 0
	}
	if c.Engine.MaxSubagentRounds <= 0 {
		c.Engine.MaxSubagentRounds = 12
	}
	if c.Engine.PerTargetRounds <= 0 {
		c.Engine.PerTargetRounds = 10 // v4.4：多目标轮次自适应默认每目标 +10 轮（方向二B）
	}
	// v5.5.0：预算耗尽策略（默认 pause——未完成阶段不得假装完成）与回环上限（默认 3，沿用原值）
	if c.Engine.BudgetExhaustedPolicy == "" {
		c.Engine.BudgetExhaustedPolicy = "pause"
	}
	c.Engine.BudgetExhaustedPolicy = strings.ToLower(strings.TrimSpace(c.Engine.BudgetExhaustedPolicy))
	if c.Engine.BudgetExhaustedPolicy != "pause" && c.Engine.BudgetExhaustedPolicy != "auto_close" {
		c.Engine.BudgetExhaustedPolicy = "pause"
	}
	if c.Engine.LoopbackMaxRuns <= 0 {
		c.Engine.LoopbackMaxRuns = 3
	}
	// v4.8 W5 行为预算器：批量动作配额（默认 12 次/10 分钟）与冷却时长（默认 5 分钟，完全静默）
	if c.Engine.BatchQuotaPer10Min <= 0 {
		c.Engine.BatchQuotaPer10Min = 12
	}
	if c.Engine.BatchCooldownMin <= 0 {
		c.Engine.BatchCooldownMin = 5
	}
	if c.Engine.AutoResume == nil {
		t := true
		c.Engine.AutoResume = &t // v3.7.7：默认自动续跑（重启/部署不再丢任务）
	}
	// v6.1.0（S1 修复方案）：治理硬门缺省开启——显式 false 才回退，缺字段不允许静默关闭。
	setTrue := func(p **bool) {
		if *p == nil {
			t := true
			*p = &t
		}
	}
	setTrue(&c.Guard.EnforceAuthorization)
	setTrue(&c.Guard.BlockShadowAssets)
	setTrue(&c.Guard.EnforceAssetScope)
	setTrue(&c.Guard.EnforceS1L0)
	setTrue(&c.Guard.EnforceS1Closure)
	setTrue(&c.Guard.EnforceS2Closure)
	setTrue(&c.Guard.EnforceBatchScope)
	setTrue(&c.Guard.EnforceS3Closure)
	setTrue(&c.Guard.EnforceTargetClassMatrix)
	setTrue(&c.Guard.EnforcePlanHandover)
	setTrue(&c.Guard.EnforceEndpointMatrix)
	setTrue(&c.Guard.EnforceS5V3Handover)
	setTrue(&c.Guard.EnforceTHBackfill)
	setTrue(&c.Guard.EnforceS3EndpointTable)
	setTrue(&c.Guard.EnforceS5TargetRecon)
	setTrue(&c.Guard.EnforceSpecTargetRecon)
	setTrue(&c.Guard.EnforceS6TargetRecon)
	setTrue(&c.Guard.EnforceS6Deliverables)
	setTrue(&c.Guard.EnforceS7StrictFollowUpPool)
	setTrue(&c.Guard.EnforceS8FindingReportRecon)
	setTrue(&c.Guard.EnforceSpecClosure)
	setTrue(&c.Guard.EnforceROERuntime)
	setTrue(&c.Guard.RequireS1ROEAck)
	setTrue(&c.Guard.RequireS1OOBChannel)
	setTrue(&c.Guard.LessonBehaviorPerTarget)
	setTrue(&c.Guard.AssetMetadataValidation)
	if c.AdminUser == "" {
		c.AdminUser = "admin"
	}
	// v6.1.0（S1 修复方案⑨）：移除默认管理员密码回填——公开文档化默认口令不再允许
	// 空配置静默生效；凭据缺失时 Load fail-fast（见 validateSecrets），运维经
	// ADMIN_PASSWORD_HASH（推荐，配置零明文）或 ADMIN_PASSWORD 环境变量注入。
	if c.AutoApprove != "manual" && c.AutoApprove != "l1" && c.AutoApprove != "all" {
		// v5.2.0 P1-2（外部审计）：默认 manual——L1（含未知命令兜底）也人工审批，
		// 杜绝"未知命令经默认策略自动执行"；自动化需求由项目级显式配置 l1/all。
		c.AutoApprove = "manual"
	}
}

// 默认风险特征库（可被 config.json 覆盖/扩充）。
var defaultForbidden = []string{
	`rm\s+-rf\s+/`,
	// v5.1.2：破坏性删除变体补全（原仅匹配 `rm -rf /` 字面序——`rm -fr /`、`rm -r -f /`、长选项均漏）
	`rm\s+-fr\s+/`, `rm\s+-r\s+-f\s+/`, `rm\s+(-[a-zA-Z]+\s+)*--recursive\b[^|;]*--force\b[^|;]*\s+/`,
	`rm\s+(-[a-zA-Z]+\s+)*--force\b[^|;]*--recursive\b[^|;]*\s+/`,
	`mkfs`, `:\(\)\{.*\};:`,
	// v5.1.2：dd 落盘目标扩到 vd/nvme/hd（原仅 /dev/sd）
	`dd\s+if=.+of=/dev/(sd|vd|hd|nvme|disk)`,
	`shutdown|reboot|halt\b`, `iptables\s+-F`, `ufw\s+reset`,
	`DROP\s+DATABASE`, `TRUNCATE\s+TABLE`, `--forkbomb`,
	// v2.3.0：无 WHERE 的全表 DELETE / DROP TABLE / TRUNCATE（防误伤全表数据）
	`DROP\s+TABLE\s`, `TRUNCATE\s+(TABLE\s+)?["']?\w`,
	`(?m)DELETE\s+FROM\s+["']?\w+["']?\s*;?\s*(--|#|\s*$)`,
}

var defaultHighRisk = []string{
	`exploit|payload|meterpreter|reverse_shell|bind_shell`,
	`nc\s+-.*-e|ncat\s+-e|bash\s+-i\s+>&`, `sshpass|hydra|medusa`,
	`sqlmap\s+.*(--dump|--os-shell)`, `mimikatz|secretsdump|hashdump`,
	`\.\/.*poc|python3?\s+.*poc`, `横向|提权|getshell`,
	// v2.3.0：破坏性 SQL 与强制删除一律 L2（审批可见；ROE 禁止破坏性写入时由智能体纪律拒绝）
	`DELETE\s+FROM`, `DROP\s+TABLE`, `TRUNCATE\s+`,
	`UPDATE\s+["']?\w+["']?\s+SET`, `INSERT\s+INTO`,
	`rm\s+(-[a-zA-Z]*f|--force)`,
	// v5.2.0 P1-2 配套：管道执行与系统路径写入属利用形态——即使 all 策略也强制人工
	`(curl|wget)[^|;]*\|\s*(sudo\s+)?(ba|z|da)?sh\b`,
	`tee\s+/(etc|usr|bin|sbin|lib|var)/`,
	`>\s*/(etc|usr/lib|usr/local/bin)/`,
	`xargs\s+(ba|z|da)?sh\b`,
}

var defaultMedRisk = []string{
	`touch|mkdir|curl\s+.*>-O|wget`, `scp|rsync`,
	`systemctl|service\s+`, `docker\s+run`, `pip\s+install|apt(-get)?\s+install`,
	`nuclei|nmap\s+.*-Pn|masscan`, `写操作|植入|持久化`,
}

// defaultReadOnly L0 只读白名单（v3.2.0 语义变更：段首词锚定 + 危险元字符否决，
// 不再是任意位置的子串匹配；每条为命令段的小写前缀，以空格结尾表示「词 + 参数」）。
// 变更：移除 env（可倒出容器环境变量，含密钥）；补充常用只读文本/系统工具（sort/uniq/cut/tr/
// ps/ss/netstat 等），保证 `cat x | grep y | sort | uniq -c` 类正常侦察管道仍为 L0。
var defaultReadOnly = []string{
	"whoami", "id", "uname", "ifconfig", "ip a", "ip addr", "hostname", "pwd",
	"ls ", "cat", "head", "tail", "file", "echo ", "which", "wait", "true", "false",
	"nmap -sV", "nmap -sn", "dig", "host", "curl -s", "httpx",
	// v6.1.0（S1 修复方案⑦）：WHOIS 注册信息查询是 S1 被动情报清单必查项（纯文本查询，
	// 网络对端是 RIR/注册商 WHOIS 服务器而非目标服务）
	"whois",
	"subfinder", "nuclei -list", "git log", "find ", "grep", "wc",
	"python3 --version", "pip list", "ls -", "cat/", "sort", "uniq",
	"cut", "tr", "ps", "ss -", "netstat ", "stat", "diff",
	"date", "du -", "df -", "sha256sum", "md5sum", "sleep ",
	"tee", "traceroute", "tracepath",
	// v3.3.0 manual 摩擦回补：纯读文本/编码工具进白名单（管道高频；无命令执行面——
	// awk 有 system()、xargs 可执行、sed 有 w 写盘，维持 L1 不放）
	"jq", "base64", "xxd", "hexdump", "od", "column", "rev", "nl",
}

// defaultSensitive v3.2.0 敏感面特征：命令命中任一模式时，即使整体判定为 L0 只读，
// 也强制降级为 L1（走审批留痕）。防两类事故：① 只读白名单读出引擎自身密钥
// （config.json / 环境变量 / bbolt 库 / SSH 凭据）；② 目标侧凭据文件被无声自动执行。
// 属「宁严勿松」的可配置项（config.json guard.sensitive 覆盖）。
var defaultSensitive = []string{
	`/app/config\.json`, `secret\.key`, `jiutouniao\.db`, // 引擎自身配置/密钥/记忆库
	`/proc/(self|\d+)/environ`,
	// v5.1.2：敏感面 glob/穿越绕过补口（cat /proc/1/en*、/proc/1/../1/environ 类变体）
	`/proc/[^ ]*en(vir|\*)`,
	`\.ssh\b|id_rsa|id_ed25519|authorized_keys`,                   // SSH 凭据（含无尾斜杠路径）
	`\.aws/credentials|\.netrc|\.git-credentials|\.docker/config`, // 云/凭据存档
	`/etc/shadow`, `\.bash_history`,
	`admin_password|admin_password_hash|llm_api_key|auth_token\b`, // 引擎密钥变量名（echo $LLM_API_KEY 等）
	`fofa_key|shodan_api_key|quake_key|zoomeye_key`,               // 测绘 Key（工具可用，但值不进上下文）
}
