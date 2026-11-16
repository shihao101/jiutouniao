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
	LLM     LLMConfig    `json:"llm"`
	Engine  EngineConfig `json:"engine"`
	Guard   GuardConfig  `json:"guard"`

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
}

// EngineConfig 执行循环与并发控制。
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

	// v4.4 多目标轮次自适应（方向二B）：S2/S4/S5 阶段预算 = base + (目标数-1)*PerTargetRounds，封顶 3×base
	PerTargetRounds int `json:"per_target_rounds"` // 每增 1 个目标追加的轮次（默认 10；<=0 视为默认）

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
	c.applyDefaults()
	c.applyEnv()
	return c, nil
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
	if c.AdminUser == "" {
		c.AdminUser = "admin"
	}
	if c.AdminPassword == "" {
		c.AdminPassword = "jiutou@2026" // 部署后务必修改
	}
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
