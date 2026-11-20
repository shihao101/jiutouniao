// Package store 基于 bbolt 的持久化层：项目状态、发现、资产、时间线、审批与证据链。
package store

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	bolt "go.etcd.io/bbolt"

	"jiutouniao/internal/events"
)

var (
	bucketProjects  = []byte("projects")
	bucketFindings  = []byte("findings")
	bucketAssets    = []byte("assets")
	bucketTimeline  = []byte("timeline")
	bucketApprovals = []byte("approvals")
	bucketEvidence  = []byte("evidence")
	bucketCoverage  = []byte("coverage")
	bucketUsage     = []byte("usage")
	bucketSettings  = []byte("settings")
	bucketChats     = []byte("chats")
	bucketStream    = []byte("stream")
	bucketSubtasks  = []byte("subtasks")
	bucketAsks      = []byte("asks")
	bucketFacts     = []byte("facts") // v3.3.0 项目黑板（事实账本）
	bucketLoot      = []byte("loot")  // v3.3.0 战利品库（凭据/票据/flag 掩码登记）
	// v5.5.0 能力修复：结构化凭据仓库（静态加密，明文仅执行瞬间解密）与压缩前工具回执归档（按 receipt id 可检索原文）
	bucketCredentials = []byte("credentials")
	bucketReceipts    = []byte("receipts")
	bucketLessons     = []byte("lessons") // v3.4.0 组织级教训库（跨项目脱敏经验）
	bucketVTs         = []byte("vts")     // v4.6 A2 验证队列（VerificationTask 一等对象）
)

// ---------- 记录结构 ----------

type Project struct {
	ID               string                 `json:"id"`
	Name             string                 `json:"name"`
	Target           string                 `json:"target"`
	Scope            string                 `json:"scope"`
	ROE              string                 `json:"roe"`
	TestType         string                 `json:"test_type"`         // 黑盒/灰盒/白盒
	TimeWindow       string                 `json:"time_window"`       // 测试时间窗口
	Contact          string                 `json:"contact"`           // 应急联系人
	SuccessCriteria  string                 `json:"success_criteria"`  // 测试目的 / 成功标准
	AuthInfo         string                 `json:"auth_info"`         // 认证会话（可选·登录后测试）
	ExecutionProfile string                 `json:"execution_profile"` // v5.3.1：执行档 production_safe（默认）/isolated_lab——引擎逐动作强制校验
	PostExploit      bool                   `json:"post_exploit"`      // v5.3.7：后渗透勾选——false（默认）s6 整段 skipped（范围决策非漏测），true 按流水线正常执行
	StrictScope      bool                   `json:"strict_scope"`      // 严格限定范围（只测给定目标）
	BudgetTokens     int64                  `json:"budget_tokens"`     // 项目级 Token 预算（0=用全局配置）
	Authorized       bool                   `json:"authorized"`        // 创建时勾选授权确认（视为已授权开工）
	ModelID          string                 `json:"model_id"`          // 本项目使用的模型（空=默认模型）
	AutoApprove      string                 `json:"auto_approve"`      // 审批策略：manual（默认，全部人工）/l1（仅 L1 自动）/all（L1+L2 自动）；空=全局配置
	PreApproved      string                 `json:"pre_approved"`      // v6.0.0：预批准档 none（默认人工）/all（全通过——含提权/横向及后续新增类别）/逗号类别（privesc,lateral,persistence）；仅自动签人工核签环节，治理门照常前置
	Specializations  []string               `json:"specializations"`   // A / B1 / B2
	Status           string                 `json:"status"`            // created/running/paused/killed/done
	CurrentStage     string                 `json:"current_stage"`
	CreatedAt        time.Time              `json:"created_at"`
	StartedAt        string                 `json:"started_at,omitempty"`  // v2.6：首次启动时间（断点续跑不重置，仪表盘运行时长基准）
	FinishedAt       string                 `json:"finished_at,omitempty"` // v2.6：终态时间（done/failed/killed），仪表盘总耗时基准
	StageStates      map[string]*StageState `json:"stage_states"`          // key: stage id（s0..s9, specA/B1/B2）
	KillReason       string                 `json:"kill_reason,omitempty"`
}

// StageState 单个阶段头的执行状态。
type StageState struct {
	Status       string   `json:"status"` // pending/running/done/skipped/failed
	Summary      string   `json:"summary,omitempty"`
	Deliverables []string `json:"deliverables,omitempty"`
	Iterations   int      `json:"iterations"`
	StartedAt    string   `json:"started_at,omitempty"`
	EndedAt      string   `json:"ended_at,omitempty"`
	Review       string   `json:"review,omitempty"`        // 反思门审查意见（PentAGI reflector 移植）
	ReviewRounds int      `json:"review_rounds,omitempty"` // 反思门已拦截次数（上限 2，防死循环）
	// v4.8 M5：反思门 LLM 调用失败计数（重试 3 次全败记 1 次）——按阶段统计自查可靠性，
	// 持续高失败时 buildContextPack 注入修复提示（M5 频次监控）。
	ReflectFailures int `json:"reflect_failures,omitempty"`
	// v5.5.0：预算耗尽暂停语义（budget_exhausted_policy=pause 时）——阶段可续跑而非被代收口为 done。
	// PauseReason 记录暂停原因，人工提升预算或手动重跑该阶段后从 pending 继续。
	PauseReason string `json:"pause_reason,omitempty"`
	// v5.9.1：最后活动时间（每次 runStage 进入刷新；StartedAt 保持首次进入——
	// 重入/断点续跑不覆盖，阶段耗时图反映真实起点）。
	LastActiveAt string `json:"last_active_at,omitempty"`
}

// FindingClaim v4.6 E1：结论-证据判据串（断言与所引文件内容的机械绑定）。
// record_finding 时由引擎逐条校验 file 存在且含 must_contain，杜绝"空 jar"式断言脱钩。
type FindingClaim struct {
	File        string `json:"file"`         // 工作区相对路径（evidence/…）
	MustContain string `json:"must_contain"` // 必须出现在该文件中的判据串
}

// FindingPOC v5.3.6：POC 自包含展示（Burp 式请求/响应原始文本对）——模型登记发现时提供，
// 未提供时 Web 层从命令类证据记录自动回填（Input=请求侧，Output=响应侧）。
type FindingPOC struct {
	Request    string `json:"request"`
	Response   string `json:"response"`
	Backfilled bool   `json:"backfilled,omitempty"` // true=证据回填（非模型原始提供）
}

type Finding struct {
	ID         string `json:"id"`
	ProjectID  string `json:"project_id"`
	Stage      string `json:"stage"`
	Title      string `json:"title"`
	Severity   string `json:"severity"`      // 高/中/低/信息
	CWE        string `json:"cwe,omitempty"` // v2.7 A4：标准编号，如 CWE-89 / CWE-79（Nebula 式映射）
	Detail     string `json:"detail"`
	Confidence string `json:"confidence"`            // 确证/疑似/待查
	Access     string `json:"access,omitempty"`      // v4.4 利用前提：anonymous/pre-auth/post-auth（S5 队列消费依据）
	ImpactRank int    `json:"impact_rank,omitempty"` // v4.4 影响排序 1-6（1=RCE系…5=上传落点；0=未标注）
	// v4.6 E4 可利用性双维：verified（已实测利用）/ conditional（条件性，schema 未知等）/ untested（未投递）。
	// 高危+untested 由引擎自动降级为中级呈现（F2320 双轨定级口径固化）。
	Exploitability string         `json:"exploitability,omitempty"`
	Claims         []FindingClaim `json:"claims,omitempty"`      // v4.6 E1 判据串（肯定/否定断言均应有）
	Remediation    string         `json:"remediation,omitempty"` // v5.3.6：修复建议（LLM 登记时提供；旧数据为空→UI 显示「未填写」）
	POC            []FindingPOC   `json:"poc,omitempty"`         // v5.3.6：POC 请求/响应对（≤5 组，单侧 ≤16KB 截断）
	EvidenceIDs    []string       `json:"evidence_ids"`          // v5.3.6 起参数废弃：模型不再显式提供，一律引擎自动关联真实证据编号；字段保留供旧数据展示
	CreatedAt      time.Time      `json:"created_at"`
}

type Asset struct {
	ID        string    `json:"id"`
	ProjectID string    `json:"project_id"`
	Stage     string    `json:"stage"`
	Type      string    `json:"type"` // 域名/IP/服务/AI应用/APP/小程序...
	Value     string    `json:"value"`
	Detail    string    `json:"detail"`
	CreatedAt time.Time `json:"created_at"`
}

type TimelineEvent struct {
	ID        string    `json:"id"`
	ProjectID string    `json:"project_id"`
	Stage     string    `json:"stage"`
	Event     string    `json:"event"`
	Detail    string    `json:"detail"`
	CreatedAt time.Time `json:"created_at"`
}

type Approval struct {
	ID          string     `json:"id"`
	ProjectID   string     `json:"project_id"`
	Stage       string     `json:"stage"`
	Action      string     `json:"action"`               // 待批动作描述（含命令/文件）
	Risk        string     `json:"risk"`                 // L1/L2
	Mode        string     `json:"mode"`                 // 决策路径：manual（人工批准）/auto（策略自动批准）
	Status      string     `json:"status"`               // pending/approved/rejected/cancelled
	Kind        string     `json:"kind,omitempty"`       // v6.0.0：scope_extension=授权扩展工单（批准即登记资产放行，scopeGate 白名单自动纳入）
	Target      string     `json:"target,omitempty"`     // v6.0.0：scope_extension 工单的扩展目标（host/IP）
	RequestedAt time.Time  `json:"requested_at"`
	DecidedAt   *time.Time `json:"decided_at,omitempty"`
	DecidedBy   string     `json:"decided_by,omitempty"` // web-operator / auto-policy / pre-approved(...)
}

// EvidenceRecord 证据链单条记录（对应贯穿线一：全程记录）。
type EvidenceRecord struct {
	ID         string    `json:"id"`
	ProjectID  string    `json:"project_id"`
	Stage      string    `json:"stage"`
	Type       string    `json:"type"` // command/file/finding/approval/stage
	Input      string    `json:"input"`
	Output     string    `json:"output,omitempty"`
	Risk       string    `json:"risk,omitempty"`
	ApprovedBy string    `json:"approved_by,omitempty"` // auto / 人工ID
	ExitCode   int       `json:"exit_code,omitempty"`
	DurationMs int64     `json:"duration_ms,omitempty"`
	CreatedAt  time.Time `json:"created_at"`
}

// Subtask 阶段内子任务（PentAGI task/subtask 双层模型移植）：
// 阶段头把当阶段工作拆解为可跟踪的子任务清单，进度可查可回填。
type Subtask struct {
	ID          string    `json:"id"`
	ProjectID   string    `json:"project_id"`
	Stage       string    `json:"stage"`
	Title       string    `json:"title"`
	Detail      string    `json:"detail,omitempty"`
	Status      string    `json:"status"` // created/running/waiting/finished/failed
	Result      string    `json:"result,omitempty"`
	Priority    int       `json:"priority,omitempty"`     // v5.3.2 P1-5：覆盖缺口/风险/证据自调优先级（1=最高，引擎重排，id 稳定）
	PriorityWhy string    `json:"priority_why,omitempty"` // 排序依据（覆盖缺口/高危动作/证据缺口…供头引用）
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// AskRecord 向人提问（PentAGI ask_user 屏障移植）：阶段/对话执行中挂起等待人工回答，全量留痕。
type AskRecord struct {
	ID         string     `json:"id"`
	ProjectID  string     `json:"project_id"`
	Stage      string     `json:"stage"`
	Question   string     `json:"question"`
	Answer     string     `json:"answer,omitempty"`
	Status     string     `json:"status"` // pending/answered/cancelled
	CreatedAt  time.Time  `json:"created_at"`
	AnsweredAt *time.Time `json:"answered_at,omitempty"`
	AnsweredBy string     `json:"answered_by,omitempty"`
	// v5.6.0：提问类型（空=普通问答；"credential"=凭据专用通道——回答不落明文，
	// 引擎拦截原文写入加密凭据仓库，Answer 只保留掩码摘要）。
	Kind string `json:"kind,omitempty"`
}

// FactRecord v3.3.0 项目黑板（CyberStrikeAI pentest-blackboard 移植）：跨阶段可复用的结构化事实账本。
// confidence 三态：confirmed（有证据确证）/ tentative（线索待验证）/ deprecated（已排除/误报——
// 负结果同样落库，防止后续阶段重复试错）。同 project+key 幂等 upsert。
type FactRecord struct {
	ID         string    `json:"id"`
	ProjectID  string    `json:"project_id"`
	Stage      string    `json:"stage,omitempty"`
	Key        string    `json:"key"`             // 事实键（如 http://target:8080/login、svc.db.mysql.cred）
	Value      string    `json:"value"`           // 事实内容（含 primitive:READ/WRITE/EXEC/SSRF/SQLI/AUTHZ/CRED 原语标注）
	Confidence string    `json:"confidence"`      // confirmed/tentative/deprecated
	Links      []string  `json:"links,omitempty"` // 关联事实键/发现 ID（凑链图边）
	Note       string    `json:"note,omitempty"`  // 证据摘要/排除原因
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
}

// LessonRecord v3.4.0 组织级教训库（BoxPwnr 失败后分析注入的跨项目版）：
// 项目收口时的通用经验/教训——**必须脱敏**（不含目标域名/IP/单位/凭据），
// 引擎写入前做合规校验，跨项目注入上下文供后续任务避免重复踩坑。
type LessonRecord struct {
	ID   string `json:"id"`
	Text string `json:"text"`           // 一句话教训（脱敏）
	Tags string `json:"tags,omitempty"` // 类别标签（如 方法论,工具,风控）
	// v4.6 E5/K2 结构化字段：教训可按行为类/技术栈检索注入（替代按目标名检索失配——
	// 审计实证：某历史任务未检索到同日另一任务的行为类教训（教训检索时序缺口））。
	BehaviorClass string    `json:"behavior_class,omitempty"` // rate-limited/js-challenge-waf/closed-site/appliance-mgmt/…
	Stack         string    `json:"stack,omitempty"`          // php/aspnet/domino/spring/…
	SampleSize    string    `json:"sample_size,omitempty"`    // 证据强度（如 "3 样本" / "单次实验"）
	ValidScope    string    `json:"valid_scope,omitempty"`    // 适用范围（如 "rate-limited 类通用" / "仅该 WAF 版本"）
	CreatedAt     time.Time `json:"created_at"`
}

// LootRecord v3.3.0 战利品库（BoxPwnr flag 库 + EVA verification 思想）：
// 凭据/票据/flag/hash 只登记掩码摘要与来源位置，不存明文（与 S5「凭据只登记摘要」纪律一致）。
type LootRecord struct {
	ID        string    `json:"id"`
	ProjectID string    `json:"project_id"`
	Stage     string    `json:"stage,omitempty"`
	Type      string    `json:"type"`     // credential/flag/hash/token/cookie/key/session
	Target    string    `json:"target"`   // 归属目标（主机/服务/账号）
	Masked    string    `json:"masked"`   // 掩码摘要（如 adm***23 / NTLM:32d***a1）
	Source    string    `json:"source"`   // 来源（路径/接口/转储位置）
	Verified  string    `json:"verified"` // unverified/verified/invalid
	CreatedAt time.Time `json:"created_at"`
}

// ---------- Store ----------

type Store struct {
	db *bolt.DB
}

// Open 打开（必要时创建）数据库；dbPath 位于项目工作区根目录。
func Open(dataDir string) (*Store, error) {
	if err := os.MkdirAll(dataDir, 0o750); err != nil {
		return nil, err
	}
	db, err := bolt.Open(filepath.Join(dataDir, "jiutouniao.db"), 0o600, &bolt.Options{Timeout: 5 * time.Second})
	if err != nil {
		return nil, err
	}
	err = db.Update(func(tx *bolt.Tx) error {
		for _, b := range [][]byte{bucketProjects, bucketFindings, bucketAssets, bucketTimeline, bucketApprovals, bucketEvidence, bucketCoverage, bucketUsage, bucketSettings, bucketChats, bucketStream, bucketSubtasks, bucketAsks, bucketFacts, bucketLoot, bucketLessons, bucketVTs, bucketCredentials, bucketReceipts} {
			if _, err := tx.CreateBucketIfNotExists(b); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		db.Close()
		return nil, err
	}
	return &Store{db: db}, nil
}

func (s *Store) Close() error { return s.db.Close() }

func newID(prefix string) string {
	b := make([]byte, 5)
	_, _ = rand.Read(b)
	return fmt.Sprintf("%s-%s", prefix, strings.ToUpper(hex.EncodeToString(b)))
}

func putJSON(tx *bolt.Tx, bucket []byte, key string, v any) error {
	b := tx.Bucket(bucket)
	raw, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return b.Put([]byte(key), raw)
}

func getJSON(tx *bolt.Tx, bucket []byte, key string, v any) error {
	raw := tx.Bucket(bucket).Get([]byte(key))
	if raw == nil {
		return fmt.Errorf("记录不存在")
	}
	return json.Unmarshal(raw, v)
}

// ---------- 项目 ----------

func (s *Store) CreateProject(p *Project) error {
	p.ID = newID("JT")
	p.CreatedAt = time.Now()
	// v5.3.1：执行档缺省 production_safe（缺省收紧——空/未知档一律按生产口径逐动作校验）
	if p.ExecutionProfile != "isolated_lab" {
		p.ExecutionProfile = "production_safe"
	}
	// v6.0.0：预批准档缺省 none（fail-closed——空/无效值一律回退人工审批，绝不静默放行）
	p.PreApproved = NormalizePreApproved(p.PreApproved)
	if p.StageStates == nil {
		p.StageStates = map[string]*StageState{}
	}
	return s.db.Update(func(tx *bolt.Tx) error { return putJSON(tx, bucketProjects, p.ID, p) })
}

// PreApprovedCategories v6.0.0：预批准类别白名单（"all"=全通过，天然覆盖提权/横向及后续新增类别）。
var preApprovedValid = map[string]bool{"privesc": true, "lateral": true, "persistence": true}

// NormalizePreApproved 归一化预批准档：none（默认）/all/类别逗号列表；无效项剔除，全无效回 none。
func NormalizePreApproved(v string) string {
	v = strings.ToLower(strings.TrimSpace(v))
	if v == "" || v == "none" {
		return "none"
	}
	if v == "all" {
		return "all"
	}
	out := []string{}
	for _, c := range strings.Split(v, ",") {
		c = strings.TrimSpace(c)
		if preApprovedValid[c] {
			out = append(out, c)
		}
	}
	if len(out) == 0 {
		return "none"
	}
	return strings.Join(out, ",")
}

func (s *Store) SaveProject(p *Project) error {
	return s.db.Update(func(tx *bolt.Tx) error { return putJSON(tx, bucketProjects, p.ID, p) })
}

func (s *Store) GetProject(id string) (*Project, error) {
	var p Project
	err := s.db.View(func(tx *bolt.Tx) error { return getJSON(tx, bucketProjects, id, &p) })
	if err != nil {
		return nil, err
	}
	return &p, nil
}

func (s *Store) ListProjects() ([]*Project, error) {
	var out []*Project
	err := s.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketProjects).ForEach(func(_, v []byte) error {
			var p Project
			if err := json.Unmarshal(v, &p); err == nil {
				out = append(out, &p)
			}
			return nil
		})
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out, nil
}

// DeleteProject v5.3.5：彻底删除项目——主记录 + 全部项目作用域记录（发现/资产/时间线/审批/
// 证据/覆盖/用量/会话/执行流/子任务/提问/黑板/战利品/验证队列）+ 键前缀作用域桶（coverage=ID\x00、
// stream=ID|seq）。组织级桶（lessons=跨项目教训库、settings=全局设置）不触碰。
func (s *Store) DeleteProject(id string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		pb := tx.Bucket(bucketProjects)
		if pb.Get([]byte(id)) == nil {
			return fmt.Errorf("记录不存在")
		}
		pb.Delete([]byte(id))
		tx.Bucket(bucketUsage).Delete([]byte(id))
		tx.Bucket(bucketChats).Delete([]byte(id))
		// 键前缀作用域桶：coverage（ID\x00...）与 stream（ID|seq）
		for _, spec := range []struct {
			bkt    *bolt.Bucket
			prefix string
		}{{tx.Bucket(bucketCoverage), id + "\x00"}, {tx.Bucket(bucketStream), id + "|"}} {
			if spec.bkt == nil {
				continue
			}
			var keys [][]byte
			c := spec.bkt.Cursor()
			for k, _ := c.First(); k != nil; k, _ = c.Next() {
				if strings.HasPrefix(string(k), spec.prefix) {
					keys = append(keys, append([]byte{}, k...))
				}
			}
			for _, k := range keys {
				spec.bkt.Delete(k)
			}
		}
		// 记录体含 project_id 字段的桶（key=记录 ID，需解 JSON 判归属）
		type owner struct {
			ProjectID string `json:"project_id"`
		}
		for _, b := range [][]byte{bucketFindings, bucketAssets, bucketTimeline, bucketApprovals,
			bucketEvidence, bucketSubtasks, bucketAsks, bucketFacts, bucketLoot, bucketVTs,
			bucketCredentials, bucketReceipts} {
			bkt := tx.Bucket(b)
			if bkt == nil {
				continue
			}
			var keys [][]byte
			c := bkt.Cursor()
			for k, v := c.First(); k != nil; k, v = c.Next() {
				var r owner
				if json.Unmarshal(v, &r) == nil && r.ProjectID == id {
					keys = append(keys, append([]byte{}, k...))
				}
			}
			for _, k := range keys {
				bkt.Delete(k)
			}
		}
		return nil
	})
}

// ---------- 发现 / 资产 / 时间线 ----------

func (s *Store) AddFinding(f *Finding) (string, error) {
	// v4.6 B1 入口判重：归一化标题（小写/全角转半角/去空白）完全一致 → 拒绝并指认已有条目。
	// 审计实证（某历史任务两条同题双记入库）——同根因合并在登记层完成，
	// 不留给收口门兜底（收口门只拦 24 字符前缀近似，入口层拦全等）。
	if dup := s.findDuplicateFinding(f.ProjectID, f.Title); dup != "" {
		return "", fmt.Errorf("疑似重复发现：与已有 %s 归一化标题完全一致——同根因请合并（在 detail 引用原 id 补充增量信息），确为独立发现请改写标题以区分位置/参数", dup)
	}
	f.ID = newID("F")
	f.CreatedAt = time.Now()
	return f.ID, s.db.Update(func(tx *bolt.Tx) error { return putJSON(tx, bucketFindings, f.ID, f) })
}

// normFindingTitle v4.6 B1：归一化标题（小写/全角转半角/去空白）。与 orchestrator s8 双记拦截口径一致。
func normFindingTitle(t string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(t) {
		if r >= 0xFF00 && r <= 0xFF5E {
			r -= 0xFEE0
		}
		if r != ' ' && r != '\t' && r != '　' {
			b.WriteRune(r)
		}
	}
	return b.String()
}

func (s *Store) findDuplicateFinding(projectID, title string) string {
	key := normFindingTitle(title)
	if key == "" {
		return ""
	}
	dup := ""
	_ = s.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketFindings).ForEach(func(_, v []byte) error {
			if dup != "" {
				return nil
			}
			var f Finding
			if json.Unmarshal(v, &f) == nil && f.ProjectID == projectID && normFindingTitle(f.Title) == key {
				dup = f.ID
			}
			return nil
		})
	})
	return dup
}

// UpdateFinding v4.4：发现更新（反思门判据抽查降级用——确证未引判据 → 疑似+补证提示）。
func (s *Store) UpdateFinding(f *Finding) error {
	return s.db.Update(func(tx *bolt.Tx) error { return putJSON(tx, bucketFindings, f.ID, f) })
}

func (s *Store) AddAsset(a *Asset) (string, error) {
	a.ID = newID("A")
	a.CreatedAt = time.Now()
	return a.ID, s.db.Update(func(tx *bolt.Tx) error { return putJSON(tx, bucketAssets, a.ID, a) })
}

func (s *Store) AddTimeline(t *TimelineEvent) (string, error) {
	t.ID = newID("T")
	t.CreatedAt = time.Now()
	return t.ID, s.db.Update(func(tx *bolt.Tx) error { return putJSON(tx, bucketTimeline, t.ID, t) })
}

func listBy[T any](s *Store, bucket []byte, projectID string) ([]*T, error) {
	out := []*T{} // 非 nil：序列化为 [] 而非 null，避免前端读 .length 崩溃
	err := s.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket(bucket).ForEach(func(_, v []byte) error {
			var rec T
			if err := json.Unmarshal(v, &rec); err == nil {
				if getProjectID(rec) == projectID {
					out = append(out, &rec)
				}
			}
			return nil
		})
	})
	return out, err
}

// 通过字段名取 project_id（避免为每个类型写重复遍历）。
func getProjectID(rec any) string {
	switch r := rec.(type) {
	case Finding:
		return r.ProjectID
	case *Finding:
		return r.ProjectID
	case Asset:
		return r.ProjectID
	case *Asset:
		return r.ProjectID
	case TimelineEvent:
		return r.ProjectID
	case *TimelineEvent:
		return r.ProjectID
	case Approval:
		return r.ProjectID
	case *Approval:
		return r.ProjectID
	case EvidenceRecord:
		return r.ProjectID
	case *EvidenceRecord:
		return r.ProjectID
	case Subtask:
		return r.ProjectID
	case *Subtask:
		return r.ProjectID
	case AskRecord:
		return r.ProjectID
	case *AskRecord:
		return r.ProjectID
	case FactRecord: // v3.3.0
		return r.ProjectID
	case *FactRecord:
		return r.ProjectID
	case LootRecord:
		return r.ProjectID
	case *LootRecord:
		return r.ProjectID
	case VerificationTask: // v4.6 A2
		return r.ProjectID
	case *VerificationTask:
		return r.ProjectID
	case CredentialRecord: // v5.5.0 凭据仓库
		return r.ProjectID
	case *CredentialRecord:
		return r.ProjectID
	case ReceiptRecord: // v5.5.0 回执归档
		return r.ProjectID
	case *ReceiptRecord:
		return r.ProjectID
	}
	return ""
}

func (s *Store) ListFindings(projectID string) ([]*Finding, error) {
	out, err := listBy[Finding](s, bucketFindings, projectID)
	sortFindings(out)
	return out, err
}

func sortFindings(fs []*Finding) {
	rank := map[string]int{"高": 0, "中": 1, "低": 2, "信息": 3}
	sort.Slice(fs, func(i, j int) bool {
		if rank[fs[i].Severity] != rank[fs[j].Severity] {
			return rank[fs[i].Severity] < rank[fs[j].Severity]
		}
		return fs[i].CreatedAt.After(fs[j].CreatedAt)
	})
}

func (s *Store) ListAssets(projectID string) ([]*Asset, error) {
	return listBy[Asset](s, bucketAssets, projectID)
}

func (s *Store) ListTimeline(projectID string) ([]*TimelineEvent, error) {
	out, err := listBy[TimelineEvent](s, bucketTimeline, projectID)
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
	return out, err
}

// ---------- 审批 ----------

func (s *Store) AddApproval(a *Approval) (string, error) {
	a.ID = newID("AP")
	a.RequestedAt = time.Now()
	return a.ID, s.db.Update(func(tx *bolt.Tx) error { return putJSON(tx, bucketApprovals, a.ID, a) })
}

func (s *Store) SaveApproval(a *Approval) error {
	return s.db.Update(func(tx *bolt.Tx) error { return putJSON(tx, bucketApprovals, a.ID, a) })
}

func (s *Store) GetApproval(id string) (*Approval, error) {
	var a Approval
	err := s.db.View(func(tx *bolt.Tx) error { return getJSON(tx, bucketApprovals, id, &a) })
	if err != nil {
		return nil, err
	}
	return &a, nil
}

func (s *Store) ListApprovals(projectID string) ([]*Approval, error) {
	out, err := listBy[Approval](s, bucketApprovals, projectID)
	sort.Slice(out, func(i, j int) bool { return out[i].RequestedAt.After(out[j].RequestedAt) })
	return out, err
}

// ---------- 证据 ----------

func (s *Store) AddEvidence(e *EvidenceRecord) (string, error) {
	e.ID = newID("EV")
	e.CreatedAt = time.Now()
	return e.ID, s.db.Update(func(tx *bolt.Tx) error { return putJSON(tx, bucketEvidence, e.ID, e) })
}

func (s *Store) ListEvidence(projectID string) ([]*EvidenceRecord, error) {
	out, err := listBy[EvidenceRecord](s, bucketEvidence, projectID)
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
	return out, err
}

// ---------- 覆盖度账本（移植自 strix outcome 枚举 + PentesterFlow 三元组矩阵） ----------

// CoverageEntry 覆盖矩阵单元：键 = (Endpoint, Param, VulnClass)，重复写入原地更新。
type CoverageEntry struct {
	ProjectID string `json:"project_id"`
	Stage     string `json:"stage"`
	Endpoint  string `json:"endpoint"`   // 如 "GET /api/user"；无 HTTP 语境时填资产/目标
	Param     string `json:"param"`      // 参数名，可空
	VulnClass string `json:"vuln_class"` // 漏洞类：注入/XSS/越权/认证/SSRF/LLM01提示注入...
	Status    string `json:"status"`     // vulnerable/no_issue_found/ruled_out/waf_blocked/skipped/needs_follow_up
	Notes     string `json:"notes"`      // 证据摘要（ruled_out/needs_follow_up 必填）
	// v4.6 E3 负结果语义：negative_valid（有有效请求/响应原文支撑的真阴性）/
	// undetermined_timeout（超时未定性）/ blocked_ratelimit / blocked_waf / not_tested。
	// 前两类之外的状态值不得支撑 ruled_out/no_issue_found 终态（orchestrator 强制）。
	ObservedResult string    `json:"observed_result,omitempty"`
	Count          int       `json:"count"` // 该单元测试次数
	FirstSeen      time.Time `json:"first_seen"`
	LastSeen       time.Time `json:"last_seen"`
}

// normCoverageEndpoint v4.6 V6：覆盖单元键归一化——去 scheme 前缀（http:// / https://）、
// 去首尾空白与结尾斜杠。审计实证（某历史任务：`www.` 与 `https://www.` 两键并存产生 9 个僵尸
// needs_follow_up，真实盲区被高估 9 倍）：键计算一律用归一化形态，展示保留首见原文。
func normCoverageEndpoint(ep string) string {
	e := strings.TrimSpace(ep)
	e = strings.TrimPrefix(e, "https://")
	e = strings.TrimPrefix(e, "http://")
	e = strings.TrimSuffix(e, "/")
	return e
}

// UpsertCoverage 原地更新覆盖矩阵单元；返回该条记录。
// NormCoverageEndpoint v4.6：导出给引擎门禁复用（s7 僵尸 NF 检测）。
func NormCoverageEndpoint(ep string) string { return normCoverageEndpoint(ep) }

func (s *Store) UpsertCoverage(c *CoverageEntry) (*CoverageEntry, error) {
	key := strings.Join([]string{c.ProjectID, normCoverageEndpoint(c.Endpoint), c.Param, c.VulnClass}, "\x00")
	err := s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketCoverage)
		if raw := b.Get([]byte(key)); raw != nil {
			var old CoverageEntry
			if err := json.Unmarshal(raw, &old); err == nil {
				old.Count++
				old.Status = c.Status
				old.Notes = c.Notes
				old.ObservedResult = c.ObservedResult
				old.Stage = c.Stage
				old.LastSeen = time.Now()
				return b.Put([]byte(key), mustJSON(&old))
			}
		}
		c.Count = 1
		c.FirstSeen = time.Now()
		c.LastSeen = time.Now()
		return b.Put([]byte(key), mustJSON(c))
	})
	if err != nil {
		return nil, err
	}
	var out CoverageEntry
	_ = s.db.View(func(tx *bolt.Tx) error { return getJSON(tx, bucketCoverage, key, &out) })
	return &out, nil
}

// AddCoverageKeepKey v4.6：按原始键写入（绕过归一化合并）——供历史数据迁移/导入与门禁测试使用。
func (s *Store) AddCoverageKeepKey(c *CoverageEntry) error {
	key := strings.Join([]string{c.ProjectID, c.Endpoint, c.Param, c.VulnClass}, "\x00")
	if c.Count == 0 {
		c.Count = 1
	}
	if c.FirstSeen.IsZero() {
		c.FirstSeen = time.Now()
	}
	if c.LastSeen.IsZero() {
		c.LastSeen = time.Now()
	}
	return s.db.Update(func(tx *bolt.Tx) error { return putJSON(tx, bucketCoverage, key, c) })
}

func (s *Store) ListCoverage(projectID string) ([]*CoverageEntry, error) {
	var out []*CoverageEntry
	err := s.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketCoverage).ForEach(func(k, v []byte) error {
			if !strings.HasPrefix(string(k), projectID+"\x00") {
				return nil
			}
			var c CoverageEntry
			if err := json.Unmarshal(v, &c); err == nil {
				out = append(out, &c)
			}
			return nil
		})
	})
	return out, err
}

// ---------- Token/成本账本（移植自 deadend 分账 + strix 双账） ----------

// UsageRecord 项目级用量：按阶段分账，成本按配置单价估算。
type UsageRecord struct {
	ProjectID   string           `json:"project_id"`
	TotalTokens int64            `json:"total_tokens"`
	InTokens    int64            `json:"in_tokens"`
	OutTokens   int64            `json:"out_tokens"`
	ByStage     map[string]int64 `json:"by_stage"`
	Calls       int              `json:"calls"`
	UpdatedAt   time.Time        `json:"updated_at"`
}

// AddUsage 累计用量（输入/输出分账，成本按当前单价在展示层计算）。
func (s *Store) AddUsage(projectID, stage string, inTokens, outTokens int64) (*UsageRecord, error) {
	rec := UsageRecord{ProjectID: projectID, ByStage: map[string]int64{}}
	_ = s.db.View(func(tx *bolt.Tx) error {
		if raw := tx.Bucket(bucketUsage).Get([]byte(projectID)); raw != nil {
			_ = json.Unmarshal(raw, &rec)
		}
		return nil
	})
	if rec.ByStage == nil {
		rec.ByStage = map[string]int64{}
	}
	total := inTokens + outTokens
	rec.TotalTokens += total
	rec.InTokens += inTokens
	rec.OutTokens += outTokens
	rec.ByStage[stage] += total
	rec.Calls++
	rec.UpdatedAt = time.Now()
	err := s.db.Update(func(tx *bolt.Tx) error { return putJSON(tx, bucketUsage, projectID, &rec) })
	return &rec, err
}

func (s *Store) GetUsage(projectID string) (*UsageRecord, error) {
	var rec UsageRecord
	err := s.db.View(func(tx *bolt.Tx) error { return getJSON(tx, bucketUsage, projectID, &rec) })
	if err != nil {
		return &UsageRecord{ProjectID: projectID, ByStage: map[string]int64{}}, nil
	}
	return &rec, nil
}

func mustJSON(v any) []byte {
	b, _ := json.Marshal(v)
	return b
}

// ---------- 设置（加密后落库）与对话持久化 ----------

func (s *Store) SaveSetting(key string, val []byte) error {
	return s.db.Update(func(tx *bolt.Tx) error { return tx.Bucket(bucketSettings).Put([]byte(key), val) })
}

func (s *Store) GetSetting(key string) ([]byte, bool) {
	var out []byte
	_ = s.db.View(func(tx *bolt.Tx) error {
		v := tx.Bucket(bucketSettings).Get([]byte(key))
		if v != nil {
			out = append([]byte{}, v...)
		}
		return nil
	})
	return out, out != nil
}

func (s *Store) SaveChat(projectID string, msgs []byte) error {
	return s.db.Update(func(tx *bolt.Tx) error { return tx.Bucket(bucketChats).Put([]byte(projectID), msgs) })
}

func (s *Store) LoadChat(projectID string) ([]byte, bool) {
	var out []byte
	_ = s.db.View(func(tx *bolt.Tx) error {
		v := tx.Bucket(bucketChats).Get([]byte(projectID))
		if v != nil {
			out = append([]byte{}, v...)
		}
		return nil
	})
	return out, out != nil
}

func (s *Store) DeleteChat(projectID string) error {
	return s.db.Update(func(tx *bolt.Tx) error { return tx.Bucket(bucketChats).Delete([]byte(projectID)) })
}

// ---------- 子任务（PentAGI 双层任务模型移植） ----------

func (s *Store) AddSubtask(t *Subtask) (string, error) {
	t.ID = newID("ST")
	now := time.Now()
	t.CreatedAt, t.UpdatedAt = now, now
	if t.Status == "" {
		t.Status = "created"
	}
	return t.ID, s.db.Update(func(tx *bolt.Tx) error { return putJSON(tx, bucketSubtasks, t.ID, t) })
}

func (s *Store) SaveSubtask(t *Subtask) error {
	t.UpdatedAt = time.Now()
	return s.db.Update(func(tx *bolt.Tx) error { return putJSON(tx, bucketSubtasks, t.ID, t) })
}

func (s *Store) GetSubtask(id string) (*Subtask, error) {
	var t Subtask
	err := s.db.View(func(tx *bolt.Tx) error { return getJSON(tx, bucketSubtasks, id, &t) })
	if err != nil {
		return nil, err
	}
	return &t, nil
}

// ListSubtasks 返回项目子任务（创建时间升序，同阶段内按计划顺序）。
func (s *Store) ListSubtasks(projectID string) ([]*Subtask, error) {
	out, err := listBy[Subtask](s, bucketSubtasks, projectID)
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
	return out, err
}

// DeleteStageSubtasks 清空某阶段现有计划（plan_subtasks 全量重建时用）。
func (s *Store) DeleteStageSubtasks(projectID, stage string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		c := tx.Bucket(bucketSubtasks).Cursor()
		for k, v := c.First(); k != nil; k, v = c.Next() {
			var t Subtask
			if json.Unmarshal(v, &t) == nil && t.ProjectID == projectID && t.Stage == stage {
				if err := c.Delete(); err != nil {
					return err
				}
			}
		}
		return nil
	})
}

// ---------- 向人提问（PentAGI ask_user 移植，全量留痕） ----------

func (s *Store) AddAsk(a *AskRecord) (string, error) {
	a.ID = newID("AQ")
	a.CreatedAt = time.Now()
	if a.Status == "" {
		a.Status = "pending"
	}
	return a.ID, s.db.Update(func(tx *bolt.Tx) error { return putJSON(tx, bucketAsks, a.ID, a) })
}

func (s *Store) SaveAsk(a *AskRecord) error {
	return s.db.Update(func(tx *bolt.Tx) error { return putJSON(tx, bucketAsks, a.ID, a) })
}

func (s *Store) GetAsk(id string) (*AskRecord, error) {
	var a AskRecord
	err := s.db.View(func(tx *bolt.Tx) error { return getJSON(tx, bucketAsks, id, &a) })
	if err != nil {
		return nil, err
	}
	return &a, nil
}

func (s *Store) ListAsks(projectID string) ([]*AskRecord, error) {
	out, err := listBy[AskRecord](s, bucketAsks, projectID)
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out, err
}

// LastEvidenceIDs 取项目（可限阶段）最近 n 条证据编号——用于发现自动关联证据。
func (s *Store) LastEvidenceIDs(projectID, stage string, n int) []string {
	all, err := s.ListEvidence(projectID)
	if err != nil {
		return nil
	}
	var ids []string
	for i := len(all) - 1; i >= 0 && len(ids) < n; i-- {
		if stage == "" || all[i].Stage == stage {
			ids = append(ids, all[i].ID)
		}
	}
	return ids
}

// ---------- 执行消息流（PentAGI 式消息流持久化：对话消息/工具调用/引擎日志） ----------

// StreamRecord 执行流单条记录：kind ∈ msg（AI 对话消息）/tool（工具调用）/log（引擎日志）。
// 全量落库，Web 刷新后按 seq 回填，与 WebSocket 实时推送互补。
type StreamRecord struct {
	Seq    int64     `json:"seq"`
	Kind   string    `json:"kind"` // msg/tool/log
	Stage  string    `json:"stage,omitempty"`
	Role   string    `json:"role,omitempty"`   // msg 用：assistant
	Text   string    `json:"text,omitempty"`   // msg/log 用
	Tool   string    `json:"tool,omitempty"`   // tool 用
	Args   string    `json:"args,omitempty"`   // tool 用
	Result string    `json:"result,omitempty"` // tool 用
	Ts     time.Time `json:"ts"`
}

const streamKeepPerProject = 2000 // 每项目保留上限，超出滚动淘汰最旧

func streamKey(projectID string, seq int64) []byte {
	return []byte(fmt.Sprintf("%s|%016d", projectID, seq))
}

// AddStream 追加一条执行流记录（seq 全局单调递增）。落盘前去 AI 化清洗（剥离 pictograph emoji）。
func (s *Store) AddStream(projectID string, r *StreamRecord) (int64, error) {
	r.Text = events.SanitizeEmoji(r.Text)
	var seq uint64
	err := s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketStream)
		seq, _ = b.NextSequence()
		r.Seq = int64(seq)
		r.Ts = time.Now()
		if err := b.Put(streamKey(projectID, r.Seq), mustJSON(r)); err != nil {
			return err
		}
		return pruneStream(tx, b, projectID)
	})
	return r.Seq, err
}

// pruneStream 每项目只保留最近 streamKeepPerProject 条（滚动淘汰）。
func pruneStream(tx *bolt.Tx, b *bolt.Bucket, projectID string) error {
	prefix := []byte(projectID + "|")
	c := b.Cursor()
	var n int
	var oldest []byte
	for k, _ := c.Seek(prefix); k != nil && bytes.HasPrefix(k, prefix); k, _ = c.Next() {
		n++
		if n == 1 {
			oldest = append([]byte{}, k...)
		}
	}
	for i := n; i > streamKeepPerProject && oldest != nil; i-- {
		if err := b.Delete(oldest); err != nil {
			return err
		}
		oldest = nextStreamKey(oldest, prefix)
	}
	return nil
}

func nextStreamKey(k, prefix []byte) []byte {
	if k == nil {
		return nil
	}
	n := append([]byte{}, k...)
	for i := len(n) - 1; i >= len(prefix); i-- {
		if n[i] < 0xff {
			n[i]++
			return n
		}
		n[i] = 0
	}
	return nil
}

// ListStream 返回项目执行流（seq 升序）；after>0 时只返回其后增量。
func (s *Store) ListStream(projectID string, after int64) ([]*StreamRecord, int64, error) {
	out := []*StreamRecord{}
	last := after
	prefix := []byte(projectID + "|")
	err := s.db.View(func(tx *bolt.Tx) error {
		c := tx.Bucket(bucketStream).Cursor()
		start := streamKey(projectID, after+1)
		for k, v := c.Seek(start); k != nil && bytes.HasPrefix(k, prefix); k, v = c.Next() {
			var r StreamRecord
			if err := json.Unmarshal(v, &r); err == nil {
				out = append(out, &r)
				if r.Seq > last {
					last = r.Seq
				}
			}
		}
		return nil
	})
	return out, last, err
}

// ---------- v3.3.0 项目黑板（facts）与战利品库（loot） ----------

// UpsertFact 同 project+key 幂等写入：已存在则更新 value/confidence/links/note（保留创建时间）。
func (s *Store) UpsertFact(f *FactRecord) (string, error) {
	if f.Confidence != "confirmed" && f.Confidence != "tentative" && f.Confidence != "deprecated" {
		f.Confidence = "tentative"
	}
	now := time.Now()
	if f.ID == "" {
		f.ID = newID("FC")
	}
	f.UpdatedAt = now
	err := s.db.Update(func(tx *bolt.Tx) error {
		c := tx.Bucket(bucketFacts).Cursor()
		for k, v := c.First(); k != nil; k, v = c.Next() {
			var old FactRecord
			if json.Unmarshal(v, &old) == nil && old.ProjectID == f.ProjectID && old.Key == f.Key {
				f.ID = old.ID
				f.CreatedAt = old.CreatedAt
				if f.CreatedAt.IsZero() {
					f.CreatedAt = now
				}
				return putJSON(tx, bucketFacts, old.ID, f)
			}
		}
		if f.CreatedAt.IsZero() {
			f.CreatedAt = now
		}
		return putJSON(tx, bucketFacts, f.ID, f)
	})
	return f.ID, err
}

// ListFacts 返回项目事实（最近更新优先，limit<=0 全量）。
func (s *Store) ListFacts(projectID string, limit int) ([]*FactRecord, error) {
	out, err := listBy[FactRecord](s, bucketFacts, projectID)
	sort.Slice(out, func(i, j int) bool { return out[i].UpdatedAt.After(out[j].UpdatedAt) })
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out, err
}

// AddLoot 登记战利品（掩码摘要）。
func (s *Store) AddLoot(l *LootRecord) (string, error) {
	l.ID = newID("LT")
	if l.CreatedAt.IsZero() {
		l.CreatedAt = time.Now()
	}
	return l.ID, s.db.Update(func(tx *bolt.Tx) error { return putJSON(tx, bucketLoot, l.ID, l) })
}

// ListLoot 返回项目战利品（最新优先，limit<=0 全量）。
func (s *Store) ListLoot(projectID string, limit int) ([]*LootRecord, error) {
	out, err := listBy[LootRecord](s, bucketLoot, projectID)
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out, err
}

// ---------- v5.5.0 结构化凭据仓库（静态加密；明文不落库，密文按项目隔离） ----------
// 设计约定（docs/repair-plan-capability-20261118.md 方案 A）：
//   - SecretCiphertext 为 AES-256-GCM 密文（nonce||ciphertext，加密封装版本化），由 credentials 包加密后写入；
//   - 存储层不接触明文，也不做掩码——展示层（引擎工具回执/UI）只输出 CredentialMeta 派生的掩码；
//   - Loot 库继续只登记掩码摘要（纪律不变），凭据本体在 credentials 桶，两者可用 SourceLootID 关联。

type CredentialRecord struct {
	ID               string    `json:"id"` // cred- 前缀
	ProjectID        string    `json:"project_id"`
	Target           string    `json:"target"`                   // 归属目标（主机/服务/账号）
	Identity         string    `json:"identity"`                 // 身份名（如 operator / viewer；同 role 多会话用 operator/session-2）
	Role             string    `json:"role,omitempty"`           // 可选角色标注（admin/user/…）
	Kind             string    `json:"kind"`                     // bearer/basic/cookie/header/token
	Username         string    `json:"username,omitempty"`       // 可选（basic 场景）；展示时由引擎层掩码
	SecretCiphertext []byte    `json:"secret_ciphertext"`        // AES-GCM 密文（nonce||ciphertext）
	SecretVersion    int       `json:"secret_version"`           // 加密封装版本（v1）
	SourceLootID     string    `json:"source_loot_id,omitempty"` // 可选关联 Loot 记录（不回填明文）
	Status           string    `json:"status"`                   // active/revoked
	CreatedAt        time.Time `json:"created_at"`
	UpdatedAt        time.Time `json:"updated_at"`
	// v5.6.0 凭据来源谱系（S2 伪造凭证轨：真实→还原→伪造→矩阵的引擎级可追溯）：
	Origin   string `json:"origin,omitempty"`    // real（客户提供）/ forged（伪造构造）/ derived（由真实凭据推导还原）
	ParentID string `json:"parent_id,omitempty"` // 伪造/派生的父凭据 cred-<id>
	Method   string `json:"method,omitempty"`    // 伪造/派生方法（如 jwt-none、alg-confusion、cookie-forge、token-relay）
}

// AddCredential 写入一条凭据（ID/时间戳为空时补齐）；密文由调用方加密。
func (s *Store) AddCredential(c *CredentialRecord) (string, error) {
	if c.ID == "" {
		c.ID = newID("cred")
	}
	if c.Status == "" {
		c.Status = "active"
	}
	c.CreatedAt = time.Now()
	c.UpdatedAt = c.CreatedAt
	return c.ID, s.db.Update(func(tx *bolt.Tx) error { return putJSON(tx, bucketCredentials, c.ID, c) })
}

// SaveCredential 覆盖写（撤销/更新用，保留原 ID）。
func (s *Store) SaveCredential(c *CredentialRecord) error {
	c.UpdatedAt = time.Now()
	return s.db.Update(func(tx *bolt.Tx) error { return putJSON(tx, bucketCredentials, c.ID, c) })
}

// GetCredential 按 id 读取（含密文；解密由 credentials 服务完成）。
func (s *Store) GetCredential(projectID, id string) (*CredentialRecord, error) {
	var c CredentialRecord
	err := s.db.View(func(tx *bolt.Tx) error { return getJSON(tx, bucketCredentials, id, &c) })
	if err != nil {
		return nil, err
	}
	if c.ProjectID != projectID {
		return nil, fmt.Errorf("凭据 %s 不属于项目 %s", id, projectID)
	}
	return &c, nil
}

// ListCredentials 项目全部凭据（含密文，仅服务层内部使用；展示走掩码投影）。
func (s *Store) ListCredentials(projectID string) ([]*CredentialRecord, error) {
	return listBy[CredentialRecord](s, bucketCredentials, projectID)
}

// ---------- v5.5.0 工具回执归档（压缩可恢复） ----------
// compactMsgs 存根化旧工具回执前，原文先归档本桶；search_memory 支持 receipt:<id> 取回原文。
// 键为回执 ID（追加式，不覆盖），压缩多轮不互相覆盖；项目删除时一并清理。

type ReceiptRecord struct {
	ID        string    `json:"id"` // rpt- 前缀
	ProjectID string    `json:"project_id"`
	Stage     string    `json:"stage,omitempty"`
	Content   string    `json:"content"`
	CreatedAt time.Time `json:"created_at"`
}

// SaveReceipt 归档一条工具回执原文，返回 receipt id。
func (s *Store) SaveReceipt(projectID, stage, content string) (string, error) {
	r := &ReceiptRecord{ID: newID("rpt"), ProjectID: projectID, Stage: stage, Content: content, CreatedAt: time.Now()}
	return r.ID, s.db.Update(func(tx *bolt.Tx) error { return putJSON(tx, bucketReceipts, r.ID, r) })
}

// GetReceipt 按 id 取回原文（跨项目读取在服务层由调用方保证 project 归属校验）。
func (s *Store) GetReceipt(id string) (*ReceiptRecord, error) {
	var r ReceiptRecord
	err := s.db.View(func(tx *bolt.Tx) error { return getJSON(tx, bucketReceipts, id, &r) })
	if err != nil {
		return nil, err
	}
	return &r, nil
}

// ---------- v3.4.0 组织级教训库（lessons） ----------

// AddLesson 登记脱敏教训（合规校验由引擎层完成，存储层只落库）。
func (s *Store) AddLesson(l *LessonRecord) (string, error) {
	l.ID = newID("LS")
	if l.CreatedAt.IsZero() {
		l.CreatedAt = time.Now()
	}
	return l.ID, s.db.Update(func(tx *bolt.Tx) error { return putJSON(tx, bucketLessons, l.ID, l) })
}

// ---------- v4.6 A2 验证队列（VerificationTask 一等对象）----------
// 立项依据（审计）：「脚本就绪未执行」线索散落在 coverage notes/交付物文字里，收口时不可调度、
// 不可统计——1AC8 七条线/14A1 五条线全部静默蒸发。VT 使待验证项可登记、可流转、可在 S7 强制清点。

type VerificationTask struct {
	ID              string    `json:"id"`
	ProjectID       string    `json:"project_id"`
	Stage           string    `json:"stage"`
	Title           string    `json:"title"`                      // 验证目标（如"wcId SQLi 布尔确认"）
	ReadyAssets     string    `json:"ready_assets,omitempty"`     // 就绪资产（脚本/PoC/参数字典路径，分号分隔）
	StartConditions string    `json:"start_conditions,omitempty"` // 启动条件（如"浏览器通道恢复"）
	CostNote        string    `json:"cost_note,omitempty"`        // 预估成本（轮次/时间）
	Priority        int       `json:"priority,omitempty"`         // 1=最高（impact-rank 对齐）
	Status          string    `json:"status"`                     // pending/ready/executed/closed-roe/deferred
	ResultRef       string    `json:"result_ref,omitempty"`       // 执行结果/证据/移交位置
	Note            string    `json:"note,omitempty"`             // 处置理由（closed-roe/deferred 必填）
	CreatedAt       time.Time `json:"created_at"`
	UpdatedAt       time.Time `json:"updated_at"`
}

func (s *Store) AddVT(t *VerificationTask) (string, error) {
	t.ID = newID("VT")
	t.CreatedAt = time.Now()
	t.UpdatedAt = t.CreatedAt
	if t.Status == "" {
		t.Status = "pending"
	}
	return t.ID, s.db.Update(func(tx *bolt.Tx) error { return putJSON(tx, bucketVTs, t.ID, t) })
}

func (s *Store) UpdateVT(t *VerificationTask) error {
	t.UpdatedAt = time.Now()
	return s.db.Update(func(tx *bolt.Tx) error { return putJSON(tx, bucketVTs, t.ID, t) })
}

func (s *Store) ListVTs(projectID string) ([]*VerificationTask, error) {
	return listBy[VerificationTask](s, bucketVTs, projectID)
}

// ListLessons 最近教训（limit<=0 全量）。
func (s *Store) ListLessons(limit int) ([]*LessonRecord, error) {
	out := []*LessonRecord{}
	err := s.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketLessons).ForEach(func(_, v []byte) error {
			var rec LessonRecord
			if json.Unmarshal(v, &rec) == nil {
				out = append(out, &rec)
			}
			return nil
		})
	})
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out, err
}
