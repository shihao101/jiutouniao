package engine

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"

	"jiutouniao/internal/events"
	"jiutouniao/internal/store"
)

// Approver 审批矩阵执行器：L0 自动放行（仅留证据）；L1/L2 生成待批工单后
// 按审批策略走「人工批准」或「自动批准」两条路径——两者均落库留痕
// （approvals 桶记录 mode/decided_by/decided_at，证据链同时记录 approved_by）。
// 一键熔断时取消该项目全部待批工单。
type Approver struct {
	store *store.Store
	bus   *events.Bus

	defPolicy   string        // 全局默认审批策略：engine（v7.1.0 默认）/manual/l1/all（项目可覆盖）
	waitTimeout time.Duration // v3.4.0：人工审批等待上限（0=不限；实证空等 115 分钟无意义）

	// v7.1.0 engine 档 L2 裁决配额（方案 §3.5：滑动窗口 + 项目总数，防引擎自动批准失控）
	engMu         sync.Mutex
	engL2Per10Min int
	engL2Total    int
	engL2Win      map[string][]time.Time // projectID -> 窗口内 L2 裁决时间戳
	engL2TotalN   map[string]int         // projectID -> L2 裁决总数

	mu      sync.Mutex
	waiters map[string]chan string   // approvalID -> 决策通道
	killCh  map[string]chan struct{} // projectID -> 熔断广播
}

func NewApprover(st *store.Store, bus *events.Bus, defPolicy string) *Approver {
	// v7.1.0：engine 加入合法策略集并作为缺省兜底；显式传入的 manual/l1/all 原样保留
	//（既有测试与已部署项目的行为契约不变——旧默认 manual 的归一化语义由 config 层负责）。
	if defPolicy != "engine" && defPolicy != "manual" && defPolicy != "l1" && defPolicy != "all" {
		defPolicy = "engine" // v7.1.0（用户决策）：默认 engine——L1 自动/L2 存在性证明语义裁决，拒绝即保守路径不进人工屏障
	}
	return &Approver{
		store:       st,
		bus:         bus,
		defPolicy:   defPolicy,
		waiters:     map[string]chan string{},
		killCh:      map[string]chan struct{}{},
		engL2Win:    map[string][]time.Time{},
		engL2TotalN: map[string]int{},
	}
}

// SetEngineQuota 设置 engine 档 L2 裁决配额（接线 config.autonomy.engine_l2_*；默认 20/10min、200/项目）。
func (a *Approver) SetEngineQuota(per10Min, total int) {
	a.engMu.Lock()
	defer a.engMu.Unlock()
	if per10Min > 0 {
		a.engL2Per10Min = per10Min
	}
	if total > 0 {
		a.engL2Total = total
	}
}

// SetWaitTimeout 设置人工审批等待上限（秒；≤0=不限）。v3.4.0 接线 engine.barrier_timeout_sec。
func (a *Approver) SetWaitTimeout(sec int) {
	if sec > 0 {
		a.waitTimeout = time.Duration(sec) * time.Second
	}
}

// policyFor 取项目审批策略：项目字段 > 全局默认。
func (a *Approver) policyFor(projectID string) string {
	if p, err := a.store.GetProject(projectID); err == nil {
		switch strings.TrimSpace(p.AutoApprove) {
		case "engine", "l1", "all":
			return p.AutoApprove
		case "manual":
			return "manual"
		}
	}
	return a.defPolicy
}

// autoOK 该风险等级在当前策略下是否自动批准：l1 策略仅自动放行 L1；all 放行 L1/L2。
func autoOK(policy, risk string) bool {
	switch policy {
	case "all":
		return true
	case "l1":
		return risk == "L1"
	}
	return false
}

// preApprovedFor 取项目预批准档（v6.0.0）：读项目字段并归一化（store 层已归一，此处防御性再校验——
// 运行中旧快照/异常输入一律回 none，fail-closed）。
func (a *Approver) preApprovedFor(projectID string) string {
	if p, err := a.store.GetProject(projectID); err == nil {
		if v := store.NormalizePreApproved(p.PreApproved); v != "" {
			return v
		}
	}
	return "none"
}

// preApprovedCategoryMatch 类别档匹配：工单动作文本命中类别关键词即视为该类动作。
// 仅类别档（逗号列表）使用；"all" 在调用处短路，天然覆盖后续新增类别，无需登记关键词。
func preApprovedCategoryMatch(pa, action string) bool {
	lc := strings.ToLower(action)
	kw := map[string][]string{
		"privesc":     {"提权", "权限提升", "privesc", "suid", "sudo", "逃逸"},
		"lateral":     {"横向", "内网", "lateral", "pivot", "凭据复用", "pass-the"},
		"persistence": {"持久化", "persistence", "驻留", "权限维持"},
	}
	for _, c := range strings.Split(pa, ",") {
		for _, k := range kw[strings.TrimSpace(c)] {
			if strings.Contains(lc, strings.ToLower(k)) {
				return true
			}
		}
	}
	return false
}

// Request 提交审批并按策略决策。返回 "approved"（人工批准）/"auto-approved"（自动批准）/"rejected" / error。
// L0 只读操作即时自动放行并留痕（工单 mode=auto）；L1/L2 按审批策略走人工或自动路径。
// 全部操作（L0/L1/L2）均在 approvals 桶留痕，人工路径阻塞等待 Web 决策。
func (a *Approver) Request(ctx context.Context, projectID, stage, action, risk string) (string, error) {
	ap := &store.Approval{
		ProjectID: projectID,
		Stage:     stage,
		Action:    action,
		Risk:      risk,
		Status:    "pending",
		Mode:      "manual",
	}
	id, err := a.store.AddApproval(ap)
	if err != nil {
		return "", err
	}

	// L0 只读侦察：无论策略如何都即时自动放行（不入人工队列），工单留痕。
	if risk == "L0" {
		now := time.Now()
		ap.Mode = "auto"
		ap.Status = "approved"
		ap.DecidedAt = &now
		ap.DecidedBy = "auto (L0只读)"
		if err := a.store.SaveApproval(ap); err != nil {
			return "", err
		}
		a.bus.Publish(projectID, "approval", ap)
		return "auto-approved", nil
	}

	// v6.0.0（用户决策③）：预批准路径——none（默认）/all（全通过：含提权/横向及后续新增类别）/类别列表。
	// 语义边界：预批只自动签「人工核签」环节；governanceGates（执行档/ROE 写门/范围门）在本函数
	// 被调用之前已确定性执行——被门拦下的动作到不了审批，预批一个都绕不过。
	if pa := a.preApprovedFor(projectID); pa != "none" {
		if pa == "all" || preApprovedCategoryMatch(pa, action) {
			now := time.Now()
			ap.Mode = "auto"
			ap.Status = "approved"
			ap.DecidedAt = &now
			ap.DecidedBy = "pre-approved(" + pa + ")"
			if err := a.store.SaveApproval(ap); err != nil {
				return "", err
			}
			a.bus.Publish(projectID, "approval", ap)
			a.bus.Publish(projectID, "log", map[string]string{
				"level": "info", "stage": stage,
				"text": fmt.Sprintf("⚙ 预批准自动通过 [%s]（pre_approved=%s）：%s", risk, pa, firstLineText(action)),
			})
			return "auto-approved", nil
		}
	}

	// 自动批准路径：命中策略即时放行，工单落痕（mode=auto）后直接返回。
	if policy := a.policyFor(projectID); autoOK(policy, risk) {
		now := time.Now()
		ap.Mode = "auto"
		ap.Status = "approved"
		ap.DecidedAt = &now
		ap.DecidedBy = "auto-policy"
		if err := a.store.SaveApproval(ap); err != nil {
			return "", err
		}
		a.bus.Publish(projectID, "approval", ap)
		a.bus.Publish(projectID, "log", map[string]string{
			"level": "info", "stage": stage,
			"text": fmt.Sprintf("⚙ 已自动批准 [%s]（策略=%s）：%s", risk, policy, firstLineText(action)),
		})
		return "auto-approved", nil
	}

	// v7.1.0 engine 裁决档（用户决策：全项目默认 engine——零人工裁决点）：
	// L1 直接自动批准（执行档/治理九门已在本函数之前确定性拦截，能到这里的最小影响写可放）；
	// L2 按「存在性证明语义白名单 + 配额」确定性裁决——拒绝即落 rejected 留痕并返回错误原因码
	// （消费方把原因带回给模型走保守路径），不进人工屏障。
	if policy := a.policyFor(projectID); policy == "engine" {
		verdict, why := a.engineAdjudicate(projectID, action, risk)
		now := time.Now()
		if verdict == "approved" {
			ap.Mode = "auto"
			ap.Status = "approved"
			ap.DecidedAt = &now
			ap.DecidedBy = "engine-adjudicator(" + why + ")"
			if err := a.store.SaveApproval(ap); err != nil {
				return "", err
			}
			a.bus.Publish(projectID, "approval", ap)
			a.bus.Publish(projectID, "log", map[string]string{
				"level": "info", "stage": stage,
				"text": fmt.Sprintf("🤖 引擎裁决批准 [%s]（engine 档，%s）：%s", risk, why, firstLineText(action)),
			})
			return "auto-approved", nil
		}
		ap.Mode = "auto"
		ap.Status = "rejected"
		ap.DecidedAt = &now
		ap.DecidedBy = "engine-adjudicator(" + why + ")"
		if err := a.store.SaveApproval(ap); err != nil {
			return "", err
		}
		a.bus.Publish(projectID, "approval", ap)
		a.bus.Publish(projectID, "log", map[string]string{
			"level": "warn", "stage": stage,
			"text": fmt.Sprintf("⛔ 引擎裁决拒绝 [%s]（engine 档，%s）：%s", risk, why, firstLineText(action)),
		})
		return "", fmt.Errorf("引擎裁决拒绝 [%s]（engine 档，原因码 %s）——请改为存在性证明/最小影响形态（无害回显/随机标记/受控 OOB/计数哈希），或拆分为只读步骤后重试；详见自主决策账本", risk, why)
	}

	// 人工批准路径：通知并阻塞等待决策。
	a.bus.Publish(projectID, "approval", ap)
	a.bus.Publish(projectID, "log", map[string]string{
		"level": "warn", "stage": stage,
		"text": fmt.Sprintf("待人工审批 [%s] %s：%s", risk, "高危操作", action),
	})

	ch := make(chan string, 1)
	kill, _ := a.register(projectID, id, ch)
	defer a.unregister(id, projectID)

	waitCtx := ctx
	var waitCancel context.CancelFunc
	if a.waitTimeout > 0 {
		waitCtx, waitCancel = context.WithTimeout(ctx, a.waitTimeout)
		defer waitCancel()
	}
	select {
	case decision := <-ch:
		return decision, nil
	case <-kill:
		a.cancelRecord(id)
		return "", fmt.Errorf("项目已熔断，审批取消")
	case <-waitCtx.Done():
		// 区分熔断（父 ctx 取消）与屏障超时：超时 → 工单标 expired，模型走保守路径而非永久挂起
		if ctx.Err() != nil {
			a.cancelRecord(id)
			return "", ctx.Err()
		}
		a.cancelRecord(id)
		if ap, gerr := a.store.GetApproval(id); gerr == nil {
			ap.Status = "expired"
			_ = a.store.SaveApproval(ap)
			a.bus.Publish(projectID, "approval", ap)
		}
		return "timeout", nil
	}
}

// engineL2QuotaOK engine 档 L2 配额检查（10 分钟滑窗 + 项目总数；超限 fail-closed 拒绝）。
func (a *Approver) engineL2QuotaOK(projectID string) (bool, string) {
	a.engMu.Lock()
	defer a.engMu.Unlock()
	if a.engL2Per10Min <= 0 && a.engL2Total <= 0 {
		return true, ""
	}
	now := time.Now()
	win := a.engL2Win[projectID][:0]
	for _, ts := range a.engL2Win[projectID] {
		if now.Sub(ts) < 10*time.Minute {
			win = append(win, ts)
		}
	}
	a.engL2Win[projectID] = win
	if a.engL2Per10Min > 0 && len(win) >= a.engL2Per10Min {
		return false, "ENGINE_L2_WINDOW_QUOTA"
	}
	if a.engL2Total > 0 && a.engL2TotalN[projectID] >= a.engL2Total {
		return false, "ENGINE_L2_TOTAL_QUOTA"
	}
	a.engL2Win[projectID] = append(win, now)
	a.engL2TotalN[projectID]++
	return true, ""
}

// engine 硬拒语义（全档位通用——数据破坏/驻留类即使 isolated_lab 也不放行，对齐清理铁律）。
var engineHardDeny = []string{
	`(?i)delete\s+from`, `(?i)update\s+["']?\w+["']?\s+set`, `(?i)insert\s+into`,
	`(?i)drop\s+(table|database)`, `(?i)truncate\s+(table\s+)?`,
	`(?i)rm\s+(-[a-za-z]*f|--force)`, `(?i)mkfs`, `shutdown|reboot|halt\b`,
	`(?i)webshell|内存马|冰蝎|哥斯拉|蚁剑`,
	`(?i)useradd|net\s+user\s+\S+\s+/add|新增账号`,
	`(?i)schtasks\s+/create|crontab\s+-l?\s*[<]*-|systemctl\s+enable`,
	`(?i)ssh-copy-id|authorized_keys`,
}

// engine 存在性证明语义白名单（production_safe 档 L2 唯一放行口径——方案 §3.5；
// 逐关键词 Contains 匹配，命中任一即视为无害存在性证明形态）。
var engineExistenceProof = []string{
	"存在性", "存在证明", "无害", "随机标记", "随机数标记", "canary", "CANARY",
	"OOB", "回连", "回显", "计数", "哈希", "摘要", "差分", "基线", "探针", "探测", "枚举", "只读",
}

// engineAdjudicate engine 档核心裁决（方案 §3.5）：
// L1 → 放行（治理九门/profile 前置已拦截，能到审批的最小影响写可自动执行）；
// L2 → isolated_lab 档：硬拒语义之外放行（完整 PoC 链 + 快照回滚兜底）；
//
//	production_safe 档：仅放行「存在性证明语义」命中的动作，其余 fail-closed 拒绝
//	（原因码 L2_NOT_EXISTENCE_PROOF——模型应改为无害回显/随机标记/受控 OOB 形态）。
func (a *Approver) engineAdjudicate(projectID, action, risk string) (string, string) {
	// v7.1.0 核对修复（逐项核对审计①）：L1 自动批准同样过硬拒语义扫描——分级正则
	// （Forbidden/HighRisk）之外的漏网写语义在此兜底，清理铁律不变式对 L1/L2 一体生效。
	for _, re := range engineHardDeny {
		if matchSimple(re, action) {
			return "denied", "ENGINE_HARD_DENY(" + re + ")"
		}
	}
	if risk != "L2" {
		return "approved", "ENGINE_L1_WRITE"
	}
	if ok, why := a.engineL2QuotaOK(projectID); !ok {
		return "denied", why
	}
	for _, re := range engineHardDeny {
		if matchSimple(re, action) {
			return "denied", "ENGINE_HARD_DENY(" + re + ")"
		}
	}
	profile := "production_safe"
	if p, err := a.store.GetProject(projectID); err == nil && p.ExecutionProfile == "isolated_lab" {
		profile = "isolated_lab"
	}
	if profile == "isolated_lab" {
		return "approved", "ENGINE_L2_ISOLATED_LAB"
	}
	for _, kw := range engineExistenceProof {
		if strings.Contains(action, kw) {
			return "approved", "ENGINE_L2_EXISTENCE_PROOF"
		}
	}
	return "denied", "L2_NOT_EXISTENCE_PROOF"
}

// matchSimple 极简正则/子串双模匹配（| 交替与 (?i) 前缀由 regexp 处理，纯字面串退化为 Contains）。
func matchSimple(pattern, s string) bool {
	if re, err := regexp.Compile(pattern); err == nil {
		return re.MatchString(s)
	}
	return strings.Contains(s, pattern)
}

// Decide 人工决策（留痕：mode=manual、decided_by、decided_at）。
func (a *Approver) Decide(id string, approve bool, by string) error {
	ap, err := a.store.GetApproval(id)
	if err != nil {
		return err
	}
	if ap.Status != "pending" {
		return fmt.Errorf("工单已处理")
	}
	now := time.Now()
	ap.Mode = "manual"
	if approve {
		ap.Status = "approved"
	} else {
		ap.Status = "rejected"
	}
	ap.DecidedAt = &now
	ap.DecidedBy = by
	if err := a.store.SaveApproval(ap); err != nil {
		return err
	}
	a.mu.Lock()
	if ch, ok := a.waiters[id]; ok {
		if approve {
			ch <- "approved"
		} else {
			ch <- "rejected"
		}
	}
	a.mu.Unlock()
	a.bus.Publish(ap.ProjectID, "approval", ap)
	a.bus.Publish(ap.ProjectID, "log", map[string]string{
		"level": "info", "stage": ap.Stage,
		"text": fmt.Sprintf("✔ 人工%s [%s] 工单 %s（决策人 %s）", map[bool]string{true: "批准", false: "拒绝"}[approve], ap.Risk, id, by),
	})
	return nil
}

// CancelProject 熔断：广播取消并关闭该项目全部待批工单。
func (a *Approver) CancelProject(projectID string) {
	a.mu.Lock()
	ch, ok := a.killCh[projectID]
	delete(a.killCh, projectID) // 关闭后移除，后续新审批重建新通道
	a.mu.Unlock()
	if ok {
		close(ch)
	}
}

// ApprovePending 按「策略变更联动」放行项目全部待批工单：
// 策略切到 all（全自动批准）时，此前按旧策略挂起阻塞的工单若不随之放行，
// 执行循环会停在审批屏障上无限等待（实测 S4 卡死 30 分钟）。
func (a *Approver) ApprovePending(projectID, by string) int {
	pending, err := a.store.ListApprovals(projectID)
	if err != nil {
		return 0
	}
	n := 0
	now := time.Now()
	for _, ap := range pending {
		if ap.Status != "pending" {
			continue
		}
		ap.Mode = "auto"
		ap.Status = "approved"
		ap.DecidedAt = &now
		ap.DecidedBy = by
		if err := a.store.SaveApproval(ap); err != nil {
			continue
		}
		a.mu.Lock()
		if ch, ok := a.waiters[ap.ID]; ok {
			ch <- "approved"
		}
		a.mu.Unlock()
		a.bus.Publish(projectID, "approval", ap)
		a.bus.Publish(projectID, "log", map[string]string{
			"level": "info", "stage": ap.Stage,
			"text": fmt.Sprintf("⚙ 策略变更联动放行 [%s] 工单 %s（%s）", ap.Risk, ap.ID, by),
		})
		n++
	}
	return n
}

func (a *Approver) register(projectID, id string, ch chan string) (chan struct{}, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if _, ok := a.killCh[projectID]; !ok {
		a.killCh[projectID] = make(chan struct{})
	}
	a.waiters[id] = ch
	return a.killCh[projectID], nil
}

func (a *Approver) unregister(id, projectID string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	delete(a.waiters, id)
}

func (a *Approver) cancelRecord(id string) {
	if ap, err := a.store.GetApproval(id); err == nil && ap.Status == "pending" {
		ap.Status = "cancelled"
		_ = a.store.SaveApproval(ap)
		a.bus.Publish(ap.ProjectID, "approval", ap)
	}
}

func firstLineText(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	if len(s) > 160 {
		s = s[:160] + "…"
	}
	return s
}
