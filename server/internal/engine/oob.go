// v7.0.0 OOB 回连通道管理器（三模式 + auto 回退链 + 项目级守护生命周期）。
//
// 背景（方案 oob-channel-optimization.md）：盲态类（盲 SSRF/XXE/盲注/反序列化）的 D3 语义验证
// 依赖回连通道；此前三通道只是技能层提示词约定，选型靠人工救场（某历史任务 实证：盲 SSRF/XXE
// 悬置两轮 + 指挥室质询 4 分钟），本机通道曾以 run_async 起进程被超时杀掉纯烧 244 分钟。
//
// 三模式（与方案 §3 一致）：
//   A1 local-interactsh  自托管 interactsh-server（自有域+公网入站；回连域名可伪装业务域，交互不出第三方）
//   C  custom-*          用户自设：interactsh（server+secret）/ dnslog（dnslog.cn 兼容 API）/ webhook（通用收集器）
//   A2 local-listener    本地 HTTP/DNS 监听器（内网/靶场，目标可直连本机；零外联）
//   B  public-interactsh 公共 interactsh（oast.pro 等；免配置兜底，受 ROE oob_callback 约束，只允许无害探针）
//
// auto 回退链（§4.1）：A1 → C → A2 → B → 不可用（盲态类禁测，coverage 强制 needs_follow_up，禁止 ruled_out）。
// 生命周期：项目级懒启动（首次 oob_check），finishRun 回收——通道永不进 run_async 任务池。
// 合规：所有模式只收回连记录（存在性证明口径）；ROE oob_callback=deny 时外部通道全部跳过（仅 A2 本地可用）。
package engine

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"jiutouniao/internal/config"
	"jiutouniao/internal/store"
	"jiutouniao/internal/tools"
)

const (
	oobRingCap       = 500                    // 每项目回连记录环形缓冲上限（与落盘文件滚动上限一致）
	oobStartTimeout  = 15 * time.Second       // 通道启动健康等待上限
	oobTestProjectID = "__settings_test__"    // 设置页连通性测试用临时项目 id
	oobPersistFile   = "evidence/oob/interactions.jsonl"
	oobChannelFile   = "evidence/oob/channel.txt"
	oobRetryUnavail  = 60 * time.Second       // 通道不可用后的重建间隔（瞬态网络失败不永久阻塞）
)

// oobInteraction 单条回连记录（case 归属由载荷里的 case-id 子串匹配）。
type oobInteraction struct {
	Ts       string `json:"ts"`
	Protocol string `json:"protocol"`
	FullID   string `json:"full_id"`
	Remote   string `json:"remote"`
	Summary  string `json:"summary,omitempty"`
}

// oobChannel 一个项目已解析的回连通道。
type oobChannel struct {
	ProjectID  string
	Mode       string // A1 自托管 | C 用户 interactsh/dnslog/webhook | A2 本地监听器 | B 公共 interactsh
	Kind       string // interactsh|listener|dnslog|webhook
	BaseDomain string // 回连载荷基域；A2 为 host:port 形态
	Status     string // healthy|degraded|unavailable
	Reason     string
	Public     bool // 第三方公共通道（纪律：无害探针白名单 + 命中即落证）
	StartedAt  time.Time
	SelfCheck  string // ok|fail|skipped

	mu     sync.Mutex
	ring   []oobInteraction
	stop   func()
	fetch  func() []oobInteraction // API 型通道（dnslog/webhook）的远端拉取闭包
	builtAt time.Time
}

func (c *oobChannel) addInteraction(in oobInteraction) {
	c.mu.Lock()
	c.ring = append(c.ring, in)
	if len(c.ring) > oobRingCap {
		c.ring = c.ring[len(c.ring)-oobRingCap:]
	}
	c.mu.Unlock()
}

// OOBCoord 通道协调器（挂在 Orchestrator 上；每项目一条通道）。
type OOBCoord struct {
	mu      sync.Mutex
	ch      map[string]*oobChannel
	once    map[string]*sync.Once
	cfg     config.OOBConfig  // config.json 基线
	ov      *config.OOBConfig // 设置页覆盖（nil=未覆盖；保存后热生效）
	exec      *tools.Executor
	logFn     func(p *store.Project, stageID, text string)
	roeDeny   func() bool // ROE oob_callback=deny 时 true（外部回连全禁，仅 A2 本地监听可用）
	persistMu sync.Mutex  // 加固③：回连落盘读改写互斥（监听器并发/轮询器/oob_poll）
}

func NewOOBCoord(cfg config.OOBConfig, exec *tools.Executor, logFn func(p *store.Project, stageID, text string), roeDeny func() bool) *OOBCoord {
	return &OOBCoord{ch: map[string]*oobChannel{}, once: map[string]*sync.Once{}, cfg: cfg, exec: exec, logFn: logFn, roeDeny: roeDeny}
}

// SetOverride 设置页保存后热生效（nil=清除覆盖回 config.json）。
// v7.0.0 核对加固⑧：热生效必须作用于已建通道——原先缓存通道沿用旧配置直到项目结束，
// "保存即热生效"只对未启动项目成立；现保存即回收全部在跑通道，下次 oob_check 按新配置重建
//（运营者显式保存即明确意图；盲态门随后按新通道状态裁决，如实不滞后）。
func (c *OOBCoord) SetOverride(ov *config.OOBConfig) {
	c.mu.Lock()
	chans := make([]*oobChannel, 0, len(c.ch))
	for id, ch := range c.ch {
		chans = append(chans, ch)
		delete(c.ch, id)
		delete(c.once, id)
	}
	c.ov = ov
	c.mu.Unlock()
	for _, ch := range chans {
		if ch != nil && ch.stop != nil {
			ch.stop()
		}
	}
}

func (c *OOBCoord) effective() config.OOBConfig {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.ov != nil {
		return *c.ov
	}
	return c.cfg
}

// IsBlindVulnClass 盲态类判别：D3 语义验证必须依赖回连通道的漏洞类。
func IsBlindVulnClass(vulnClass string) bool {
	low := strings.ToLower(vulnClass)
	for _, kw := range []string{"ssrf", "xxe", "盲注", "blind", "反序列化", "deserial", "jndi", "log4j", "oob", "cmdi"} {
		if strings.Contains(low, kw) {
			return true
		}
	}
	return false
}

// normalizeOOBDepth 深度阶梯归一化：接受 D2/d2/2 → D2；非法值返回空（按未声明处理，门自然拦截）。
func normalizeOOBDepth(s string) string {
	t := strings.ToUpper(strings.TrimSpace(s))
	if t == "" {
		return ""
	}
	if len(t) == 1 {
		t = "D" + t
	}
	if len(t) == 2 && t[0] == 'D' && t[1] >= '0' && t[1] <= '4' {
		return t
	}
	return ""
}

func depthNum(d string) int {
	if len(d) == 2 && d[0] == 'D' {
		return int(d[1] - '0')
	}
	return -1
}

// Ensure 懒启动项目通道（幂等；auto 模式走回退链）。返回通道或 nil（mode=off）。
func (c *OOBCoord) Ensure(p *store.Project, stageID string) *oobChannel {
	c.mu.Lock()
	if ch, ok := c.ch[p.ID]; ok && ch != nil {
		// 不可用通道按间隔自动重建（瞬态网络失败不永久阻塞）
		if ch.Status != "unavailable" || time.Since(ch.builtAt) < oobRetryUnavail {
			c.mu.Unlock()
			return ch
		}
		delete(c.ch, p.ID)
		delete(c.once, p.ID)
	}
	o, ok := c.once[p.ID]
	if !ok {
		o = &sync.Once{}
		c.once[p.ID] = o
	}
	c.mu.Unlock()
	o.Do(func() { c.buildAndStore(p, stageID) })
	c.mu.Lock()
	ch := c.ch[p.ID]
	c.mu.Unlock()
	return ch
}

func (c *OOBCoord) buildAndStore(p *store.Project, stageID string) {
	ch := c.build(p)
	c.mu.Lock()
	c.ch[p.ID] = ch
	c.mu.Unlock()
	if p.ID == oobTestProjectID { // 加固④：测试通道状态只经 SelfTest 返回值呈现，不写执行流
		return
	}
	if ch == nil {
		if c.logFn != nil {
			c.logFn(p, stageID, "🛰 OOB 通道已关闭（mode=off）：盲态类禁测，coverage 落 needs_follow_up")
		}
		return
	}
	c.persistChannelFile(p, ch)
	if c.logFn != nil && ch.Status != "unavailable" {
		c.logFn(p, stageID, fmt.Sprintf("🛰 OOB 通道就绪：%s | 类型=%s | 基域=%s | 状态=%s%s", ch.Mode, ch.Kind, ch.BaseDomain, ch.Status, oobReasonSuffix(ch.Reason)))
	} else if c.logFn != nil {
		c.logFn(p, stageID, "🛰 OOB 通道不可用："+ch.Reason+"（盲态类禁测，coverage 落 needs_follow_up）")
	}
}

// Stop 项目结束回收通道（finishRun 钩子；通道不进 run_async 任务池的结构性保证）。
func (c *OOBCoord) Stop(projectID string) {
	c.mu.Lock()
	ch := c.ch[projectID]
	delete(c.ch, projectID)
	delete(c.once, projectID)
	c.mu.Unlock()
	if ch != nil && ch.stop != nil {
		ch.stop()
	}
}

// Healthy 通道健康（盲态前置门判据）。
func (c *OOBCoord) Healthy(p *store.Project) bool {
	ch := c.Ensure(p, "")
	return ch != nil && ch.Status == "healthy"
}

// BlindGateReady 盲态前置门：require_channel_for_blind 开启时，盲态类需要健康通道。
func (c *OOBCoord) BlindGateReady(p *store.Project, vulnClass string) (bool, string) {
	if !IsBlindVulnClass(vulnClass) {
		return true, ""
	}
	eff := c.effective()
	if !config.FlagOrDefault(eff.RequireChannelForBlind, true) {
		return true, ""
	}
	ch := c.Ensure(p, "")
	if ch != nil && ch.Status == "healthy" {
		return true, ""
	}
	reason := "mode=off"
	if ch != nil {
		reason = ch.Reason
	}
	return false, reason
}

// CheckText oob_check 工具输出：模式/域名/状态/约束/用法。
func (c *OOBCoord) CheckText(p *store.Project) string {
	ch := c.Ensure(p, "")
	if ch == nil {
		return "OOB 通道：已关闭（mode=off）。\n盲态类（盲 SSRF/XXE/盲注/反序列化）在通道开启前不得开测：相关覆盖单元落 needs_follow_up（禁止 ruled_out）。\n" + oobConfigHint()
	}
	if ch.Status == "unavailable" {
		return fmt.Sprintf("OOB 通道：不可用（回退链全部失败：%s）。\n盲态类（盲 SSRF/XXE/盲注/反序列化）在通道建立前不得开测：相关覆盖单元落 needs_follow_up（禁止 ruled_out）。\n%s", ch.Reason, oobConfigHint())
	}
	var b strings.Builder
	fmt.Fprintf(&b, "OOB 通道：%s | 类型=%s | 回连基域=%s | 状态=%s | 自检=%s%s\n", ch.Mode, ch.Kind, ch.BaseDomain, ch.Status, ch.SelfCheck, oobReasonSuffix(ch.Reason))
	if ch.Public {
		b.WriteString("约束：公共第三方通道——只投递无害探针载荷（存在性证明口径）；记录留存短，oob_poll 命中后立即落 evidence/oob/ 并引用 EV-。\n")
	} else {
		b.WriteString("约束：非公共通道——回连记录不出第三方；证据落 evidence/oob/。\n")
	}
	b.WriteString("用法：回连载荷指向 " + ch.BaseDomain + "/<case-id>（case-id 命名=漏洞类-目标-序号）；oob_poll(case_id) 收回连记录；载荷示例见技能 oob-interactsh。\n")
	return b.String()
}

// PollText oob_poll 工具输出：按 case-id 子串过滤回连记录。
func (c *OOBCoord) PollText(p *store.Project, caseID string) string {
	ch := c.Ensure(p, "")
	if ch == nil || ch.Status == "unavailable" {
		return "OOB 通道不可用，无回连可收。" + oobConfigHint()
	}
	if ch.fetch != nil { // API 型通道：poll 即拉取一次远端
		for _, in := range ch.fetch() {
			ch.addInteraction(in)
			c.persistInteraction(p, in)
		}
	}
	filter := func() []oobInteraction {
		ch.mu.Lock()
		defer ch.mu.Unlock()
		var recs []oobInteraction
		for i := len(ch.ring) - 1; i >= 0 && len(recs) < 20; i-- {
			if caseID == "" || strings.Contains(ch.ring[i].FullID, caseID) || strings.Contains(ch.ring[i].Summary, caseID) {
				recs = append(recs, ch.ring[i])
			}
		}
		return recs
	}
	recs := filter()
	if len(recs) == 0 {
		return fmt.Sprintf("回连记录 0 条（case=%s；通道 %s 运行中）。盲态未命中≠阴性：保持 needs_follow_up，勿写 ruled_out（无 OOB 命中的真阴性需要 D2 差分+通道健康的双重支撑）。", caseID, ch.Mode)
	}
	var b strings.Builder
	fmt.Fprintf(&b, "回连记录 %d 条（case=%s）：\n", len(recs), caseID)
	for _, r := range recs {
		fmt.Fprintf(&b, "- %s [%s] %s ← %s\n", r.Ts, r.Protocol, r.FullID, r.Remote)
	}
	b.WriteString("下一步：立即把本结论写 evidence/oob/（EV- 编号引用本记录）并 update_coverage 登记（depth=D3）——公共通道记录留存短，落证勿延迟。\n")
	return b.String()
}

// ---- 通道构建（回退链） ----

func (c *OOBCoord) build(p *store.Project) *oobChannel {
	eff := c.effective()
	denyExternal := c.roeDeny != nil && c.roeDeny()
	var chain []string
	switch eff.Mode {
	case "off":
		return nil
	case "local":
		chain = []string{"A1", "A2"}
	case "public":
		chain = []string{"B"}
	case "custom":
		chain = []string{"C"}
	default: // auto
		chain = []string{"A1", "C", "A2", "B"}
	}
	var lastReason string
	for _, step := range chain {
		var ch *oobChannel
		var err error
		switch step {
		case "A1":
			if denyExternal {
				lastReason = "ROE oob_callback=deny：外部回连禁用（含自托管）"
				continue
			}
			if strings.TrimSpace(eff.Local.ServerURL) == "" {
				continue // A1 未配置
			}
			ch, err = c.startInteractsh(p, eff.Local.ServerURL, eff.Local.Secret, "A1 自托管 interactsh", false)
		case "C":
			if denyExternal {
				lastReason = "ROE oob_callback=deny：外部回连禁用"
				continue
			}
			if strings.TrimSpace(eff.Custom.ServerURL) == "" {
				continue // C 未配置
			}
			ch, err = c.startCustom(p, eff.Custom, eff.PollIntervalSec)
		case "A2":
			ch, err = c.startListener(p, eff.Local)
		case "B":
			if denyExternal {
				lastReason = "ROE oob_callback=deny：公共通道禁用"
				continue
			}
			ch, err = c.startPublic(p, eff.Public.Server)
		}
		if err != nil {
			lastReason = step + ": " + err.Error()
			continue
		}
		if ch != nil && ch.Status == "healthy" {
			return ch
		}
		if ch != nil { // degraded 视为该环节失败：回收并继续回退链（waitHealthy 已等待 15s，不再滞留）
			if ch.Reason != "" {
				lastReason = step + ": " + ch.Reason
			} else if lastReason == "" {
				lastReason = step + ": 通道降级未达 healthy"
			}
			ch.stop()
		}
	}
	return &oobChannel{ProjectID: p.ID, Mode: "none", Status: "unavailable", Reason: lastReason, builtAt: time.Now()}
}

// startInteractsh A1/C1/B：interactsh-client 子进程（引擎守护，非 run_async）。
func (c *OOBCoord) startInteractsh(p *store.Project, serverURL, secret, label string, public bool) (*oobChannel, error) {
	bin, err := exec.LookPath("interactsh-client")
	if err != nil {
		return nil, fmt.Errorf("interactsh-client 未安装（go install -v github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest）")
	}
	ch := &oobChannel{ProjectID: p.ID, Mode: label, Kind: "interactsh", Status: "degraded", Public: public, StartedAt: time.Now(), builtAt: time.Now(),
		Reason: "启动中：未在超时内捕获分配域名（client 版本/网络差异），通道保留但结果暂不可信"}
	sfFile := filepath.Join(os.TempDir(), "jtn-oob-"+p.ID+".sf")
	args := []string{"-json", "-sf", sfFile}
	if strings.TrimSpace(serverURL) != "" {
		args = append(args, "-server", strings.TrimSpace(serverURL))
	}
	if strings.TrimSpace(secret) != "" {
		args = append(args, "-token", strings.TrimSpace(secret))
	}
	ctx, cancel := context.WithCancel(context.Background())
	cmd := exec.CommandContext(ctx, bin, args...)
	stdout, _ := cmd.StdoutPipe()
	stderr, _ := cmd.StderrPipe()
	if err := cmd.Start(); err != nil {
		cancel()
		return nil, fmt.Errorf("interactsh-client 启动失败: %v", err)
	}
	ch.stop = func() { cancel(); _ = cmd.Wait() }
	// v7.0.0 核对加固⑤：进程监督——client 异常退出后通道不得继续标 healthy（盲态门会放行假通道）；
	// 退出即降级并如实标注（stop() 中的 Wait 属正常回收路径，此监督 Wait 拿到的重复返回可忽略）
	go func() {
		_ = cmd.Wait()
		ch.mu.Lock()
		if ch.Status == "healthy" {
			ch.Status = "degraded"
			ch.Reason = "interactsh-client 进程已退出（通道失活）——盲态类禁测，可 oob_check 重建"
		}
		ch.mu.Unlock()
	}()
	pipe := make(chan string, 64)
	go feedLines(stdout, pipe)
	go feedLines(stderr, pipe)
	go c.consumeInteractsh(ch, pipe)
	if ch.waitHealthy(oobStartTimeout) {
		ch.Reason = ""
	}
	return ch, nil
}

func feedLines(r io.Reader, out chan<- string) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 512*1024)
	for sc.Scan() {
		out <- sc.Text()
	}
}

var oobDomainRe = regexp.MustCompile(`[a-zA-Z0-9][a-zA-Z0-9-]*(?:\.[a-zA-Z0-9-]+)+`)

var oobURLRe = regexp.MustCompile(`https?://[^\s]+`)

// consumeInteractsh 解析 interactsh-client 输出：JSON 行=回连记录；[DNS]/[HTTP] 等文本行=回连；
// 其余（INFO 行）仅用于捕获分配的基域。
func (c *OOBCoord) consumeInteractsh(ch *oobChannel, pipe <-chan string) {
	for line := range pipe {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var in oobInteraction
		isInteraction := false
		if line[0] == '{' {
			var raw struct {
				Timestamp string `json:"timestamp"`
				Protocol  string `json:"protocol"`
				FullID    string `json:"full-id"`
				Remote    string `json:"remote-address"`
			}
			if json.Unmarshal([]byte(line), &raw) == nil && raw.FullID != "" {
				in = oobInteraction{Ts: raw.Timestamp, Protocol: raw.Protocol, FullID: raw.FullID, Remote: raw.Remote, Summary: line}
				isInteraction = true
			}
		} else {
			for _, pfx := range []string{"[DNS]", "[HTTP]", "[SMTP]", "[LDAP]", "[SMB]"} {
				if strings.HasPrefix(line, pfx) {
					rest := strings.TrimPrefix(line, pfx)
					fields := strings.Fields(rest)
					// v7.0.0 核对加固①：DNS 行首字段是 QTYPE（如 "[DNS] A abc.oast.pro 1.2.3.4"），
					// 原 fields[0] 把 QTYPE 当回连 ID——case-id 过滤失配；改为优选含点号的最长 token，
					// HTTP 行优先提取完整 URL。
					full := ""
					if pfx == "[HTTP]" {
						if m := oobURLRe.FindString(rest); m != "" {
							full = m
						}
					}
					if full == "" {
						for _, tk := range fields {
							if strings.Contains(tk, ".") && len(tk) > len(full) {
								full = tk
							}
						}
					}
					if full == "" && len(fields) > 0 {
						full = fields[0]
					}
					remote := ""
					if len(fields) > 0 {
						remote = fields[len(fields)-1]
					}
					in = oobInteraction{Ts: time.Now().UTC().Format(time.RFC3339), Protocol: strings.Trim(pfx, "[]"), FullID: full, Remote: remote, Summary: line}
					isInteraction = true
					break
				}
			}
		}
		if isInteraction {
			// v7.0.0 核对加固③：通道状态字段此前跨协程无锁读写（本消费者写 / waitHealthy 读，
			// go test -race 实报竞态）——统一经 setDomainHealthy 加锁落定
			if ch.BaseDomain == "" {
				if parts := strings.SplitN(in.FullID, ".", 2); len(parts) == 2 {
					sc := selfCheckDNS(parts[1])
					ch.setDomainHealthy(parts[1], sc)
				}
			}
			if ch.BaseDomain != "" && ch.SelfCheck == "" {
				// v7.0.0（代理出口修正）：基域分配成功即通道就绪——DNS 直查在代理出口环境
				//（JT-ED 实证形态）必然失败，skipped 只作展示不作降级依据；可用性以 oob_poll 实测为准。
				// 先置就绪再做展示性解析（解析带 1.5s 超时，不阻塞状态落定）
				sc := selfCheckDNS(ch.BaseDomain)
				ch.setDomainHealthy(ch.BaseDomain, sc)
			}
			ch.addInteraction(in)
			continue
		}
		// INFO 行：捕获基域（"Using OOB server: oast.pro" / "interactsh-url: xxx.oast.pro" 等）
		if ch.BaseDomain == "" {
			low := strings.ToLower(line)
			if strings.Contains(low, "server") || strings.Contains(low, "url") || strings.Contains(low, "oast") {
				for _, cand := range oobDomainRe.FindAllString(line, -1) {
					if strings.Count(cand, ".") >= 1 && !strings.HasSuffix(strings.ToLower(cand), ".exe") && !strings.HasSuffix(strings.ToLower(cand), ".log") {
						sc := selfCheckDNS(cand)
						ch.setDomainHealthy(cand, sc) // 分配即就绪，解析 skipped 不降级
						break
					}
				}
			}
		}
	}
}

// setDomainHealthy 基域落定 + 置就绪（互斥：消费者协程写 / waitHealthy 与工具路径读）。
func (ch *oobChannel) setDomainHealthy(domain, selfCheck string) {
	ch.mu.Lock()
	ch.BaseDomain = domain
	ch.Status = "healthy"
	ch.Reason = ""
	if selfCheck != "" {
		ch.SelfCheck = selfCheck
	}
	ch.mu.Unlock()
}

// startPublic B：公共 interactsh（候选健康序逐个尝试）。
func (c *OOBCoord) startPublic(p *store.Project, candidates string) (*oobChannel, error) {
	for _, srv := range strings.Split(candidates, ",") {
		srv = strings.TrimSpace(srv)
		if srv == "" {
			continue
		}
		ch, err := c.startInteractsh(p, srv, "", "B 公共 interactsh("+srv+")", true)
		if err == nil && ch != nil && ch.Status == "healthy" {
			return ch, nil
		}
		if ch != nil && ch.stop != nil {
			ch.stop()
		}
	}
	return nil, fmt.Errorf("公共候选全部不可用: %s", candidates)
}

// startCustom C：按 kind 接线 interactsh / dnslog / webhook。
func (c *OOBCoord) startCustom(p *store.Project, cc config.OOBCustomConfig, pollSec int) (*oobChannel, error) {
	switch strings.ToLower(strings.TrimSpace(cc.Kind)) {
	case "interactsh":
		return c.startInteractsh(p, cc.ServerURL, cc.Secret, "C 用户 interactsh", false)
	case "dnslog":
		return c.startDnslog(p, cc, pollSec)
	case "webhook":
		return c.startWebhook(p, cc, pollSec)
	default:
		return nil, fmt.Errorf("custom.kind 仅支持 interactsh|dnslog|webhook，当前 %q", cc.Kind)
	}
}

// startDnslog C2：dnslog.cn 兼容 API（getdomain.php 取域 + getrecords.php 轮询）。
// v7.0.0 核对加固②：getrecords.php 要求与取域同一 PHPSESSID 会话（dnslog 类服务以 cookie 绑定
// 域名与记录）——原实现每次独立请求，轮询恒拿不到记录；改用 CookieJar 会话客户端贯通全程。
func (c *OOBCoord) startDnslog(p *store.Project, cc config.OOBCustomConfig, pollSec int) (*oobChannel, error) {
	base := strings.TrimRight(cc.ServerURL, "/")
	jar, jerr := cookiejar.New(nil)
	if jerr != nil {
		return nil, fmt.Errorf("cookie jar 初始化失败: %v", jerr)
	}
	client := &http.Client{Timeout: 10 * time.Second, Jar: jar}
	domain, err := oobClientGet(client, base+"/getdomain.php", cc.Secret)
	if err != nil || strings.TrimSpace(domain) == "" {
		return nil, fmt.Errorf("dnslog 取域失败: %v", err)
	}
	domain = strings.TrimSpace(domain)
	ch := &oobChannel{ProjectID: p.ID, Mode: "C 用户 dnslog", Kind: "dnslog", BaseDomain: domain, Status: "healthy", SelfCheck: "ok", StartedAt: time.Now(), builtAt: time.Now()}
	ch.fetch = func() []oobInteraction {
		raw, err := oobClientGet(client, base+"/getrecords.php", cc.Secret)
		if err != nil {
			return nil
		}
		var payload struct {
			Record []struct {
				Subdomain string `json:"subdomain"`
				CreatedAt string `json:"created_at"`
				IP        string `json:"ip"`
			} `json:"record"`
		}
		if json.Unmarshal([]byte(raw), &payload) != nil {
			return nil
		}
		var out []oobInteraction
		for _, r := range payload.Record {
			out = append(out, oobInteraction{Ts: r.CreatedAt, Protocol: "dns", FullID: r.Subdomain, Remote: r.IP, Summary: r.Subdomain})
		}
		return out
	}
	ch.stop = c.startPoller(p, ch, pollSec)
	return ch, nil
}

// startWebhook C3：通用收集器（写=server_url?case=…；读=GET server_url 带 Authorization，返回 JSON 数组 [{ts,path,remote,body}]）。
func (c *OOBCoord) startWebhook(p *store.Project, cc config.OOBCustomConfig, pollSec int) (*oobChannel, error) {
	u, err := url.Parse(cc.ServerURL)
	if err != nil || u.Host == "" {
		return nil, fmt.Errorf("webhook server_url 非法: %v", err)
	}
	ch := &oobChannel{ProjectID: p.ID, Mode: "C 用户 webhook", Kind: "webhook", BaseDomain: u.Host, Status: "healthy", SelfCheck: "ok", StartedAt: time.Now(), builtAt: time.Now()}
	ch.fetch = func() []oobInteraction {
		raw, err := oobHTTPGetHeader(cc.ServerURL, "Authorization", cc.Secret, 10*time.Second)
		if err != nil {
			return nil
		}
		var rows []struct {
			Ts     string `json:"ts"`
			Path   string `json:"path"`
			Remote string `json:"remote"`
			Body   string `json:"body"`
		}
		if json.Unmarshal([]byte(raw), &rows) != nil {
			return nil
		}
		var out []oobInteraction
		for _, r := range rows {
			summary := r.Path
			if summary == "" {
				summary = r.Body
			}
			out = append(out, oobInteraction{Ts: r.Ts, Protocol: "http", FullID: summary, Remote: r.Remote, Summary: summary})
		}
		return out
	}
	ch.stop = c.startPoller(p, ch, pollSec)
	return ch, nil
}

// startListener A2：本地 HTTP 监听器（+可选 UDP DNS 记录器）；内网/靶场零外联场景。
func (c *OOBCoord) startListener(p *store.Project, lc config.OOBLocalConfig) (*oobChannel, error) {
	mux := http.NewServeMux()
	ch := &oobChannel{ProjectID: p.ID, Mode: "A2 本地监听器", Kind: "listener", Status: "degraded", StartedAt: time.Now(), builtAt: time.Now()}
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		in := oobInteraction{Ts: time.Now().UTC().Format(time.RFC3339), Protocol: "http",
			FullID: r.URL.Path, Remote: r.RemoteAddr, Summary: r.URL.Path + "?" + r.URL.RawQuery}
		ch.addInteraction(in)
		c.persistInteraction(p, in)
		w.WriteHeader(200)
		_, _ = w.Write([]byte("ok"))
	})
	srv := &http.Server{Addr: fmt.Sprintf("0.0.0.0:%d", lc.HTTPPort), Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	ln, err := net.Listen("tcp", srv.Addr)
	if err != nil {
		return nil, fmt.Errorf("HTTP 监听 %s 失败（端口占用/权限）: %v", srv.Addr, err)
	}
	go func() { _ = srv.Serve(ln) }()
	stop := func() { _ = srv.Close() }
	// 自检：本地回环 GET
	selfOK := false
	if resp, gerr := http.Get(fmt.Sprintf("http://127.0.0.1:%d/oob-selfcheck", lc.HTTPPort)); gerr == nil {
		_ = resp.Body.Close()
		selfOK = resp.StatusCode == 200
	}
	ch.SelfCheck = map[bool]string{true: "ok", false: "fail"}[selfOK]
	ip := oobLocalIP()
	ch.BaseDomain = fmt.Sprintf("%s:%d", ip, lc.HTTPPort)
	ch.Status = map[bool]string{true: "healthy", false: "degraded"}[selfOK]
	ch.Reason = map[bool]string{true: "", false: "本机自检未通过（回环 GET 失败），通道保留但结果不可信"}[selfOK]
	if selfOK && lc.DNSPort > 0 {
		if dnsStop, derr := c.startDNSLogger(p, ch, lc.DNSPort); derr == nil {
			ch.BaseDomain = fmt.Sprintf("%s（HTTP:%d / DNS:%d）", ip, lc.HTTPPort, lc.DNSPort)
			prev := stop
			stop = func() { dnsStop(); prev() }
		} else {
			ch.Reason = "DNS 监听未启用: " + derr.Error() + "（HTTP 通道正常）"
		}
	}
	ch.stop = stop
	return ch, nil
}

// startDNSLogger A2 可选：最小 UDP DNS 记录器——解析 QNAME 落账并应答固定 A 记录。
func (c *OOBCoord) startDNSLogger(p *store.Project, ch *oobChannel, port int) (func(), error) {
	addr := &net.UDPAddr{IP: net.IPv4zero, Port: port}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return nil, err
	}
	go func() {
		buf := make([]byte, 1500)
		for {
			n, raddr, err := conn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			qname := dnsQNAME(buf[:n])
			if qname == "" {
				continue
			}
			in := oobInteraction{Ts: time.Now().UTC().Format(time.RFC3339), Protocol: "dns", FullID: qname, Remote: raddr.IP.String(), Summary: qname}
			ch.addInteraction(in)
			c.persistInteraction(p, in)
			if resp := dnsReply(buf[:n]); resp != nil {
				_, _ = conn.WriteToUDP(resp, raddr)
			}
		}
	}()
	return func() { _ = conn.Close() }, nil
}

// dnsQNAME 从原始 DNS 查询报文提取首个问题名（容错解析，失败返回空）。
func dnsQNAME(pkt []byte) string {
	if len(pkt) < 12 {
		return ""
	}
	pos := 12
	var labels []string
	for pos < len(pkt) {
		l := int(pkt[pos])
		if l == 0 {
			break
		}
		if pos+1+l > len(pkt) || l > 63 {
			return ""
		}
		labels = append(labels, string(pkt[pos+1:pos+1+l]))
		pos += 1 + l
	}
	if len(labels) == 0 {
		return ""
	}
	return strings.Join(labels, ".")
}

// dnsReply 构造最小 A 记录应答（拷贝问题段 + 单条 127.0.0.1 应答；不完整报文返回 nil 不应答）。
func dnsReply(q []byte) []byte {
	if len(q) < 12 {
		return nil
	}
	pos := 12
	for pos < len(q) {
		l := int(q[pos])
		if l == 0 {
			pos++
			break
		}
		if pos+1+l+4 > len(q) {
			return nil
		}
		pos += 1 + l
	}
	pos += 4 // QTYPE+QCLASS
	if pos > len(q) {
		return nil
	}
	resp := make([]byte, 0, pos+16)
	resp = append(resp, q[:2]...)                            // ID
	resp = append(resp, 0x81, 0x80)                          // 响应+递归可用
	resp = append(resp, q[4:6]...)                           // QDCOUNT 原样
	resp = append(resp, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00)  // ANCOUNT=1 其余 0
	resp = append(resp, q[12:pos]...)                        // 原问题段
	resp = append(resp, 0xC0, 0x0C)                          // 名字指针
	resp = append(resp, 0x00, 0x01, 0x00, 0x01)              // TYPE=A CLASS=IN
	resp = append(resp, 0x00, 0x00, 0x00, 0x3C)              // TTL=60
	resp = append(resp, 0x00, 0x04, 127, 0, 0, 1)            // RDLENGTH + 127.0.0.1
	return resp
}

func oobLocalIP() string {
	conn, err := net.Dial("udp", "8.8.8.8:53")
	if err != nil {
		return "127.0.0.1"
	}
	defer func() { _ = conn.Close() }()
	return conn.LocalAddr().(*net.UDPAddr).IP.String()
}

func (c *OOBCoord) startPoller(p *store.Project, ch *oobChannel, pollSec int) func() {
	stop := make(chan struct{})
	go func() {
		t := time.NewTicker(time.Duration(pollSec) * time.Second)
		defer t.Stop()
		for {
			select {
			case <-stop:
				return
			case <-t.C:
				if ch.fetch == nil {
					return
				}
				for _, in := range ch.fetch() {
					ch.addInteraction(in)
					c.persistInteraction(p, in)
				}
			}
		}
	}()
	return func() { close(stop) }
}

// selfCheckDNS 基域解析自检（代理出口环境 DNS 直查失败不代表通道不可用，skipped 不降级状态）。
func selfCheckDNS(domain string) string {
	ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
	defer cancel()
	if ips, err := net.DefaultResolver.LookupIPAddr(ctx, domain); err == nil && len(ips) > 0 {
		return "ok"
	}
	return "skipped"
}

func (ch *oobChannel) waitHealthy(timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		ch.mu.Lock()
		st, dom := ch.Status, ch.BaseDomain
		ch.mu.Unlock()
		if st == "healthy" && dom != "" {
			return true
		}
		time.Sleep(300 * time.Millisecond)
	}
	return false
}

func oobReasonSuffix(reason string) string {
	if strings.TrimSpace(reason) == "" {
		return ""
	}
	return "（" + reason + "）"
}

// persistChannelFile 落 evidence/oob/channel.txt（S1 门⑪ oobChannelSelfCheckPassed 口径：含 domain 与 self_check=ok）。
func (c *OOBCoord) persistChannelFile(p *store.Project, ch *oobChannel) {
	if ch.Status == "unavailable" || p.ID == oobTestProjectID { // 加固④：测试不落工作区
		return
	}
	content := fmt.Sprintf("# OOB 通道（引擎 v7.0.0 守护管理）\ndomain=%s\nmode=%s\nchannel_type=%s\nstatus=%s\nself_check=%s\nself_check_result=%s\npid=engine-managed\nstarted_at_utc=%s\n约束=%s\n",
		ch.BaseDomain, ch.Mode, ch.Kind, ch.Status, ch.SelfCheck, ch.SelfCheck, ch.StartedAt.UTC().Format(time.RFC3339),
		map[bool]string{true: "公共第三方通道：只投递无害探针", false: "非公共通道：回连不出第三方"}[ch.Public])
	if ch.Status == "degraded" {
		content += "degraded_reason=" + ch.Reason + "\n"
	}
	if _, err := c.exec.WriteFile(p.ID, oobChannelFile, content); err != nil && c.logFn != nil {
		c.logFn(p, "", "⚠ OOB channel.txt 落盘失败: "+err.Error())
	}
}

// persistInteraction 回连记录落 evidence/oob/interactions.jsonl（读改写小文件；C27/EV 引用可直接指向该文件）。
// v7.0.0 核对加固③：读改写非原子——监听器并发回连/轮询器与 oob_poll 并发触发时会互相覆盖丢行，
// 协调器级互斥保护。
func (c *OOBCoord) persistInteraction(p *store.Project, in oobInteraction) {
	if p.ID == oobTestProjectID { // v7.0.0 核对加固④：连通性测试不落任何项目工作区
		return
	}
	c.persistMu.Lock()
	defer c.persistMu.Unlock()
	line, err := json.Marshal(in)
	if err != nil {
		return
	}
	old, _ := c.exec.ReadFile(p.ID, oobPersistFile)
	var lines []string
	if strings.TrimSpace(old) != "" {
		lines = strings.Split(strings.TrimRight(old, "\n"), "\n")
	}
	lines = append(lines, string(line))
	if len(lines) > oobRingCap {
		lines = lines[len(lines)-oobRingCap:]
	}
	_, _ = c.exec.WriteFile(p.ID, oobPersistFile, strings.Join(lines, "\n")+"\n")
}

// SelfTest 设置页连通性测试：以临时项目 id 起通道→取状态→回收，不落任何项目工作区。
func (c *OOBCoord) SelfTest(cfg config.OOBConfig) map[string]any {
	old := c.effective()
	c.SetOverride(&cfg)
	defer c.SetOverride(&old)
	fake := &store.Project{ID: oobTestProjectID}
	ch := c.Ensure(fake, "")
	res := map[string]any{"ok": false}
	if ch == nil {
		res["detail"] = "OOB 已关闭（mode=off）"
		return res
	}
	res["mode"], res["kind"], res["base_domain"], res["status"], res["self_check"] = ch.Mode, ch.Kind, ch.BaseDomain, ch.Status, ch.SelfCheck
	res["ok"] = ch.Status == "healthy"
	if ch.Reason != "" {
		res["detail"] = ch.Reason
	}
	c.Stop(oobTestProjectID)
	return res
}

func oobConfigHint() string {
	return "通道配置指引：①设置页「OOB 回连通道」卡片（推荐，保存即热生效）；或 ②config.json oob 节（mode=auto|local|public|custom，custom.kind=interactsh|dnslog|webhook）。ROE oob_callback=deny 时仅本地监听器可用。"
}

// oobBlindSkillID 盲态技能判别（OOB 前置门适用集）：oob-interactsh 手册本身不拦（载入即学 oob_check 用法）。
func oobBlindSkillID(id string) bool {
	low := strings.ToLower(id)
	if low == "oob-interactsh" {
		return false
	}
	for _, k := range []string{"ssrf", "xxe", "cmdi", "blind", "deserial", "jndi", "log4j"} {
		if strings.Contains(low, k) {
			return true
		}
	}
	return false
}

// blindSkillGate 盲态技能前置门：返回空=放行；非空=拒绝文案（load_skill 直接命中与 Bundle 配套共用）。
// 方案 §4.3：无健康通道时盲态技能不派发——消灭无通道白烧的轮次（某历史任务 实证场景）。
func (o *Orchestrator) blindSkillGate(p *store.Project, skillID string) string {
	if !oobBlindSkillID(skillID) {
		return ""
	}
	ok, reason := o.oob.BlindGateReady(p, skillID)
	if ok {
		return ""
	}
	return fmt.Sprintf("盲态技能前置门（v7.0.0）：OOB 回连通道不可用（%s）——技能 %s 未注入。先调 oob_check 查看通道状态与配置指引；通道不可用期间盲态类禁止开测，相关覆盖单元落 needs_follow_up（禁止 ruled_out）。%s", reason, skillID, oobConfigHint())
}

func oobHTTPGet(u, secret string, timeout time.Duration) (string, error) {
	return oobHTTPGetHeader(u, "X-OOB-Token", secret, timeout)
}

// oobClientGet 会话化 GET（dnslog 类服务要求取域与取记录同 cookie 会话）。
func oobClientGet(client *http.Client, u, secret string) (string, error) {
	req, err := http.NewRequest("GET", u, nil)
	if err != nil {
		return "", err
	}
	if strings.TrimSpace(secret) != "" {
		req.Header.Set("X-OOB-Token", secret)
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func oobHTTPGetHeader(u, hdrKey, hdrVal string, timeout time.Duration) (string, error) {
	client := &http.Client{Timeout: timeout}
	req, err := http.NewRequest("GET", u, nil)
	if err != nil {
		return "", err
	}
	if strings.TrimSpace(hdrVal) != "" && hdrKey != "" {
		req.Header.Set(hdrKey, hdrVal)
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// ---- Web 设置层入口（server.go 调用） ----

// OOBApply 设置页保存后热生效：settings 桶配置覆盖 config.json（nil 语义由调用方保证非 nil）。
func (o *Orchestrator) OOBApply(cfg config.OOBConfig) { o.oob.SetOverride(&cfg) }

// OOBSelfTest 设置页连通性测试：以表单值起临时通道自检后回收，不落任何项目工作区。
func (o *Orchestrator) OOBSelfTest(cfg config.OOBConfig) map[string]any { return o.oob.SelfTest(cfg) }
