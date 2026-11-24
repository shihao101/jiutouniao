package engine

// v6.1.0（S1 修复方案）：S1 治理硬门与逐目标对账的集中实现。
// 文件组织：②影子资产门/㉒资产范围门、③S1 阶段 L0 门、④⑤S1 确定性收口门与逐目标对账、
// ⑧ROE 运行时门、⑫子域候选合并器。所有门默认开启（config.GuardConfig 三态开关，显式 false 才回退）。

import (
	"context"
	"crypto/sha256"
	"fmt"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"jiutouniao/internal/config"
	"jiutouniao/internal/llm"
	"jiutouniao/internal/store"
	"jiutouniao/internal/tools"
)

// assetMetadataKeyLooksSecret ⑳：metadata 键是否疑似凭据——明文凭据不入台账，
// 密钥只允许以 _ref 结尾的指针键（指向凭据仓库/密钥管理系统的 ID）。
func assetMetadataKeyLooksSecret(key string) bool {
	k := strings.ToLower(strings.TrimSpace(key))
	if strings.HasSuffix(k, "_ref") {
		return false
	}
	return secretKeyRe.MatchString(k)
}

var secretKeyRe = regexp.MustCompile(`(?i)(access[_-]?key|secret|token|password|passwd|\bpwd\b|credential|api[_-]?key|private[_-]?key|cookie)`)

// assetTestBlockedAssets ②：提取命令中引用、且命中「已登记但未授权测试」资产的 host/IP 列表。
// 判定口径：shadow_pending/out_of_scope/conditional/unknown 一律不放行——unknown 覆盖旧库
// 无字段数据（fail-closed）。项目原始目标（授权清单）与外部源白名单不受此门约束。
func (o *Orchestrator) assetTestBlockedAssets(p *store.Project, command string) []string {
	if !o.guardEnabled(func(g *config.GuardConfig) *bool { return g.BlockShadowAssets }) {
		return nil
	}
	// v6.3.2：剥除被动 DNS/WHOIS 查询段——归属核实类只读查询不因 shadow_pending 资产名
	// 出现在查询参数中被拦（实战 S1：dig henetc.edu.cn NS/SOA ×8 被拦，归属核实被迫绕道）。
	command = stripDNSQuerySegments(command)
	assets, _ := o.store.ListAssets(p.ID)
	if len(assets) == 0 {
		return nil
	}
	targetKeys := map[string]bool{}
	for _, t := range splitProjectTargets(p) {
		targetKeys[normalizeS1Host(t)] = true
	}
	restricted := map[string]*store.Asset{}
	for _, a := range assets {
		if a.EffectiveScope() == "in_scope" {
			continue
		}
		for _, key := range assetHostKeys(a) {
			if key == "" || targetKeys[key] {
				continue
			}
			if _, seen := restricted[key]; !seen {
				restricted[key] = a
			}
		}
	}
	if len(restricted) == 0 {
		return nil
	}
	blocked := []string{}
	seen := map[string]bool{}
	check := func(rawHost string) {
		h := normalizeS1Host(rawHost)
		if h == "" || seen[h] {
			return
		}
		a, hit := restricted[h]
		if !hit {
			// 通配授权态的逆用：受限资产的通配键（.example* 后缀）覆盖其子域
			for key, ra := range restricted {
				if strings.HasSuffix(key, "*") && strings.HasSuffix(h, strings.TrimSuffix(key, "*")) {
					a, hit = ra, true
					break
				}
			}
		}
		if hit {
			seen[h] = true
			blocked = append(blocked, fmt.Sprintf("%s(scope_status=%s)", h, a.EffectiveScope()))
		}
	}
	for _, m := range urlHostRe.FindAllStringSubmatch(command, -1) {
		check(m[1])
	}
	for _, m := range ipLitRe.FindAllStringSubmatch(command, -1) {
		check(m[1])
	}
	stripped := urlHostRe.ReplaceAllString(command, " ")
	stripped = ipLitRe.ReplaceAllString(stripped, " ")
	for _, m := range bareDomainRe.FindAllStringSubmatch(stripped, -1) {
		if !isPlausibleDomainHost(m[1]) {
			continue // v6.3.2：TLD 纯数字（版本号 3.7/3.7.1 类）非域名候选
		}
		check(m[1])
	}
	return blocked
}

// shadowAssetGate ②：任何命令通道在审批前拦截对「已登记未授权测试」资产的流量（strict_scope 无关）。
func (o *Orchestrator) shadowAssetGate(p *store.Project, stageID, command, channel string) string {
	blocked := o.assetTestBlockedAssets(p, command)
	if len(blocked) == 0 {
		return ""
	}
	msg := fmt.Sprintf("范围外/待确认资产已登记但未授权测试：%s；请取得书面授权并用 update_asset 将台账状态更新为 in_scope（附授权依据）后重试。",
		strings.Join(blocked, "、"))
	_, _ = o.store.AddEvidence(&store.EvidenceRecord{ProjectID: p.ID, Stage: stageID,
		Type: "command", Input: truncateText(command, 200), Output: msg,
		Risk: tools.Forbidden, ApprovedBy: "shadow-scope-gate"})
	o.log(p, stageID, fmt.Sprintf("⛔ 影子资产门拦截（%s 通道）：%s", channel, strings.Join(blocked, "、")))
	return msg
}

// assetHostKeys 资产值的规范化主机键集合（value 可能是域名/URL/IP；通配授权以 * 结尾键表达）。
func assetHostKeys(a *store.Asset) []string {
	out := []string{}
	add := func(v string) {
		if k := normalizeS1Host(v); k != "" {
			out = append(out, k)
		}
	}
	add(a.Value)
	if a.Metadata != nil {
		add(a.Metadata["base_url"])
		add(a.Metadata["store_url"])
	}
	v := strings.ToLower(strings.TrimSpace(a.Value))
	if strings.HasPrefix(v, "*.") {
		out = append(out, v[1:]+"*") // ".example" → ".example*" 后缀匹配键（仅 in_scope 被 scopeGate 消费）
	}
	return out
}

// normalizeS1Host 主机/URL/IP 归一化：小写、去 scheme、去端口、去路径、去尾点、去 www. 前缀
// （与 hostAllowed 既有口径一致，保证门与对账使用同一事实源）。
func normalizeS1Host(v string) string {
	s := strings.ToLower(strings.TrimSpace(v))
	s = strings.TrimPrefix(strings.TrimPrefix(s, "https://"), "http://")
	if i := strings.IndexAny(s, "/?#"); i >= 0 {
		s = s[:i]
	}
	// 去端口（IPv6 字面量 [..] 内的冒号不动）
	if i := strings.LastIndex(s, ":"); i >= 0 && !strings.Contains(s, "]") && isAllDigits(s[i+1:]) {
		s = s[:i]
	}
	s = strings.TrimSuffix(s, ".")
	if strings.HasPrefix(s, "www.") {
		s = strings.TrimPrefix(s, "www.")
	}
	return s
}

func isAllDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// isPlausibleDomainHost v6.3.2：裸域名候选的通用置信过滤——ICANN TLD 不存在纯数字
// （实战误拦：searchsploit --id "jQuery 3.7" 把版本号 3.7/3.7.1 当域名；CSS 值同类）。
// 点分最后一段为纯数字 → 非域名候选；IP 字面量已被 ipLitRe 单独提取不受影响。
// 只做排除不做放行：含字母 TLD 仍走既有 allow/资产判定，不新增漏拦面。
func isPlausibleDomainHost(raw string) bool {
	h := normalizeS1Host(raw)
	if h == "" || !strings.Contains(h, ".") {
		return false
	}
	last := h[strings.LastIndex(h, ".")+1:]
	return !isAllDigits(last)
}

// dnsQuerySegmentRe 被动 DNS/WHOIS 查询段：dig/host/nslookup/whois 开头的命令段
// （段=以 ;|& 与换行分隔）——协议本身不接触目标服务（与 s1ActionGate「dig/host/whois 族
// 不提取查询键」同一哲学；v6.3.2 补齐 shadowAssetGate/scopeGate 缺失的同款豁免，
// 实战 某历史任务：S1 影子父域 henetc.edu.cn 的 8 条 dig 被动归属查询被拦）。
// dig axfr（区域传送）是对目标 DNS 服务器的主动查询，不豁免。
var dnsQuerySegmentRe = regexp.MustCompile(`(?im)(?:^|[;|&])\s*(?:dig|host|nslookup|whois)\b[^\n;|&]*`)

// stripDNSQuerySegments 剥除命令中的被动 DNS/WHOIS 查询段（axfr=对目标 DNS 服务器的主动
// 区域传送——原文出现 axfr 字样即整体不做豁免，保守不新增放行面）。
func stripDNSQuerySegments(command string) string {
	if strings.Contains(strings.ToLower(command), "axfr") {
		return command
	}
	return dnsQuerySegmentRe.ReplaceAllString(command, " ")
}

// ---- ⑤ 逐目标对账 ----

// canonicalTargetKey ⑤：目标/资产的精确规范化键（区分端口、忽略 scheme/路径/大小写/尾点）。
// 不用全文子串包含——审计 F-14：包含匹配会互相误命中（a.ndu.edu.tw 命中 ndu.edu.tw）。
func canonicalTargetKey(v string) string {
	s := strings.ToLower(strings.TrimSpace(v))
	s = strings.TrimPrefix(strings.TrimPrefix(s, "https://"), "http://")
	if i := strings.IndexAny(s, "/?#"); i >= 0 {
		s = s[:i]
	}
	s = strings.TrimSuffix(s, ".")
	return s
}

// missingS1TargetRefs ⑤：逐目标对账——每个原始目标必须至少有一条资产记录（TargetRef 或
// 值/元数据精确键命中）且范围状态已判定（in_scope/shadow_pending/out_of_scope/conditional）。
// 返回（缺资产记录的目标、缺范围判定的目标）。
func missingS1TargetRefs(targets []string, assets []*store.Asset) (noAsset, noScopeVerdict []string) {
	type assetEntry struct {
		key     string // 精确键
		raw     string // 原值（小写）
		verdict bool
	}
	assetEntries := []assetEntry{}
	for _, a := range assets {
		raws := []string{}
		if tr := strings.TrimSpace(a.TargetRef); tr != "" {
			raws = append(raws, tr)
		}
		raws = append(raws, a.Value)
		if a.Metadata != nil {
			raws = append(raws, a.Metadata["base_url"])
		}
		for _, raw := range raws {
			if strings.TrimSpace(raw) == "" {
				continue
			}
			assetEntries = append(assetEntries, assetEntry{
				key: canonicalTargetKey(raw), raw: strings.ToLower(strings.TrimSpace(raw)),
				verdict: a.EffectiveScope() == "in_scope" || a.EffectiveScope() == "shadow_pending" ||
					a.EffectiveScope() == "out_of_scope" || a.EffectiveScope() == "conditional",
			})
		}
	}
	hostLike := func(v string) bool {
		// 主机形态：含点且各段为字母数字连字符（域名/IP）；其余视为描述性
		s := canonicalTargetKey(v)
		if s == "" || !strings.Contains(s, ".") {
			return false
		}
		for _, seg := range strings.Split(s, ".") {
			if seg == "" {
				return false
			}
			for _, r := range seg {
				if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-' || r == ':' || r >= 'A' && r <= 'Z') {
					return false
				}
			}
		}
		return true
	}
	for _, t := range targets {
		kt := canonicalTargetKey(t)
		if kt == "" {
			continue
		}
		var hit, verd *assetEntry
		for i := range assetEntries {
			e := &assetEntries[i]
			if e.key == kt {
				if hit == nil {
					hit = e
				}
				if e.verdict {
					verd = e
				}
			}
		}
		if hit == nil && hostLike(t) {
			// v6.6.0 回放驱动：IP 目标的端口兼容层——目标行 10.10.254.116/index.html 与
			// 资产值 10.10.254.116:443/console 在精确键（保留端口）下不命中，但 IP 目标的
			// 端口是服务维度而非新资产：去端口后同为该 IP 即视为同宿主命中。
			stripPort := func(s string) string {
				if i := strings.LastIndex(s, ":"); i > 0 && isAllDigits2(s[i+1:]) {
					return s[:i]
				}
				return s
			}
			ktNoPort := stripPort(kt)
			if isIPHost(ktNoPort) {
				for i := range assetEntries {
					e := &assetEntries[i]
					if stripPort(e.key) == ktNoPort && isIPHost(stripPort(e.key)) {
						if hit == nil {
							hit = e
						}
						if e.verdict {
							verd = e
						}
					}
				}
			}
		}
		if hit == nil && !hostLike(t) {
			// v6.6.0 回放驱动修复：描述性目标（「小程序测试」「xxx」、带路径 IP 等非 host
			// 形态）回退词边界子串命中——与 S4/S5 targetCoverageRecon 的 CIDR/描述性目标
			// 回退口径同族，避免旧项目描述性目标行被误判「缺资产台账」。
			nt := strings.ToLower(strings.TrimSpace(t))
			for i := range assetEntries {
				e := &assetEntries[i]
				if e.raw == "" || len(e.raw) < len(nt) {
					continue
				}
				idx := strings.Index(e.raw, nt)
				if idx < 0 {
					continue
				}
				// 词边界：命中点前后不得为字母/数字（消「更大词元内部片段」误命中；
				// '.'/'-' 不拒绝——与 v6.5.0 S5-① 口径一致，保持子域与列表符邻接命中）
				before := byte(0)
				if idx > 0 {
					before = e.raw[idx-1]
				}
				after := byte(0)
				if idx+len(nt) < len(e.raw) {
					after = e.raw[idx+len(nt)]
				}
				if isReplayWordByte(before) || isReplayWordByte(after) {
					continue
				}
				if hit == nil {
					hit = e
				}
				if e.verdict {
					verd = e
				}
			}
		}
		if hit == nil {
			// v6.6.0 回放驱动：描述性目标（非 host 形态）零命中 = 提示级（目标行本身是
			// 描述/占位——「小程序测试」「xxx」等），不硬拦（与 S4/S5 对账 matched=0
			// 提示级留痕同口径）；主机形态零命中仍硬拦（漏登记是方案⑤核心缺陷）。
			if !hostLike(t) {
				continue
			}
			noAsset = append(noAsset, t)
			continue
		}
		if verd == nil {
			noScopeVerdict = append(noScopeVerdict, t)
		}
	}
	return noAsset, noScopeVerdict
}

// isIPHost 判定 s 是否为 IPv4/IPv6 字面量主机。
func isIPHost(s string) bool {
	if strings.Contains(s, ":") && strings.Contains(s, "::") || strings.Count(s, ":") >= 2 {
		return true // IPv6 粗判
	}
	parts := strings.Split(s, ".")
	if len(parts) != 4 {
		return false
	}
	for _, seg := range parts {
		if !isAllDigits2(seg) || len(seg) > 3 {
			return false
		}
	}
	return true
}

func isAllDigits2(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// isReplayWordByte 词边界拒绝集：字母/数字（与 v6.5.0 multitarget 词边界层一致）。
func isReplayWordByte(b byte) bool {
	return b >= 'a' && b <= 'z' || b >= '0' && b <= '9' || b >= 'A' && b <= 'Z'
}

// ---- ④ S1 确定性收口门 ----

var s1RequiredDeliverables = []string{
	"deliverables/s1-资产台账.md",
	"deliverables/s1-范围边界表.md",
	"deliverables/s1-架构草图V0.md",
	"deliverables/s1-影子资产线索清单.md",
}

// s1ClosureIssues ④⑤⑪：S1 收口确定性校验（四件套存在且非空 + 逐目标对账 + 条件 OOB 门）。
// 由 complete_stage 前置门与 deterministicGate（s1 进入无条件名单）共同调用。
func (o *Orchestrator) s1ClosureIssues(p *store.Project) []string {
	issues := []string{}
	for _, f := range s1RequiredDeliverables {
		raw, err := o.exec.ReadFile(p.ID, f)
		if err != nil || len(strings.TrimSpace(raw)) < 40 {
			if strings.Contains(f, "范围边界表") {
				issues = append(issues, "收口被拦截（S1 确定性门）：缺少 deliverables/s1-范围边界表.md；请补齐每个目标/资产的授权状态与判定依据后重试。")
			} else {
				issues = append(issues, fmt.Sprintf("收口被拦截（S1 确定性门）：缺少或内容为空：%s（须为实质内容，不接受占位空壳）。", f))
			}
		}
	}
	// ④：范围边界表必须出现范围判定语义（结构级校验，不做脆弱全文模板匹配）
	if raw, err := o.exec.ReadFile(p.ID, "deliverables/s1-范围边界表.md"); err == nil {
		text := strings.ToLower(raw)
		hasScopeEnum := strings.Contains(text, "in_scope") || strings.Contains(text, "in-scope") ||
			strings.Contains(text, "范围内") || strings.Contains(text, "out_of_scope") || strings.Contains(text, "范围外")
		if !hasScopeEnum {
			issues = append(issues, "收口被拦截（S1 确定性门）：范围边界表未包含逐资产范围判定（in_scope/in-scope/范围内 三态标注）——请按 s1.md S1-3 逐项标注后重试。")
		}
	}
	// ⑤：逐目标对账——每个原始目标至少一条资产记录且范围状态已判定
	targets := splitProjectTargets(p)
	if len(targets) > 0 {
		assets, _ := o.store.ListAssets(p.ID)
		noAsset, noScope := missingS1TargetRefs(targets, assets)
		for _, t := range noAsset {
			issues = append(issues, fmt.Sprintf("收口被拦截（S1 逐目标对账）：目标 %s 缺少资产台账记录——S1 要求逐目标登记测绘，禁止只测第一个。", t))
		}
		for _, t := range noScope {
			issues = append(issues, fmt.Sprintf("收口被拦截（S1 逐目标对账）：目标 %s 的资产记录缺少范围判定（scope_status）——请补齐授权状态与判定依据。", t))
		}
	}
	// ⑪：项目声明 OOBRequired=true 时核验通道产物（guard.require_s1_oob_channel）
	if p.OOBRequired && o.guardEnabled(func(g *config.GuardConfig) *bool { return g.RequireS1OOBChannel }) {
		ch, err := o.exec.ReadFile(p.ID, "evidence/oob/channel.txt")
		if err != nil || !oobChannelSelfCheckPassed(ch) {
			issues = append(issues, "收口被拦截（S1 OOB 门）：项目要求 OOB，但 evidence/oob/channel.txt 缺失或自检未通过；完成预置/自检或记录关闭该能力的授权决策后重试。")
		}
	}
	return issues
}

// oobChannelSelfCheckPassed ⑪：channel.txt 最少字段齐备（domain/self_check）且自检结果为通过。
func oobChannelSelfCheckPassed(content string) bool {
	low := strings.ToLower(content)
	for _, kw := range []string{"domain", "self_check"} {
		if !strings.Contains(low, kw) {
			return false
		}
	}
	return strings.Contains(low, "self_check=ok") || strings.Contains(low, "self_check=pass") ||
		strings.Contains(low, "self_check_result=ok") || strings.Contains(low, "self_check_result=pass") ||
		strings.Contains(low, "self_check: ok") || strings.Contains(low, "自检通过") ||
		strings.Contains(low, "self_check=success") ||
		strings.Contains(low, "status=healthy") // v7.0.0：引擎托管通道以 status=healthy 为准（基域分配即注册成功；代理出口 DNS 直查 skipped 属正常，不否定通道可用性）
}

// ---- ⑧ ROE 运行时门 ----

// ROERuntimeEnforcer ⑧：ROE 限定参数的进程内确定性执行器。
// 已强制：时间窗 windows（窗口外阻断全部目标流量通道）、max_conn_per_s（进程级目标连接
// 预算——滑动窗口计数目标定向执行，超限阻断；⚠ 近似语义：非出口层线速计量，文案明示）、
// cooldown_protocol=full-silence（与行为预算器冷却联动）。
// 未强制：rotation（出口轮换额度）——需出口层支持；接入前由 UnenforcedFields 诚实披露，
// 不伪装成「引擎已强制」。
type ROERuntimeEnforcer struct {
	profile    *ROEProfile
	windows    string
	maxConn    int
	cooldown   string
	rotCap     string
	connLog    []time.Time // 目标定向执行时间戳（滑动窗口）
	lastSilent time.Time   // full-silence 冷却起点
}

// NewROERuntimeEnforcer 从 ROE Profile 构造运行时执行器；无 profile 返回 nil。
func NewROERuntimeEnforcer(p *ROEProfile) *ROERuntimeEnforcer {
	if p == nil {
		return nil
	}
	e := &ROERuntimeEnforcer{profile: p,
		windows:  strings.TrimSpace(p.Values["windows"]),
		cooldown: strings.TrimSpace(p.Values["cooldown_protocol"]),
		rotCap:   strings.TrimSpace(p.Values["rotation"])}
	if v := strings.TrimSpace(p.Values["max_conn_per_s"]); isAllDigits(v) {
		fmt.Sscanf(v, "%d", &e.maxConn)
	}
	return e
}

// roeWindow ⑧：windows 字段解析（schema 校验过形态 {"..."} 或 none）。
// 支持 {"start":"HH:MM","end":"HH:MM","tz":"Area/City","days":["Mon",...]}：跨日窗口支持
// start>end；tz 缺省 UTC；days 缺省每天。解析失败 fail-closed（拒绝执行，不静默放行）。
type roeWindow struct {
	startMin, endMin int
	tz               string
	days             map[string]bool
	ok               bool
}

func parseROEWindow(w string) roeWindow {
	out := roeWindow{ok: false}
	if w == "" || w == "none" {
		return roeWindow{ok: true} // 无限制
	}
	getHHMM := func(key string) int {
		m := regexp.MustCompile(`"` + key + `"\s*:\s*"(\d{1,2}):(\d{2})"`).FindStringSubmatch(w)
		if m == nil {
			return -1
		}
		h, mi := 0, 0
		fmt.Sscanf(m[1], "%d", &h)
		fmt.Sscanf(m[2], "%d", &mi)
		if h < 0 || h > 24 || mi < 0 || mi > 59 {
			return -1
		}
		return h*60 + mi
	}
	s, e := getHHMM("start"), getHHMM("end")
	if s < 0 || e < 0 {
		return out
	}
	out.startMin, out.endMin = s, e
	if m := regexp.MustCompile(`"tz"\s*:\s*"([^"]+)"`).FindStringSubmatch(w); m != nil {
		out.tz = m[1]
	}
	out.days = map[string]bool{}
	if m := regexp.MustCompile(`"days"\s*:\s*\[([^\]]*)\]`).FindStringSubmatch(w); m != nil {
		for _, d := range strings.Split(m[1], ",") {
			d = strings.ToLower(strings.Trim(strings.TrimSpace(d), `"`))
			if d != "" {
				out.days[d] = true
			}
		}
	}
	out.ok = true
	return out
}

var roeWeekdayNames = map[time.Weekday]string{
	time.Sunday: "sun", time.Monday: "mon", time.Tuesday: "tue", time.Wednesday: "wed",
	time.Thursday: "thu", time.Friday: "fri", time.Saturday: "sat",
}

// roeWindowAllowed ⑧：now 是否在 ROE 窗口内。windows 未配置/none → 恒允许。
func (e *ROERuntimeEnforcer) roeWindowAllowed(now time.Time) (bool, string) {
	if e == nil || e.windows == "" || e.windows == "none" {
		return true, ""
	}
	w := parseROEWindow(e.windows)
	if !w.ok {
		return false, "ROE 时间窗格式不可解析（" + truncateText(e.windows, 80) + "）：按 fail-closed 拒绝执行；请修正 roe profile 的 windows 字段（{\"start\":\"HH:MM\",\"end\":\"HH:MM\",\"tz\":\"Area/City\"} 或 none）"
	}
	loc := time.UTC
	if w.tz != "" {
		l, err := time.LoadLocation(w.tz)
		if err != nil {
			return false, "ROE 时间窗时区不可解析（" + w.tz + "）：按 fail-closed 拒绝执行"
		}
		loc = l
	}
	cur := now.In(loc)
	if len(w.days) > 0 && !w.days[roeWeekdayNames[cur.Weekday()]] {
		return false, ""
	}
	curMin := cur.Hour()*60 + cur.Minute()
	if w.startMin == w.endMin {
		return true, "" // 同值=显式全天
	}
	inWin := false
	if w.startMin < w.endMin {
		inWin = curMin >= w.startMin && curMin < w.endMin
	} else {
		inWin = curMin >= w.startMin || curMin < w.endMin // 跨日窗口（如 22:00-06:00）
	}
	if !inWin {
		return false, ""
	}
	return true, ""
}

// Check ⑧：命令通道前置判定（governanceGates 授权门之后调用）。返回空串=放行。
func (e *ROERuntimeEnforcer) Check(stageID, command string, now time.Time) string {
	if e == nil {
		return ""
	}
	if ok, why := e.roeWindowAllowed(now); !ok {
		if why != "" {
			return "执行被拦截（ROE 时间窗）：" + why
		}
		return fmt.Sprintf("执行被拦截（ROE 时间窗）：当前时间（%s UTC%s）不在授权测试窗口内；窗口外禁止任何主动流量（含登录请求）。",
			now.UTC().Format("2006-01-02T15:04Z"), e.profile.Values["windows"])
	}
	if e.maxConn > 0 {
		e.trimConnLog(now)
		if len(e.connLog) >= e.maxConn {
			return fmt.Sprintf("执行被拦截（ROE 连接预算）：目标定向执行已达 max_conn_per_s=%d 的进程级预算上限；请降低并发/改批量形态并稍后重试（⚠ 进程级近似计量，非出口层线速）。", e.maxConn)
		}
		e.connLog = append(e.connLog, now)
	}
	if e.cooldown == "full-silence" && !e.lastSilent.IsZero() && now.Sub(e.lastSilent) < 5*time.Minute {
		return "执行被拦截（ROE 冷却协议）：cooldown_protocol=full-silence 生效中，该目标全部流量静默至冷却结束。"
	}
	return ""
}

func (e *ROERuntimeEnforcer) trimConnLog(now time.Time) {
	keep := e.connLog[:0]
	for _, t := range e.connLog {
		if now.Sub(t) < time.Second {
			keep = append(keep, t)
		}
	}
	e.connLog = keep
}

// NoteCooldown ⑧：行为预算器触发静默冷却时联动记录起点（full-silence 语义）。
func (e *ROERuntimeEnforcer) NoteCooldown(now time.Time) {
	if e != nil && e.cooldown == "full-silence" {
		e.lastSilent = now
	}
}

// UnenforcedFields ⑧：诚实披露——未接入出口层前不可强制的字段清单（Digest 与启动日志标注）。
func (e *ROERuntimeEnforcer) UnenforcedFields() []string {
	if e == nil {
		return nil
	}
	out := []string{}
	if e.rotCap != "" && e.rotCap != "unlimited" {
		out = append(out, "rotation（出口轮换额度需出口层支持——当前仅登记不强制，Digest 已标注）")
	}
	return out
}

// ---- ⑫ S1 子域候选合并器 ----

// buildS1SubdomainInput ⑫：读取工作区已有 CT/subfinder/DNS 候选文本，本地规范化去重排序，
// 产出 evidence/s1-subs-final.txt + evidence/s1-subs-manifest.json（来源/候选数/时间/状态）。
// 纯本地零网络；全部来源缺失时仍生成空输入并在 manifest 记 not_checked（不静默当零候选）。
var s1SubSourceFiles = []string{
	"evidence/s1-crtsh-subs.txt", "evidence/s1-subfinder.txt", "evidence/s1-ct-subs.txt",
	"evidence/s1-dns-subs.txt", "evidence/s1-subs-candidates.txt",
}

var s1DomainTokenRe = regexp.MustCompile(`(?i)(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}`)

func (o *Orchestrator) buildS1SubdomainInput(p *store.Project) (string, error) {
	seen := map[string]bool{}
	candidates := []string{}
	sources := []string{}
	totalTokens := 0
	for _, src := range s1SubSourceFiles {
		raw, err := o.exec.ReadFile(p.ID, src)
		if err != nil {
			continue
		}
		n := 0
		for _, tok := range s1DomainTokenRe.FindAllString(raw, -1) {
			d := strings.ToLower(strings.TrimSuffix(tok, "."))
			if len(d) < 4 || len(d) > 253 || !strings.Contains(d, ".") {
				continue
			}
			if !seen[d] {
				seen[d] = true
				candidates = append(candidates, d)
			}
			n++
		}
		if n > 0 {
			totalTokens += n
			sources = append(sources, fmt.Sprintf(`{"file":"%s","tokens":%d}`, src, n))
		}
	}
	sort.Strings(candidates)
	status := "ok"
	if len(sources) == 0 {
		status = "not_checked" // 无任何来源：显式标注，不静默当作零候选
	}
	body := strings.Join(candidates, "\n")
	if _, err := o.exec.WriteFile(p.ID, "evidence/s1-subs-final.txt", body); err != nil {
		return "", err
	}
	// v6.1.0（方案⑫）：manifest 附输出哈希（sha256）——下游可核验「脚本输入=合并器输出」
	sum := sha256.Sum256([]byte(body))
	manifest := fmt.Sprintf(`{"status":"%s","generated_at_utc":"%s","sources":[%s],"candidates":%d,"sha256":"%x"}`,
		status, time.Now().UTC().Format(time.RFC3339), strings.Join(sources, ","), len(candidates), sum)
	if _, err := o.exec.WriteFile(p.ID, "evidence/s1-subs-manifest.json", manifest); err != nil {
		return "", err
	}
	return fmt.Sprintf("已生成 evidence/s1-subs-final.txt（候选 %d 条，来源 %d 个，status=%s）与 evidence/s1-subs-manifest.json；对该文件执行子域接管 DNS 指纹脚本（只登记线索，不做 HTTP 二次确认）。",
		len(candidates), len(sources), status), nil
}

// ---- ③ S1 阶段 L0 门 ----

// s1PassiveQueryVerbs ③：DNS/WHOIS 查询族段首动词——查询键可以是目标域名（网络对端是
// 解析器/WHOIS 服务器而非目标服务），S1 放行。
var s1PassiveQueryVerbs = []string{"dig", "host", "whois", "nslookup"}

// s1ScannerVerbs ③：目标侧探测/扫描动词——即使全局 ClassifyRisk 判 L0（nmap -sV/httpx 在
// defaultReadOnly），S1 一律拒绝：目标侧 HTTP 请求、端口/服务探测均属主动探测（方案⑰口径）。
var s1ScannerVerbRe = regexp.MustCompile(`(?i)(?:^|[|;&]\s*|\$\(\s*)(nmap|masscan|httpx|whatweb|wafw00f|ffuf|gobuster|dirsearch|arjun|nuclei|nikto|subzy|can-i-take-over-xyz|katana|hakrawler|gau|waybackurls)\b`)

// s1ActionGate ③：S1 阶段命令通道硬门（governanceGates 前置）。三重判定：
// ① ClassifyRisk 非 L0 → 拒（S1 仅只读）；
// ② 命令含扫描器动词 → 拒（目标探测不因全局 L0 白名单放行）；
// ③ curl/wget 等出网动词的网络对端必须是被动公开数据源（guard.scope_allowlist/defaultScopeAllowlist），
//    指向项目目标或任何其他主机的 HTTP 请求一律拒。
// dig/host/whois 族不提取查询键——DNS/WHOIS 协议本身不接触目标服务。
func (o *Orchestrator) s1ActionGate(p *store.Project, stageID, command, channel string) string {
	if s1ScannerVerbRe.MatchString(command) {
		msg := "执行被拦截（S1 阶段门）：S1 禁止目标侧探测/扫描（httpx/nmap/whatweb/目录爆破等）——被动域名与网络归属清单见 s1.md；目标侧探测统一在 S2 按 ROE 时间窗与速率约束执行。命令被全局判为 L0 不改变本阶段边界。"
		_, _ = o.store.AddEvidence(&store.EvidenceRecord{ProjectID: p.ID, Stage: stageID,
			Type: "command", Input: truncateText(command, 200), Output: msg,
			Risk: tools.Forbidden, ApprovedBy: "s1-l0-gate"})
		o.log(p, stageID, fmt.Sprintf("⛔ S1 阶段门拦截（%s 通道）：目标探测动词", channel))
		return msg
	}
	if tools.Forbidden != "" && executorClassify(o.exec, command) != tools.L0ReadOnly {
		msg := "执行被拦截（S1 阶段门）：S1 仅允许只读被动查询（L0）；该命令超出 S1 边界，主动探测/写操作请在 S2 及以后按授权与审批执行。"
		_, _ = o.store.AddEvidence(&store.EvidenceRecord{ProjectID: p.ID, Stage: stageID,
			Type: "command", Input: truncateText(command, 200), Output: msg,
			Risk: tools.Forbidden, ApprovedBy: "s1-l0-gate"})
		o.log(p, stageID, fmt.Sprintf("⛔ S1 阶段门拦截（%s 通道）：非 L0 命令", channel))
		return msg
	}
	// 出网 HTTP 动词：对端必须是被动公开数据源
	if o.passiveSourceOnlyBlocked(p, command) {
		msg := "执行被拦截（S1 阶段门）：S1 仅允许被动查询 CT/公开 DNS/WHOIS/ASN/测绘等公开数据源，不连接目标服务——任何发往目标的 HTTP 请求（含单次 GET）属主动探测，S2 起在授权与 ROE 约束下执行。"
		_, _ = o.store.AddEvidence(&store.EvidenceRecord{ProjectID: p.ID, Stage: stageID,
			Type: "command", Input: truncateText(command, 200), Output: msg,
			Risk: tools.Forbidden, ApprovedBy: "s1-l0-gate"})
		o.log(p, stageID, fmt.Sprintf("⛔ S1 阶段门拦截（%s 通道）：HTTP 出网目标非被动源", channel))
		return msg
	}
	return ""
}

// executorClassify 包装 ClassifyRisk（极简测试环境 exec 可能为 nil）。
func executorClassify(e *tools.Executor, command string) string {
	if e == nil {
		return tools.L1Write // nil 保守按 L1（拦截）
	}
	return e.ClassifyRisk(command)
}

// passiveSourceOnlyBlocked ③：命令含 HTTP 出网动词且存在网络对端不在被动源白名单。
func (o *Orchestrator) passiveSourceOnlyBlocked(p *store.Project, command string) bool {
	if !s1HTTPVerbRe.MatchString(command) {
		return false
	}
	passive := o.passiveSourceAllowset()
	for _, m := range urlHostRe.FindAllStringSubmatch(command, -1) {
		if !passive[normalizeS1Host(m[1])] {
			return true
		}
	}
	// 剥除完整 URL（含 query/参数）——查询参数中的域名不是网络对端（crt.sh/?q=example.com 误拦教训）
	stripped := urlFullRe.ReplaceAllString(command, " ")
	for _, m := range bareDomainRe.FindAllStringSubmatch(stripped, -1) {
		// 剩余裸域名 = curl/wget 的直接对端（curl -s example.com 形态）
		if !passive[normalizeS1Host(m[1])] {
			return true
		}
	}
	return false
}

// urlFullRe 完整 URL（scheme→host→path→query）——供「剥 URL 留裸参数」判定用。
var urlFullRe = regexp.MustCompile(`(?i)(?:https?|ftp)://[^\s"'<>]+`)

var s1HTTPVerbRe = regexp.MustCompile(`(?i)(?:^|[|;&]\s*|\$\(\s*)(curl|wget|wget2|httpie|http)\b`)

// passiveSourceAllowset ③：被动源集合 = defaultScopeAllowlist ∪ guard.scope_allowlist ∪ in_scope 资产
// ⚠ 不含项目目标行——目标服务连接即使已授权也属主动探测（S1 禁止）。
func (o *Orchestrator) passiveSourceAllowset() map[string]bool {
	out := map[string]bool{}
	for _, h := range defaultScopeAllowlist {
		out[normalizeS1Host(h)] = true
	}
	if o.cfg != nil {
		for _, h := range o.cfg.Guard.ScopeAllowlist {
			out[normalizeS1Host(h)] = true
		}
	}
	return out
}

// toolDefsForStage ③：阶段感知工具面——S1 隐藏执行/交互/子代理类工具（减少误用面；
// 安全边界由 s1ActionGate 在治理链强制，直调仍拦）。其余阶段维持全量工具面不变。
func (o *Orchestrator) toolDefsForStage(stageID string) []llm.ToolDef {
	defs := o.toolDefs()
	if stageID != "s1" {
		return defs
	}
	hidden := map[string]bool{
		"run_async": true, "run_batch": true, "http_request": true, "cred_command": true,
		"hexstrike_command": true, "install_tool": true,
		"shell_open": true, "shell_write": true, "shell_read": true, "shell_close": true,
		"spawn_subagent": true, "poll_subagents": true,
	}
	out := make([]llm.ToolDef, 0, len(defs))
	for _, d := range defs {
		if hidden[d.Name] {
			continue
		}
		out = append(out, d)
	}
	// S1 追加本阶段专用本地合并器（⑫：纯本地、零网络、确定性）
	out = append(out, llm.ToolDef{Name: "build_s1_subdomain_input",
		Description: "v6.1.0（S1 专用·纯本地零网络）：读取工作区已落盘的 CT/subfinder/DNS 候选文本（evidence/s1-crtsh-subs.txt 等），规范化去重排序生成 evidence/s1-subs-final.txt 与来源 manifest（s1-subs-manifest.json）——子域接管 DNS 指纹脚本的输入必须经此生成；无来源时 manifest 记 not_checked，不静默当作零候选。",
		Parameters:  map[string]any{"type": "object", "properties": map[string]any{}}})
	return out
}

// ---- ⑩ ROE 红线确认 ----

// requestROEAck ⑩：S1 红线复述确认屏障——问题落库（Kind=roe_ack）→ 等待人工回答 →
// 明确 yes 才置位 ROEAcknowledgedAt（时间线+证据留痕）；非 yes/超时不置位。
func (o *Orchestrator) requestROEAck(ctx context.Context, p *store.Project, stageID, question string) string {
	rec := &store.AskRecord{ProjectID: p.ID, Stage: stageID, Kind: "roe_ack",
		Question: truncateText(question, 1500), Status: "pending"}
	id, err := o.store.AddAsk(rec)
	if err != nil {
		return "提问失败: " + err.Error()
	}
	o.bus.Publish(p.ID, "ask", rec)
	o.log(p, stageID, fmt.Sprintf("❓ ROE 红线确认[%s]：%s", id, firstLine(question)))
	answer, err := o.askWaiterBlocking(ctx, id, p.ID, stageID)
	if err != nil {
		return "红线确认失败（" + err.Error() + "）：ROEAcknowledgedAt 未置位，命令通道保持拦截；请重新复述四要素并再次 request_user_input(purpose=roe_ack)。"
	}
	norm := strings.ToLower(strings.TrimSpace(answer))
	affirmative := norm == "yes" || norm == "y" || norm == "是" || norm == "确认" || norm == "同意" || strings.HasPrefix(norm, "yes，") || strings.HasPrefix(norm, "yes,")
	if !affirmative {
		_, _ = o.store.AddTimeline(&store.TimelineEvent{ProjectID: p.ID, Stage: stageID,
			Event: "ROE 红线确认未通过（回答=" + truncateText(strings.TrimSpace(answer), 40) + "）", Detail: "命令通道保持拦截；需重新确认"})
		return "红线确认未通过（回答非 yes）：ROEAcknowledgedAt 未置位，命令通道保持拦截。请与用户澄清后重新 request_user_input(purpose=roe_ack)。"
	}
	now := time.Now().UTC().Format(time.RFC3339)
	p.ROEAcknowledgedAt = now
	if lp := o.liveP[p.ID]; lp != nil {
		lp.ROEAcknowledgedAt = now
	}
	_ = o.store.SaveProject(p)
	_, _ = o.store.AddTimeline(&store.TimelineEvent{ProjectID: p.ID, Stage: stageID,
		Event: "✅ ROE 红线四要素已确认（" + now + "，提问 " + id + "）", Detail: truncateText(question, 200)})
	_, _ = o.store.AddEvidence(&store.EvidenceRecord{ProjectID: p.ID, Stage: stageID,
		Type: "roe-ack", Input: truncateText(question, 200),
		Output: "用户回答 yes（" + now + "）；命令通道放行", Risk: tools.L0ReadOnly, ApprovedBy: "roe-ack"})
	o.log(p, stageID, "✅ ROE 红线确认完成，命令通道放行")
	return "ROE 红线确认完成（" + now + "）：命令通道已放行。"
}

// askWaiterBlocking askUser 的 Kind 化变体（roe_ack：回答原文经内存通道返回）。
func (o *Orchestrator) askWaiterBlocking(ctx context.Context, askID, projectID, stage string) (string, error) {
	var timeoutCh <-chan time.Time
	if o.cfg != nil && o.cfg.Engine.BarrierTimeoutSec > 0 {
		timer := time.NewTimer(time.Duration(o.cfg.Engine.BarrierTimeoutSec) * time.Second)
		defer timer.Stop()
		timeoutCh = timer.C
	}
	ch := o.askWaiter(askID)
	select {
	case ans := <-ch:
		return ans, nil
	case <-ctx.Done():
		o.cancelAsk(askID, "")
		return "", ctx.Err()
	case <-timeoutCh:
		o.cancelAsk(askID, "等待超时")
		return "", fmt.Errorf("等待超时（%d 分钟），已自动取消", o.cfg.Engine.BarrierTimeoutSec/60)
	}
}

// ---- ⑳ 资产类型化台账字段 ----

// assetTypeRequiredFields ⑳：四类非 Web 资产的最小字段集（键必须存在，值可 unknown）。
var assetTypeRequiredFields = map[string][]string{
	"APP":     {"platform", "version", "backend_api"},
	"小程序":   {"platform", "app_id", "version", "backend_api"},
	"云账号":    {"provider", "role", "region"},
	"API":    {"base_url", "auth_type"},
}

// missingAssetTypeFields 返回该资产类型缺失的最小字段（metadata 为 nil 视为全缺）。
// 仅对已知类型生效（域名/IP/服务类无类型化字段要求）。
func missingAssetTypeFields(assetType string, metadata map[string]string) []string {
	req, ok := assetTypeRequiredFields[strings.TrimSpace(assetType)]
	if !ok {
		return nil
	}
	missing := []string{}
	for _, f := range req {
		if metadata == nil {
			missing = append(missing, f)
			continue
		}
		if _, present := metadata[f]; !present {
			missing = append(missing, f)
		}
	}
	return missing
}

// ---- ㉑ 资源目录定位 ----

// ResolveResourceDir ㉑：资源目录解析——空=默认相对路径；相对路径以 config 文件所在目录
// 为基准（换 cwd 启动不再依赖目录布局巧合）；绝对路径直接使用。
func ResolveResourceDir(configPath, configured, fallback string) string {
	p := strings.TrimSpace(configured)
	if p == "" {
		p = fallback
	}
	if filepath.IsAbs(p) {
		return filepath.Clean(p)
	}
	base, err := filepath.Abs(filepath.Dir(configPath))
	if err != nil {
		return p
	}
	return filepath.Join(base, p)
}
