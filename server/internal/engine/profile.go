package engine

// v5.3.1 P0-1：Execution Profile 运行时——逐动作强制校验。
// 此前（v5.3.0）双运行模式只存在于提示词层（loop-core 规则 6）与声明文件
// （policies/execution-profiles.yaml），「引擎/审批强制」承诺为纸面口径；
// 本文件使承诺落地：解析声明文件（单一事实源）+ 编译期模式表（执行层），
// 对每一条进入执行通道的命令做确定性校验。声明层 forbidden 行 ↔ 执行层
// profileRule 一一对应（注释互引），两源漂移由 file_layer_check 锁定。
// 解析器沿用 roe.go 的 YAML 子集惯例（2 空格嵌套/行内注释剥离），零新依赖。

import (
	"fmt"
	"os"
	"regexp"
	"strings"

	"jiutouniao/internal/store"
)

// ExecutionProfiles 对应 policies/execution-profiles.yaml 顶层结构。
type ExecutionProfiles struct {
	Path     string                  `json:"path"`
	Profiles map[string]*ProfileSpec `json:"profiles"` // production_safe / isolated_lab
	Gate     string                  `json:"gate"`     // 校验口径声明行
}

// ProfileSpec 单档声明：allowed/forbidden 为策略语义行（人读），执行由本文件模式表承接（机执）。
type ProfileSpec struct {
	AppliesTo string   `json:"applies_to"`
	Allowed   []string `json:"allowed"`
	Forbidden []string `json:"forbidden"`
	Cleanup   string   `json:"cleanup"`
	Evidence  string   `json:"evidence"`
}

// LoadExecutionProfiles 解析执行档声明文件（YAML 子集）；缺失或非法即报错（fail-fast），
// 与 ROE Profile 同口径：治理单一事实源不可静默降级。
func LoadExecutionProfiles(path string) (*ExecutionProfiles, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	ep := &ExecutionProfiles{Path: path, Profiles: map[string]*ProfileSpec{}}
	// 三层结构：execution_profiles → <profile 名> → 字段（标量或列表）
	var topKey, profileName, field string
	for ln, line := range strings.Split(string(raw), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		if i := strings.Index(trimmed, " #"); i >= 0 { // 行内注释剥离
			trimmed = strings.TrimSpace(trimmed[:i])
		}
		indent := len(line) - len(strings.TrimLeft(line, " "))
		if indent%2 != 0 {
			return nil, fmt.Errorf("execution-profiles 第 %d 行缩进非 2 空格倍数", ln+1)
		}
		switch {
		case strings.HasPrefix(trimmed, "- "):
			val := strings.TrimSpace(trimmed[2:])
			switch {
			case field == "allowed" && profileName != "":
				ep.Profiles[profileName].Allowed = append(ep.Profiles[profileName].Allowed, val)
			case field == "forbidden" && profileName != "":
				ep.Profiles[profileName].Forbidden = append(ep.Profiles[profileName].Forbidden, val)
			default:
				return nil, fmt.Errorf("execution-profiles 第 %d 行列表项无归属字段", ln+1)
			}
		case indent == 0 && strings.HasSuffix(trimmed, ":"):
			topKey = strings.TrimSuffix(trimmed, ":")
			profileName, field = "", ""
		case indent == 0 && strings.Contains(trimmed, ":"):
			kv := strings.SplitN(trimmed, ":", 2) // 顶层标量（gate: ...）
			if kv[0] == "gate" {
				ep.Gate = strings.TrimSpace(kv[1])
			}
		case indent == 2 && topKey == "execution_profiles" && strings.HasSuffix(trimmed, ":"):
			profileName = strings.TrimSuffix(trimmed, ":")
			ep.Profiles[profileName] = &ProfileSpec{}
			field = ""
		case indent == 4 && profileName != "":
			kv := strings.SplitN(trimmed, ":", 2)
			if len(kv) != 2 {
				return nil, fmt.Errorf("execution-profiles 第 %d 行字段非法", ln+1)
			}
			field = strings.TrimSpace(kv[0])
			val := strings.TrimSpace(kv[1])
			switch field {
			case "applies_to":
				ep.Profiles[profileName].AppliesTo = val
			case "cleanup":
				ep.Profiles[profileName].Cleanup = val
			case "evidence":
				ep.Profiles[profileName].Evidence = val
			case "allowed", "forbidden":
				// 紧随的列表项（- 开头）归属此字段
			default:
				return nil, fmt.Errorf("execution-profiles 第 %d 行未知字段 %q", ln+1, field)
			}
		default:
			return nil, fmt.Errorf("execution-profiles 第 %d 行结构非法", ln+1)
		}
	}
	if err := ep.validate(); err != nil {
		return nil, err
	}
	return ep, nil
}

// validate 结构校验：两档齐备、allowed/forbidden 非空。
func (ep *ExecutionProfiles) validate() error {
	for _, name := range []string{ProfileProductionSafe, ProfileIsolatedLab} {
		p, ok := ep.Profiles[name]
		if !ok {
			return fmt.Errorf("execution-profiles 缺少 %s 档", name)
		}
		if len(p.Forbidden) == 0 {
			return fmt.Errorf("execution-profiles %s 档 forbidden 为空", name)
		}
		if len(p.Allowed) == 0 {
			return fmt.Errorf("execution-profiles %s 档 allowed 为空", name)
		}
	}
	return nil
}

// ---- 执行层模式表（声明层 forbidden 行 ↔ 规则一一对照）----

// profileRule 单条确定性规则；and 非空时须同命令同时命中（RE2 无环视，用双正则合取表达组合语义）。
type profileRule struct {
	name string // 对应 execution-profiles.yaml forbidden 语义行（注释引原文）
	re   *regexp.Regexp
	and  *regexp.Regexp // 可选第二条件
	// v5.4.3 C：skipIfReadOnly=true 的规则为「状态关键词 + 泛用 flag」合取类——只读命令在语义上
	// 不可能造成状态变更，文本巧合命中（引号内独立词、payload 目录名子串等）应豁免。
	// 仅标注确属该类的规则；SQL 写/HTTP DELETE/导出类规则不豁免（拦截能力零放松）。
	skipIfReadOnly bool
}

// productionSafeForbidden 对应 execution-profiles.yaml production_safe.forbidden 五行：
// ①植入 webshell/内存马/持久化/隧道/新增账号 ②上传可执行文件 ③批量导出业务数据/凭据
// ④修改/删除/覆盖目标数据（含自建行——登记移交）⑤真实订单/支付/短信状态变更。
var productionSafeForbidden = []profileRule{
	// ①a webshell/内存马植入（写入/提交形态；纯读不匹配）
	{name: "植入 webshell/内存马", re: regexp.MustCompile(`(?i)(webshell|memshell|内存马|behinder|godzilla|antsword|蚁剑|冰蝎|哥斯拉|webeditor|jspspy|shell\.(jsp|asp|aspx|php))`),
		and: regexp.MustCompile(`(?i)(>|>>|tee\s|cp\s|mv\s|touch\s|echo\s|--data|-F\s|upload|\bput\b|-T\s|\bwrite\b)`)},
	{name: "植入 webshell（PHP 后门特征）", re: regexp.MustCompile(`(?i)(eval|assert)\s*\(\s*\$_(POST|GET|REQUEST)`),
		and: regexp.MustCompile(`(?i)(>|>>|echo\s|tee\s|--data|-F\s|upload)`)},
	// ①b 持久化植入（写启动项/计划任务/SSH 后门；crontab -l 纯读不匹配）
	{name: "持久化植入（启动项/计划任务写入）", re: regexp.MustCompile(`(?i)(>>|>|tee\s|cp\s|mv\s|touch\s|chattr\s)\s*\S*(crontab|rc\.local|rc\.common|\.bashrc|\.zshrc|\.profile|authorized_keys|sudoers|systemd|/etc/init|/var/spool/cron|schtasks)`)},
	{name: "持久化植入（crontab/服务注册）", re: regexp.MustCompile(`(?i)crontab\s+-(e|r|u)|systemctl\s+enable|chkconfig\s+--add|schtasks\s+/create|reg\s+add\s`)},
	// ①c 隧道/代理驻留
	{name: "隧道/代理驻留", re: regexp.MustCompile(`(?i)\bfrp[cs]?\b|\bnps\b|\bnpc\b|\bchisel\b|\bregeorg\b|\bligolo\b|\bvenom\b|\biox\b|\bstowaway\b|\btunna\b|earthworm|ew\.py|\bssh\b[^|]*\s-[DLR]\b|端口转发|端口映射|socks[45]?\s*(代理|隧道)`)},
	// ①d 新增账号（目标侧）
	{name: "新增账号", re: regexp.MustCompile(`(?i)\b(useradd|adduser|usermod|chpasswd)\b|net\s+(user|localgroup)\s+\S+\s+\S+\s+/add|create\s+user\b|grant\s+\S+\s+on\s+\S+\s+to\s|insert\s+into\s+\S*(user|admin|member)s?\b|(>|>>|tee\s)\s*\S*/etc/(passwd|shadow)`)},
	// ②上传可执行文件（向目标主机；工作区写入不匹配）
	{name: "上传可执行文件", re: regexp.MustCompile(`(?i)curl\s[^|]*(\s-T\s|--upload-file)|(^|\s)scp\s+\S+\s+\S+@|wget\s+--post-file|curl\s[^|]*--data-binary\s+@\S+\.(exe|dll|so|bin|jsp|war|jar|sh|py|ps1|bat|php|asp|aspx)`)},
	// ③批量导出业务数据/凭据
	{name: "批量导出业务数据/凭据", re: regexp.MustCompile(`(?i)mysqldump|sqlmap[^|]*--dump|--dump-all|into\s+(out|dump)file|\bbcp\s|bulk\s+insert|select\s+\*.{0,60}\blimit\s+\d{3,}|hashdump|secretsdump|mimikatz|ntds\.dit|/etc/shadow\b|credential\s+dump`)},
	// ④修改/删除/覆盖目标数据（SQL 写 + HTTP DELETE；生产档一律拦截，登记移交）。
	// SQL 动词后要求「标识符+分隔符」避免包管理器误伤（apt update && / dnf update vim 等不含 SQL 语义）。
	{name: "修改/删除目标数据（SQL 写）", re: regexp.MustCompile(`(?i)\b(update|insert\s+into|delete\s+from|drop\s+(table|database)|truncate\s+table|alter\s+table|merge\s+into)\s+[a-z_]\w*\s*(\s|\(|=|;|,)`)},
	{name: "修改/删除目标数据（HTTP DELETE）", re: regexp.MustCompile(`(?i)curl\s[^|]*(-X\s*DELETE|-XDELETE|--request\s+DELETE)`)},
	// ⑤真实订单/支付/短信状态变更（状态关键词 + 提交动作合取）。
	// v5.4.3 C：关键词全部词边界锚定——原 `pay` 无边界子串曾命中 "payloads" 导致纯只读
	// 工具预检命令连坐被拦（实证）；CJK 词无子串歧义不变。skipIfReadOnly：只读命令豁免。
	{name: "真实订单/支付/短信状态变更", re: regexp.MustCompile(`(?i)(\bpay\b|\bpayment\b|\border\b|\bcheckout\b|\brefund\b|\bsms\b|\botp\b|verify_code|sendmsg|下单|支付|退款|发货|改价)`),
		and: regexp.MustCompile(`(?i)(--data|-d\s|-F\s|-X\s*POST|--request\s+POST)`), skipIfReadOnly: true},
}

// isolatedLabForbidden 对应 execution-profiles.yaml isolated_lab.forbidden 两行：
// ①向公网分发测试产物 ②接触生产数据。受控写操作不在档内拦截（走风险分级+审批链，
// isolated_lab 以 ROE write_policy 与快照回滚为回收保障——P0-4 统一高影响限制后仍保留此差异）。
var isolatedLabForbidden = []profileRule{
	{name: "向公网分发测试产物", re: regexp.MustCompile(`(?i)(pastebin|anonfiles|transfer\.sh|file\.io|0x0\.st|gofile|catbox|termbin|dpaste|oshi\.at|temp\.sh|bashupload|网盘)`),
		and: regexp.MustCompile(`(?i)(\s-T\s|--upload-file|--data-binary|--data|-d\s|-F\s|(^|\s)scp\s|wget\s+--post-file|\bput\b)`)},
	{name: "接触生产数据", re: regexp.MustCompile(`(?i)(生产库|生产数据|生产环境|prod[-_](db|mysql|api|server)\b|production[-_](db|api)\b)`)},
}

// labOnlySkillIds v5.3.1：高危技能 Lab Only 策展清单（production_safe 下 load_skill 注入禁用横幅）。
// v5.3.2 P1-2 起由 skills/manifest.json lab_only 标注驱动（本清单保留为兜底并集）。
var labOnlySkillIds = map[string]bool{
	"persistence": true, "webshell-memshell": true, "upload-bypass": true,
	"logic-csrf-deser": true, "database-postex": true, "tunnel-pivot": true,
	"cve-weaponization": true, "crypto-offensive": true, "hypothesis-0day": true,
}

const (
	ProfileProductionSafe = "production_safe"
	ProfileIsolatedLab    = "isolated_lab"
)

// ValidProfiles 合法执行档集合（web/API 层校验用）。
func ValidProfiles() []string { return []string{ProfileProductionSafe, ProfileIsolatedLab} }

// profileOf 项目生效档：空/未知一律归 production_safe（缺省收紧，unknown 不放行）。
func (o *Orchestrator) profileOf(p *store.Project) string {
	prof := strings.ToLower(strings.TrimSpace(p.ExecutionProfile))
	if prof != ProfileProductionSafe && prof != ProfileIsolatedLab {
		return ProfileProductionSafe
	}
	return prof
}

// profileHit 单条命中档案（v5.4.3 C：拦截消息可解释性——执行主体需要知道命中了什么才能自纠）。
type profileHit struct {
	Rule  string // 规则名
	Match string // 命中的命令文本片段（re 侧匹配，截断展示）
}

// profileViolations 命中的违禁规则档案列表（声明层↔执行层对照输出，供阻断文案引用）。
// readOnly=true（命令经只读判定）时跳过 skipIfReadOnly 类「状态变更合取」规则。
func profileViolations(profile, command string, readOnly bool) []profileHit {
	var rules []profileRule
	switch profile {
	case ProfileIsolatedLab:
		rules = isolatedLabForbidden
	default:
		rules = productionSafeForbidden
	}
	var hits []profileHit
	for _, r := range rules {
		if r.skipIfReadOnly && readOnly {
			continue // 只读命令不可能造成状态变更——文本巧合命中豁免（v5.4.3 C）
		}
		m := r.re.FindString(command)
		if m == "" {
			continue // RE2 合取：re 侧命中才有意义（and 侧由合取语义另行保证）
		}
		if r.and != nil && !r.and.MatchString(command) {
			continue
		}
		hits = append(hits, profileHit{Rule: r.name, Match: truncateRunesText(m, 60)})
	}
	return hits
}

// truncateRunesText rune 安全截断（profile 包内复用）。
func truncateRunesText(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "…"
}

// profileGate 逐动作强制校验：返回阻断文案（空串放行）。isolated_lab 不在档内拦截受控写，
// 其风险分级与审批照常生效（生产与实验室共用同一门入口——P0-4 统一高影响限制）。
// v5.4.3 C：只读命令豁免状态变更合取类规则；拦截消息附命中细节（可解释拒绝）。
func (o *Orchestrator) profileGate(p *store.Project, command string) (bool, string) {
	prof := o.profileOf(p)
	readOnly := false
	if o.exec != nil {
		readOnly = o.exec.ReadOnlySafe(command)
	}
	hits := profileViolations(prof, command, readOnly)
	if len(hits) == 0 {
		return false, ""
	}
	names := make([]string, 0, len(hits))
	matches := make([]string, 0, len(hits))
	for _, h := range hits {
		names = append(names, h.Rule)
		matches = append(matches, "\""+h.Match+"\"")
	}
	if prof == ProfileProductionSafe {
		return true, fmt.Sprintf("Execution Profile=production_safe：违禁动作[%s]已被逐动作强制拦截（v5.3.1）——命中文本: %s。"+
			"生产口径只允许存在性证明（无害回显/随机标记/受控 OOB）；如确属可快照回滚的隔离靶场，"+
			"请在项目设置将执行档显式切换为 isolated_lab 后重试；若本命令混合了合法动作与被禁动作，请拆分后单独重试合法部分。",
			strings.Join(names, "、"), strings.Join(matches, "、"))
	}
	return true, fmt.Sprintf("Execution Profile=isolated_lab：违禁动作[%s]已被拦截——命中文本: %s。"+
		"隔离靶场内仍禁止向公网分发测试产物与接触生产数据；请改用合规方式取证。", strings.Join(names, "、"), strings.Join(matches, "、"))
}

// labOnlyBannerText Lab Only 禁用横幅文案（production_safe 口径）。
func labOnlyBannerText() string {
	return "\n\n⛔【Execution Profile 提示】上述技能含 Lab Only 高危动作（植入/持久化/清理类）。当前项目为 production_safe 模式：这些动作已被引擎逐动作强制禁止（v5.3.1），只允许存在性证明与无害验证；相关工件的处置一律登记移交《需人工清理清单》。"
}

// labOnlyBanner production_safe 下 load_skill 对 Lab Only 技能注入禁用横幅（v5.3.1 逐动作强制的知识面配套）。
// v5.3.2 P1-1：以 manifest lab_only 标注为准（SkillRegistry.LabOnly），策展清单保留为降级兜底。
func (o *Orchestrator) labOnlyBanner(p *store.Project, skillID string) string {
	if o.profileOf(p) == ProfileProductionSafe && o.skills.LabOnly(skillID) {
		return labOnlyBannerText()
	}
	return ""
}
