// v5.5.0 凭据仓库引擎工具面（docs/repair-plan-capability-20261118.md 方案 A）：
//   - store_credential / list_credentials / revoke_credential：结构化凭据管理（静态加密，全程掩码）；
//   - http_request：结构化 HTTP 请求工具，auth_ref 注入 Authorization/Cookie——有凭证深度测试
//     （authz-diff/api-idor 角色矩阵）从"手册级步骤"变为"引擎可执行"；
//   - cred_command：显式占位符命令模板（${CRED_USERNAME}/${CRED_SECRET} 等），密文经工作区
//     临时文件中介（0600，执行后即删），命令文本/审批/证据/日志全程无明文。
//
// 纪律（与方案一致）：
//   - 明文只在解密后的短生命周期内存出现；一切日志/证据/回执只输出掩码；
//   - 注入不改变治理语义：http_request/cred_command 与 run_command 同样经过
//     governanceGates（执行档/注册写/范围门）→ 风险分级 → 审批 → 留证；
//   - 交互式 shell / run_async 不做自动注入（方案明确排除）。
package engine

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"jiutouniao/internal/credentials"
	"jiutouniao/internal/store"
	"jiutouniao/internal/tools"
)

// credToolsEnabled 凭据工具可用性（未配置主密钥时 fail closed）。
func (o *Orchestrator) credToolsEnabled() bool {
	return o.creds != nil && o.creds.Enabled()
}

// activeCredentialMetas 项目全部 active 凭据掩码投影（仓库未启用返回空）。
func (o *Orchestrator) activeCredentialMetas(p *store.Project) []credentials.CredentialMeta {
	if !o.credToolsEnabled() {
		return nil
	}
	metas, err := o.creds.List(p.ID)
	if err != nil {
		return nil
	}
	out := make([]credentials.CredentialMeta, 0, len(metas))
	for _, m := range metas {
		if m.Status == "active" {
			out = append(out, m)
		}
	}
	return out
}

// hasActiveCredentials 凭据仓库是否存在 active 记录（v5.6.0 状态机判据之一）。
func (o *Orchestrator) hasActiveCredentials(p *store.Project) bool {
	return len(o.activeCredentialMetas(p)) > 0
}

// projectHasIdentity v5.6.0 统一身份判据：旧 AuthInfo 字段 ∪ 凭据仓库 active ∪ verified Loot。
// W4/S4 状态机一律走本函数（审计修复：store_credential 入库后不再被当 S0）。
func (o *Orchestrator) projectHasIdentity(p *store.Project) bool {
	return strings.TrimSpace(p.AuthInfo) != "" || o.hasActiveCredentials(p) || o.sessionObtained(p)
}

// credentialStateBlock v5.6.0 凭证状态三态上下文（审计④-13：阶段头按 S1-S8 编排，缺少
// S0/S1/S2 差异化——引擎级统一注入，覆盖全部阶段头）。返回带标题的上下文块。
func (o *Orchestrator) credentialStateBlock(p *store.Project) string {
	metas := o.activeCredentialMetas(p)
	var b strings.Builder
	b.WriteString("### 凭证状态三态（v5.6.0 引擎注入——所有阶段按当前状态执行）\n")
	// v5.6.1（审计缺陷#1）：S0 判据与 W4 的 projectHasIdentity 统一——verified Loot
	// 算「已持身份」，不再出现 W4 跳过六轨而三态块仍要求 S0 六轨的矛盾指令。
	if !o.projectHasIdentity(p) {
		// S0 无凭证
		b.WriteString("- **当前状态 S0（无凭证）**：最大化匿名面测试（anon-attack-surface 全清单）+ 按六轨编排身份获取（identity-bootstrapping）；发现登录面必须登记资产。\n")
		b.WriteString("- 用户**主动提供**凭据时经 request_credential 专用通道接收入库（原文不落明文；v5.9.0：智能体不主动发起询问）；伪造尝试（JWT/签名/会话构造）是 S0 轨道的一部分，成功即 store_credential 入库（origin=forged）。\n")
		b.WriteString("- 全轨未命中且用户未提供 → 按 observable-degradation 四通道降级移交，不静默跳过认证面。\n\n")
		return b.String()
	}
	// S1（含 S2 子状态：存在伪造/派生凭据时追加伪造轨指令）
	realN, forgedN := 0, 0
	ids := make([]string, 0, len(metas))
	for _, m := range metas {
		ids = append(ids, m.Identity+"("+m.Origin+"/"+m.Kind+")")
		if m.Origin == "forged" || m.Origin == "derived" {
			forgedN++
		} else {
			realN++
		}
	}
	if len(metas) == 0 {
		// 身份来自 verified Loot 或旧 AuthInfo（未入仓库）——引导入库以便矩阵编排
		b.WriteString("- **当前状态 S1（持有身份，来源：verified Loot / 旧 AuthInfo，未入凭据仓库）**：建议 store_credential 入库（identity 命名区分角色）以便 authz-diff/api-idor 矩阵逐身份编排与来源谱系登记。\n")
	} else {
		b.WriteString(fmt.Sprintf("- **当前状态 S1（持有身份）**：active 凭据 %d 条——%s（旧 AuthInfo 亦视为身份来源）。所有带态测试统一走 http_request auth_ref / cred_command；逐身份显式引用（多会话同名时必须 cred-<id>）。\n", len(metas), truncateText(strings.Join(ids, ", "), 220)))
	}
	if strings.TrimSpace(p.AuthInfo) != "" {
		b.WriteString("- ⚠ 旧 AuthInfo 字段含认证信息（legacy）：测试时直接引用其内容；建议将其中的会话经 store_credential 入库以便矩阵编排。\n")
	}
	b.WriteString("- 带态测试纪律：角色/越权矩阵逐身份执行并逐行记账（authz-diff v5.5.0 节）；伪造变体（JWT none/alg 混淆、claim 改值、cookie 变体）逐一尝试，产物 store_credential origin=forged method=<手法> 登记谱系。\n")
	if forgedN > 0 {
		b.WriteString(fmt.Sprintf("- **当前状态叠加 S2 伪造轨**：%d 条伪造/派生凭据在库——伪造身份与真实身份分开记账，伪造成功的越权效果按 authz-diff/api-idor 矩阵完整测试；伪造失败记录变体+失败原因+恢复条件（record_vt deferred 或 coverage needs_follow_up）。\n", forgedN))
	}
	b.WriteString("- 凭据 Target 与请求 host 绑定：跨 host 使用会被引擎拒绝；如确需复用请按新 target 另录。\n\n")
	return b.String()
}

// resolveCredential 按 ref 解析凭据：支持 "cred-<id>" 直取，或 "identity:<身份名>" 取该身份
// 的 active 凭据（角色矩阵场景按身份引用更自然）。
// v5.6.0：返回记录本身（供 Target-host 绑定与来源谱系）；同名身份存在多条 active 时
// 显式拒绝（审计缺陷#8：按更新时间静默取最新可能选错会话——强制 cred-<id> 消歧）。
func (o *Orchestrator) resolveCredential(p *store.Project, ref string) (string, *credentials.Secret, *store.CredentialRecord, error) {
	if !o.credToolsEnabled() {
		return "", nil, nil, fmt.Errorf("凭据仓库未启用：请设置 CREDENTIALS_MASTER_KEY（32 字节 hex/base64）后重启引擎")
	}
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return "", nil, nil, fmt.Errorf("credential_ref 为空")
	}
	if strings.HasPrefix(ref, "cred-") {
		rec, err := o.store.GetCredential(p.ID, ref)
		if err != nil {
			return "", nil, nil, err
		}
		sec, gerr := o.creds.Get(p.ID, ref)
		if gerr != nil {
			return "", nil, nil, gerr
		}
		return ref, sec, rec, nil
	}
	if strings.HasPrefix(ref, "identity:") {
		ident := strings.TrimSpace(strings.TrimPrefix(ref, "identity:"))
		raws, lerr := o.store.ListCredentials(p.ID)
		if lerr != nil {
			return "", nil, nil, lerr
		}
		sort.Slice(raws, func(i, j int) bool { return raws[i].UpdatedAt.After(raws[j].UpdatedAt) })
		var matches []*store.CredentialRecord
		for _, r := range raws {
			if r.Identity == ident && r.Status == "active" {
				matches = append(matches, r)
			}
		}
		if len(matches) == 0 {
			return "", nil, nil, fmt.Errorf("未找到身份 %q 的 active 凭据（list_credentials 可查）", ident)
		}
		if len(matches) > 1 {
			ids := make([]string, 0, len(matches))
			for _, m := range matches {
				ids = append(ids, m.ID)
			}
			return "", nil, nil, fmt.Errorf("身份 %q 有 %d 条 active 凭据（%s）——同名多会话必须用 cred-<id> 显式引用，禁止 identity: 隐式选择", ident, len(matches), strings.Join(ids, ", "))
		}
		r := matches[0]
		sec, gerr := o.creds.Get(p.ID, r.ID)
		if gerr != nil {
			return "", nil, nil, gerr
		}
		return r.ID, sec, r, nil
	}
	return "", nil, nil, fmt.Errorf("credential_ref 格式非法（应为 cred-<id> 或 identity:<身份名>）")
}

// toolRequestCredential v5.6.0 凭据专用接收通道（request_credential，审计修复高危#1）：
// 接收用户主动提供的凭据 → 回答原文只经内存通道 → 直接入加密仓库 → AskRecord/工具回执只含掩码。
// v5.9.0 口径：智能体不主动发起索取。
// 全链路明文不落任何持久化介质（对照普通 request_user_input：答案会明文落 AskRecord）。
func (o *Orchestrator) toolRequestCredential(ctx context.Context, p *store.Project, stageID string, args map[string]any) string {
	get := func(k string) string { v, _ := args[k].(string); return strings.TrimSpace(v) }
	question := get("question")
	identity := get("identity")
	kind := strings.ToLower(get("kind"))
	target := get("target")
	role := get("role")
	usernameHint := get("username")
	origin := strings.ToLower(get("origin"))
	if question == "" || identity == "" || kind == "" {
		return "错误: question/identity/kind 必填（question 说明索取原因与粘贴格式）"
	}
	switch kind {
	case "bearer", "basic", "cookie", "header", "token":
	default:
		return "错误: kind 仅支持 bearer/basic/cookie/header/token"
	}
	if !o.credToolsEnabled() {
		return "错误: 凭据仓库未启用（需设置 CREDENTIALS_MASTER_KEY 后重启引擎），无法安全接收凭据——请用户改用带外方式提供，不得粘贴到普通对话。"
	}
	if origin == "" {
		origin = "real"
	}
	switch origin {
	case "real", "forged", "derived":
	default:
		return "错误: origin 仅支持 real/forged/derived"
	}

	pasteHint := "直接粘贴凭据原文（一行）"
	if kind == "basic" {
		pasteHint = "一行 `用户名:口令`（basic 凭据）"
	} else if kind == "header" {
		pasteHint = "一行 `头名: 头值`（完整认证头）"
	}
	q := fmt.Sprintf("%s\n\n[粘贴格式] %s；回答原文经专用通道加密入库，界面与日志只显示掩码。", question, pasteHint)
	askID, answer, err := o.askUserCredential(ctx, p.ID, stageID, q)
	if err != nil {
		o.saveCredentialAskSummary(askID, "（未入库："+truncateText(err.Error(), 120)+"）")
		return "凭据索取失败: " + err.Error()
	}
	secret := strings.TrimSpace(answer)
	secret = strings.Trim(secret, "\"'` ")
	if secret == "" {
		o.saveCredentialAskSummary(askID, "（未入库：回答为空）")
		return "错误: 用户回答为空，未入库。"
	}
	uname := usernameHint
	if kind == "basic" {
		if i := strings.IndexByte(secret, ':'); i > 0 {
			uname, secret = secret[:i], strings.TrimSpace(secret[i+1:])
		}
	}
	meta, perr := o.creds.Put(credentials.Input{
		ProjectID: p.ID, Target: target, Identity: identity, Role: role,
		Kind: kind, Username: uname, Secret: secret, Origin: origin,
	})
	if perr != nil {
		o.saveCredentialAskSummary(askID, "（未入库："+truncateText(perr.Error(), 120)+"）")
		return "错误: 凭据入库失败（原文已丢弃，不落任何存储）: " + perr.Error()
	}
	summary := fmt.Sprintf("已入库凭据 %s（identity=%s kind=%s 掩码=%s origin=%s）", meta.ID, meta.Identity, meta.Kind, meta.Username, meta.Origin)
	o.saveCredentialAskSummary(askID, summary)
	o.log(p, stageID, fmt.Sprintf("🔐 用户凭据经专用通道入库 %s（全程无明文落库）", meta.ID))
	o.SendInput(p.ID, fmt.Sprintf("⚠ 凭证状态变更：用户提供的凭据 %s（identity=%s）已加密入库——后续带态测试切换 http_request auth_ref=%s；本阶段剩余工作按三态新口径执行", meta.ID, meta.Identity, meta.ID))
	return fmt.Sprintf("凭据已安全入库: id=%s identity=%s kind=%s target=%s username=%s origin=%s\n"+
		"后续：http_request 的 auth_ref 传 %s；cred_command 的 credential_ref 传 %s。\n"+
		"纪律：本回执与所有日志只含掩码；禁止在 record_finding/时间线/交付物/普通 request_user_input 中复写凭据原文。",
		meta.ID, meta.Identity, meta.Kind, meta.Target, meta.Username, meta.Origin, meta.ID, meta.ID)
}

// toolStoreCredential 录入凭据（store_credential）。
func (o *Orchestrator) toolStoreCredential(p *store.Project, stageID string, args map[string]any) string {
	get := func(k string) string { v, _ := args[k].(string); return strings.TrimSpace(v) }
	if !o.credToolsEnabled() {
		return "错误: 凭据仓库未启用（需设置环境变量 CREDENTIALS_MASTER_KEY 后重启引擎）。用户主动提供凭据时请配置主密钥后用 request_credential 通道接收，不得粘贴到普通对话。"
	}
	origin := strings.ToLower(get("origin"))
	if origin == "" {
		origin = "real"
	}
	switch origin {
	case "real", "forged", "derived":
	default:
		return "错误: origin 仅支持 real/forged/derived（real=客户提供真实凭据 / forged=伪造构造 / derived=由真实凭据推导）"
	}
	in := credentials.Input{
		ProjectID:    p.ID,
		Target:       get("target"),
		Identity:     get("identity"),
		Role:         get("role"),
		Kind:         strings.ToLower(get("kind")),
		Username:     get("username"),
		Secret:       get("secret"),
		SourceLootID: get("source_loot_id"),
		Origin:       origin,
		ParentID:     get("parent_id"),
		Method:       get("method"),
	}
	meta, err := o.creds.Put(in)
	if err != nil {
		return "错误: " + err.Error()
	}
	_, _ = o.store.AddTimeline(&store.TimelineEvent{ProjectID: p.ID, Stage: stageID,
		Event: "凭据入库（v5.6.0 来源谱系）",
		Detail: fmt.Sprintf("cred=%s identity=%s kind=%s target=%s origin=%s method=%s parent=%s（掩码 %s；明文已 AES-256-GCM 静态加密，日志/证据不落明文）",
			meta.ID, meta.Identity, meta.Kind, meta.Target, meta.Origin, in.Method, in.ParentID, meta.Username)})
	o.log(p, stageID, fmt.Sprintf("🔐 凭据 %s 已入库（identity=%s kind=%s origin=%s 掩码=%s）", meta.ID, meta.Identity, meta.Kind, meta.Origin, meta.Username))
	// v5.6.1（审计缺陷#5）：阶段中途入库 → 注入状态变更提示（下一轮进入消息链），
	// 三态口径在当前阶段内即时生效，不再依赖模型从工具回执自行推断。
	o.SendInput(p.ID, fmt.Sprintf("⚠ 凭证状态变更：凭据 %s（identity=%s origin=%s）已入库——后续带态测试切换 http_request auth_ref=%s / cred_command credential_ref=%s；本阶段剩余工作按三态新口径执行（S2 伪造凭据须进角色矩阵）", meta.ID, meta.Identity, meta.Origin, meta.ID, meta.ID))
	// v5.6.1（审计 RunB#25）：伪造/派生凭据入库 → 引擎自动登记矩阵编排 VT（引擎级调度钩子）
	if meta.Origin == "forged" || meta.Origin == "derived" {
		_, _ = o.store.AddVT(&store.VerificationTask{ProjectID: p.ID, Stage: stageID,
			Title:       fmt.Sprintf("[S2-矩阵] 对 %s 凭据 %s（%s）执行 authz-diff/api-idor 角色矩阵", meta.Origin, meta.ID, meta.Method),
			ReadyAssets: meta.ID, StartConditions: "凭据已在仓库；矩阵逐身份显式引用", Priority: 2, Status: "ready"})
		o.SendInput(p.ID, fmt.Sprintf("🧾 已自动登记矩阵编排 VT：[S2-矩阵] 对 %s 凭据 %s 执行角色矩阵——record_vt 列表可查，S5 按就绪资产投递", meta.Origin, meta.ID))
	}
	return fmt.Sprintf("凭据已安全入库: id=%s identity=%s kind=%s target=%s username=%s origin=%s status=active\n"+
		"后续使用：%s 的 auth_ref 传 %s；或 cred_command 的 credential_ref 传 %s。\n"+
		"纪律：本工具回执与证据只含掩码；不要在 record_finding/时间线/交付物中书写明文凭据。", meta.ID, meta.Identity, meta.Kind, meta.Target, meta.Username, meta.Origin, "http_request", meta.ID, meta.ID)
}

// toolListCredentials 凭据清单（list_credentials，掩码投影）。
func (o *Orchestrator) toolListCredentials(p *store.Project) string {
	if !o.credToolsEnabled() {
		return "凭据仓库未启用（未配置 CREDENTIALS_MASTER_KEY）。"
	}
	metas, err := o.creds.List(p.ID)
	if err != nil {
		return "错误: " + err.Error()
	}
	if len(metas) == 0 {
		return "本项目暂无入库凭据。可经 store_credential 录入（明文静态加密），或继续无凭证测试。"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "共 %d 条凭据（掩码投影，明文不可检索）：\n", len(metas))
	for _, m := range metas {
		fmt.Fprintf(&b, "- %s | identity=%s role=%s kind=%s target=%s username=%s status=%s\n",
			m.ID, m.Identity, m.Role, m.Kind, m.Target, m.Username, m.Status)
	}
	b.WriteString("注入方式：http_request auth_ref=cred-<id>（或 identity:<身份名>）；命令模板用 cred_command。")
	return b.String()
}

// toolRevokeCredential 撤销凭据（revoke_credential）。
func (o *Orchestrator) toolRevokeCredential(p *store.Project, stageID string, args map[string]any) string {
	if !o.credToolsEnabled() {
		return "凭据仓库未启用。"
	}
	id, _ := args["id"].(string)
	if strings.TrimSpace(id) == "" {
		return "错误: id 为空"
	}
	if err := o.creds.Revoke(p.ID, strings.TrimSpace(id)); err != nil {
		return "错误: " + err.Error()
	}
	o.log(p, stageID, "🔐 凭据已撤销: "+id+"（后续 resolve/注入将直接拒绝）")
	return "凭据 " + id + " 已 revoke，后续注入直接拒绝。"
}

// maskAll 把 secret 值与其掩码应用到文本（证据/回执脱敏）。
func maskAll(text, secret string) string {
	if secret == "" {
		return text
	}
	m := credentials.Mask(secret)
	text = strings.ReplaceAll(text, secret, m)
	return text
}

// toolHTTPRequest 结构化 HTTP 请求（http_request）：auth_ref 注入 + 全量治理留证。
// 治理语义：以等价 curl 命令文本过 governanceGates（执行档/注册写/范围门），
// 风险分级 GET/HEAD/OPTIONS=L0、其余=L1（写语义），审批流与 run_command 同级。
func (o *Orchestrator) toolHTTPRequest(ctx context.Context, p *store.Project, stageID string, args map[string]any) string {
	get := func(k string) string { v, _ := args[k].(string); return strings.TrimSpace(v) }
	urlStr := get("url")
	method := strings.ToUpper(get("method"))
	if method == "" {
		method = "GET"
	}
	if urlStr == "" {
		return "错误: url 为空"
	}
	if !strings.HasPrefix(urlStr, "http://") && !strings.HasPrefix(urlStr, "https://") {
		return "错误: url 仅支持 http/https"
	}
	body := get("body")
	authRef := get("auth_ref")

	// 1) 解析凭据（在治理门前完成——引用不存在应立即失败，不产生审批工单）
	var sec *credentials.Secret
	var credRec *store.CredentialRecord
	credID := ""
	if authRef != "" {
		id, s, rec, err := o.resolveCredential(p, authRef)
		if err != nil {
			return "错误: " + err.Error()
		}
		credID, sec, credRec = id, s, rec
		// v5.6.0（审计缺陷#4）：凭据 Target 与请求 host 绑定——Target 记录了归属目标时，
		// 禁止把该凭据带到其它 host（strict_scope 管范围不管归属）。
		if h := credTargetHost(credRec.Target); h != "" {
			if u, perr := url.Parse(urlStr); perr == nil && !strings.EqualFold(u.Hostname(), h) {
				return fmt.Sprintf("错误: 凭据 %s 的归属目标 %s 与请求 host %s 不匹配——禁止跨 host 使用凭据（如确需复用请另录 target 匹配的凭据）", credID, h, u.Hostname())
			}
		}
	}

	// 2) 等价 curl 命令文本（供范围门/执行档/审批/留证；凭据在引擎侧注入不出现在命令里，
	//    v5.6.0：headers 中的敏感头值也按头名脱敏——审计高危#3）
	var curlParts []string
	curlParts = append(curlParts, "curl", "-sS", "-X", method, "'"+strings.ReplaceAll(urlStr, "'", "'\\''")+"'")
	for k, v := range asStringMap(args["headers"]) {
		curlParts = append(curlParts, "-H", fmt.Sprintf("'%s: %s'", strings.ReplaceAll(k, "'", ""), strings.ReplaceAll(maskSensitiveHeaderValue(k, v), "'", "'\\''")))
	}
	if credID != "" {
		curlParts = append(curlParts, "-H", fmt.Sprintf("'X-JT-Cred-Ref: %s'", credID))
	}
	if body != "" {
		curlParts = append(curlParts, "--data-raw", fmt.Sprintf("'<%d 字节请求体，见证据>'", len(body)))
	}
	curlEquiv := strings.Join(curlParts, " ")

	// 3) 治理门（与 run_command 全同：执行档/注册写/范围，阻断在审批前并留证）
	if msg := o.governanceGates(p, stageID, curlEquiv, "http_request", false); msg != "" {
		return msg
	}
	// 4) 风险分级：读方法 L0；写方法至少 L1
	risk := o.exec.ClassifyRisk(curlEquiv)
	if risk == tools.L0ReadOnly && method != "GET" && method != "HEAD" && method != "OPTIONS" {
		risk = tools.L1Write
	}
	if risk == tools.Forbidden {
		return "拒绝执行：该请求命中破坏性操作禁令。"
	}
	approvedBy := "auto"
	decision, err := o.approver.Request(ctx, p.ID, stageID,
		fmt.Sprintf("HTTP %s %s\n%s", method, urlStr, truncateText(curlEquiv, 300)), risk)
	if err != nil {
		return "审批异常: " + err.Error()
	}
	if decision != "approved" && decision != "auto-approved" {
		_, _ = o.store.AddEvidence(&store.EvidenceRecord{ProjectID: p.ID, Stage: stageID, Type: "http_request",
			Input: curlEquiv, Output: "人工拒绝", Risk: risk, ApprovedBy: "human-rejected"})
		return "人工审批拒绝该请求。请说明替代方案或收口本阶段。"
	}
	if decision == "approved" {
		approvedBy = "human"
		o.log(p, stageID, "✔ 人工批准 HTTP 请求: "+method+" "+truncateText(urlStr, 100))
	}

	// 5) 构造请求（凭据注入；secret 仅存在于本函数内存）
	timeoutSec := 30
	if t := get("timeout"); t != "" {
		if n, perr := strconv.Atoi(t); perr == nil && n > 0 && n <= 300 {
			timeoutSec = n
		}
	}
	var reqBody io.Reader
	if body != "" {
		reqBody = strings.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, urlStr, reqBody)
	if err != nil {
		return "错误: 构造请求失败: " + err.Error()
	}
	for k, v := range asStringMap(args["headers"]) {
		req.Header.Set(k, v)
	}
	if req.Header.Get("User-Agent") == "" {
		req.Header.Set("User-Agent", "jiutouniao/5.5")
	}
	if body != "" && req.Header.Get("Content-Type") == "" {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	authDesc := ""
	if sec != nil {
		k := ""
		if credRec != nil {
			k = credRec.Kind
		}
		authDesc = applyAuthHeader(req, k, sec)
	}

	// 6) 执行
	client := &http.Client{Timeout: time.Duration(timeoutSec) * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return fmt.Errorf("停止重定向（超过 5 跳）")
			}
			// v5.6.1（审计 RunB#13）：凭据绑定 host 时逐跳校验——重定向离开归属 host
			// 即中止（Go 默认会转发 Authorization/Cookie 到同域跳转，跨域=凭据外带）。
			if credRec != nil {
				if h := credTargetHost(credRec.Target); h != "" && req.URL != nil {
					if !strings.EqualFold(req.URL.Hostname(), h) {
						return fmt.Errorf("重定向离开凭据归属 host（%s → %s）：已中止（防止带态凭据外带）", h, req.URL.Hostname())
					}
				}
			}
			return nil
		}}
	start := time.Now()
	resp, err := client.Do(req)
	dur := time.Since(start).Milliseconds()
	if err != nil {
		_, _ = o.store.AddEvidence(&store.EvidenceRecord{ProjectID: p.ID, Stage: stageID, Type: "http_request",
			Input: curlEquiv, Output: "请求失败: " + err.Error(), Risk: risk, ApprovedBy: approvedBy, DurationMs: dur})
		return fmt.Sprintf("HTTP 请求失败（%dms）: %v", dur, err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 2*1024*1024))
	respBody := string(raw)
	if sec != nil { // 响应回显令牌时同步脱敏
		respBody = maskAll(respBody, sec.Value)
		// v5.6.1（审计 RunB#10）：kind=header 的 sec.Value 是完整 "Name: value"——
		// 响应常只回显值本身，把值部分单独掩码（名/值两种形态都覆盖）。
		if o.credsKindOf(p, credID) == "header" {
			if i := strings.IndexByte(sec.Value, ':'); i >= 0 {
				respBody = maskAll(respBody, strings.TrimSpace(sec.Value[i+1:]))
			}
		}
		if sec.Username != "" {
			respBody = maskAll(respBody, sec.Username)
		}
	}
	// 溢出落盘（与 run_command 同纪律）
	if o.cfg.Engine.SpillBytes > 0 && len(respBody) > o.cfg.Engine.SpillBytes {
		rel := fmt.Sprintf(".tool-output/http-%d.txt", time.Now().UnixNano())
		if _, werr := o.exec.WriteFile(p.ID, rel, respBody); werr == nil {
			respBody = tools.TruncateSmart(respBody, 8*1024) + fmt.Sprintf("\n📦 响应体已溢出落盘: %s（read_file/grep 取片段）", rel)
		}
	}
	// 7) 留证（v5.6.0 审计高危#3：请求/响应头全部按敏感头名脱敏——含 Set-Cookie 新会话）
	var reqDump strings.Builder
	fmt.Fprintf(&reqDump, "%s %s HTTP/1.1\n", method, urlStr)
	for k, v := range req.Header {
		val := strings.Join(v, ", ")
		fmt.Fprintf(&reqDump, "%s: %s\n", k, maskSensitiveHeaderValue(k, val))
	}
	if body != "" {
		fmt.Fprintf(&reqDump, "\n[%d 字节请求体，原文见执行流]", len(body))
	}
	var hdrDump strings.Builder
	for k, v := range resp.Header {
		val := strings.Join(v, ", ")
		fmt.Fprintf(&hdrDump, "%s: %s\n", k, maskSensitiveHeaderValue(k, val))
	}
	evidenceOut := fmt.Sprintf("HTTP/%d.%d %s\n%s\n--- body ---\n%s", resp.ProtoMajor, resp.ProtoMinor, resp.Status, hdrDump.String(), truncateText(respBody, 2000))
	_, _ = o.store.AddEvidence(&store.EvidenceRecord{ProjectID: p.ID, Stage: stageID, Type: "http_request",
		Input: reqDump.String(), Output: truncateText(evidenceOut, 2000), Risk: risk, ApprovedBy: approvedBy, DurationMs: dur})
	o.log(p, stageID, fmt.Sprintf("🌐 HTTP %s %s → %s（%dms, auth=%s）", method, truncateText(urlStr, 80), resp.Status, dur, authDesc))
	return fmt.Sprintf("HTTP %s %s → %s（%dms）\n认证: %s\n响应头:\n%s\n--- body（前 8KB，超限见溢出文件）---\n%s",
		method, urlStr, resp.Status, dur, authDesc, truncateText(hdrDump.String(), 800), respBody)
}

// credTargetHost 从凭据 Target 提取可比对的 hostname（无 scheme/host 语义时返回空 = 不绑定）。
// 支持形态：http://host[:port]、host[:port]、域名字面量；纯账号名/描述性文本不绑定。
func credTargetHost(target string) string {
	t := strings.TrimSpace(target)
	if t == "" {
		return ""
	}
	hadScheme := false
	if i := strings.Index(t, "://"); i >= 0 {
		t = t[i+3:]
		hadScheme = true
	}
	if i := strings.IndexAny(t, "/?#"); i >= 0 {
		t = t[:i]
	}
	if i := strings.LastIndex(t, "@"); i >= 0 { // user@host 形态取 host 段
		t = t[i+1:]
	}
	if i := strings.IndexByte(t, ':'); i >= 0 { // 去端口
		t = t[:i]
	}
	t = strings.TrimSpace(t)
	if t == "" {
		return ""
	}
	// v5.6.1（审计 RunB#14）：带 scheme（http://localhost 等）的单标签主机同样绑定；
	// 仅在无 scheme 且无点（大概率账号名/别名）时不绑定。
	if !strings.Contains(t, ".") && !hadScheme {
		return ""
	}
	return strings.ToLower(t)
}

// credsKindOf 查询凭据 kind（掩码投影外的一次元数据读取，不含明文）。
func (o *Orchestrator) credsKindOf(p *store.Project, credID string) string {
	if credID == "" {
		return ""
	}
	rec, err := o.store.GetCredential(p.ID, credID)
	if err != nil {
		return ""
	}
	return rec.Kind
}

// applyAuthHeader 按 kind 注入认证头；返回描述（掩码）。
func applyAuthHeader(req *http.Request, kind string, sec *credentials.Secret) string {
	switch kind {
	case "bearer", "token", "":
		req.Header.Set("Authorization", "Bearer "+sec.Value)
		return "Authorization: Bearer " + credentials.Mask(sec.Value)
	case "basic":
		req.SetBasicAuth(sec.Username, sec.Value)
		return "Authorization: Basic (" + credentials.Mask(sec.Username) + "/***)"
	case "cookie":
		req.Header.Set("Cookie", sec.Value)
		return "Cookie: " + credentials.Mask(sec.Value)
	case "header":
		// secret 为完整 "Name: value" 形式
		i := strings.IndexByte(sec.Value, ':')
		if i <= 0 {
			req.Header.Set("Authorization", "Bearer "+sec.Value)
			return "Authorization: Bearer " + credentials.Mask(sec.Value)
		}
		name := strings.TrimSpace(sec.Value[:i])
		val := strings.TrimSpace(sec.Value[i+1:])
		req.Header.Set(name, val)
		return name + ": " + credentials.Mask(val)
	}
	req.Header.Set("Authorization", "Bearer "+sec.Value)
	return "Authorization: Bearer " + credentials.Mask(sec.Value)
}

// toolCredCommand 显式占位符命令模板执行（cred_command）：密文经临时文件中介。
// ${CRED_USERNAME}/${CRED_SECRET}/${CRED_TOKEN}/${CRED_PASSWORD} 在命令文本中被替换为
// 无明文形态（用户名 shell 转义、密值 "$(cat .jtn-cred/<rand>)"），执行后临时文件即删——
// 审批文本/证据/日志/模型回执全程不含明文；治理与审批与 run_command 完全同级。
func (o *Orchestrator) toolCredCommand(ctx context.Context, p *store.Project, stageID string, args map[string]any) string {
	get := func(k string) string { v, _ := args[k].(string); return strings.TrimSpace(v) }
	tmpl := get("template")
	ref := get("credential_ref")
	reason := get("reason")
	if tmpl == "" {
		return "错误: template 为空"
	}
	if !strings.Contains(tmpl, "${CRED_") {
		return "错误: template 未包含 ${CRED_*} 占位符——本工具专用于带凭据命令；普通命令请直接 run_command。"
	}
	if verr := validateCredTemplate(tmpl); verr != nil {
		return "错误: " + verr.Error()
	}
	credID, sec, _, err := o.resolveCredential(p, ref)
	if err != nil {
		return "错误: " + err.Error()
	}
	// 临时文件中介：写工作区（0600），命令文本引用 $(cat …)，执行完立即删除。
	rel := fmt.Sprintf(".jtn-cred/%d", time.Now().UnixNano())
	dir := filepath.Join(o.workspaceRoot(p.ID), ".jtn-cred")
	if mkErr := os.MkdirAll(dir, 0o700); mkErr != nil {
		return "错误: 凭据临时目录创建失败: " + mkErr.Error()
	}
	// v5.6.1（审计 RunB#12）：崩溃残留清扫——顺带删除超过 1 小时的陈旧凭据临时文件
	//（defer os.Remove 只覆盖正常路径；进程崩溃时明文文件会残留，此处兜底）。
	if ents, rerr := os.ReadDir(dir); rerr == nil {
		cutoff := time.Now().Add(-time.Hour)
		for _, e := range ents {
			if !e.IsDir() {
				if info, ierr := e.Info(); ierr == nil && info.ModTime().Before(cutoff) {
					_ = os.Remove(filepath.Join(dir, e.Name()))
				}
			}
		}
	}
	abs := filepath.Join(o.workspaceRoot(p.ID), rel)
	if wErr := os.WriteFile(abs, []byte(sec.Value), 0o600); wErr != nil {
		return "错误: 凭据临时文件写入失败: " + wErr.Error()
	}
	defer func() { _ = os.Remove(abs) }() // 无论成败执行后即删（明文不驻留）
	username := sec.Username
	if username == "" {
		username = "unk"
	}
	cmd := expandCredTemplate(tmpl, rel, username)
	o.log(p, stageID, fmt.Sprintf("🔐 cred_command（凭据 %s 临时文件中介，命令文本无明文）", credID))
	return o.toolRunCommand(ctx, p, stageID, cmd, reason+"（cred_command 经凭据 "+credID+" 注入，密文走临时文件，证据无明文）")
}

// credPlaceholders 凭据占位符全集（校验与展开共用）。
var credPlaceholders = []string{"${CRED_USERNAME}", "${CRED_SECRET}", "${CRED_TOKEN}", "${CRED_PASSWORD}"}

// validateCredTemplate 确定性校验：占位符不得位于「含其他内容的单引号串」内部——
// 单引号内的命令替换/变量引用在 shell 中不生效，任何文本替换都无法安全处理该形态
// （fail closed 拒绝并指路，而非产出静默错误命令）。允许两种安全形态：
// 整段单引号（'${CRED_SECRET}'，替换含引号 token）与裸占位符（替换值自带安全引号）。
func validateCredTemplate(tmpl string) error {
	for i := 0; i < len(tmpl); i++ {
		if tmpl[i] != '\'' {
			continue
		}
		j := strings.IndexByte(tmpl[i+1:], '\'')
		if j < 0 {
			break
		}
		span := tmpl[i+1 : i+1+j]
		for _, ph := range credPlaceholders {
			if idx := strings.Index(span, ph); idx >= 0 && len(span) != len(ph) {
				return fmt.Errorf("占位符 %s 位于含其他内容的单引号串内（…%s…）——单引号内命令替换不生效；请去掉外层单引号改用裸占位符（引擎替换值自带安全引号），或将占位符独立成整段引号", ph, truncateText(span, 60))
			}
		}
		i += 1 + j
	}
	return nil
}

// expandCredTemplate 占位符展开（纯函数便于单测；前置条件：validateCredTemplate 通过）：
//   - '${CRED_SECRET}' 整段单引号形式 → 替换整个引号 token 为 "$(cat <rel>)"（双引号保证命令替换生效）；
//   - 裸 ${CRED_SECRET} → "$(cat <rel>)"（自带双引号，防 shell 分词/特殊字符）；
//   - ${CRED_USERNAME}（含单引号包裹形式）→ shell 转义后的用户名字面量。
//     任何形态替换后命令文本都不含明文（明文只在运行时由 shell 从 0600 临时文件读取）。
func expandCredTemplate(tmpl, rel, username string) string {
	quotedUser := "'" + strings.ReplaceAll(username, "'", "'\\''") + "'"
	secretCmd := fmt.Sprintf(`"$(cat %s)"`, rel)
	out := tmpl
	// 用户名：先处理整段引号形态（引号并入替换，避免双重引号），再处理裸形态
	out = strings.ReplaceAll(out, "'${CRED_USERNAME}'", quotedUser)
	out = strings.ReplaceAll(out, "${CRED_USERNAME}", quotedUser)
	// 密值：单引号包裹形态先替换整段引号 token（否则 $(cat …) 落在单引号内不展开），再裸形态
	for _, ph := range credPlaceholders[1:] {
		out = strings.ReplaceAll(out, "'"+ph+"'", secretCmd)
		out = strings.ReplaceAll(out, ph, secretCmd)
	}
	return out
}

// asStringMap 宽松地把 args 中的 map[string]any 转为 map[string]string。
func asStringMap(v any) map[string]string {
	m, ok := v.(map[string]any)
	if !ok {
		return nil
	}
	out := make(map[string]string, len(m))
	for k, vv := range m {
		if s, ok := vv.(string); ok {
			out[k] = s
		}
	}
	return out
}
