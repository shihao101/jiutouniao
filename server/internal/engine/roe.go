package engine

// v4.6 T3/H 批次：ROE Profile 引擎消费（治理参数化落地）。
// 依据《优化方案_黑盒无凭证高危挖掘能力最大化_v4.6能力主版》§3：
// 合规/边界/预算从设计约束降为运行时参数——引擎加载 profile、校验、把运行时含义注入上下文包。
// 口径：profile 只参数化「许可」，不参数化「取证与清退纪律」（诚实性/清理铁律不受影响）。

import (
	"fmt"
	"os"
	"regexp"
	"strings"
)

type ROEProfile struct {
	Path   string
	Values map[string]string // 扁平化（如 write_policy / waf_policy.offline_challenge / identity.cred_attack.dict_size）
}

var roeLeafSchema = map[string]*regexp.Regexp{
	"write_policy":      regexp.MustCompile(`^(full|existence-proof)$`),
	"expansion":         regexp.MustCompile(`^(auto|auto-with-approval|deny)$`),
	"windows":           regexp.MustCompile(`^none$|^\{.*\}$`),
	"offline_challenge": regexp.MustCompile(`^(allow|deny)$`),
	"rotation":          regexp.MustCompile(`^(unlimited|capped:\d+)$`),
	"max_conn_per_s":    regexp.MustCompile(`^\d+$`),
	"cooldown_protocol": regexp.MustCompile(`^(full-silence|canary-exp)$`),
	"auto_register":     regexp.MustCompile(`^(allow|deny)$`),
	"dict_size":         regexp.MustCompile(`^\d+$`),
	"lockout_aware":     regexp.MustCompile(`^(true|false)$`),
	"residential_proxy": regexp.MustCompile(`^(allow|deny)$`),
	"oob_callback":      regexp.MustCompile(`^(allow|deny)$`),
}

var roeRequired = []string{"profile", "write_policy", "scope", "waf_policy", "identity", "outbound"}

// LoadROEProfile 解析 YAML 子集（2 空格嵌套 / 行内注释剥离），校验 schema；非法即报错（fail-fast）。
func LoadROEProfile(path string) (*ROEProfile, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	p := &ROEProfile{Path: path, Values: map[string]string{}}
	stack := []int{}
	// v5.1.2 P1 修复：两层嵌套键扁平化——原实现单游标 lastSection 被嵌套节头覆盖，
	// identity.cred_attack.dict_size 被错挂为 cred_attack.dict_size（Digest 永远取不到、静默丢失且校验通过）。
	// 改为前缀栈随缩进出栈，任意层级嵌套均正确。
	prefix := []string{}
	sections := map[string]bool{}
	for ln, line := range strings.Split(string(raw), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		indent := len(line) - len(strings.TrimLeft(line, " "))
		if indent%2 != 0 {
			return nil, fmt.Errorf("roe profile 第 %d 行缩进非 2 空格倍数", ln)
		}
		for len(stack) > 0 && stack[len(stack)-1] >= indent {
			stack = stack[:len(stack)-1]
			if len(prefix) > 0 {
				prefix = prefix[:len(prefix)-1]
			}
		}
		m := regexp.MustCompile(`^([\w_]+):\s*(.*)$`).FindStringSubmatch(trimmed)
		if m == nil {
			return nil, fmt.Errorf("roe profile 第 %d 行非法语法: %s", ln, trimmed)
		}
		key, val := m[1], strings.TrimSpace(m[2])
		val = strings.Trim(val, `"'`)
		if val == "" {
			sections[key] = true
			prefix = append(prefix, key)
			stack = append(stack, indent)
			continue
		}
		val = regexp.MustCompile(`\s+#.*$`).ReplaceAllString(val, "")
		if re, ok := roeLeafSchema[key]; ok && !re.MatchString(val) {
			return nil, fmt.Errorf("roe profile 第 %d 行 %s=%s 不合法", ln, key, val)
		}
		if len(prefix) == 0 {
			p.Values[key] = val
		} else {
			p.Values[strings.Join(prefix, ".")+"."+key] = val
		}
	}
	for _, r := range roeRequired {
		if !sections[r] && p.Values[r] == "" {
			return nil, fmt.Errorf("roe profile 缺少必填节: %s", r)
		}
	}
	return p, nil
}

// WritePolicy 返回写策略（默认 existence-proof，与引擎护栏既有口径一致）。
func (r *ROEProfile) WritePolicy() string {
	if r == nil || r.Values["write_policy"] == "" {
		return "existence-proof"
	}
	return r.Values["write_policy"]
}

// Digest 生成上下文包注入的运行时含义摘要（不含原文，含引擎行为影响）。
func (r *ROEProfile) Digest() string {
	if r == nil {
		return ""
	}
	wp := r.WritePolicy()
	wpNote := "写操作仅做存在性证明（截图/计数/哈希摘要），禁止业务数据修改"
	if wp == "full" {
		wpNote = "写操作允许（靶场/评测口径——仍受清理铁律与取证纪律约束）"
	}
	lines := []string{
		fmt.Sprintf("- profile=%s", r.Values["profile"]),
		fmt.Sprintf("- write_policy=%s → %s", wp, wpNote),
	}
	if v, ok := r.Values["windows"]; ok && v != "none" {
		lines = append(lines, "- 测试时间窗："+v+"——窗口外禁止任何主动流量（含登录请求）")
	} else {
		lines = append(lines, "- 测试时间窗：无限制")
	}
	if v, ok := r.Values["waf_policy.offline_challenge"]; ok {
		lines = append(lines, "- 瑞数类离线挑战实现："+map[string]string{"allow": "允许（ROE 已覆盖）", "deny": "禁止（未授权意图，改走对策阶梯上级）"}[v])
	}
	if v, ok := r.Values["outbound.residential_proxy"]; ok {
		lines = append(lines, "- 住宅代理出口："+map[string]string{"allow": "允许（出口轮换可用）", "deny": "禁止（单出口策略）"}[v])
	}
	if v, ok := r.Values["identity.cred_attack.dict_size"]; ok {
		lines = append(lines, "- 弱口令字典上限："+v+"（配合锁定感知，weak-cred-bruteforce 口径）")
	}
	if v, ok := r.Values["identity.auto_register"]; ok {
		lines = append(lines, "- identity.auto_register="+v+" → "+map[string]string{
			"deny":  "注册面只评估不注册（身份向客户索取，identity-bootstrapping 一a节）",
			"allow": "可自建测试账号（唯一标记+S7 清理登记）",
		}[v])
	}
	return strings.Join(lines, "\n")
}
