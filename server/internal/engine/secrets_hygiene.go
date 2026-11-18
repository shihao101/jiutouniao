// v5.6.0 秘密卫生设施（审计修复：三个明文泄露旁路的统一收口）：
//   - streamTool 写入前对工具参数做 JSON 感知脱敏、对结果做模式脱敏——
//     审计实证：store_credential 的 secret 参数原本会绕过加密仓库明文落执行流（高危）；
//   - 敏感 HTTP 头集合：请求/响应证据与审批文本统一按头名脱敏——
//     审计实证：此前仅掩码 Authorization/Cookie 两种头，Set-Cookie（新会话）等原样入证据；
//   - 正则模式脱敏兜底内联凭据（Authorization:/Bearer/Cookie:/token= 等），
//     覆盖模型把凭据直接写进 command/write_file 参数的情形。
//
// 纪律：脱敏只作用于"持久化与展示层"（执行流/证据/审批文本）；模型看到的实时工具结果
// 仍由各工具自行控制（http_request 已对注入密钥回显脱敏）。
package engine

import (
	"encoding/json"
	"regexp"
	"strings"

	"jiutouniao/internal/credentials"
)

// sensitiveArgKeyFrag 敏感参数键片段（小写包含匹配；JSON 感知脱敏用）。
var sensitiveArgKeyFrag = []string{
	"secret", "password", "passwd", "pwd", "token", "cookie", "authorization",
	"auth", "api_key", "apikey", "credential", "session",
}

// sensitiveHeaderNames 敏感 HTTP 头（小写精确集合；证据/审批文本按头名脱敏）。
var sensitiveHeaderNames = map[string]bool{
	"authorization": true, "proxy-authorization": true, "cookie": true, "set-cookie": true,
	"x-api-key": true, "x-apikey": true, "api-key": true, "apikey": true,
	"x-auth-token": true, "x-access-token": true, "access-token": true, "auth-token": true,
	"x-csrf-token": true, "csrf-token": true, "x-xsrf-token": true, "xsrf-token": true,
	"x-session-token": true, "session-token": true, "x-amz-security-token": true,
	"jwt": true, "x-jwt": true, "x-forwarded-access-token": true,
}

// SensitiveHeaderName 判断头名是否承载凭据（证据/审批文本脱敏入口）。
func SensitiveHeaderName(name string) bool {
	return sensitiveHeaderNames[strings.ToLower(strings.TrimSpace(name))]
}

// 敏感模式（对任意文本兜底）：头名=值 / Bearer 令牌 / key=value 形态。
// 值字符集排除 `*`——已掩码值（含 ***）不再被二次匹配（幂等）。
var (
	reAuthHeaderLine = regexp.MustCompile(`(?i)((?:authorization|proxy-authorization|cookie)\s*[:=]\s*)([^"*;&,\s]{8,})`)
	reBearerToken    = regexp.MustCompile(`(?i)(bearer\s+)([A-Za-z0-9\-._~+/=]{16,})`)
	reKeyValSecret   = regexp.MustCompile(`(?i)((?:api[-_]?key|apikey|access[-_]?token|refresh[-_]?token|session[-_]?token|auth[-_]?token|client[-_]?secret|private[-_]?token|secret|token)["']?\s*[:=]\s*["']?)([^"*;&,\s]{8,})`)
)

// maskSensitiveText 对自由文本做模式脱敏（工具结果/命令参数值兜底）。
func maskSensitiveText(s string) string {
	if s == "" {
		return s
	}
	s = reAuthHeaderLine.ReplaceAllStringFunc(s, func(m string) string {
		loc := reAuthHeaderLine.FindStringSubmatchIndex(m)
		if len(loc) < 6 {
			return m
		}
		return m[:loc[2]] + credentials.Mask(m[loc[4]:loc[5]])
	})
	s = reBearerToken.ReplaceAllStringFunc(s, func(m string) string {
		loc := reBearerToken.FindStringSubmatchIndex(m)
		if len(loc) < 6 {
			return m
		}
		return m[:loc[2]] + credentials.Mask(m[loc[4]:loc[5]])
	})
	s = reKeyValSecret.ReplaceAllStringFunc(s, func(m string) string {
		loc := reKeyValSecret.FindStringSubmatchIndex(m)
		if len(loc) < 6 {
			return m
		}
		return m[:loc[2]] + credentials.Mask(m[loc[4]:loc[5]])
	})
	return s
}

// maskSensitiveHeaderValue 按头名脱敏单个头值（请求/响应证据、审批文本用）。
func maskSensitiveHeaderValue(name, value string) string {
	if SensitiveHeaderName(name) {
		return credentials.Mask(value)
	}
	return maskSensitiveText(value)
}

// maskToolArgsJSON JSON 感知的工具参数脱敏（streamTool 持久化前调用）：
//   - 命中敏感键的字符串值整体掩码（secret/password/token/cookie/auth…）；
//   - 其余字符串值做模式兜底脱敏（覆盖 command/content 内联凭据）；
//   - 非法 JSON 退化为纯文本模式脱敏（不阻断留痕）。
func maskToolArgsJSON(args string) string {
	if args == "" {
		return args
	}
	var obj any
	if err := json.Unmarshal([]byte(args), &obj); err != nil {
		return maskSensitiveText(args)
	}
	maskWalk(obj, 0)
	out, err := json.Marshal(obj)
	if err != nil {
		return maskSensitiveText(args)
	}
	return string(out)
}

func maskWalk(v any, depth int) {
	if depth > 6 {
		return
	}
	switch t := v.(type) {
	case map[string]any:
		for k, vv := range t {
			lk := strings.ToLower(k)
			sensitive := false
			for _, frag := range sensitiveArgKeyFrag {
				if strings.Contains(lk, frag) {
					sensitive = true
					break
				}
			}
			switch sv := vv.(type) {
			case string:
				if sensitive && sv != "" {
					t[k] = credentials.Mask(sv)
				} else {
					t[k] = maskSensitiveText(sv)
				}
			default:
				maskWalk(vv, depth+1)
			}
		}
	case []any:
		for _, item := range t {
			maskWalk(item, depth+1)
		}
	}
}
