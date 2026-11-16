package web

// v5.0.0 批1 代理模块 + 批2 设备连接启用按钮（Web 界面直达能力）。
//
// 代理模块（用户想法①）：
//   - 三类流量分级：工具下载代理（TOOL_PROXY 热生效，沿用「智能体按需 env 前缀」纪律，不全局改道）；
//     目标流量出口池（v4.8 W5 exit-pool.py 消费，exits 落盘 dataDir/exit-pool.json + JT_EXIT_POOL 注入，
//     默认关闭——目标流量默认直连口径不变，项目级显式启用）；LLM 出口跟随部署环境变量（只读展示）。
//   - 支持常见代理：http/https/socks5（含 user:pass@host:port 认证），端点加密存储、UI 掩码回显。
//
// 设备连接启用按钮（用户想法②）：
//   - POST /api/devices/action 动作注册表——7 种连接场景中可命令化的动作在此收口：参数严格校验、
//     exec.Command 直执行（无 shell、带超时）、审计日志；长驻进程（frida-server/mitmdump）仍由
//     智能体 run_async 执行（本接口不做长驻）；USB 直通（场景5）安全口径保持禁用不提供动作。

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"jiutouniao/internal/crypto"
)

// ---------- 代理模块 ----------

type proxyExit struct {
	Name        string `json:"name"`
	Kind        string `json:"kind"` // http / https / socks5
	EndpointEnc string `json:"endpoint_enc"`
}

type proxySettings struct {
	ToolProxyEnc  string      `json:"tool_proxy_enc"`
	TargetEnabled bool        `json:"target_enabled"`
	Exits         []proxyExit `json:"exits"`
}

type setProxyReq struct {
	ToolProxy     string             `json:"tool_proxy"`
	TargetEnabled *bool              `json:"target_enabled"`
	Exits         []proxyExitReqBody `json:"exits"`
}

type proxyExitReqBody struct {
	Name     string `json:"name"`
	Kind     string `json:"kind"`
	Endpoint string `json:"endpoint"`
}

var validProxyKind = map[string]bool{"http": true, "https": true, "socks5": true}

var hostPortRe = regexp.MustCompile(`^[a-zA-Z0-9._-]{1,253}:[0-9]{1,5}$`)

// validateProxyEndpoint 校验 endpoint：允许 scheme://[user:pass@]host:port 或裸 host:port（kind 补 scheme）。
func validateProxyEndpoint(kind, endpoint string) (string, error) {
	if !validProxyKind[kind] {
		return "", fmt.Errorf("kind 仅支持 http/https/socks5")
	}
	endpoint = strings.TrimSpace(endpoint)
	if endpoint == "" {
		return "", fmt.Errorf("endpoint 为空")
	}
	if !strings.Contains(endpoint, "://") {
		endpoint = kind + "://" + endpoint
	}
	u, err := url.Parse(endpoint)
	if err != nil {
		return "", fmt.Errorf("endpoint 格式非法: %v", err)
	}
	if u.Host == "" || !hostPortRe.MatchString(u.Host) {
		return "", fmt.Errorf("endpoint 需为 host:port 形态（%s）", u.Host)
	}
	port, _ := strconv.Atoi(u.Port())
	if port < 1 || port > 65535 {
		return "", fmt.Errorf("端口超出范围")
	}
	return endpoint, nil
}

// maskProxyEndpoint 掩码回显：保留 scheme 与 host:port，凭据段替换为 ***。
func maskProxyEndpoint(endpoint string) string {
	u, err := url.Parse(endpoint)
	if err != nil || u.User == nil {
		return endpoint
	}
	host := u.Host
	if _, portSet := u.User.Password(); portSet || u.User.Username() != "" {
		host = "***@" + u.Host
	}
	return u.Scheme + "://" + host
}

func (s *Server) loadProxySettings() proxySettings {
	var ps proxySettings
	if raw, ok := s.st.GetSetting("proxy"); ok {
		_ = json.Unmarshal(raw, &ps)
	}
	return ps
}

// rebuildCommandEnv 合并重建注入命令的环境（测绘 Key + 代理变量）。
// 口径：只注入变量供智能体按需引用（$TOOL_PROXY / $JT_EXIT_POOL），不注入全局
// HTTP_PROXY——对目标流量默认直连的纪律不变（v4.8 W5 出口池由智能体显式调用）。
func (s *Server) rebuildCommandEnv() {
	env := map[string]string{}
	// 测绘 Key（与 main.go 启动恢复同源逻辑）
	if raw, ok := s.st.GetSetting("recon"); ok {
		var rs struct {
			ShodanKeyEnc string `json:"shodan_enc"`
			FofaEmail    string `json:"fofa_email"`
			FofaKeyEnc   string `json:"fofa_key_enc"`
			QuakeKeyEnc  string `json:"quake_enc"`
			ZoomEyeEnc   string `json:"zoomeye_enc"`
		}
		if json.Unmarshal(raw, &rs) == nil {
			if k, e := crypto.Decrypt(s.encKey(), rs.ShodanKeyEnc); e == nil && k != "" {
				env["SHODAN_API_KEY"] = k
			}
			if rs.FofaEmail != "" {
				env["FOFA_EMAIL"] = rs.FofaEmail
			}
			if k, e := crypto.Decrypt(s.encKey(), rs.FofaKeyEnc); e == nil && k != "" {
				env["FOFA_KEY"] = k
			}
			if k, e := crypto.Decrypt(s.encKey(), rs.QuakeKeyEnc); e == nil && k != "" {
				env["QUAKE_KEY"] = k
			}
			if k, e := crypto.Decrypt(s.encKey(), rs.ZoomEyeEnc); e == nil && k != "" {
				env["ZOOMEYE_KEY"] = k
			}
		}
	}
	// 代理变量
	ps := s.loadProxySettings()
	if tp, e := crypto.Decrypt(s.encKey(), ps.ToolProxyEnc); e == nil && strings.TrimSpace(tp) != "" {
		env["TOOL_PROXY"] = strings.TrimSpace(tp)
	}
	if ps.TargetEnabled && len(ps.Exits) > 0 {
		path := s.writeExitPoolFile(ps)
		if path != "" {
			env["JT_EXIT_POOL"] = path
		}
	}
	s.orch.Exec().SetExtraEnv(env)
	names := make([]string, 0, len(env))
	for k := range env {
		names = append(names, k)
	}
	log.Printf("[settings] 命令环境已重建（%d 项）: %v", len(env), names)
}

// writeExitPoolFile 出口池配置落盘（exit-pool.py --config 消费；dataDir 运行数据不随分发包走）。
func (s *Server) writeExitPoolFile(ps proxySettings) string {
	type exitRow struct {
		Name     string `json:"name"`
		Kind     string `json:"kind"`
		Endpoint string `json:"endpoint"`
	}
	rows := make([]exitRow, 0, len(ps.Exits))
	for _, x := range ps.Exits {
		ep, e := crypto.Decrypt(s.encKey(), x.EndpointEnc)
		if e != nil || strings.TrimSpace(ep) == "" {
			continue
		}
		rows = append(rows, exitRow{Name: x.Name, Kind: x.Kind, Endpoint: strings.TrimSpace(ep)})
	}
	if len(rows) == 0 {
		return ""
	}
	raw, _ := json.Marshal(map[string]any{"exits": rows})
	path := filepath.Join(s.cfg.DataDir, "exit-pool.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		log.Printf("[proxy] exits 落盘失败: %v", err)
		return ""
	}
	return path
}

func (s *Server) handleProxyGet(w http.ResponseWriter, _ *http.Request) {
	ps := s.loadProxySettings()
	tpMasked := ""
	if tp, e := crypto.Decrypt(s.encKey(), ps.ToolProxyEnc); e == nil && tp != "" {
		tpMasked = maskProxyEndpoint(tp)
	}
	exits := make([]map[string]any, 0, len(ps.Exits))
	for _, x := range ps.Exits {
		ep, e := crypto.Decrypt(s.encKey(), x.EndpointEnc)
		masked := ""
		if e == nil {
			masked = maskProxyEndpoint(ep)
		}
		exits = append(exits, map[string]any{"name": x.Name, "kind": x.Kind, "endpoint_masked": masked})
	}
	llmProxy := strings.TrimSpace(os.Getenv("LLM_PROXY"))
	if llmProxy == "" {
		llmProxy = strings.TrimSpace(os.Getenv("HTTP_PROXY"))
	}
	writeJSON(w, 200, map[string]any{
		"tool_proxy_masked": tpMasked,
		"target_enabled":    ps.TargetEnabled,
		"exits":             exits,
		"llm_proxy_env":     llmProxy,
		"llm_proxy_note":    "LLM 出口跟随部署环境变量（compose LLM_PROXY），此处只读展示",
	})
}

func (s *Server) handleProxySave(w http.ResponseWriter, r *http.Request) {
	var req setProxyReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, 400, err)
		return
	}
	ps := s.loadProxySettings()
	keep := func(oldEnc, nv string) (string, error) {
		if strings.TrimSpace(nv) == "" {
			return oldEnc, nil // 留空保持不变（与测绘 Key 同口径）
		}
		return crypto.Encrypt(s.encKey(), strings.TrimSpace(nv))
	}
	var err error
	if ps.ToolProxyEnc, err = keep(ps.ToolProxyEnc, req.ToolProxy); err != nil {
		writeErr(w, 500, err)
		return
	}
	if req.TargetEnabled != nil {
		ps.TargetEnabled = *req.TargetEnabled
	}
	if req.Exits != nil {
		exits := make([]proxyExit, 0, len(req.Exits))
		seen := map[string]bool{}
		for i, x := range req.Exits {
			name := strings.TrimSpace(x.Name)
			if name == "" {
				writeErr(w, 400, fmt.Errorf("exits[%d].name 为空", i))
				return
			}
			if seen[name] {
				writeErr(w, 400, fmt.Errorf("exits[%d].name 重复: %s", i, name))
				return
			}
			seen[name] = true
			ep, verr := validateProxyEndpoint(x.Kind, x.Endpoint)
			if verr != nil {
				writeErr(w, 400, fmt.Errorf("exits[%d]: %v", i, verr))
				return
			}
			enc, eerr := crypto.Encrypt(s.encKey(), ep)
			if eerr != nil {
				writeErr(w, 500, eerr)
				return
			}
			exits = append(exits, proxyExit{Name: name, Kind: x.Kind, EndpointEnc: enc})
		}
		ps.Exits = exits
	}
	raw, _ := json.Marshal(ps)
	_ = s.st.SaveSetting("proxy", raw)
	s.rebuildCommandEnv()
	writeJSON(w, 200, map[string]any{"ok": true})
}

// handleProxyTest 代理连通性测试：经代理对中性探测端点发一次 HTTP 请求（工具下载类用途）。
func (s *Server) handleProxyTest(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Proxy string `json:"proxy"`
		URL   string `json:"url"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, 400, err)
		return
	}
	proxy := strings.TrimSpace(req.Proxy)
	if proxy == "" {
		writeErr(w, 400, fmt.Errorf("proxy 为空"))
		return
	}
	// 测试允许任意 scheme（http/https/socks5/socks5h…），只校验 [scheme://]host:port 形态
	testURL := proxy
	if !strings.Contains(testURL, "://") {
		testURL = "http://" + testURL
	}
	if u, perr := url.Parse(testURL); perr != nil || u.Host == "" || !hostPortRe.MatchString(u.Host) {
		writeErr(w, 400, fmt.Errorf("proxy 需为 [scheme://]host:port 形态"))
		return
	}
	target := strings.TrimSpace(req.URL)
	if target == "" {
		target = "http://connectivitycheck.gstatic.com/generate_204"
	}
	if u, perr := url.Parse(target); perr != nil || (u.Scheme != "http" && u.Scheme != "https") {
		writeErr(w, 400, fmt.Errorf("url 仅支持 http/https"))
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	start := time.Now()
	cmd := exec.CommandContext(ctx, "curl", "-s", "-o", "/dev/null", "-w", "%{http_code} %{time_total}", "-m", "10", "-x", proxy, target)
	out, err := cmd.CombinedOutput()
	res := map[string]any{"ok": err == nil, "output": strings.TrimSpace(string(out)), "duration_ms": time.Since(start).Milliseconds()}
	if err != nil {
		res["error"] = err.Error()
	}
	log.Printf("[proxy] 连通性测试 %s → %s: ok=%v", maskProxyEndpoint(proxy), target, err == nil)
	writeJSON(w, 200, res)
}

// ---------- 设备连接启用按钮（动作注册表） ----------

type deviceActionReq struct {
	Action string            `json:"action"`
	Params map[string]string `json:"params"`
}

var ipv4Re = regexp.MustCompile(`^(\d{1,3}\.){3}\d{1,3}$`)
var pairCodeRe = regexp.MustCompile(`^[0-9]{6,8}$`)

func paramIP(params map[string]string, key string) (string, error) {
	v := strings.TrimSpace(params[key])
	if v == "" {
		return "", fmt.Errorf("%s 为空", key)
	}
	if !ipv4Re.MatchString(v) && !hostPortRe.MatchString(v+`:1`) {
		return "", fmt.Errorf("%s 不是合法地址: %s", key, v)
	}
	for _, seg := range strings.Split(v, ".") {
		if n, e := strconv.Atoi(seg); e == nil && n > 255 {
			return "", fmt.Errorf("%s 段越界: %s", key, v)
		}
	}
	return v, nil
}

func paramPort(params map[string]string, key string, def string) (string, error) {
	v := strings.TrimSpace(params[key])
	if v == "" {
		v = def
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 1 || n > 65535 {
		return "", fmt.Errorf("%s 非法端口: %s", key, v)
	}
	return strconv.Itoa(n), nil
}

// runDeviceCmd 直执行设备命令（无 shell、参数数组注入、超时熔断；审计留痕于服务日志）。
func (s *Server) runDeviceCmd(ctx context.Context, name string, timeout time.Duration, env []string, args ...string) (string, error) {
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	bin, lookErr := exec.LookPath(args[0])
	if lookErr != nil {
		return "", fmt.Errorf("%s 未安装（动态阶段由智能体 install_tool 自动补装）", args[0])
	}
	cmd := exec.CommandContext(cctx, bin, args[1:]...)
	if len(env) > 0 {
		cmd.Env = append(os.Environ(), env...)
	}
	out, err := cmd.CombinedOutput()
	trimmed := strings.TrimSpace(string(out))
	log.Printf("[devices] %s → err=%v out=%dB", name, err, len(trimmed))
	if err != nil {
		if trimmed != "" {
			return trimmed, fmt.Errorf("%v: %s", err, firstLine(trimmed))
		}
		return "", err
	}
	return trimmed, nil
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}

func (s *Server) handleDeviceAction(w http.ResponseWriter, r *http.Request) {
	var req deviceActionReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, 400, err)
		return
	}
	p := req.Params
	action := strings.TrimSpace(req.Action)
	var (
		out string
		err error
	)
	switch action {
	case "wireless_pair": // 场景1：adb pair <ip:port> <code>
		ip, e1 := paramIP(p, "ip")
		port, e2 := paramPort(p, "port", "")
		code := strings.TrimSpace(p["code"])
		if e1 != nil || e2 != nil {
			err = firstErr(e1, e2)
			break
		}
		if !pairCodeRe.MatchString(code) {
			err = fmt.Errorf("配对码需为 6-8 位数字")
			break
		}
		out, err = s.runDeviceCmd(r.Context(), action, 60*time.Second, nil, "adb", "pair", net.JoinHostPort(ip, port), code)
	case "wireless_connect": // 场景1/2/3：adb connect <ip:port>
		ip, e1 := paramIP(p, "ip")
		port, e2 := paramPort(p, "port", "5555")
		if e1 != nil || e2 != nil {
			err = firstErr(e1, e2)
			break
		}
		out, err = s.runDeviceCmd(r.Context(), action, 20*time.Second, nil, "adb", "connect", net.JoinHostPort(ip, port))
	case "wireless_disconnect": // 测完切回：断开网络 adb
		ip, e1 := paramIP(p, "ip")
		port, e2 := paramPort(p, "port", "5555")
		if e1 != nil || e2 != nil {
			err = firstErr(e1, e2)
			break
		}
		out, err = s.runDeviceCmd(r.Context(), action, 15*time.Second, nil, "adb", "disconnect", net.JoinHostPort(ip, port))
	case "tcpip_env_check": // 场景2前置：容器视角是否存在 USB 形态序列号（决定 tcpip 5555 是否可用）
		out, err = s.runDeviceCmd(r.Context(), action, 15*time.Second, nil, "adb", "devices", "-l")
		if err == nil {
			usb := false
			for _, line := range strings.Split(out, "\n") {
				serial := strings.Fields(line)
				if len(serial) > 1 && serial[1] == "device" && !strings.Contains(serial[0], ":") && !strings.HasPrefix(serial[0], "emulator-") {
					usb = true
					break
				}
			}
			out = fmt.Sprintf("usb_available=%v\n%s", usb, out)
		}
	case "shared_adb_test": // 场景4：经共享宿主 adb server 枚举
		host, e1 := paramIP(p, "host")
		port, e2 := paramPort(p, "port", "5037")
		if e1 != nil || e2 != nil {
			err = firstErr(e1, e2)
			break
		}
		out, err = s.runDeviceCmd(r.Context(), action, 15*time.Second,
			[]string{"ADB_SERVER_SOCKET=tcp:" + net.JoinHostPort(host, port)}, "adb", "devices", "-l")
	case "hotspot_probe": // 场景3：只读探测容器当前网络面（默认路由/本机地址），供热点反连规划
		r1, e1 := s.runDeviceCmd(r.Context(), action, 10*time.Second, nil, "ip", "route", "show", "default")
		r2, e2 := s.runDeviceCmd(r.Context(), action, 10*time.Second, nil, "hostname", "-I")
		out = fmt.Sprintf("默认路由:\n%s\n本机地址:\n%s\n（热点反连：设备开热点、宿主连热点后，容器经宿主 NAT 可达设备网段）", r1, strings.TrimSpace(r2))
		err = firstErr(e1, e2)
	case "frida_direct_test": // 场景6备用：frida -H 直连（免 adb）
		host, e1 := paramIP(p, "ip")
		port, e2 := paramPort(p, "port", "27042")
		if e1 != nil || e2 != nil {
			err = firstErr(e1, e2)
			break
		}
		out, err = s.runDeviceCmd(r.Context(), action, 25*time.Second, nil, "frida-ps", "-H", net.JoinHostPort(host, port))
	case "tunnel_check": // 场景6：隧道拉回端口连通性（TCP 探测，只读）
		host, e1 := paramIP(p, "host")
		port, e2 := paramPort(p, "port", "5555")
		if e1 != nil || e2 != nil {
			err = firstErr(e1, e2)
			break
		}
		conn, derr := net.DialTimeout("tcp", net.JoinHostPort(host, port), 5*time.Second)
		if derr != nil {
			err = derr
			break
		}
		_ = conn.Close()
		out = fmt.Sprintf("tcp %s:%s 可达（隧道/服务在监听；下一步 adb connect）", host, port)
	case "cloud_platform_check": // 场景7：云真机平台可达性（只读 GET）
		base := strings.TrimSpace(p["url"])
		u, perr := url.Parse(base)
		if base == "" || perr != nil || (u.Scheme != "http" && u.Scheme != "https") {
			err = fmt.Errorf("url 仅支持 http/https")
			break
		}
		cctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()
		resp, rerr := http.NewRequestWithContext(cctx, http.MethodGet, base, nil)
		if rerr != nil {
			err = rerr
			break
		}
		hc := &http.Client{Timeout: 10 * time.Second}
		hresp, herr := hc.Do(resp)
		if herr != nil {
			err = herr
			break
		}
		_ = hresp.Body.Close()
		out = fmt.Sprintf("%s → HTTP %d（平台可达）", base, hresp.StatusCode)
	default:
		writeErr(w, 400, fmt.Errorf("未知动作: %s（可用：wireless_pair/wireless_connect/wireless_disconnect/tcpip_env_check/shared_adb_test/hotspot_probe/frida_direct_test/tunnel_check/cloud_platform_check）", action))
		return
	}
	res := map[string]any{"ok": err == nil, "action": action, "output": out}
	if err != nil {
		res["error"] = err.Error()
	}
	writeJSON(w, 200, res)
}

func firstErr(errs ...error) error {
	for _, e := range errs {
		if e != nil {
			return e
		}
	}
	return nil
}
