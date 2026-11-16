// Package web HTTP API + WebSocket 实时推送 + 静态前端托管。
package web

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/websocket"

	"jiutouniao/internal/config"
	"jiutouniao/internal/crypto"
	"jiutouniao/internal/engine"
	"jiutouniao/internal/events"
	"jiutouniao/internal/llm"
	"jiutouniao/internal/store"
	"jiutouniao/internal/version"
)

type Server struct {
	orch      *engine.Orchestrator
	st        *store.Store
	bus       *events.Bus
	cfg       *config.Config
	webDir    string
	authToken string
	cryptKey  []byte
	sessions  *sessionStore
	captchas  *captchaStore
}

func New(orch *engine.Orchestrator, st *store.Store, bus *events.Bus, cfg *config.Config, webDir string, cryptKey []byte) *Server {
	s := &Server{orch: orch, st: st, bus: bus, cfg: cfg, webDir: webDir, authToken: cfg.AuthToken, cryptKey: cryptKey,
		sessions: newSessionStore(), captchas: newCaptchaStore()}
	// v5.0.0：启动恢复注入命令环境（测绘 Key + 代理变量合并重建；main.go 的 recon 恢复在其前执行，
	// 此处合并重建为最终态）
	s.rebuildCommandEnv()
	return s
}

func (s *Server) Register(mux *http.ServeMux) {
	// 公开：登录三件套与静态资源
	mux.HandleFunc("GET /api/captcha", s.handleCaptcha)
	mux.HandleFunc("POST /api/login", s.handleLogin)
	mux.HandleFunc("GET /api/public/info", s.handlePublicInfo)
	mux.HandleFunc("GET /api/settings", s.handleSettingsGet)
	mux.HandleFunc("POST /api/settings/llm", s.handleSettingsLLM)
	mux.HandleFunc("POST /api/settings/recon", s.handleSettingsRecon)
	mux.HandleFunc("GET /api/settings/models", s.handleModelsGet)
	mux.HandleFunc("POST /api/settings/models", s.handleModelsSave)
	mux.HandleFunc("DELETE /api/settings/models", s.handleModelsDelete)
	mux.HandleFunc("POST /api/settings/price", s.handlePrice)
	// v5.0.0 代理模块 + 设备连接启用按钮
	mux.HandleFunc("GET /api/settings/proxy", s.handleProxyGet)
	mux.HandleFunc("POST /api/settings/proxy", s.handleProxySave)
	mux.HandleFunc("POST /api/settings/proxy/test", s.handleProxyTest)
	mux.HandleFunc("POST /api/devices/action", s.handleDeviceAction)
	// 需认证
	mux.HandleFunc("POST /api/logout", s.handleLogout)
	mux.HandleFunc("GET /api/heads", s.handleHeads)
	mux.HandleFunc("GET /api/devices", s.handleDevices)
	mux.HandleFunc("GET /api/heads/{id}", s.handleHeadDetail)
	mux.HandleFunc("GET /api/skills", s.handleSkills)
	mux.HandleFunc("POST /api/projects", s.handleCreateProject)
	mux.HandleFunc("GET /api/projects", s.handleListProjects)
	mux.HandleFunc("GET /api/projects/{id}", s.handleGetProject)
	mux.HandleFunc("GET /api/projects/{id}/coverage", s.handleCoverage)
	// v3.9.5 对账视图：自述面清单条目归宿 + 清单外发现计数（覆盖度页签）
	mux.HandleFunc("GET /api/projects/{id}/reconciliation", s.handleReconciliation)
	// v3.7.0 控制台可视化：黑板/战利品/子代理/教训 只读接口（与引擎新状态层对齐）
	mux.HandleFunc("GET /api/projects/{id}/facts", s.handleFacts)
	mux.HandleFunc("GET /api/projects/{id}/loot", s.handleLoot)
	mux.HandleFunc("GET /api/projects/{id}/subagents", s.handleSubAgents)
	mux.HandleFunc("GET /api/lessons", s.handleLessons)
	mux.HandleFunc("GET /api/projects/{id}/files", s.handleFiles)
	mux.HandleFunc("GET /api/projects/{id}/file", s.handleFileContent)
	mux.HandleFunc("POST /api/projects/{id}/start", s.handleStart)
	mux.HandleFunc("POST /api/projects/{id}/kill", s.handleKill)
	mux.HandleFunc("DELETE /api/projects/{id}", s.handleProjectDelete) // v5.3.5：彻底删除（记录+工作区）
	mux.HandleFunc("POST /api/projects/{id}/stage/{stage}/run", s.handleRunStage)
	mux.HandleFunc("GET /api/projects/{id}/report", s.handleReport)
	mux.HandleFunc("POST /api/approvals/{id}/decide", s.handleDecide)
	mux.HandleFunc("POST /api/projects/{id}/chat", s.handleChat)
	mux.HandleFunc("GET /api/projects/{id}/chat", s.handleChatHistory)
	mux.HandleFunc("DELETE /api/projects/{id}/chat", s.handleChatReset)
	mux.HandleFunc("GET /api/projects/{id}/stream", s.handleStream)
	mux.HandleFunc("POST /api/projects/{id}/policy", s.handlePolicy)
	mux.HandleFunc("POST /api/asks/{id}/answer", s.handleAskAnswer)
	mux.HandleFunc("GET /ws", s.handleWS)
	mux.Handle("/", s.noCache(http.FileServer(http.Dir(s.webDir))))
}

// noCache 静态资源禁缓存：UI 更新即时生效，避免浏览器停留在旧版页面。
func (s *Server) noCache(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store, must-revalidate")
		next.ServeHTTP(w, r)
	})
}

// Middleware 供 main 将认证应用于整个 mux（API + 静态 + WS）。
func (s *Server) Middleware(next http.Handler) http.Handler {
	return s.withAuth(next)
}

// withAuth 认证中间件：静态资源与登录接口放行；API/WS 一律需要「会话令牌或 API 令牌」。
func (s *Server) withAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := r.URL.Path
		publicAPI := p == "/api/captcha" || p == "/api/login" || p == "/api/public/info"
		if !strings.HasPrefix(p, "/api") && !strings.HasPrefix(p, "/ws") || publicAPI {
			next.ServeHTTP(w, r)
			return
		}
		if s.checkToken(r) {
			next.ServeHTTP(w, r)
			return
		}
		writeErr(w, 401, fmt.Errorf("未登录或会话过期"))
	})
}

func (s *Server) debugCaptcha() bool { return s.cfg.DebugCaptcha }

// checkToken 接受：登录会话令牌（Bearer/?token=）或静态 API 令牌。
func (s *Server) checkToken(r *http.Request) bool {
	tok := ""
	if h := r.Header.Get("Authorization"); strings.HasPrefix(h, "Bearer ") {
		tok = strings.TrimPrefix(h, "Bearer ")
	} else if q := r.URL.Query().Get("token"); q != "" {
		tok = q
	}
	if tok == "" {
		return false
	}
	if s.sessions.valid(tok) {
		return true
	}
	if s.authToken != "" && subtle.ConstantTimeCompare([]byte(tok), []byte(s.authToken)) == 1 {
		return true
	}
	return false
}

// ---------- 登录 ----------

func (s *Server) handleCaptcha(w http.ResponseWriter, _ *http.Request) {
	id, svg, code := s.captchas.Generate(s.debugCaptcha())
	resp := map[string]any{"captcha_id": id, "svg": svg}
	if code != "" {
		resp["debug_code"] = code
	}
	writeJSON(w, 200, resp)
}

type loginReq struct {
	Username    string `json:"username"`
	Password    string `json:"password"`
	CaptchaID   string `json:"captcha_id"`
	CaptchaCode string `json:"captcha_code"`
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req loginReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, 400, err)
		return
	}
	if !s.captchas.Verify(req.CaptchaID, req.CaptchaCode) {
		writeErr(w, 401, fmt.Errorf("验证码错误或已过期"))
		return
	}
	if !loginCheck(s.cfg, req.Username, req.Password) {
		writeErr(w, 401, fmt.Errorf("账号或密码错误"))
		return
	}
	tok := s.sessions.create()
	writeJSON(w, 200, map[string]any{
		"token": tok, "user": req.Username, "expires_hours": 24,
	})
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if h := r.Header.Get("Authorization"); strings.HasPrefix(h, "Bearer ") {
		s.sessions.drop(strings.TrimPrefix(h, "Bearer "))
	}
	writeJSON(w, 200, map[string]string{"ok": "logged out"})
}

func (s *Server) handlePublicInfo(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, 200, map[string]any{
		"app": "九头鸟（鬼車）", "version": version.App,
		"model": s.defaultModelName(), "protocol": s.cfg.LLM.Protocol,
		"mock": s.cfg.LLM.Mock, "hexstrike": s.cfg.HexStrikeURL != "",
	})
}

// defaultModelName 实际生效的默认模型名（多模型注册表 > 基础配置）。
func (s *Server) defaultModelName() string {
	raw, _ := s.st.GetSetting("default_model")
	defID := string(raw)
	if defID != "" {
		for _, m := range s.loadModels() {
			if m.ID == defID {
				return m.Model
			}
		}
	}
	return s.cfg.LLM.Model
}

// ---------- 对话指挥室 ----------

type chatReq struct {
	Message string `json:"message"`
}

func (s *Server) handleChat(w http.ResponseWriter, r *http.Request) {
	var req chatReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, 400, err)
		return
	}
	projectID := r.PathValue("id")
	if projectID == "_global" {
		projectID = ""
	}
	// v2.6 空闲期指令驱动（PentAGI 单一入口）：paused/created/killed 项目收到启动类指令 → 直接断点续跑
	if projectID != "" && !s.orch.IsRunning(projectID) {
		if handled, reply := s.orch.TryStartFromChat(projectID, req.Message); handled {
			writeJSON(w, 200, map[string]any{"reply": reply, "routed": true, "started": true})
			return
		}
	}
	// 运行中的项目：消息作为指挥室指令注入执行流（PentAGI putUserInput 式），不另起对话轮
	if projectID != "" && s.orch.IsRunning(projectID) {
		s.orch.SendInput(projectID, req.Message)
		writeJSON(w, 200, map[string]any{"reply": "（指令已送达执行流，将在下一轮执行循环注入）", "routed": true})
		return
	}
	reply, err := s.orch.Chat(projectID, req.Message)
	if err != nil {
		writeErr(w, 500, err)
		return
	}
	writeJSON(w, 200, map[string]any{"reply": reply})
}

func (s *Server) handleChatHistory(w http.ResponseWriter, r *http.Request) {
	projectID := r.PathValue("id")
	if projectID == "_global" {
		projectID = ""
	}
	msgs := s.orch.ChatHistory(projectID)
	// 读侧清洗：历史对话统一去 AI 化
	for i := range msgs {
		msgs[i].Content = events.SanitizeEmoji(msgs[i].Content)
	}
	writeJSON(w, 200, msgs)
}

func (s *Server) handleChatReset(w http.ResponseWriter, r *http.Request) {
	projectID := r.PathValue("id")
	if projectID == "_global" {
		projectID = ""
	}
	s.orch.ChatReset(projectID)
	writeJSON(w, 200, map[string]string{"ok": "reset"})
}

// handleStream 执行流回填（PentAGI 式消息流持久化）：?after=seq 增量拉取。
func (s *Server) handleStream(w http.ResponseWriter, r *http.Request) {
	after := int64(0)
	if v := r.URL.Query().Get("after"); v != "" {
		_, _ = fmt.Sscanf(v, "%d", &after)
	}
	recs, last, err := s.st.ListStream(r.PathValue("id"), after)
	if err != nil {
		writeErr(w, 500, err)
		return
	}
	// 读侧清洗：历史落盘记录可能含 pictograph emoji，展示统一去 AI 化
	for _, e := range recs {
		e.Text = events.SanitizeEmoji(e.Text)
	}
	writeJSON(w, 200, map[string]any{"events": recs, "last": last})
}

// handleAskAnswer 人工回答「向人提问」（PentAGI ask_user 移植）。
func (s *Server) handleAskAnswer(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Answer string `json:"answer"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, 400, err)
		return
	}
	if strings.TrimSpace(req.Answer) == "" {
		writeErr(w, 400, fmt.Errorf("answer 不能为空"))
		return
	}
	if err := s.orch.AnswerAsk(r.PathValue("id"), req.Answer, "web-operator"); err != nil {
		writeErr(w, 400, err)
		return
	}
	writeJSON(w, 200, map[string]string{"ok": "answered"})
}

// handlePolicy 更新项目审批策略：manual=全部人工 / l1=仅L1自动 / all=全部操作自动。
// handleProjectDelete v5.3.5：彻底删除项目（bbolt 全部项目作用域记录 + 工作区目录）。
// 运行中项目拒绝——前端/调用方须先 kill。
func (s *Server) handleProjectDelete(w http.ResponseWriter, r *http.Request) {
	if err := s.orch.DeleteProject(r.PathValue("id")); err != nil {
		writeErr(w, 400, err)
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

func (s *Server) handlePolicy(w http.ResponseWriter, r *http.Request) {
	var req struct {
		AutoApprove      string `json:"auto_approve"`
		ExecutionProfile string `json:"execution_profile"` // v5.3.1：执行档切换（可空=不改）
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, 400, err)
		return
	}
	policy := req.AutoApprove
	if policy != "manual" && policy != "l1" && policy != "all" {
		writeErr(w, 400, fmt.Errorf("auto_approve 仅支持 manual / l1 / all"))
		return
	}
	if err := s.orch.SetAutoApprove(r.PathValue("id"), policy); err != nil {
		writeErr(w, 400, err)
		return
	}
	// v5.3.1：执行档随策略接口切换——isolated_lab 是高危显式声明，切换留痕进时间线
	if req.ExecutionProfile != "" {
		if err := s.orch.SetExecutionProfile(r.PathValue("id"), req.ExecutionProfile); err != nil {
			writeErr(w, 400, err)
			return
		}
	}
	writeJSON(w, 200, map[string]any{"ok": true, "auto_approve": policy, "execution_profile": req.ExecutionProfile})
}

// ---------- 技能库 / 头管理 ----------

func (s *Server) handleSkills(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, 200, s.orch.SkillList())
}

func (s *Server) handleHeadDetail(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	h, ok := s.orch.Heads()[id]
	if !ok {
		writeErr(w, 404, fmt.Errorf("头不存在"))
		return
	}
	writeJSON(w, 200, h)
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, code int, err error) {
	writeJSON(w, code, map[string]string{"error": err.Error()})
}

func (s *Server) handleHeads(w http.ResponseWriter, _ *http.Request) {
	heads := s.orch.Heads()
	out := []*engine.Head{}
	for _, h := range heads {
		out = append(out, h)
	}
	writeJSON(w, 200, out)
}

// handleDevices 实时设备连接状态（v2.7.4）：执行 adb devices -l 与 frida-ls-devices，
// 供「设备连接」页展示真实通道（USB/网络/模拟器）与 frida 注入可用性。工具缺失如实返回。
func (s *Server) handleDevices(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 8*time.Second)
	defer cancel()
	out := map[string]any{"checked_at": time.Now().Format(time.RFC3339)}
	if p, e := exec.LookPath("adb"); e == nil {
		out["adb_installed"] = true
		if b, e2 := exec.CommandContext(ctx, p, "devices", "-l").Output(); e2 != nil {
			out["adb_error"] = e2.Error()
		} else {
			raw := strings.TrimSpace(string(b))
			out["adb_raw"] = raw
			out["adb_devices"] = parseAdbDevices(raw)
		}
	} else {
		out["adb_installed"] = false
	}
	if p, e := exec.LookPath("frida-ls-devices"); e == nil {
		out["frida_installed"] = true
		if b, e2 := exec.CommandContext(ctx, p).Output(); e2 != nil {
			out["frida_error"] = e2.Error()
		} else {
			out["frida_devices"] = strings.TrimSpace(string(b))
		}
	} else {
		out["frida_installed"] = false
	}
	writeJSON(w, 200, out)
}

// parseAdbDevices 解析 adb devices -l 输出；transport 按序列号形态推断（ip:port=网络 / emulator-*=模拟器 / 其余=USB）。
func parseAdbDevices(raw string) []map[string]string {
	out := []map[string]string{}
	for _, ln := range strings.Split(raw, "\n") {
		ln = strings.TrimSpace(ln)
		if ln == "" || strings.HasPrefix(ln, "List of devices") || strings.HasPrefix(ln, "* ") {
			continue
		}
		f := strings.Fields(ln)
		if len(f) < 2 {
			continue
		}
		d := map[string]string{"serial": f[0], "state": f[1]}
		for _, kv := range f[2:] {
			if i := strings.IndexByte(kv, ':'); i > 0 {
				d[kv[:i]] = kv[i+1:]
			}
		}
		if strings.Contains(d["serial"], "emulator-") {
			d["transport"] = "模拟器"
		} else if _, _, e := net.SplitHostPort(d["serial"]); e == nil {
			d["transport"] = "网络"
		} else {
			d["transport"] = "USB"
		}
		out = append(out, d)
	}
	return out
}

type createReq struct {
	Name             string   `json:"name"`
	Target           string   `json:"target"`
	Scope            string   `json:"scope"`
	ROE              string   `json:"roe"`
	TestType         string   `json:"test_type"`
	TimeWindow       string   `json:"time_window"`
	Contact          string   `json:"contact"`
	SuccessCriteria  string   `json:"success_criteria"`
	AuthInfo         string   `json:"auth_info"`
	ExecutionProfile string   `json:"execution_profile"` // v5.3.1：执行档（空/未知=production_safe）
	PostExploit      bool     `json:"post_exploit"`      // v5.3.7：后渗透勾选（默认 false=s6 整段 skipped）
	StrictScope      *bool    `json:"strict_scope"`
	BudgetTokens     int64    `json:"budget_tokens"`
	Authorized       bool     `json:"authorized"`
	ModelID          string   `json:"model_id"`
	AutoApprove      string   `json:"auto_approve"`
	Specializations  []string `json:"specializations"`
}

func (s *Server) handleCreateProject(w http.ResponseWriter, r *http.Request) {
	var req createReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, 400, err)
		return
	}
	if !req.Authorized {
		writeErr(w, 400, fmt.Errorf("必须勾选「授权确认」：确认已获书面授权并知悉测试风险后才能创建项目"))
		return
	}
	strict := req.StrictScope == nil || *req.StrictScope
	// v5.3.1：执行档白名单校验（isolated_lab 是高危显式声明，创建时即定档并持久化）
	if req.ExecutionProfile != "" && req.ExecutionProfile != "production_safe" && req.ExecutionProfile != "isolated_lab" {
		writeErr(w, 400, fmt.Errorf("execution_profile 仅支持 production_safe / isolated_lab"))
		return
	}
	p, err := s.orch.CreateProject(&store.Project{
		Name: req.Name, Target: req.Target, Scope: req.Scope, ROE: req.ROE,
		TestType: req.TestType, TimeWindow: req.TimeWindow,
		Contact: req.Contact, SuccessCriteria: req.SuccessCriteria,
		AuthInfo: req.AuthInfo, StrictScope: strict, BudgetTokens: req.BudgetTokens,
		Authorized: req.Authorized, ModelID: req.ModelID, AutoApprove: req.AutoApprove,
		ExecutionProfile: req.ExecutionProfile,
		PostExploit:      req.PostExploit,
		Specializations:  req.Specializations,
	})
	if err != nil {
		writeErr(w, 400, err)
		return
	}
	writeJSON(w, 200, p)
}

func (s *Server) handleListProjects(w http.ResponseWriter, _ *http.Request) {
	ps, err := s.st.ListProjects()
	if err != nil {
		writeErr(w, 500, err)
		return
	}
	if ps == nil {
		ps = []*store.Project{} // 空列表统一返回 []，避免前端拿到 null（O-3）
	}
	writeJSON(w, 200, ps)
}

func (s *Server) handleGetProject(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	p, err := s.st.GetProject(id)
	if err != nil {
		writeErr(w, 404, err)
		return
	}
	findings, _ := s.st.ListFindings(id)
	assets, _ := s.st.ListAssets(id)
	timeline, _ := s.st.ListTimeline(id)
	approvals, _ := s.st.ListApprovals(id)
	evidence, _ := s.st.ListEvidence(id)
	usage, _ := s.st.GetUsage(id)
	subtasks, _ := s.st.ListSubtasks(id)
	asks, _ := s.st.ListAsks(id)
	// v5.3.6 POC 证据回填：模型未提供 poc 的发现，从命令类证据记录自动构建请求/响应对
	// （Input=请求侧，Output=响应侧，标记 backfilled；只读不改库，展示层兜底）
	backfillPOC(findings, evidence)
	writeJSON(w, 200, map[string]any{
		"project": p, "findings": findings, "assets": assets,
		"timeline": timeline, "approvals": approvals, "evidence": evidence,
		"usage": usage, "subtasks": subtasks, "asks": asks,
		"price_in": s.cfg.PricePer1MInput, "price_out": s.cfg.PricePer1MOutput,
	})
}

func (s *Server) handleCoverage(w http.ResponseWriter, r *http.Request) {
	cov, err := s.st.ListCoverage(r.PathValue("id"))
	if err != nil {
		writeErr(w, 500, err)
		return
	}
	writeJSON(w, 200, cov)
}

// handleReconciliation v3.9.5 对账视图数据：自述面清单条目归宿 + 清单外发现计数。
func (s *Server) handleReconciliation(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, s.orch.ReconciliationPublic(r.PathValue("id")))
}

// handleFiles 工作区文件清单（交付物中心）。
// 参数：dirs=顶层目录白名单（逗号分隔，"."=根目录散落文件，如 ".,deliverables,poc,evidence"）；
//
//	exclude=排除的顶层目录/前缀（逗号分隔）。兼容旧参数 dir（单目录）。
//
// 响应头 X-Total-Count=过滤后总数（截断前），body 仍为最新 80 条的 wsFile 数组。
func (s *Server) handleFiles(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	dirs := q.Get("dirs")
	if dirs == "" {
		dirs = q.Get("dir")
	}
	files, total, err := s.orch.ListWorkspaceFilesFilteredPublic(r.PathValue("id"), engine.SplitDirs(dirs), engine.SplitDirs(q.Get("exclude")))
	if err != nil {
		writeErr(w, 500, err)
		return
	}
	w.Header().Set("X-Total-Count", strconv.Itoa(total))
	writeJSON(w, 200, files)
}

// handleFileContent 读取单个文件内容（文本预览）。
func (s *Server) handleFileContent(w http.ResponseWriter, r *http.Request) {
	content, err := s.orch.ReadFilePublic(r.PathValue("id"), r.URL.Query().Get("path"))
	if err != nil {
		writeErr(w, 404, err)
		return
	}
	writeJSON(w, 200, map[string]string{"content": content})
}

// ---------- v3.7.0 控制台可视化：新状态层只读接口 ----------

func (s *Server) handleFacts(w http.ResponseWriter, r *http.Request) {
	facts, err := s.st.ListFacts(r.PathValue("id"), 0)
	if err != nil {
		writeErr(w, 500, err)
		return
	}
	writeJSON(w, 200, facts)
}

func (s *Server) handleLoot(w http.ResponseWriter, r *http.Request) {
	loot, err := s.st.ListLoot(r.PathValue("id"), 0)
	if err != nil {
		writeErr(w, 500, err)
		return
	}
	writeJSON(w, 200, loot)
}

func (s *Server) handleSubAgents(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, s.orch.SubAgentSnapshots(r.PathValue("id")))
}

func (s *Server) handleLessons(w http.ResponseWriter, _ *http.Request) {
	lessons, err := s.st.ListLessons(100)
	if err != nil {
		writeErr(w, 500, err)
		return
	}
	writeJSON(w, 200, lessons)
}

func (s *Server) handleStart(w http.ResponseWriter, r *http.Request) {
	if err := s.orch.StartProject(r.PathValue("id")); err != nil {
		writeErr(w, 400, err)
		return
	}
	writeJSON(w, 200, map[string]string{"ok": "started"})
}

func (s *Server) handleKill(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Reason string `json:"reason"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
	if err := s.orch.Kill(r.PathValue("id"), req.Reason); err != nil {
		writeErr(w, 400, err)
		return
	}
	writeJSON(w, 200, map[string]string{"ok": "killed"})
}

func (s *Server) handleRunStage(w http.ResponseWriter, r *http.Request) {
	if err := s.orch.RunStage(r.PathValue("id"), r.PathValue("stage")); err != nil {
		writeErr(w, 400, err)
		return
	}
	writeJSON(w, 200, map[string]string{"ok": "running"})
}

// handleReport 返回工作区 report.md（阶段8产出）。尚未生成时返回 200+exists:false
// （前端显示占位文案；避免控制台 404 噪音）。
func (s *Server) handleReport(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" || strings.Contains(id, "..") || strings.Contains(id, "/") {
		writeErr(w, 400, fmt.Errorf("非法项目 ID"))
		return
	}
	// 报告由 stage8 头写在工作区 report.md
	path := filepath.Join("projects", id, "report.md")
	raw, err := os.ReadFile(path)
	if err != nil {
		writeJSON(w, 200, map[string]any{"exists": false, "content": ""})
		return
	}
	w.Header().Set("Content-Type", "text/markdown; charset=utf-8")
	_, _ = w.Write(raw)
}

type decideReq struct {
	Approve bool `json:"approve"`
}

func (s *Server) handleDecide(w http.ResponseWriter, r *http.Request) {
	var req decideReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, 400, err)
		return
	}
	if err := s.orch.Approver().Decide(r.PathValue("id"), req.Approve, "web-operator"); err != nil {
		writeErr(w, 400, err)
		return
	}
	writeJSON(w, 200, map[string]string{"ok": "decided"})
}

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool { return true },
}

func (s *Server) handleWS(w http.ResponseWriter, r *http.Request) {
	projectID := r.URL.Query().Get("project")
	if projectID == "" {
		http.Error(w, "missing project", 400)
		return
	}
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer conn.Close()
	ch := s.bus.Subscribe(projectID)
	defer s.bus.Unsubscribe(projectID, ch)
	for payload := range ch {
		if err := conn.WriteMessage(websocket.TextMessage, payload); err != nil {
			return
		}
	}
}

// ---------- 设置（LLM / 空间测绘 Key） ----------

type llmSettings struct {
	Protocol  string `json:"protocol"`
	BaseURL   string `json:"base_url"`
	Model     string `json:"model"`
	APIKeyEnc string `json:"api_key_enc"`
}

type reconSettings struct {
	ShodanKeyEnc string `json:"shodan_enc"`
	FofaEmail    string `json:"fofa_email"`
	FofaKeyEnc   string `json:"fofa_key_enc"`
	QuakeKeyEnc  string `json:"quake_enc"`
	ZoomEyeEnc   string `json:"zoomeye_enc"`
}

func (s *Server) encKey() []byte { return s.cryptKey }

func (s *Server) handleSettingsGet(w http.ResponseWriter, _ *http.Request) {
	resp := map[string]any{
		"llm": map[string]any{
			"protocol": s.cfg.LLM.Protocol, "base_url": s.cfg.LLM.BaseURL,
			"model": s.cfg.LLM.Model, "mock": s.cfg.LLM.Mock,
			"api_key_set": false,
		},
		"recon": map[string]any{
			"shodan": false, "fofa": false, "fofa_email": "", "quake": false, "zoomeye": false,
		},
	}
	if raw, ok := s.st.GetSetting("llm"); ok {
		var ls llmSettings
		if json.Unmarshal(raw, &ls) == nil {
			resp["llm"] = map[string]any{
				"protocol": ls.Protocol, "base_url": ls.BaseURL, "model": ls.Model,
				"api_key_set": ls.APIKeyEnc != "", "mock": false,
			}
		}
	}
	if raw, ok := s.st.GetSetting("recon"); ok {
		var rs reconSettings
		if json.Unmarshal(raw, &rs) == nil {
			resp["recon"] = map[string]any{
				"shodan": rs.ShodanKeyEnc != "", "fofa": rs.FofaKeyEnc != "",
				"fofa_email": rs.FofaEmail, "quake": rs.QuakeKeyEnc != "", "zoomeye": rs.ZoomEyeEnc != "",
			}
		}
	}
	if raw, ok := s.st.GetSetting("pricing"); ok {
		var pr struct {
			In  float64 `json:"in"`
			Out float64 `json:"out"`
		}
		if json.Unmarshal(raw, &pr) == nil {
			resp["pricing"] = pr
		}
	}
	writeJSON(w, 200, resp)
}

type setLLMReq struct {
	Protocol string `json:"protocol"`
	BaseURL  string `json:"base_url"`
	Model    string `json:"model"`
	APIKey   string `json:"api_key"` // 留空 = 保持已有 Key
}

func (s *Server) handleSettingsLLM(w http.ResponseWriter, r *http.Request) {
	var req setLLMReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, 400, err)
		return
	}
	ls := llmSettings{Protocol: req.Protocol, BaseURL: req.BaseURL, Model: req.Model}
	if raw, ok := s.st.GetSetting("llm"); ok {
		var old llmSettings
		if json.Unmarshal(raw, &old) == nil {
			if ls.Protocol == "" {
				ls.Protocol = old.Protocol
			}
			if ls.BaseURL == "" {
				ls.BaseURL = old.BaseURL
			}
			if ls.Model == "" {
				ls.Model = old.Model
			}
			ls.APIKeyEnc = old.APIKeyEnc
		}
	}
	if strings.TrimSpace(req.APIKey) != "" {
		enc, err := crypto.Encrypt(s.encKey(), strings.TrimSpace(req.APIKey))
		if err != nil {
			writeErr(w, 500, err)
			return
		}
		ls.APIKeyEnc = enc
	}
	if ls.BaseURL == "" || ls.Model == "" {
		writeErr(w, 400, fmt.Errorf("base_url 与 model 必填"))
		return
	}
	if ls.Protocol == "" {
		ls.Protocol = "openai"
	}
	raw, _ := json.Marshal(ls)
	_ = s.st.SaveSetting("llm", raw)

	// 热切换：解密构建新客户端并即时生效
	key := ""
	if ls.APIKeyEnc != "" {
		key, _ = crypto.Decrypt(s.encKey(), ls.APIKeyEnc)
	}
	var client llm.Client
	if strings.EqualFold(ls.Protocol, "anthropic") {
		client = llm.NewAnthropic(ls.BaseURL, key)
	} else {
		client = llm.NewOpenAI(ls.BaseURL, key)
	}
	s.orch.SetLLMClient(client)
	s.cfg.LLM.Protocol, s.cfg.LLM.BaseURL, s.cfg.LLM.Model, s.cfg.LLM.Mock = ls.Protocol, ls.BaseURL, ls.Model, false
	log.Printf("[settings] LLM 已热切换: %s %s %s", ls.Protocol, ls.BaseURL, ls.Model)
	writeJSON(w, 200, map[string]any{"ok": true, "api_key_set": ls.APIKeyEnc != ""})
}

type setReconReq struct {
	Shodan    string `json:"shodan"`
	FofaEmail string `json:"fofa_email"`
	FofaKey   string `json:"fofa_key"`
	Quake     string `json:"quake"`
	ZoomEye   string `json:"zoomeye"`
}

func (s *Server) handleSettingsRecon(w http.ResponseWriter, r *http.Request) {
	var req setReconReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, 400, err)
		return
	}
	rs := reconSettings{}
	if raw, ok := s.st.GetSetting("recon"); ok {
		_ = json.Unmarshal(raw, &rs)
	}
	rs.FofaEmail = strings.TrimSpace(req.FofaEmail)
	keep := func(old string, nv string) (string, error) {
		if strings.TrimSpace(nv) == "" {
			return old, nil
		}
		return crypto.Encrypt(s.encKey(), strings.TrimSpace(nv))
	}
	var err error
	if rs.ShodanKeyEnc, err = keep(rs.ShodanKeyEnc, req.Shodan); err != nil {
		writeErr(w, 500, err)
		return
	}
	if rs.FofaKeyEnc, err = keep(rs.FofaKeyEnc, req.FofaKey); err != nil {
		writeErr(w, 500, err)
		return
	}
	if rs.QuakeKeyEnc, err = keep(rs.QuakeKeyEnc, req.Quake); err != nil {
		writeErr(w, 500, err)
		return
	}
	if rs.ZoomEyeEnc, err = keep(rs.ZoomEyeEnc, req.ZoomEye); err != nil {
		writeErr(w, 500, err)
		return
	}
	raw, _ := json.Marshal(rs)
	_ = s.st.SaveSetting("recon", raw)

	// 注入命令环境（侦察头直接用 $SHODAN_API_KEY 等）
	env := map[string]string{}
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
	s.rebuildCommandEnv() // v5.0.0：合并测绘 Key+代理变量重建，避免覆写
	writeJSON(w, 200, map[string]any{"ok": true})
}

// ---------- 多模型管理 ----------

type modelCfg struct {
	ID        string `json:"id"`
	Label     string `json:"label"`
	Protocol  string `json:"protocol"`
	BaseURL   string `json:"base_url"`
	Model     string `json:"model"`
	APIKeyEnc string `json:"api_key_enc"`
}

func (s *Server) loadModels() []modelCfg {
	raw, ok := s.st.GetSetting("models")
	if !ok {
		return nil
	}
	var out []modelCfg
	if json.Unmarshal(raw, &out) == nil {
		return out
	}
	return nil
}

func (s *Server) saveModels(ms []modelCfg) {
	raw, _ := json.Marshal(ms)
	_ = s.st.SaveSetting("models", raw)
}

// applyModels 重建客户端注册表并热应用。
func (s *Server) applyModels(def string) {
	ms := s.loadModels()
	clients := map[string]llm.Client{}
	names := map[string]string{}
	for _, m := range ms {
		key, _ := crypto.Decrypt(s.cryptKey, m.APIKeyEnc)
		if strings.EqualFold(m.Protocol, "anthropic") {
			clients[m.ID] = llm.NewAnthropic(m.BaseURL, key)
		} else {
			clients[m.ID] = llm.NewOpenAI(m.BaseURL, key)
		}
		names[m.ID] = m.Model
	}
	if def == "" {
		for _, m := range ms {
			def = m.ID
			break
		}
	}
	s.orch.SetModels(clients, names, def)
}

func (s *Server) handleModelsGet(w http.ResponseWriter, _ *http.Request) {
	ms := s.loadModels()
	type view struct {
		ID        string `json:"id"`
		Label     string `json:"label"`
		Protocol  string `json:"protocol"`
		BaseURL   string `json:"base_url"`
		Model     string `json:"model"`
		APIKeySet bool   `json:"api_key_set"`
	}
	out := []view{}
	for _, m := range ms {
		out = append(out, view{m.ID, m.Label, m.Protocol, m.BaseURL, m.Model, m.APIKeyEnc != ""})
	}
	raw, _ := s.st.GetSetting("default_model")
	def := string(raw)
	writeJSON(w, 200, map[string]any{"models": out, "default": def})
}

type modelReq struct {
	ID       string `json:"id"`
	Label    string `json:"label"`
	Protocol string `json:"protocol"`
	BaseURL  string `json:"base_url"`
	Model    string `json:"model"`
	APIKey   string `json:"api_key"` // 留空保持旧 Key
	Default  bool   `json:"default"`
}

func (s *Server) handleModelsSave(w http.ResponseWriter, r *http.Request) {
	var req modelReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, 400, err)
		return
	}
	if req.BaseURL == "" || req.Model == "" {
		writeErr(w, 400, fmt.Errorf("base_url 与 model 必填"))
		return
	}
	if req.Protocol == "" {
		req.Protocol = "openai"
	}
	ms := s.loadModels()
	var target *modelCfg
	for i := range ms {
		if ms[i].ID == req.ID {
			target = &ms[i]
			break
		}
	}
	if target == nil {
		ms = append(ms, modelCfg{ID: fmt.Sprintf("m%d", time.Now().UnixNano()), Label: req.Label, Protocol: req.Protocol, BaseURL: req.BaseURL, Model: req.Model})
		target = &ms[len(ms)-1]
	}
	target.Label, target.Protocol, target.BaseURL, target.Model = req.Label, req.Protocol, req.BaseURL, req.Model
	if strings.TrimSpace(req.APIKey) != "" {
		enc, err := crypto.Encrypt(s.cryptKey, strings.TrimSpace(req.APIKey))
		if err != nil {
			writeErr(w, 500, err)
			return
		}
		target.APIKeyEnc = enc
	}
	s.saveModels(ms)
	def := ""
	if raw, ok := s.st.GetSetting("default_model"); ok {
		def = string(raw)
	}
	if req.Default || def == "" {
		def = target.ID
		_ = s.st.SaveSetting("default_model", []byte(def))
	}
	s.applyModels(def)
	log.Printf("[settings] 模型已保存: %s %s/%s 默认=%s", target.Label, target.Protocol, target.Model, def)
	writeJSON(w, 200, map[string]any{"ok": true, "default": def})
}

func (s *Server) handleModelsDelete(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	ms := s.loadModels()
	out := ms[:0]
	for _, m := range ms {
		if m.ID != id {
			out = append(out, m)
		}
	}
	s.saveModels(out)
	def := ""
	if raw, ok := s.st.GetSetting("default_model"); ok {
		def = string(raw)
	}
	if def == id {
		def = ""
		_ = s.st.SaveSetting("default_model", []byte(""))
	}
	s.applyModels(def)
	writeJSON(w, 200, map[string]any{"ok": true})
}

type priceReq struct {
	In  float64 `json:"in"`
	Out float64 `json:"out"`
}

func (s *Server) handlePrice(w http.ResponseWriter, r *http.Request) {
	var req priceReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, 400, err)
		return
	}
	raw, _ := json.Marshal(req)
	_ = s.st.SaveSetting("pricing", raw)
	s.cfg.PricePer1MInput, s.cfg.PricePer1MOutput = req.In, req.Out
	log.Printf("[settings] 单价更新: in=%.2f out=%.2f $/1M", req.In, req.Out)
	writeJSON(w, 200, map[string]any{"ok": true})
}

// backfillPOC v5.3.6：POC 证据回填（展示层兜底，只读不改库）。模型未提供 poc 的发现：
// 从命令类证据中挑选复现性记录——资格：Type=command/hexstrike、Input 含 URL 字面量(://)与
// 请求工具特征（curl/wget/httpx/nc）、排除工作区操作（echo/cat/grep 起手）与被拦/被拒记录、
// Output 非 HTTP 工具类命令需含响应特征。每条发现 ≤2 组：优先本阶段（e.Stage=f.Stage）最新，
// 不足再全局最新补足——实证修正：初版仅按 http 子串过滤，曾把工作区 grep/报告追加命令回填给
// 全部发现（同一对垃圾 POC 刷满页面）。
func backfillPOC(findings []*store.Finding, evidence []*store.EvidenceRecord) {
	isWSOp := func(in string) bool {
		t := strings.TrimSpace(in)
		for _, kw := range []string{"echo ", "cat >>", "grep -r", "grep -rl", "ls ", "find .", "report.md", "deliverables/"} {
			if strings.HasPrefix(t, kw) || strings.Contains(t, "&& "+kw) {
				return true
			}
		}
		return false
	}
	qualifies := func(e *store.EvidenceRecord) bool {
		if e.Type != "command" && e.Type != "hexstrike" {
			return false
		}
		in := strings.ToLower(strings.TrimSpace(e.Input))
		// v5.3.7 收紧：起手必须是请求工具调用（curl/wget/python/httpx/nc）——
		// 复合命令（cd…; { echo…; grep…} / 报告追加）内嵌 URL 子串不算复现请求（两轮实证）。
		tool := false
		for _, pre := range []string{"curl", "wget", "python", "httpx", "nc "} {
			if strings.HasPrefix(in, pre) {
				tool = true
				break
			}
		}
		if !tool {
			return false
		}
		if isWSOp(e.Input) {
			return false // 工作区操作命令（echo/cat/grep/报告追加）不是复现请求
		}
		if strings.Contains(e.Output, "被治理门拦截") || strings.Contains(e.Output, "人工拒绝") {
			return false
		}
		if strings.TrimSpace(e.Output) == "" {
			return false
		}
		return true
	}
	var cands []*store.EvidenceRecord
	for _, e := range evidence { // ListEvidence 时间升序 → 末尾最新
		if qualifies(e) {
			cands = append(cands, e)
		}
	}
	if len(cands) == 0 {
		return
	}
	take := func(f *store.Finding, stageOnly bool) int {
		n := 0
		for i := len(cands) - 1; i >= 0 && n < 2; i-- {
			e := cands[i]
			if stageOnly && e.Stage != f.Stage {
				continue
			}
			f.POC = append(f.POC, store.FindingPOC{Request: e.Input, Response: e.Output, Backfilled: true})
			n++
		}
		return n
	}
	for _, f := range findings {
		if len(f.POC) > 0 {
			continue // 模型原始 POC 优先
		}
		if n := take(f, true); n < 2 {
			take(f, false)
		}
	}
}

