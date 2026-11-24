// v5.6.0 秘密卫生/状态机打通/三态上下文回归测试（审计修复对应项）：
//   - 脱敏：maskToolArgsJSON/maskSensitiveText/streamTool 落库无明文（审计高危#2 修复回归）
//   - 秘密通道：request_credential 全链路无明文落库（审计高危#1 修复回归）
//   - 状态机：projectHasIdentity 三来源打通（审计缺陷#5）、identityTrackIssues 处置校验（缺陷补强）
//   - 三态上下文：credentialStateBlock S0/S1(S2) 差异化（审计④-13）
//   - 注入边界：credTargetHost host 绑定（审计缺陷#4）
package engine

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"jiutouniao/internal/credentials"
	"jiutouniao/internal/llm"
	"jiutouniao/internal/store"
)

const v560Key = v550TestKey

// ---- 脱敏设施 ----

func TestV560MaskToolArgs(t *testing.T) {
	args := `{"identity":"operator","kind":"bearer","secret":"super-secret-token-123","command":"curl -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJ1IjoxfQ.sig1234567890' http://t","note":"普通说明"}`
	out := maskToolArgsJSON(args)
	if strings.Contains(out, "super-secret-token-123") {
		t.Fatalf("secret 键应被掩码: %s", out)
	}
	if strings.Contains(out, "eyJhbGciOiJIUzI1NiJ9") {
		t.Fatalf("command 内联 Authorization 应被模式脱敏: %s", out)
	}
	if !strings.Contains(out, "operator") || !strings.Contains(out, "普通说明") {
		t.Fatalf("非敏感内容应保留: %s", out)
	}
	// 非法 JSON 退化不 panic
	if out2 := maskToolArgsJSON("not-json{"); out2 == "" {
		t.Fatal("非法 JSON 应回退纯文本脱敏")
	}
}

func TestV560MaskSensitiveText(t *testing.T) {
	s := "GET /\nAuthorization: Bearer abcdef1234567890abcdef\nCookie: session=xyz987654321\napi_key: kkkk11112222"
	out := maskSensitiveText(s)
	if strings.Contains(out, "abcdef1234567890") || strings.Contains(out, "xyz987654321") || strings.Contains(out, "kkkk11112222") {
		t.Fatalf("敏感模式应被掩码: %s", out)
	}
	if !strings.Contains(out, "Authorization") {
		t.Fatal("头名应保留（可读性）")
	}
}

func TestV560SensitiveHeaders(t *testing.T) {
	cases := map[string]bool{"Authorization": true, "set-cookie": true, "X-API-Key": true,
		"X-Custom-Trace": false, "User-Agent": false}
	for name, want := range cases {
		if SensitiveHeaderName(name) != want {
			t.Fatalf("头名 %s 判定应 %v", name, want)
		}
	}
}

func TestV560StreamToolNoPlaintextSecret(t *testing.T) {
	o, st := v550Orchestrator(t)
	t.Setenv(credentials.EnvMasterKey, v560Key)
	svc, err := credentials.New(st)
	if err != nil {
		t.Fatal(err)
	}
	o.creds = svc
	p := &store.Project{ ROEAcknowledgedAt: "2026-11-22T00:00:00Z",ID: "P-HY", StageStates: map[string]*store.StageState{}}
	_ = st.SaveProject(p)
	// 模拟 store_credential 的参数流经 streamTool
	args, _ := json.Marshal(map[string]string{"identity": "operator", "kind": "bearer", "secret": "leaky-token-xyz"})
	o.streamTool(p.ID, "s4", llmToolCallV560("store_credential", string(args)), "凭据已安全入库: id=cred-X（掩码 le***yz）")
	streams, _, _ := st.ListStream(p.ID, 0)
	for _, r := range streams {
		if strings.Contains(r.Args+r.Result, "leaky-token-xyz") {
			t.Fatalf("执行流不得包含明文 secret: %s", r.Args)
		}
	}
}

// ---- 秘密通道（request_credential 全链路） ----

func TestV560RequestCredentialNoPlaintext(t *testing.T) {
	o, st := v550Orchestrator(t)
	t.Setenv(credentials.EnvMasterKey, v560Key)
	svc, err := credentials.New(st)
	if err != nil {
		t.Fatal(err)
	}
	o.creds = svc
	p := &store.Project{ ROEAcknowledgedAt: "2026-11-22T00:00:00Z",ID: "P-RC", StageStates: map[string]*store.StageState{}}
	_ = st.SaveProject(p)

	// 异步等待提问 → 1s 后回答 → 校验入库/掩码/无明文
	done := make(chan string, 1)
	go func() {
		res := o.dispatch(context.Background(), p, "s4", llmToolCallV560("request_credential",
			`{"question":"请提供测试账号令牌","identity":"operator","kind":"bearer","target":"http://t.local"}`))
		done <- res
	}()
	time.Sleep(500 * time.Millisecond)
	asks, _ := st.ListAsks(p.ID)
	var askID string
	for _, a := range asks {
		if a.Kind == "credential" && a.Status == "pending" {
			askID = a.ID
		}
	}
	if askID == "" {
		t.Fatal("应创建 credential 类型提问")
	}
	if err := o.AnswerAsk(askID, "user-pasted-secret-abc", "tester"); err != nil {
		t.Fatal(err)
	}
	res := <-done
	if !strings.Contains(res, "凭据已安全入库") || strings.Contains(res, "user-pasted-secret-abc") {
		t.Fatalf("回执应含入库确认且无明文: %s", res)
	}
	// AskRecord 无明文
	rec, _ := st.GetAsk(askID)
	if rec == nil || strings.Contains(rec.Answer, "user-pasted-secret-abc") {
		t.Fatalf("AskRecord 不得落明文: %+v", rec)
	}
	// 执行流无明文
	streams, _, _ := st.ListStream(p.ID, 0)
	for _, r := range streams {
		if strings.Contains(r.Args+r.Result, "user-pasted-secret-abc") {
			t.Fatalf("执行流不得包含明文: %s | %s", r.Args, r.Result)
		}
	}
	// 凭据已入库且可解密回读
	metas, _ := svc.List(p.ID)
	if len(metas) != 1 || metas[0].Identity != "operator" || metas[0].Origin != "real" {
		t.Fatalf("凭据应入库 real 来源: %+v", metas)
	}
	if sec, gerr := svc.Get(p.ID, metas[0].ID); gerr != nil || sec.Value != "user-pasted-secret-abc" {
		t.Fatalf("入库凭据应可解密回读: %v", gerr)
	}
}

// ---- 状态机打通 ----

func TestV560ProjectHasIdentityAndStateBlock(t *testing.T) {
	o, st := v550Orchestrator(t)
	t.Setenv(credentials.EnvMasterKey, v560Key)
	svc, _ := credentials.New(st)
	o.creds = svc
	p := &store.Project{ ROEAcknowledgedAt: "2026-11-22T00:00:00Z",ID: "P-ST", StageStates: map[string]*store.StageState{}}
	_ = st.SaveProject(p)

	// S0：无任何身份
	if o.projectHasIdentity(p) {
		t.Fatal("空项目不应视为已持身份")
	}
	block := o.credentialStateBlock(p)
	if !strings.Contains(block, "S0") || !strings.Contains(block, "request_credential") {
		t.Fatalf("S0 块应含六轨指引与专用通道: %s", block)
	}
	// S1：入库后打通
	if _, err := svc.Put(credentials.Input{ProjectID: p.ID, Identity: "operator", Kind: "bearer", Secret: "tok1"}); err != nil {
		t.Fatal(err)
	}
	if !o.projectHasIdentity(p) {
		t.Fatal("凭据仓库 active 后应视为已持身份（审计缺陷#5 修复回归）")
	}
	block1 := o.credentialStateBlock(p)
	if !strings.Contains(block1, "S1") || !strings.Contains(block1, "auth_ref") {
		t.Fatalf("S1 块应含矩阵编排指引: %s", block1)
	}
	// S2：伪造来源凭据 → 叠加伪造轨
	if _, err := svc.Put(credentials.Input{ProjectID: p.ID, Identity: "forged-admin", Kind: "bearer",
		Secret: "forged1", Origin: "forged", Method: "jwt-none"}); err != nil {
		t.Fatal(err)
	}
	block2 := o.credentialStateBlock(p)
	if !strings.Contains(block2, "S2 伪造轨") || !strings.Contains(block2, "forged-admin") {
		t.Fatalf("伪造轨应叠加注入: %s", block2)
	}
}

func TestV560IdentityTrackDispositionGate(t *testing.T) {
	o, st := v550Orchestrator(t)
	p := &store.Project{ ROEAcknowledgedAt: "2026-11-22T00:00:00Z",ID: "P-DIS", StageStates: map[string]*store.StageState{}}
	_ = st.SaveProject(p)
	_, _ = o.store.AddAsset(&store.Asset{ProjectID: p.ID, Type: "登录面", Value: "http://t/login"})
	// 六轨全部登记但仅 pending（未处置）→ 应拦（审计修复：此前只查标题）
	for _, tk := range []string{"L1", "L2", "L3", "L4", "L5", "L6"} {
		_, _ = st.AddVT(&store.VerificationTask{ProjectID: p.ID, Title: "[W4-" + tk + "] 六轨测试（v5.6.0 处置门回归）", Status: "pending"})
	}
	_, _ = st.AddVT(&store.VerificationTask{ProjectID: p.ID, Title: "[W4-DG] 降级四通道评估（v5.6.1 机械门回归）", Status: "pending"})
	issues := o.identityTrackIssues(p, "s4")
	if len(issues) == 0 || !strings.Contains(issues[0], "未处置") {
		t.Fatalf("全 pending 六轨应触发处置门: %v", issues)
	}
	// 全部处置后放行
	vts, _ := st.ListVTs(p.ID)
	for _, v := range vts {
		v.Status = "deferred"
		v.Note = "移交"
		_ = st.UpdateVT(v)
	}
	if issues := o.identityTrackIssues(p, "s4"); len(issues) != 0 {
		t.Fatalf("全处置后应放行: %v", issues)
	}
}

// ---- host 绑定 ----

func TestV560CredTargetHost(t *testing.T) {
	cases := map[string]string{
		"http://api.t.local:8080/x": "api.t.local",
		"api.t.local":               "api.t.local",
		"user@api.t.local":          "api.t.local",
		"管理员账号":                     "",
		"":                          "",
	}
	for in, want := range cases {
		if got := credTargetHost(in); got != want {
			t.Fatalf("credTargetHost(%q)=%q want %q", in, got, want)
		}
	}
}

func llmToolCallV560(name, args string) llm.ToolCall {
	return llm.ToolCall{ID: "c-" + name, Name: name, Arguments: args}
}

func TestV560MaskIdempotent(t *testing.T) {
	// 已掩码值二次脱敏不再变化（幂等，审计复核）
	s := "Authorization: Bearer abcdef1234567890abcdef"
	once := maskSensitiveText(s)
	twice := maskSensitiveText(once)
	if once != twice {
		t.Fatalf("脱敏应幂等: once=%q twice=%q", once, twice)
	}
	if strings.Contains(once, "abcdef1234567890") {
		t.Fatal("原值应被掩码")
	}
}
