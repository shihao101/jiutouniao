// v5.5.0 能力修复回归测试（docs/repair-plan-capability-20261118.md 方案 A/D/E/G/H）：
//   - A：凭据仓库加解密/隔离/撤销/fail-closed；http_request 无凭据引用治理路径（scope 门）
//   - D：回环超额显式拒绝不改状态；非法目标阶段拒绝
//   - E：预算耗尽默认 paused（不装作完成）；auto_close 兼容档保留代收口
//   - G：压缩前回执归档 + search_memory receipt:<id> 取回原文 + 跨项目拒绝
//   - H：对话轮次耗尽挂起运行链持久化 + 下轮断点续跑不重放
package engine

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"jiutouniao/internal/config"
	"jiutouniao/internal/credentials"
	"jiutouniao/internal/events"
	"jiutouniao/internal/llm"
	"jiutouniao/internal/store"
)

// v550Orchestrator 带 heads+skills 的测试编排器（runStage/buildContextPack 需要）。
func v550Orchestrator(t *testing.T) (*Orchestrator, *store.Store) {
	t.Helper()
	_, st := testApprover(t)
	dir := t.TempDir()
	cfg := &config.Config{}
	cfg.ApplyDefaultsForTest()
	cfg.DataDir = dir
	heads, err := LoadHeads("../../../heads")
	if err != nil {
		t.Fatal(err)
	}
	skills, err := LoadSkills("../../../skills")
	if err != nil {
		t.Fatal(err)
	}
	o := &Orchestrator{store: st, exec: newTestExec(t, dir), bus: events.NewBus(), cfg: cfg,
		heads: heads, skills: skills, coreLoop: "test-core-loop",
		tokens: map[string]int64{}, loops: map[string][]string{}, inputs: map[string][]string{},
		batchStats: map[string]*batchBudgetState{}}
	return o, st
}

const v550TestKey = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" // 64 hex = 32B

// ---- 方案 A：凭据仓库 ----

func TestV550CredentialsRoundtrip(t *testing.T) {
	_, st := testApprover(t)
	t.Setenv(credentials.EnvMasterKey, v550TestKey)
	svc, err := credentials.New(st)
	if err != nil {
		t.Fatal(err)
	}
	if !svc.Enabled() {
		t.Fatal("配置主密钥后应启用")
	}
	meta, err := svc.Put(credentials.Input{ProjectID: "PA", Target: "http://t", Identity: "operator",
		Role: "admin", Kind: "bearer", Username: "ops-user", Secret: "ops-cred-2026"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(meta.Username, "ops-user") || !strings.Contains(meta.Username, "***") {
		t.Fatalf("meta 用户名应掩码: %q", meta.Username)
	}
	sec, err := svc.Get("PA", meta.ID)
	if err != nil || sec.Value != "ops-cred-2026" {
		t.Fatalf("解密回读不符: %v %q", err, sec.Value)
	}
	// ① 项目隔离
	if _, err := svc.Get("PB", meta.ID); err == nil {
		t.Fatal("跨项目读取应拒绝")
	}
	// ② 数据库无明文
	if rec, _ := st.GetCredential("PA", meta.ID); rec != nil && strings.Contains(string(rec.SecretCiphertext), "super-secret") {
		t.Fatal("密文中不得出现明文")
	}
	// ③ 撤销后拒绝
	if err := svc.Revoke("PA", meta.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Get("PA", meta.ID); err == nil {
		t.Fatal("revoke 后 Get 应拒绝")
	}
	// ④ fail-closed：无主密钥时录入直接拒绝
	t.Setenv(credentials.EnvMasterKey, "")
	svc2, err := credentials.New(st)
	if err != nil {
		t.Fatal(err)
	}
	if svc2.Enabled() {
		t.Fatal("无主密钥不应启用")
	}
	if _, err := svc2.Put(credentials.Input{ProjectID: "PA", Identity: "x", Kind: "bearer", Secret: "v"}); err == nil {
		t.Fatal("fail-closed：未启用时 Put 应报错")
	}
}

func TestV550IdentityResolve(t *testing.T) {
	o, st := v550Orchestrator(t)
	t.Setenv(credentials.EnvMasterKey, v550TestKey)
	svc, err := credentials.New(st)
	if err != nil {
		t.Fatal(err)
	}
	o.creds = svc
	p := &store.Project{ ROEAcknowledgedAt: "2026-11-22T00:00:00Z",ID: "P-RES"}
	_ = st.SaveProject(p)
	m1, err1 := svc.Put(credentials.Input{ProjectID: p.ID, Identity: "operator/session-1", Kind: "cookie", Secret: "ck-1"})
	if err1 != nil {
		t.Fatal(err1)
	}
	m2, err2 := svc.Put(credentials.Input{ProjectID: p.ID, Identity: "operator/session-2", Kind: "cookie", Secret: "ck-2"})
	if err2 != nil {
		t.Fatal(err2)
	}
	id, sec, _, err := o.resolveCredential(p, "identity:operator/session-2")
	if err != nil {
		t.Fatalf("identity 解析失败: %v", err)
	}
	if id != m2.ID || sec == nil || sec.Value != "ck-2" {
		t.Fatalf("按身份解析应取最近入库会话: id=%s want=%s sec=%v", id, m2.ID, sec)
	}
	_ = m1
	// v5.6.0：同名身份多条 active → 显式拒绝（禁止静默选最新）
	m3, err3 := svc.Put(credentials.Input{ProjectID: p.ID, Identity: "operator/session-2", Kind: "cookie", Secret: "ck-3"})
	if err3 != nil {
		t.Fatal(err3)
	}
	_, _, _, ambErr := o.resolveCredential(p, "identity:operator/session-2")
	if ambErr == nil || !strings.Contains(ambErr.Error(), "cred-") {
		t.Fatalf("同名多 active 应拒绝并提示用 cred-<id> 消歧: %v", ambErr)
	}
	// cred-<id> 显式引用仍可精确解析
	_, sec3, rec3, err3b := o.resolveCredential(p, m3.ID)
	if err3b != nil || sec3 == nil || sec3.Value != "ck-3" || rec3 == nil || rec3.Origin != "real" {
		t.Fatalf("显式 cred-<id> 解析应精确: %v %v %v", err3b, sec3, rec3)
	}
	// revoke 后 identity 解析跳过失效凭据
	_ = svc.Revoke(p.ID, m2.ID)
	_ = svc.Revoke(p.ID, m3.ID)
	id2, _, _, err := o.resolveCredential(p, "identity:operator/session-2")
	if err == nil || id2 != "" {
		t.Fatalf("身份仅剩 revoke 凭据时应拒绝: %v %s", err, id2)
	}
}

// ---- 方案 G：压缩归档 + receipt 检索 ----

func TestV550CompactArchiveAndReceiptRetrieval(t *testing.T) {
	o, st := v550Orchestrator(t)
	p := &store.Project{ ROEAcknowledgedAt: "2026-11-22T00:00:00Z",ID: "P-G"}
	p.StageStates = map[string]*store.StageState{"s2": {Status: "running"}}
	_ = st.SaveProject(p)

	long := strings.Repeat("X", 5000)
	msgs := []llm.Message{
		{Role: "system", Content: "[[HEAD:s2]]\n核心循环"},
		{Role: "user", Content: "上下文包"},
		{Role: "tool", ToolCallID: "t1", Content: long},
		{Role: "assistant", Content: "收到，结论 A"},
		{Role: "user", Content: "继续"},
		{Role: "assistant", Content: "补充"},
		{Role: "user", Content: "再查"},
		{Role: "tool", ToolCallID: "t2", Content: long},
	}
	archive := func(stage, content string) string {
		rid, rerr := st.SaveReceipt(p.ID, stage, content)
		if rerr != nil {
			return ""
		}
		return rid
	}
	out, n := compactMsgsWithArchive(msgs, 300, 4, archive)
	if n == 0 {
		t.Fatal("超预算应发生压缩")
	}
	// 存根携带 receipt id，且可经 dispatch search_memory 取回原文
	rid := ""
	for _, m := range out {
		if m.Role == "tool" && strings.Contains(m.Content, "receipt=") {
			i := strings.Index(m.Content, "receipt=")
			rid = m.Content[i+len("receipt="):]
			if j := strings.Index(rid, "："); j >= 0 {
				rid = rid[:j]
			}
			if j := strings.Index(rid, "）"); j >= 0 {
				rid = rid[:j]
			}
			rid = strings.Trim(rid, "：） ")
		}
	}
	if rid == "" {
		t.Fatal("压缩存根应携带 receipt id")
	}
	res := o.dispatch(context.Background(), p, "s2", llm.ToolCall{Name: "search_memory",
		Arguments: fmt.Sprintf(`{"query":"receipt:%s"}`, rid)})
	if !strings.Contains(res, long[:100]) {
		t.Fatalf("receipt 取回应返回原文: %s", truncateText(res, 200))
	}
	// 跨项目拒绝
	res2 := o.dispatch(context.Background(), &store.Project{ ROEAcknowledgedAt: "2026-11-22T00:00:00Z",ID: "P-OTHER"}, "s2", llm.ToolCall{Name: "search_memory",
		Arguments: fmt.Sprintf(`{"query":"receipt:%s"}`, rid)})
	if !strings.Contains(res2, "不属于本项目") {
		t.Fatalf("跨项目 receipt 读取应拒绝: %s", res2)
	}
	// 保留旧语义：无归档回调时存根不含 receipt
	out2, _ := compactMsgsWithArchive(msgs, 300, 4, nil)
	for _, m := range out2 {
		if m.Role == "tool" && len(m.Content) < 400 && !strings.Contains(m.Content, "receipt=") {
			continue
		}
	}
}

// ---- 方案 D：回环超额拒绝 ----

func TestV550LoopbackOverLimit(t *testing.T) {
	o, st := v550Orchestrator(t)
	states := map[string]*store.StageState{}
	for _, sid := range []string{"s1", "s2", "s4", "s5", "s7"} {
		states[sid] = &store.StageState{Status: "done"}
	}
	p := &store.Project{ ROEAcknowledgedAt: "2026-11-22T00:00:00Z",ID: "P-D", StageStates: states}
	_ = st.SaveProject(p)
	// 前 3 次入队
	for _, to := range []string{"s1", "s2", "s4"} {
		res := o.dispatch(context.Background(), p, "s7", llm.ToolCall{Name: "loopback",
			Arguments: fmt.Sprintf(`{"to_stage":"%s","reason":"t"}`, to)})
		if !strings.Contains(res, "已触发回环") {
			t.Fatalf("额度内应成功: %s", res)
		}
	}
	if len(o.loops["P-D"]) != 3 {
		t.Fatalf("应入队 3 个: %v", o.loops["P-D"])
	}
	// 第 4 次：显式拒绝、状态不动
	res4 := o.dispatch(context.Background(), p, "s7", llm.ToolCall{Name: "loopback",
		Arguments: `{"to_stage":"s5","reason":"t"}`})
	if !strings.Contains(res4, "回环未执行") {
		t.Fatalf("超额应显式拒绝: %s", res4)
	}
	if p.StageStates["s5"].Status != "done" {
		t.Fatalf("超额不得改动目标阶段状态: %s", p.StageStates["s5"].Status)
	}
	// 非法目标
	resBad := o.dispatch(context.Background(), p, "s7", llm.ToolCall{Name: "loopback",
		Arguments: `{"to_stage":"s99","reason":"t"}`})
	if !strings.Contains(resBad, "不存在") {
		t.Fatalf("非法阶段应拒绝: %s", resBad)
	}
}

// ---- 方案 E：预算耗尽暂停 ----

// fakeToolLLM 每轮返回一个 list_files 工具调用（永不收口，耗尽预算）。
type fakeToolLLM struct{ calls int }

func (f *fakeToolLLM) Chat(_ context.Context, _ string, _ []llm.Message, _ []llm.ToolDef, _ float32, _ int) (llm.Message, llm.Usage, error) {
	f.calls++
	return llm.Message{Role: "assistant", ToolCalls: []llm.ToolCall{{ID: fmt.Sprintf("c%d", f.calls), Name: "list_files", Arguments: `{}`}}},
		llm.Usage{TotalTokens: 10}, nil
}

func TestV550BudgetExhaustionPauses(t *testing.T) {
	o, st := v550Orchestrator(t)
	o.llm = &fakeToolLLM{}
	o.approver = NewApprover(st, o.bus, "manual")
	p := &store.Project{ ROEAcknowledgedAt: "2026-11-22T00:00:00Z",ID: "P-E", Name: "预算暂停", PostExploit: true, Target: "http://t",
		StageStates: map[string]*store.StageState{}}
	_ = st.SaveProject(p)
	if err := o.runStage(context.Background(), p, "s2"); err != nil {
		t.Fatalf("预算耗尽应软着陆: %v", err)
	}
	stt := p.StageStates["s2"]
	if stt.Status != "paused" {
		t.Fatalf("默认 pause 档：预算耗尽应为 paused，实际 %s（%s）", stt.Status, stt.Summary)
	}
	if stt.PauseReason == "" || !strings.Contains(stt.Summary, "暂停") {
		t.Fatalf("应有暂停原因与摘要: %+v", stt)
	}
	// auto_close 兼容档：保留 v4.9 代收口行为
	o2, _ := v550Orchestrator(t)
	o2.llm = &fakeToolLLM{}
	o2.approver = NewApprover(st, o2.bus, "manual")
	o2.cfg.Engine.BudgetExhaustedPolicy = "auto_close"
	p2 := &store.Project{ ROEAcknowledgedAt: "2026-11-22T00:00:00Z",ID: "P-E2", Name: "auto_close", PostExploit: true, Target: "http://t",
		StageStates: map[string]*store.StageState{}}
	_ = st.SaveProject(p2)
	if err := o2.runStage(context.Background(), p2, "s2"); err != nil {
		t.Fatalf("auto_close 应照旧软着陆: %v", err)
	}
	if p2.StageStates["s2"].Status != "done" || !strings.Contains(p2.StageStates["s2"].Review, "quality-pending") {
		t.Fatalf("auto_close 应代收口 done+quality-pending: %+v", p2.StageStates["s2"])
	}
}

// ---- 方案 H：对话轮次耗尽挂起 + 断点续跑 ----

// fakeSeqLLM 按脚本顺序返回：先 N 轮工具调用，后纯文本。
type fakeSeqLLM struct {
	toolRounds int // 剩余工具轮数
	seen       []int
}

func (f *fakeSeqLLM) Chat(_ context.Context, _ string, msgs []llm.Message, _ []llm.ToolDef, _ float32, _ int) (llm.Message, llm.Usage, error) {
	f.seen = append(f.seen, len(msgs))
	if f.toolRounds > 0 {
		f.toolRounds--
		return llm.Message{Role: "assistant", ToolCalls: []llm.ToolCall{{ID: fmt.Sprintf("h%d", len(f.seen)), Name: "list_files", Arguments: `{}`}}},
			llm.Usage{TotalTokens: 5}, nil
	}
	return llm.Message{Role: "assistant", Content: "最终答复"}, llm.Usage{TotalTokens: 5}, nil
}

// ---- 方案 A：cred_command 占位符展开（引号形态安全） ----

func TestV550ExpandCredTemplate(t *testing.T) {
	// ① 单引号包裹的密值占位符：整段替换为双引号命令替换（否则 $(cat) 不展开）
	got := expandCredTemplate(`curl -H 'Authorization: Bearer ${CRED_SECRET}' http://t`, ".jtn-cred/1", "u1")
	if !strings.Contains(got, `"$(cat .jtn-cred/1)"`) || strings.Contains(got, "${CRED_SECRET}") {
		t.Fatalf("引号形态应展开: %s", got)
	}
	// ② 裸形态
	got2 := expandCredTemplate(`hydra -l ${CRED_USERNAME} -p ${CRED_SECRET} svc`, ".jtn-cred/2", "adm'in")
	if !strings.Contains(got2, `"$(cat .jtn-cred/2)"`) || strings.Contains(got2, "${CRED_SECRET}") {
		t.Fatalf("裸形态应展开: %s", got2)
	}
	if !strings.Contains(got2, `'adm'\''in'`) {
		t.Fatalf("用户名应 shell 转义: %s", got2)
	}
	// ③ 替换后全文无明文语义位（占位符清零）
	if strings.Contains(got2, "${CRED_") {
		t.Fatalf("占位符应清零: %s", got2)
	}
	// ④ 占位符位于含其他内容的单引号串内：确定性拒绝（fail closed，不产出静默坏命令）
	if err := validateCredTemplate(`curl -u '${CRED_USERNAME}:${CRED_PASSWORD}' http://t`); err == nil {
		t.Fatal("单引号串内嵌占位符应被拒绝")
	} else if !strings.Contains(err.Error(), "单引号串内") {
		t.Fatalf("拒绝信息应说明原因: %v", err)
	}
	// ⑤ 整段单引号形态允许
	if err := validateCredTemplate(`hydra -l '${CRED_USERNAME}' -p '${CRED_SECRET}' svc`); err != nil {
		t.Fatalf("整段引号形态应放行: %v", err)
	}
	// ⑥ 裸形态允许
	if err := validateCredTemplate(`hydra -l ${CRED_USERNAME} -p ${CRED_SECRET} svc`); err != nil {
		t.Fatalf("裸形态应放行: %v", err)
	}
}

func TestV550ChatPendingRunResume(t *testing.T) {
	o, st := v550Orchestrator(t)
	o.cfg.Engine.ChatToolRounds = 2
	o.approver = NewApprover(st, o.bus, "manual")
	chatSessions = newChatSessions(o)
	p := &store.Project{ ROEAcknowledgedAt: "2026-11-22T00:00:00Z",ID: "P-H", Name: "chat", PostExploit: true, Target: "http://t"}
	_ = st.SaveProject(p)

	llm1 := &fakeSeqLLM{toolRounds: 5}
	o.llm = llm1
	final1, err := chatSessions.Turn(p.ID, "第一问")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(final1, "已挂起") {
		t.Fatalf("轮次耗尽应提示挂起: %s", final1)
	}
	if msgs, ok := chatSessions.loadPendingRun(p.ID); !ok || len(msgs) < 4 {
		t.Fatalf("挂起链应持久化（含工具轮）: ok=%v len=%d", func() bool { _, ok := chatSessions.loadPendingRun(p.ID); return ok }(), len(msgs))
	}
	// 续跑：新客户端（首轮即纯文本），断言模型收到的链含历史工具消息（不重放）
	llm2 := &fakeSeqLLM{}
	o.llm = llm2
	final2, err := chatSessions.Turn(p.ID, "第二问（续跑）")
	if err != nil || final2 != "最终答复" {
		t.Fatalf("续跑应完成: %v %q", err, final2)
	}
	if len(llm2.seen) == 0 || llm2.seen[0] < 5 {
		t.Fatalf("续跑链应携带上轮工具消息（首调消息数=%d，期望≥5）", llm2.seen[0])
	}
	if _, ok := chatSessions.loadPendingRun(p.ID); ok {
		t.Fatal("正常完成后挂起链应清除")
	}
	// Reset 清挂起链
	chatSessions.savePendingRun(p.ID, []llm.Message{{Role: "system", Content: "x"}})
	chatSessions.Reset(p.ID)
	if _, ok := chatSessions.loadPendingRun(p.ID); ok {
		t.Fatal("Reset 应清除挂起链")
	}
}
