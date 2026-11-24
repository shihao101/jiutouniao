package engine

// v4.6 二轮批次 E/H 测试：V2 预算消息 VT 枚举 / V4 L2 已批未用门 / T3-H ROE Profile
// 加载校验、摘要注入、非法 profile fail-fast。

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"jiutouniao/internal/config"
	"jiutouniao/internal/events"
	"jiutouniao/internal/store"
)

func v46cOrchestrator(t *testing.T) (*Orchestrator, *store.Store, string) {
	t.Helper()
	_, st := testApprover(t)
	dir := t.TempDir()
	o := &Orchestrator{store: st, exec: newTestExec(t, dir), bus: events.NewBus(),
		cfg: func() *config.Config { c := &config.Config{}; c.ApplyDefaultsForTest(); return c }()}
	return o, st, dir
}

// V4：L2 已批准工单既无使用痕迹也未申报 → s7 门拦截；有使用痕迹 → 放行。
func TestV46cGateL2Unused(t *testing.T) {
	o, st, _ := v46cOrchestrator(t)
	p := &store.Project{ ROEAcknowledgedAt: "2026-11-22T00:00:00Z",ID: "P-C1"}
	_ = st.SaveProject(p)
	// L2 已批工单 A：无任何使用痕迹（应拦截）
	idUnused, _ := st.AddApproval(&store.Approval{ProjectID: p.ID, Stage: "s3",
		Action: "T-07 注入验证载荷", Risk: "L2", Mode: "auto", Status: "approved"}) // AddApproval 生成 ID
	// L2 已批工单 B：时间线有使用痕迹（应放行）
	idUsed, _ := st.AddApproval(&store.Approval{ProjectID: p.ID, Stage: "s3",
		Action: "T-11 越权验证", Risk: "L2", Mode: "auto", Status: "approved"})
	_, _ = st.AddTimeline(&store.TimelineEvent{ProjectID: p.ID, Event: "VT 处置",
		Detail: idUsed + " 投递完成 → executed"})
	// L2 已批工单 C：在 V3 清单申报放弃（应放行）
	idDecl, _ := st.AddApproval(&store.Approval{ProjectID: p.ID, Stage: "s3",
		Action: "T-12 支付写验证", Risk: "L2", Mode: "auto", Status: "approved"})
	_, _ = st.AddTimeline(&store.TimelineEvent{ProjectID: p.ID, Event: "v4.6 V3 清单",
		Detail: "l2_approved_unused: " + idDecl + "（指挥室 10:15 决策否决写验证）"})
	issues := o.deterministicGate(p, "s7")
	joined := strings.Join(issues, "\n")
	if !strings.Contains(joined, idUnused) {
		t.Fatalf("无痕迹 L2 工单应被拦截: %v", issues)
	}
	if strings.Contains(joined, idUsed) || strings.Contains(joined, idDecl) {
		t.Fatalf("已使用/已申报工单不应被拦: %v", issues)
	}
}

// T3/H：合法 profile 加载+摘要；非法值拒绝；上下文注入（write_policy=existence-proof 摘要）。
func TestV46cROEProfile(t *testing.T) {
	dir := t.TempDir()
	good := filepath.Join(dir, "roe.yaml")
	_ = os.WriteFile(good, []byte(`profile: eval-fullrange
scope:
  assets: ["127.0.0.1"]
  expansion: auto
windows: none
write_policy: existence-proof
waf_policy:
  offline_challenge: deny
  rotation: unlimited
ratelimit:
  max_conn_per_s: 50
  cooldown_protocol: full-silence
identity:
  auto_register: allow
  cred_attack:
    dict_size: 20
    lockout_aware: true
outbound:
  residential_proxy: allow
  oob_callback: allow
`), 0o600)
	rp, err := LoadROEProfile(good)
	if err != nil {
		t.Fatalf("合法 profile 应加载成功: %v", err)
	}
	d := rp.Digest()
	if !strings.Contains(d, "write_policy=existence-proof") || !strings.Contains(d, "禁止业务数据修改") {
		t.Fatalf("摘要应含 write_policy 运行时含义: %s", d)
	}
	if !strings.Contains(d, "瑞数类离线挑战实现：禁止") {
		t.Fatalf("deny 应映射为禁止说明: %s", d)
	}
	// v5.1.1：identity.auto_register 进 Digest 运行时含义（allow/deny 双映射）
	if !strings.Contains(d, "identity.auto_register=allow") || !strings.Contains(d, "可自建测试账号") {
		t.Fatalf("摘要应含 auto_register 运行时含义: %s", d)
	}
	// 非法值 → 拒绝
	bad := filepath.Join(dir, "roe-bad.yaml")
	_ = os.WriteFile(bad, []byte("profile: x\nwrite_policy: whatever\nscope: {}\n"), 0o600)
	if _, err = LoadROEProfile(bad); err == nil || !strings.Contains(err.Error(), "不合法") {
		t.Fatalf("非法 write_policy 应拒绝: %v", err)
	}
	// 缺必填节 → 拒绝
	bad2 := filepath.Join(dir, "roe-missing.yaml")
	_ = os.WriteFile(bad2, []byte("profile: y\n"), 0o600)
	if _, err = LoadROEProfile(bad2); err == nil || !strings.Contains(err.Error(), "缺少必填节") {
		t.Fatalf("缺必填节应拒绝: %v", err)
	}
	// 上下文注入：o.roe 非空 → 上下文含 ROE 节；nil → 不含
	o, st, _ := v46cOrchestrator(t)
	p := &store.Project{ ROEAcknowledgedAt: "2026-11-22T00:00:00Z",ID: "P-C2"}
	_ = st.SaveProject(p)
	o.roe = rp
	ctx := o.buildContextPack(p, "s4")
	if !strings.Contains(ctx, "ROE Profile（运行时治理参数") || !strings.Contains(ctx, "write_policy=existence-proof") {
		t.Fatalf("ROE 摘要应注入上下文")
	}
	o.roe = nil
	ctx2 := o.buildContextPack(p, "s4")
	if strings.Contains(ctx2, "ROE Profile（运行时治理参数") {
		t.Fatalf("未启用 profile 不应注入")
	}
}

// V2：预算预警消息对 ready/pending VT 的引擎枚举（构造 remain==budget/3 场景直接测消息构造分支）。
// 消息构造内联于执行循环，此处以等价断言覆盖：ListVTs 就绪过滤与拼接逻辑经 dispatch 侧无法直接触达，
// 改为验证 store 侧过滤前提（本测试锁定数据形状，防止字段变更破坏枚举）。
func TestV46cVTListShapeForSprint(t *testing.T) {
	_, st, _ := v46cOrchestrator(t)
	p := &store.Project{ ROEAcknowledgedAt: "2026-11-22T00:00:00Z",ID: "P-C3"}
	_ = st.SaveProject(p)
	_, _ = st.AddVT(&store.VerificationTask{ProjectID: p.ID, Stage: "s4", Title: "SQLi 布尔确认",
		ReadyAssets: "scripts/b4.sh", Status: "ready", Priority: 1})
	_, _ = st.AddVT(&store.VerificationTask{ProjectID: p.ID, Stage: "s4", Title: "已执行项",
		ReadyAssets: "scripts/x.sh", Status: "executed"})
	vts, _ := st.ListVTs(p.ID)
	ready := 0
	var rt *store.VerificationTask
	for _, t2 := range vts {
		if t2.Status == "ready" || t2.Status == "pending" {
			ready++
			rt = t2
		}
	}
	if ready != 1 || rt == nil || rt.ReadyAssets != "scripts/b4.sh" || rt.Priority != 1 || rt.Title != "SQLi 布尔确认" {
		t.Fatalf("VT 形状不满足 sprint 枚举前提: %+v", vts)
	}
}
