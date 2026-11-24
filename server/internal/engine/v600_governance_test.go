// v6.0.0 治理贯通单测：①预批准（all 全通过/类别/none 回退）②执行档派生（effectiveWritePolicy/
// expansionMode 三层参数）③scopeGate expansion 接线（发现驱动授权扩展工单→批准登记资产→放行）。
package engine

import (
	"context"
	"strings"
	"testing"

	"jiutouniao/internal/store"
)

// ---- ① 预批准 ----

func TestV600PreApprovedAllAutoPass(t *testing.T) {
	ap, st := testApprover(t)
	// all=全通过：提权类 L2 工单即时自动批准（含后续新增类别，无需登记关键词）
	p := &store.Project{ ROEAcknowledgedAt: "2026-11-22T00:00:00Z",ID: "P-V600-A", Name: "全通过", PreApproved: "all"}
	_ = st.SaveProject(p)
	res, err := ap.Request(context.Background(), p.ID, "s6", "【提权】SUID find 本地提权验证", "L2")
	if err != nil || res != "auto-approved" {
		t.Fatalf("all 档 L2 应即时自动批准: res=%s err=%v", res, err)
	}
	aps, _ := st.ListApprovals(p.ID)
	if len(aps) != 1 || aps[0].Status != "approved" || !strings.Contains(aps[0].DecidedBy, "pre-approved") {
		t.Fatalf("工单应 approved 且 DecidedBy 含 pre-approved: %+v", aps)
	}
}

func TestV600PreApprovedNoneFallsBackToManual(t *testing.T) {
	ap, st := testApprover(t)
	p := &store.Project{ ROEAcknowledgedAt: "2026-11-22T00:00:00Z",ID: "P-V600-B", Name: "默认", PreApproved: ""}
	_ = st.SaveProject(p)
	ap.SetWaitTimeout(1) // 屏障超时语义（barrier_timeout_sec）：1s 后工单 expired、Request 返回 timeout
	res, err := ap.Request(context.Background(), p.ID, "s6", "【提权】验证", "L2")
	if err != nil {
		t.Fatalf("不应返回 error（屏障超时走保守路径）: %v", err)
	}
	if res != "timeout" {
		t.Fatalf("none 档应回人工等待路径（屏障超时=timeout）: %s", res)
	}
	aps, _ := st.ListApprovals(p.ID)
	if len(aps) != 1 || aps[0].Status != "expired" {
		t.Fatalf("超时工单应落库 expired: %+v", aps)
	}
}

func TestV600PreApprovedCategoryMatch(t *testing.T) {
	ap, st := testApprover(t)
	p := &store.Project{ ROEAcknowledgedAt: "2026-11-22T00:00:00Z",ID: "P-V600-C", Name: "类别档", PreApproved: "privesc,lateral"}
	_ = st.SaveProject(p)
	if res, _ := ap.Request(context.Background(), p.ID, "s6", "【横向】凭据复用 SMB 枚举", "L2"); res != "auto-approved" {
		t.Fatalf("类别命中应自动批准: %s", res)
	}
	ap.SetWaitTimeout(1)
	if res, _ := ap.Request(context.Background(), p.ID, "s6", "批量导出用户表数据", "L2"); res != "timeout" {
		t.Fatalf("类别未命中应走人工路径（屏障超时=timeout）: %s", res)
	}
}

func TestV600NormalizePreApproved(t *testing.T) {
	cases := map[string]string{
		"": "none", "none": "none", "all": "all", "ALL": "all",
		"privesc": "privesc", " privesc , lateral ": "privesc,lateral",
		"bogus": "none", "privesc,bogus": "privesc",
	}
	for in, want := range cases {
		if got := store.NormalizePreApproved(in); got != want {
			t.Fatalf("NormalizePreApproved(%q)=%q want %q", in, got, want)
		}
	}
}

// ---- ② 三层治理参数派生 ----

func TestV600EffectiveWritePolicyAndExpansion(t *testing.T) {
	o, st := v48Orchestrator(t)
	lab := &store.Project{ ROEAcknowledgedAt: "2026-11-22T00:00:00Z",ID: "P-V600-D", Name: "靶场", ExecutionProfile: "isolated_lab"}
	prod := &store.Project{ ROEAcknowledgedAt: "2026-11-22T00:00:00Z",ID: "P-V600-E", Name: "生产", ExecutionProfile: "production_safe"}
	_ = st.SaveProject(lab)
	_ = st.SaveProject(prod)
	// 第 2 层：无部署级 YAML → 按执行档派生
	if o.effectiveWritePolicy(lab) != "full" {
		t.Fatal("isolated_lab 无 YAML 应派生 full 写策略")
	}
	if o.effectiveWritePolicy(prod) != "unset" {
		t.Fatal("production_safe 无 YAML 应派生 unset（写门不武装——生产写操作按审批矩阵，历史行为不变）")
	}
	if o.expansionMode(lab) != "auto-with-approval" {
		t.Fatal("isolated_lab 无 YAML 应派生 auto-with-approval")
	}
	if o.expansionMode(prod) != "deny" {
		t.Fatal("production_safe 无 YAML 应派生 deny")
	}
	// 第 1 层：部署级 YAML 覆盖派生（全项目生效）
	o.roe = &ROEProfile{Values: map[string]string{"write_policy": "existence-proof", "expansion": "auto"}}
	if o.effectiveWritePolicy(lab) != "existence-proof" || o.expansionMode(prod) != "auto" {
		t.Fatal("部署级 YAML 应覆盖派生值")
	}
	// 第 3 层：YAML expansion 非法值 → deny（fail-closed）
	o.roe = &ROEProfile{Values: map[string]string{"write_policy": "full", "expansion": "bogus"}}
	if o.expansionMode(lab) != "deny" || o.effectiveWritePolicy(prod) != "full" {
		t.Fatal("YAML 非法 expansion 应回 deny；write_policy=full 应全项目生效")
	}
	o.roe = nil
}

// ---- ③ scopeGate expansion 接线 ----

func TestV600ScopeGateExtensionTicket(t *testing.T) {
	o, st := v48Orchestrator(t)
	p := &store.Project{ ROEAcknowledgedAt: "2026-11-22T00:00:00Z",ID: "P-V600-F", Name: "扩展", Target: "10.0.0.1",
		ExecutionProfile: "isolated_lab", StrictScope: true}
	_ = st.SaveProject(p)
	// 立足点发现证据：172.33.0.40 出现在证据链 → 可走 expansion 通道
	_, _ = st.AddEvidence(&store.EvidenceRecord{ProjectID: p.ID, Stage: "s5", Type: "command",
		Input: "cat pwned.txt", Output: "fs01=172.33.0.40 nas02 creds"})
	// 已发现范围外目标：生成授权扩展工单（而非硬拦放弃）
	blocked, msg := o.scopeGate(p, "curl -s http://172.33.0.40/")
	if !blocked || !strings.Contains(msg, "授权扩展工单") {
		t.Fatalf("已发现目标应走扩展工单通道: blocked=%v msg=%s", blocked, msg)
	}
	aps, _ := st.ListApprovals(p.ID)
	if len(aps) != 1 || aps[0].Kind != "scope_extension" || aps[0].Target != "172.33.0.40" {
		t.Fatalf("应生成 1 张 scope_extension 工单: %+v", aps)
	}
	// 幂等：重复命中不重复开单
	_, msg2 := o.scopeGate(p, "curl -s http://172.33.0.40/")
	aps2, _ := st.ListApprovals(p.ID)
	if len(aps2) != 1 || !strings.Contains(msg2, "在批") {
		t.Fatalf("重复命中应复用在批工单: n=%d msg=%s", len(aps2), msg2)
	}
	// 批准回调：登记资产 → scopeGate 白名单自动纳入 → 放行
	if err := o.ApplyScopeExtension(p.ID, "172.33.0.40"); err != nil {
		t.Fatalf("扩展回调失败: %v", err)
	}
	if blocked3, _ := o.scopeGate(p, "curl -s http://172.33.0.40/"); blocked3 {
		t.Fatal("扩展批准后目标应在白名单放行")
	}
	// 未发现目标：任何档维持硬拦（范围门不因 expansion 变橡皮章）
	blocked4, msg4 := o.scopeGate(p, "curl -s http://9.9.9.9/")
	if !blocked4 || strings.Contains(msg4, "授权扩展工单") {
		t.Fatalf("未发现目标应维持硬拦且不开工单: msg=%s", msg4)
	}
	// 生产档对照：派生 deny，已发现目标也硬拦（通用型缺省收紧）
	p2 := &store.Project{ ROEAcknowledgedAt: "2026-11-22T00:00:00Z",ID: "P-V600-G", Name: "生产对照", Target: "10.0.0.1",
		ExecutionProfile: "production_safe", StrictScope: true}
	_ = st.SaveProject(p2)
	_, _ = st.AddEvidence(&store.EvidenceRecord{ProjectID: p2.ID, Stage: "s5", Type: "command",
		Input: "cat pwned.txt", Output: "fs01=172.33.0.40"})
	if blocked5, msg5 := o.scopeGate(p2, "curl -s http://172.33.0.40/"); !blocked5 || strings.Contains(msg5, "授权扩展工单") {
		t.Fatalf("生产档应维持硬拦不开工单: msg=%s", msg5)
	}
}

// ---- ④ 声明文件锁定：随包 YAML 必须可被引擎解析（fail-fast 前移到 CI）----

func TestV600PolicyYamlsLoadable(t *testing.T) {
	if _, err := LoadExecutionProfiles("../../../policies/execution-profiles.yaml"); err != nil {
		t.Fatalf("execution-profiles.yaml 应可解析: %v", err)
	}
	ep, err := LoadROEProfile("../../../policies/roe-profile.example.yaml")
	if err != nil {
		t.Fatalf("roe-profile.example.yaml 应可解析: %v", err)
	}
	if ep.WritePolicy() != "full" {
		t.Fatalf("覆盖模板 write_policy 应为 full: %s", ep.WritePolicy())
	}
	if m := strings.ToLower(strings.TrimSpace(ep.Values["expansion"])); m != "auto-with-approval" {
		t.Fatalf("覆盖模板 expansion 应为 auto-with-approval: %q", ep.Values["expansion"])
	}
}
