package engine

// v6.2.0 S2 修复方案②回归：批量通道逐目标范围门。
// 覆盖：run_batch targets 逐目标（shadow 拒整批 / strict_scope 范围外拒 / in_scope 通过）、
// 工作区 `-l` 清单逐行（shadow 拦 / 词表路径与不存在文件不拦 / strict_scope 未登记子域拦）、
// guard.enforce_batch_scope 显式 false 回退。

import (
	"context"
	"strings"
	"testing"

	"jiutouniao/internal/store"
)

// batchScopeProject 构造批量范围门夹具项目（targets 参数为项目原始目标行）。
func batchScopeProject(t *testing.T, o *Orchestrator, id, targets string, strictScope bool) *store.Project {
	t.Helper()
	p := &store.Project{ID: id, Name: "S2批量范围", Target: targets,
		Authorized: true, StrictScope: strictScope, ROEAcknowledgedAt: "2026-11-23T00:00:00Z",
		StageStates: map[string]*store.StageState{"s2": {Status: "running"}}}
	_ = o.store.SaveProject(p)
	return p
}

func TestV620BatchRejectsShadowTarget(t *testing.T) {
	o, _ := v48Orchestrator(t)
	p := batchScopeProject(t, o, "P-V620-BS1", "a.test", false)
	_, _ = o.store.AddAsset(&store.Asset{ProjectID: p.ID, Stage: "s1", Type: "域名",
		Value: "shadow.test", ScopeStatus: "shadow_pending", Source: "CT 线索"})
	msg := o.toolRunBatch(context.Background(), p, "s2", "httpx -t {{TARGET}} -rate-limit 20",
		"a.test\nshadow.test", "", "批量存活探测")
	if !strings.Contains(msg, "拒绝整批") || !strings.Contains(msg, "shadow.test") {
		t.Fatalf("shadow 目标混入批量应拒整批并指明目标: %s", msg)
	}
	if !strings.Contains(msg, "record_asset") {
		t.Fatalf("拦截文案应给出先登记后批量的合法路径: %s", msg)
	}
}

func TestV620BatchRejectsOutOfScopeUnderStrictScope(t *testing.T) {
	o, _ := v48Orchestrator(t)
	p := batchScopeProject(t, o, "P-V620-BS2", "a.test", true)
	msg := o.toolRunBatch(context.Background(), p, "s2", "httpx -t {{TARGET}}",
		"a.test\nstranger.test", "", "批量存活探测")
	if !strings.Contains(msg, "拒绝整批") || !strings.Contains(msg, "stranger.test") {
		t.Fatalf("strict_scope 下未登记目标应拒整批: %s", msg)
	}
}

func TestV620BatchAllowsProjectTargets(t *testing.T) {
	o, _ := v48Orchestrator(t)
	p := batchScopeProject(t, o, "P-V620-BS3", "a.test\nb.test", false)
	_, _ = o.store.AddAsset(&store.Asset{ProjectID: p.ID, Stage: "s1", Type: "域名",
		Value: "b.test", ScopeStatus: "in_scope", ScopeEvidence: "项目授权清单"})
	for _, tgt := range []string{"a.test", "b.test"} {
		if v := o.singleTargetScopeViolations(p, tgt); v != "" {
			t.Fatalf("项目目标/有依据 in_scope 资产应通过逐目标校验: %s → %s", tgt, v)
		}
	}
}

func TestV620TargetListFileBlocksShadow(t *testing.T) {
	o, _ := v48Orchestrator(t)
	p := batchScopeProject(t, o, "P-V620-BS4", "a.test", false)
	_, _ = o.store.AddAsset(&store.Asset{ProjectID: p.ID, Stage: "s1", Type: "域名",
		Value: "shadow.test", ScopeStatus: "shadow_pending", Source: "CT 线索"})
	_, _ = o.exec.WriteFile(p.ID, "targets.txt", "a.test\nshadow.test\n# 注释行\n")
	msg := o.targetListScopeIssues(p, "s2", "run_command", "httpx -l targets.txt -title -rate-limit 20")
	if !strings.Contains(msg, "批量清单范围门") || !strings.Contains(msg, "shadow.test") {
		t.Fatalf("工作区 -l 清单含 shadow 目标应拦截: %s", msg)
	}
}

func TestV620TargetListFileAllowsInScopeAndIgnoresWordlists(t *testing.T) {
	o, _ := v48Orchestrator(t)
	p := batchScopeProject(t, o, "P-V620-BS5", "a.test\nb.test", false)
	_, _ = o.store.AddAsset(&store.Asset{ProjectID: p.ID, Stage: "s1", Type: "域名",
		Value: "b.test", ScopeStatus: "in_scope", ScopeEvidence: "项目授权清单"})
	_, _ = o.exec.WriteFile(p.ID, "targets.txt", "a.test\nb.test\n")
	// 工作区内全 in_scope 清单 → 放行
	if msg := o.targetListScopeIssues(p, "s2", "run_command", "httpx -l targets.txt -title"); msg != "" {
		t.Fatalf("全 in_scope 清单不应拦截: %s", msg)
	}
	// 容器词表路径（非工作区）不读不拦
	if msg := o.targetListScopeIssues(p, "s2", "run_command",
		"gobuster dir -u https://a.test -w /usr/share/seclists/rockyou.txt"); msg != "" {
		t.Fatalf("容器词表路径不应误拦: %s", msg)
	}
	// 工作区内不存在的清单文件 → 不拦（执行自然失败）
	if msg := o.targetListScopeIssues(p, "s2", "run_command", "httpx -l not-exist.txt"); msg != "" {
		t.Fatalf("不存在的清单文件不应拦截: %s", msg)
	}
}

func TestV620TargetListStrictScopeUnregisteredSubdomain(t *testing.T) {
	o, _ := v48Orchestrator(t)
	p := batchScopeProject(t, o, "P-V620-BS6", "a.test", true)
	_, _ = o.exec.WriteFile(p.ID, "subs.txt", "newsub.a.test\n")
	msg := o.targetListScopeIssues(p, "s2", "run_command", "httpx -l subs.txt -tech-detect")
	if !strings.Contains(msg, "批量清单范围门") || !strings.Contains(msg, "newsub.a.test") {
		t.Fatalf("strict_scope 下未登记新子域应拦截: %s", msg)
	}
	if !strings.Contains(msg, "record_asset") {
		t.Fatalf("拦截文案应指引先登记（v6.1.0 删除主域子域自动放行后的合法路径）: %s", msg)
	}
}

func TestV620BatchScopeRollbackFlag(t *testing.T) {
	o, _ := v48Orchestrator(t)
	p := batchScopeProject(t, o, "P-V620-BS7", "a.test", false)
	_, _ = o.store.AddAsset(&store.Asset{ProjectID: p.ID, Stage: "s1", Type: "域名",
		Value: "shadow.test", ScopeStatus: "shadow_pending", Source: "CT 线索"})
	_, _ = o.exec.WriteFile(p.ID, "targets.txt", "shadow.test\n")
	f := false
	o.cfg.Guard.EnforceBatchScope = &f
	if msg := o.targetListScopeIssues(p, "s2", "run_command", "httpx -l targets.txt"); msg != "" {
		t.Fatalf("enforce_batch_scope=false 应回退（事故手段）: %s", msg)
	}
}
