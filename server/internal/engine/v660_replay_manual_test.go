package engine

// 手动回放工具（v6.6.0 M1 验收：多目标/专项历史项目回放 deterministicGate(specX) 拦截差异）。
// 仅当 JTN_REPLAY_MANUAL=1 且 JTN_REPLAY_DIR 指向【隔离副本】（jiutouniao.db + 项目工作区拷贝）
// 时执行；CI/常规测试路径直接 Skip。回放只读项目数据，StreamRecord 写入发生在副本上。

import (
	"fmt"
	"os"
	"strings"
	"testing"

	"jiutouniao/internal/config"
	"jiutouniao/internal/events"
	"jiutouniao/internal/store"
	"jiutouniao/internal/tools"
)

func TestManualSpecGateReplay(t *testing.T) {
	if os.Getenv("JTN_REPLAY_MANUAL") != "1" {
		t.Skip("手动回放：需 JTN_REPLAY_MANUAL=1 + 隔离副本 JTN_REPLAY_DIR")
	}
	dir := os.Getenv("JTN_REPLAY_DIR")
	st, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	f, h, m, r, se := config.DefaultGuard()
	execr, err := tools.NewExecutor(dir, 10, 10240, struct {
		Forbidden, HighRisk, MedRisk, ReadOnly, Sensitive []string
	}{f, h, m, r, se})
	if err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{}
	cfg.ApplyDefaultsForTest()
	cfg.DataDir = dir
	o := &Orchestrator{store: st, exec: execr, bus: events.NewBus(), cfg: cfg, tokens: map[string]int64{}}

	projs, _ := st.ListProjects()
	isNewSpecIssue := func(s string) bool {
		for _, kw := range []string{"前置契约未登记", "缺少核心交付物", "专项条目清单", "分段收口对账"} {
			if strings.Contains(s, kw) {
				return true
			}
		}
		return false
	}
	var multi []string
	for _, pr := range projs {
		if pr == nil {
			continue
		}
		targets := splitProjectTargets(pr)
		if len(targets) > 1 {
			multi = append(multi, fmt.Sprintf("%s(%d目标: %s)", pr.ID, len(targets), truncateText(strings.Join(targets, "|"), 80)))
		}
	}
	fmt.Printf("=== 回放开始：项目 %d 个，多目标项目 %d 个 ===\n", len(projs), len(multi))
	for _, l := range multi {
		fmt.Println("  多目标:", l)
	}
	for _, tc := range []struct{ pid, stage string }{
		{os.Getenv("JTN_REPLAY_APP_PID"), "specB1"},
		{os.Getenv("JTN_REPLAY_AI_PID"), "specA"},
		{os.Getenv("JTN_REPLAY_MT_PID"), "specA"},
		{os.Getenv("JTN_REPLAY_MT_PID"), "specB1"},
	} {
		if tc.pid == "" {
			continue
		}
		p, err := st.GetProject(tc.pid)
		if err != nil || p == nil {
			t.Logf("项目 %s 不存在", tc.pid)
			continue
		}
		fmt.Printf("=== %s 回放 %s（目标 %d 个）===\n", tc.pid, tc.stage, len(splitProjectTargets(p)))
		if assets, aerr := st.ListAssets(tc.pid); aerr == nil {
			types := map[string]int{}
			for _, a := range assets {
				types[a.Type]++
			}
			fmt.Printf("  资产类型分布: %v（豁免判定依据）\n", types)
		}
		// 第四遍多目标回放演示（仅隔离副本）：注入合成 APP 资产 + 单目标 specB1 coverage，
		// 使 specB1 适用且 matched=1——逐目标门从 matched=0 提示级进入真实拦截路径。
		if tc.stage == "specB1" && tc.pid == os.Getenv("JTN_REPLAY_MT_PID") {
			_, _ = st.AddAsset(&store.Asset{ProjectID: tc.pid, Type: "APP（合成回放注入）",
				Value: "synthetic-app", ScopeStatus: "in_scope", ScopeEvidence: "隔离副本演示"})
			_, _ = st.UpsertCoverage(&store.CoverageEntry{ProjectID: tc.pid, Stage: "specB1",
				Endpoint: "https://zhihuihuli.hospital-nsmc.com.cn/", VulnClass: "认证", Status: "vulnerable",
				Notes: "回放注入的合成覆盖行"})
			fmt.Println("  （已向副本注入合成 APP 资产 + 1 条 specB1 覆盖行——演示多目标对账）")
		}
		if tc.stage == "specB1" && tc.pid == os.Getenv("JTN_REPLAY_MT_PID") {
			p.Target = p.Target + "\nsynthetic-extra.target.example\n"
			fmt.Println("  （已向副本项目追加第 7 个合成目标——裁决逐目标门拦截路径）")
		}
		issues := o.deterministicGate(p, tc.stage)
		newN, oldN := 0, 0
		for _, iss := range issues {
			tag := "既有通用"
			if isNewSpecIssue(iss) {
				tag = "★新专项门"
				newN++
			} else {
				oldN++
			}
			fmt.Printf("  [%s] %s\n", tag, truncateText(iss, 150))
		}
		fmt.Printf("  小计：新专项门拦截 %d 项 / 既有通用 %d 项（修复前新专项门 0 项——spec 无任何专属校验）\n", newN, oldN)
	}
}
