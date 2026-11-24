// v6.6.0 历史项目回放（引擎真函数）：对隔离库副本 /tmp/v66-closure 的全部项目跑
// s1ClosureIssues / 授权门 / 影子门判定，验证新门对存量数据的行为。
// ⚠ 环境依赖测试（需 /tmp/v66-closure/jiutouniao.db 存在）——CI 缺席时 t.Skip。
package engine

import (
	"context"
	"os"
	"strings"
	"testing"

	"jiutouniao/internal/config"
	"jiutouniao/internal/events"
	"jiutouniao/internal/store"
	"jiutouniao/internal/tools"
)

func TestV66ReplayHistoricalProjects(t *testing.T) {
	if _, err := os.Stat("/tmp/v66-closure/jiutouniao.db"); err != nil {
		t.Skip("回放库副本不存在（/tmp/v66-closure），跳过环境回放")
	}
	cfg := &config.Config{}
	cfg.ApplyDefaultsForTest()
	cfg.DataDir = "/root/jiutouniao/projects" // 交付物/证据读原工作区（只读）
	st, err := store.Open(backfillDir())
	if err != nil {
		t.Skipf("回放库打开失败（容器持锁或副本缺失）: %v", err)
	}
	defer st.Close()
	gf, gh, gm, gr, gs := config.DefaultGuard()
	exec, err := tools.NewExecutor("/root/jiutouniao/projects", 10, 102400, struct {
		Forbidden, HighRisk, MedRisk, ReadOnly, Sensitive []string
	}{gf, gh, gm, gr, gs})
	if err != nil {
		t.Fatal(err)
	}
	o := &Orchestrator{store: st, exec: exec, bus: events.NewBus(), cfg: cfg,
		heads: map[string]*Head{}, running: map[string]context.CancelFunc{},
		tokens: map[string]int64{}, inputs: map[string][]string{}, loops: map[string][]string{},
		liveP: map[string]*store.Project{}, batchStats: map[string]*batchBudgetState{}}
	// 恢复 nil-guard 依赖：heads 索引（workspaceRoot 不依赖 heads）
	ps, err := st.ListProjects()
	if err != nil {
		t.Fatal(err)
	}
	pass4, fail4 := 0, 0
	authBlocks, shadowBlocks := 0, 0
	for _, p := range ps {
		s1 := p.StageStates["s1"]
		if s1 == nil || s1.Status != "done" {
			continue
		}
		// ④⑤⑪ 收口门真函数
		issues := o.s1ClosureIssues(p)
		if len(issues) == 0 {
			pass4++
		} else {
			fail4++
			if true { // v6.6.0 回放打印全集
				t.Logf("将拦截 %s（targets=%d）:%s", p.ID, len(splitProjectTargets(p)), strings.Join(issues[:minInt(2,len(issues))], " | "))
			}
		}
		// ① 授权门（历史项目全部 authorized=true → 应放行）
		if msg := o.governanceGates(p, "s2", "curl -s http://127.0.0.1:1/", "run_command", false); strings.Contains(msg, "授权未确认") {
			authBlocks++
		}
	}
	t.Logf("== 回放完成：s1=done 项目 %d 个；四件套门全绿 %d / 将拦截 %d；授权门误拦 %d ==", pass4+fail4, pass4, fail4, authBlocks)
	if fail4 > 0 {
		t.Logf("（预期行为）v6.1.0 门对旧 run 收口缺四件套的 %d 个项目将拦截——正是方案④针对的历史缺陷形态", fail4)
	}
	_ = shadowBlocks
}

func minInt(a, b int) int { if a < b { return a }; return b }

// backfillDir 环境变量可切换回放库副本（默认隔离副本；补录副本走 V66_BACKFILL=1）
func backfillDir() string {
	if os.Getenv("V66_BACKFILL") == "1" {
		return "/tmp/v66-backfill"
	}
	return "/tmp/v66-closure"
}

func TestV66ProbeDE4335A477(t *testing.T) {
	if os.Getenv("V66_BACKFILL") != "1" {
		t.Skip("仅补录副本环境")
	}
	cfg := &config.Config{}
	cfg.ApplyDefaultsForTest()
	cfg.DataDir = "/root/jiutouniao/projects"
	st, err := store.Open("/tmp/v66-backfill")
	if err != nil {
		t.Skipf("%v", err)
	}
	defer st.Close()
	gf, gh, gm, gr, gs := config.DefaultGuard()
	exec, err := tools.NewExecutor("/root/jiutouniao/projects", 10, 102400, struct {
		Forbidden, HighRisk, MedRisk, ReadOnly, Sensitive []string
	}{gf, gh, gm, gr, gs})
	if err != nil {
		t.Fatal(err)
	}
	o := &Orchestrator{store: st, exec: exec, bus: events.NewBus(), cfg: cfg,
		heads: map[string]*Head{}, running: map[string]context.CancelFunc{},
		tokens: map[string]int64{}, inputs: map[string][]string{}, loops: map[string][]string{},
		liveP: map[string]*store.Project{}, batchStats: map[string]*batchBudgetState{}}
	p, err := st.GetProject("某历史任务")
	if err != nil {
		t.Fatal(err)
	}
	issues := o.s1ClosureIssues(p)
	t.Logf("issues=%d: %v", len(issues), issues)
	for _, f := range s1RequiredDeliverables {
		_, err := o.exec.ReadFile(p.ID, f)
		t.Logf("ReadFile(%s) err=%v", f, err != nil)
	}
}
