// v5.4.0 回归测试：创建项目必须携带 ModelID（此前漏拷导致创建页选择模型静默失效，
// 32/32 项目 model_id 全空）。还原缺陷（删掉 CreateProject 的 ModelID 拷贝）本测试即抓出。
package engine

import (
	"context"
	"testing"

	"jiutouniao/internal/config"
	"jiutouniao/internal/events"
	"jiutouniao/internal/llm"
	"jiutouniao/internal/store"
)

func testOrchestratorForCreate(t *testing.T) *Orchestrator {
	t.Helper()
	dir := t.TempDir()
	st, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	return &Orchestrator{
		store: st, bus: events.NewBus(),
		heads: map[string]*Head{},
		running: map[string]context.CancelFunc{}, tokens: map[string]int64{},
		inputs: map[string][]string{}, loops: map[string][]string{},
		liveP: map[string]*store.Project{}, projModel: map[string]string{},
		batchStats: map[string]*batchBudgetState{}, modelWarn: map[string]bool{},
	}
}

func TestV540CreateProjectCarriesModelID(t *testing.T) {
	o := testOrchestratorForCreate(t)
	p, err := o.CreateProject(&store.Project{
		Name: "模型选择回归", Target: "http://127.0.0.1:1", Authorized: true,
		ModelID: "m-deepseek-test",
	})
	if err != nil {
		t.Fatalf("CreateProject: %v", err)
	}
	if p.ModelID != "m-deepseek-test" {
		t.Fatalf("ModelID 未随项目落库（回归复现）：got %q", p.ModelID)
	}
	// 持久化层验证：重新 GetProject 后字段仍在
	got, err := o.store.GetProject(p.ID)
	if err != nil {
		t.Fatalf("GetProject: %v", err)
	}
	if got.ModelID != "m-deepseek-test" {
		t.Fatalf("持久化后 ModelID 丢失：got %q", got.ModelID)
	}
}

func TestV540CreateProjectEmptyModelIDOK(t *testing.T) {
	o := testOrchestratorForCreate(t)
	p, err := o.CreateProject(&store.Project{Name: "默认模型", Target: "http://127.0.0.1:1", Authorized: true})
	if err != nil {
		t.Fatalf("CreateProject: %v", err)
	}
	if p.ModelID != "" {
		t.Fatalf("未选择模型时应为空：got %q", p.ModelID)
	}
}

// TestV540ClientForFallbackWarnOnce：项目指定模型不在注册表 → 回退默认且每项目只告警一次。
func TestV540ClientForFallbackWarnOnce(t *testing.T) {
	o := testOrchestratorForCreate(t)
	o.cfg = &config.Config{}
	o.llm = llm.NewMock()
	p, err := o.CreateProject(&store.Project{Name: "fallback", Target: "http://127.0.0.1:1", Authorized: true, ModelID: "gone"})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		cli, name := o.clientFor(p)
		if cli == nil {
			t.Fatal("clientFor 返回 nil client")
		}
		_ = name
	}
	o.projMu.Lock()
	warned := o.modelWarn[p.ID]
	o.projMu.Unlock()
	if !warned {
		t.Fatal("回退告警未记录（去重表应置位）")
	}
}
