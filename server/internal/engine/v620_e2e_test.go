package engine

// v6.2.0 端到端补验：新门经真实 dispatch 链路生效（非仅直调内部函数）。
// 项目测试惯例为 deterministicGate 直测（engine_test.go:775 注释）——本文件补 dispatch 级
// 三条真实入口：complete_stage（s2 收口门拦截+齐备放行全路径，stub LLM 驱动反思门）、
// run_batch（逐目标范围门）、run_command（-l 清单范围门）。另验 config.Load 真实加载路径
// 的开关回退与 LoadHeads/LoadSkills 对本次修改文件的解析。

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"jiutouniao/internal/config"
	"jiutouniao/internal/llm"
	"jiutouniao/internal/store"
)

// passThroughClient 反思门 stub：恒返回 PASS（只驱动收口流程，不参与判定——判定在确定性门）。
type passThroughClient struct{}

func (passThroughClient) Chat(_ context.Context, _ string, _ []llm.Message, _ []llm.ToolDef, _ float32, _ int) (llm.Message, llm.Usage, error) {
	return llm.Message{Role: "assistant", Content: "PASS"}, llm.Usage{}, nil
}

func v620E2EProject(t *testing.T, o *Orchestrator, id, targets string) *store.Project {
	t.Helper()
	p := &store.Project{ID: id, Name: "v620端到端", Target: targets,
		Authorized: true, StrictScope: false, ROEAcknowledgedAt: "2026-11-23T00:00:00Z",
		StageStates: map[string]*store.StageState{"s2": {Status: "running", StartedAt: "2026-11-23T00:00:00Z"}}}
	_ = o.store.SaveProject(p)
	registerS2StepSubtasks(t, o, p.ID)
	return p
}

// complete_stage 真实 dispatch：无交付物 → S2 确定性门前置拦截（反思门之前，无需 LLM）。
func TestV620E2ES2ClosureGateDispatch(t *testing.T) {
	o, _ := v48Orchestrator(t)
	p := v620E2EProject(t, o, "P-V620-E1", "a.test")
	resp := o.dispatch(context.Background(), p, "s2", llm.ToolCall{Name: "complete_stage", Arguments: `{"summary":"测试"}`})
	if !strings.Contains(resp, "收口被拦截（S2 确定性门）") {
		t.Fatalf("complete_stage 真实链路未触发 S2 收口门: %s", resp)
	}
	if !strings.Contains(resp, "s2-攻击面地图.md") || !strings.Contains(resp, "拓扑重建-V1.md") {
		t.Fatalf("拦截文案应列出确切缺失项: %s", resp)
	}
}

// complete_stage 真实 dispatch：交付物齐备 → 前置门过 → 反思门（stub PASS）→
// deterministicGate（s2 已入无条件名单）→ 阶段收口。坏 JSON checklist 在反思门之前的前置门拦截。
func TestV620E2ES2ClosureGatePassThrough(t *testing.T) {
	o, _ := v48Orchestrator(t)
	o.llm = passThroughClient{}
	p := v620E2EProject(t, o, "P-V620-E2", "a.test")
	for f, body := range s2GateFixture {
		_, _ = o.exec.WriteFile(p.ID, f, body)
	}
	_, _ = o.exec.WriteFile(p.ID, "checklist.json", `{"items":[{"id":"C1","item":"登录功能","hint":"/login","class":"弱口令"}]}`)
	resp := o.dispatch(context.Background(), p, "s2", llm.ToolCall{Name: "complete_stage", Arguments: `{"summary":"S2 攻击面收敛"}`})
	if !strings.HasPrefix(resp, "阶段已收口") {
		t.Fatalf("交付物齐备应放行收口: %s", resp)
	}
	// 坏 JSON → 前置门 fail-closed 拦截（真实链路，不待下游 G2 静默失效）
	_, _ = o.exec.WriteFile(p.ID, "checklist.json", `{"items":[{"id":"C1" `)
	resp2 := o.dispatch(context.Background(), p, "s2", llm.ToolCall{Name: "complete_stage", Arguments: `{"summary":"S2 攻击面收敛"}`})
	if !strings.Contains(resp2, "checklist.json 存在但不可解析") {
		t.Fatalf("坏 JSON checklist 应在收口当轮拦截: %s", resp2)
	}
}

// run_batch 真实 dispatch：targets 含 shadow_pending → 逐目标范围门拒整批。
func TestV620E2EBatchScopeDispatch(t *testing.T) {
	o, _ := v48Orchestrator(t)
	p := v620E2EProject(t, o, "P-V620-E3", "a.test")
	_, _ = o.store.AddAsset(&store.Asset{ProjectID: p.ID, Stage: "s1", Type: "域名",
		Value: "shadow.test", ScopeStatus: "shadow_pending", Source: "CT 线索"})
	resp := o.dispatch(context.Background(), p, "s2", llm.ToolCall{Name: "run_batch",
		Arguments: `{"command":"httpx -t {{TARGET}} -rate-limit 20","targets":"a.test\nshadow.test","reason":"批量存活探测"}`})
	if !strings.Contains(resp, "拒绝整批") || !strings.Contains(resp, "shadow.test") {
		t.Fatalf("run_batch 真实链路未拒 shadow 目标: %s", resp)
	}
}

// run_command 真实 dispatch：-l 指向工作区清单（含 shadow 行）→ 批量清单范围门拦截。
func TestV620E2ETargetListDispatch(t *testing.T) {
	o, _ := v48Orchestrator(t)
	p := v620E2EProject(t, o, "P-V620-E4", "a.test")
	_, _ = o.store.AddAsset(&store.Asset{ProjectID: p.ID, Stage: "s1", Type: "域名",
		Value: "shadow.test", ScopeStatus: "shadow_pending", Source: "CT 线索"})
	_, _ = o.exec.WriteFile(p.ID, "targets.txt", "a.test\nshadow.test\n")
	resp := o.dispatch(context.Background(), p, "s2", llm.ToolCall{Name: "run_command",
		Arguments: `{"command":"httpx -l targets.txt -title -rate-limit 20","reason":"批量存活探测"}`})
	if !strings.Contains(resp, "批量清单范围门") || !strings.Contains(resp, "shadow.test") {
		t.Fatalf("run_command -l 真实链路未拦截: %s", resp)
	}
}

// config.Load 真实加载路径：guard 开关缺省 true（applyDefaults setTrue），显式 false 才回退。
func TestV620E2EConfigLoadGuardFlags(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.json")
	_ = os.WriteFile(cfgPath, []byte(`{"llm":{"model":"m","api_key":"k"},"admin_password":"x","guard":{"enforce_s2_closure":false}}`), 0o600)
	c, err := config.Load(cfgPath)
	if err != nil {
		t.Fatalf("config.Load 失败: %v", err)
	}
	if c.Guard.EnforceS2Closure == nil || *c.Guard.EnforceS2Closure {
		t.Fatalf("显式 false 应回退 enforce_s2_closure")
	}
	if c.Guard.EnforceBatchScope == nil || !*c.Guard.EnforceBatchScope {
		t.Fatalf("未配置的 enforce_batch_scope 应缺省 true")
	}
	_ = os.WriteFile(cfgPath, []byte(`{"llm":{"model":"m","api_key":"k"},"admin_password":"x"}`), 0o600)
	c2, err := config.Load(cfgPath)
	if err != nil {
		t.Fatalf("config.Load 失败: %v", err)
	}
	if c2.Guard.EnforceS2Closure == nil || !*c2.Guard.EnforceS2Closure {
		t.Fatalf("缺省应归一为 true")
	}
}

// LoadHeads 真实解析：本次修改的 s2.md/s3.md frontmatter 完整、正文含新契约。
func TestV620E2ELoadHeadsRepo(t *testing.T) {
	heads, err := LoadHeads(filepath.Join("..", "..", "..", "heads"))
	if err != nil {
		t.Fatalf("LoadHeads 解析失败（frontmatter/正文格式漂移）: %v", err)
	}
	s2, ok := heads["s2"]
	if !ok || strings.Trim(s2.Stage, `"`) != "2" || s2.Kind != "stage" {
		t.Fatalf("s2 头解析异常: %+v", s2)
	}
	if !strings.Contains(s2.Body, "deliverables/s2-已知漏洞候选清单.md") || !strings.Contains(s2.Body, "连续两类探针") {
		t.Fatalf("s2 头正文未包含 v6.2.0 新契约")
	}
	s3, ok := heads["s3"]
	if !ok || !strings.Contains(s3.Body, "deliverables/s2-已知漏洞候选清单.md") {
		t.Fatalf("s3 头正文未包含 S3-6 固定路径")
	}
}

// LoadSkills 真实解析：本次修改的技能 frontmatter（osint-leak-intel 引号 tags、
// recon-playbook 多关键词 tags、jwt-crypto s2）全部可被引擎加载器消费，
// 且 manifest 一并入库不报错。
func TestV620E2ELoadSkillsRepo(t *testing.T) {
	reg, err := LoadSkills(filepath.Join("..", "..", "..", "skills"))
	if err != nil {
		t.Fatalf("LoadSkills 解析失败: %v", err)
	}
	if len(reg.skills) < 100 {
		t.Fatalf("技能载入数异常: %d", len(reg.skills))
	}
	for _, id := range []string{"recon-playbook", "osint-leak-intel", "jwt-crypto", "request-smuggling", "instance-diff", "auth-flow-deep", "cloud-security"} {
		if _, ok := reg.skills[id]; !ok {
			t.Fatalf("技能 %s 未被引擎加载器载入", id)
		}
	}
}
