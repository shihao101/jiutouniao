package engine

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

// TestSpecAAIFaceHandoverBlock v6.6.0 SP-⑦：specA 上下文包注入「S4 AI 面移交」块（AI 面发现 +
// AI 类资产 + 判定表 AI:specA 行指针）；无 AI 面产出时不占位；s4/s5 等其他阶段不受影响。
func TestSpecAAIFaceHandoverBlock(t *testing.T) {
	dir := t.TempDir()
	st, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	o := &Orchestrator{store: st, exec: newTestExec(t, dir), cfg: &config.Config{Engine: config.EngineConfig{PerTargetRounds: 10}}}
	o.heads = map[string]*Head{}
	p := &store.Project{ROEAcknowledgedAt: "2026-11-23T00:00:00Z", ID: "P-SP7", Name: "AI目标",
		Target: "chat.test", Specializations: []string{"A"}}
	_ = st.SaveProject(p)
	_, _ = st.AddFinding(&store.Finding{ProjectID: p.ID, Stage: "s4", Title: "LLM01 提示注入面排查",
		Severity: "中", Confidence: "疑似", Detail: "系统提示面存在间接注入通道（LLM0x 映射待深测）"})
	_, _ = st.AddAsset(&store.Asset{ProjectID: p.ID, Type: "AI应用", Value: "chat.test", ScopeStatus: "shadow_pending", ScopeEvidence: ""})
	if _, err := o.exec.WriteFile(p.ID, "deliverables/s3-筛查矩阵判定表.md",
		"# 判定表\n| C-13 | chat.test | 输入面 | 假设 | evidence/x.md | TH-1（AI:specA 承接） |\n"); err != nil {
		t.Fatal(err)
	}

	out := o.buildContextPack(p, "specA")
	for _, want := range []string{"S4 AI 面移交", "LLM01 提示注入面排查", "AI 类资产", "登记≠授权", "AI:specA 承接行"} {
		if !strings.Contains(out, want) {
			t.Errorf("specA 上下文缺少 %q", want)
		}
	}
	// s4 阶段不受影响（块仅 specA 注入）
	if out4 := o.buildContextPack(p, "s4"); strings.Contains(out4, "S4 AI 面移交（v6.6.0 SP-⑦") {
		t.Error("S4 阶段不应注入 specA 专属块")
	}
}

// TestReflectSpecChecklistSections v6.6.0 SP-⑧：反思门三专项核查节落位（源码级断言——
// 问句含判定纪律关键词，与 s3/s7/s8 专项节同款机制）。
func TestReflectSpecChecklistSections(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "server/internal/engine/expert.go"))
	if err != nil {
		t.Skipf("仓库文件不可达: %v", err)
	}
	code := string(raw)
	for _, want := range []string{
		"专项A 核查（AI/LLM 目标判定纪律）", "而非模型复述恶意内容", "原文是否落库",
		"专项B1 核查（APP 双链判定纪律）", "静态直升确证", "客户端检测绕过是否被单独确证为服务端授权缺陷",
		"专项B2 核查（小程序判定纪律）", "越出平台边界", "解包子包覆盖率与解析失败项",
	} {
		if !strings.Contains(code, want) {
			t.Errorf("reflectStage 缺少专项核查要素 %q", want)
		}
	}
}

// TestSpecHeadsProcessSemantics v6.6.0 SP-⑩：三头回环语义/早退分支落位（源码级断言）。
func TestSpecHeadsProcessSemantics(t *testing.T) {
	for id, want := range map[string][]string{
		"heads/specA.md":  {"## 流程语义（v6.6.0 SP-⑩）", "前提不成立", "loopback(to_stage=specA)", "禁止虚构测试动作"},
		"heads/specB1.md": {"编号消歧", "专项内部链编号", "loopback(to_stage=specB1)"},
		"heads/specB2.md": {"## 流程语义（v6.6.0 SP-⑩）", "loopback(to_stage=specB2)", "前提不成立"},
	} {
		raw, err := os.ReadFile(filepath.Join("..", "..", "..", id))
		if err != nil {
			t.Skipf("仓库文件不可达: %v", err)
		}
		for _, kw := range want {
			if !strings.Contains(string(raw), kw) {
				t.Errorf("%s 缺少 %q", id, kw)
			}
		}
	}
}

// captureClient SP-⑧ 行为级验证：捕获反思门提示词后恒回 PASS。
type captureClient struct{ prompt string }

func (c *captureClient) Chat(_ context.Context, _ string, msgs []llm.Message, _ []llm.ToolDef, _ float32, _ int) (llm.Message, llm.Usage, error) {
	for _, m := range msgs {
		c.prompt += m.Role + ":" + m.Content + "\n"
	}
	return llm.Message{Role: "assistant", Content: "PASS"}, llm.Usage{}, nil
}

// TestReflectStageSpecChecklistInPrompt v6.6.0 SP-⑧：reflectStage(specX) 真实构建的审查提示词
// 含对应专项核查节（非源码断言，走 expert.go 真实构建路径）。
func TestReflectStageSpecChecklistInPrompt(t *testing.T) {
	o, st := v48Orchestrator(t)
	p := &store.Project{ROEAcknowledgedAt: "2026-11-23T00:00:00Z", ID: "P-SP8", Name: "AI",
		Target: "chat.test", Specializations: []string{"A"}}
	_ = st.SaveProject(p)
	cc := &captureClient{}
	o.llm = cc
	if _, _, err := o.reflectStage(context.Background(), p, "specA"); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"专项A 核查", "正/负/基线对照", "模型复述恶意内容", "原文是否落库"} {
		if !strings.Contains(cc.prompt, want) {
			t.Errorf("reflectStage(specA) 提示词缺 %q", want)
		}
	}
}
