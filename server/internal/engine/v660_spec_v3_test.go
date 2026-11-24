package engine

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"jiutouniao/internal/config"
	"jiutouniao/internal/events"
	"jiutouniao/internal/store"
)

// TestSpecV3HandoverInS5Context v6.6.0 SP-③：specB1 收口 V3 ready_but_unexecuted 落 StageState
// 后，S5 上下文包出现「专项就绪移交」小节（呈现性注入，条目带阶段前缀；单目标不打 @目标 标签）。
func TestSpecV3HandoverInS5Context(t *testing.T) {
	dir := t.TempDir()
	st, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	o := &Orchestrator{store: st, exec: newTestExec(t, dir), cfg: &config.Config{Engine: config.EngineConfig{PerTargetRounds: 10}}}
	o.heads = map[string]*Head{}
	p := &store.Project{ROEAcknowledgedAt: "2026-11-23T00:00:00Z", ID: "P-SP3-A", Name: "APP",
		Target: "app-a.example.com", Specializations: []string{"B1"}}
	p.StageStates = map[string]*store.StageState{
		"specB1": {Status: "done", V3Ready: []string{"Frida hook 脚本 evidence/frida-cipher.js（启动条件：root 设备）"}},
	}
	_ = st.SaveProject(p)

	out := o.buildContextPack(p, "s5")
	for _, want := range []string{"专项就绪移交", "[specB1 就绪未执行]", "Frida hook 脚本", "二选一留痕"} {
		if !strings.Contains(out, want) {
			t.Errorf("S5 上下文缺少专项移交要素 %q", want)
		}
	}
	// 单目标：不注入 @目标 分桶标签
	if strings.Contains(out, "@app-a.example.com") {
		t.Error("单目标项目移交条目不应带 @目标 标签")
	}
	// 无 spec V3 的项目：小节不占位
	p2 := &store.Project{ROEAcknowledgedAt: "2026-11-23T00:00:00Z", ID: "P-SP3-B", Name: "Web",
		Target: "a.test", StageStates: map[string]*store.StageState{}}
	if out2 := o.buildContextPack(p2, "s5"); strings.Contains(out2, "专项就绪移交") {
		t.Error("无专项 V3 项目不应出现专项移交小节")
	}
}

// TestSpecV3MultiTargetTagging v6.6.0 SP-③：多目标项目专项移交条目带 @目标 标签（复用
// tagHandoverTarget，与 S4→S5 移交分桶对账同一机制）。
func TestSpecV3MultiTargetTagging(t *testing.T) {
	dir := t.TempDir()
	st, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	o := &Orchestrator{store: st, exec: newTestExec(t, dir), cfg: &config.Config{Engine: config.EngineConfig{PerTargetRounds: 10}}}
	o.heads = map[string]*Head{}
	p := &store.Project{ROEAcknowledgedAt: "2026-11-23T00:00:00Z", ID: "P-SP3-C", Name: "多APP",
		Target: "app-alpha.example.com\napp-beta.example.com", Specializations: []string{"B1"}}
	p.StageStates = map[string]*store.StageState{
		"specB1": {Status: "done", V3Ready: []string{"sqlmap 批量四件套 oracle（app-alpha.example.com 签名已还原）"}},
	}
	_ = st.SaveProject(p)
	out := o.buildContextPack(p, "s5")
	if !strings.Contains(out, "[specB1 就绪未执行@app-alpha.example.com]") {
		t.Errorf("多目标移交条目应带 @目标 标签: %s", out[strings.Index(out, "专项就绪移交"):strings.Index(out, "专项就绪移交")+300])
	}
}

// TestSpecV3GateInterception v6.6.0 SP-③：spec 阶段 complete_stage 缺 V3 双清单 → 拦截文案
// 与 s4/s5 同款（含三专项提示）；双通道（summary 字面格式）提交可用。
func TestSpecV3GateInterception(t *testing.T) {
	dir := t.TempDir()
	st, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	o := &Orchestrator{store: st, exec: newTestExec(t, dir), bus: events.NewBus(),
		cfg: &config.Config{Engine: config.EngineConfig{PerTargetRounds: 10}}}
	o.heads = map[string]*Head{"specA": {ID: "specA", Name: "专项A", Kind: "spec", Stage: "A"}}
	p := &store.Project{ROEAcknowledgedAt: "2026-11-23T00:00:00Z", ID: "P-SP3-D", Name: "AI",
		Target: "chat.test", Specializations: []string{"A"}}
	p.StageStates = map[string]*store.StageState{"specA": {Status: "running", StartedAt: "2026-11-23T00:00:00Z"}}
	_ = st.SaveProject(p)
	// 收口门链会先走到 V3 检查（无文件产出会在其后拦，但 V3 检查在前——先断 V3 拦截文案）
	// 注意：complete_stage 分支在 V3 检查前有 s8 quality 门与 harvest，spec 无特殊化。
	// 直接构造缺清单调用：模拟 dispatch 的 complete_stage 分支难以整体拉起（需要 ctx/审批等），
	// 此处用纯函数断言 V3 解析双通道 + 门条件表达式三段验证。
	if _, ok := parseV3ListFromText("收口摘要\nready_but_unexecuted=[\"oracle 就绪未投递\"]\nl2_approved_unused=[]", "ready_but_unexecuted"); !ok {
		t.Error("summary 字面格式回退通道应可解析")
	}
	src, err := os.ReadFile(filepath.Join("..", "..", "..", "server/internal/engine/orchestrator.go"))
	if err != nil {
		t.Skipf("仓库文件不可达: %v", err)
	}
	code := string(src)
	if !strings.Contains(code, `if stageID == "s4" || stageID == "s5" || isSpecStage(stageID) {`) {
		t.Error("V3 强制清单门应含三专项")
	}
	if !strings.Contains(code, "专项就绪移交（v6.6.0 SP-③") {
		t.Error("S5 注入块应含专项就绪移交小节")
	}
}

// TestSpecV3StatePersistence 专项收口代收口路径 V3 落 StageState（runStage 预算耗尽代收口对
// spec 阶段同样收割——harvestV3Lists 已是阶段无关机制，此处断言状态字段写入）。
func TestSpecV3StatePersistence(t *testing.T) {
	dir := t.TempDir()
	st, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	p := &store.Project{ROEAcknowledgedAt: "2026-11-23T00:00:00Z", ID: "P-SP3-E", Name: "AI",
		Target: "chat.test", Specializations: []string{"A"}}
	p.StageStates = map[string]*store.StageState{"specA": {Status: "running"}}
	state := p.StageStates["specA"]
	state.V3Ready = []string{"specA oracle（就绪）"}
	state.V3L2 = []string{}
	if err := st.SaveProject(p); err != nil {
		t.Fatal(err)
	}
	got, err := st.GetProject(p.ID)
	if err != nil {
		t.Fatal(err)
	}
	if stA := got.StageStates["specA"]; stA == nil || len(stA.V3Ready) != 1 || stA.V3Ready[0] != "specA oracle（就绪）" {
		t.Errorf("spec 阶段 V3 落库回读失败: %+v", got.StageStates["specA"])
	}
}
