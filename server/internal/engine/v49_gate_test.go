package engine

// v4.9 F1/F2/F3 专项测试（2026-11-12 兰州/重庆预算耗尽六连败整改）：
// F1 V3 清单双通道提交（顶层参数 / summary 约定字面格式回退）；
// F2 预算护栏代收口（VT 台账代填）；F3 s4 阶段预算 ×2（见 multitarget_test.go）。

import (
	"context"
	"strings"
	"testing"

	"jiutouniao/internal/llm"
	"jiutouniao/internal/store"
)

// V3-F1①：顶层 JSON 数组参数仍然放行（回归 v4.6 原语义）
func TestV49CompleteStageTopLevelLists(t *testing.T) {
	o, _ := v46Orchestrator(t)
	p := &store.Project{ ROEAcknowledgedAt: "2026-11-22T00:00:00Z",ID: "P-V49A", StageStates: map[string]*store.StageState{"s4": {Status: "running", StartedAt: "2026-01-01T00:00:00Z"}}}
	_ = o.store.SaveProject(p)
	got := call(t, o, p, "s4", "complete_stage", `{"summary":"x","ready_but_unexecuted":[],"l2_approved_unused":[]}`)
	if strings.Contains(got, "V3") || strings.Contains(got, "缺少必填清单") {
		t.Fatalf("顶层空数组应放行 V3: %s", got)
	}
	// 非空内容 → 登记时间线
	got = call(t, o, p, "s4", "complete_stage", `{"summary":"x","ready_but_unexecuted":["poc/a.sh（启动条件：通道恢复）"],"l2_approved_unused":[]}`)
	if strings.Contains(got, "缺少必填清单") {
		t.Fatalf("顶层内容数组应放行 V3: %s", got)
	}
	tl, err := o.store.ListTimeline("P-V49A")
	if err != nil {
		t.Fatal(err)
	}
	hit := false
	for _, e := range tl {
		if strings.Contains(e.Event, "v4.6 V3 清单") && strings.Contains(e.Detail, "poc/a.sh") {
			hit = true
		}
	}
	if !hit {
		t.Fatalf("非空清单应登记时间线: %+v", tl)
	}
}

// V3-F1②：summary 约定字面格式回退（实证模型行为：清单写进 summary 文本）
func TestV49CompleteStageSummaryFallback(t *testing.T) {
	o, _ := v46Orchestrator(t)
	p := &store.Project{ ROEAcknowledgedAt: "2026-11-22T00:00:00Z",ID: "P-V49B", StageStates: map[string]*store.StageState{"s4": {Status: "running", StartedAt: "2026-01-01T00:00:00Z"}}}
	_ = o.store.SaveProject(p)
	// 实证形态 1：冒号 + 空数组（含前后文）
	got := call(t, o, p, "s4", "complete_stage", `{"summary":"S4 收口。\n\nready_but_unexecuted: []\nl2_approved_unused: []\n本轮全部投递。"}`)
	if strings.Contains(got, "缺少必填清单") {
		t.Fatalf("summary 冒号空数组应放行 V3: %s", got)
	}
	// 实证形态 2：等号 + 转义内容数组（模型在 JSON 里写 \" 的双转义残留）
	got = call(t, o, p, "s4", "complete_stage", `{"summary":"ready_but_unexecuted=[\"VT-298DAF6E81\",\"VT-3CA2A8A834\"]\nl2_approved_unused=[]"}`)
	if strings.Contains(got, "缺少必填清单") {
		t.Fatalf("summary 等号内容数组应放行 V3: %s", got)
	}
	// 实证形态 3：JSON 数组字面量直接可解析
	got = call(t, o, p, "s4", "complete_stage", `{"summary":"- ready_but_unexecuted: []（本轮 5 个就绪脚本全部投递执行完毕）\n- l2_approved_unused: []（无 L2 余量）"}`)
	if strings.Contains(got, "缺少必填清单") {
		t.Fatalf("summary 带中文注释的空数组应放行 V3: %s", got)
	}
	// v7.1.0 E1'：两通道都取不到 → 引擎按台账代填放行 V3（收口继续到后续门），不再拦截
	got = call(t, o, p, "s4", "complete_stage", `{"summary":"x"}`)
	if strings.Contains(got, "缺少必填清单") {
		t.Fatalf("v7.1.0 E1' 后双通道皆缺应引擎代填放行 V3: %s", got)
	}
}

// V3-F1：解析器单元覆盖（主形态/宽松形态/内容解析/无数组不误判）
func TestV49ParseV3ListFromText(t *testing.T) {
	cases := []struct {
		name   string
		text   string
		field  string
		wantOK bool
		wantN  int
	}{
		{"冒号空数组", "ready_but_unexecuted: []", "ready_but_unexecuted", true, 0},
		{"等号空数组", "l2_approved_unused=[]", "l2_approved_unused", true, 0},
		{"全角冒号", "l2_approved_unused：[]", "l2_approved_unused", true, 0},
		{"空数组带中文注释", "ready_but_unexecuted: []（本轮全部投递）", "ready_but_unexecuted", true, 0},
		{"JSON 内容数组", `ready_but_unexecuted=["VT-1","VT-2"]`, "ready_but_unexecuted", true, 2},
		{"双转义内容数组", `ready_but_unexecuted=[\"VT-1\",\"VT-2\"]`, "ready_but_unexecuted", true, 2},
		{"宽松切分顿号", "ready_but_unexecuted=[VT-1、VT-2]", "ready_but_unexecuted", true, 2},
		{"中文连接宽松形态", "ready_but_unexecuted 为空数组 []", "ready_but_unexecuted", true, 0},
		{"句首大写边界", "Ready_but_unexecuted: []", "ready_but_unexecuted", false, 0},
		{"无数组不误判", "把就绪项列入 ready_but_unexecuted 清单", "ready_but_unexecuted", false, 0},
		{"字段不存在", "summary 无清单", "ready_but_unexecuted", false, 0},
		{"空文本", "", "ready_but_unexecuted", false, 0},
	}
	for _, c := range cases {
		items, ok := parseV3ListFromText(c.text, c.field)
		if ok != c.wantOK || (ok && len(items) != c.wantN) {
			t.Errorf("%s: ok=%v n=%d want ok=%v n=%d", c.name, ok, len(items), c.wantOK, c.wantN)
		}
	}
}

// F2：护栏代收口清单收割（VT 台账 pending/ready → 代填；executed/其他阶段不收）
func TestV49HarvestV3Lists(t *testing.T) {
	o, st := v46Orchestrator(t)
	p := &store.Project{ ROEAcknowledgedAt: "2026-11-22T00:00:00Z",ID: "P-V49C"}
	_ = st.SaveProject(p)
	mk := func(id, stage, status string) {
		if _, err := st.AddVT(&store.VerificationTask{ID: id, ProjectID: p.ID, Stage: stage,
			Title: "验证 " + id, ReadyAssets: "poc/" + id + ".sh", Status: status}); err != nil {
			t.Fatal(err)
		}
	}
	mk("VT-1", "s4", "ready")
	mk("VT-2", "s4", "pending")
	mk("VT-3", "s4", "executed")
	mk("VT-4", "s5", "ready")
	ready, l2 := o.harvestV3Lists(p, "s4", nil)
	if len(ready) != 2 || l2 != nil {
		t.Fatalf("s4 应收割 ready+pending 两项且 l2 空: ready=%v l2=%v", ready, l2)
	}
	// AddVT 由 store 生成 ID，断言用我们注入的状态与就绪资产定位
	var hasReady bool
	for _, it := range ready {
		if strings.Contains(it, "[ready]") && strings.Contains(it, "poc/VT-1.sh") {
			hasReady = true
		}
	}
	if !hasReady {
		t.Fatalf("收割条目应含 ready 状态与就绪资产: %v", ready)
	}
	ready5, _ := o.harvestV3Lists(p, "s5", nil)
	if len(ready5) != 1 {
		t.Fatalf("s5 应收割 VT-4 一项: %v", ready5)
	}
	// 非 s4/s5 不代填
	ready1, l21 := o.harvestV3Lists(p, "s2", nil)
	if ready1 != nil || l21 != nil {
		t.Fatalf("s2 不应代填: %v %v", ready1, l21)
	}
}

// F2 回归：代收口不改变 dispatch 侧行为——complete_stage 在 V3 通过后仍被实体文件检查拦截
func TestV49CompleteStageStillRequiresFiles(t *testing.T) {
	o, _ := v46Orchestrator(t)
	p := &store.Project{ ROEAcknowledgedAt: "2026-11-22T00:00:00Z",ID: "P-V49D", StageStates: map[string]*store.StageState{"s4": {Status: "running", StartedAt: "2026-01-01T00:00:00Z"}}}
	_ = o.store.SaveProject(p)
	got := call(t, o, p, "s4", "complete_stage", `{"summary":"x","ready_but_unexecuted":[],"l2_approved_unused":[]}`)
	if !strings.Contains(got, "实体交付物") {
		t.Fatalf("无实体文件应被文件门拦截（F2 不放行文件要求）: %s", got)
	}
}

// dispatch(ctx) 直连冒烟：确保新增解析在完整分发路径上无 panic
func TestV49DispatchSmoke(t *testing.T) {
	o, _ := v46Orchestrator(t)
	p := &store.Project{ ROEAcknowledgedAt: "2026-11-22T00:00:00Z",ID: "P-V49E", StageStates: map[string]*store.StageState{"s5": {Status: "running", StartedAt: "2026-01-01T00:00:00Z"}}}
	_ = o.store.SaveProject(p)
	got := o.dispatch(context.Background(), p, "s5", llm.ToolCall{Name: "complete_stage", Arguments: `{"summary":"ready_but_unexecuted=[] l2_approved_unused=[]"}`})
	if strings.Contains(got, "缺少必填清单") {
		t.Fatalf("s5 summary 回退应放行 V3: %s", got)
	}
}
