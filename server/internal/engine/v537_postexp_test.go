// v5.3.7 后渗透勾选门单测：s6 跳过决策（未勾选/勾选/非 s6 阶段/持久化）。
package engine

import (
	"strings"
	"testing"

	"jiutouniao/internal/store"
)

func TestV537PostExploitGate(t *testing.T) {
	o, st := v48Orchestrator(t)
	// 未勾选：s6 → skipped，Summary 记录决策原因
	p := &store.Project{ ROEAcknowledgedAt: "2026-11-22T00:00:00Z",ID: "P-V537-A", Name: "未勾选", PostExploit: false,
		StageStates: map[string]*store.StageState{"s6": {Status: "pending"}}}
	_ = st.SaveProject(p)
	state := p.StageStates["s6"] // 与 runPipeline 一致：gate 操作的是项目映射内的状态对象
	if !o.applyPostExploitGate(p, "s6", state) {
		t.Fatal("未勾选时 s6 应被跳过")
	}
	// v5.9.1：skipped 无 StartedAt/EndedAt（跳过不是运行）——断言同步
	if state.Status != "skipped" || !strings.Contains(state.Summary, "未勾选") || state.EndedAt != "" {
		t.Fatalf("skipped 状态/留痕不完整: %+v", state)
	}
	got, _ := st.GetProject(p.ID)
	if gs := got.StageStates["s6"]; gs == nil || gs.Status != "skipped" {
		t.Fatalf("skipped 未落库: %+v", got.StageStates["s6"])
	}
	// 勾选：s6 不跳过
	p2 := &store.Project{ ROEAcknowledgedAt: "2026-11-22T00:00:00Z",ID: "P-V537-B", Name: "已勾选", PostExploit: true}
	_ = st.SaveProject(p2)
	state2 := &store.StageState{Status: "pending"}
	if o.applyPostExploitGate(p2, "s6", state2) {
		t.Fatal("勾选后 s6 不应跳过")
	}
	if state2.Status != "pending" {
		t.Fatalf("勾选后状态不应被改动: %+v", state2)
	}
	// 非 s6 阶段不受影响（s5 在未勾选时也照常执行）
	p3 := &store.Project{ ROEAcknowledgedAt: "2026-11-22T00:00:00Z",ID: "P-V537-C", Name: "负例", PostExploit: false}
	_ = st.SaveProject(p3)
	if o.applyPostExploitGate(p3, "s5", &store.StageState{Status: "pending"}) {
		t.Fatal("s5 不应受后渗透门影响")
	}
	// 幂等：对已 skipped 的 s6 重入主循环再次置 skipped 不出错
	state4 := &store.StageState{Status: "skipped", Summary: "前次留痕"}
	if !o.applyPostExploitGate(p, "s6", state4) {
		t.Fatal("重复进入仍应返回跳过")
	}
}

func TestV537PostExploitPersist(t *testing.T) {
	_, st := v48Orchestrator(t)
	p := &store.Project{ ROEAcknowledgedAt: "2026-11-22T00:00:00Z",ID: "P-V537-D", Name: "持久化", PostExploit: true}
	if err := st.CreateProject(p); err != nil {
		t.Fatal(err)
	}
	got, _ := st.GetProject(p.ID)
	if !got.PostExploit {
		t.Fatal("post_exploit=true 应持久化")
	}
	p2 := &store.Project{ ROEAcknowledgedAt: "2026-11-22T00:00:00Z",ID: "P-V537-E", Name: "默认"}
	_ = st.CreateProject(p2)
	got2, _ := st.GetProject(p2.ID)
	if got2.PostExploit {
		t.Fatal("默认应 false（不执行后渗透）")
	}
}

// v5.3.7 逻辑核查②补验：update_finding remediation 补写/追加
func TestV537RemediationPatch(t *testing.T) {
	o, st := v48Orchestrator(t)
	p := &store.Project{ ROEAcknowledgedAt: "2026-11-22T00:00:00Z",ID: "P-V537-F", Name: "remediation"}
	_ = st.SaveProject(p)
	// 首登无 remediation → 补写
	got := o.dispatch(testCtx(), p, "s4", mkCall("record_finding",
		`{"title":"越权","severity":"高","detail":"d","confidence":"疑似"}`))
	if strings.Contains(got, "错误") {
		t.Fatalf("登记失败: %s", got)
	}
	fs, _ := st.ListFindings(p.ID)
	fid := fs[0].ID
	got2 := o.dispatch(testCtx(), p, "s4", mkCall("update_finding",
		`{"id":"`+fid+`","reason":"复测确认","remediation":"按会话校验资源归属"}`))
	if !strings.Contains(got2, "remediation 补写") {
		t.Fatalf("补写应发生: %s", got2)
	}
	// 再次修订 → 追加
	got3 := o.dispatch(testCtx(), p, "s4", mkCall("update_finding",
		`{"id":"`+fid+`","reason":"方案更新","remediation":"增加网关层拦截"}`))
	if !strings.Contains(got3, "remediation+append") {
		t.Fatalf("追加应发生: %s", got3)
	}
	fs2, _ := st.ListFindings(p.ID)
	if !strings.Contains(fs2[0].Remediation, "按会话校验资源归属") || !strings.Contains(fs2[0].Remediation, "网关层拦截") {
		t.Fatalf("两段建议都应在库: %q", fs2[0].Remediation)
	}
}
