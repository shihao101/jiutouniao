// v5.3.8 收口死锁修复单测：quality-pending 标记不再硬拒（A）+ confirm_quality_review 显式确认清除（B）。
package engine

import (
	"strings"
	"testing"

	"jiutouniao/internal/store"
)

func TestV538QualityReviewConfirm(t *testing.T) {
	o, st := v48Orchestrator(t)
	p := &store.Project{ID: "P-V538", Name: "死锁修复", PostExploit: true,
		StageStates: map[string]*store.StageState{
			"s1": {Status: "done", Review: "反思门调用失败（重试 3 次）；确定性质量门通过放行【quality-pending：S8 收口前须复核本阶段交付物】"},
			"s4": {Status: "done", Review: "预算护栏代收口【quality-pending：确定性门拦截 2 项——S8 收口前逐项复核】"},
			"s2": {Status: "done", Review: "反思门审查：通过"},
		}}
	_ = st.SaveProject(p)

	// ① 未确认：软提示（返回 true），标记不动
	if !o.applyQualityReviewConfirm(p, false) {
		t.Fatal("存在标记且未确认时应返回 true（软提示）")
	}
	if !strings.Contains(p.StageStates["s1"].Review, "quality-pending") {
		t.Fatal("未确认时标记不应被清除")
	}
	// ② 确认：清除全部标记并留痕
	if o.applyQualityReviewConfirm(p, true) {
		t.Fatal("确认后应放行（返回 false）")
	}
	if strings.Contains(p.StageStates["s1"].Review, "quality-pending") ||
		strings.Contains(p.StageStates["s4"].Review, "quality-pending") {
		t.Fatalf("标记应清除: %+v / %+v", p.StageStates["s1"].Review, p.StageStates["s4"].Review)
	}
	if !strings.Contains(p.StageStates["s1"].Review, "quality-reviewed") {
		t.Fatalf("清除后应留痕 quality-reviewed: %q", p.StageStates["s1"].Review)
	}
	got, _ := st.GetProject(p.ID)
	if strings.Contains(got.StageStates["s4"].Review, "quality-pending") {
		t.Fatal("清除应落库")
	}
	// ③ 无标记项目：直接放行
	p2 := &store.Project{ID: "P-V538-B", Name: "无标记", StageStates: map[string]*store.StageState{
		"s1": {Status: "done", Review: "反思门审查：通过"}}}
	if o.applyQualityReviewConfirm(p2, false) {
		t.Fatal("无标记不应要求确认")
	}
}

func TestV538DeterministicGateNoDeadlock(t *testing.T) {
	o, st := v48Orchestrator(t)
	p := &store.Project{ID: "P-V538-C", Name: "门回归", PostExploit: true,
		StageStates: map[string]*store.StageState{
			"s1": {Status: "done", Review: "【quality-pending：S8 收口前须复核】"},
			"s8": {Status: "running", Review: ""},
		}}
	_ = st.SaveProject(p)
	issues := o.deterministicGate(p, "s8")
	for _, iss := range issues {
		if strings.Contains(iss, "quality-pending") {
			t.Fatalf("确定性门不应再生成 quality-pending 硬拦截项（死锁源）: %s", iss)
		}
	}
	// 静默通过即可——其他 issue 类型（报告引用核验等）保持原有行为
	_ = st
}
