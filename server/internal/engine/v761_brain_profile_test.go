// v7.6.1 作战参谋证据实体注入单测（方案：参谋画像从统计升级为渗透信号）：
// ① 画像含全部四类可核存引用实体（VT-/fact:/F-/CD-），deprecated 事实被排除；
// ② 覆盖缺口行带「不可作 evidence 引用」显式标注（核存不支持 endpoint 键）；
// ③ 系统提示词含引用纪律（画像外引用将被拒）；
// ④ 核存链路不变：画像中出现的实体编号经 verifyEvidenceRefs 全部可达（闭环自证——
//
//	参谋只要按纪律引用，就必然通过 NO_EVIDENCE）。
package engine

import (
	"strings"
	"testing"

	"jiutouniao/internal/store"
)

func TestV761BrainProfileCitableEntities(t *testing.T) {
	o := v750TestOrchestrator(t)
	p, err := o.CreateProject(&store.Project{ROEAcknowledgedAt: "2026-11-26T00:00:00Z",
		Name: "参谋画像回归", Target: "http://127.0.0.1:1", Authorized: true})
	if err != nil {
		t.Fatal(err)
	}
	// VT：P1 pending + P2 ready
	vt1, _ := o.store.AddVT(&store.VerificationTask{ProjectID: p.ID, Stage: "s4", Title: "SSRF OOB 探针", Priority: 1, Status: "pending"})
	vt2, _ := o.store.AddVT(&store.VerificationTask{ProjectID: p.ID, Stage: "s4", Title: "SSO 票据伪造", Priority: 2, Status: "ready", ReadyAssets: "evidence/s4-probe/t01.html"})
	// 事实：confirmed（可引用）+ deprecated（必须排除）
	o.store.UpsertFact(&store.FactRecord{ProjectID: p.ID, Key: "http://x/login", Value: "primitive:AUTHZ 匿名可达", Confidence: "confirmed"})
	o.store.UpsertFact(&store.FactRecord{ProjectID: p.ID, Key: "http://x/old", Value: "旧结论", Confidence: "deprecated"})
	// 发现：高/确证 + 低/疑似（确证优先排序）
	f1, _ := o.store.AddFinding(&store.Finding{ProjectID: p.ID, Stage: "s4", Title: "SSO 匿名票据签发", Severity: "高", Confidence: "确证"})
	f2, _ := o.store.AddFinding(&store.Finding{ProjectID: p.ID, Stage: "s4", Title: "路径泄露", Severity: "低", Confidence: "疑似"})
	// 候选 open
	cd, _ := o.store.AddCandidate(&store.Candidate{ProjectID: p.ID, Stage: "s4", Title: "验证码端点待评估", Disposition: "open"})
	// 覆盖：needs_follow_up 缺口 + 战利品
	o.store.UpsertCoverage(&store.CoverageEntry{ProjectID: p.ID, Stage: "s4", Endpoint: "/jpkInfo", VulnClass: "越权", Param: "stuId", Status: "needs_follow_up", Notes: "待查"})
	o.store.AddLoot(&store.LootRecord{ProjectID: p.ID, Stage: "s4", Type: "credential", Masked: "stu***", Source: "evidence/s4-cred.txt"})

	prof := o.buildBrainProfile(p, "s4")
	sys := brainSystemPrompt()

	// ① 四类可核存实体在画像中且编号可核存
	for _, must := range []string{vt1, vt2, "fact:http://x/login", f1, f2, cd} {
		if !strings.Contains(prof, must) {
			t.Fatalf("画像缺可引用实体 %q", must)
		}
	}
	if strings.Contains(prof, "fact:http://x/old") {
		t.Fatalf("deprecated 事实不应注入画像")
	}
	// 确证发现排在高危疑似之前（rank：确证 -4）
	if strings.Index(prof, f1) > strings.Index(prof, f2) {
		t.Fatalf("确证发现应排序在前")
	}
	// P1 VT 排在 P2 前
	if strings.Index(prof, vt1) > strings.Index(prof, vt2) {
		t.Fatalf("P1 VT 应排序在前")
	}
	// ② 覆盖缺口带不可引用标注
	if !strings.Contains(prof, "### 覆盖缺口") || !strings.Contains(prof, "不可作 evidence 引用") || !strings.Contains(prof, "/jpkInfo × 越权 × stuId") {
		t.Fatalf("覆盖缺口块缺失或标注错误")
	}
	if !strings.Contains(prof, "## 战利品") {
		t.Fatalf("战利品价值信号行缺失")
	}
	// ③ 系统提示词引用纪律
	if !strings.Contains(sys, "引用纪律") || !strings.Contains(sys, "将被裁决拒绝") {
		t.Fatalf("系统提示词缺引用纪律节")
	}
	// ④ 闭环自证：画像中出现的全部实体编号经核存可达
	refs := []string{vt1, vt2, "fact:http://x/login", f1, f2, cd}
	valid, invalid, _ := o.verifyEvidenceRefs(p, refs)
	if len(invalid) > 0 || len(valid) != len(refs) {
		t.Fatalf("画像实体应全部通过核存（valid=%d invalid=%v）", len(valid), invalid)
	}
}
