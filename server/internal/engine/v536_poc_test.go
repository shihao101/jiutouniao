// v5.3.6 record_finding POC/修复建议 单测：
// ① poc 合法入库（≤5 组、request/response 必填）② evidence_ids 参数废弃——传入自造编号被忽略，
// 一律自动关联真实证据 ③ remediation 落库 ④ 空 request/response 拒绝。
package engine

import (
	"strings"
	"testing"

	"jiutouniao/internal/store"
)

func TestV536RecordFindingPOC(t *testing.T) {
	o, st := v48Orchestrator(t)
	p := &store.Project{ID: "P-V536", Name: "poc"}
	_ = st.SaveProject(p)
	// 预置真实证据（自动关联的数据源）
	ev1, _ := st.AddEvidence(&store.EvidenceRecord{ProjectID: p.ID, Stage: "s4", Type: "command", Input: "curl -s http://t/x", Output: "HTTP/1.1 200"})

	got := o.dispatch(testCtx(), p, "s4", mkCall("record_finding", `{
		"title":"越权读取","severity":"高","detail":"越权成因","confidence":"确证",
		"remediation":"服务端按会话校验资源归属，修复后用他人 token 验证 403",
		"poc":[{"request":"GET /api/order/2 HTTP/1.1\r\nHost: t\r\n","response":"HTTP/1.1 200 OK\r\n{\"owner\":\"others\"}"}],
		"evidence_ids":["EV-FAKE-001","EV-S4-MADE-UP"]}`))
	if strings.Contains(got, "错误") {
		t.Fatalf("合法登记被拒: %s", got)
	}
	fs, _ := st.ListFindings(p.ID)
	if len(fs) != 1 {
		t.Fatalf("应入库 1 条: %d", len(fs))
	}
	f := fs[0]
	if f.Remediation == "" || !strings.Contains(f.Remediation, "403") {
		t.Fatalf("修复建议未落库: %q", f.Remediation)
	}
	if len(f.POC) != 1 || !strings.Contains(f.POC[0].Request, "GET /api/order/2") || !strings.Contains(f.POC[0].Response, "200 OK") {
		t.Fatalf("POC 未落库: %+v", f.POC)
	}
	// evidence_ids 废弃：传入的杜撰编号被忽略，自动关联真实证据
	for _, eid := range f.EvidenceIDs {
		if eid == "EV-FAKE-001" || eid == "EV-S4-MADE-UP" {
			t.Fatalf("杜撰编号不应入库: %v", f.EvidenceIDs)
		}
	}
	if len(f.EvidenceIDs) == 0 || f.EvidenceIDs[0] != ev1 {
		t.Fatalf("应自动关联真实证据编号 %s: %v", ev1, f.EvidenceIDs)
	}
}

func TestV536RecordFindingPOCValidation(t *testing.T) {
	o, st := v48Orchestrator(t)
	p := &store.Project{ID: "P-V536-B", Name: "poc校验"}
	_ = st.SaveProject(p)
	// 空 response 拒绝
	got := o.dispatch(testCtx(), p, "s4", mkCall("record_finding",
		`{"title":"t","severity":"低","detail":"d","confidence":"疑似","poc":[{"request":"GET / HTTP/1.1","response":""}]}`))
	if !strings.Contains(got, "均必填非空") {
		t.Fatalf("空 response 应被拒绝: %s", got)
	}
	// 超 5 组拒绝
	got2 := o.dispatch(testCtx(), p, "s4", mkCall("record_finding",
		`{"title":"t","severity":"低","detail":"d","confidence":"疑似","poc":[
		 {"request":"a","response":"b"},{"request":"a","response":"b"},{"request":"a","response":"b"},
		 {"request":"a","response":"b"},{"request":"a","response":"b"},{"request":"a","response":"b"}]}`))
	if !strings.Contains(got2, "最多 5 组") {
		t.Fatalf("超量 poc 应被拒绝: %s", got2)
	}
	if fs, _ := st.ListFindings(p.ID); len(fs) != 0 {
		t.Fatalf("被拒登记不应入库: %d", len(fs))
	}
}
