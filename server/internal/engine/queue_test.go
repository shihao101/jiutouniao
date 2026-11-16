package engine

import (
	"encoding/json"
	"strings"
	"testing"

	"jiutouniao/internal/events"
	"jiutouniao/internal/store"
)

func TestSortQueueFindings(t *testing.T) {
	mk := func(id, sev, conf string, rank int) *store.Finding {
		return &store.Finding{ID: id, Severity: sev, Confidence: conf, ImpactRank: rank}
	}
	// B(高,疑似,无rank) A(高,确证,rank3) C(中,确证,rank1) D(高,确证,无rank) E(高,确证,rank1)
	in := []*store.Finding{mk("B", "高", "疑似", 0), mk("A", "高", "确证", 3), mk("C", "中", "确证", 1), mk("D", "高", "确证", 0), mk("E", "高", "确证", 1)}
	got := sortQueueFindings(in)
	want := []string{"E", "C", "A", "D", "B"} // rank升序(1→1按严重度高前→3)；未标注按置信度→严重度
	for i := range want {
		if got[i].ID != want[i] {
			t.Fatalf("排序第 %d 位 got=%s want=%s（全序列 %v）", i+1, got[i].ID, want[i], ids(got))
		}
	}
	// 原列表不被修改（稳定排序返回副本）
	if in[0].ID != "B" {
		t.Error("sortQueueFindings 不应修改原列表")
	}
}

func ids(fs []*store.Finding) []string {
	out := []string{}
	for _, f := range fs {
		out = append(out, f.ID)
	}
	return out
}

func TestEvidenceCriteriaMissing(t *testing.T) {
	cases := []struct {
		name string
		f    *store.Finding
		want bool
	}{
		{"高危确证未引判据→降级", &store.Finding{Severity: "高", Confidence: "确证", Detail: "SQL 注入可提取数据"}, true},
		{"高危确证引用判据→合规", &store.Finding{Severity: "高", Confidence: "确证", Detail: "布尔差分对照实验：判据项满足（evidence-standard SQLi 类）"}, false},
		{"高危确证引用技能名→合规", &store.Finding{Severity: "高", Confidence: "确证", Detail: "按 evidence-standard 未授权类双主体矩阵验证"}, false},
		{"疑似不触发", &store.Finding{Severity: "高", Confidence: "疑似", Detail: ""}, false},
		{"中危不触发", &store.Finding{Severity: "中", Confidence: "确证", Detail: ""}, false},
		{"待查不触发", &store.Finding{Severity: "高", Confidence: "待查", Detail: ""}, false},
		{"nil 安全", nil, false},
	}
	for _, c := range cases {
		if got := evidenceCriteriaMissing(c.f); got != c.want {
			t.Errorf("%s: evidenceCriteriaMissing=%v want=%v", c.name, got, c.want)
		}
	}
}

// TestEvidenceCriteriaIssuesDowngrade 引擎级验证：收口判据抽查把未引判据的高危确证降级为疑似
// （detail 追加补证提示），合规条目与低危/疑似条目不受影响。
func TestEvidenceCriteriaIssuesDowngrade(t *testing.T) {
	dir := t.TempDir()
	st, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	o := &Orchestrator{store: st, exec: newTestExec(t, dir), bus: events.NewBus()}

	bad := &store.Finding{ProjectID: "P4C", Stage: "s4", Title: "RCE 候选", Severity: "高", Confidence: "确证", Detail: "疑似命令拼接"}
	if _, err := st.AddFinding(bad); err != nil {
		t.Fatal(err)
	}
	good := &store.Finding{ProjectID: "P4C", Stage: "s4", Title: "SQLi 确证", Severity: "高", Confidence: "确证", Detail: "孪生谓词对照实验成立（判据项：≥2 组反向谓词×3 重放）"}
	if _, err := st.AddFinding(good); err != nil {
		t.Fatal(err)
	}
	mid := &store.Finding{ProjectID: "P4C", Stage: "s4", Title: "信息泄露", Severity: "中", Confidence: "确证", Detail: ""}
	if _, err := st.AddFinding(mid); err != nil {
		t.Fatal(err)
	}

	issues := o.evidenceCriteriaIssues(&store.Project{ID: "P4C"}, "s4")
	if len(issues) != 1 {
		t.Fatalf("期望 1 条判据抽查 issue，实际 %d: %v", len(issues), issues)
	}
	fs, _ := st.ListFindings("P4C")
	byID := map[string]*store.Finding{}
	for _, f := range fs {
		byID[f.ID] = f
	}
	if byID[bad.ID].Confidence != "疑似" || !strings.Contains(byID[bad.ID].Detail, "引擎降级") {
		t.Errorf("bad 未被降级: %s / %s", byID[bad.ID].Confidence, byID[bad.ID].Detail)
	}
	if byID[good.ID].Confidence != "确证" {
		t.Error("合规确证条目不应被降级")
	}
	if byID[mid.ID].Confidence != "确证" {
		t.Error("中危条目不应被降级")
	}
	// 降级后不应再触发（幂等，防重复拦截）
	if again := o.evidenceCriteriaIssues(&store.Project{ID: "P4C"}, "s4"); len(again) != 0 {
		t.Errorf("降级后不应再次触发: %v", again)
	}
}

// TestFindingAccessSerialization 正反实证（批次4）：标注了 access/impact_rank 的发现
// 持久化并序列化出 JSON 字段；未标注时 omitempty 省略（API 不出现零值键）。
func TestFindingAccessSerialization(t *testing.T) {
	dir := t.TempDir()
	st, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if _, err := st.AddFinding(&store.Finding{ProjectID: "P5", Stage: "s4", Title: "已标注", Severity: "高", Confidence: "确证", Access: "anonymous", ImpactRank: 1}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.AddFinding(&store.Finding{ProjectID: "P5", Stage: "s4", Title: "未标注", Severity: "低", Confidence: "待查"}); err != nil {
		t.Fatal(err)
	}
	fs, _ := st.ListFindings("P5")
	byTitle := map[string]*store.Finding{}
	for _, f := range fs {
		byTitle[f.Title] = f
	}
	if byTitle["已标注"].Access != "anonymous" || byTitle["已标注"].ImpactRank != 1 {
		t.Errorf("持久化丢失标注: %+v", byTitle["已标注"])
	}
	b, _ := json.Marshal(byTitle["已标注"])
	if !strings.Contains(string(b), `"access":"anonymous"`) || !strings.Contains(string(b), `"impact_rank":1`) {
		t.Errorf("标注项 JSON 未序列化字段: %s", b)
	}
	b2, _ := json.Marshal(byTitle["未标注"])
	if strings.Contains(string(b2), "access") || strings.Contains(string(b2), "impact_rank") {
		t.Errorf("未标注项应被 omitempty 省略: %s", b2)
	}
}
