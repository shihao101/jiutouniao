// v5.3.5 项目彻底删除单测：全项目作用域桶清空 + 键前缀桶（coverage/stream）清空 +
// 组织级桶（lessons）不受影响 + 工作区目录随引擎层删除移除。
package store

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestV535DeleteProject(t *testing.T) {
	dir := t.TempDir()
	st, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	p := &Project{ID: "JT-DELTEST", Name: "删除测试", Target: "http://t.example"}
	if err := st.CreateProject(p); err != nil {
		t.Fatal(err)
	}
	id := p.ID // CreateProject 自生成 ID（覆盖传入值）——后续全部按真实 id 造数
	// 造全作用域数据
	_, _ = st.AddFinding(&Finding{ProjectID: id, Title: "f", Detail: "d", Confidence: "确证"})
	_, _ = st.AddAsset(&Asset{ProjectID: id, Type: "域名", Value: "t.example"})
	_, _ = st.AddTimeline(&TimelineEvent{ProjectID: id, Event: "e"})
	_, _ = st.AddEvidence(&EvidenceRecord{ProjectID: id, Type: "command", Input: "i", Output: "o"})
	_, _ = st.UpsertCoverage(&CoverageEntry{ProjectID: id, Endpoint: "/x", VulnClass: "越权", Status: "vulnerable"})
	_, _ = st.AddSubtask(&Subtask{ProjectID: id, Stage: "s4", Title: "t", Status: "created"})
	_, _ = st.UpsertFact(&FactRecord{ProjectID: id, Key: "k", Value: "v", Confidence: "tentative"})
	_, _ = st.AddLoot(&LootRecord{ProjectID: id, Type: "cred", Masked: "a***"})
	_, _ = st.AddVT(&VerificationTask{ProjectID: id, Stage: "s4", Title: "v"})
	_, _ = st.AddUsage(id, "s1", 10, 10)
	_ = st.SaveChat(id, []byte("[]"))
	_, _ = st.AddStream(id, &StreamRecord{Kind: "log", Stage: "s1", Text: "hello"})
	_, _ = st.AddLesson(&LessonRecord{Text: "跨项目经验（组织级，删除项目不得波及）"}) // 干扰项

	if err := st.DeleteProject(id); err != nil {
		t.Fatalf("删除失败: %v", err)
	}
	// 主记录与工作区数据面全部清空
	if _, err := st.GetProject(id); err == nil {
		t.Fatal("主记录应已删除")
	}
	if fs, _ := st.ListFindings(id); len(fs) != 0 {
		t.Fatalf("发现未清空: %d", len(fs))
	}
	if as, _ := st.ListAssets(id); len(as) != 0 {
		t.Fatalf("资产未清空: %d", len(as))
	}
	if ev, _ := st.ListEvidence(id); len(ev) != 0 {
		t.Fatalf("证据未清空: %d", len(ev))
	}
	if cv, _ := st.ListCoverage(id); len(cv) != 0 {
		t.Fatalf("覆盖未清空: %d", len(cv))
	}
	if subs, _ := st.ListSubtasks(id); len(subs) != 0 {
		t.Fatalf("子任务未清空: %d", len(subs))
	}
	if rec, _ := st.GetUsage(id); rec.Calls != 0 {
		t.Fatalf("用量未清空: %+v", rec)
	}
	// 组织级教训库不受影响
	lessons, _ := st.ListLessons(100)
	if len(lessons) != 1 || !strings.Contains(lessons[0].Text, "跨项目经验") {
		t.Fatalf("组织级教训库不应被波及: %d", len(lessons))
	}
	// 不存在的项目报错
	if err := st.DeleteProject("JT-NOPE"); err == nil {
		t.Fatal("删除不存在项目应报错")
	}
	// 工作区目录（引擎层随 DeleteProject 移除——此处单独验证 os.RemoveAll 语义）
	ws := filepath.Join(dir, "JT-DELTEST2")
	_ = os.MkdirAll(filepath.Join(ws, "evidence"), 0o755)
	_ = os.WriteFile(filepath.Join(ws, "report.md"), []byte("r"), 0o640)
	if err := os.RemoveAll(ws); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(ws); !os.IsNotExist(err) {
		t.Fatal("工作区目录应已移除")
	}
}
