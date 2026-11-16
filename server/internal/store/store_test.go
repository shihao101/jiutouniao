package store

import (
	"testing"
)

// v3.3.0 项目黑板与战利品库：幂等 upsert / 列表排序 / 掩码登记。
func TestFactsAndLoot(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	// Upsert 幂等：同 key 二次写入覆盖而非新增
	id1, _ := st.UpsertFact(&FactRecord{ProjectID: "P1", Key: "http://t:8080/login", Value: "primitive:AUTHZ 未鉴权", Confidence: "tentative"})
	facts, _ := st.ListFacts("P1", 0)
	if len(facts) != 1 {
		t.Fatalf("首次写入应为 1 条，实际 %d", len(facts))
	}
	id2, _ := st.UpsertFact(&FactRecord{ProjectID: "P1", Key: "http://t:8080/login", Value: "primitive:AUTHZ 未鉴权（已实测确认）", Confidence: "confirmed"})
	if id1 != id2 {
		t.Fatalf("同 key upsert 应复用同 id: %s vs %s", id1, id2)
	}
	facts, _ = st.ListFacts("P1", 0)
	if len(facts) != 1 || facts[0].Confidence != "confirmed" {
		t.Fatalf("upsert 未覆盖: %+v", facts)
	}
	// 非法 confidence 归位 tentative
	_, _ = st.UpsertFact(&FactRecord{ProjectID: "P1", Key: "k2", Value: "v", Confidence: "whatever"})
	facts, _ = st.ListFacts("P1", 0)
	if facts[0].Key != "k2" { // 最近更新优先
		t.Fatalf("列表应按更新时间倒序: %+v", facts[0])
	}
	if facts[0].Confidence != "tentative" {
		t.Fatalf("非法 confidence 应回退 tentative")
	}
	// 项目隔离
	other, _ := st.ListFacts("P2", 0)
	if len(other) != 0 {
		t.Fatal("项目隔离失效")
	}
	// 战利品
	if _, err := st.AddLoot(&LootRecord{ProjectID: "P1", Type: "credential", Target: "db@10.0.0.1", Masked: "adm***23", Source: "config leak", Verified: "verified"}); err != nil {
		t.Fatal(err)
	}
	loot, _ := st.ListLoot("P1", 10)
	if len(loot) != 1 || loot[0].Masked != "adm***23" {
		t.Fatalf("战利品登记异常: %+v", loot)
	}
}
