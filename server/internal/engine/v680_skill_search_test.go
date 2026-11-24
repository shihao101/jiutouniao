package engine

import (
	"path/filepath"
	"testing"
)

// TestV680CleanupHandoverRetrieval S7-⑧ 修复后效果验证：收尾/清理移交类查询可召回
// cleanup-handover（00-router 路由行 + aliases「收尾/清理移交/影响量化/待续处置/移交清单」）。
func TestV680CleanupHandoverRetrieval(t *testing.T) {
	reg, err := LoadSkills(filepath.Join("..", "..", "..", "skills"))
	if err != nil {
		t.Skipf("技能目录不可达: %v", err)
	}
	if len(reg.skills) == 0 {
		t.Skipf("技能库为空")
	}
	for _, q := range []string{"收尾", "清理移交", "影响量化", "待续处置"} {
		hits := reg.Search(q, 5)
		found := false
		for _, s := range hits {
			if s.ID == "cleanup-handover" {
				found = true
			}
		}
		if !found {
			t.Errorf("查询 %q top5 未召回 cleanup-handover（命中: %d 个）", q, len(hits))
		}
	}
}
