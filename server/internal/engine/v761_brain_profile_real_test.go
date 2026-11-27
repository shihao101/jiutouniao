// v7.6.1 真实数据门禁：参谋画像 × 生产库快照——快照数据目录存在（默认 /tmp/jt-real-brain/，
// 内含 jiutouniao.db，可用 JTN_BRAIN_REAL_DB 覆盖目录路径）时用真实项目数据验证画像产出，
// 否则跳过（干净环境零依赖）。
// 验证口径：①画像含可核存实体（有数据时 ≥1 类）②画像中出现的全部实体编号经
// verifyEvidenceRefs 闭环可达——参谋按纪律引用必然通过 NO_EVIDENCE（真实数据实证）。
package engine

import (
	"fmt"
	"os"
	"strings"
	"testing"

	"jiutouniao/internal/config"
	"jiutouniao/internal/store"
)

func TestV761BrainProfileRealData(t *testing.T) {
	path := os.Getenv("JTN_BRAIN_REAL_DB")
	if path == "" {
		path = "/tmp/jt-real-brain"
	}
	if _, err := os.Stat(path); err != nil {
		t.Skipf("生产库快照不存在（%s），干净环境跳过", path)
	}
	st, err := store.Open(path)
	if err != nil {
		t.Skipf("快照打开失败（脏快照）: %v", err)
	}
	defer st.Close()
	cfg := &config.Config{}
	cfg.ApplyDefaultsForTest()
	o := &Orchestrator{cfg: cfg, store: st}

	// 选数据最丰富的 running/done 项目（VT/事实/发现至少有一类非空）
	projects, _ := st.ListProjects()
	var best *store.Project
	bestN := 0
	for _, p := range projects {
		vts, _ := st.ListVTs(p.ID)
		facts, _ := st.ListFacts(p.ID, 200)
		fs, _ := st.ListFindings(p.ID)
		if n := len(vts) + len(facts) + len(fs); n > bestN {
			best, bestN = p, n
		}
	}
	if best == nil || bestN == 0 {
		t.Skip("快照内无含账本数据的项目")
	}
	t.Logf("选取真实项目 %s（VT/事实/发现合计 %d）", best.ID, bestN)

	prof := o.buildBrainProfile(best, "s4")
	// 从画像行提取实体引用（与参谋可引用集合同口径）
	var refs []string
	for _, ln := range strings.Split(prof, "\n") {
		ln = strings.TrimPrefix(ln, "- ")
		switch {
		case strings.HasPrefix(ln, "VT-"):
			refs = append(refs, ln[:strings.Index(ln, " ")])
		case strings.HasPrefix(ln, "fact:"):
			refs = append(refs, "fact:"+ln[len("fact:"):strings.Index(ln[len("fact:"):], " ")+len("fact:")])
		case strings.HasPrefix(ln, "F-"):
			refs = append(refs, ln[:strings.Index(ln, " ")])
		case strings.HasPrefix(ln, "CD-"):
			refs = append(refs, ln[:strings.Index(ln, " ")])
		}
	}
	if len(refs) == 0 {
		t.Fatalf("真实项目画像未产出任何可引用实体（VT/事实/发现/候选均空？）")
	}
	t.Logf("画像实体引用 %d 条：%v…", len(refs), refs[:min(len(refs), 6)])
	valid, invalid, _ := o.verifyEvidenceRefs(best, refs)
	if len(invalid) > 0 {
		t.Fatalf("真实数据闭环失败：画像实体存在不可核存引用 %v", invalid)
	}
	if len(valid) != len(refs) {
		t.Fatalf("核存数量不匹配 valid=%d refs=%d", len(valid), len(refs))
	}
	fmt.Printf("✅ 真实数据实证：项目 %s 画像实体 %d 条全部通过核存（参谋按纪律引用必然过 NO_EVIDENCE）\n", best.ID, len(refs))
}
