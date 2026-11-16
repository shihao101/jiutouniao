// v5.3.3 P2-1 技能检索准确率金标回归：真实 skills/ 目录 + golden.json 逐条验证。
// 判据：SearchCtx(q, stage, 3) 的 top3 命中任一期望技能即通过（金标源自 00-router 两张表与别名策展）。
// 目录缺失时 Skip（纯净部署包不带评测夹具属预期）。
package engine

import (
	"encoding/json"
	"fmt"
	"os"
	"testing"
)

type goldenCase struct {
	Q         string   `json:"q"`
	Stage     string   `json:"stage"`
	AnyInTop3 []string `json:"any_in_top3"`
	Source    string   `json:"source"`
}

type goldenFile struct {
	MinPassRate float64      `json:"min_pass_rate"`
	Cases       []goldenCase `json:"cases"`
}

func TestV533GoldenRetrieval(t *testing.T) {
	skillsDir := "../../../skills"
	goldenPath := "../../../eval/gates/fixtures/skill-retrieval/golden.json"
	if _, err := os.Stat(skillsDir); err != nil {
		t.Skip("技能库目录不存在（非仓库根运行）")
	}
	if _, err := os.Stat(goldenPath); err != nil {
		t.Skip("金标夹具不存在（纯净部署包口径）")
	}
	reg, err := LoadSkills(skillsDir)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(goldenPath)
	if err != nil {
		t.Fatal(err)
	}
	var gf goldenFile
	if err := json.Unmarshal(raw, &gf); err != nil {
		t.Fatal(err)
	}
	if len(gf.Cases) < 30 {
		t.Fatalf("金标应 ≥30 条，实际 %d", len(gf.Cases))
	}
	pass, top1 := 0, 0
	var fails []string
	for _, c := range gf.Cases {
		hits := reg.SearchCtx(c.Q, c.Stage, 3)
		if len(hits) == 0 {
			fails = append(fails, c.Q+" → 无命中")
			continue
		}
		if hits[0].ID == c.AnyInTop3[0] {
			top1++
		}
		ok := false
		for _, h := range hits {
			for _, want := range c.AnyInTop3 {
				if h.ID == want {
					ok = true
					break
				}
			}
		}
		if ok {
			pass++
		} else {
			fails = append(fails, fmt.Sprintf("%s → top3=[%s %s %s] 期望任一 %s", c.Q, hits[0].ID,
				idOf(hits, 1), idOf(hits, 2), c.AnyInTop3[0]))
		}
	}
	rate := float64(pass) / float64(len(gf.Cases))
	t.Logf("检索准确率: %d/%d（%.0f%%）top1 精确 %d/%d", pass, len(gf.Cases), rate*100, top1, len(gf.Cases))
	if rate < gf.MinPassRate {
		t.Fatalf("检索准确率 %.0f%% 低于金标线 %.0f%%；未过用例:\n%s", rate*100, gf.MinPassRate*100, joinLines(fails))
	}
}

func idOf(hits []*Skill, i int) string {
	if i < len(hits) {
		return hits[i].ID
	}
	return "—"
}

func joinLines(ss []string) string {
	out := ""
	for _, s := range ss {
		out += "  " + s + "\n"
	}
	return out
}
