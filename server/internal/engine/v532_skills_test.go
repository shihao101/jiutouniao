// v5.3.2 P1-1/P1-3 技能库单测：manifest 消费（对齐校验+降级）+ 多关键词检索 + 组合选择 + 上下文感知。
package engine

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeSkillDir(t *testing.T, skills map[string]string, manifest string) string {
	t.Helper()
	dir := t.TempDir()
	for id, body := range skills {
		if err := os.WriteFile(filepath.Join(dir, id+".md"), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if manifest != "" {
		if err := os.WriteFile(filepath.Join(dir, "manifest.json"), []byte(manifest), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

const fixtureManifest = `{"version":"5.3.2","count":3,"skills":[
 {"id":"sqli-deep","file":"skills/sqli-deep.md","title":"SQL注入深测","tags":["s4","注入"],
  "aliases":["sql注入","injection"],"depends_on":["chain-proxy"],"handoff_to":["evidence-standard"],"stage_fit":["s4"]},
 {"id":"chain-proxy","file":"skills/chain-proxy.md","title":"链式代理注入通道","tags":["s4","工具"],"stage_fit":["s4"]},
 {"id":"evidence-standard","file":"skills/evidence-standard.md","title":"证据标准","tags":["s8"],"lab_only":false}
]}`

func TestV532ManifestConsumption(t *testing.T) {
	skills := map[string]string{
		"sqli-deep":        "---\nid: sqli-deep\ntitle: SQL注入深测\ntags: s4,注入\n---\n正文A",
		"chain-proxy":      "---\nid: chain-proxy\ntitle: 链式代理\ntags: s4,工具\n---\n正文B",
		"evidence-standard": "---\nid: evidence-standard\ntitle: 证据标准\ntags: s8\n---\n正文C",
	}
	reg, err := LoadSkills(writeSkillDir(t, skills, fixtureManifest))
	if err != nil {
		t.Fatal(err)
	}
	// 元数据并入
	s := reg.Get("sqli-deep")
	if s == nil || len(s.Aliases) != 2 || len(s.DependsOn) != 1 || s.DependsOn[0] != "chain-proxy" || len(s.StageFit) != 1 {
		t.Fatalf("manifest 元数据未并入: %+v", s)
	}
	if !reg.mOK {
		t.Fatal("manifest 应校验通过")
	}
	// 索引含结构化摘要
	idx := reg.Index()
	if !strings.Contains(idx, "配合:chain-proxy") || !strings.Contains(idx, "交接:evidence-standard") {
		t.Fatalf("索引应含配合/交接摘要: %s", idx)
	}
}

func TestV532ManifestDegradation(t *testing.T) {
	skills := map[string]string{
		"sqli-deep": "---\nid: sqli-deep\ntitle: t\ntags: s4\n---\n正文A",
		"chain-proxy": "---\nid: chain-proxy\ntitle: t\ntags: s4\n---\n正文B",
	}
	// manifest 引用不存在的技能 → 失配降级（不阻断）
	bad := `{"count":3,"skills":[{"id":"sqli-deep","file":"skills/sqli-deep.md","title":"t","tags":["s4"]},
	 {"id":"ghost-skill","file":"skills/ghost-skill.md","title":"t","tags":[]},
	 {"id":"chain-proxy","file":"skills/chain-proxy.md","title":"t","tags":["s4"]}}]}`
	if len(bad) == 0 {
		t.Fatal("unreachable")
	}
	reg, _ := LoadSkills(writeSkillDir(t, skills, bad))
	if reg.mOK {
		t.Fatal("失配 manifest 应降级")
	}
	if reg.Get("ghost-skill") != nil {
		t.Fatal("降级后不应有幽灵技能")
	}
	if reg.Get("sqli-deep") == nil {
		t.Fatal("markdown 技能仍应可用")
	}
	// 降级态下 LabOnly 走策展兜底
	if !reg.LabOnly("persistence") {
		t.Fatal("降级态策展兜底应生效（persistence）")
	}
}

func TestV532LabOnlyManifestDriven(t *testing.T) {
	skills := map[string]string{
		"lab-skill":  "---\nid: lab-skill\ntitle: t\ntags: s6\n---\n正文",
		"safe-skill": "---\nid: safe-skill\ntitle: t\ntags: s4\n---\n正文",
	}
	manifest := `{"count":2,"skills":[{"id":"lab-skill","file":"skills/lab-skill.md","title":"t","tags":["s6"],"lab_only":true},
	 {"id":"safe-skill","file":"skills/safe-skill.md","title":"t","tags":["s4"]}]}`
	reg, _ := LoadSkills(writeSkillDir(t, skills, manifest))
	if !reg.LabOnly("lab-skill") || reg.LabOnly("safe-skill") {
		t.Fatal("manifest lab_only 标注应驱动 LabOnly 判定")
	}
}

func TestV532MultiKeywordSearch(t *testing.T) {
	skills := map[string]string{
		"sqli-deep":   "---\nid: sqli-deep\ntitle: SQL注入深测\ntags: s4,注入\n---\n正文提及 报价 单",
		"chain-proxy": "---\nid: chain-proxy\ntitle: 链式代理\ntags: s4,工具\n---\n正文提及 报价 注入",
		"zzz-other":   "---\nid: zzz-other\ntitle: 其他\ntags: s2\n---\n正文提及 报价",
	}
	reg, _ := LoadSkills(writeSkillDir(t, skills, ""))
	// 多关键词叠加：sqli-deep 命中 id 前缀(sqli)+tags(注入)；chain-proxy 只命中正文两词；
	// zzz-other 与查询无交集 → 不入列（无命中不硬凑）
	hits := reg.Search("sqli 注入", 5)
	if len(hits) == 0 || hits[0].ID != "sqli-deep" {
		t.Fatalf("多关键词检索首位应为 sqli-deep: %v", skillIDs(hits))
	}
	if len(hits) < 2 || hits[1].ID != "chain-proxy" {
		t.Fatalf("第二位应为 chain-proxy: %v", skillIDs(hits))
	}
	for _, h := range hits {
		if h.ID == "zzz-other" {
			t.Fatalf("无命中词技能不应入列: %v", skillIDs(hits))
		}
	}
	// 确定性：同分并列按 ID 升序
	hits2 := reg.Search("zzz", 5)
	if len(hits2) != 1 || hits2[0].ID != "zzz-other" {
		t.Fatalf("单关键词精确检索: %v", skillIDs(hits2))
	}
}

func TestV532AliasSearch(t *testing.T) {
	skills := map[string]string{
		"sqli-deep": "---\nid: sqli-deep\ntitle: SQL注入深测\ntags: s4\n---\n正文",
	}
	manifest := `{"count":1,"skills":[{"id":"sqli-deep","file":"skills/sqli-deep.md","title":"SQL注入深测","tags":["s4"],"aliases":["sql注入","盲注"]}]}`
	reg, _ := LoadSkills(writeSkillDir(t, skills, manifest))
	hits := reg.Search("盲注 怎么测", 5)
	if len(hits) == 0 || hits[0].ID != "sqli-deep" {
		t.Fatalf("别名应参与检索: %v", skillIDs(hits))
	}
}

func TestV532StageAwareSearch(t *testing.T) {
	skills := map[string]string{
		"aaa-inject": "---\nid: aaa-inject\ntitle: 注入测试\ntags: s4,注入\n---\n注入 正文",
		"bbb-inject": "---\nid: bbb-inject\ntitle: 注入深测\ntags: s5,注入\n---\n注入 正文",
	}
	reg, _ := LoadSkills(writeSkillDir(t, skills, ""))
	// 同分并列（同词同权）：s5 阶段上下文下 bbb-inject（stage_fit/tags=s5）应优先
	hits := reg.SearchCtx("注入", "s5", 5)
	if len(hits) < 2 || hits[0].ID != "bbb-inject" {
		t.Fatalf("阶段感知排序应优先 s5 技能: %v", skillIDs(hits))
	}
	hits2 := reg.SearchCtx("注入", "s4", 5)
	if hits2[0].ID != "aaa-inject" {
		t.Fatalf("s4 上下文应优先 aaa-inject: %v", skillIDs(hits2))
	}
}

func TestV532BundleComposition(t *testing.T) {
	skills := map[string]string{
		"sqli-deep":        "---\nid: sqli-deep\ntitle: SQL注入深测\ntags: s4\n---\n正文A",
		"chain-proxy":      "---\nid: chain-proxy\ntitle: 链式代理\ntags: s4\n---\n正文B",
		"evidence-standard": "---\nid: evidence-standard\ntitle: 证据标准\ntags: s8\n---\n正文C",
	}
	reg, _ := LoadSkills(writeSkillDir(t, skills, fixtureManifest))
	// Bundle：主命中 sqli-deep + depends_on(chain-proxy) + handoff_to(evidence-standard)
	bundle := reg.Bundle("sqli-deep", "s4", 5)
	got := skillIDs(bundle)
	if len(got) != 3 || got[0] != "sqli-deep" || got[1] != "chain-proxy" || got[2] != "evidence-standard" {
		t.Fatalf("组合展开应含主命中+配合+交接: %v", got)
	}
	// 幽灵依赖被静默跳过（无阶段上下文：chain-proxy 不因阶段加分入列，仅剩 handoff 展开）
	manifest := strings.Replace(fixtureManifest, `"depends_on":["chain-proxy"]`, `"depends_on":["ghost-x"]`, 1)
	reg2, _ := LoadSkills(writeSkillDir(t, skills, manifest))
	b2 := skillIDs(reg2.Bundle("sqli-deep", "", 5))
	if len(b2) != 2 || b2[0] != "sqli-deep" || b2[1] != "evidence-standard" {
		t.Fatalf("不存在的依赖应跳过: %v", b2)
	}
}

func skillIDs(s []*Skill) []string {
	out := []string{}
	for _, x := range s {
		out = append(out, x.ID)
	}
	return out
}
