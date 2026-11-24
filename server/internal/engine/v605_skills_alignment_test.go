package engine

// v6.0.5 P0 验收：真实技能库一致性回归门——manifest ↔ 文件 ↔ 引用三方对齐。
// 任何新增技能未注册 manifest、任何 depends_on/handoff_to/load_skill 指向不存在 id，都会在此拦截。

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

const v605RepoSkills = "../../../skills"

func TestV605RealSkillsAlignment(t *testing.T) {
	skillDir := filepath.Join("..", "..", "..", "skills")
	if _, err := os.Stat(skillDir); err != nil {
		t.Skipf("仓库 skills 目录不可达（非源码树运行）: %v", err)
	}
	files := map[string]bool{}
	if entries, err := os.ReadDir(skillDir); err == nil {
		for _, en := range entries {
			if filepath.Ext(en.Name()) == ".md" {
				files[en.Name()[:len(en.Name())-3]] = true
			}
		}
	}
	if len(files) < 100 {
		t.Fatalf("真实技能文件数异常: %d", len(files))
	}
	raw, err := os.ReadFile(filepath.Join(skillDir, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var m struct {
		Count  int `json:"count"`
		Skills []struct {
			ID         string   `json:"id"`
			File       string   `json:"file"`
			StageFit   []string `json:"stage_fit"`
			DependsOn  []string `json:"depends_on"`
			HandoffTo  []string `json:"handoff_to"`
		} `json:"skills"`
	}
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	// ① manifest.count 与条数一致
	if m.Count != len(m.Skills) {
		t.Fatalf("manifest.count=%d != skills 条数 %d", m.Count, len(m.Skills))
	}
	// ② manifest ↔ 文件双向对齐
	for _, s := range m.Skills {
		if !files[s.ID] {
			t.Errorf("manifest 注册了不存在的技能文件: %s", s.ID)
		}
	}
	for id := range files {
		if id == "00-router" {
			continue
		}
		found := false
		for _, s := range m.Skills {
			if s.ID == id {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("技能文件 %s.md 未注册进 manifest（孤儿）", id)
		}
	}
	// ③ 引用完整性：depends_on / handoff_to / 文内 load_skill 必须指向存在 id
	ids := files
	loadRe := regexp.MustCompile(`\bload_skill\s*\(?\s*([\w-]+)`)
	for _, s := range m.Skills {
		for _, ref := range append(s.DependsOn, s.HandoffTo...) {
			if ref != "" && !ids[ref] && ref != "00-router" {
				t.Errorf("%s 的引用指向不存在的技能: %q（via manifest）", s.ID, ref)
			}
		}
		if s.ID == "00-router" {
			continue // 00-router 是用法说明文档，正文含教学占位符 load_skill(id)，不作引用校验
		}
		body, err := os.ReadFile(filepath.Join(skillDir, s.ID+".md"))
		if err == nil {
			for _, ref := range loadRe.FindAllStringSubmatch(string(body), -1) {
				if ref[1] != "00-router" && !ids[ref[1]] {
					t.Errorf("%s 文内 load_skill 指向不存在的技能: %q", s.ID, ref[1])
				}
			}
		}
	}
	// ④ 头文件 load_skill 引用完整性
	headDir := filepath.Join("..", "..", "..", "heads")
	if entries, err := os.ReadDir(headDir); err == nil {
		for _, en := range entries {
			if filepath.Ext(en.Name()) != ".md" {
				continue
			}
			body, err := os.ReadFile(filepath.Join(headDir, en.Name()))
			if err != nil {
				continue
			}
			for _, ref := range loadRe.FindAllStringSubmatch(string(body), -1) {
				if ref[1] != "00-router" && !ids[ref[1]] {
					t.Errorf("heads/%s load_skill 指向不存在的技能: %q", en.Name(), ref[1])
				}
			}
		}
	}
	// ⑤ v6.0.5 三个新技能必须在库
	for _, need := range []string{"business-state-machine", "identity-flow-audit", "http-security-headers"} {
		if !ids[need] {
			t.Errorf("v6.0.5 新技能缺失: %s", need)
		}
	}
}

// TestV605RealSkillsLoaderRoundTrip v6.0.5：用引擎真实加载器 LoadSkills 解析仓库 skills 目录——
// 验证新增/存量剧本的 frontmatter 格式可被引擎消费（id/title/tags 解析成功、126+ 技能全部载入、
// manifest 元数据并入不报错）。正则审计通过但格式漂移导致的加载失败在此兜底。
func TestV605RealSkillsLoaderRoundTrip(t *testing.T) {
	skillDir := filepath.Join("..", "..", "..", "skills")
	if _, err := os.Stat(skillDir); err != nil {
		t.Skipf("仓库 skills 目录不可达: %v", err)
	}
	reg, err := LoadSkills(skillDir)
	if err != nil {
		t.Fatalf("LoadSkills 解析失败（frontmatter 格式漂移）: %v", err)
	}
	if got := len(reg.skills); got < 125 {
		t.Fatalf("载入技能数异常: %d（应 ≥125）", got)
	}
	for _, need := range []string{"business-state-machine", "identity-flow-audit", "http-security-headers", "api-idor", "hypothesis-matrix", "00-router"} {
		if sk := reg.Get(need); sk == nil {
			t.Errorf("关键技能 %s 未被引擎加载器解析", need)
		} else if strings.TrimSpace(sk.Title) == "" || strings.TrimSpace(sk.Body) == "" {
			t.Errorf("技能 %s 的 title/body 为空（解析漂移）", need)
		}
	}
}
