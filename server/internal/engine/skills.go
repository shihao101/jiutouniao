package engine

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync/atomic"
)

// Skill 技能库单元（移植自 strix skills/ 双通道注入 + PentesterFlow SKILL.md 约定）：
// frontmatter 含 id/title/tags，正文为攻击剧本/清单。阶段头按需 load_skill 注入，
// 避免把全部知识塞进 system prompt 撑爆上下文。
type Skill struct {
	ID    string   `json:"id"`
	Title string   `json:"title"`
	Tags  []string `json:"tags"`
	Body  string   `json:"body"` // 正文（技能库浏览需要展示全文）
	// v5.3.2 P1-1/P1-2：manifest 元数据（frontmatter 三字段之外的结构化扩展，来源于 skills/manifest.json）
	Aliases   []string `json:"aliases,omitempty"`    // 别名/同义词（检索入口）
	DependsOn []string `json:"depends_on,omitempty"` // 配合技能（组合选择展开）
	HandoffTo []string `json:"handoff_to,omitempty"` // 交接/后续技能
	StageFit  []string `json:"stage_fit,omitempty"`  // 适用阶段（s1..s8/specA/B1/B2）
	LabOnly   bool     `json:"lab_only,omitempty"`   // 含 Lab Only 高危动作（production_safe 下 load_skill 注入禁用横幅）
}

// SkillMeta manifest.json 单技能条目（生成器 scripts/gen_skill_manifest.py 单源产出）。
type SkillMeta struct {
	ID         string   `json:"id"`
	File       string   `json:"file"`
	Title      string   `json:"title"`
	Tags       []string `json:"tags"`
	Aliases    []string `json:"aliases,omitempty"`
	DependsOn  []string `json:"depends_on,omitempty"`
	HandoffTo  []string `json:"handoff_to,omitempty"`
	StageFit   []string `json:"stage_fit,omitempty"`
	LabOnly    bool     `json:"lab_only,omitempty"`
	ProfileDef string   `json:"execution_profile_default,omitempty"`
	LabOnlyAct string   `json:"lab_only_actions,omitempty"`
}

// manifestFile manifest.json 顶层结构（v5.3.0 §14 引入，v5.3.2 扩展 aliases/depends_on/handoff_to/stage_fit/lab_only）。
type manifestFile struct {
	Version string      `json:"version"`
	Count   int         `json:"count"`
	Skills  []SkillMeta `json:"skills"`
}

type SkillRegistry struct {
	skills   map[string]*Skill
	manifest map[string]*SkillMeta // manifest.json 元数据（缺失/失配时降级 markdown-only，启动日志告警）
	mOK      bool
	lastMain atomic.Int64 // v5.9.0：最近一次检索主命中数（Bundle 标签判定用）
}

// LastMainHitCount v5.9.0：最近一次 searchScored/Bundle 的主命中数。
func (r *SkillRegistry) LastMainHitCount() int {
	return int(r.lastMain.Load())
}

// LoadSkills 从目录加载技能（markdown + frontmatter：id/title/tags）。
// v5.3.2 P1-1：同目录 manifest.json 一并消费——条目 id 与 .md 文件双向对齐校验，
// 失配只告警降级（知识面单一事实源漂移不得静默，也不得阻断引擎启动）。
func LoadSkills(dir string) (*SkillRegistry, error) {
	reg := &SkillRegistry{skills: map[string]*Skill{}, manifest: map[string]*SkillMeta{}}
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return reg, nil // 无技能目录时降级为空库
		}
		return nil, err
	}
	for _, ent := range entries {
		if ent.IsDir() || !strings.HasSuffix(ent.Name(), ".md") {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(dir, ent.Name()))
		if err != nil {
			continue
		}
		s := parseSkill(string(raw))
		if s.ID == "" {
			s.ID = strings.TrimSuffix(ent.Name(), ".md")
		}
		reg.skills[s.ID] = s
	}
	reg.loadManifest(dir)
	return reg, nil
}

// loadManifest 读取并校验 manifest.json：条目 id 必须 .md 对应存在、file 指向该技能文件、
// count 与实际技能数一致。通过则元数据并入 Skill（frontmatter 仍为正文与标题的兜底事实源）。
func (r *SkillRegistry) loadManifest(dir string) {
	raw, err := os.ReadFile(filepath.Join(dir, "manifest.json"))
	if err != nil {
		log.Printf("技能库 manifest.json 缺失（降级 markdown-only）：无 aliases/depends_on/stage_fit 元数据")
		return
	}
	var mf manifestFile
	if err := json.Unmarshal(raw, &mf); err != nil {
		log.Printf("技能库 manifest.json 解析失败（降级 markdown-only）: %v", err)
		return
	}
	problems := []string{}
	for i := range mf.Skills {
		m := &mf.Skills[i]
		if m.ID == "" {
			problems = append(problems, fmt.Sprintf("第 %d 条缺 id", i+1))
			continue
		}
		s, ok := r.skills[m.ID]
		if !ok {
			problems = append(problems, fmt.Sprintf("manifest 条目 %s 无对应 .md 文件", m.ID))
			continue
		}
		if m.File != "" && m.File != "skills/"+m.ID+".md" {
			problems = append(problems, fmt.Sprintf("manifest 条目 %s file 字段漂移: %s", m.ID, m.File))
			continue
		}
		r.manifest[m.ID] = m
		// 元数据并入（frontmatter 三字段以 .md 为准；扩展字段仅 manifest 提供）
		if len(m.Aliases) > 0 {
			s.Aliases = m.Aliases
		}
		if len(m.DependsOn) > 0 {
			s.DependsOn = m.DependsOn
		}
		if len(m.HandoffTo) > 0 {
			s.HandoffTo = m.HandoffTo
		}
		if len(m.StageFit) > 0 {
			s.StageFit = m.StageFit
		}
		if m.LabOnly {
			s.LabOnly = true
		}
	}
	if len(problems) > 0 {
		log.Printf("技能库 manifest 校验失配（降级 markdown-only，前 5 条）: %v；技能文件 %d 个 / manifest 对齐 %d 条 / count=%d",
			problems[:min(5, len(problems))], len(r.skills), len(r.manifest), mf.Count)
		return
	}
	if mf.Count != len(r.skills) {
		log.Printf("技能库 manifest count=%d 与实际技能数 %d 不一致（降级 markdown-only）", mf.Count, len(r.skills))
		return
	}
	r.mOK = true
	log.Printf("技能库 manifest 已消费: %d/%d 技能元数据对齐（aliases/depends_on/handoff_to/stage_fit/lab_only 生效）", len(r.manifest), len(r.skills))
}

// LabOnly 技能是否含 Lab Only 高危动作：manifest 标注为准，策展清单兜底（manifest 降级时仍强制）。
func (r *SkillRegistry) LabOnly(id string) bool {
	id = strings.TrimSpace(id)
	if r == nil {
		return labOnlySkillIds[id] // nil registry（极简测试环境）：策展兜底
	}
	if s := r.skills[id]; s != nil && s.LabOnly {
		return true
	}
	if r.mOK {
		return false // manifest 在位且未标注 → 以清单为准
	}
	return labOnlySkillIds[id] // 降级：策展兜底
}

func parseSkill(raw string) *Skill {
	s := &Skill{}
	body := raw
	if strings.HasPrefix(raw, "---") {
		parts := strings.SplitN(raw, "---", 3)
		if len(parts) >= 3 {
			body = strings.TrimSpace(parts[2])
			for _, line := range strings.Split(parts[1], "\n") {
				kv := strings.SplitN(strings.TrimSpace(line), ":", 2)
				if len(kv) != 2 {
					continue
				}
				k, v := strings.TrimSpace(kv[0]), strings.TrimSpace(kv[1])
				switch k {
				case "id":
					s.ID = strings.Trim(v, `"`) // v3.4.3：剥离 frontmatter 引号（00-router 曾以 `"00-router"` 含引号入库，按 id 精确加载失配）
				case "title":
					s.Title = v
				case "tags":
					for _, t := range strings.Split(v, ",") {
						if t = strings.TrimSpace(t); t != "" {
							s.Tags = append(s.Tags, strings.Trim(t, `"`))
						}
					}
				}
			}
		}
	}
	s.Body = body
	return s
}

// tokenize 检索分词：空白 + 常见分隔符（多关键词检索 v5.3.2 P1-3）。
func tokenize(q string) []string {
	seps := func(r rune) bool {
		return r == ' ' || r == '\t' || r == '、' || r == ',' || r == '，' || r == '+' || r == '/' || r == ';' || r == '|'
	}
	var out []string
	for _, t := range strings.FieldsFunc(strings.ToLower(strings.TrimSpace(q)), seps) {
		if t != "" {
			out = append(out, t)
		}
	}
	return out
}

// Search 多关键词检索（v5.3.2 P1-3 升级，PentesterFlow skillRouter 风格）：
// 查询分词后逐词加权（id 精确 15 / 别名 12 / 标题 10 / tags 5 / 正文 2），总分排序；
// 多词命中叠加（命中词数越多越靠前）。
// v5.3.0 P1-2：确定性排序——同分按 ID 升序（消除 map 遍历顺序导致的并列不稳定），多级并列键保持。
func (r *SkillRegistry) Search(query string, n int) []*Skill {
	return r.searchScored(query, "", n).hits
}

// SearchCtx 上下文感知检索：在 Search 基础上按当前阶段（s1..s8/specA/B1/B2）与 manifest
// stage_fit/tags 匹配加分（+3）——同分情况下优先返回适用当前阶段的技能。
func (r *SkillRegistry) SearchCtx(query, stage string, n int) []*Skill {
	hits := r.searchScored(query, stage, n)
	r.lastMain.Store(int64(len(hits.hits)))
	return hits.hits
}

// Bundle 组合选择：top 命中技能按 manifest depends_on/handoff_to 展开配合技能（去重、
// 只展开存在项），返回 [主命中..., 配合...] 有序清单——阶段头一次拿到可直接组合的技能集。
// lastMain 记录最近一次检索的主命中数（v5.9.0 标签判定；并发下近似值即可）。
func (r *SkillRegistry) Bundle(query, stage string, n int) []*Skill {
	sc := r.searchScored(query, stage, n)
	out := sc.hits
	// v5.9.0（方案 P2-5）：记录主命中数供标签判定（主命中 vs depends_on/handoff_to 扩展）
	r.lastMain.Store(int64(len(sc.hits)))
	seen := map[string]bool{}
	for _, h := range sc.hits {
		seen[h.ID] = true
	}
	var companions []*Skill
	for _, h := range sc.hits {
		for _, dep := range append(append([]string{}, h.DependsOn...), h.HandoffTo...) {
			if seen[dep] {
				continue
			}
			if s := r.Get(dep); s != nil {
				seen[dep] = true
				companions = append(companions, s)
			}
		}
	}
	out = append(out, companions...)
	if n > 0 && len(out) > n*2 { // 配合展开上限：主命中数 ×2
		out = out[:n*2]
	}
	return out
}

// searchScored 多关键词打分核心（Search/SearchCtx/Bundle 共用）。
func (r *SkillRegistry) searchScored(query, stage string, n int) *scoredResult {
	if r == nil {
		return &scoredResult{}
	}
	type hit struct {
		s     *Skill
		score int
		terms int
	}
	terms := tokenize(query)
	stage = strings.ToLower(strings.TrimSpace(stage))
	var hits []hit
	for _, s := range r.skills {
		score, matched := 0, 0
		idL, titleL := strings.ToLower(s.ID), strings.ToLower(s.Title)
		for _, q := range terms {
			t := 0
			if idL == q || strings.HasPrefix(idL, q) || strings.HasSuffix(idL, q) {
				t += 15 // id 精确/前后缀命中
			} else if strings.Contains(idL, q) {
				t += 8
			}
			for _, a := range s.Aliases {
				al := strings.ToLower(a)
				if al == q || strings.Contains(q, al) || strings.Contains(al, q) {
					t += 12
					break
				}
			}
			if strings.Contains(titleL, q) || strings.Contains(q, idL) {
				t += 10
			}
			for _, tag := range s.Tags {
				tl := strings.ToLower(tag)
				if tl == q || strings.Contains(q, tl) || strings.Contains(tl, q) {
					t += 5
					break
				}
			}
			if strings.Contains(strings.ToLower(s.Body), q) {
				t += 2
			}
			if t > 0 {
				matched++
			}
			score += t
		}
		// 上下文感知：stage_fit 或 tags 命中当前阶段 +3（v5.3.2 P1-3）
		if stage != "" {
			for _, f := range append(append([]string{}, s.StageFit...), s.Tags...) {
				if strings.EqualFold(strings.TrimSpace(f), stage) {
					score += 3
					break
				}
			}
		}
		if score > 0 {
			hits = append(hits, hit{s, score, matched})
		}
	}
	// 确定性排序：总分降序 → 命中词数降序 → ID 升序（消除并列不稳定）
	sort.Slice(hits, func(i, j int) bool {
		if hits[i].score != hits[j].score {
			return hits[i].score > hits[j].score
		}
		if hits[i].terms != hits[j].terms {
			return hits[i].terms > hits[j].terms
		}
		return hits[i].s.ID < hits[j].s.ID
	})
	if n <= 0 || n > len(hits) {
		n = len(hits)
	}
	out := make([]*Skill, 0, n)
	for _, h := range hits[:n] {
		out = append(out, h.s)
	}
	return &scoredResult{hits: out}
}

type scoredResult struct{ hits []*Skill }

// Get 按 id 取技能。
func (r *SkillRegistry) Get(id string) *Skill {
	if r == nil {
		return nil
	}
	return r.skills[strings.TrimSpace(id)]
}

// Index 生成技能索引（注入每阶段上下文，供头按需 load_skill）。
// v5.3.2：manifest 在位时索引行追加别名/配合/交接摘要，给头结构化路由信号。
func (r *SkillRegistry) Index() string {
	if r == nil || len(r.skills) == 0 {
		return "（技能库为空）"
	}
	ids := make([]string, 0, len(r.skills))
	for id := range r.skills {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	var b strings.Builder
	b.WriteString(fmt.Sprintf("共 %d 个技能：\n", len(ids)))
	for _, id := range ids {
		s := r.skills[id]
		line := fmt.Sprintf("- %s：%s（tags: %s）", s.ID, s.Title, strings.Join(s.Tags, "/"))
		if r.mOK {
			extra := ""
			if len(s.Aliases) > 0 {
				extra += " 别名:" + strings.Join(s.Aliases, "|")
			}
			if len(s.DependsOn) > 0 {
				extra += " 配合:" + strings.Join(s.DependsOn, "|")
			}
			if len(s.HandoffTo) > 0 {
				extra += " 交接:" + strings.Join(s.HandoffTo, "|")
			}
			if s.LabOnly {
				extra += " [Lab Only]"
			}
			if extra != "" {
				line += " —" + extra
			}
		}
		b.WriteString(line + "\n")
	}
	return b.String()
}

// stageKeywords v7.5.0（C1）：阶段 → 技能匹配关键词（manifest.StageFit 缺失时的兜底打分词表）。
var stageKeywords = map[string][]string{
	"s1":     {"recon", "subdomain", "osint", "dns", "whois", "fingerprint", "被动", "足迹", "子域", "信息收集"},
	"s2":     {"asset", "surface", "port", "topology", "mapping", "测绘", "资产", "攻击面", "拓扑"},
	"s3":     {"threat", "plan", "stride", "model", "matrix", "威胁", "测试计划", "判定", "假设"},
	"s4":     {"web", "api", "auth", "inject", "xss", "sqli", "ssrf", "upload", "waf", "poc", "exploit", "idor", "漏洞", "注入", "越权", "上传"},
	"s5":     {"exploit", "bypass", "post", "credential", "session", "利用", "登录", "后渗透", "凭据", "绕过"},
	"s6":     {"lateral", "privesc", "persist", "domain", "pivot", "横向", "提权", "持久化", "权限"},
	"s7":     {"cleanup", "loot", "handover", "exfil", "清理", "收尾", "移交", "待续"},
	"s8":     {"report", "evidence", "finding", "writing", "报告", "证据", "定级"},
	"specA":  {"llm", "ai", "prompt", "agent", "智能体", "注入"},
	"specB1": {"app", "android", "ios", "static", "hook", "客户端", "脱壳"},
	"specB2": {"miniapp", "wechat", "小程序", "解包"},
	"chat":   {"router", "workflow", "方法", "流程"},
}

// skillStageScore C1 兜底打分：id/title/tags 命中阶段关键词计分（>0 即视为该阶段相关）。
func skillStageScore(s *Skill, stageID string) int {
	kws, ok := stageKeywords[stageID]
	if !ok {
		return 0
	}
	hay := strings.ToLower(s.ID + " " + s.Title + " " + strings.Join(s.Tags, " "))
	n := 0
	for _, kw := range kws {
		if strings.Contains(hay, strings.ToLower(kw)) {
			n++
		}
	}
	return n
}

// isCoreSkill C1：核心路由/纪律技能恒在分阶索引（不随阶段过滤丢失）。
func isCoreSkill(id string) bool {
	return id == "00-router" || id == "capability-primitive-search" || id == "evidence-standard" || strings.HasPrefix(id, "00-")
}

// IndexForStage v7.5.0（C1 分阶技能索引）：只注入与当前阶段相关的技能行（≤cap 行），
// 核心路由/纪律技能恒在；数据源优先 manifest.StageFit 结构化元数据，缺失时关键词打分兜底；
// 命中不足 3 个（低置信度）返回 ok=false 由调用方回退全量索引——宁可多注入不漏技能。
// 头仍可用 load_skill(id) 载全文 / load_skill(query) 检索全库（通道现成，注入策略只是
// 把「全量扫描」改为「按需检索」——ZCode 技能渐进披露 / PentAGI 检索回流同款）。
func (r *SkillRegistry) IndexForStage(stageID string, cap int) (string, bool) {
	if r == nil || len(r.skills) == 0 {
		return "", false
	}
	if cap <= 0 {
		cap = 30
	}
	type scored struct {
		id    string
		score int
	}
	var sel []scored
	fitCount := 0
	for id, s := range r.skills {
		score := 0
		if m := r.manifest[id]; m != nil && len(m.StageFit) > 0 {
			for _, sf := range m.StageFit {
				if sf == stageID {
					score = 10
					break
				}
			}
		}
		if score == 0 {
			score = skillStageScore(s, stageID)
		}
		if score > 0 {
			fitCount++
		}
		if score > 0 || isCoreSkill(id) {
			sel = append(sel, scored{id: id, score: score})
		}
	}
	if fitCount < 3 {
		// 低置信度回退线取 3：真实技能库中 s8 类收尾阶段天然只有 3 个相关技能
		//（report-writing/evidence-standard/autonomy-proposal）——绝对数小≠元数据缺失；
		// 回退防的是「元数据坏了选不出东西」，防漏由核心技能恒在 + eval 盲挖指标兜底。
		return "", false
	}
	sort.Slice(sel, func(i, j int) bool {
		if sel[i].score != sel[j].score {
			return sel[i].score > sel[j].score
		}
		return sel[i].id < sel[j].id
	})
	if len(sel) > cap {
		sel = sel[:cap]
	}
	var b strings.Builder
	fmt.Fprintf(&b, "共 %d 个技能，本阶段相关 %d 个（其余用 load_skill query 检索全库）：\n", len(r.skills), len(sel))
	for _, sc := range sel {
		b.WriteString(r.indexLine(sc.id))
	}
	return b.String(), true
}

// indexLine 单技能索引行（与 Index() 同格式，manifest 元数据一并呈现）。
func (r *SkillRegistry) indexLine(id string) string {
	s := r.skills[id]
	if s == nil {
		return ""
	}
	line := fmt.Sprintf("- %s：%s（tags: %s）", s.ID, s.Title, strings.Join(s.Tags, "/"))
	if r.mOK {
		extra := ""
		if len(s.Aliases) > 0 {
			extra += " 别名:" + strings.Join(s.Aliases, "|")
		}
		if len(s.DependsOn) > 0 {
			extra += " 配合:" + strings.Join(s.DependsOn, "|")
		}
		if len(s.HandoffTo) > 0 {
			extra += " 交接:" + strings.Join(s.HandoffTo, "|")
		}
		if s.LabOnly {
			extra += " [Lab Only]"
		}
		if extra != "" {
			line += " —" + extra
		}
	}
	return line + "\n"
}
