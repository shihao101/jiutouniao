// Package engine 九头鸟核心：头（专家）注册、审批矩阵与执行编排。
package engine

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Head 一个「头」= 一个阶段的专家人格（提示词）。
type Head struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	Kind  string `json:"kind"`  // main / stage / spec
	Stage string `json:"stage"` // 流程图阶段号（stage 类）；spec 类为 A/B1/B2
	Body  string `json:"body"`  // 提示词正文
	Order int    `json:"order"` // 流水线顺序
}

// LoadHeads 从目录加载全部头定义（markdown + YAML 风格 frontmatter）。
func LoadHeads(dir string) (map[string]*Head, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("读取头目录失败: %w", err)
	}
	heads := map[string]*Head{}
	for _, ent := range entries {
		if ent.IsDir() || !strings.HasSuffix(ent.Name(), ".md") {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(dir, ent.Name()))
		if err != nil {
			return nil, err
		}
		h, body, err := parseFrontmatter(string(raw))
		if err != nil {
			return nil, fmt.Errorf("解析 %s: %w", ent.Name(), err)
		}
		if h.ID == "" {
			h.ID = strings.TrimSuffix(ent.Name(), ".md")
		}
		h.Body = body
		heads[h.ID] = h
	}
	assignOrder(heads)
	return heads, nil
}

// assignOrder 按渗透测试流水线固定顺序编号：
// 主流程 s0..s4 → 专项（A/B1/B2）→ s5..s9。专项介于阶段4与5之间（对应流程图「替换/扩展阶段2-5」语义）。
func assignOrder(heads map[string]*Head) {
	order := []string{"s1", "s2", "s3", "s4", "specA", "specB1", "specB2", "s5", "s6", "s7", "s8"}
	idx := map[string]int{}
	for i, id := range order {
		idx[id] = i + 1
	}
	for id, h := range heads {
		if n, ok := idx[id]; ok {
			h.Order = n
		} else if h.Kind != "main" {
			h.Order = 999 // 未知阶段排最后
		}
	}
}

// Pipeline 返回项目实际要跑的流水线（含已启用专项）。
func Pipeline(heads map[string]*Head, specializations []string) []string {
	// v1.4：阶段0（授权与立项）并入创建页授权确认，阶段9（复测验收）取消
	base := []string{"s1", "s2", "s3", "s4"}
	tail := []string{"s5", "s6", "s7", "s8"}
	specs := map[string]bool{}
	for _, s := range specializations {
		switch s {
		case "A", "B1", "B2":
			specs["spec"+s] = true
		}
	}
	var out []string
	out = append(out, base...)
	if specs["specA"] {
		out = append(out, "specA")
	}
	if specs["specB1"] {
		out = append(out, "specB1")
	}
	if specs["specB2"] {
		out = append(out, "specB2")
	}
	out = append(out, tail...)
	return out
}

// parseFrontmatter 解析 ```--- key: value ---``` 头部。
func parseFrontmatter(raw string) (*Head, string, error) {
	h := &Head{}
	body := raw
	if strings.HasPrefix(raw, "---") {
		parts := strings.SplitN(raw, "---", 3)
		if len(parts) >= 3 {
			fm := parts[1]
			body = strings.TrimSpace(parts[2])
			for _, line := range strings.Split(fm, "\n") {
				line = strings.TrimSpace(line)
				if line == "" {
					continue
				}
				kv := strings.SplitN(line, ":", 2)
				if len(kv) != 2 {
					continue
				}
				k := strings.TrimSpace(kv[0])
				v := strings.TrimSpace(kv[1])
				switch k {
				case "id":
					h.ID = v
				case "name":
					h.Name = v
				case "kind":
					h.Kind = v
				case "stage":
					h.Stage = v
				}
			}
		}
	}
	return h, body, nil
}
