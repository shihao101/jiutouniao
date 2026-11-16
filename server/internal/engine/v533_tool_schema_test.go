// v5.3.3 工具 schema 严格性回归：全量 ToolDef 递归校验——JSON Schema 节点必须为 map，
// 禁止裸字符串混入 properties/items（实证：evidence_ids 误用 arr() 包裹致严格校验供应商
// 400 拒绝整个请求，s1 无法启动，任务"LLM 拒绝"）。
package engine

import (
	"strings"
	"testing"
)

// validateSchemaNode 递归校验一个 schema 节点：type/description 为字符串，properties 与
// properties 的每个值、items 必须是 map[string]any（即 JSON Schema 对象），非法即返回问题清单。
func validateSchemaNode(node map[string]any, path string) []string {
	var bad []string
	for k, v := range node {
		switch k {
		case "type", "description":
			if _, ok := v.(string); !ok && v != nil {
				bad = append(bad, path+"."+k+" 应为字符串: "+toString(v))
			}
		case "properties":
			props, ok := v.(map[string]any)
			if !ok {
				bad = append(bad, path+".properties 应为对象: "+toString(v))
				continue
			}
			for name, pv := range props {
				pmap, ok := pv.(map[string]any)
				if !ok {
					bad = append(bad, path+".properties."+name+" 必须是 schema 对象（禁止裸值）: "+toString(pv))
					continue
				}
				bad = append(bad, validateSchemaNode(pmap, path+".properties."+name)...)
			}
		case "items":
			imap, ok := v.(map[string]any)
			if !ok {
				bad = append(bad, path+".items 必须是 schema 对象（禁止裸值/裸字符串——供应商严格校验即 400 拒绝）: "+toString(v))
				continue
			}
			bad = append(bad, validateSchemaNode(imap, path+".items")...)
		case "required":
			// obj() 助手写入的是 Go []string（JSON 序列化正常）；运行时反序列化形态为 []any——两者皆合法
			_, isStrArr := v.([]string)
			_, isAnyArr := v.([]any)
			if !isStrArr && !isAnyArr {
				bad = append(bad, path+".required 应为数组: "+toString(v))
			}
		}
	}
	return bad
}

func toString(v any) string {
	if m, ok := v.(map[string]any); ok {
		parts := []string{"{"}
		for k, mv := range m {
			parts = append(parts, k+"="+toString(mv))
		}
		parts = append(parts, "}")
		return strings.Join(parts, " ")
	}
	if s, ok := v.(string); ok {
		return "\"" + s[:min(40, len(s))] + "\""
	}
	return "?"
}

func TestV533ToolDefsSchemaStrict(t *testing.T) {
	o, _ := v48Orchestrator(t)
	defs := o.toolDefs()
	if len(defs) < 15 {
		t.Fatalf("工具定义数量异常: %d", len(defs))
	}
	var bad []string
	for _, d := range defs {
		params := d.Parameters
		if params == nil {
			continue
		}
		bad = append(bad, validateSchemaNode(params, d.Name)...)
	}
	if len(bad) > 0 {
		t.Fatalf("工具 schema 存在严格校验不通过节点（供应商将 400 拒绝）:\n  %s", strings.Join(bad, "\n  "))
	}
}
