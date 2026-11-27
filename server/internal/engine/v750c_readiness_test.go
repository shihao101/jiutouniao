// v7.5.0（C1）分阶技能索引就绪度回归：加载真实 skills/ 目录 + manifest.json，
// 逐阶段验证 IndexForStage 的命中质量——任一阶段低置信度回退即告警（启用 staged 前的
// 门禁数据）；核心路由技能恒在；缺技能目录的环境自动跳过（打包部署最小集不阻塞）。
package engine

import (
	"strings"
	"testing"
)

func TestV750C1SkillIndexRealLibraryReadiness(t *testing.T) {
	reg, err := LoadSkills("../../../skills")
	if err != nil {
		t.Skipf("技能目录不可达（打包环境）: %v", err)
	}
	if len(reg.skills) == 0 {
		t.Skip("空技能库（打包环境）")
	}
	t.Logf("技能库 %d 个；manifest 对齐 mOK=%v", len(reg.skills), reg.mOK)
	if !reg.mOK {
		t.Fatalf("manifest.json 未对齐（staged 模式的 StageFit 数据源缺失）")
	}
	stages := []string{"s1", "s2", "s3", "s4", "s5", "s6", "s7", "s8", "specA", "specB1", "specB2", "chat"}
	for _, st := range stages {
		sel, ok := reg.IndexForStage(st, 30)
		if !ok {
			t.Errorf("阶段 %s 低置信度回退（staged 不可用）——补 manifest.StageFit 或关键词表", st)
			continue
		}
		lines := strings.Count(sel, "\n- ") + strings.Count(sel, "\n共")
		if !strings.Contains(sel, "00-router") {
			t.Errorf("阶段 %s 缺核心路由技能", st)
		}
		t.Logf("阶段 %-6s 注入 %2d 行（含核心）", st, lines)
	}
}
