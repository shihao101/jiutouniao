package engine

import (
	"strings"

	"jiutouniao/internal/store"
)

// v4.4 方向二（多目标 × 阶段迭代预算）核心纯函数。
// 口径：项目目标数以 p.Target 按行拆分为准——与 buildContextPack 的「多目标完整呈现」
// （v2.4.0：逐行列出全部目标，S1 逐个登记测绘）同一事实源，不做正则启发式解析。

// splitProjectTargets v4.4 批次6：按非空行拆分项目目标（与 buildContextPack 多目标呈现同一事实源）。
func splitProjectTargets(p *store.Project) []string {
	if p == nil {
		return nil
	}
	out := make([]string, 0, 4)
	for _, line := range strings.Split(p.Target, "\n") {
		if t := strings.TrimSpace(line); t != "" {
			out = append(out, t)
		}
	}
	return out
}

// countProjectTargets 统计项目目标数：p.Target 按非空行计数；空串/全空行返回 1（单目标语义不变）。
func countProjectTargets(p *store.Project) int {
	if n := len(splitProjectTargets(p)); n > 0 {
		return n
	}
	return 1
}

// targetCoverageRecon v4.4 批次6（方向二E）S4 分段收口对账纯函数：
// 逐目标判定「已归宿」——归一化小写后出现在覆盖矩阵语料（endpoint/param/vuln_class/notes）
// 或交付物语料（分组交付物/待续清单/档案目标）中即已归宿；返回未归宿清单与已归宿数。
// 匹配口径与 G2 checklistItemCovered 同族（normCovText 归一化 + 包含判定）。
func targetCoverageRecon(targets []string, covCorpus, delivCorpus string) (missing []string, matched int) {
	nc, nd := normCovText(covCorpus), normCovText(delivCorpus)
	missing = make([]string, 0)
	for _, t := range targets {
		nt := normCovText(t)
		if nt == "" {
			continue
		}
		if strings.Contains(nc, nt) || strings.Contains(nd, nt) {
			matched++
		} else {
			missing = append(missing, t)
		}
	}
	return missing, matched
}

// stageBudget 阶段迭代轮次预算：
//   - s8/s4 保持 ×2（v2.3.2 既有：报告/文档阶段写入量大且需承接全部交付物；
//     v4.9 F3：s4 漏洞发现同样 ×2——最重执行阶段（串行深挖+子代理扇出+收口对账），
//     60 轮实证结构性不足，兰州项目 s4 曾六连败撞上限）；
//   - S2/S4/S5 多目标自适应（方向二B）：base*mult + (N-1)*perTarget，封顶 3×base×mult——
//     侦察/漏洞发现/利用是随目标数线性增长的工作量，轮次封顶不随之放大=多目标必然浅测；
//   - 其余阶段与 perTarget<=0（禁用自适应）时维持原值。
func stageBudget(base int, stageID string, targets, perTarget int) int {
	mult := 1
	if stageID == "s8" || stageID == "s4" {
		mult = 2
	}
	budget := base * mult
	if targets > 1 && perTarget > 0 {
		switch stageID {
		case "s2", "s4", "s5":
			budget = base*mult + (targets-1)*perTarget
			if max := base * 3 * mult; budget > max {
				budget = max
			}
		}
	}
	return budget
}
