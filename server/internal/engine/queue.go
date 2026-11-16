package engine

import (
	"sort"
	"strings"

	"jiutouniao/internal/store"
)

// v4.4 方向一批次4：S5 待利用队列排序（xalgorix 深度优先学说的队列化落地）。

// severityTier 严重度分档：高（含"严重"/"危急"变体）=0 → 中=1 → 低=2 → 信息/未知=3。
func severityTier(sev string) int {
	switch sev {
	case "严重", "危急", "高":
		return 0
	case "中":
		return 1
	case "低":
		return 2
	default:
		return 3
	}
}

// confidenceTier 置信度分档：确证=0 → 疑似=1 → 待查/未知=2。
func confidenceTier(conf string) int {
	switch conf {
	case "确证":
		return 0
	case "疑似":
		return 1
	default:
		return 2
	}
}

// sortQueueFindings 待利用队列排序（稳定排序，原列表不被修改）：
//  1. 已标注 impact_rank（1-6）的项排在未标注之前，标注内按 rank 升序——RCE 系先打；
//  2. 同档内置信度高在前（确证 → 疑似 → 待查）；
//  3. 再按严重度高在前；
//  4. 其余保持登记时间序（稳定排序保证）。
func sortQueueFindings(fs []*store.Finding) []*store.Finding {
	out := make([]*store.Finding, len(fs))
	copy(out, fs)
	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i], out[j]
		ra, rb := a.ImpactRank > 0, b.ImpactRank > 0
		if ra != rb {
			return ra
		}
		if ra && rb && a.ImpactRank != b.ImpactRank {
			return a.ImpactRank < b.ImpactRank
		}
		ca, cb := confidenceTier(a.Confidence), confidenceTier(b.Confidence)
		if ca != cb {
			return ca < cb
		}
		sa, sb := severityTier(a.Severity), severityTier(b.Severity)
		return sa < sb
	})
	return out
}

// evidenceCriteriaMarkers v4.4：detail 中出现任一标记即视为「已对照 evidence-standard 判据」——
// 接受 LLM 的多样合规表述（判据/对照实验/孪生谓词/双主体矩阵/三重时延/重放/OOB 回连等），
// 降低确定性关键词检查的误伤面；全部缺席才触发降级。
var evidenceCriteriaMarkers = []string{
	"evidence-standard", "判据", "对照实验", "孪生", "双主体", "双会话",
	"三重", "重放", "时延中位", "反向谓词", "回连命中", "双码对比", "基线 vs 变异",
}

// evidenceCriteriaMissing 反思门判据抽查判式（纯函数便于单测）：
// 高危 + 确证 + detail 未引用任何判据标记 → 需降级。
// 合规路径：s4 头纪律 12 要求确证前 load_skill evidence-standard 并在 detail 引用判据项。
func evidenceCriteriaMissing(f *store.Finding) bool {
	if f == nil || f.Severity != "高" || f.Confidence != "确证" {
		return false
	}
	for _, m := range evidenceCriteriaMarkers {
		if strings.Contains(f.Detail, m) {
			return false
		}
	}
	return true
}
