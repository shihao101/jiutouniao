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
// v6.5.0（S5-①）：升级为词边界命中——纯子串包含会互相误命中（审计 F-14 形态：
// example.com 被 notexample.com 误命中；s1_gates.go canonicalTargetKey 注释同源教训）。
// ①候选键 = 原值 + 精确键（剥 scheme/路径/尾点，兼容「登记 https://、语料 http://」的
// scheme 误拦）；②词边界判定不引入新拦截：'.' 不属拒绝集（sub.example.com 对目标
// example.com 的既有宽松命中保持）；③CIDR/描述性目标（无 ./: 的非主机形态）词边界
// 不命中时回退纯子串（保持旧行为），仍零命中由调用方输出提示级留痕。
func targetCoverageRecon(targets []string, covCorpus, delivCorpus string) (missing []string, matched int) {
	nc, nd := normCovText(covCorpus), normCovText(delivCorpus)
	missing = make([]string, 0)
	for _, t := range targets {
		nt := normCovText(t)
		if nt == "" {
			continue
		}
		cands := []string{nt}
		if ck := normCovText(canonicalTargetKey(t)); ck != "" && ck != nt {
			cands = append(cands, ck)
		}
		hit := false
		for _, c := range cands {
			if wordBoundaryContains(nc, c) || wordBoundaryContains(nd, c) {
				hit = true
				break
			}
		}
		if !hit && !targetHostLike(t) {
			// CIDR/描述性目标回退层：词边界对「目标串作为更大词元内部片段」的拒绝
			// 对主机形态是消误报，对描述形态可能是误伤——回退纯子串保持 v6.4.1 行为。
			hit = strings.Contains(nc, nt) || strings.Contains(nd, nt)
		}
		if hit {
			matched++
		} else {
			missing = append(missing, t)
		}
	}
	return missing, matched
}

// targetHostLike v6.5.0（S5-①）：目标是否为域名/IP/URL 形态（精确键含 . 或 :）——
// 否则视为 CIDR/描述性目标（如「集团OA系统」），启用纯子串回退层。
func targetHostLike(t string) bool {
	return strings.ContainsAny(canonicalTargetKey(t), ".:")
}

// wordBoundaryContains v6.5.0（S5-①）：词边界包含判定——命中位置的紧邻字符不是
// 字母/数字/连字符时才算命中（目标串是更大词元内部片段的形态一律拒绝）。
func wordBoundaryContains(corpus, token string) bool {
	if token == "" || !strings.Contains(corpus, token) {
		return false
	}
	for i := 0; i < len(corpus); {
		idx := strings.Index(corpus[i:], token)
		if idx < 0 {
			return false
		}
		idx += i
		before := byte(0)
		if idx > 0 {
			before = corpus[idx-1]
		}
		after := byte(0)
		if idx+len(token) < len(corpus) {
			after = corpus[idx+len(token)]
		}
		if !boundaryRejectByte(before) && !boundaryRejectByte(after) {
			return true
		}
		i = idx + 1
	}
	return false
}

// boundaryRejectByte v6.5.0（S5-①）：命中位置紧邻字母/数字 = 目标串是更大词元的内部片段
// （notexample.com 内的 example.com、110.0.0.0 内的 10.0.0.0）——不计命中。
// '-'/'.'/'/'/':' 等不属拒绝集：normCovText 去空白后 markdown 列表符「- 」紧邻目标串
// （"- b.example.com" → "-b.example.com"）是覆盖 notes/交付物的常态形态，连字符邻接
// 若拒绝会把既有命中全部打成误拦；scheme/路径/子域邻接同理保持。
func boundaryRejectByte(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')
}

// stageBudget 阶段迭代轮次预算：
//   - s8/s4 保持 ×2（v2.3.2 既有：报告/文档阶段写入量大且需承接全部交付物；
//     v4.9 F3：s4 漏洞发现同样 ×2——最重执行阶段（串行深挖+子代理扇出+收口对账），
//     60 轮实证结构性不足，兰州项目 s4 曾六连败撞上限）；
//   - v6.6.0 SP-①：specB1 同为重执行阶段（静态链解包/反编译 + 动态链设备通道，
//     与 s4 同级成本）×2——对齐 v4.9 F3 论证；specA/specB2 保持 ×1；
//   - S1/S2/S3/S4/S5/S6/S8/specA/specB1/specB2 多目标自适应（方向二B；v6.1.0 方案⑤将 s1 纳入；
//     v6.3.0 S3-② 将 s3 纳入——27 类×目标判定与执行卡撰写随目标数线性增长，不放大=多目标判定表
//     被迫"高信号目标代表全部"；v6.6.0 SP-① 将三个专项纳入；v6.7.0 S6-⑩ 选项 A 将 s6 纳入；
//     v6.9.0 S8-④ 将 s8 纳入——多目标报告按目标组织（s8.md 分组合并条款逐组 read_file+核对合并）
//     工作量随目标数线性增长，固定 base 会把报告合并挤压成静默省略→quality-pending 代收口连锁；
//     s7 不入选：收尾按条目不按目标，工作量非线性）：base*mult + (N-1)*perTarget，封顶 3×base×mult
//     ——上下文包的「多目标推进纪律」块对这十个阶段承诺放大（与 stageBudget 同名单，不向模型撒谎）；
//   - 其余阶段（s7）与 perTarget<=0（禁用自适应）时维持原值。
func stageBudget(base int, stageID string, targets, perTarget int) int {
	mult := 1
	// v7.6.0（B2 用户决策②）：s5 纳入倍增名单——实证 某实战项目 S5 按 base 计（60 轮）
	// 未收口暂停，S5 利用编排（子代理扇出+人机协同+受控验证）轮耗与 s4 同量级，固定 base
	// 标定不足；放宽预算后 s5 与 s4/s8/specB1 同享 ×2。
	if stageID == "s8" || stageID == "s4" || stageID == "s5" || stageID == "specB1" {
		mult = 2
	}
	budget := base * mult
	if targets > 1 && perTarget > 0 {
		switch stageID {
		case "s1", "s2", "s3", "s4", "s5", "s6", "s8", "specA", "specB1", "specB2":
			budget = base*mult + (targets-1)*perTarget
			if max := base * 3 * mult; budget > max {
				budget = max
			}
		}
	}
	return budget
}

// shouldInjectSprint v6.5.0（S5-⑥）：预算冲刺预警触发判式（纯函数便于单测）——进入
// 「剩 ≤1/3」阈值区间后的首轮触发一次（notified 去重）。旧实现 remain == budget/3
// 精确等于在 budget 非 3 的倍数时永不命中（budget=80 时 remain 序列 79..27,25..0 无 26），
// 多目标放大后 s4/s5 的 V3 就绪投递引导整段丢失。budget<=0 不触发（防御）。
func shouldInjectSprint(budget, remain int, notified bool) bool {
	if budget <= 0 || notified {
		return false
	}
	return remain <= budget/3
}
