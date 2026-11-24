package engine

// lessons_select.go v6.0.6（P0 修复：教训库选取机制重构）
// 实证事故：ListLessons(8) 先按时间截断再打分，指纹只对窗口内 8 条生效——
// LS-4DD9BCB0E6（HyLib export 类端点教训，406 条中排第 31）被挤出窗口，
// 任务 9427 漏测 exportIOS 中危。本文件将「选取」与「打分」合并为全库操作：
// 命中教训（指纹/行为类）优先进入上下文，最近教训保底补齐。

import (
	"fmt"
	"sort"
	"strings"

	"jiutouniao/internal/store"
)

// scoreLesson 教训指纹打分（原 buildContextPack 内联逻辑抽取 + token 去重）：
// BehaviorClass 精确命中 +2；Stack/Tags token 对指纹池子串命中各 +1（同 token 不重复计分）。
func scoreLesson(l *store.LessonRecord, fpJoined, behaviorClass string) int {
	score := 0
	if behaviorClass != "" && l.BehaviorClass == behaviorClass {
		score += 2
	}
	seen := map[string]bool{}
	splitAny := func(s, seps string) []string {
		return strings.FieldsFunc(s, func(r rune) bool { return strings.ContainsRune(seps, r) })
	}
	for _, tok := range splitAny(l.Stack, "/,，； ") {
		t := strings.ToLower(tok)
		if t != "" && !seen[t] && strings.Contains(fpJoined, t) {
			seen[t] = true
			score++
		}
	}
	for _, tok := range splitAny(l.Tags, ",， ") {
		t := strings.ToLower(tok)
		if len([]rune(t)) >= 2 && !seen[t] && strings.Contains(fpJoined, t) {
			seen[t] = true
			score++
		}
	}
	return score
}

// lessonScored 打分后的教训（选取/渲染共用）。
type lessonScored struct {
	lesson *store.LessonRecord
	score  int
}

// selectLessonsForContext v6.0.6 B：全库打分选取（消除先截断后打分的窗口漏召回）。
// 选取策略：①全部 score>0 的教训按分数 desc、时间 desc 排序，占前 (limit-2) 槽；
// ②其余槽位由最近未命中教训补齐（保底 ≥2 条最近上下文）；
// ③最终列表按分数 desc、时间 desc 排序渲染。total=全库条数，hits=全库命中条数。
func selectLessonsForContext(lessons []*store.LessonRecord, fpJoined, behaviorClass string, limit int) (selected []lessonScored, total, hits int) {
	if limit <= 0 {
		limit = 8
	}
	total = len(lessons)
	var hitList, rest []lessonScored
	for _, l := range lessons {
		s := scoreLesson(l, fpJoined, behaviorClass)
		if s > 0 {
			hits++
			hitList = append(hitList, lessonScored{l, s})
		} else {
			rest = append(rest, lessonScored{l, 0}) // ListLessons(0) 已按时间倒序，rest 保持近期优先
		}
	}
	sort.Slice(hitList, func(i, j int) bool {
		if hitList[i].score != hitList[j].score {
			return hitList[i].score > hitList[j].score
		}
		return hitList[i].lesson.CreatedAt.After(hitList[j].lesson.CreatedAt)
	})
	hitCap := limit - 2 // 保底 2 条最近教训
	if hitCap < 0 {
		hitCap = limit
	}
	// ① 命中槽：全部命中教训按分数/时间排序，占前 hitCap 槽
	for _, sl := range hitList {
		if len(selected) >= hitCap {
			break
		}
		selected = append(selected, sl)
	}
	// ② 方法论槽（v6.0.6 B 补充，codex Phase B methodology_slots）：命中未占满 hitCap 时，
	// 空出的槽位优先给「最久未注入」的方法论标签教训——方法论型教训占全库 96.3% 且无
	// Stack 可填，指纹打分对它们结构性失灵（实证：LS-4DD9BCB0E6 在指纹池 0 条时不可达）；
	// oldest-first 轮转保证覆盖面随时间展开，不固定偏爱某一条。
	if len(selected) < hitCap {
		picked := map[string]bool{}
		for _, sl := range selected {
			picked[sl.lesson.ID] = true
		}
		var cands []*store.LessonRecord
		for _, sl := range rest {
			if strings.Contains(sl.lesson.Tags, "方法论") && !picked[sl.lesson.ID] {
				cands = append(cands, sl.lesson)
			}
		}
		sort.Slice(cands, func(i, j int) bool {
			return cands[i].CreatedAt.Before(cands[j].CreatedAt)
		})
		if len(cands) > 0 {
			selected = append(selected, lessonScored{cands[0], 0})
		}
	}
	// ③ 最近槽：剩余容量由最近的零分教训补齐（保底 ≥2 条近期上下文）
	for _, sl := range rest {
		if len(selected) >= limit {
			break
		}
		picked := false
		for _, s2 := range selected {
			if s2.lesson.ID == sl.lesson.ID {
				picked = true
				break
			}
		}
		if !picked {
			selected = append(selected, sl)
		}
	}
	sort.SliceStable(selected, func(i, j int) bool {
		if selected[i].score != selected[j].score {
			return selected[i].score > selected[j].score
		}
		return selected[i].lesson.CreatedAt.After(selected[j].lesson.CreatedAt)
	})
	return selected, total, hits
}

// lessonEvidenceNote v6.0.6 A：证据强度标注——区分「未记录」与「单次实验」。
// 原实现 SampleSize 为空时全库统一标 provisional（406/406 触发），把 schema 缺参
// 误当低证据，等于整库降格、无法区分真实单次与字段缺失。
func lessonEvidenceNote(l *store.LessonRecord) string {
	ss := strings.TrimSpace(l.SampleSize)
	switch {
	case ss == "":
		return "【证据强度未记录】"
	case strings.Contains(ss, "单次") || ss == "1":
		return "【provisional：单次实验——跨目标使用前须 ≥3 样本复验（E5）】"
	default:
		return ""
	}
}

// searchLessonsScan v6.0.6 A：教训库关键词扫描（search_memory lessons 分支的纯函数抽取）。
// 匹配范围：Text/Tags/Stack/BehaviorClass/ValidScope（小写子串包含）。
// 返回格式与 search_memory 其他数据源一致（[教训/ID/Tags] Text）。
func searchLessonsScan(ls []*store.LessonRecord, q string) []string {
	var out []string
	for _, l := range ls {
		if strings.Contains(strings.ToLower(l.Text+l.Tags+l.Stack+l.BehaviorClass+l.ValidScope), q) {
			out = append(out, fmt.Sprintf("[教训/%s/%s] %s", l.ID, truncateText(l.Tags, 30), truncateText(l.Text, 150)))
		}
	}
	return out
}
