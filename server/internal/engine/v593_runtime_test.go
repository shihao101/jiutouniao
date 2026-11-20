// v5.9.3 首页时间口径回归测试（全部使用泛化样本，不复用任何项目特定内容）：
// A beginStageRun 阶段进入语义（首启保护 + 残留收口时间清退）；
// B endStageRun 收口语义（done/paused/failed/killed 统一落 EndedAt——v5.9.3 前 failed/killed 缺失）。
// 背景：光宇游戏类实证——项目重跑后 status=running 而 finished_at 残留上次收口，首页总时长
// 冻结成 36m14s（真实 2h16m）；重跑阶段带旧 EndedAt 使对账重复计入旧区间。
package engine

import (
	"testing"
	"time"

	"jiutouniao/internal/store"
)

// A1：重跑进入——StartedAt 首启保护不被覆盖，残留 EndedAt 必须清退，LastActiveAt 刷新为本段起点
func TestV593BeginStageRunRerunClearsStaleEnded(t *testing.T) {
	first := time.Now().Add(-2 * time.Hour)
	started := first.Format(time.RFC3339)
	st := &store.StageState{
		Status:       "done",
		StartedAt:    started,
		EndedAt:      first.Add(10 * time.Minute).Format(time.RFC3339),
		LastActiveAt: started,
	}
	beginStageRun(st)
	if st.StartedAt != started {
		t.Fatalf("首启保护被破坏：StartedAt %s → %s", started, st.StartedAt)
	}
	if st.EndedAt != "" {
		t.Fatalf("重跑未清残留收口时间 %s（旧区间会被首页对账重复计入）", st.EndedAt)
	}
	la, err := time.Parse(time.RFC3339, st.LastActiveAt)
	if err != nil || time.Since(la) > time.Minute {
		t.Fatalf("LastActiveAt 未刷新为本段起点: %q err=%v", st.LastActiveAt, err)
	}
}

// A2：首次进入——StartedAt 落盘、无残留
func TestV593BeginStageRunFirstEntry(t *testing.T) {
	st := &store.StageState{}
	beginStageRun(st)
	if st.StartedAt == "" {
		t.Fatal("首次进入应落 StartedAt")
	}
	if _, err := time.Parse(time.RFC3339, st.StartedAt); err != nil {
		t.Fatalf("StartedAt 非 RFC3339: %v", err)
	}
	if st.EndedAt != "" {
		t.Fatalf("首次进入不应有 EndedAt: %q", st.EndedAt)
	}
}

// B：收口统一——四种离开 running 的语义都必须落合法 EndedAt（晚于 StartedAt）
func TestV593EndStageRunStampsEnded(t *testing.T) {
	for _, status := range []string{"done", "paused", "failed", "killed"} {
		st := &store.StageState{Status: status, StartedAt: time.Now().Add(-time.Hour).Format(time.RFC3339)}
		endStageRun(st)
		if st.EndedAt == "" {
			t.Fatalf("status=%s 收口未落 EndedAt（首页对账将缺角）", status)
		}
		end, err := time.Parse(time.RFC3339, st.EndedAt)
		if err != nil {
			t.Fatalf("status=%s EndedAt 非 RFC3339: %v", status, err)
		}
		start, _ := time.Parse(time.RFC3339, st.StartedAt)
		if end.Before(start) {
			t.Fatalf("status=%s 收口早于起点: %s < %s", status, st.EndedAt, st.StartedAt)
		}
		if st.LastActiveAt != st.EndedAt {
			t.Fatalf("status=%s LastActiveAt 未同步收口时间", status)
		}
	}
}
