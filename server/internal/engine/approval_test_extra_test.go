package engine

import (
	"context"
	"testing"
	"time"

	"jiutouniao/internal/events"
	"jiutouniao/internal/store"
)

// v3.4.0 审批屏障超时：manual 策略下无人决策，等满上限返回 "timeout" 且工单标 expired。
func TestApprovalWaitTimeout(t *testing.T) {
	dir := t.TempDir()
	st, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ap := NewApprover(st, events.NewBus(), "manual")
	ap.SetWaitTimeout(1) // 1 秒上限
	start := time.Now()
	decision, err := ap.Request(context.Background(), "P1", "s4", "测试高危动作", "L2")
	if err != nil {
		t.Fatalf("超时应返回 decision=timeout 而非 error: %v", err)
	}
	if decision != "timeout" {
		t.Fatalf("期望 timeout，实际 %s", decision)
	}
	if el := time.Since(start); el < 900*time.Millisecond || el > 3*time.Second {
		t.Fatalf("超时未按 1s 生效: %v", el)
	}
	aps, _ := st.ListApprovals("P1")
	if len(aps) != 1 || aps[0].Status != "expired" {
		t.Fatalf("工单应标 expired: %+v", aps)
	}
}
