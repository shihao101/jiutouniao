package tools

// v4.6 执行层专项测试：E2 后台任务终态标记 / K7 同步命令空闲护栏。

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// E2：任务结束后日志必须带 [JT-JOB-END] 终态标记，sidecar 必须刷新终态字段。
func TestV46AsyncEndMarker(t *testing.T) {
	dir := t.TempDir()
	e := newV46Exec(t, dir)
	job, err := e.StartAsync("P-V46", "echo hello-v46-marker", 0)
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(10 * time.Second)
	var side struct {
		State    string `json:"state"`
		ExitCode int    `json:"exit_code"`
	}
	for time.Now().Before(deadline) {
		if raw, rerr := os.ReadFile(filepath.Join(dir, "P-V46", ".async", "job-"+job.ID+".json")); rerr == nil {
			_ = json.Unmarshal(raw, &side)
			if side.State != "" {
				break
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	if side.State != "finished" {
		t.Fatalf("sidecar 终态应为 finished: %+v", side)
	}
	raw, rerr := os.ReadFile(filepath.Join(dir, "P-V46", ".async", "job-"+job.ID+".log"))
	if rerr != nil {
		t.Fatal(rerr)
	}
	if !strings.Contains(string(raw), "[JT-JOB-END] state=finished") {
		t.Fatalf("日志缺终态标记: %s", string(raw))
	}
	if !strings.Contains(string(raw), "hello-v46-marker") {
		t.Fatalf("任务输出应已在标记之前落盘: %s", string(raw))
	}
}

// K7：同步命令连续无输出超过空闲阈值 → 进程组被终止并返回明确错误（长静默应走 run_async）。
func TestV46IdleTimeout(t *testing.T) {
	dir := t.TempDir()
	e := newV46Exec(t, dir)
	e.SetIdleTimeout(1) // 1s 无输出即杀
	start := time.Now()
	_, err := e.Run(context.Background(), "P-V46I", "sleep 8", 60)
	elapsed := time.Since(start)
	if err == nil || !strings.Contains(err.Error(), "空闲超时") {
		t.Fatalf("空闲护栏应终止命令: %v", err)
	}
	if elapsed > 6*time.Second {
		t.Fatalf("空闲护栏应在 ~1s 触发，实测 %s", elapsed)
	}
	// 正常输出命令不受影响
	if _, err := e.Run(context.Background(), "P-V46I", "echo ok", 30); err != nil {
		t.Fatalf("有输出的命令不应被护栏误杀: %v", err)
	}
}

func newV46Exec(t *testing.T, dir string) *Executor {
	t.Helper()
	e, err := NewExecutor(dir, 30, 40960, struct {
		Forbidden, HighRisk, MedRisk, ReadOnly, Sensitive []string
	}{nil, nil, nil, nil, nil})
	if err != nil {
		t.Fatal(err)
	}
	return e
}
