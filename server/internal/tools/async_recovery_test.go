package tools

import (
	"context"
	"strings"
	"testing"
	"time"
)

// v3.4.0 后台任务持久化恢复：引擎重启（注册表丢失）后 poll_async 从落盘元数据恢复状态，
// 不再「未知 job id」——断点续跑的后台任务支撑回归。
func TestAsyncRecoveryAfterRegistryLoss(t *testing.T) {
	workspace := t.TempDir()
	e1, err := NewExecutor(workspace, 30, 4096, struct {
		Forbidden, HighRisk, MedRisk, ReadOnly, Sensitive []string
	}{})
	if err != nil {
		t.Fatal(err)
	}
	job, err := e1.StartAsync("p1", "echo recovery-mark", 30)
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		state, _, _, _, _ := e1.PollAsync("p1", job.ID)
		if state != "running" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("任务未结束")
		}
		time.Sleep(30 * time.Millisecond)
	}
	// 模拟引擎重启：全新 Executor（注册表为空），同一工作区
	e2, err := NewExecutor(workspace, 30, 4096, struct {
		Forbidden, HighRisk, MedRisk, ReadOnly, Sensitive []string
	}{})
	if err != nil {
		t.Fatal(err)
	}
	state, out, _, _, ok := e2.PollAsync("p1", job.ID)
	if !ok {
		t.Fatal("重启后应从 sidecar 恢复而非返回未知 job")
	}
	if state != "finished" {
		t.Fatalf("恢复状态应为 finished，实际 %s", state)
	}
	if !strings.Contains(out, "recovery-mark") {
		t.Fatalf("恢复应带日志尾部: %q", out)
	}
	// 未知 job 仍然如实报未知
	if _, _, _, _, ok := e2.PollAsync("p1", "nope"); ok {
		t.Fatal("无 sidecar 的 job 仍应返回 ok=false")
	}
}

// v3.4.0 stderr 分离：错误流独立可判（原 CombinedOutput 混流、Stderr 死字段）。
func TestRunStderrSeparate(t *testing.T) {
	e, err := NewExecutor(t.TempDir(), 30, 4096, struct {
		Forbidden, HighRisk, MedRisk, ReadOnly, Sensitive []string
	}{})
	if err != nil {
		t.Fatal(err)
	}
	res, err := e.Run(context.Background(), "p1", "echo out-mark; echo err-mark 1>&2", 10)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(res.Stdout, "out-mark") || strings.Contains(res.Stdout, "err-mark") {
		t.Fatalf("stdout 不应混入 stderr: %q", res.Stdout)
	}
	if !strings.Contains(res.Stderr, "err-mark") {
		t.Fatalf("stderr 应独立捕获: %q", res.Stderr)
	}
}
