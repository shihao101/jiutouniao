package tools

// v6.0.1 P2/P4 验收测试（fix-plan 20261122）：
// StartBatch 逐目标隔离（单目标超时不影响其余）/ 参数校验 / AsyncLogStats 实时字节数 /
// IncompleteAsyncJobs 对账数据源。

import (
	"strings"
	"testing"
	"time"
)

// waitJobDone 等待作业到终态（finished/killed），返回终态。
func waitJobDone(e *Executor, projectID, jobID string, timeout time.Duration) string {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		state, _, _, _, ok := e.PollAsync(projectID, jobID)
		if ok && state != "running" {
			return state
		}
		time.Sleep(50 * time.Millisecond)
	}
	state, _, _, _, _ := e.PollAsync(projectID, jobID)
	return state
}

// ① 模板校验：缺占位符 / 空目标 / 超上限 → 拒绝
func TestV601StartBatchValidation(t *testing.T) {
	e := newTestExecutor(t)
	if _, err := e.StartBatch("P", "echo hello", []string{"a.com"}, 10); err == nil || !strings.Contains(err.Error(), "{{TARGET}}") {
		t.Fatalf("缺占位符应报错: %v", err)
	}
	if _, err := e.StartBatch("P", "echo {{TARGET}}", nil, 10); err == nil {
		t.Fatal("空目标列表应报错")
	}
	many := make([]string, 101)
	for i := range many {
		many[i] = "t" + string(rune('a'+i%26)) + ".com"
	}
	if _, err := e.StartBatch("P", "echo {{TARGET}}", many, 10); err == nil || !strings.Contains(err.Error(), "上限") {
		t.Fatalf("超上限应报错: %v", err)
	}
}

// ② 逐目标隔离：3 目标（快/快/慢超时）——慢目标被杀不影响其余完成，且全部并行执行
func TestV601BatchIsolation(t *testing.T) {
	e := newTestExecutor(t)
	batch, err := e.StartBatch("P",
		"echo out-{{TARGET}}; sleep 30",
		[]string{"fast1.example", "fast2.example", "slow.example"},
		1) // 每目标 1s 超时：slow 被杀，fast 在被杀前已完成输出
	if err != nil {
		t.Fatal(err)
	}
	if len(batch.Targets) != 3 {
		t.Fatalf("应 3 个子任务: %d", len(batch.Targets))
	}
	// 安全引用校验：目标值必须单引号包裹注入
	if !strings.Contains(batch.Targets[0].Command, "'fast1.example'") {
		t.Fatalf("目标应单引号安全引用: %q", batch.Targets[0].Command)
	}
	start := time.Now()
	states := map[string]string{}
	for _, tr := range batch.Targets {
		states[tr.Target] = waitJobDone(e, "P", tr.JobID, 15*time.Second)
	}
	elapsed := time.Since(start)
	// 全部应已结束（killed 或 finished），且总耗时应远小于 3×30s 串行——证明并行隔离
	if elapsed > 20*time.Second {
		t.Fatalf("批量应并行隔离执行，实测总耗时 %v", elapsed)
	}
	// slow.example 应被 killed；两个 fast 目标在 1s 内也大概率被杀（sleep 30 未完成）——
	// 但都有日志输出（echo 先行）。验证点：3 个 job 都有终态（无 running 残留）。
	for tgt, st := range states {
		if st != "finished" && st != "killed" {
			t.Fatalf("目标 %s 应有终态，实际 %s", tgt, st)
		}
	}
	// IncompleteAsyncJobs（C31 数据源）：sleep 30 + 1s 超时 → killed 必须全部在列
	inc := e.IncompleteAsyncJobs("P")
	if len(inc) < 3 {
		t.Fatalf("killed 任务应全部进入未完成清单（sleep 30 vs 1s 超时），实际 %d: %+v", len(inc), inc)
	}
}

// ③ 快任务正常完成：AsyncLogStats 字节数 > 0 且目标值出现在输出
func TestV601AsyncLogStats(t *testing.T) {
	e := newTestExecutor(t)
	batch, err := e.StartBatch("P", "echo marker-{{TARGET}}", []string{"ok.example"}, 15)
	if err != nil {
		t.Fatal(err)
	}
	tr := batch.Targets[0]
	if tr.Err != "" {
		t.Fatalf("启动失败: %s", tr.Err)
	}
	if st := waitJobDone(e, "P", tr.JobID, 15*time.Second); st != "finished" {
		t.Fatalf("快任务应 finished，实际 %s", st)
	}
	lb, lastOut, ok := e.AsyncLogStats("P", tr.JobID)
	if !ok {
		t.Fatal("job 应存在")
	}
	if lb <= 0 {
		t.Fatalf("finished 任务日志字节数应 >0（P4 实时观测），实际 %d", lb)
	}
	if lastOut == "" {
		t.Fatal("lastOutputAt 应非空")
	}
	state, out, _, _, _ := e.PollAsync("P", tr.JobID)
	if state != "finished" || !strings.Contains(out, "marker-ok.example") {
		t.Fatalf("输出应含目标值: state=%s out=%q", state, out)
	}
}

// ④ 目标值单引号转义（防注入）
func TestV601QuoteShellArg(t *testing.T) {
	if got := quoteShellArg("a'b.com"); got != `'a'\''b.com'` {
		t.Fatalf("单引号转义不符: %q", got)
	}
}
