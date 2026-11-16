package tools

import (
	"context"
	"strings"
	"testing"
	"time"
)

// v2.6 后台任务：启动/收结果/超时终止/熔断清理。
func TestAsyncJobsLifecycle(t *testing.T) {
	e, err := NewExecutor(t.TempDir(), 30, 4096, struct {
		Forbidden, HighRisk, MedRisk, ReadOnly, Sensitive []string
	}{})
	if err != nil {
		t.Fatal(err)
	}
	// ① 正常完成
	job, err := e.StartAsync("p1", "echo hello-async", 30)
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		state, out, code, _, ok := e.PollAsync("p1", job.ID)
		if !ok {
			t.Fatal("job 不存在")
		}
		if state == "finished" {
			if code != 0 || !strings.Contains(out, "hello-async") {
				t.Fatalf("退出码=%d 输出=%q", code, out)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("任务未在期限内完成")
		}
		time.Sleep(50 * time.Millisecond)
	}
	// ② 超时终止（进程组）
	job2, _ := e.StartAsync("p1", "sleep 30", 1)
	deadline = time.Now().Add(5 * time.Second)
	for {
		state, _, _, _, _ := e.PollAsync("p1", job2.ID)
		if state == "killed" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("超时任务未被终止")
		}
		time.Sleep(50 * time.Millisecond)
	}
	// ③ 未知 job
	if _, _, _, _, ok := e.PollAsync("p1", "nope"); ok {
		t.Fatal("未知 job 应返回 ok=false")
	}
}

// v2.6 同步命令硬上限：超大超时请求被钳制（以能跑完为准，不真等 30 分钟——
// 验证方式：hardCap 设置为 2s，跑 sleep 10 应在数秒内返回超时错误）。
func TestSyncHardCapClamp(t *testing.T) {
	e, err := NewExecutor(t.TempDir(), 30, 4096, struct {
		Forbidden, HighRisk, MedRisk, ReadOnly, Sensitive []string
	}{})
	if err != nil {
		t.Fatal(err)
	}
	e.SetCaps(2, 0, 0)
	start := time.Now()
	_, err = e.Run(context.Background(), "p1", "sleep 10", 3600)
	if err == nil {
		t.Fatal("超出硬上限的长命令应返回超时错误")
	}
	if el := time.Since(start); el > 8*time.Second {
		t.Fatalf("硬上限未生效，实际耗时 %v", el)
	}
}
