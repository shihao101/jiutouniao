package engine

// v7.7.0 十三轮核对回归：在途任务守卫（防过早收敛）

import (
	"testing"
)

func TestV770PendingAsyncGuard(t *testing.T) {
	o, st := v48Orchestrator(t)
	p := v710Project(st, "P-V770-ASYNC")
	// 无在途任务 → 空列表
	if jobs := o.pendingAsyncJobs(p.ID); len(jobs) != 0 {
		t.Fatalf("无 .async 目录应返回空: %v", jobs)
	}
	// 写一个 running 侧车 + 一个 finished 侧车
	dir := p.ID
	_, _ = o.exec.WriteFile(dir, ".async/job-a.json", `{"id":"job-a","state":"running"}`)
	_, _ = o.exec.WriteFile(dir, ".async/job-b.json", `{"id":"job-b","state":"finished"}`)
	jobs := o.pendingAsyncJobs(dir)
	if len(jobs) != 1 || jobs[0].ID != "job-a" {
		t.Fatalf("应只列在途任务: %+v", jobs)
	}
	// 有在途任务 → convMaybeFire 不触发（即使其余条件满足）
	o.cfg.Engine.ConvergenceRounds = 3
	o.heads = map[string]*Head{"s4": {ID: "s4", Order: 4}}
	for i := 0; i < 3; i++ {
		o.convMarkIdle(p, "s4")
	}
	if msg, fired := o.convMaybeFire(p, "s4", 40, 120); fired {
		t.Fatalf("在途任务应阻止收敛: %s", msg)
	}
	// 在途任务结束 → 触发
	_, _ = o.exec.WriteFile(dir, ".async/job-a.json", `{"id":"job-a","state":"finished"}`)
	if jobs := o.pendingAsyncJobs(dir); len(jobs) != 0 {
		t.Fatalf("任务结束后应无在途: %v", jobs)
	}
	if _, fired := o.convMaybeFire(p, "s4", 40, 120); !fired {
		t.Fatalf("在途归位后应触发收敛")
	}
}

// v7.7.0 十四轮核对：收敛信号适用域锁定 s4/s5（s2 侦察产出语义不同——防误砍侦察广度）
func TestV770ConvergenceScope(t *testing.T) {
	o, st := v48Orchestrator(t)
	o.heads = map[string]*Head{"s2": {ID: "s2", Order: 2}, "s4": {ID: "s4", Order: 4}}
	p := v710Project(st, "P-V770-SCOPE")
	for i := 0; i < 3; i++ {
		o.convMarkIdle(p, "s2")
	}
	if _, fired := o.convMaybeFire(p, "s2", 40, 120); fired {
		t.Fatalf("s2 不应触发收敛信号（适用域=s4/s5）")
	}
	// s4 同条件可触发
	o2, st2 := v48Orchestrator(t)
	p2 := v710Project(st2, "P-V770-SCOPE2")
	for i := 0; i < 3; i++ {
		o2.convMarkIdle(p2, "s4")
	}
	if _, fired := o2.convMaybeFire(p2, "s4", 40, 120); !fired {
		t.Fatalf("s4 同条件应触发")
	}
}
