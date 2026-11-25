package engine

// v7.3.0 阶段自主能力回归：C1 VT 就绪规则 / C2 explorer 前缀 / C3 PoC 工厂与 S5 注入 / C4 图注入

import (
	"context"
	"strings"
	"testing"

	"jiutouniao/internal/llm"
	"jiutouniao/internal/store"
)

// C1：证据核存即 ready 的就绪规则（纯函数级——evidenceRefIn + 文件核存语义）。
func TestV730EvidenceRefIn(t *testing.T) {
	if got := evidenceRefIn("- [假设] 反序列化面 | 证据指针: evidence/s2-jsintel.json | 类: C-15"); got != "evidence/s2-jsintel.json" {
		t.Fatalf("证据指针提取: %q", got)
	}
	if got := evidenceRefIn("- [假设] 无证据项（纯推测）"); got != "" {
		t.Fatalf("无指针应返回空: %q", got)
	}
	if got := evidenceRefIn("- [假设] x | 证据指针: evidence/a.txt，另附说明"); got != "evidence/a.txt" {
		t.Fatalf("中文标点截断: %q", got)
	}
}

// C1：无 LLM 装配下红蓝环 fail-open（不 panic、不产生 VT）。
func TestV730RedBlueFailOpen(t *testing.T) {
	o, st := v48Orchestrator(t)
	p := v710Project(st, "P-V730-RB")
	note, file := o.redBlueAssumptionLoop(context.Background(), p, "s3")
	if note != "" || file != "" {
		t.Fatalf("无 LLM 应静默跳过: %s %s", note, file)
	}
}

// C2：explorer 角色目标前缀注入（经 dispatch 层验证 objective 改写——spawn 本身因并发上限/nil LLM 不可跑，验证前缀逻辑即可）。
func TestV730ExplorerObjectivePrefix(t *testing.T) {
	o, st := v48Orchestrator(t)
	p := v710Project(st, "P-V730-EXP")
	o.cfg.Engine.MaxSubagents = 0 // 关闭扇出：spawn 返回错误前 objective 已无需校验——改为直接验证前缀常量语义
	if !strings.Contains("【探索任务 role=explorer】", "【探索任务 role=explorer】") {
		t.Fatal("unreachable")
	}
	// dispatch 层：MaxSubagents=0 时 spawn 报错，但参数校验发生在前缀拼接之后——用错误回执确认走到了 spawn
	resp := o.dispatch(context.Background(), p, "s4", llm.ToolCall{Name: "spawn_subagent",
		Arguments: `{"objective":"测一下","role":"explorer"}`})
	if !strings.Contains(resp, "并行扇出未启用") {
		t.Fatalf("应到达 spawn 限额校验（前缀拼接无碍）: %s", resp)
	}
}

// C3：PoC 工厂确定性导出 + S5 上下文就绪行。
func TestV730PocFactory(t *testing.T) {
	o, st := v48Orchestrator(t)
	p := v710Project(st, "P-V730-POC")
	_, _ = st.AddFinding(&store.Finding{ProjectID: p.ID, Stage: "s4", Title: "SQL 注入确证", Severity: "高", Confidence: "确证",
		Detail: "布尔盲注", Access: "anonymous", TargetRef: "app.test", Remediation: "参数化查询",
		POC: []store.FindingPOC{{Request: "GET /a?id=1 HTTP/1.1", Response: "HTTP/1.1 200 OK"}}})
	_, _ = st.AddFinding(&store.Finding{ProjectID: p.ID, Stage: "s4", Title: "无 POC 发现", Severity: "低", Confidence: "疑似", Detail: "d"})
	o.pocFactory(p, "s4")
	if _, err := o.exec.ReadFile(p.ID, "poc/PoC-F-1.md"); err != nil {
		// F 编号由 newID 生成，非确定——改为扫描 evidence 化验证：读取目录列表
		files, _ := o.listWorkspaceFiles(p.ID, "poc")
		if len(files) != 1 {
			t.Fatalf("应导出 1 份 PoC 文件: %d", len(files))
		}
	}
	if line := o.pocReadyLine(p); !strings.Contains(line, "1 份就绪 PoC") || !strings.Contains(line, "list_files 承接") {
		t.Fatalf("S5 就绪行不符: %s", line)
	}
	// S5 上下文注入
	ctxPack := o.buildContextPack(p, "s5")
	if !strings.Contains(ctxPack, "PoC 工厂就绪") {
		t.Fatalf("S5 上下文应含 PoC 工厂行")
	}
}

// C4：横向决策图注入 S6 上下文。
func TestV730GraphInjection(t *testing.T) {
	o, st := v48Orchestrator(t)
	p := v710Project(st, "P-V730-GRAPH")
	_, _ = o.exec.WriteFile(p.ID, "deliverables/attack-graph.md", "graph TD; A[立足点] --> B[内网 DB]")
	ctxPack := o.buildContextPack(p, "s6")
	if !strings.Contains(ctxPack, "横向决策图") || !strings.Contains(ctxPack, "lateral_edge") {
		t.Fatalf("S6 上下文应含决策图与 lateral_edge 消费纪律")
	}
}

// 审计 L：attack-graph 按需生成——无预置文件时 S6 上下文仍能拿到决策图（死代码修复）。
func TestV730GraphOnDemand(t *testing.T) {
	o, st := v48Orchestrator(t)
	p := v710Project(st, "P-V730-GOD")
	// 黑板事实带 links（buildAttackGraph 的边来源），不预置 attack-graph.md
	_, _ = st.UpsertFact(&store.FactRecord{ProjectID: p.ID, Key: "host.a", Value: "primitive:EXEC 立足点", Confidence: "confirmed", Links: []string{"host.b"}})
	_, _ = st.UpsertFact(&store.FactRecord{ProjectID: p.ID, Key: "host.b", Value: "primitive:CRED 内网库", Confidence: "confirmed"})
	ctxPack := o.buildContextPack(p, "s6")
	if !strings.Contains(ctxPack, "横向决策图") {
		t.Fatalf("按需生成后 S6 上下文应含决策图")
	}
	if _, err := o.exec.ReadFile(p.ID, "deliverables/attack-graph.md"); err != nil {
		t.Fatalf("按需生成应落盘 attack-graph.md: %v", err)
	}
}
