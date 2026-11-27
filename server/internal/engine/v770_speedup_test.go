package engine

// v7.7.0 五项提速回归：P1 收敛收口 / P2 C27 代填 / P4 体积降序 / P5 阶段路由

import (
	"strings"
	"testing"
	"time"

	"jiutouniao/internal/llm"
	"jiutouniao/internal/store"
)

// P1：三重条件 + 冷却豁免 + 一次触发。
func TestV770P1Convergence(t *testing.T) {
	o, st := v48Orchestrator(t)
	o.heads = map[string]*Head{"s4": {ID: "s4", Order: 4}}
	p := v710Project(st, "P-V770-CONV")
	o.cfg.Engine.ConvergenceRounds = 3
	// ②候选无 open（无候选登记=通过）③idle 累计 3 轮
	for i := 0; i < 3; i++ {
		o.convMarkIdle(p, "s4")
	}
	// ①执行卡有 queued → 阻止
	_ = st.UpsertCard(&store.CardRecord{ProjectID: p.ID, Stage: "s4", Class: "C-13", State: "queued"})
	if _, fired := o.convMaybeFire(p, "s4", 40, 120); fired {
		t.Fatalf("有 queued 卡应阻止收敛")
	}
	// 卡片处置（dispositioned）→ 条件①通过
	cards, _ := st.ListCards(p.ID)
	cards[0].State = "dispositioned"
	_ = st.UpsertCard(&store.CardRecord{ProjectID: p.ID, Stage: "s4", Class: "C-13", Target: cards[0].Target, State: "dispositioned"})
	msg, fired := o.convMaybeFire(p, "s4", 40, 120)
	if !fired || !strings.Contains(msg, "收敛信号") {
		t.Fatalf("三重条件满足应触发: %s", msg)
	}
	if _, fired2 := o.convMaybeFire(p, "s4", 41, 120); fired2 {
		t.Fatal("每阶段至多触发 1 次")
	}
	// 预算 30% 前不触发
	o2, _ := v48Orchestrator(t)
	p2 := v710Project(st, "P-V770-CONV2")
	_ = p2
	for i := 0; i < 3; i++ {
		o2.convMarkIdle(p2, "s4")
	}
	if _, fired := o2.convMaybeFire(p2, "s4", 5, 120); fired {
		t.Fatal("预算 30pct 前不应触发")
	}
	// 冷却豁免：冷却期 convMarkIdle 重置 idle
	o3, _ := v48Orchestrator(t)
	p3 := v710Project(st, "P-V770-COOL")
	o3.convMarkIdle(p3, "s4")
	o3.batchStats = map[string]*batchBudgetState{"P-V770-COOL": {cooldownUntil: time.Now().Add(5 * time.Minute)}}
	o3.convMarkIdle(p3, "s4")
	if got := o3.convIdleRounds(p3, "s4"); got != 0 {
		t.Fatalf("冷却期应豁免 idle（got %d）", got)
	}
}

// P2：C27 代填——有台账依据的键落行、零依据键交回拦截。
func TestV770P2Autofill(t *testing.T) {
	o, st := v48Orchestrator(t)
	p := v710Project(st, "P-V770-C27")
	// 判定表（假设类 C-01..C-03）
	_, _ = o.exec.WriteFile(p.ID, "deliverables/s3-筛查矩阵判定表.md", matrixTableFixture(nil, nil))
	// C-01 有 coverage vulnerable 留痕；C-02 有 VT 承接；C-03 零依据
	_, _ = o.store.UpsertCoverage(&store.CoverageEntry{ProjectID: p.ID, Stage: "s4",
		Endpoint: "/login", VulnClass: "认证 C-01", Status: "vulnerable", Notes: "布尔差分"})
	_, _ = st.AddVT(&store.VerificationTask{ProjectID: p.ID, Stage: "s4",
		Title: "C-02 注入面 VT", Status: "ready"})
	filled := o.c27Autofill(p, "s4", []string{"C-01", "C-02", "C-03"})
	if filled {
		t.Fatalf("C-03 零依据应返回 false（不造已测）")
	}
	raw, err := o.exec.ReadFile(p.ID, "deliverables/s6-27类收口对账表.md")
	if err != nil || !strings.Contains(raw, "C-01") || !strings.Contains(raw, "C-02") || strings.Contains(raw, "C-03 |") {
		t.Fatalf("代填行应含 C-01/C-02 且不含零依据的 C-03: %v", err)
	}
	if !strings.Contains(raw, "引擎代填") {
		t.Fatalf("对账表应带权威口径标注")
	}
}

// P5：stage_models 路由次序（projModel 覆盖 > stage > 默认；未配置回退）。
func TestV770P5StageModels(t *testing.T) {
	o, st := v48Orchestrator(t)
	p := v710Project(st, "P-V770-SM")
	// 未配置 → 回退默认
	c1, m1 := o.clientForStage(p, "s1")
	c2, m2 := o.clientFor(p)
	if c1 != c2 || m1 != m2 {
		t.Fatalf("未配置应回退 clientFor")
	}
	// 配置 s1 → fast（注册表内需存在——用默认模型 id 注册第二份模拟）
	defID := o.defModel
	if o.models == nil {
		o.models = map[string]string{}
	}
	if o.clients == nil {
		o.clients = map[string]llm.Client{}
	}
	o.models[defID] = "default-model-name"
	o.clients[defID] = o.llm
	fastID := defID + "-fast"
	o.models[fastID] = "fast-model-name"
	o.clients[fastID] = o.clients[defID]
	o.cfg.LLM.StageModels = map[string]string{"s1": fastID}
	_, m3 := o.clientForStage(p, "s1")
	if m3 != "fast-model-name" {
		t.Fatalf("s1 应路由到 fast 模型: %s", m3)
	}
	if _, m := o.clientForStage(p, "s4"); m == "fast-model-name" {
		t.Fatalf("s4 未配置应回退默认")
	}
	// projModel（failover 接管）覆盖 stage 路由
	if o.projModel == nil {
		o.projModel = map[string]string{}
	}
	o.setModelOverride(p.ID, defID)
	if _, m := o.clientForStage(p, "s1"); m == "fast-model-name" {
		t.Fatalf("failover 接管应覆盖 stage 路由")
	}
	// s4 未配置 → 默认
	if _, m := o.clientForStage(p, "s4"); m == "fast-model-name" {
		t.Fatalf("s4 未配置应回退默认")
	}
}

// P4：体积降序压缩——大技能回执先于小回执被裁。
func TestV770P4SkillFirstCompaction(t *testing.T) {
	skill := strings.Repeat("技能全文内容。", 6000) // ~42k 级
	small := strings.Repeat("小回执。", 80)
	msgs := []llm.Message{{Role: "system", Content: "[[HEAD:s4]]"}, {Role: "user", Content: "包"}}
	msgs = append(msgs, llm.Message{Role: "tool", Content: "【技能 sqli-deep】" + skill})
	msgs = append(msgs, llm.Message{Role: "tool", Content: small})
	msgs = append(msgs, llm.Message{Role: "user", Content: "近端"}, llm.Message{Role: "tool", Content: "近端2"})
	// 补尾部消息：keepRecent=4 的保护区不能覆盖技能回执（i=2 必须在可裁区）
	for i := 0; i < 6; i++ {
		msgs = append(msgs, llm.Message{Role: "assistant", Content: "分析轮。" }, llm.Message{Role: "tool", Content: "回执。"})
	}
	out, _ := compactMsgsWithArchiveFloor(msgs, 3000, 1500, 4, nil)
	skillStub, smallStub := false, false
	for _, m := range out {
		if strings.Contains(m.Content, "【技能 sqli-deep】") && strings.Contains(m.Content, "已压缩") {
			skillStub = true
		}
		if strings.Contains(m.Content, "小回执。小回执。") && !strings.Contains(m.Content, "已压缩") {
			smallStub = true
		}
	}
	if !skillStub {
		t.Fatalf("大技能回执应被压缩（存根保留技能 id）")
	}
	if !smallStub {
		t.Fatalf("小回执应在大回执之后才被动（或预算未触及时保留）")
	}
}

// v7.7.0 十五轮核对：跨阶段不污染——s4 代填后 s5 仍可代填；同阶段重入仍被拦（c27Tried）。
func TestV770P2CrossStage(t *testing.T) {
	o, st := v48Orchestrator(t)
	p := v710Project(st, "P-V770-XS")
	_, _ = o.exec.WriteFile(p.ID, "deliverables/s3-筛查矩阵判定表.md", matrixTableFixture(nil, nil))
	_, _ = o.store.UpsertCoverage(&store.CoverageEntry{ProjectID: p.ID, Stage: "s4",
		Endpoint: "/a@s4t", VulnClass: "认证 C-01", Status: "vulnerable", Notes: "差分"})
	// s4 代填（1 键有依据）
	if !o.c27Autofill(p, "s4", []string{"C-01"}) {
		t.Fatalf("s4 有依据键应代填成功")
	}
	// 同阶段重入（模拟门重跑递归）→ false（防重入）
	if o.c27Autofill(p, "s4", []string{"C-01"}) {
		t.Fatalf("同阶段重入应被拦（防递归）")
	}
	// s5 新键（零依据）→ false，但尝试机会独立于 s4
	if o.c27Autofill(p, "s5", []string{"C-02"}) {
		t.Fatalf("s5 零依据键不落行")
	}
	// s5 新键有依据 → 代填成功（证明 s4 的尝试未污染 s5）
	_, _ = o.store.UpsertCoverage(&store.CoverageEntry{ProjectID: p.ID, Stage: "s5",
		Endpoint: "/b@s5t", VulnClass: "注入 C-02", Status: "vulnerable", Notes: "报错"})
	if !o.c27Autofill(p, "s5", []string{"C-02"}) {
		t.Fatalf("s5 有依据键应代填成功（跨阶段不污染）")
	}
}
