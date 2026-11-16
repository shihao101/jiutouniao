// v5.3.1 P0-2 通道级集成测试：治理门（执行档+注册写+范围）在全部命令执行通道接线。
// 此前（v5.2.0）双门只在 shell_open 生效，run_command/run_async/shell_write/hexstrike 全部绕过——
// 本文件以「通道 × 门类型」矩阵锁定：每个通道的违禁动作必须在风险分级与审批之前被确定性拦截
// （不产生审批工单），且阻断留证进证据链。
package engine

import (
	"context"
	"strings"
	"testing"

	"jiutouniao/internal/store"
)

// gateBlocked 断言 dispatch 返回了治理门阻断文案，且未产生审批工单（门先于审批）。
func gateBlocked(t *testing.T, o *Orchestrator, st *store.Store, p *store.Project, name, args string, wantKeyword string) {
	t.Helper()
	got := o.dispatch(context.Background(), p, "s4", mkCall(name, args))
	if !strings.Contains(got, wantKeyword) {
		t.Fatalf("通道 %s 未按预期阻断（期望含 %q）：%s", name, wantKeyword, got)
	}
	aps, _ := st.ListApprovals(p.ID)
	if len(aps) != 0 {
		t.Fatalf("通道 %s 阻断前不应产生审批工单（门必须先于审批）：%+v", name, aps)
	}
}

func TestV531ChannelGatesRunCommand(t *testing.T) {
	o, st := v48Orchestrator(t)
	p := &store.Project{ID: "P-V531-C1", Name: "通道测试", Target: "https://target.example"}
	_ = st.SaveProject(p)
	// 执行档门：HTTP DELETE（生产档违禁）
	gateBlocked(t, o, st, p, "run_command",
		`{"command":"curl -s -X DELETE http://target.example/api/items/5","reason":"r"}`, "production_safe")
	// 范围门：strict_scope 项目访问范围外目标
	ps := &store.Project{ID: "P-V531-C1S", Name: "范围测试", Target: "https://target.example", StrictScope: true}
	_ = st.SaveProject(ps)
	gateBlocked(t, o, st, ps, "run_command",
		`{"command":"curl -s https://other-univ.edu.cn/admin","reason":"r"}`, "范围外目标")
	// 注册门：auto_register=deny（默认）下注册端点 POST
	gateBlocked(t, o, st, ps, "run_command",
		`{"command":"curl -s -X POST https://target.example/register -d 'user=a&pass=b'","reason":"r"}`, "auto_register=deny")
	// 阻断留证进证据链
	evs, _ := st.ListEvidence(p.ID)
	if len(evs) == 0 {
		t.Fatalf("阻断应统一留证")
	}
}

func TestV531ChannelGatesRunAsync(t *testing.T) {
	o, st := v48Orchestrator(t)
	p := &store.Project{ID: "P-V531-C2", Name: "异步通道", Target: "https://target.example"}
	_ = st.SaveProject(p)
	// 此前 run_async 完全绕过双门——后台 mysqldump 批量导出必须被执行档拦截
	gateBlocked(t, o, st, p, "run_async",
		`{"command":"mysqldump -h target.example -u root appdb","reason":"r"}`, "production_safe")
}

func TestV531ChannelGatesShellWrite(t *testing.T) {
	o, st := v48Orchestrator(t)
	p := &store.Project{ID: "P-V531-C3", Name: "会话注入", Target: "https://target.example"}
	_ = st.SaveProject(p)
	// 此前 stdin 注入只过风险分级不过双门——注册写提交须被注册门拦截
	gateBlocked(t, o, st, p, "shell_write",
		`{"session":"nonexistent","input":"curl -X POST https://target.example/register -d 'user=a&pass=b'","enter":"true"}`, "auto_register=deny")
	// 交互会话内注入 SQL 写（执行档门）
	gateBlocked(t, o, st, p, "shell_write",
		`{"session":"nonexistent","input":"UPDATE products SET price=0 WHERE id<100","enter":"true"}`, "production_safe")
}

func TestV531ChannelGatesShellOpen(t *testing.T) {
	o, st := v48Orchestrator(t)
	p := &store.Project{ID: "P-V531-C4", Name: "会话打开", Target: "https://target.example"}
	_ = st.SaveProject(p)
	// shell_open 自 v5.2.0 已有双门，v5.3.1 并入执行档门
	gateBlocked(t, o, st, p, "shell_open",
		`{"command":"crontab -e","reason":"r"}`, "production_safe")
}

func TestV531ChannelGatesHexstrike(t *testing.T) {
	o, st := v48Orchestrator(t)
	p := &store.Project{ID: "P-V531-C5", Name: "工具桥", Target: "https://target.example"}
	_ = st.SaveProject(p)
	o.hex = NewHexStrikeBridge("http://127.0.0.1:1") // 门必须先于网关调用（端口不通即可验证未被触达）
	gateBlocked(t, o, st, p, "hexstrike_command",
		`{"command":"curl -s -X DELETE http://target.example/api/x","reason":"r"}`, "production_safe")
}

func TestV531ChannelGatesAllowNormalFlow(t *testing.T) {
	o, st := v48Orchestrator(t)
	ap, st2 := testApprover(t)
	_ = st2
	o.approver = ap // v48Orchestrator 不预置审批器；正常流必须经审批链
	// l1 策略：L0/L1 自动批准——治理门放行的正常流量不被误伤
	p := &store.Project{ID: "P-V531-C6", Name: "正常流", Target: "https://target.example", AutoApprove: "l1"}
	_ = st.SaveProject(p)
	got := o.dispatch(context.Background(), p, "s4", mkCall("run_command", `{"command":"echo gate-ok","reason":"r"}`))
	if strings.Contains(got, "拦截") || strings.Contains(got, "拒绝") {
		t.Fatalf("治理门不应误伤正常命令: %s", got)
	}
	if !strings.Contains(got, "gate-ok") {
		t.Fatalf("正常命令应真实执行: %s", got)
	}
}
