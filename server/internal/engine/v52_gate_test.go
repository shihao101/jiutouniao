// v5.2.0 P1-1 治理门单测：注册 deny 硬门 + strict_scope 范围确定性校验
package engine

import (
	"os"
	"strings"
	"testing"

	"jiutouniao/internal/store"
)

func TestV52RegistrationGate(t *testing.T) {
	o, _ := v48Orchestrator(t)
	// 未配置 YAML Profile → 平台默认 deny
	if blocked, msg := o.registrationGate("curl -s -X POST https://t/register -d 'user=a&pass=b'"); !blocked {
		t.Fatalf("默认 deny 下注册 POST 应被拦截")
	} else if !strings.Contains(msg, "auto_register=deny") {
		t.Fatalf("拦截文案应说明 ROE 口径: %s", msg)
	}
	// GET 页面评估不拦
	if blocked, _ := o.registrationGate("curl -s https://t/register"); blocked {
		t.Fatalf("注册页 GET 评估不应拦截")
	}
	// 非注册端点的 POST 不拦
	if blocked, _ := o.registrationGate("curl -s -X POST https://t/account/uslogin -d 'a=1'"); blocked {
		t.Fatalf("非注册端点 POST 不应拦截")
	}
	// 显式 allow → 放行
	rp, err := LoadROEProfile(writeTempROE(t, "identity:\n  auto_register: allow\n"))
	if err != nil {
		t.Fatalf("ROE 加载失败: %v", err)
	}
	o.roe = rp
	if blocked, _ := o.registrationGate("curl -X POST https://t/register -d a=1"); blocked {
		t.Fatalf("ROE allow 下注册 POST 不应拦截")
	}
}

func TestV52ScopeGate(t *testing.T) {
	o, st := v48Orchestrator(t)
	p := &store.Project{ID: "P-V52", Target: "https://iop.example.edu.cn/", StrictScope: true}
	_ = st.SaveProject(p)
	// 主目标子域 → 放行
	if blocked, _ := o.scopeGate(p, "curl -s https://api.iop.example.edu.cn/x"); blocked {
		t.Fatalf("主目标子域不应拦截")
	}
	// 白名单 OSINT → 放行
	if blocked, _ := o.scopeGate(p, "curl -s https://crt.sh/?q=x"); blocked {
		t.Fatalf("白名单 OSINT 不应拦截")
	}
	// 范围外目标 → 拦截
	blocked, msg := o.scopeGate(p, "curl -s https://other-univ.edu.cn/admin")
	if !blocked {
		t.Fatalf("范围外目标应拦截")
	}
	if !strings.Contains(msg, "record_asset") {
		t.Fatalf("拦截文案应指引 record_asset: %s", msg)
	}
	// 资产登记后放行
	_, _ = st.AddAsset(&store.Asset{ProjectID: p.ID, Type: "域名", Value: "other-univ.edu.cn"})
	if blocked, _ := o.scopeGate(p, "curl -s https://other-univ.edu.cn/admin"); blocked {
		t.Fatalf("资产登记后应放行")
	}
	// 非 strict 项目不校验
	p2 := &store.Project{ID: "P-V52B", Target: "https://iop.example.edu.cn/", StrictScope: false}
	_ = st.SaveProject(p2)
	if blocked, _ := o.scopeGate(p2, "curl -s https://anywhere.example/"); blocked {
		t.Fatalf("非 strict_scope 项目不应校验")
	}
}

func writeTempROE(t *testing.T, content string) string {
	t.Helper()
	p := t.TempDir() + "/roe.yaml"
	if err := os.WriteFile(p, []byte("profile: v52test\nwrite_policy: existence-proof\nscope:\n  assets: [\"127.0.0.1\"]\nwaf_policy:\n  offline_challenge: allow\nidentity:\n"+content+"\noutbound:\n  oob_callback: allow\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}
