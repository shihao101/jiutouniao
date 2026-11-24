// v7.0.0 OOB 通道管理器单测：盲态判别/深度阶梯/技能门/回退链/最小 DNS 应答。
package engine

import (
	"strings"
	"time"
	"testing"

	"jiutouniao/internal/config"
	"jiutouniao/internal/store"
)

func TestIsBlindVulnClass(t *testing.T) {
	yes := []string{"SSRF", "ssrf（横向入口）", "XXE（盲态）", "盲注", "SQLi-blind", "Java反序列化", "jndi/log4j", "命令注入(cmdi)"}
	no := []string{"XSS", "越权/IDOR", "信息泄露", "配置缺陷", "CRLF", "开放重定向"}
	for _, v := range yes {
		if !IsBlindVulnClass(v) {
			t.Errorf("IsBlindVulnClass(%q)=false，应为 true", v)
		}
	}
	for _, v := range no {
		if IsBlindVulnClass(v) {
			t.Errorf("IsBlindVulnClass(%q)=true，应为 false", v)
		}
	}
}

func TestNormalizeOOBDepth(t *testing.T) {
	eq := map[string]string{"D2": "D2", "d2": "D2", "2": "D2", "D4": "D4", "": "", "D9": "", "abc": "", "D0": "D0"}
	for in, want := range eq {
		if got := normalizeOOBDepth(in); got != want {
			t.Errorf("normalizeOOBDepth(%q)=%q，应为 %q", in, got, want)
		}
	}
	if depthNum("D2") != 2 || depthNum("") != -1 {
		t.Errorf("depthNum 解析错误")
	}
}

func TestOOBBlindSkillID(t *testing.T) {
	if !oobBlindSkillID("ssrf-deep") || !oobBlindSkillID("xxe-full") || !oobBlindSkillID("cmdi-deep") || !oobBlindSkillID("blind-sqli") {
		t.Errorf("盲态技能判别漏判")
	}
	if oobBlindSkillID("oob-interactsh") || oobBlindSkillID("recon-playbook") || oobBlindSkillID("authz-diff") {
		t.Errorf("非盲态技能误判（oob-interactsh 手册必须放行）")
	}
}

// TestOOBBuildChain 回退链裁决：off=关、ROE deny=外部全禁、配置缺失逐级降级。
// 纯裁决路径测试（不真实绑定端口——A2 监听成功与否依赖环境权限，不作断言对象）。
func TestOOBBuildChain(t *testing.T) {
	c := NewOOBCoord(config.OOBConfig{}, nil, nil, nil)
	c.SetOverride(&config.OOBConfig{Mode: "off"})
	if ch := c.build(&store.Project{ID: "t1"}); ch != nil {
		t.Errorf("mode=off 应返回 nil")
	}

	// ROE oob_callback=deny：public 链被确定性跳过（原因含 deny 语义，不依赖 A2 是否可绑定）
	c2 := NewOOBCoord(config.OOBConfig{Mode: "public"}, nil, nil, func() bool { return true })
	ch := c2.build(&store.Project{ID: "t1"})
	if ch == nil || ch.Status != "unavailable" {
		t.Fatalf("ROE deny 下 public 应 unavailable，got %+v", ch)
	}
	if !strings.Contains(ch.Reason, "deny") {
		t.Errorf("不可用原因应包含 ROE deny 语义，got %q", ch.Reason)
	}

	// custom 未配置 → 不可用而非 panic
	c3 := NewOOBCoord(config.OOBConfig{Mode: "custom", Custom: config.OOBCustomConfig{Kind: "webhook"}}, nil, nil, func() bool { return false })
	ch3 := c3.build(&store.Project{ID: "t1"})
	if ch3 == nil || ch3.Status != "unavailable" {
		t.Fatalf("custom 未配置应 unavailable，got %+v", ch3)
	}

	// custom.kind 非法 → 显式拒绝
	c4 := NewOOBCoord(config.OOBConfig{Mode: "custom", Custom: config.OOBCustomConfig{Kind: "ftp", ServerURL: "http://x"}}, nil, nil, func() bool { return false })
	ch4 := c4.build(&store.Project{ID: "t1"})
	if ch4 == nil || !strings.Contains(ch4.Reason, "custom.kind") {
		t.Fatalf("kind 非法应显式报错，got %+v", ch4)
	}
}

// TestOOBDepthGateLogic 盲态真阴性门槛：depth<2 或通道不可用都必须降级（逻辑映射单测）。
func TestOOBDepthGateLogic(t *testing.T) {
	cases := []struct {
		depth string
		want  bool // want=true = 通过门（可 ruled_out）
	}{
		{"D2", true}, {"D3", true}, {"D4", true},
		{"D1", false}, {"D0", false}, {"", false}, {"xx", false},
	}
	for _, tc := range cases {
		if got := depthNum(normalizeOOBDepth(tc.depth)) >= 2; got != tc.want {
			t.Errorf("depth=%q 过门=%v，应为 %v", tc.depth, got, tc.want)
		}
	}
}

func TestDNSQNAMEAndReply(t *testing.T) {
	// 构造查询：header + QNAME(3abc7example3com0) + QTYPE=A + QCLASS=IN
	pkt := []byte{0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0, 3, 'a', 'b', 'c', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0, 0, 1, 0, 1}
	if got := dnsQNAME(pkt); got != "abc.example.com" {
		t.Fatalf("dnsQNAME=%q，应为 abc.example.com", got)
	}
	resp := dnsReply(pkt)
	if resp == nil || len(resp) < len(pkt) {
		t.Fatalf("dnsReply 应返回完整应答")
	}
	if resp[2]&0x80 == 0 {
		t.Errorf("应答标志位未置位")
	}
	if resp[len(resp)-4] != 127 || resp[len(resp)-1] != 1 {
		t.Errorf("应答 A 记录应为 127.0.0.1")
	}
	if dnsQNAME([]byte{0, 1, 2}) != "" {
		t.Errorf("畸形报文应返回空")
	}
}

// TestOOBInteractshDomainCapture INFO 行捕获基域即就绪——代理出口环境 DNS 直查 skipped 不降级。
func TestOOBInteractshDomainCapture(t *testing.T) {
	ch := &oobChannel{Status: "degraded", Reason: "启动中"}
	pipe := make(chan string, 8)
	coord := &OOBCoord{}
	go coord.consumeInteractsh(ch, pipe)
	pipe <- "[INF] Using OOB server: oast.pro"
	pipe <- "[DNS] A abc123.oast.pro 1.2.3.4"
	close(pipe)
	chMu := func() (base, st, sc string) {
		ch.mu.Lock()
		defer ch.mu.Unlock()
		return ch.BaseDomain, ch.Status, ch.SelfCheck
	}
	deadline := time.Now().Add(3 * time.Second)
	var base, stt, sck string
	for time.Now().Before(deadline) {
		base, stt, sck = chMu()
		if base != "" && sck != "" {
			break
		}
		time.Sleep(20 * time.Millisecond) // 状态即时落定；SelfCheck 为展示性解析（≤1.5s 超时），一并等待
	}
	if base != "oast.pro" {
		t.Fatalf("BaseDomain=%q，应为 oast.pro", base)
	}
	if stt != "healthy" {
		t.Fatalf("Status=%q，分配即就绪（代理出口修正）", stt)
	}
	if sck != "ok" && sck != "skipped" {
		t.Fatalf("SelfCheck=%q 越界", sck)
	}
}
