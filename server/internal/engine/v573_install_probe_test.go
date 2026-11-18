// v5.7.3 install_tool 存在性探测修复单测：/root/go/bin 显式路径（登录 shell PATH 剥离兜底）
package engine

import (
	"strings"
	"testing"
)

func TestV573InstallProbeCmdCoversGoBin(t *testing.T) {
	const marker = "/opt/tools/.installed-interactsh-client"
	p := installProbeCmd("interactsh-client", marker)
	for _, want := range []string{
		"command -v interactsh-client",
		"test -x /root/go/bin/interactsh-client",
		"test -f " + marker,
	} {
		if !strings.Contains(p, want) {
			t.Fatalf("探测命令应包含 %q（背景：bash -lc 登录 shell PATH 被剥掉 /root/go/bin）: %s", want, p)
		}
	}
	// 探测命令自身不能被 scopeGate 代理剥离或注册门误伤——纯 test/命令存在性，无 URL
	if strings.Contains(p, "http://") || strings.Contains(p, "http_proxy") {
		t.Fatalf("探测命令不应包含网络目标或代理赋值: %s", p)
	}
}

func TestV573InstallVerifyCmdCoversGoBin(t *testing.T) {
	v := installVerifyCmd("sqlmap")
	for _, want := range []string{
		"command -v sqlmap >/dev/null 2>&1",
		"test -x /root/go/bin/sqlmap",
		"test -f /opt/tools/sqlmap/sqlmap.py",
	} {
		if !strings.Contains(v, want) {
			t.Fatalf("校验命令应包含 %q: %s", want, v)
		}
	}
	// 三路探测互为冗余：任意一路命中即算存在（|| 语义）
	if strings.Count(v, "||") != 2 {
		t.Fatalf("校验命令应为三路 || 探测: %s", v)
	}
}
