package web

// v5.0.0 代理模块/设备动作 纯函数与校验测试（不依赖外部 adb/代理）。

import (
	"strings"
	"testing"
)

func TestValidateProxyEndpoint(t *testing.T) {
	// 合法形态（带/不带 scheme、带凭据）
	ok := []string{"http", "127.0.0.1:7897", "http", "http://u:p@10.0.0.1:8080", "socks5", "socks5://192.168.1.5:1080"}
	for i := 0; i < len(ok); i += 2 {
		if _, err := validateProxyEndpoint(ok[i], ok[i+1]); err != nil {
			t.Fatalf("合法形态应通过: %s %s → %v", ok[i], ok[i+1], err)
		}
	}
	// 非法形态
	bad := []struct{ kind, ep, why string }{
		{"ftp", "1.2.3.4:21", "kind 不支持"},
		{"http", "", "空端点"},
		{"http", "1.2.3.4", "缺端口"},
		{"http", "1.2.3.4:99999", "端口越界"},
		{"http", "host with space:8080", "非法 host"},
	}
	for _, b := range bad {
		if _, err := validateProxyEndpoint(b.kind, b.ep); err == nil {
			t.Fatalf("非法形态应拒绝: %s %s (%s)", b.kind, b.ep, b.why)
		}
	}
}

func TestMaskProxyEndpoint(t *testing.T) {
	m := maskProxyEndpoint("http://user:secret@10.0.0.1:8080")
	if strings.Contains(m, "secret") || !strings.Contains(m, "***@10.0.0.1:8080") {
		t.Fatalf("凭据应掩码: %s", m)
	}
	if got := maskProxyEndpoint("socks5://10.0.0.1:1080"); got != "socks5://10.0.0.1:1080" {
		t.Fatalf("无凭据端点应原样: %s", got)
	}
}

func TestDeviceParamValidation(t *testing.T) {
	if _, err := paramIP(map[string]string{"ip": "192.0.2.10"}, "ip"); err != nil {
		t.Fatalf("合法 IP 应通过: %v", err)
	}
	if _, err := paramIP(map[string]string{"ip": "999.1.1.1"}, "ip"); err == nil {
		t.Fatal("越界 IP 应拒绝")
	}
	if _, err := paramIP(map[string]string{"ip": "abc;rm -rf /"}, "ip"); err == nil {
		t.Fatal("注入串应拒绝")
	}
	if got, _ := paramPort(map[string]string{}, "port", "5555"); got != "5555" {
		t.Fatalf("缺省端口应取默认: %s", got)
	}
	if _, err := paramPort(map[string]string{"port": "0"}, "port", ""); err == nil {
		t.Fatal("非法端口应拒绝")
	}
}
