// v5.7.2 安装通道分流单测：国内源直连优先/国外源代理优先互为兜底 + scopeGate 代理赋值剥离
package engine

import (
	"strings"
	"testing"

	"jiutouniao/internal/store"
)

func TestV572BuildInstallAttemptsDomesticDirectFirst(t *testing.T) {
	const px = "http://172.17.0.1:8118"
	attempts := buildInstallAttempts("wafw00f", px)
	var labels []string
	for _, a := range attempts {
		labels = append(labels, a.label)
	}
	want := []string{
		"apt 包管理器(Kali)·直连", "apt 包管理器(Kali)·代理兜底",
		"pip 清华源·直连", "pip 清华源·代理兜底",
	}
	if len(attempts) != len(want) {
		t.Fatalf("wafw00f（无 git 源）应有 %d 条尝试，实得 %d: %v", len(want), len(attempts), labels)
	}
	for i, w := range want {
		if labels[i] != w {
			t.Fatalf("尝试[%d] 标签应为 %q，实得 %q（全序列 %v）", i, w, labels[i], labels)
		}
	}
	// 直连前缀显式剥离代理变量；代理前缀显式注入指定地址
	if !strings.HasPrefix(attempts[0].cmd, "unset http_proxy https_proxy HTTP_PROXY HTTPS_PROXY; ") {
		t.Fatalf("直连尝试应以 unset 代理变量开头: %s", attempts[0].cmd)
	}
	if !strings.Contains(attempts[1].cmd, "export http_proxy="+px) || !strings.Contains(attempts[1].cmd, "https_proxy="+px) {
		t.Fatalf("代理兜底尝试应显式注入双代理变量: %s", attempts[1].cmd)
	}
}

func TestV572BuildInstallAttemptsGitRegionOrdering(t *testing.T) {
	const px = "http://172.17.0.1:8118"
	attempts := buildInstallAttempts("sqlmap", px)
	labels := map[string]string{}
	var order []string
	for _, a := range attempts {
		labels[a.label] = a.cmd
		order = append(order, a.label)
	}
	for _, l := range []string{
		"apt 包管理器(Kali)·直连", "apt 包管理器(Kali)·代理兜底",
		"pip 清华源·直连", "pip 清华源·代理兜底",
		"git 源码(github)·代理", "git 源码(github)·直连兜底",
		"git 源码(gitee)·直连", "git 源码(gitee)·代理兜底",
	} {
		if _, ok := labels[l]; !ok {
			t.Fatalf("缺少尝试 %q（全序列 %v）", l, order)
		}
	}
	// github 国外源：代理为主路径；gitee 国内源：直连为主路径
	if !strings.Contains(labels["git 源码(github)·代理"], "https://github.com/sqlmapproject/sqlmap.git") {
		t.Fatalf("github·代理应克隆 github 源: %s", labels["git 源码(github)·代理"])
	}
	if !strings.Contains(labels["git 源码(gitee)·直连"], "https://gitee.com/mirrors/sqlmap.git") {
		t.Fatalf("gitee·直连应克隆 gitee 镜像: %s", labels["git 源码(gitee)·直连"])
	}
	// 标签由源地址派生而非下标硬编码（源清单顺序调整不再错标）
	if gitSourceLabel("https://github.com/x/y.git") != "github" || gitSourceLabel("https://gitee.com/mirrors/x.git") != "gitee" {
		t.Fatalf("gitSourceLabel 派生错误: %q / %q", gitSourceLabel("https://github.com/x/y.git"), gitSourceLabel("https://gitee.com/mirrors/x.git"))
	}
	if !installSourceDomestic("https://gitee.com/mirrors/sqlmap.git") || installSourceDomestic("https://github.com/sqlmapproject/sqlmap.git") {
		t.Fatalf("国内源判定错误：gitee 应 domestic、github 应 foreign")
	}
}

func TestV572BuildInstallAttemptsNoProxyDirectOnly(t *testing.T) {
	// 未配置任何代理（公开分发默认）→ 仅直连尝试，行为同旧版
	attempts := buildInstallAttempts("sqlmap", "")
	if len(attempts) != 4 {
		t.Fatalf("无代理时 sqlmap 应恰好 4 条直连尝试（apt/pip/git×2），实得 %d", len(attempts))
	}
	for _, a := range attempts {
		if strings.Contains(a.label, "代理") {
			t.Fatalf("无代理时不应出现代理尝试: %s", a.label)
		}
		if !strings.HasPrefix(a.cmd, "unset http_proxy") {
			t.Fatalf("全部尝试均应为直连前缀: %s", a.label)
		}
	}
}

func TestV572ScopeGateIgnoresProxyAssignments(t *testing.T) {
	o, st := v48Orchestrator(t)
	p := &store.Project{ ROEAcknowledgedAt: "2026-11-22T00:00:00Z",ID: "P-V572", Target: "https://iop.example.edu.cn/", StrictScope: true}
	_ = st.SaveProject(p)
	// install_tool 代理兜底命令形态：代理地址（docker 网桥 IP）+ 白名单 kali 源 → 放行
	cmd := "export http_proxy=http://172.17.0.1:8118 https_proxy=http://172.17.0.1:8118; unset http_proxy https_proxy HTTP_PROXY HTTPS_PROXY; apt-get update -qq; apt-get install -y wafw00f"
	if blocked, _ := o.scopeGate(p, cmd); blocked {
		t.Fatalf("代理赋值应剥离后再做目标匹配，install_tool 代理兜底命令不应被 strict_scope 误拦")
	}
	// loop-core 教的 env http_proxy=$TOOL_PROXY 前缀 + 白名单源 → 放行（既有潜伏误拦面）
	if blocked, _ := o.scopeGate(p, "env http_proxy=http://192.0.2.1:7897 curl -s https://crt.sh/?q=x"); blocked {
		t.Fatalf("env 代理前缀+白名单源不应被误拦")
	}
	// 代理赋值不豁免业务目标：范围外 URL 仍拦截
	blocked, _ := o.scopeGate(p, "export https_proxy=http://172.17.0.1:8118; curl -s https://other-univ.edu.cn/admin")
	if !blocked {
		t.Fatalf("代理赋值剥离后，范围外目标仍应拦截")
	}
	// 无代理赋值的旧行为不回归：白名单放行 / 范围外拦截
	if blocked, _ := o.scopeGate(p, "curl -s https://http.kali.org/kali/"); blocked {
		t.Fatalf("白名单 kali 源应放行")
	}
	if blocked, _ := o.scopeGate(p, "curl -s https://random-target.example.net/x"); !blocked {
		t.Fatalf("范围外目标应拦截")
	}
}
