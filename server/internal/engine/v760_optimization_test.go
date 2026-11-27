package engine

import (
	"strings"
	"testing"

	"jiutouniao/internal/llm"
)

// ---------- v7.6.0 双任务实证优化总案：新机制单元测试 ----------

// TestV760NonTargetBareToken B4：裸域名候选的文件名/属性访问过滤。
func TestV760NonTargetBareToken(t *testing.T) {
	cases := []struct {
		stripped string
		token    string
		want     bool // true=非目标位（应过滤）
	}{
		{"cat coverage.json", "coverage.json", true},          // 文件名
		{"python3 -c \"json.load(f)\"", "json.load", true},    // 属性访问
		{"grep s.replace file", "s.replace", true},            // 属性访问
		{"nmap admin.zbj999.com", "admin.zbj999.com", false},  // 真实目标不过滤
		{"curl -s api.example.com", "api.example.com", false}, // 真实目标不过滤
		{"Vant 2.9.0 版本", "2.9.0", true},                      // 版本号尾标签纯数字
		{"checklist.json 解析", "checklist.json", true},         // 文件名
	}
	for _, c := range cases {
		if got := isNonTargetBareToken(c.stripped, c.token); got != c.want {
			t.Errorf("isNonTargetBareToken(%q,%q)=%v want %v", c.stripped, c.token, got, c.want)
		}
	}
}

// TestV760ExecutableScriptPath E7：脚本类落盘路径判定。
func TestV760ExecutableScriptPath(t *testing.T) {
	for _, p := range []string{"scripts/probe.sh", "run.py", "tool.pl", "x.rb", "job.bash"} {
		if !isExecutableScriptPath(p) {
			t.Errorf("%s 应判定为脚本", p)
		}
	}
	for _, p := range []string{"deliverables/s4-漏洞清单.md", "evidence/out.txt", "checklist.json", "report.md"} {
		if isExecutableScriptPath(p) {
			t.Errorf("%s 不应判定为脚本", p)
		}
	}
}

// TestV760CompactFloor C1 集中式压缩：触发线与裁剪目标分离——
// 超 trigger 才压缩，且压到 floor 以下（一次深剪，减少触发频次）。
func TestV760CompactFloor(t *testing.T) {
	// 构造大量工具回执消息（每条 >400 字符可被压缩）
	mk := func(n int) []llm.Message {
		msgs := []llm.Message{{Role: "system", Content: strings.Repeat("S", 500)}, {Role: "user", Content: "目标"}}
		for i := 0; i < n; i++ {
			msgs = append(msgs, llm.Message{Role: "tool", Content: strings.Repeat("T", 2000)})
		}
		return msgs
	}
	// 未超触发线：不压缩
	msgs := mk(10)
	if _, n := compactMsgsWithArchiveFloor(msgs, 100_000, 70_000, 6, nil); n != 0 {
		t.Fatalf("未超触发线不应压缩, got %d", n)
	}
	// 超 trigger、floor=50%：压缩后估算应显著低于 trigger
	msgs = mk(200)
	out, n := compactMsgsWithArchiveFloor(msgs, 20_000, 10_000, 6, nil)
	if n == 0 {
		t.Fatal("超触发线应发生压缩")
	}
	if est := estimateTokens(out); est > 20_000 {
		t.Fatalf("集中式压缩后应 ≤floor 口径，估算 %d", est)
	}
}

// TestV760FindingSyncRegex A4：修订要求+F 编号同句正则。
func TestV760FindingSyncRegex(t *testing.T) {
	hits := findingRevRe.FindAllStringSubmatch("子代理请求主头修订 F-F6D2DD02C6：追加明文子项关闭；另有 F-5B62CE511C 维持疑似不移入", -1)
	if len(hits) != 1 {
		t.Fatalf("应命中 1 处修订要求，实际 %d", len(hits))
	}
	if !strings.EqualFold(hits[0][1], "F-F6D2DD02C6") {
		t.Fatalf("应捕获 F-F6D2DD02C6，实际 %s", hits[0][1])
	}
	// 无修订关键词的 F- 引用不命中
	if hits := findingRevRe.FindAllStringSubmatch("复验 F-EC36873B25 与库内 detail 一致", -1); len(hits) != 0 {
		t.Fatalf("纯引用不应命中: %v", hits)
	}
	// 距离超 30 字符不命中
	if hits := findingRevRe.FindAllStringSubmatch("修订依据详见第五节证据链完整论述及附录索引 F-12345678", -1); len(hits) != 0 {
		t.Fatalf("远距离引用不应命中: %v", hits)
	}
}

// TestV760EngineIntrospection B7：引擎自省识别。
func TestV760EngineIntrospection(t *testing.T) {
	o := &Orchestrator{}
	for _, cmd := range []string{
		"grep -a endpoint_enc /app/jiutouniao",
		"strings /app/jiutouniao | grep gate",
		"python3 /app/eval/gates/coverage_gate.py",
		"cat eval/gates/coverage_gate.py",
	} {
		if o.engineIntrospectionBlocked(cmd) == "" {
			t.Errorf("应拦截引擎自省: %s", cmd)
		}
	}
	for _, cmd := range []string{"nmap -sV target", "curl -s https://target/api", "dig @ns1 target"} {
		if o.engineIntrospectionBlocked(cmd) != "" {
			t.Errorf("不应拦截正常测试命令: %s", cmd)
		}
	}
}
