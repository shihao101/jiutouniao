package engine

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ListDir 路径沙箱专项（前缀归一语义与 ReadFile 一致）：任何输入都被 Clean 钳制进项目工作区，
// 绝不触达工作区外文件；不存在目录返回空列表而非错误。
func TestListDirPathSandbox(t *testing.T) {
	dir := t.TempDir()
	e := newTestExec(t, dir)
	// 工作区内证据文件 + 工作区外的机密文件（用于证明父目录不可达）
	inFile := filepath.Join(dir, "PX", "evidence", "a.log")
	if err := os.MkdirAll(filepath.Dir(inFile), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(inFile, []byte("TIME=0.2s"), 0o640); err != nil {
		t.Fatal(err)
	}
	secret := filepath.Join(dir, "secret.txt")
	if err := os.WriteFile(secret, []byte("top-secret"), 0o640); err != nil {
		t.Fatal(err)
	}
	// 绝对路径/上层路径全部被钳制为工作区相对路径 → 空结果（不存在的 PX/etc），无泄漏；
	// "/"（等于工作区根本身）被前缀校验拒绝——与 ReadFile 同语义，同样安全
	for _, p := range []string{"/etc", "../../etc", "../outside", "/"} {
		out, err := e.ListDir("PX", p)
		if err != nil && p != "/" {
			t.Fatalf("ListDir(%q) 不应报错（钳制语义）: %v", p, err)
		}
		for _, rel := range out {
			if strings.Contains(rel, "secret") || strings.HasPrefix(rel, "../") {
				t.Fatalf("ListDir(%q) 泄漏工作区外内容: %v", p, out)
			}
		}
	}
	// ".." 归一后等于工作区根本身 → 被前缀校验拒绝（报错）；即便放行也绝不能列出父目录 secret.txt
	out, err := e.ListDir("PX", "..")
	if err == nil {
		for _, rel := range out {
			if strings.Contains(rel, "secret") || strings.HasPrefix(rel, "../") {
				t.Fatalf("\"..\" 泄漏父目录内容: %v", out)
			}
		}
	}
	// 工作区内正常列举 + 不存在目录 → 空
	out, err = e.ListDir("PX", "evidence")
	if err != nil || len(out) != 1 || !strings.HasSuffix(out[0], "evidence/a.log") {
		t.Fatalf("工作区内列举应正常: %v %v", out, err)
	}
	if out, err = e.ListDir("PX", "deliverables"); err != nil || len(out) != 0 {
		t.Fatalf("不存在目录应返回空: %v %v", out, err)
	}
}
