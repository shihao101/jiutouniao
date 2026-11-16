package engine

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"jiutouniao/internal/config"
)

func TestSplitDirs(t *testing.T) {
	got := SplitDirs(" ., /deliverables ,, poc,")
	want := []string{".", "deliverables", "poc"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("SplitDirs = %v, want %v", got, want)
	}
	if SplitDirs("") != nil {
		t.Fatalf("SplitDirs(\"\") 应为 nil")
	}
}

func TestListWorkspaceFilesFiltered(t *testing.T) {
	root := t.TempDir()
	pid := "P1"
	mk := func(rel string) {
		p := filepath.Join(root, pid, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("x"), 0o640); err != nil {
			t.Fatal(err)
		}
	}
	for _, rel := range []string{
		"report.md", "findings.json", "app_demo.apk",
		"deliverables/s1-a.md", "deliverables/s2-b.md",
		"poc/exp.py",
		"evidence/e1.txt", "evidence/e2.txt",
		"jadx_out/src/A.java", "jadx_out/src/B.java",
		"assets_www/www/index.js",
	} {
		mk(rel)
	}
	o := &Orchestrator{cfg: &config.Config{DataDir: root}}

	// 白名单：根目录散落 + deliverables + poc；反编译目录天然排除
	files, total, err := o.listWorkspaceFilesFiltered(pid, wsFilter{dirs: []string{".", "deliverables", "poc"}}, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	if total != 6 || len(files) != 6 {
		t.Fatalf("白名单过滤 = %d/%d, want 6/6: %+v", len(files), total, files)
	}

	// 单目录
	files, total, _ = o.listWorkspaceFilesFiltered(pid, wsFilter{dirs: []string{"evidence"}}, time.Time{})
	if total != 2 || len(files) != 2 {
		t.Fatalf("evidence 过滤 = %d/%d, want 2/2", len(files), total)
	}

	// exclude 剔除
	files, total, _ = o.listWorkspaceFilesFiltered(pid, wsFilter{exclude: []string{"jadx_out"}}, time.Time{})
	if total != 9 {
		t.Fatalf("exclude 后 = %d, want 9", total)
	}

	// 旧 prefix 语义保持：engine 内部承接/收口不受新参数影响
	files, _ = o.listWorkspaceFiles(pid, "deliverables")
	if len(files) != 2 {
		t.Fatalf("prefix 模式 = %d, want 2", len(files))
	}

	// 截断与总数：85 个文件 → 显示 80，总数 85
	for i := 0; i < 85; i++ {
		mk(fmt.Sprintf("evidence/bulk-%02d.txt", i))
	}
	files, total, _ = o.listWorkspaceFilesFiltered(pid, wsFilter{dirs: []string{"evidence"}}, time.Time{})
	if len(files) != 80 || total != 87 {
		t.Fatalf("截断 = %d/%d, want 80/87", len(files), total)
	}
}
