package engine

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// ---------- 工作区文件扫描（交付物承接 / 收口强制） ----------

type wsFile struct {
	Path    string `json:"path"`
	Size    int64  `json:"size"`
	ModTime string `json:"mod_time"`
}

func (o *Orchestrator) workspaceRoot(projectID string) string {
	return filepath.Join(o.cfg.DataDir, projectID)
}

// wsFilter 工作区列举过滤器：prefix=相对路径前缀（旧语义，引擎内部沿用）；
// dirs=顶层目录白名单（"." 代表根目录散落文件）；exclude=排除的顶层目录/前缀。dirs 非空时优先于 prefix。
type wsFilter struct {
	prefix  string
	dirs    []string
	exclude []string
}

// SplitDirs 逗号分隔的目录参数 → 清洗后的列表（去空、去首尾斜杠）。供 Web 层解析 query 参数。
func SplitDirs(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		p = strings.Trim(strings.TrimSpace(p), "/")
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

// listWorkspaceFiles 列出工作区文件（prefix 相对目录可选），按修改时间倒序。
func (o *Orchestrator) listWorkspaceFiles(projectID, prefix string) ([]wsFile, error) {
	return o.listWorkspaceFilesSince(projectID, prefix, time.Time{})
}

// listWorkspaceFilesSince 仅列出 mtime>=since 的文件。
func (o *Orchestrator) listWorkspaceFilesSince(projectID, prefix string, since time.Time) ([]wsFile, error) {
	files, _, err := o.listWorkspaceFilesFiltered(projectID, wsFilter{prefix: prefix}, since)
	return files, err
}

// listWorkspaceFilesFiltered 按过滤器列出工作区文件，按修改时间倒序并截断到最新 cap 条。
// 返回（截断后列表, 过滤后总数）——总数供 UI 如实展示「共 N · 显示 M」。
func (o *Orchestrator) listWorkspaceFilesFiltered(projectID string, f wsFilter, since time.Time) ([]wsFile, int, error) {
	root := o.workspaceRoot(projectID)
	dirSet := map[string]bool{}
	wantRoot := false
	for _, d := range f.dirs {
		if d == "." {
			wantRoot = true
			continue
		}
		dirSet[d] = true
	}
	var out []wsFile
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		rel = filepath.ToSlash(rel)
		if len(dirSet) > 0 || wantRoot {
			top, isSub := rel, false
			if i := strings.IndexByte(rel, '/'); i >= 0 {
				top, isSub = rel[:i], true
			}
			if isSub {
				if !dirSet[top] {
					return nil
				}
			} else if !wantRoot {
				return nil
			}
		} else if f.prefix != "" && !strings.HasPrefix(rel, strings.Trim(f.prefix, "/")) {
			return nil
		}
		for _, ex := range f.exclude {
			if rel == ex || strings.HasPrefix(rel, ex+"/") {
				return nil
			}
		}
		if info.ModTime().Before(since) {
			return nil
		}
		out = append(out, wsFile{Path: rel, Size: info.Size(), ModTime: info.ModTime().Format(time.RFC3339)})
		return nil
	})
	// 倒序：最新产出在前；同刻按路径，保证顺序稳定
	sort.Slice(out, func(i, j int) bool {
		if out[i].ModTime != out[j].ModTime {
			return out[i].ModTime > out[j].ModTime
		}
		return out[i].Path < out[j].Path
	})
	total := len(out)
	const cap = 80
	if total > cap {
		out = out[:cap]
	}
	return out, total, err
}

func freshPaths(files []wsFile) []string {
	var out []string
	for _, f := range files {
		out = append(out, f.Path)
	}
	return out
}

func humanSize(n int64) string {
	switch {
	case n >= 1<<20:
		return fmt.Sprintf("%.1fMB", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.1fKB", float64(n)/(1<<10))
	default:
		return fmt.Sprintf("%dB", n)
	}
}

// WriteFileAt 在工作区写文件（供导出等内部使用）。
func (o *Orchestrator) WriteFileAt(projectID, relPath string, content []byte) error {
	full := filepath.Join(o.workspaceRoot(projectID), filepath.Clean("/" + relPath)[1:])
	if err := os.MkdirAll(filepath.Dir(full), 0o750); err != nil {
		return err
	}
	return os.WriteFile(full, content, 0o640)
}
