package config

import (
	"os"
	"path/filepath"
	"testing"
)

// v3.4.1 回归：barrier_timeout_sec 未配置时代码默认 1800 必须真实生效
// （v3.4.0 曾只有文档承诺、代码默认 0=无限等待，与「屏障超时」目标相悖）。
func TestBarrierTimeoutDefault(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	minimal := `{"listen":":9999"}`
	if err := os.WriteFile(path, []byte(minimal), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Engine.BarrierTimeoutSec != 1800 {
		t.Fatalf("未配置 barrier_timeout_sec 应回退默认 1800，实际 %d", cfg.Engine.BarrierTimeoutSec)
	}
	// 显式配置可覆盖
	if err := os.WriteFile(path, []byte(`{"engine":{"barrier_timeout_sec":600}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err = Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Engine.BarrierTimeoutSec != 600 {
		t.Fatalf("显式配置未生效: %d", cfg.Engine.BarrierTimeoutSec)
	}
}
