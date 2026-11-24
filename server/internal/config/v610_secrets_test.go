// v6.1.0（S1 修复方案⑨）：凭据外置回归——缺失管理员凭据 fail-fast、env 注入生效、
// 错误信息不回显凭据值、默认口令不再回填。
package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeCfg(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestV610MissingAdminCredentialFailsStartup(t *testing.T) {
	p := writeCfg(t, `{"listen":":8787","data_dir":"/tmp/x"}`)
	_, err := Load(p)
	if err == nil || !strings.Contains(err.Error(), "管理员凭据未配置") {
		t.Fatalf("无管理员凭据应 fail-fast: %v", err)
	}
	// 哈希配置即可启动
	p2 := writeCfg(t, `{"listen":":8787","data_dir":"/tmp/x","admin_password_hash":"abc"}`)
	if _, err := Load(p2); err != nil {
		t.Fatalf("配置哈希应可启动: %v", err)
	}
}

func TestV610ConfigReadsSecretsFromEnvironment(t *testing.T) {
	t.Setenv("ADMIN_PASSWORD", "env-pass-123")
	t.Setenv("ADMIN_PASSWORD_HASH", "")
	p := writeCfg(t, `{"listen":":8787","data_dir":"/tmp/x"}`)
	c, err := Load(p)
	if err != nil {
		t.Fatalf("env 注入应通过校验: %v", err)
	}
	if c.AdminPassword != "env-pass-123" {
		t.Fatalf("ADMIN_PASSWORD 环境变量应生效: %q", c.AdminPassword)
	}
	t.Setenv("ADMIN_PASSWORD", "")
	t.Setenv("ADMIN_PASSWORD_HASH", "hash-env")
	p2 := writeCfg(t, `{"listen":":8787","data_dir":"/tmp/x"}`)
	c2, err := Load(p2)
	if err != nil {
		t.Fatalf("hash env 应通过: %v", err)
	}
	if c2.AdminPasswordHash != "hash-env" {
		t.Fatalf("ADMIN_PASSWORD_HASH 环境变量应生效: %q", c2.AdminPasswordHash)
	}
}

func TestV610ConfigErrorsNeverPrintSecret(t *testing.T) {
	secret := "super-secret-pass-xyz"
	p := writeCfg(t, `{"listen":":8787","data_dir":"/tmp/x","admin_password_hash":""}`)
	_, err := Load(p)
	if err == nil {
		t.Fatal("应失败")
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatal("错误信息不得回显凭据")
	}
	_ = secret
}

func TestV610NoDefaultPasswordBackfill(t *testing.T) {
	c := &Config{}
	c.ApplyDefaultsForTest()
	if c.AdminPassword != "" {
		t.Fatalf("applyDefaults 不得回填默认口令（v6.1.0 移除）: %q", c.AdminPassword)
	}
}

func TestV610GuardGatesDefaultOn(t *testing.T) {
	c := &Config{}
	c.ApplyDefaultsForTest()
	for name, flag := range map[string]*bool{
		"enforce_authorization": c.Guard.EnforceAuthorization, "block_shadow_assets": c.Guard.BlockShadowAssets,
		"enforce_asset_scope": c.Guard.EnforceAssetScope, "enforce_s1_l0": c.Guard.EnforceS1L0,
		"enforce_s1_closure": c.Guard.EnforceS1Closure, "enforce_roe_runtime": c.Guard.EnforceROERuntime,
		"require_s1_roe_ack": c.Guard.RequireS1ROEAck, "require_s1_oob_channel": c.Guard.RequireS1OOBChannel,
		"lesson_behavior_per_target": c.Guard.LessonBehaviorPerTarget, "asset_metadata_validation": c.Guard.AssetMetadataValidation,
	} {
		if !FlagOrDefault(flag, true) {
			t.Fatalf("guard.%s 缺省应为 true（缺字段不允许静默关闭）", name)
		}
	}
	// 显式 false 才回退
	f := false
	if FlagOrDefault(&f, true) {
		t.Fatal("显式 false 应生效")
	}
}

func TestV610WhoisInL0Whitelist(t *testing.T) {
	_, _, _, ro, _ := DefaultGuard()
	found := false
	for _, p := range ro {
		if p == "whois" {
			found = true
		}
	}
	if !found {
		t.Fatal("whois 应在 defaultReadOnly（⑦ S1 被动情报清单支撑）")
	}
}
