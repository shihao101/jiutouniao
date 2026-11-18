// Package credentials v5.5.0 结构化凭据仓库（修复方案 A：有凭证深度测试的地基）。
//
// 职责边界：
//   - 明文只在两个瞬间存在：录入工具调用参数、执行注入的短生命周期内存 buffer；
//   - 静态存储一律 AES-256-GCM 密文（nonce 独立随机、加密封装版本化），主密钥仅从
//     CREDENTIALS_MASTER_KEY 环境变量注入（不落 config.json/DB）；
//   - 主密钥缺失时 fail closed：录入/解密直接报错，绝不降级为明文存储；
//   - 展示纪律：一切日志/证据/工具回执/UI 只输出掩码（Mask），与 Loot 掩码纪律一致。
//
// 与 Loot 的关系：LootRecord 继续只存掩码摘要（可审计的发现记录）；凭据本体在此仓库，
// 可用 SourceLootID 关联，但不得从 Loot 掩码反推凭据。
package credentials

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"strings"

	"jiutouniao/internal/store"
)

// CipherVersion 加密封装版本（密文前缀 v1:），支持未来轮换。
const CipherVersion = 1

// EnvMasterKey 主密钥环境变量名（32 字节原始/hex/base64 均可，解析失败即拒绝启用）。
const EnvMasterKey = "CREDENTIALS_MASTER_KEY"

// Service 凭据仓库服务：包装 store.CredentialRecord 的加解密与掩码投影。
type Service struct {
	st      *store.Store
	aead    cipher.AEAD
	enabled bool
}

// masterKey 解析主密钥：32 字节原始 / 64 字符 hex / 44 字符 base64（填充后 32 字节）。
func masterKey(raw string) ([]byte, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, errors.New("CREDENTIALS_MASTER_KEY 未设置")
	}
	if len(raw) == 32 {
		return []byte(raw), nil
	}
	if len(raw) == 64 {
		if b, err := hexDecode(raw); err == nil && len(b) == 32 {
			return b, nil
		}
	}
	if b, err := base64.StdEncoding.DecodeString(raw); err == nil && len(b) == 32 {
		return b, nil
	}
	return nil, errors.New("CREDENTIALS_MASTER_KEY 格式非法（需 32 字节原始 / 64 字符 hex / base64(32B)）")
}

func hexDecode(s string) ([]byte, error) {
	var out []byte
	for i := 0; i+1 < len(s); i += 2 {
		hi, ok1 := hexVal(s[i])
		lo, ok2 := hexVal(s[i+1])
		if !ok1 || !ok2 {
			return nil, errors.New("bad hex")
		}
		out = append(out, hi<<4|lo)
	}
	return out, nil
}

func hexVal(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	}
	return 0, false
}

// New 构造服务：主密钥缺失/非法时返回 enabled=false 的服务（fail closed，不报错——
// 未配置凭据仓库的项目照常运行，只是录入/注入工具不可用）。
func New(st *store.Store) (*Service, error) {
	s := &Service{st: st}
	raw := os.Getenv(EnvMasterKey)
	if strings.TrimSpace(raw) == "" {
		return s, nil
	}
	key, err := masterKey(raw)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	s.aead = aead
	s.enabled = true
	return s, nil
}

// Enabled 是否已配置主密钥（决定引擎是否暴露凭据工具）。
func (s *Service) Enabled() bool { return s.enabled }

// encrypt 明文 → "v1:base64(nonce||ciphertext)"。
func (s *Service) encrypt(plain []byte) ([]byte, error) {
	if !s.enabled {
		return nil, errors.New("凭据仓库未启用（缺少 CREDENTIALS_MASTER_KEY）")
	}
	nonce := make([]byte, s.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	ct := s.aead.Seal(nonce, nonce, plain, nil)
	return []byte(fmt.Sprintf("v%d:%s", CipherVersion, base64.StdEncoding.EncodeToString(ct))), nil
}

// decrypt "v1:…" 密文 → 明文（认证失败/版本未知均拒绝）。
func (s *Service) decrypt(blob []byte) ([]byte, error) {
	if !s.enabled {
		return nil, errors.New("凭据仓库未启用（缺少 CREDENTIALS_MASTER_KEY）")
	}
	str := string(blob)
	i := strings.IndexByte(str, ':')
	if i < 0 {
		return nil, errors.New("密文格式非法（缺版本前缀）")
	}
	var ver int
	if _, err := fmt.Sscanf(str[:i], "v%d", &ver); err != nil || ver != CipherVersion {
		return nil, fmt.Errorf("密文版本 %s 不受支持", str[:i])
	}
	raw, err := base64.StdEncoding.DecodeString(str[i+1:])
	if err != nil {
		return nil, err
	}
	if len(raw) < s.aead.NonceSize() {
		return nil, errors.New("密文过短")
	}
	nonce, body := raw[:s.aead.NonceSize()], raw[s.aead.NonceSize():]
	return s.aead.Open(nil, nonce, body, nil)
}

// Secret 解密后的凭据载荷（短生命周期；调用方用完即弃，不得落日志/证据）。
type Secret struct {
	Username string
	Value    string // 按 Kind 解释：bearer/token=令牌；basic=口令；cookie=Cookie 头值；header=完整 "Name: value"
}

// CredentialMeta 掩码投影（一切对外展示只用这个）。
type CredentialMeta struct {
	ID       string `json:"id"`
	Target   string `json:"target"`
	Identity string `json:"identity"`
	Role     string `json:"role,omitempty"`
	Kind     string `json:"kind"`
	Username string `json:"username,omitempty"` // 已掩码
	Status   string `json:"status"`
	Origin   string `json:"origin,omitempty"` // real/forged/derived（v5.6.0 来源谱系）
	Method   string `json:"method,omitempty"` // 伪造/派生方法
}

// Input 录入参数。
type Input struct {
	ProjectID    string
	Target       string
	Identity     string
	Role         string
	Kind         string // bearer/basic/cookie/header/token
	Username     string
	Secret       string // 明文（仅本次调用内存在）
	SourceLootID string
	Origin       string // v5.6.0：real（默认）/forged/derived
	ParentID     string // v5.6.0：伪造/派生父凭据
	Method       string // v5.6.0：伪造/派生方法
}

// Put 加密落库；返回掩码元数据（不回显明文）。
func (s *Service) Put(in Input) (*CredentialMeta, error) {
	if !s.enabled {
		return nil, errors.New("凭据仓库未启用：请设置 CREDENTIALS_MASTER_KEY（32 字节 hex/base64）后重启")
	}
	if strings.TrimSpace(in.Secret) == "" {
		return nil, errors.New("secret 为空")
	}
	if strings.TrimSpace(in.Identity) == "" || strings.TrimSpace(in.Kind) == "" {
		return nil, errors.New("identity 与 kind 必填")
	}
	switch in.Kind {
	case "bearer", "basic", "cookie", "header", "token":
	default:
		return nil, fmt.Errorf("kind 仅支持 bearer/basic/cookie/header/token，收到 %q", in.Kind)
	}
	switch in.Origin {
	case "real", "forged", "derived":
	default:
		in.Origin = "real" // v5.6.0：来源谱系规范化——入库记录一律携带 origin
	}
	// v5.6.1（审计 RunB#25）：谱系可信校验——①forged/derived 必须声明 Method；②ParentID
	// 必须存在、同项目、且父凭据为 real/derived（谱系链不可凭空指向）。
	if (in.Origin == "forged" || in.Origin == "derived") && strings.TrimSpace(in.Method) == "" {
		return nil, fmt.Errorf("origin=%s 必须携带 method（伪造/派生手法，如 jwt-none、alg-confusion、token-relay）", in.Origin)
	}
	if strings.TrimSpace(in.ParentID) != "" {
		parent, perr := s.st.GetCredential(in.ProjectID, strings.TrimSpace(in.ParentID))
		if perr != nil {
			return nil, fmt.Errorf("parent 凭据 %s 校验失败: %w", in.ParentID, perr)
		}
		if parent.Origin == "forged" && in.Origin == "real" {
			return nil, fmt.Errorf("谱系矛盾：origin=real 的凭据不能以 forged 凭据 %s 为父", in.ParentID)
		}
	}
	ct, err := s.encrypt([]byte(in.Secret))
	if err != nil {
		return nil, err
	}
	rec := &store.CredentialRecord{
		ProjectID:        in.ProjectID,
		Target:           in.Target,
		Identity:         in.Identity,
		Role:             in.Role,
		Kind:             in.Kind,
		Username:         in.Username,
		SecretCiphertext: ct,
		SecretVersion:    CipherVersion,
		SourceLootID:     in.SourceLootID,
		Origin:           in.Origin,
		ParentID:         in.ParentID,
		Method:           in.Method,
	}
	id, err := s.st.AddCredential(rec)
	if err != nil {
		return nil, err
	}
	return s.meta(rec, id), nil
}

// Get 解密取回（校验项目归属；revoke 状态拒绝）。
func (s *Service) Get(projectID, id string) (*Secret, error) {
	rec, err := s.st.GetCredential(projectID, id)
	if err != nil {
		return nil, err
	}
	if rec.Status != "active" {
		return nil, fmt.Errorf("凭据 %s 已 revoke/失效", id)
	}
	plain, err := s.decrypt(rec.SecretCiphertext)
	if err != nil {
		return nil, fmt.Errorf("凭据解密失败: %w", err)
	}
	return &Secret{Username: rec.Username, Value: string(plain)}, nil
}

// List 项目凭据掩码清单（永不返回明文）。
func (s *Service) List(projectID string) ([]CredentialMeta, error) {
	recs, err := s.st.ListCredentials(projectID)
	if err != nil {
		return nil, err
	}
	out := make([]CredentialMeta, 0, len(recs))
	for _, r := range recs {
		out = append(out, *s.meta(r, r.ID))
	}
	return out, nil
}

// Revoke 撤销（下次 Resolve/Get 直接拒绝）。
func (s *Service) Revoke(projectID, id string) error {
	rec, err := s.st.GetCredential(projectID, id)
	if err != nil {
		return err
	}
	rec.Status = "revoked"
	return s.st.SaveCredential(rec)
}

// meta 掩码投影（含 Username 掩码；凭据值本身不投影）。
func (s *Service) meta(r *store.CredentialRecord, id string) *CredentialMeta {
	if r.Origin == "" {
		r.Origin = "real" // 旧记录/未标注默认真实凭据
	}
	return &CredentialMeta{
		ID: id, Target: r.Target, Identity: r.Identity, Role: r.Role,
		Kind: r.Kind, Username: Mask(r.Username), Status: r.Status,
		Origin: r.Origin, Method: r.Method,
	}
}

// Mask 掩码：≤4 字符全 ***；否则保留首 2 末 2。
func Mask(s string) string {
	r := []rune(s)
	if len(r) == 0 {
		return s
	}
	if len(r) <= 4 {
		return "***"
	}
	return string(r[:2]) + "***" + string(r[len(r)-2:])
}
