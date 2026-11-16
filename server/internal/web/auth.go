package web

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"
	"sync"
	"time"

	"jiutouniao/internal/config"
)

// ---------- 会话存储 ----------

type sessionStore struct {
	mu       sync.Mutex
	sessions map[string]time.Time // token -> 过期时间
}

func newSessionStore() *sessionStore {
	return &sessionStore{sessions: map[string]time.Time{}}
}

func (s *sessionStore) create() string {
	b := make([]byte, 24)
	_, _ = rand.Read(b)
	tok := fmt.Sprintf("%x", b)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions[tok] = time.Now().Add(24 * time.Hour)
	s.gcLocked()
	return tok
}

func (s *sessionStore) valid(token string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	exp, ok := s.sessions[token]
	if !ok {
		return false
	}
	if time.Now().After(exp) {
		delete(s.sessions, token)
		return false
	}
	return true
}

func (s *sessionStore) drop(token string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessions, token)
}

func (s *sessionStore) gcLocked() {
	now := time.Now()
	for k, exp := range s.sessions {
		if now.After(exp) {
			delete(s.sessions, k)
		}
	}
}

// ---------- 验证码（SVG，无外部依赖） ----------

type captchaEntry struct {
	answer  string
	expires time.Time
}

type captchaStore struct {
	mu sync.Mutex
	m  map[string]captchaEntry
}

func newCaptchaStore() *captchaStore {
	return &captchaStore{m: map[string]captchaEntry{}}
}

var captchaAlphabet = []rune("23456789ABCDEFGHJKMNPQRSTUVWXYZ") // 去除易混淆字符

// Generate 生成 4 位验证码：返回 id、SVG 文本；debug 模式附带明文。
func (c *captchaStore) Generate(debug bool) (id, svg, code string) {
	ans := make([]rune, 4)
	for i := range ans {
		n, _ := rand.Int(rand.Reader, big.NewInt(int64(len(captchaAlphabet))))
		ans[i] = captchaAlphabet[n.Int64()]
	}
	answer := string(ans)
	b := make([]byte, 12)
	_, _ = rand.Read(b)
	id = fmt.Sprintf("%x", b)

	c.mu.Lock()
	// 惰性清理过期项
	now := time.Now()
	for k, e := range c.m {
		if now.After(e.expires) {
			delete(c.m, k)
		}
	}
	c.m[id] = captchaEntry{answer: answer, expires: now.Add(3 * time.Minute)}
	c.mu.Unlock()

	svg = renderCaptchaSVG(answer)
	if debug {
		code = answer
	}
	return id, svg, code
}

// Verify 校验并销毁（一次性）。
func (c *captchaStore) Verify(id, input string) bool {
	c.mu.Lock()
	e, ok := c.m[id]
	if ok {
		delete(c.m, id) // 无论对错都销毁，防重放
	}
	c.mu.Unlock()
	if !ok || time.Now().After(e.expires) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(strings.ToUpper(input)), []byte(e.answer)) == 1
}

// renderCaptchaSVG 生成带干扰线与随机旋转的 SVG。
// 安全修复：字符以描边路径（polyline）绘制，SVG 中不再出现明文 <text> 节点——
// 防止脚本直接从标记解析验证码（曾被发现可用 10 行脚本自动破译）。
func renderCaptchaSVG(code string) string {
	var b strings.Builder
	b.WriteString(`<svg xmlns="http://www.w3.org/2000/svg" width="150" height="52" viewBox="0 0 150 52">`)
	colors := []string{"#4493f8", "#3fb950", "#d29922", "#a371f7", "#39c5cf"}
	// 背景渐变
	b.WriteString(`<defs><linearGradient id="bg" x1="0" y1="0" x2="1" y2="1">`)
	b.WriteString(`<stop offset="0" stop-color="#101826"/><stop offset="1" stop-color="#1a2338"/>`)
	b.WriteString(`</linearGradient></defs>`)
	b.WriteString(`<rect width="150" height="52" fill="url(#bg)" rx="8"/>`)
	// 干扰线
	for i := 0; i < 5; i++ {
		x1 := rnd(0, 140)
		y1 := rnd(4, 46)
		x2 := x1 + rnd(-40, 40)
		y2 := rnd(4, 46)
		fmt.Fprintf(&b, `<line x1="%d" y1="%d" x2="%d" y2="%d" stroke="%s" stroke-width="1" opacity="0.45"/>`,
			x1, y1, x2, y2, colors[i%len(colors)])
	}
	// 干扰点
	for i := 0; i < 24; i++ {
		fmt.Fprintf(&b, `<circle cx="%d" cy="%d" r="1" fill="%s" opacity="0.5"/>`,
			rnd(0, 148), rnd(0, 50), colors[rnd(0, 4)])
	}
	// 字符：描边字体（随机旋转/位移/颜色/轻微缩放），无文本节点
	for i, ch := range code {
		glyph, ok := captchaGlyphs[ch]
		if !ok {
			continue
		}
		s := 2.0 + float64(rnd(-1, 2))*0.05 // 缩放抖动
		x0 := float64(20+i*30) + float64(rnd(-3, 3))
		y0 := float64(10 + rnd(-2, 2))
		rot := rnd(-25, 25)
		cx, cy := x0+10, y0+14
		c1 := colors[rnd(0, len(colors)-1)]
		var paths strings.Builder
		for _, line := range glyph {
			pts := make([]string, 0, len(line))
			for _, pt := range line {
				pts = append(pts, fmt.Sprintf("%.1f,%.1f", x0+float64(pt[0])*s, y0+float64(pt[1])*s))
			}
			paths.WriteString(fmt.Sprintf(`<polyline points="%s" />`, strings.Join(pts, " ")))
		}
		fmt.Fprintf(&b, `<g transform="rotate(%d %.0f %.0f)" stroke="%s" stroke-width="2.4" fill="none" stroke-linecap="round" stroke-linejoin="round" opacity="0.92">%s</g>`,
			rot, cx, cy, c1, paths.String())
	}
	b.WriteString(`</svg>`)
	return b.String()
}

// captchaGlyphs 描边验证码字体：10×14 网格坐标（y 向下），覆盖 captchaAlphabet 全部 30 字符。
var captchaGlyphs = map[rune][][][2]int{
	'2': {{{1, 3}, {3, 1}, {7, 1}, {9, 3}, {9, 6}, {1, 13}, {9, 13}}},
	'3': {{{1, 1}, {9, 1}, {5, 6}, {9, 8}, {9, 11}, {7, 13}, {3, 13}, {1, 11}}},
	'4': {{{7, 1}, {1, 9}, {10, 9}}, {{7, 1}, {7, 13}}},
	'5': {{{9, 1}, {2, 1}, {2, 6}, {7, 6}, {9, 8}, {9, 11}, {7, 13}, {2, 13}}},
	'6': {{{9, 2}, {7, 1}, {3, 1}, {1, 4}, {1, 10}, {3, 13}, {7, 13}, {9, 11}, {9, 9}, {7, 7}, {1, 7}}},
	'7': {{{1, 1}, {9, 1}, {4, 13}}},
	'8': {{{3, 1}, {7, 1}, {9, 3}, {9, 5}, {7, 7}, {3, 7}, {1, 5}, {1, 3}, {3, 1}},
		{{3, 7}, {1, 9}, {1, 11}, {3, 13}, {7, 13}, {9, 11}, {9, 9}, {7, 7}}},
	'9': {{{1, 12}, {3, 13}, {7, 13}, {9, 10}, {9, 4}, {7, 1}, {3, 1}, {1, 3}, {1, 6}, {3, 8}, {9, 8}}},
	'A': {{{1, 13}, {5, 1}, {9, 13}}, {{3, 9}, {7, 9}}},
	'B': {{{2, 1}, {2, 13}},
		{{2, 1}, {7, 1}, {9, 3}, {9, 5}, {7, 7}, {2, 7}},
		{{7, 7}, {9, 9}, {9, 11}, {7, 13}, {2, 13}}},
	'C': {{{9, 3}, {7, 1}, {3, 1}, {1, 3}, {1, 11}, {3, 13}, {7, 13}, {9, 11}}},
	'D': {{{2, 1}, {2, 13}}, {{2, 1}, {6, 1}, {9, 4}, {9, 10}, {6, 13}, {2, 13}}},
	'E': {{{9, 1}, {2, 1}, {2, 13}, {9, 13}}, {{2, 7}, {7, 7}}},
	'F': {{{9, 1}, {2, 1}, {2, 13}}, {{2, 7}, {7, 7}}},
	'G': {{{9, 3}, {7, 1}, {3, 1}, {1, 3}, {1, 11}, {3, 13}, {7, 13}, {9, 11}, {9, 8}, {5, 8}}},
	'H': {{{2, 1}, {2, 13}}, {{8, 1}, {8, 13}}, {{2, 7}, {8, 7}}},
	'J': {{{8, 1}, {8, 11}, {6, 13}, {3, 13}, {1, 11}}},
	'K': {{{2, 1}, {2, 13}}, {{8, 1}, {2, 7}, {8, 13}}},
	'M': {{{1, 13}, {1, 1}, {5, 8}, {9, 1}, {9, 13}}},
	'N': {{{2, 13}, {2, 1}, {8, 13}, {8, 1}}},
	'P': {{{2, 13}, {2, 1}, {7, 1}, {9, 3}, {9, 6}, {7, 8}, {2, 8}}},
	'Q': {{{8, 3}, {6, 1}, {3, 1}, {1, 3}, {1, 11}, {3, 13}, {6, 13}, {8, 11}, {8, 3}}, {{6, 9}, {9, 13}}},
	'R': {{{2, 13}, {2, 1}, {7, 1}, {9, 3}, {9, 6}, {7, 8}, {2, 8}}, {{5, 8}, {9, 13}}},
	'S': {{{9, 3}, {7, 1}, {3, 1}, {1, 3}, {1, 6}, {3, 8}, {7, 8}, {9, 10}, {9, 11}, {7, 13}, {3, 13}, {1, 11}}},
	'T': {{{1, 1}, {9, 1}}, {{5, 1}, {5, 13}}},
	'U': {{{2, 1}, {2, 11}, {4, 13}, {6, 13}, {8, 11}, {8, 1}}},
	'V': {{{1, 1}, {5, 13}, {9, 1}}},
	'W': {{{1, 1}, {3, 13}, {5, 6}, {7, 13}, {9, 1}}},
	'X': {{{1, 1}, {9, 13}}, {{9, 1}, {1, 13}}},
	'Y': {{{1, 1}, {5, 7}}, {{9, 1}, {5, 7}, {5, 13}}},
	'Z': {{{1, 1}, {9, 1}, {1, 13}, {9, 13}}},
}

func rnd(min, max int) int {
	n, _ := rand.Int(rand.Reader, big.NewInt(int64(max-min+1)))
	return min + int(n.Int64())
}

// loginCheck 校验账号密码（常数时间比较）。支持两种口令存储：
// ①明文 admin_password（默认，配置文件应 0600）；②admin_password_hash（推荐）：
// sha256("jiutouniao$v1:" + 密码) 十六进制，设置后 admin_password 不再参与校验。
func loginCheck(cfg *config.Config, user, pass string) bool {
	u := subtle.ConstantTimeCompare([]byte(user), []byte(cfg.AdminUser))
	var p int
	if h := strings.TrimSpace(cfg.AdminPasswordHash); h != "" {
		sum := sha256.Sum256([]byte("jiutouniao$v1:" + pass))
		p = subtle.ConstantTimeCompare([]byte(hex.EncodeToString(sum[:])), []byte(strings.ToLower(h)))
	} else {
		p = subtle.ConstantTimeCompare([]byte(pass), []byte(cfg.AdminPassword))
	}
	return u&p == 1
}
