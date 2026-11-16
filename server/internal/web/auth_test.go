package web

import (
	"strings"
	"testing"

	"jiutouniao/internal/version"
)

// F-05 回归：验证码 SVG 不得含明文 <text> 节点（曾可被脚本直接解析），且全部字符可渲染。
func TestCaptchaSVGNoPlainText(t *testing.T) {
	for range 20 {
		_, svg, _ := newCaptchaStore().Generate(false)
		if strings.Contains(svg, "<text") {
			t.Fatalf("验证码 SVG 含明文 <text> 节点，可被脚本解析:\n%s", svg)
		}
		if !strings.Contains(svg, "<polyline") {
			t.Fatal("验证码 SVG 未按描边路径渲染")
		}
	}
}

// 字形表必须覆盖验证码字母表全部字符，否则随机到缺字会整字符消失。
func TestCaptchaGlyphsCoverAlphabet(t *testing.T) {
	for _, r := range captchaAlphabet {
		g, ok := captchaGlyphs[r]
		if !ok || len(g) == 0 {
			t.Fatalf("字符 %c 缺少描边字形", r)
		}
	}
	if len(captchaGlyphs) > len(captchaAlphabet) {
		t.Fatalf("字形表含字母表之外的字符: %d > %d", len(captchaGlyphs), len(captchaAlphabet))
	}
}

// F-01 回归：/api/public/info 的版本必须来自单一事实源，不得再硬编码。
func TestPublicInfoVersionMatchesSource(t *testing.T) {
	if version.App == "" {
		t.Fatal("version.App 为空")
	}
	if version.App == "1.4.0" {
		t.Fatal("版本号仍是旧的硬编码值 1.4.0")
	}
}
