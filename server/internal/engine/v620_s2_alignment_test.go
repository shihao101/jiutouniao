package engine

// v6.2.0 S2 修复方案③④⑤⑥回归：技能层承载、提示词固定路径、S2-10 边界下沉、扇出提示的
// 仓库级对齐检查（与 eval/gates/file_layer_check.py 锁互补——引擎测试在源码树运行时校验）。

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func v620RepoFile(t *testing.T, rel string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", rel))
	if err != nil {
		t.Skipf("仓库文件不可达（非源码树运行）: %v", err)
	}
	return string(raw)
}

// S2-④：提示词固定路径与硬判据落位。
func TestV620S2PromptFixedPaths(t *testing.T) {
	s2 := v620RepoFile(t, "heads/s2.md")
	for _, kw := range []string{
		"deliverables/s2-已知漏洞候选清单.md", "deliverables/s2-泄露与情报报告.md",
		"连续两类探针", "evidence/s1-subs-final.txt", "read_file 复读自校验",
	} {
		if !strings.Contains(s2, kw) {
			t.Errorf("heads/s2.md 缺少 %q", kw)
		}
	}
	s3 := v620RepoFile(t, "heads/s3.md")
	if !strings.Contains(s3, "deliverables/s2-已知漏洞候选清单.md") {
		t.Errorf("heads/s3.md S3-6 未固定读 s2 已知漏洞候选清单路径")
	}
}

// S2-③：路由行承诺的被动侦察动作必须在被指技能正文可落地（内容级断链防回退），
// 配合列不得混入非技能 ID。
func TestV620RouterContentLevelLinks(t *testing.T) {
	router := v620RepoFile(t, "skills/00-router.md")
	rp := v620RepoFile(t, "skills/recon-playbook.md")
	oli := v620RepoFile(t, "skills/osint-leak-intel.md")
	for _, kw := range []string{"whois", "DNS 全谱八类", "whois.cymru.com", "被动 DNS", "s1-subs-final.txt"} {
		if !strings.Contains(rp, kw) {
			t.Errorf("recon-playbook 缺少路由承诺的 %q（L118 内容级断链）", kw)
		}
	}
	for _, kw := range []string{"filetype:", "SHODAN", "组织架构与邮箱格式"} {
		if !strings.Contains(oli, kw) {
			t.Errorf("osint-leak-intel 缺少 %q（S2-2 子项承载）", kw)
		}
	}
	if strings.Contains(router, "| exit-pool / rate-limit-playbook") {
		t.Errorf("00-router 代理行配合列仍把工具脚本 exit-pool 当技能 ID")
	}
}

// S2-⑤：S2-10 引用组逐技能 manifest stage_fit 含 s2；含主动动作的技能必须有「阶段边界（S2）」节。
func TestV620S210GroupStageFitAndBoundary(t *testing.T) {
	raw := v620RepoFile(t, "skills/manifest.json")
	var m struct {
		Skills []struct {
			ID       string   `json:"id"`
			StageFit []string `json:"stage_fit"`
		} `json:"skills"`
	}
	if err := json.Unmarshal([]byte(raw), &m); err != nil {
		t.Fatal(err)
	}
	fit := map[string][]string{}
	for _, s := range m.Skills {
		fit[s.ID] = s.StageFit
	}
	for _, id := range []string{"request-smuggling", "jwt-crypto", "auth-flow-deep", "instance-diff"} {
		hasS2 := false
		for _, st := range fit[id] {
			if st == "s2" {
				hasS2 = true
			}
		}
		if !hasS2 {
			t.Errorf("S2-10 引用组技能 %s 的 manifest stage_fit 不含 s2（检索加权失灵）: %v", id, fit[id])
		}
	}
	for _, id := range []string{"request-smuggling", "instance-diff", "auth-flow-deep"} {
		body := v620RepoFile(t, "skills/"+id+".md")
		if !strings.Contains(body, "阶段边界（S2") {
			t.Errorf("技能 %s 缺「阶段边界（S2）」节——00-router「以技能库为准」口径下 S2 只登记不执行约束未下沉", id)
		}
	}
}

// S2-⑥ 扇出提示回归已按方案迁移至 multitarget_test.go（TestV620S2FanoutHintMultitarget）。
