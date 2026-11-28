package engine

import (
	"fmt"
	"jiutouniao/internal/store"
	"strings"
)

// spec_gate.go v6.6.0（SP-②，修复方案_三大专项补全_v6.6.0_20261123.md）：
// 专项确定性收口门——specA/specB1/specB2 是流水线中此前唯一没有阶段专属机械校验的成员
//（S1/S2/S3 各有 closureIssues、S4/S5 有分项门簇、S7 VT 清点、S8 报告契约；反思 PASS 无条件
// 硬校验名单也不含 spec），专项收口被强制仅剩「任意新增文件」。
//
// 门设计纪律（与 C27/M2「只查留痕不查内容」防诱导原则同构）：
//  1. 只拦「无登记/无产出/无留痕」，不推断测试质量——条目内容质量由反思门 spec 专项核查节
//     （expert.go，v6.6.0 SP-⑧）承接；
//  2. 豁免分支：资产台账无适用类型资产（specA 无 AI/LLM 类、specB1 无 APP 类、specB2 无
//     小程序类）→ 不拦截（前提不成立路径，提示级留痕），与 spec 头早退分支闭环；
//  3. 拦截文案给出确切缺失项（与 S1 门「空工作区也返回确切缺失项」同款可验收形态）。
//
// guard：enforce_spec_closure（缺省 true，显式 false 回退——回滚是事故手段，须记录配置变更）。

// isSpecStage 专项阶段判定（SP-①②③⑥ 多处复用同一名单，单一事实源）。
func isSpecStage(stageID string) bool {
	return stageID == "specA" || stageID == "specB1" || stageID == "specB2"
}

// specHasApplicableAssets 判定项目资产台账中是否存在该专项适用类型的资产（豁免分支依据，
// 复用 record_asset 类型化台账——与 assetTypeRequiredFields 的类型口径同源）：
// specA ← type 含 ai/llm/agent/模型（hypothesis-matrix「AI:specA」承接口径同源）；
// specB1 ← type 含 app；specB2 ← type 含 小程序/miniapp。
func (o *Orchestrator) specHasApplicableAssets(p *store.Project, stageID string) bool {
	assets, err := o.store.ListAssets(p.ID)
	if err != nil {
		return true // 台账不可读时不豁免（fail-closed：宁可走正常门也不静默放行）
	}
	for _, a := range assets {
		t := strings.ToLower(a.Type)
		switch stageID {
		case "specA":
			if strings.Contains(t, "ai") || strings.Contains(t, "llm") ||
				strings.Contains(t, "agent") || strings.Contains(a.Type, "模型") {
				return true
			}
		case "specB1":
			// v6.6.0 第四遍（历史回放 某历史任务 实证）：仅 "app" 子串会把「Android应用/
			// Android APK/iOS IPA」等非标准类型误豁免——APP 专项适用面按移动生态词根放宽。
			if strings.Contains(t, "app") || strings.Contains(t, "android") || strings.Contains(t, "ios") ||
				strings.Contains(t, "apk") || strings.Contains(t, "ipa") || strings.Contains(t, "移动") {
				return true
			}
		case "specB2":
			if strings.Contains(a.Type, "小程序") || strings.Contains(t, "miniapp") ||
				strings.Contains(t, "mini-app") {
				return true
			}
		}
	}
	return false
}

// specClosureCorpus 前置契约/交付物留痕语料：时间线（Event+Detail）+ 交付物全文。
// 只查留痕存在，不核验内容语义（M2 防诱导原则）。
func (o *Orchestrator) specClosureCorpus(p *store.Project) string {
	var b strings.Builder
	if tl, terr := o.store.ListTimeline(p.ID); terr == nil {
		for _, ev := range tl {
			b.WriteString(ev.Event)
			b.WriteString("\n")
			b.WriteString(ev.Detail)
			b.WriteString("\n")
		}
	}
	b.WriteString(o.deliverablesText(p.ID))
	return b.String()
}

// specClosureIssues 专项确定性收口门（SP-②）。返回拦截项清单；豁免（无适用资产）返回 nil
// 并留提示级日志。调用方：complete_stage 前置门（与 s1/s2/s3 同位）+ deterministicGate spec 分支
// （反思 PASS/三振降级/auto_close 代收口三路径共用）。
func (o *Orchestrator) specClosureIssues(p *store.Project, stageID string) []string {
	// 豁免分支：台账无适用资产 → 前提不成立路径（不拦，提示级留痕——与 SP-⑩ 早退分支闭环）
	if !o.specHasApplicableAssets(p, stageID) {
		o.log(p, stageID, fmt.Sprintf("💡 %s 豁免提示：资产台账无本专项适用类型资产（前提不成立路径）——交付物须写明豁免依据（核验台账与授权范围），不拦截收口", stageID))
		return nil
	}
	var issues []string
	corpus := o.specClosureCorpus(p)
	nc := normCovText(corpus)

	// ① 前置契约登记核验（各头「前置契约」节明文强制的第一步；只查留痕存在）
	for _, ele := range specContractElements(stageID) {
		hit := false
		for _, kw := range ele.keywords {
			if strings.Contains(nc, normCovText(kw)) {
				hit = true
				break
			}
		}
		if !hit {
			issues = append(issues, fmt.Sprintf("%s 前置契约未登记：%s——按头文件前置契约节登记（时间线/交付物任一留痕即可，缺失前置时静态发现保持待动态验证）", stageID, ele.label))
		}
	}

	// ② 核心交付物存在性（头文件点名名目，文件名或正文任一命中即算存在）
	named := specNamedDeliverables(stageID)
	deliv := o.deliverablesText(p.ID)
	nd := normCovText(deliv)
	hit := false
	for _, kw := range named.searchKeywords {
		if strings.Contains(nd, normCovText(kw)) {
			hit = true
			break
		}
	}
	if !hit {
		issues = append(issues, fmt.Sprintf("%s 缺少核心交付物：%s（任一其一即可）——按头文件步骤产出写入 deliverables/", stageID, named.displayName))
	}

	// ③ 条目三态清单存在性（软门：只拦「清单缺失」，三态完整性与逐条判据由反思门核查节抽查）
	if !strings.Contains(nd, normCovText("专项条目清单")) && !strings.Contains(nd, normCovText("条目清单")) {
		issues = append(issues, fmt.Sprintf("%s 收口交付物须含《专项条目清单》——本专项条目逐条三态：已测（update_coverage 引用）/ 不适用（依据）/ 未测（原因+移交去向）；引擎本门只查清单存在，三态完整性与逐条判据由反思门按清单抽查", stageID))
	}
	// v7.8.0 用户决策：子包完整性不强求——核验逻辑已撤销（交付完整性由客户自行决定）
	return issues
}

// specContractElement 前置契约登记件（label=人读名目，keywords=任一命中即算已登记）。
type specContractElement struct {
	label    string
	keywords []string
}

// specContractElements 各专项前置契约登记件清单（与三头「前置契约」节逐条对应）：
// specA——Canary/合成标记数据方案（production_safe 验证器依赖）；specB1——测试包来源/设备登记/
// 测试账号三要素；specB2——包来源/测试身份状态两要素。
func specContractElements(stageID string) []specContractElement {
	switch stageID {
	case "specA":
		return []specContractElement{
			{"Canary/合成标记数据方案（验证器依赖）", []string{"canary", "金丝雀", "合成标记", "合成数据", "合成 RAG", "对照实验", "mock 工具", "mock邮件", "mock 邮件", "隔离测试租户", "合成 Canary"}},
		}
	case "specB1":
		return []specContractElement{
			{"测试包来源（客户提供/合法测试包）", []string{"包来源", "测试包", "合法测试包", "安装包来源", "apk 来源", "ipa 来源"}},
			{"设备登记（测试设备所有权/越狱 root 状态）", []string{"设备登记", "设备所有权", "测试设备", "root", "越狱", "adb devices", "frida"}},
			{"测试账号/测试证书与信任配置", []string{"测试账号", "测试身份", "测试证书", "信任配置"}},
		}
	case "specB2":
		return []specContractElement{
			{"小程序包来源/解包产物登记", []string{"包来源", "解包来源", "解包产物", "wxapkg"}},
			{"测试身份状态（测试账号/测试租户）", []string{"测试身份", "测试账号", "测试租户"}},
		}
	}
	return nil
}

// specNamedDeliverables 各专项核心交付物（displayName=头文件点名名目；searchKeywords=存在性
// 检索词，文件名或正文任一命中即过）。
func specNamedDeliverables(stageID string) struct {
	displayName    string
	searchKeywords []string
} {
	switch stageID {
	case "specA":
		return struct {
			displayName    string
			searchKeywords []string
		}{"《AI 系统架构图》或《基线响应集》", []string{"架构图", "基线响应", "模型指纹", "组件与信任边界", "信任边界清单"}}
	case "specB1":
		return struct {
			displayName    string
			searchKeywords []string
		}{"《假设队列》或动态验证记录", []string{"假设队列", "动态验证", "反编译", "应用画像", "静态审计"}}
	case "specB2":
		return struct {
			displayName    string
			searchKeywords []string
		}{"《小程序结构与页面清单》或接口测试记录", []string{"页面清单", "结构清单", "小程序结构", "接口测试", "云函数"}}
	}
	return struct {
		displayName    string
		searchKeywords []string
	}{}
}
