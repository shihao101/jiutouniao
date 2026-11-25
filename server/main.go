// 九头鸟（鬼車）—— 通用型、实战型 AI 渗透测试智能体引擎。
//
// 架构：主控（真头）+ 9 阶段专家头 + 专项 A/B1/B2；Go 并发引擎 + OpenAI 兼容 LLM +
// 审批矩阵 + 全量证据链 + Web 控制台。仅用于书面授权的渗透测试场景。
package main

import (
	"encoding/json"
	"flag"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"jiutouniao/internal/config"
	"jiutouniao/internal/crypto"
	"jiutouniao/internal/engine"
	"jiutouniao/internal/events"
	"jiutouniao/internal/llm"
	"jiutouniao/internal/store"

	"jiutouniao/internal/tools"
	"jiutouniao/internal/version"
	"jiutouniao/internal/web"
)

func main() {
	cfgPath := flag.String("config", "config.json", "配置文件路径")
	flag.Parse()

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		log.Fatalf("加载配置: %v", err)
	}
	// v6.1.0（S1 修复方案⑨）：配置文件明文凭据迁移提示（不含值）——凭据请经环境变量
	// ADMIN_PASSWORD_HASH（推荐）/ADMIN_PASSWORD/AUTH_TOKEN/LLM_API_KEY 注入，配置文件留空。
	if cfg.HasInlineSecrets() {
		log.Printf("⚠ 配置文件仍含明文凭据字段（llm.api_key/auth_token/admin_password）——v6.1.0 起默认密码不再回填；请迁移至环境变量并清空配置文件后重启（本提示不显示具体值）")
	}

	st, err := store.Open(cfg.DataDir)
	if err != nil {
		log.Fatalf("打开存储: %v", err)
	}
	defer st.Close()

	var client llm.Client
	if cfg.LLM.Mock {
		log.Println("LLM: Mock 模式（演示用，不调用真实模型）")
		client = llm.NewMock()
	} else {
		protocol := strings.ToLower(strings.TrimSpace(cfg.LLM.Protocol))
		// v6.0.1 P1：LLM 时限/重试参数从 config 注入（原 900s 硬编码；实证网关静默时主循环冻结 15 分钟）
		llmOpts := llm.Options{
			RequestTimeoutSec: cfg.LLM.RequestTimeoutSec,
			MaxRetries:        cfg.LLM.MaxRetries,
			RetryBaseSec:      cfg.LLM.RetryBaseSec,
			RetryMaxSec:       cfg.LLM.RetryMaxSec,
			ResponseMaxBytes:  cfg.LLM.ResponseMaxBytes,
		}
		switch protocol {
		case "anthropic":
			log.Printf("LLM: Anthropic 协议 %s 模型=%s 请求预算=%ds", cfg.LLM.BaseURL, cfg.LLM.Model, cfg.LLM.RequestTimeoutSec)
			client = llm.NewAnthropicWithOptions(cfg.LLM.BaseURL, cfg.LLM.APIKey, llmOpts)
		case "", "openai":
			log.Printf("LLM: OpenAI 协议 %s 模型=%s 请求预算=%ds", cfg.LLM.BaseURL, cfg.LLM.Model, cfg.LLM.RequestTimeoutSec)
			client = llm.NewOpenAIWithOptions(cfg.LLM.BaseURL, cfg.LLM.APIKey, llmOpts)
		default:
			log.Fatalf("未知 LLM 协议: %s（支持 openai / anthropic）", protocol)
		}
	}

	guard := struct {
		Forbidden, HighRisk, MedRisk, ReadOnly, Sensitive []string
	}{cfg.Guard.Forbidden, cfg.Guard.HighRisk, cfg.Guard.MedRisk, cfg.Guard.ReadOnly, cfg.Guard.Sensitive}
	exec, err := tools.NewExecutor(cfg.DataDir, cfg.Engine.CommandTimeoutSec, cfg.Engine.MaxOutputBytes, guard)
	if err != nil {
		log.Fatalf("初始化执行器: %v", err)
	}
	// v2.6：同步/后台命令硬上限；v3.2.0 补 run_async 默认超时；v3.4.0 接线并发闸与屏障超时（原死配置）
	exec.SetCaps(cfg.Engine.CmdHardCapSec, cfg.Engine.AsyncHardCapSec, cfg.Engine.AsyncTimeoutSec)
	exec.SetConcurrency(cfg.Engine.MaxConcurrentExec)
	exec.SetIdleTimeout(cfg.Engine.CommandIdleTimeoutSec) // v4.6 K7：同步命令空闲护栏（默认 120s，-1 禁用）

	bus := events.NewBus()
	ap := engine.NewApprover(st, bus, cfg.AutoApprove)
	ap.SetWaitTimeout(cfg.Engine.BarrierTimeoutSec) // v3.4.0：人工审批/提问屏障超时（默认 1800，配置可覆盖）
	// v7.1.0：engine 审批档 L2 裁决配额（config.autonomy.engine_l2_*，默认 20/10min、200/项目）
	ap.SetEngineQuota(cfg.Autonomy.EngineL2Per10Min, cfg.Autonomy.EngineL2Total)
	// v6.1.0（S1 修复方案㉑）：资源目录由 config.paths 定位（相对路径以 config 文件所在目录
	// 为基准；空值=默认相对路径兼容旧部署）——启动时存在性检查 fail-fast，防止带病加载过期提示词。
	headsDir := engine.ResolveResourceDir(*cfgPath, cfg.Paths.HeadsDir, "heads")
	promptsDir := engine.ResolveResourceDir(*cfgPath, cfg.Paths.PromptsDir, "prompts")
	skillsDir := engine.ResolveResourceDir(*cfgPath, cfg.Paths.SkillsDir, "skills")
	for _, d := range map[string]string{"heads": headsDir, "prompts": promptsDir, "skills": skillsDir} {
		if fi, err := os.Stat(d); err != nil || !fi.IsDir() {
			log.Fatalf("资源目录不存在或不可读（%s=%s）——检查 config.paths 配置或恢复默认目录布局", d, d)
		}
	}
	log.Printf("资源目录: heads=%s prompts=%s skills=%s", headsDir, promptsDir, skillsDir)
	orch, err := engine.NewOrchestrator(cfg, st, client, exec, ap, bus, headsDir, promptsDir, skillsDir)
	if err != nil {
		log.Fatalf("初始化编排器: %v", err)
	}

	cryptKey, err := crypto.LoadOrCreateKey(filepath.Join(cfg.DataDir, "secret.key"))
	if err != nil {
		log.Fatalf("初始化加密密钥: %v", err)
	}

	// 启动恢复已保存的设置（多模型 / 测绘 Key 环境注入 / 单价）
	if raw, ok := st.GetSetting("pricing"); ok {
		var pr struct {
			In, Out float64
		}
		if json.Unmarshal(raw, &pr) == nil {
			cfg.PricePer1MInput, cfg.PricePer1MOutput = pr.In, pr.Out
		}
	}
	if raw, ok := st.GetSetting("models"); ok && len(raw) > 4 {
		var ms []struct {
			ID        string `json:"id"`
			Label     string `json:"label"`
			Protocol  string `json:"protocol"`
			BaseURL   string `json:"base_url"`
			Model     string `json:"model"`
			APIKeyEnc string `json:"api_key_enc"`
		}
		if json.Unmarshal(raw, &ms) == nil && len(ms) > 0 {
			clients := map[string]llm.Client{}
			names := map[string]string{}
			for _, m := range ms {
				key, _ := crypto.Decrypt(cryptKey, m.APIKeyEnc)
				if strings.EqualFold(m.Protocol, "anthropic") {
					clients[m.ID] = llm.NewAnthropic(m.BaseURL, key)
				} else {
					clients[m.ID] = llm.NewOpenAI(m.BaseURL, key)
				}
				names[m.ID] = m.Model
			}
			def := ""
			if d, ok := st.GetSetting("default_model"); ok {
				def = string(d)
			}
			orch.SetModels(clients, names, def)
			log.Printf("已恢复多模型配置: %d 个，默认=%s", len(ms), def)
		}
	} else if raw, ok := st.GetSetting("llm"); ok {
		// 旧版单模型设置迁移为默认模型
		var ls struct {
			Protocol  string `json:"protocol"`
			BaseURL   string `json:"base_url"`
			Model     string `json:"model"`
			APIKeyEnc string `json:"api_key_enc"`
		}
		if json.Unmarshal(raw, &ls) == nil && ls.BaseURL != "" {
			key, _ := crypto.Decrypt(cryptKey, ls.APIKeyEnc)
			var client llm.Client
			if strings.EqualFold(ls.Protocol, "anthropic") {
				client = llm.NewAnthropic(ls.BaseURL, key)
			} else {
				client = llm.NewOpenAI(ls.BaseURL, key)
			}
			orch.SetLLMClient(client)
			log.Printf("已恢复 LLM 设置(单模型): %s %s", ls.Protocol, ls.Model)
		}
	}
	if raw, ok := st.GetSetting("recon"); ok {
		var rs struct {
			ShodanKeyEnc string `json:"shodan_enc"`
			FofaEmail    string `json:"fofa_email"`
			FofaKeyEnc   string `json:"fofa_key_enc"`
			QuakeKeyEnc  string `json:"quake_enc"`
			ZoomEyeEnc   string `json:"zoomeye_enc"`
		}
		if json.Unmarshal(raw, &rs) == nil {
			env := map[string]string{}
			if k, e := crypto.Decrypt(cryptKey, rs.ShodanKeyEnc); e == nil && k != "" {
				env["SHODAN_API_KEY"] = k
			}
			if rs.FofaEmail != "" {
				env["FOFA_EMAIL"] = rs.FofaEmail
			}
			if k, e := crypto.Decrypt(cryptKey, rs.FofaKeyEnc); e == nil && k != "" {
				env["FOFA_KEY"] = k
			}
			if k, e := crypto.Decrypt(cryptKey, rs.QuakeKeyEnc); e == nil && k != "" {
				env["QUAKE_KEY"] = k
			}
			if k, e := crypto.Decrypt(cryptKey, rs.ZoomEyeEnc); e == nil && k != "" {
				env["ZOOMEYE_KEY"] = k
			}
			exec.SetExtraEnv(env)
			log.Printf("已恢复空间测绘 Key: %d 项", len(env))
		}
	}

	mux := http.NewServeMux()
	ws := web.New(orch, st, bus, cfg, cfg.WebDir, cryptKey)
	ws.Register(mux)

	// v2.3.4 启动恢复：进程重启会杀死在跑的流水线协程，DB 中遗留的 running 状态
	// 变成僵尸（实测：升级重建容器后项目永卡「运行中」且无任何活动）。启动时统一
	// 置为 paused 并留痕，用户可手动重跑断点续跑。
	if ps, err := st.ListProjects(); err == nil {
		n := 0
		var recovered []string
		for _, p := range ps {
			if p.Status != "running" {
				continue
			}
			p.Status = "paused"
			if p.CurrentStage == "" {
				for sid, st := range p.StageStates {
					if st != nil && st.Status == "running" {
						p.CurrentStage = sid
						break
					}
				}
			}
			_ = st.SaveProject(p)
			orch.LogStartupRecovery(p)
			n++
			recovered = append(recovered, p.ID)
		}
		if n > 0 {
			log.Printf("启动恢复：%d 个因进程重启中断的项目已置为 paused（可在阶段流水线手动重跑续测）", n)
		}
		// v3.7.7 重启自愈：auto_resume（默认开）——延迟 30s（等 Web/WS 就绪），
		// 对仍处于 paused 的被中断项目自动断点续跑；部署/重启不再丢任务。
		if cfg.Engine.AutoResume != nil && *cfg.Engine.AutoResume && len(recovered) > 0 {
			go func(ids []string) {
				time.Sleep(30 * time.Second)
				for _, id := range ids {
					p, err := st.GetProject(id)
					if err != nil || p.Status != "paused" {
						continue // 期间已被人工处置/熔断则跳过
					}
					if err := orch.StartProject(id); err != nil {
						log.Printf("自动续跑失败 %s: %v", id, err)
						continue
					}
					log.Printf("已自动续跑 %s（auto_resume，断点续测）", id)
				}
			}(recovered)
		}
	}

	log.Printf("Web 认证：账号 %s + 验证码登录（API 直连令牌=%t）", cfg.AdminUser, cfg.AuthToken != "")
	log.Printf("九头鸟（鬼車）v%s 已就绪：http://localhost%s", version.App, cfg.Listen)
	log.Fatal(http.ListenAndServe(cfg.Listen, ws.Middleware(mux)))
}