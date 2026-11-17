# 功能与部署详解

> 本文档承载 README 未展开的详细参考材料。快速上手请看 [README](../README.md)。

## Web 控制台

**登录**：账号 + 密码 + SVG 图形验证码（会话制 24h；验证码以描边路径渲染，标记中无明文字符）。默认 `admin / jiutou@2026`（`config.json` 或环境变量 `ADMIN_USER/ADMIN_PASSWORD`，**部署后必改**）；API 直连另支持 `auth_token`。

**视觉**：专业安全控制台风格（紧凑侧边导航 + 顶栏项目切换），支持**明暗双主题**（右下角 🌙/☀️ 切换，持久化）。参考 PentAGI 工作区布局与国内安全控制台规范（信息密度、克制用色）。

**功能板块**：

| 导航/入口 | 说明 |
|---|---|
| 📊 仪表盘 | 进度/发现/资产/覆盖/Token 成本统计 + 等级分布与覆盖图 + 最近活动 |
| ◉ **工作台** | 左：阶段流水线（含产出文件数/手动重跑）；中：**执行流·对话工作台**（统一消息流 + 对话输入）；右页签：**审批/提问、子任务、工具调用、覆盖度、交付物** |
| ＋ 新建项目 | 授权确认必勾 + 范围/ROE/审批策略/模型/专项 |
| ⚔ 漏洞 / ◍ 资产 / ⏱ 时间线 | 记忆库（证据链并入漏洞页展开查看） |
| 📖 技能库 / 📜 提示词 / 📄 报告 / ⚙ 设置 / 🕘 更新记录 | 攻击剧本、头提示词全文、report.md 预览、多模型与测绘 Key 直配、版本历史 |

## 防幻觉机制（实体文件产出与承接）

- **强制产出**：每个阶段收口时引擎校验工作区必须有本阶段新增文件，否则拒绝收口并提示补写（`deliverables/<阶段>-<名称>.md`，报告为 `report.md`）；
- **文件承接**：下一阶段开工上下文自动携带工作区文件清单，头用 `read_file` 索取上一阶段产出，以文件内容为事实来源；`list_files` 工具可随时列出；
- **同步落盘**：发现/时间线除入库外同步写入交付物文件，保证文件自洽，防流程中断后上下文丢失。

## 移植模块（源自对 46 个开源安全 Agent 的深研）

| 模块 | 来源 | 用法 |
|---|---|---|
| **覆盖度账本** | strix（outcome 枚举/唯一键/证据强制）+ PentesterFlow（endpoint×param×vulnClass 三元组原地更新） | 头工具 `update_coverage`；UI「覆盖度」Tab 看矩阵；报告含「安全向量/盲区」两章 |
| **技能库** | strix（运行时 load_skill 双通道）+ PentesterFlow（SKILL.md 约定+关键词路由） | `skills/` 目录 109 个中文攻击剧本；头按需 `load_skill` 注入，不撑爆上下文 |
| **hexstrike 工具桥** | hexstrike-ai（`/health`、`/api/command` 原样兼容） | 配置 `hexstrike_url` 后头工具 `hexstrike_command` 直调远端 150+ 安全工具（同样过审批矩阵） |
| **Token/成本账本** | deadend-cli（按 agent 分账）+ strix（双账）+ BoxPwnr（stats） | 按阶段分账；UI 实时显示 token 与估算成本；`max_project_tokens` 超限自动熔断 |
| **记忆检索** | pentagi/VulnBot RAG 的轻量版 | 头工具 `search_memory` 关键词扫描发现/资产/时间线 |
| **SARIF/JSON 导出** | strix/shannon | 结项自动产出 `findings.json` + `findings.sarif 2.1.0`，可直接导入安全平台 |
| **断点续跑** | seclab-taskflow（ResultStore 快照思想） | 流水线跳过 done 阶段；`/stage/{id}/run` 手动重跑任意阶段 |
| **Web 访问令牌** | 外网暴露安全护栏 | `auth_token` 配置后全站 Basic/Bearer/?token= 认证 |
| **确定性循环检测** | ctf-agent（签名窗口 warn@3/break@5）+ cai（卡壳续跑） | 归一化签名 12 轮滑窗计数，同签名第 3 次注入换路预警、第 5 次自动召导师评审——「换编号逐条枚举」式空转引擎级拦截 |
| **能力原语凑链** | CyberStrikeAI（能力原语 + 状态空间搜索） | 技能 capability-primitive-search：低危发现标注 READ/WRITE/EXEC/SSRF/SQLI/AUTHZ/CRED 原语，按 RCE 六等式凑链，正向扩展/反向回推找缺口 |
| **输出治理三层** | strix（溢出落盘）+ pentagi/HackSynth（窗口压缩/摘要即状态） | >16KB 溢出落盘 .tool-output/ + head/tail 智截断 + 消息链预算压缩（确定性零 LLM 成本） |
| **项目黑板** | CyberStrikeAI（pentest-blackboard） | upsert_fact 幂等事实账本（confirmed/tentative/deprecated 三态，负结果落库防重复试错），黑板 Top25 随上下文包自动注入 |
| **战利品库** | BoxPwnr（flag 库）+ EVA（verification 状态） | record_loot 掩码登记凭据/票据/flag（不存明文），S5/S6 横向复用第一入口 |
| **持久交互会话** | strix/CAI/BoxPwnr（PTY 会话） | shell_open/write/read/close：stdin 管道+增量读+进程组清理，mysql/ssh/nc 类多轮交互不再拆轮次 |
| **确定性质量门** | T3MP3ST（REFUTE 引证校验） | 反思门 LLM 不可用时引擎硬校验兜底：高危确证必须引用 EV-/evidence/ 证据，覆盖矩阵非空 |
| **攻击路径缝合器** | communitytools（attack-path-stitcher） | 结项自动把黑板 facts（links=边）+ 战利品（凭据复用边）缝合成 attack-graph.dot/md，单点发现升维影响链 |
| **错误自愈** | hexstrike-ai（错误分类重试） | run_command 失败按特征给处置建议（超时→后台化/403→WAF 分型/DNS→核范围），stderr 独立捕获 |
| **组织级教训库** | BoxPwnr（失败后分析注入） | record_lesson 跨项目脱敏经验（引擎强校验去标识），最近 8 条随上下文注入 |
| **后台任务持久化** | 断点续跑强化 | run_async 元数据落盘 sidecar，引擎重启后 poll_async 恢复状态与日志尾部 |
| **技能进化评测环** | 评测体系与平台分离：平台仅含通用判分器 `scripts/eval_run.py`；靶标/埋点清单/对抗模拟器在外部评测扩展包（`JTN_EVALPACK_PATH` 加载）——部署包/镜像零靶场信息 |
| **验证码本地 OCR** | 实证失败模式 | browser_login --captcha-ocr（可选档）：ddddocr 识别自动填入，失败回退人工读码，默认关闭 |
| **阶段内并行扇出** | strix agents_graph / CAI | spawn_subagent/poll_subagents：独立测试单元派给 ≤3 路受控子代理并行（独立消息链、共享黑板/审批），收口前强制收结果 |
| **人工屏障超时** | 实证失败模式修正 | barrier_timeout_sec（默认 30min）：审批/提问不再无限挂起流水线，超时工单标 expired |

## 评测环（make eval）

```bash
make eval   # 起本地靶场(127.0.0.1:18080) → 跑完整项目 → 按预期清单判分 → eval/results/ 产出报告
```

前置：容器就绪 + config.json 配置真实 LLM 与 auth_token + 外部评测扩展包（JTN_EVALPACK_PATH——靶标/埋点/预期清单不在平台内）。判分三指标：自述面召回（覆盖下限）+ 清单外盲挖（隐藏项命中=0day 能力度量）+ 匿名高危召回（无凭证高危能力度量）；未命中清单是技能库迭代的直接输入。

## 模型接入（OpenAI / Anthropic 双协议）

> **切换边界**：多模型自动切换仅适用于**供应商拒绝类错误**（HTTP 4xx / 内容风控）——网络超时/连接失败走同模型重试，不切换模型。接管模型锁定至项目结束并全量留痕。

`config.json` → `llm.protocol`：

```json
{
  "protocol": "openai",
  "base_url": "https://your-endpoint/v1",
  "api_key": "sk-xxx",
  "model": "your-model",
  "max_tokens": 8192,
  "mock": false
}
```

- **OpenAI 协议**：`POST {base_url}/chat/completions`，Bearer 鉴权；tool_calls 自动按严格嵌套格式打包/解包（兼容火山方舟等严格校验网关）
- **Anthropic 协议**：`POST {base_url}/v1/messages`，x-api-key + anthropic-version 头；system 抽离、tool_use/tool_result 块自动转换
- 内置工程化保障：**请求级重试**（TLS 抖动/5xx/429 指数退避）、IPv4 优先连接、LLM 错误落盘
- 环境变量覆盖：`LLM_PROTOCOL / LLM_BASE_URL / LLM_API_KEY / LLM_MODEL`
- v5.4.0 起 Web 设置页支持**多模型注册表**：23 个服务商预设、模型清单实时拉取（兼容 openai/anthropic 两种列举协议）、连通性实测、创建项目页按项目选模型

## Docker 部署完整说明

**运行时基础系统为 Kali GNU/Linux Rolling**：默认全量底座开箱即得
nmap / sqlmap / nikto / hydra / gobuster / john / hashcat / masscan / whatweb / dirb / wfuzz /
ffuf / subfinder / httpx / nuclei / amass / dig / whois 等全链工具；缺什么装什么——
Kali 仓库数千款渗透工具均可经 `install_tool`（apt 官方源）或 `run_command` 的 `apt-get install` 现场安装。

```bash
# 构建 + 启动（数据持久化在宿主机 ./projects，heads/skills/prompts 卷挂载可热编辑）
docker compose up -d --build

# 验证
docker compose ps
curl "http://localhost:8787/api/projects?token=<auth_token>"

# 环境变量覆盖 config.json（无需改文件）：.env 或直接导出
#   AUTH_TOKEN / LLM_MOCK / LLM_BASE_URL / LLM_API_KEY / LLM_MODEL /
#   HEXSTRIKE_URL / MAX_PROJECT_TOKENS / PRICE_IN / PRICE_OUT /
#   TOOL_PROXY（工具安装代理，默认空=直连；受限网络时按需注入）
AUTH_TOKEN=你的令牌 LLM_MOCK=false LLM_BASE_URL=https://api.x.com/v1 \
LLM_API_KEY=sk-xxx LLM_MODEL=gpt-4o docker compose up -d

# 外网访问（可选）：自动获得 trycloudflare.com 公网地址
docker compose --profile tunnel up -d
docker compose logs tunnel        # 查看公网 URL（带 auth_token 访问）

# hexstrike-ai 工具网关（可选，需本地有 hexstrike-ai 源码）
docker compose --profile hexstrike up -d
# 然后在 .env 设置 HEXSTRIKE_URL=http://hexstrike:9023 后重启
```

### 代理接入（代理仅限工具下载与容器构建，其余流量一律直连）

| 环节 | 变量 | 默认值 | 说明 |
|---|---|---|---|
| 构建（npm/go/apt） | `HTTP_PROXY` / `HTTPS_PROXY`（build-arg） | 空=直连 | 国内源已内置（goproxy.cn/npmmirror/apt 多镜像，直连更快）；受限网络时经 `docker-compose.override.yml` 或 build-arg 注入 |
| 运行时工具安装（install_tool 的 apt/pip/git、智能体外网下载） | `TOOL_PROXY`（容器环境） | 空=直连 | 仅作用于下载类命令；测试环境经 `docker-compose.override.yml` 注入 |
| LLM 出口 | `LLM_PROXY`（容器环境） | 空=直连 | 默认直连；如需经代理：`LLM_PROXY=http://… docker compose up -d` |
| 靶机测试流量 | — | 引擎级强制直连 | 执行器剥离子命令的标准代理环境变量（TOOL_PROXY 保留，智能体可显式 `env http_proxy=$TOOL_PROXY <命令>` 引用），与 LLM/工具安装路径彻底解耦 |

> 部署包纪律：`config.json`（密钥/口令）、`projects/`（运行数据）、`docker-compose.override.yml`（环境专属地址）等一律不进包——`make pack` 自动排除，详见 scripts/pack.py。

底座切换：`RUNTIME_BASE=kalilinux/kali-rolling:latest docker compose build` 换官方最小底座
（约 130MB，构建期从 kali-rolling 官方源装齐工具，需构建期网络）。

安全说明：容器以 root 运行（nmap SYN 扫描等需要特权），建议仅在内网/受控环境部署；
公网暴露务必设置强 `auth_token`，并尽量走隧道 + HTTPS。

## 新机部署 Quickstart（部署包收包方视角）

从 `dist/jiutouniao_v<版本>_部署包.zip`（`make pack` 产物）在一台全新 Linux（amd64）机器上部署：

```bash
# 0. 前置：Docker Engine 24+ 与 compose v2 插件；磁盘 ≥60GB 空闲（镜像 ~27GB，构建期峰值更高）；
#    联网（拉底座镜像 + github clone×3 + go install×4；受限网络见上文「代理」）；bash/unzip/python3
# 1. 解压（zip 含 UTF-8 中文名与符号链接——用 unzip 或 python3 -m zipfile，勿用不保留 symlink 的工具）
unzip jiutouniao_v<版本>_部署包.zip -d jiutouniao && cd jiutouniao
# 2. 创建配置（【致命步骤】包内无 config.json，缺失则容器启动即崩溃循环）：
cp config.example.json config.json
#    必填：llm.api_key / llm.base_url / llm.model（OpenAI 兼容或 Anthropic 协议均可）；
#    必改：admin_password（默认 admin/jiutou@2026 为公开文档化默认值）；auth_token 会话令牌
# 3. 构建并启动（首次构建 15-40 分钟：拉 24GB 底座 + 编译 + 语料克隆，失败重试 3 次内自动恢复）
docker compose up -d --build
# 4. 验收：curl http://127.0.0.1:8787/api/public/info 应返回 {"version":"<版本>"...}
#    浏览器打开 http://127.0.0.1:8787 → admin + 你设置的密码 → 新建项目（目标/授权范围/ROE）→ ▶ 启动
# 5. 升级：替换 heads/ skills/ prompts/ 三个目录即热生效（bind-mount）；引擎/工具/web 更新需重建镜像；
#    升级前备份 projects/（含记忆库与 secret.key）
```

**⚠ 安全提示**：8787 端口默认绑定全网卡（`0.0.0.0`，兼容远程访问场景）且存在公开文档化的默认口令——**部署后必改 `admin_password`**；加固方式：`.env` 里设 `JT_WEB_BIND=127.0.0.1`（仅本机）或前置反代+TLS；公网暴露（tunnel profile）仅限测试。资源限制/healthcheck 默认未配置，生产部署建议自行加 `mem_limit/cpus`。

**已知边界**：底座 `vxcontrol/kali-linux` 与 wheelhouse（cp314 wheel）、`/opt/venv` 路径强耦合——更换底座需同步重建 wheelhouse；`RUNTIME_BASE` 切最小底座当前不可用（终检强制 chromium/interactsh-client，未适配）。

**供应链已锁定**：三阶段基础镜像 digest、4 个 go 工具（nuclei/subfinder/httpx/ffuf）版本、3 个语料仓库（nuclei-templates/PayloadsAllTheThings/wxappUnpacker）commit sha——上游漂移时构建 FATAL 拒绝产出，升级需人工更新 Dockerfile 内 PIN。

**离线边界**：构建期需联网（拉底座+编译工具+克隆语料）；构建完成后运行时离线可用（install_tool/测绘 API 等按需联网项除外）；wheelhouse 仅覆盖 playwright 依赖栈。

## 外网访问

`config.json` 设置 `auth_token` 后监听 0.0.0.0；两种暴露方式：

```bash
# 方式一：Cloudflare 快速隧道（无需域名/账号，WebSocket 支持）
cloudflared tunnel --url http://localhost:8787
# 输出形如 https://xxx-yyy.trycloudflare.com —— 访问时输入令牌（Basic 认证任意用户名，密码=auth_token）

# 方式二：自有服务器 frp/nginx 反代 —— 反向代理到 8787 即可，务必保留令牌认证
```

## API 一览

```
POST /api/projects                     # 创建项目 {name,target,scope,roe,specializations:["A","B1","B2"]}
GET  /api/projects                     # 项目列表
GET  /api/projects/{id}                # 详情（状态/发现/资产/时间线/审批/证据）
POST /api/projects/{id}/start          # 启动全流程流水线
POST /api/projects/{id}/stage/{s}/run  # 手动运行/重跑某阶段（s1..s8, specA, specB1, specB2）
POST /api/projects/{id}/kill           # ⛔ 一键熔断
POST /api/approvals/{id}/decide        # 审批决策 {approve:true|false}
GET  /api/projects/{id}/report         # 获取 report.md
GET  /ws?project={id}                  # 实时事件流
```

## 与《AI 渗透测试全流程图》的模块映射

| 流程图 | 九头鸟模块 |
|---|---|
| 主流程 1-8 | `heads/s1.md ... s8.md`（进入条件/分步动作/交付物/红线全量编码） |
| 专项 A（LLM 目标，A1-A11） | `heads/specA.md`（OWASP LLM Top10 + MITRE ATLAS 映射） |
| 专项 B1（APP 静态+动态双链） | `heads/specB1.md`（jadx 静态链 + Frida 动态链） |
| 专项 B2（小程序 W1-W6） | `heads/specB2.md`（解包→密钥审计→逻辑推理→接口/云侧） |
| 引擎 E（执行循环 + 护栏） | `prompts/loop-core.md` + `internal/engine`（9 步循环、审批矩阵、熔断） |
| 贯穿线一（全程记录） | 证据链 `EvidenceRecord` + 攻击时间线 |
| 贯穿线二（人机协作） | Web 审批队列 + 人工批准点（◆） |
| 贯穿线三（合规红线） | FORBIDDEN 禁令 + ROE 核验 + 一键熔断 |

> 专项 C（免杀对抗）按流程图要求**默认禁用、不予实现**——仅限书面授权红队且需 ROE 专项允许，属受限支线。

## 二次开发指引

- **调优某个头的打法**：直接改 `heads/*.md`（纯中文提示词，改完重启生效）。
- **换模型**：改 `config.json` 或 Web 设置页；任何 OpenAI 兼容端点均可。
- **加工具**：无需注册——智能体可执行任意命令并自写 PoC；建议把新的风险特征加进 `config.json` 的护栏正则。
- **升级存储**：`internal/store` 当前为 bbolt（单机并发安全）；换 SQLite/Postgres 只需实现同名 CRUD。
- **自主编排**：`heads/main.md` 预留真头自主决策扩展点（当前流水线由引擎按固定顺序驱动 + 回环）。

## 测试

```bash
make test        # Go 单元测试：风险分级、路径沙箱、审批批准/拒绝/熔断、头注册与流水线
make ui-check    # 前端构建 + 体积预算守卫
```

E2E 验证（Mock 模式）：创建项目→启动→11 个阶段全部 done→证据链落库→阶段 8 产出 report.md。
