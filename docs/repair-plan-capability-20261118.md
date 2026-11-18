# 九头鸟 v5.4.5 能力缺陷修复方案

> 日期：2026-11-18。依据当前工作树只读核对，本文是实施计划，不代表功能已实现。涉及文件名和函数均对应现有代码。

## 缺陷索引

| 编号 | 缺陷 | 计划阶段 |
|---|---|---|
| A | 只有 `Project.AuthInfo` 单字符串、Loot 仅掩码，无结构化凭证和自动带态请求 | P1 |
| B | 无源码获取、SCA、source/sink、污点及补丁 diffing 闭环 | P2 |
| C | Fuzz 缺 harness、语料/覆盖/崩溃闭环，长任务受 async 上限约束 | P2 |
| D | `loopback` 最多入队 3 次，超额仍回成功但不排队 | P0/P1 |
| E | `runStage` 预算耗尽把阶段设 `done`，流水线继续 | P0/P1 |
| F | 子代理 Chat 错误直接 `failed`，状态/结果主要在内存共享 store 及摘要 | P1 |
| G | `compactMsgs` 替换历史消息正文，原始 tool receipt 不可恢复 | P0/P1 |
| H | Chat 工具轮次耗尽只返回“已暂停”，无可恢复续接状态 | P0/P1 |
| I | 技能清单化、工具状态缺失、s7 清理口径矛盾、技能计数口径漂移 | P0 |

## 总路线图

| 阶段 | 目标/范围 | 估算 | 依赖 |
|---|---|---:|---|
| P0 快赢 | I：修订技能/manifest 口径和工具可用状态；D：拒绝或持久化超额回环；E：预算耗尽改为显式待续而非 done；G：压缩留可恢复原文索引；H：保存 Chat continuation | 4–6 人日 | 无；先为 P1/P2 建立状态与验收基线 |
| P1 核心能力 | A 凭据仓库与带态请求；D 回环队列持久化/限额；E 可续跑预算状态；F 子代理重试与结果对象 | 12–18 人日 | P0 的状态迁移和回归测试约定 |
| P2 长期能力 | B 白盒流水线；C fuzz 闭环及长作业生命周期 | 16–24 人日 | A 的安全存储/审批接口；P1 子任务和作业状态接口 |

**依赖关系**：A 与 F 可并行；D/E 是调度正确性前置，应先于 B/C 自动编排；B 先完成源码工件和工具适配，再做污点/补丁比较；C 先有可持久化 async job 状态，再接 harness、corpus 与 coverage feedback。新增能力仍经 `governanceGates`、现有审批和 execution profile；不以技能提示词替代引擎强制门。

## 逐项方案

### A. 结构化凭据仓库与自动注入

**目标**：在明文只存在于受控运行时的前提下，让经授权的多身份会话可供 HTTP 深测与指定命令复用；Loot 继续用于可审计的发现摘要，不成为秘密存储。

**设计**

新增 bbolt `credentials` bucket，按项目隔离，记录密文及非敏感元数据。静态加密采用 AES-256-GCM，随机 nonce 每条独立生成；主密钥仅从 `CREDENTIALS_MASTER_KEY` 环境注入（32 字节原始/编码形式明确配置），不写入 DB/config JSON，缺失时禁用写入/解密并 fail closed。配置项只保存启用状态/密钥来源标识，不保存密钥。DB 文件权限继续 0600；备份也按密文资产管控。加密封装版本化，支持未来轮换。

```go
type CredentialRecord struct {
    ID, ProjectID, Target, Identity, Role, Kind string
    SecretCiphertext []byte // AES-GCM nonce || ciphertext; JSON/base64 编码由存储层处理
    SecretVersion int
    Username string // 可选；按字段敏感等级同样加密，展示只提供 masked
    CreatedAt, UpdatedAt time.Time
    ExpiresAt *time.Time
    SourceLootID string // 可选关联，不重复把秘密塞入 Loot
    Status string // active/revoked/expired
}
type CredentialStore interface {
    PutCredential(ctx context.Context, in CredentialInput) (CredentialMeta, error)
    GetCredential(ctx context.Context, projectID, id string) (CredentialSecret, error)
    ListCredentialMeta(projectID string) ([]CredentialMeta, error) // 永不返回 secret
    RevokeCredential(projectID, id string) error
}
type CredentialInjector interface {
    Resolve(projectID, target, identity string) (CredentialSecret, error)
    ApplyHTTP(req *http.Request, secret CredentialSecret, mode AuthMode) error
    ExpandCommand(template string, secret CredentialSecret) (string, error)
}
```

凭据主键是 `projectID + identity + target + kind` 的逻辑唯一组合，允许同一 role 下多个 session（例如 `operator/session-1`、`operator/session-2`）；矩阵对象显式引用 identity/session，禁止“当前全局账号”隐式覆盖。凭据录入/读取都记录审计事件，但审计、stream、timeline 和工具返回不得包含明文。UI/API 只暴露 `CredentialMeta` 和掩码值；创建后一次性回显也只回显掩码。

与 Loot 的关系：`LootRecord` 保持 `Masked/Source/Verified` 语义。模型调用现有 `record_loot` 时只登记掩码；新增受控 `store_credential` 工具接收秘密参数，存储后只返回 ID/掩码。必要时将 `SourceLootID` 关联 loot；不得从旧 Loot 的 `Masked` 反推秘密。旧 `Project.AuthInfo` 只作迁移兼容：将其作为 legacy 未结构化提示，不自动解析成用户名/口令，也不复制进凭据库；后续版本可弃用字段但保留旧项目反序列化能力。

注入流程（文字图）：`工具参数 credential_ref/identity` → `CredentialStore.GetCredential` 解密到短生命周期内存 → 针对目标/ROE 检查 → HTTP 构造器或命令模板变量绑定 → 原有 `governanceGates`/审批 → 执行与证据脱敏 → 擦除临时 buffer。HTTP 只在新 `http_request` 工具中支持 `auth_ref`，不对任意 `run_command` 文本做秘密替换。命令模板采用 argv/结构化变量而非 shell 字符串拼接；`hydra/curl` 初期只提供显式占位变量（如 `${CRED_USERNAME}`、`${CRED_PASSWORD}`），由适配器做 shell-safe 参数化并对 hydra 的字典/目标参数仍走原治理。交互式 shell、任意命令和异步命令不自动注入。

**实施步骤**

1. `server/internal/store/store.go`：增加 bucket、`CredentialRecord`、加密封装与 CRUD；扩展 `Open` bucket 初始化。单测覆盖 reopen、隔离、篡改 tag、撤销、迁移旧 DB。
2. 新增 `server/internal/credentials/crypto.go`、`service.go`：AES-GCM、密钥解析/校验、脱敏与生命周期；不得在通用 JSON marshal 中带出明文。
3. `server/internal/config/config.go`：增加只读密钥来源/开关配置及 env 装载；启动时校验，密钥不落 `config.json`。初始化装配位置查 `server/internal/engine/orchestrator.go` 的 `New`/store 注入路径后接入服务。
4. `server/internal/engine/orchestrator.go`：在 `toolDefs` 与工具 dispatch 增加 `store_credential/list_credentials/revoke_credential`；读取仅通过 ref。新增结构化 `http_request` 的请求构造和响应留证，经过 `governanceGates`、审批及 `toolRunCommand` 对应治理边界；不能绕过范围门。
5. 新增 `server/internal/credentials/http.go`、`command.go`：支持 Bearer、Basic、Cookie、指定 header 等有限 AuthMode；命令模板只允许预定义变量和允许工具名。更新 `skills/authz-diff.md`、`skills/api-idor.md`、`skills/session-state-chain.md`：矩阵每行显式身份引用，记录 `role×object×operation` 覆盖结果。
6. Web/API 展示接线按现有项目/loot handler 的数据投影增加掩码元数据；任何 API 的序列化使用 DTO，禁止直接序列化密文/secret。

**验收标准**

- DB 中无输入明文；正确密钥可解密，错误密钥/tag 篡改均失败；不同项目不能跨读；无密钥时 fail closed。
- API、stream、timeline、tool result、evidence 均不包含凭据原文；UI 只显示掩码。
- 两个以上 role/session 可并存，authz 矩阵在每种身份下构造不同请求；覆盖和证据能关联 identity ID。
- 自动注入的请求仍触发范围拒绝/审批；未经批准的写请求不能因带态而执行；revoke 后下一次 resolve 失败。
- 旧 v5.4.5 DB 可打开，旧 Loot/Project JSON 可读取且不触发秘密迁移。

**估算**：6–9 人日（含存储、服务、引擎工具、API/UI DTO 与回归）。**风险/兼容性**：密钥丢失意味着凭据不可恢复；需要备份/轮换运维手册。新增能力不改变既有 manual/l1/all 策略，但执行请求照旧进入审批。现有 `AuthInfo`/Loot 不自动升级为可执行秘密，避免误用和数据泄露。

### B. 白盒审计工作流

**目标**：把授权源码工件纳入可追溯流水线，产生可复核的依赖风险、source/sink、污点候选和补丁差异结果。

**设计**：技能描述分析方法；代码负责工件来源校验、工具可用性探测、异步作业状态、输出落盘和证据关联。流程：授权源码/仓库快照 → hash/版本记录 → 语言识别 → SCA → source/sink 检索 → 静态污点工具（按语言适配）→ 候选人工/动态验证 → 相邻版本补丁 diff → `record_finding`/`record_vt`/coverage。源码获取只接受客户提供文件或明确授权仓库；不新增凭据外传或公网上传。

**实施步骤**

1. 新增 `skills/whitebox-source-audit.md`、`skills/whitebox-sca-taint.md`、`skills/patch-diffing.md`，写清输入前置、语言分流、命令、判定、证据及工具不可用时的 `needs_follow_up`，并在 `skills/manifest.json` 及生成脚本输入中登记。
2. `server/internal/engine/orchestrator.go` 工具表接入 `inspect_source`/`run_analysis` 受限工具；命令仍经 `run_async` 及治理门。新增工具适配包 `server/internal/analysis/`，仅允许白名单工具、仓库工作区路径和输出目录。
3. `server/internal/store/store.go` 增加 AnalysisRun 工件元数据（source hash、tool/version、status、output refs），或复用扩展现有 evidence/async 状态时明确 job ID 与 source hash 关联。
4. `heads/s2.md`/`heads/s3.md` 增白盒任务分支和交付契约；`skills/frontend-sca.md` 作为前端依赖分析互链，不以提示词替代命令执行状态检测。

**验收标准**：Go/JS 示例仓库可识别依赖并生成 JSON 结果；不存在工具时状态是 `unavailable/needs_follow_up` 而非“无问题”；source hash、工具版本、命令、输出证据可追溯；污点候选不得自动成为确证 Finding；补丁 diff 有版本基线和差异文件证据；范围外仓库访问被拒。

**估算**：7–10 人日。**风险/兼容性**：静态分析误报高；必须将工具版本和规则集版本留证，结果进入验证队列而非自动提升严重度。源码体积及许可证处理需由客户授权约束；不向远端分析服务上传。

### C. Fuzzing 闭环

**目标**：支持受范围约束的 harness 生成/执行、语料与覆盖累计、崩溃去重和最小化，并能跨重启续跑。

**设计**：技能给 harness 模式和安全纪律；引擎/适配器实现 job、corpus、coverage、crash 状态。流程：目标/协议与边界确认 → harness 模板/用户 harness → seed corpus → 有限 smoke → `run_async` fuzz job → 定期采样覆盖和崩溃 → crash signature 去重 → 最小化 → 复现验证 → finding/evidence。支持 Go native fuzz、AFL++/libFuzzer 等首批适配器，逐工具 capability 声明；长作业可 checkpoint，不以提高单次 timeout 代替闭环。

**实施步骤**

1. 新增 `skills/fuzzing-workflow.md`、`skills/fuzz-harness-go.md`，明确测试对象所有权、速率/资源上限、无 destructive corpus、crash 对目标影响和停止规则。
2. 新增 `server/internal/fuzz/`：`Adapter` 接口、Job/Corpus/Crash 元数据、coverage/crash signature 归一化和 reducer 调度；在 `orchestrator.go` 工具定义/dispatch 接 `start_fuzz/poll_fuzz/stop_fuzz`，所有启动动作走审批/范围门。
3. 在 store 增加 fuzz job bucket，语料/覆盖大文件存工作区、DB 只存 hash/path/状态；校验路径防目录逃逸。接入 async sidecar 的终态和恢复逻辑，配置 `FuzzMaxRuntimeSec`、CPU/内存、并发及 checkpoint 周期。
4. 阶段收口前扫描未终态 fuzz job，设为明确 pending/needs_follow_up 或经授权后台继续；不能由 `harvestAsyncOutputs` 将仍运行作业误判完成。

**验收标准**：确定性 fixture 可从 seed 触发已知崩溃、归并重复 signature、最小化到可复现输入；coverage 至少两次采样可看到增量；重启后 job/corpus 状态可恢复；stop/预算/项目 kill 能停进程组；无 harness 或工具时落待续项；目标地址超范围和资源上限均阻断。

**估算**：9–14 人日（首批 Go fuzz 与一个外部适配器；更多引擎另计）。**风险/兼容性**：Fuzz 会造成 CPU/内存占用及目标服务压力，默认仅本地/隔离副本；外部目标 fuzz 必须有明确 ROE、限速和审批。语料可能含敏感数据，按项目隔离并提供保留期限策略。

### D. 阶段回环超限丢失

**目标**：每次被接受的回环都有明确去向，达到限额时返回拒绝或持久化为待办，不能假报成功。

**设计**：将 `Orchestrator.loops` 内存队列变为持久化 `LoopbackRequest{ID, ProjectID, FromStage, ToStage, Reason, Status, Attempts, CreatedAt}`；配置每项目最大自动补跑数和每目标次数。超过自动额度时登记 `pending_review` 并返回“已登记待人工/后续调度”，不可写 `pending` 后却不排队。

**实施步骤**：`orchestrator.go` `case "loopback"` 校验目标阶段合法性、先原子登记再更新状态；`RunStage`/阶段调度处消费并更新状态；`store/store.go` 新 bucket/CRUD；配置增加额度与拒绝策略；覆盖 restart 恢复。

**验收标准**：额度内请求只执行一次并可重启恢复；额度外请求有持久记录且工具明确告知未排队；非法 stage 不修改状态；并发请求不丢不重。

**估算**：2–3 人日。**风险/兼容性**：已有 v5.4.5 进程内 loops 重启即失的行为不迁移；不改变 loopback 对审批的现状，但新增调度仍不能绕过治理门。

### E. Token 预算耗尽代收口

**目标**：预算耗尽表达为 `paused/budget_exhausted` 或 `needs_follow_up`，不得把未完成阶段标为 done 并驱动后续阶段。

**设计**：扩充 StageState 的暂停原因/可续跑游标，设置项目状态 paused，保持已收割证据及 V3 清单；调度器只推进 `done/skipped`，暂停阶段等待预算增加或人工继续。若产品需要自动降级收口，应作为显式策略并产生独立终态，不与完成混用。

**实施步骤**：`orchestrator.go` `runStage` 预算检查及 1428–1484 耗尽分支改为持久化 paused + timeline；`RunStage` 和流水线推进逻辑明确处理 paused；`store.StageState` 添加 `PauseReason`/`ResumeAtIteration`；`config/config.go` 增续跑策略（默认暂停）。

**验收标准**：预算阈值触发后阶段非 done、后续阶段未启动、项目可见暂停原因；提升预算后从可恢复状态继续，不重复已完成工具调用；Kill/人工暂停优先级不被预算续跑覆盖；旧数据无新字段可读。

**估算**：2–4 人日。**风险/兼容性**：改变当前预算熔断后自动推进的既有行为；需要 UI 能展示 paused 原因。此前依赖 S8 quality-pending 代收口发现缺口的项目仍保留历史状态，不批量重写。

### F. 子代理失败重试与结构化结果

**目标**：瞬时 LLM 错误有界重试，最终结果可持久查询、合并和审计；不重复执行已发生的工具副作用。

**设计**：每个 SubAgentRun 保存 attempts、last error、next retry、消息链引用、结构化结果状态；只在 LLM 请求失败且尚未收到工具调用时指数退避重试。工具执行后若后续 LLM 失败，恢复消息链继续对话，不重放上轮 tool call。共享 store 仍承载 Finding/coverage 等事实，额外写 `SubtaskResult` 汇总状态和引用 ID。

**实施步骤**：`server/internal/engine/subagent.go` `SubAgentRun`/`runSubAgent` 增加 retry policy 和上下文取消判断；`pollSubAgents` 输出 attempts/error/result refs；`store/store.go` 增子代理档案 bucket；`orchestrator.go` 的 spawn/poll dispatch 与项目重启恢复接线。

**验收标准**：前两次 Chat 失败第三次成功只执行一次；永久错误在上限后 failed 且摘要可查；Kill 不重试；工具调用后错误恢复时无重复命令/evidence；重启后 poll 可见终态。

**估算**：3–5 人日。**风险/兼容性**：当前子代理仅内存态，旧运行记录无法恢复；重试增加 token，纳入项目预算并限制次数；不得对工具执行结果不确定的动作自动重放。

### G. 压缩后原始工具回执不可恢复

**目标**：消息窗口可压缩，但原始 tool receipt 可通过稳定 ID 检索；摘要和回执可核对。

**设计**：压缩不再把唯一原文覆盖成 stub。消息增加 `ReceiptID`/`ContentHash`；原始回执按需落到现有 evidence/独立消息归档 bucket，窗口仅保存引用和摘要。`search_memory` 支持 receipt ID、job ID、关键词检索，并返回分页片段/文件引用。

**实施步骤**：`context.go` `compactMsgs` 将工具消息压缩为包含 receipt ID 的引用标记；`orchestrator.go` 主循环在追加 tool message 前归档原文，扩展 `case "search_memory"` 检索；`store/store.go` 新增消息归档 API；Chat 与阶段链都使用同一 archive。

**验收标准**：压缩前后所有 receipt ID 可查回原始字节/hash；多次压缩不覆盖归档；权限按 project 隔离；大输出仍与 `.tool-output/` 文件引用一致；无原文时明确标记归档缺失，不声称可检索。

**估算**：3–4 人日。**风险/兼容性**：新增存储容量和敏感命令输出保留风险；按现有项目数据保留策略管理，搜索结果仍需脱敏；旧消息仅能恢复当时已落 evidence/或 spill 文件部分。

### H. Chat 工具轮次耗尽无续接

**目标**：轮次上限后能够从待续工具链继续，而非只有一段自然语言“已暂停”。

**设计**：增加持久化 `ChatRun`，存 status、轮次、消息链引用、待处理 tool call、最后错误、更新时间。耗尽时状态 `paused_round_limit` 并返回 run ID；下一次 `Turn` 先恢复同一 run，再追加用户消息。工具调用执行结果先持久化后追加，避免断线重复执行；显式继续 API/UI 可以复用普通 Turn。

**实施步骤**：`chat.go` `Turn` 把历史装配/运行循环拆成创建与恢复；轮次耗尽持久化完整 msgs，不只存最终 user/assistant 文本；`store/store.go` 增 ChatRun bucket/API；`orchestrator.go` `dispatchChat` 前后写入执行状态和幂等 tool call ID。

**验收标准**：达到配置轮次时有 run ID/status；继续后不丢 tool call/receipt；重复提交续接请求不会重放已执行动作；全局咨询模式仍禁工具；历史 API 不泄露内部密文或被压缩归档全文。

**估算**：3–4 人日。**风险/兼容性**：现存 Chat 历史仍可展示，但没有完整未保存消息链的旧暂停轮次不可恢复；续接保留原有审批和对话鉴权。

### I. 技能质量、工具可用性及计数口径

**目标**：技能能指导执行与判定；工具可用状态可证实；计数单一生成；s7 清理规则只有一套。

**设计**：技能统一结构：适用条件/前置、步骤、成功与否判据、证据/coverage 记账、工具可用性探针及 fallback、治理限制。区分“引擎内置”“环境可选”“需安装”“不可用”，禁止把命令存在性当执行成功。manifest count 由 `scripts/gen_skill_manifest.py` 生成；文档引用生成值。s7 统一为：production_safe 仅登记移交与只读复核；isolated_lab 用快照/环境重置，不在目标执行删除；禁止模糊的“清理命令执行”表述。

**实施步骤**：抽样并逐批重写高频清单技能，优先 `authz-diff.md`、`api-idor.md`、`weak-cred-bruteforce.md`、`frontend-sca.md`；为 `tool-channels.md` 增 capability 表与探针结果格式；`heads/s7.md` 与 `skills/` 中冲突条款统一；执行 manifest 生成脚本并在 CI/验收中断言文件数、manifest count、有效 id 一致。清点仓库当前 manifest 声明 count=115 与实际文件计数的口径差异，明确统计规则（是否含 router/非技能文档）。

**验收标准**：按抽样技能逐项具备五个执行字段；工具 unavailable 不得记录 negative_valid；脚本两次生成无 diff；`heads/s7.md` 全文无目标侧 DELETE/UPDATE 执行指令歧义；统计脚本输出与 manifest 一致。

**估算**：P0 2–3 人日（规则/生成和前 10 个核心技能）；全量 60% 清单技能改造 8–12 人日，可跨 P1/P2 逐批完成。**风险/兼容性**：技能文本变动可能影响模型路由；保留旧 id/aliases，先改内容再改依赖关系；不得因技能写了工具支持就绕过运行时能力检查。

## 验收清单

- [ ] DB 旧版本升级/打开无损；新增密文和归档按 project 隔离。
- [ ] 凭据 UI/API/日志/证据掩码完整，注入仍经过范围、执行档和审批。
- [ ] 回环额度内执行、超额待办、重启续跑均可验证。
- [ ] Token 耗尽不再把未完成阶段标 `done` 或推进流水线。
- [ ] 子代理重试只重试安全的 LLM 请求，不重放副作用工具。
- [ ] 压缩 receipt 可按 ID 原文取回；Chat 达轮次上限可恢复续接。
- [ ] 白盒/Fuzz 的缺工具、缺授权、超范围和预算耗尽均有明确状态与证据。
- [ ] 技能工具状态有探针记录，manifest 与真实清点结果一致，s7 口径唯一。
- [ ] 所有新增自动执行保持现有 `approval.go` 审批、execution profile、ROE 与范围门约束。

## 明确不做的事（非目标）

- 不把密码、token、cookie 明文写进 Loot、Timeline、Finding、Evidence、Stream 或 LLM system prompt；仅在明确授权的具体请求执行瞬间进入短生命周期参数。
- 不从旧 `AuthInfo` 或 Loot 掩码猜测/恢复凭据，不静默解密旧数据。
- 不为完成 fuzz/白盒而绕过 `governanceGates`、审批、ROE、strict scope 或执行档；不自动将静态候选当确证漏洞。
- 不在 production_safe 下执行目标侧清理删除、修改或还原；自建测试数据也按现行 s7 政策登记移交。
- 不通过无限提高轮次、超时或自动重试掩盖预算、状态和作业生命周期缺陷。
- 不在本方案内调整漏洞严重度标准、扩大默认攻击面或新增未授权外部服务上传。
