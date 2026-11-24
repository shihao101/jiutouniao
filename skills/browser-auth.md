---
id: browser-auth
title: 浏览器认证实战手册（真实浏览器登录 + CLI 接管混合流水线）
tags: 认证,浏览器,加密协议,挑战值,验证码,wasm,browser-kit,s5,s6,s4
---
# 浏览器认证实战手册（browser-auth）

> 一句话：**浏览器负责「进门」与加密，CLI 负责进门之后的一切。**
> 套件位置 `/opt/tools/browser-kit/`（v2.8.0 构建期固化），解释器 `/opt/venv/bin/python`。

## 一、触发条件（何时放弃 curl 构造、切换真实浏览器）

登录面命中以下**任一**特征，立即停止明文请求构造，走本手册流水线：

| 特征 | 典型失败形态 |
|---|---|
| 前端加密链路：JS/WASM 加密（Emscripten/asm.js/cryptoParam 类组件） | 明文凭据 POST 得到 404 或参数类错误，密码从未到达服务端校验环节——页面存在加密组件时固定明文载荷必然失败 |
| 动态挑战 token：random/selKey 类端点取值参与密钥派生 | 挑战值存于 sessionStorage 且每次会话不同，离线构造的固定载荷全部无效 |
| 参数名陷阱：真实参数与表面可见字段不符（name/username 类错位） | 返回「xx参数为必填项」类错误——字段名对不上，凭据未被评估即被拒绝 |
| 验证码渲染 / fd-hide 类隐藏条件验证码 | 明文构造无法通过前端校验链；验证码控件默认隐藏、失败超限后才启用 |
| UA 指纹过滤 | 工具 UA 被 TLS 层断连/RST，浏览器 UA 正常返回——工具态全部误报「连接失败」 |
| JS 种 Cookie / 前端状态机（两步提交、前端跳转校验） | 单请求构造永远缺前置状态，重放行为与真实流程不符 |

> 判断原则：**连续 2 轮明文构造失败且页面源码存在前端加密链路 → 不再尝试第 3 轮**（同参数重试触发导师评审），直接切浏览器。离线逆向协议（wasm2wat）降级为可选深挖项，不再是登录的前置条件。

## 二、标准流水线（浏览器进门 → CLI 接管）

```
步骤 1  browser_login.py 登录 + 抓取（见下）
步骤 2  CLI 基线验证：curl -b cookies.txt 请求一个登录后端点 → 200 = 会话有效 + 指纹被接受
步骤 3  端点清单入队：postlogin-links.txt 的菜单/API 候选 → 生成越权矩阵与功能面测试队列（移交 s6）
步骤 4  CLI 执行测试主体（会话安全/越权矩阵/功能面只读探测，run_command + 现有护栏/审批）
步骤 5  回浏览器仅限五场景（见 §四）
```

### 步骤 1 操作要点

```bash
JT_PASS='<凭据>' /opt/venv/bin/python /opt/tools/browser-kit/browser_login.py \
    --url https://<目标>/index.html --user <用户名> \
    --success-marker '<登录后页面特征文本>' \
    --out evidence/browser-login
```

- **凭据纪律**：密码只走环境变量（`--password-env`），禁止写入 argv/脚本/交付物明文；报告与证据只记摘要。
- **产物即证据**（EV 编号引用）：`cookies.txt`（Netscape，curl 直接 `-b` 复用）、`storage.json`（挑战值/权限矩阵等）、`postlogin.html`、`postlogin-links.txt`（端点候选）、`network.har`（已脱敏）、`shots/*.png`。
- **退出码**：0 成功｜2 导航失败｜3 登录未确认（看 `login-failed.html/png` 诊断）｜42 验证码需人工｜45 多步登录需 OTP 口令。
- **选择器**：默认自动探测（同 form 内 password + 文本输入 + code/captcha 启发式）；非标页面用 `--profile selector.json` 指定，profile 存入项目工作区。
- **失败额度**：浏览器登录与 curl 同受账号失败额度约束（如授权账号 ≤5），计数与 curl 尝试合并统计，写入时间线。

### 步骤 2-3 操作要点

- 每隔 N 个请求做一次廉价基线校验（GET 任意登录后端点），防会话中途过期导致全队列误报。
- CLI 收到 403/断连 → **停队**，浏览器单请求复核区分「封禁 / 会话失效 / 端点变更」，恢复后再继续。
- 串行限速与时间窗纪律不变：浏览器只是换了客户端，ROE 一切红线照常生效（对目标流量默认直连，脚本已剥离代理环境变量）。

## 三、验证码与多步登录人机协同（强制）

- `browser_login.py` exit 42 → 用已落盘的 `shots/login.png` 调 `request_user_input` 请人工读码 → 携 `--captcha <值>` 重试一次。
- **登录流水线内禁止自动打码/碰撞（v6.5.0 S5-⑤ 边界明文化）**：人工读码单次会话内有效，验证码过期则再次转人工，不循环。L4 验证码攻坚轨的受控 OCR 闭环（captcha-ocr 单会话）不属本流水线，口径见 identity-bootstrapping L4——两轨不混用。
- 验证码若仅在失败超限后启用（fd-hide 类），默认路径无验证码，直接登录。
- **多步登录/MFA（v3.1.0）**：提交后出现口令输入位（密码框消失）→ 配置 `--otp-env` 自动注入动态口令（口令值只走环境变量）；未配置时 exit 45 → request_user_input 向人工索取口令后重试。滑块/行为类验证码不支持自动处理，转人工或登记 needs_follow_up。
- **SPA 慢挂载**：表单延迟渲染由探测重试覆盖（`--detect-timeout` 默认 10s 轮询），无需人工干预。
- **无头特征**：默认抹除基础自动化特征（webdriver/plugins 等）；强对抗目标（主动探测型风控）不承诺绕过，受阻时如实登记 waf_blocked/blocked 并转人工。

## 四、必须回浏览器的五个场景

1. **加密预言机**（最高频）：登录后部分业务端点同样加密（改密/敏感操作）——用 `browser_oracle.py` 在页面上下文执行其加密函数取回密文，**载荷仍由 CLI 发送**：
   ```bash
   /opt/venv/bin/python /opt/tools/browser-kit/browser_oracle.py \
       --url https://<目标>/index.html \
       --cookies evidence/browser-login/cookies.txt \
       --storage evidence/browser-login/storage.json \
       --wait-js "typeof _encryptWebuiString !== 'undefined'" \
       --eval "_encryptWebuiString('<payload>')" \
       --out evidence/oracle-<用途>.json
   ```
2. **前端逻辑漏洞**：DOM XSS / postMessage / CSRF（表单自动提交）/ 点击劫持视觉证明。
3. **会话语义测试**：注销失效、会话固定（Cookie 置换）、并发会话（开第二个隔离 profile+独立 cookie jar）、SameSite 行为。
4. **存在性证明截图**：ROE 要求的截图取证。
5. **漏洞回验**：CLI 发现的发现，浏览器以真实用户视角复现一次，防误报进报告。

## 五、会话与坑位纪律

- **会话一致性**：正常测试全程单一会话（浏览器登录后浏览器闲置，CLI 接管）；多会话可能触发目标异常检测，且注销类测试互相干扰。
- **指纹一致性**：CLI 复用浏览器的 UA/Referer/X-Requested-With 模式（从 HAR 提取）；UA 钉住 `--ua`。
- **审计**：浏览器动作同样走 `run_command` 风险分级与审批矩阵；登录动作 reason 写明「使用项目授权凭据合规登录」。
- **清理**：登录会话（SESSID）纳入 S7 清理确认清单；storage 中目标侧数据不修改不删除。

## 六、覆盖度登记

- 每完成一个「认证机制×测试项」单元，`update_coverage` 登记（如 认证/登录协议=browser 登录成功）。
- 浏览器路径受阻（如强制验证码+人工不可用）→ `update_coverage(needs_follow_up)` 附原因，禁止静默跳过。

## v4.8 M6 工具通道兼容性声明

> 口径（loop-core v4.8 纪律 3）：先 probe 后 batch——外部工具首次使用前小样本探针确认可用性。本技能工具链在「挑战型 WAF / 封闭站」下的可用性与适配通道：

- captcha-ocr.py：验证码识别（列投影分割+模板匹配）——**仅用于 identity-bootstrapping L4 攻坚轨的受控探针（会话内取图、单会话闭环，v6.5.0 S5-⑤ 边界）**，不用于本流水线登录提交（登录流水线强制人工读码，见 §三）；直连取图被拦时先建会话再取。识别率对扭曲/干扰型有上限（总案 §七.3），分割数不符返回 None 强制降级人工读码/browser-auth 会话，不硬套。
- browser_login.py：浏览器会话建立——适配通道本体（挑战型 WAF/封闭站下始终可用），是 captcha-ocr 取图与后续 oracle 探针的通道来源。
- browser_oracle.py：凭据面预言机探针（枚举/锁定预言机）——挑战态已注入（经 browser_login 会话）时可用；无验证码面直连可用（auth-browser 分流：无验证码面直连、SimCaptcha 类面走会话）。
- channel-snapshot.py：通道资产固化（挑战态提取/复放）——始终可用，且是本清单其它工具的适配通道来源。
- channel-heartbeat.py：空闲期通道基线自检——始终可用；连续 down 判定后先重建会话再继续 oracle 探针。
