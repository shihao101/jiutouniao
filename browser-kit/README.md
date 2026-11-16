# browser-kit — 浏览器认证套件（v2.8.0 固化）

真实浏览器（系统 Chromium + Playwright）驱动登录与会话捕获，解决「curl 明文构造
无法通过 JS/WASM 加密登录协议」的实战短板。构建期固化进镜像：`/opt/tools/browser-kit/`。

## 组件

| 文件 | 用途 |
|---|---|
| `browser_login.py` | 真实浏览器合规登录 + 一次性抓取 CLI 接管全部材料（cookies/storage/页面源码/端点清单/HAR/截图） |
| `browser_oracle.py` | 加密预言机：在页面自身上下文中执行加密函数取回密文，载荷仍由 CLI 发送 |
| `selftest/mock_server.py` | 本地 mock 靶场（仅 127.0.0.1）：挑战值协议/参数名陷阱/隐藏验证码/HttpOnly 会话 |
| `selftest/selftest.sh` | 全链路自测（零外部流量），7 组断言 |

## 使用（运行环境为 Kali 容器内）

```bash
# 登录 + 抓取（密码只走环境变量）
JT_PASS='******' /opt/venv/bin/python /opt/tools/browser-kit/browser_login.py \
    --url https://TARGET/index.html --user testuser \
    --success-url-contains "/main.html" \
    --out evidence/browser-login          # 退出码 42 = 验证码需人工读码

# CLI 接管：curl 直接复用浏览器会话
curl -sk -b evidence/browser-login/cookies.txt https://TARGET/home/auth/userManage/

# 加密预言机：页面自己的 JS 加密任意载荷（已登录上下文）
/opt/venv/bin/python /opt/tools/browser-kit/browser_oracle.py \
    --url https://TARGET/index.html \
    --cookies evidence/browser-login/cookies.txt \
    --storage evidence/browser-login/storage.json \
    --wait-js "typeof _encryptPayload !== 'undefined'" \
    --eval "_encryptPayload('payload')" \
    --out evidence/oracle-payload.json
```

## 纪律（与 ROE 对齐，违反即事故）

- **验证码人机协同**：可见验证码且未提供 `--captcha` 时 exit 42——智能体必须
  `request_user_input` 转人工读码，**禁止自动打码/OCR 爆破**。
- **凭据卫生**：密码只经环境变量注入；HAR/日志自动脱敏；报告与证据只记摘要。
- **流量纪律**：默认剥离代理环境变量直连目标（与「靶机流量严禁走代理」方针一致）；
  串行、`--interval-sec` 间隔、`--global-timeout` 看门狗默认 240s（低于引擎 300s 上限）。
- **会话卫生**：登录会话纳入 S7 清理确认清单（SESSID 由服务器过期/注销失效）。

## 使用时机（何时切浏览器）

登录口命中以下任一特征即放弃 curl 构造、切换本套件（详见 `skills/browser-auth.md`）：
JS/WASM 加密（Emscripten 特征）、动态挑战 token（random/selKey 类端点）、验证码渲染、
JS 种 Cookie、UA 指纹过滤、明文构造多轮失败且页面源码存在前端加密链路。

## 自测

```bash
bash /opt/tools/browser-kit/selftest/selftest.sh
# 预期：browser-kit selftest: PASS=18 FAIL=0
# 覆盖：挑战值协议登录/CLI 接管/预言机/上下文还原/验证码人机协同/错误口令/HAR 脱敏/
#       SPA 慢挂载（探测重试）/MFA-OTP 两步自动/OTP 缺失转人工（exit 45）
```

## 多步登录与调试口径（v3.1.0）

- **MFA-OTP**：提交后页面出现口令输入位 → `--otp-env JT_OTP` 自动注入（口令值只走环境变量）；
  未配置时 exit 45 转人工（request_user_input）。滑块/行为类验证码仍不支持自动处理（exit 42 人工）。
- **SPA 慢挂载**：表单延迟渲染由探测重试覆盖（`--detect-timeout` 默认 10s 轮询）。
- **基础特征抹除**：默认禁用 AutomationControlled 并补丁 webdriver/plugins/languages——
  属基础特征级，非完整反风控；强对抗目标（瑞数类）如实登记 coverage，勿夸大能力。
- **有头调试**：容器内无 X 时可用 `xvfb-run -a /opt/venv/bin/python ... --headed`（xvfb 经 install_tool 安装）。
