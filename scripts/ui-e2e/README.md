# UI 真实浏览器 E2E 套件（Playwright-core + 本机 Chromium，零硬编码目标数据）

环境变量（全部经环境注入，脚本内不含任何真实项目/目标信息）：
- E2E_BASE：实例地址（默认 http://localhost:8787）
- E2E_TOKEN：API 令牌或会话令牌（后端 checkToken 认可）
- E2E_PROJECT：交互/图表验证所需的项目编号（可选）
- E2E_EXEC：Chromium 可执行路径（默认 ~/.cache/ms-playwright 下）

运行：
- `E2E_TOKEN=xx E2E_PROJECT=yy node scripts/ui-e2e/run.mjs /tmp/out "" both`   # 全页双主题截图+错误收集
- `E2E_TOKEN=xx E2E_PROJECT=yy node scripts/ui-e2e/interact.mjs`              # 交互断言 7 项
- `E2E_TOKEN=xx E2E_PROJECT=yy node scripts/ui-e2e/canvascheck.mjs`           # 图表实例化计数（仪表盘 3/发现页 1）

口径：console/page 错误必须为 0；UI 改动交付前必过（v3.7.3 白屏教训——构建绿灯可能是假阴性，真实浏览器是唯一拦截手段）。
隔离实例建议（不动生产容器）：复制 config.json 改 listen=127.0.0.1:8788 + data_dir 副本 + debug_captcha=true（联调开关，验证后必须回 false）。
