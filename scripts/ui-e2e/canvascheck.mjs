// UI 图表实例化计数（仪表盘 3 / 发现页 1；零硬编码目标数据）
// 环境变量: E2E_BASE E2E_TOKEN E2E_PROJECT E2E_EXEC
import { chromium } from '../../web-app/node_modules/playwright-core/index.mjs';

const BASE = process.env.E2E_BASE || 'http://localhost:8787';
const TOKEN = process.env.E2E_TOKEN || '';
const PROJ = process.env.E2E_PROJECT || '';
const EXEC = process.env.E2E_EXEC || '/root/.cache/ms-playwright/chromium-1248/chrome-linux64/chrome';
if (!TOKEN || !PROJ) { console.error('FATAL: 缺 E2E_TOKEN 或 E2E_PROJECT'); process.exit(2); }
const browser = await chromium.launch({ executablePath: EXEC, args: ['--no-sandbox'] });
const page = await browser.newPage({ viewport: { width: 1600, height: 900 } });
await page.goto(`${BASE}/#/login`, { waitUntil: 'domcontentloaded' });
await page.evaluate(([tok, pj]) => {
  sessionStorage.setItem('jt_session', tok); sessionStorage.setItem('jt_user', 'admin');
  localStorage.setItem('jt_theme', 'dark'); localStorage.setItem('jt_last_project', pj);
}, [TOKEN, PROJ]);
for (const [name, route, expect] of [['dashboard', '/', 3], ['findings', '/findings', 1]]) {
  await page.goto(`${BASE}/?c=${name}#${route}`, { waitUntil: 'domcontentloaded' });
  await page.waitForTimeout(700);
  await page.evaluate(rr => { location.hash = '#' + rr }, route);
  await page.waitForTimeout(1400);
  const n = await page.evaluate(() => document.querySelectorAll('canvas').length);
  console.log(`${name}: canvas 数 = ${n}（期望 ≥${expect}）`);
  if (n < expect) { console.error('图表实例化不足'); await browser.close(); process.exit(1); }
}
await browser.close();
