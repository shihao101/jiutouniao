// UI 真实浏览器 E2E：全页双主题截图 + console/page 错误收集（零硬编码目标数据）
// 用法: node scripts/ui-e2e/run.mjs <输出前缀> [路由逗号表] [dark|light|both]
// 环境变量: E2E_BASE(默认 http://localhost:8787) E2E_TOKEN(API 令牌/会话令牌) E2E_PROJECT(可选，项目编号) E2E_EXEC(chromium 路径)
import { chromium } from '../../web-app/node_modules/playwright-core/index.mjs';
import fs from 'node:fs';

const BASE = process.env.E2E_BASE || 'http://localhost:8787';
const TOKEN = process.env.E2E_TOKEN || '';
const PROJ = process.env.E2E_PROJECT || '';
const EXEC = process.env.E2E_EXEC || '/root/.cache/ms-playwright/chromium-1248/chrome-linux64/chrome';
if (!TOKEN) { console.error('FATAL: 缺 E2E_TOKEN'); process.exit(2); }

const OUT = process.argv[2] || '/tmp/ui-e2e/run';
const THEMES = (process.argv[4] || 'both') === 'both' ? ['dark', 'light'] : (process.argv[4] || 'both').split(',');
const ROUTES = (process.argv[3] || '/,/workbench,/findings,/assets,/devices,/timeline,/skills,/heads,/report,/settings,/changelog,/create').split(',').filter(Boolean);
fs.mkdirSync('/tmp/ui-e2e', { recursive: true });

const browser = await chromium.launch({ executablePath: EXEC, args: ['--no-sandbox'] });
const summary = { pages: [], consoleErrors: [], pageErrors: [] };
let ri = 0;
for (const theme of THEMES) {
  const ctx = await browser.newContext({ viewport: { width: 1600, height: 900 } });
  const page = await ctx.newPage();
  page.on('console', m => { if (m.type() === 'error') summary.consoleErrors.push(`[${theme}] ${page.url()} :: ${m.text()}`); });
  page.on('pageerror', e => summary.pageErrors.push(`[${theme}] ${page.url()} :: ${e.message}`));
  await page.goto(`${BASE}/#/login`, { waitUntil: 'domcontentloaded' });
  await page.evaluate(([tok, th, pj]) => {
    sessionStorage.setItem('jt_session', tok); sessionStorage.setItem('jt_user', 'admin');
    localStorage.setItem('jt_theme', th);
    if (pj) localStorage.setItem('jt_last_project', pj);
  }, [TOKEN, theme, PROJ]);
  for (const r of ROUTES) {
    ri++;
    await page.goto(`${BASE}/?_p=${theme}-${ri}#${r}`, { waitUntil: 'domcontentloaded' });
    await page.waitForTimeout(600);
    await page.evaluate(rr => { location.hash = '#' + rr }, r);
    await page.waitForTimeout(1100);
    const file = `${OUT}-${theme}${r.replaceAll('/', '_')}.png`;
    await page.screenshot({ path: file });
    summary.pages.push({ theme, route: r, url: page.url() });
  }
  await ctx.close();
}
await browser.close();
fs.writeFileSync(`${OUT}-summary.json`, JSON.stringify(summary, null, 2));
console.log(`E2E：${summary.pages.length} 页；console 错误 ${summary.consoleErrors.length}；page 错误 ${summary.pageErrors.length}`);
if (summary.consoleErrors.length || summary.pageErrors.length) { console.log(JSON.stringify({ c: summary.consoleErrors.slice(0, 3), p: summary.pageErrors.slice(0, 3) })); process.exit(1); }
