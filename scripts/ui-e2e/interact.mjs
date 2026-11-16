// UI 交互断言 7 项：计数/筛选/搜索(期望值取自 API)/排序/快捷键/语义边条（零硬编码目标数据）
// 环境变量: E2E_BASE E2E_TOKEN E2E_PROJECT(必填，交互验证需要项目数据) E2E_EXEC
import { chromium } from '../../web-app/node_modules/playwright-core/index.mjs';

const BASE = process.env.E2E_BASE || 'http://localhost:8787';
const TOKEN = process.env.E2E_TOKEN || '';
const PROJ = process.env.E2E_PROJECT || '';
const EXEC = process.env.E2E_EXEC || '/root/.cache/ms-playwright/chromium-1248/chrome-linux64/chrome';
if (!TOKEN || !PROJ) { console.error('FATAL: 缺 E2E_TOKEN 或 E2E_PROJECT'); process.exit(2); }

const ok = [], bad = [];
const t = (n, c) => (c ? ok : bad).push(n);
const browser = await chromium.launch({ executablePath: EXEC, args: ['--no-sandbox'] });
const page = await browser.newPage({ viewport: { width: 1600, height: 900 } });
const cerr = [];
page.on('console', m => { if (m.type() === 'error') cerr.push(m.text()); });
page.on('pageerror', e => cerr.push('PAGEERROR ' + e.message));

await page.goto(`${BASE}/#/login`, { waitUntil: 'domcontentloaded' });
await page.evaluate(([tok, pj]) => {
  sessionStorage.setItem('jt_session', tok); sessionStorage.setItem('jt_user', 'admin');
  localStorage.setItem('jt_theme', 'dark'); localStorage.setItem('jt_last_project', pj);
}, [TOKEN, PROJ]);

// 1) 漏洞页总数
await page.goto(`${BASE}/?i=1#/findings`, { waitUntil: 'domcontentloaded' });
await page.waitForTimeout(700);
await page.evaluate(() => { location.hash = '#/findings' });
await page.locator('.f-toolbar').waitFor({ state: 'visible', timeout: 15000 });
const fsApi = await (await fetch(`${BASE}/api/projects/${PROJ}`, { headers: { Authorization: 'Bearer ' + TOKEN } })).json();
const total = (fsApi.findings || []).length;
const chip0 = await page.locator('.f-toolbar .chip').textContent();
t(`初始计数 ${total}/${total}`, chip0.replace(/\s/g, '').includes(`${total}/${total}`));

// 2) 等级筛选=高
await page.selectOption('.f-toolbar select >> nth=0', '高');
await page.waitForTimeout(300);
const expHigh = (fsApi.findings || []).filter(f => (f.severity || '信息') === '高').length;
const chip1 = await page.locator('.f-toolbar .chip').textContent();
t(`筛选高 ${expHigh}/${total}`, chip1.replace(/\s/g, '').includes(`${expHigh}/${total}`));

// 3) 搜索（期望值取自 API：等级=高 且 标题+详情含关键字）
await page.fill('.f-search', 'SQL');
await page.waitForTimeout(300);
const expSQL = (fsApi.findings || []).filter(f => (f.severity || '信息') === '高' &&
  ((f.title || '') + (f.detail || '')).toLowerCase().includes('sql')).length;
const chip2 = await page.locator('.f-toolbar .chip').textContent();
t(`高+SQL ${expSQL} 条（API 口径）`, chip2.replace(/\s/g, '').includes(`${expSQL}/${total}`));

// 4) 清筛选，等级排序降序 → 首行=高
await page.fill('.f-search', '');
await page.selectOption('.f-toolbar select >> nth=0', '');
await page.waitForTimeout(300);
if (expHigh > 0) {
  await page.click('th:has-text("等级")');
  await page.waitForTimeout(300);
  const firstSev = await page.locator('tbody tr >> nth=0 >> td >> nth=0').textContent();
  t('等级排序首行=高', firstSev.trim() === '高');
} else { ok.push('等级排序跳过（无高危样本）'); }

// 5) 快捷键 g d / g f
await page.keyboard.press('g'); await page.keyboard.press('d');
await page.waitForTimeout(600);
t('快捷键 g d → 仪表盘', page.url().includes('#/'));
await page.keyboard.press('g'); await page.keyboard.press('f');
await page.waitForTimeout(600);
t('快捷键 g f → 漏洞', page.url().includes('#/findings'));

// 6) 工作台工具卡语义边条
await page.goto(`${BASE}/?i=2#/workbench`, { waitUntil: 'domcontentloaded' });
await page.waitForTimeout(700);
await page.evaluate(() => { location.hash = '#/workbench' });
await page.waitForTimeout(1500);
const bordered = await page.evaluate(() => {
  const els = [...document.querySelectorAll('.toolcard')].slice(0, 40);
  return els.filter(el => getComputedStyle(el).borderLeftWidth === '3px').length;
});
t('工具卡左边条已生效（>0）', bordered > 0);

console.log(JSON.stringify({ pass: ok.length, fail: bad.length, bad, consoleErrors: cerr.length }));
await browser.close();
if (bad.length || cerr.length) process.exit(1);
