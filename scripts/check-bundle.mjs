#!/usr/bin/env node
// P3 打包体积预算守卫：超阈值 exit 1（CI/发版前必过）
import fs from 'node:fs';
import path from 'node:path';
import zlib from 'node:zlib';
const dist = process.argv[2] || path.join(process.cwd(), 'dist', 'assets');
const BUDGETS = { 'index': 75 * 1024, '*': 200 * 1024 }; // gzip 阈值：主包 75K（i18n+图标后实值 ~66K），单 chunk 200K
let fail = 0;
for (const f of fs.readdirSync(dist).filter(x => x.endsWith('.js'))) {
  const gz = zlib.gzipSync(fs.readFileSync(path.join(dist, f))).length;
  const name = f.split('-')[0];
  const budget = BUDGETS[name] ?? BUDGETS['*'];
  const over = gz > budget;
  if (over) fail++;
  console.log(`${over ? 'OVER ' : 'ok   '}${f} gzip=${(gz / 1024).toFixed(1)}K 预算=${(budget / 1024).toFixed(0)}K`);
}
process.exit(fail ? 1 : 0);
