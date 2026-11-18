#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""更新记录同源校验门（CHANGELOG.md ↔ web-app/src/pages/ChangelogPage.vue）。

单一事实源口径（CHANGELOG.md 头部）：
  「与 Web 控制台『更新记录』页同源」+「每次发版必须递增 version.go 的 App 常量并在两处补记录」。
  本门校验三件事：
  ① 两个文件中的版本条目集合一致（含顺序）；
  ② 每个版本的 date 与 items 文本逐条一致；
  ③ 两处版本中最大者 == server/internal/version/version.go 的 App 常量。

用法：python3 scripts/changelog_sync_check.py   （退出码 0=一致；1=漂移）
建议接线：make ui-check / CI。
"""
import os
import re
import sys

ROOT = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
MD = os.path.join(ROOT, "CHANGELOG.md")
VUE = os.path.join(ROOT, "web-app", "src", "pages", "ChangelogPage.vue")
VER = os.path.join(ROOT, "server", "internal", "version", "version.go")

VER_HEAD = re.compile(r"^## (v[\d.]+(?:-v[\d.]+)?) · (\d{4}-\d{2}-\d{2})\s*$", re.M)
VUE_HEAD = re.compile(r"\{\s*v:\s*'(v[\d.]+(?:-v[\d.]+)?)',\s*date:\s*'(\d{4}-\d{2}-\d{2})',\s*items:\s*\[(.*?)\]\}", re.S)
ITEM = re.compile(r"^\s*-\s+(.+?)\s*$", re.M)


def parse_md(text):
    """CHANGELOG.md → [(version, date, [item...])]（按文件顺序）。"""
    heads = list(VER_HEAD.finditer(text))
    out = []
    for i, m in enumerate(heads):
        end = heads[i + 1].start() if i + 1 < len(heads) else len(text)
        body = text[m.end():end]
        items = ITEM.findall(body)
        out.append((m.group(1), m.group(2), [re.sub(r"\s+", " ", it).strip() for it in items]))
    return out


def parse_vue(text):
    """ChangelogPage.vue CHANGELOG 数组 → [(version, date, [item...])]。"""
    out = []
    for m in VUE_HEAD.finditer(text):
        raw_items = re.findall(r"'((?:[^'\\]|\\.)*)'", m.group(3))
        out.append((m.group(1), m.group(2), [it.strip() for it in raw_items if it.strip()]))
    return out


def norm_items(items):
    """宽松归一：全角/半角空格与不可见差异容忍，但文本本体必须一致。"""
    return [re.sub(r"\s+", " ", it).strip() for it in items]


def main():
    md = parse_md(open(MD, encoding="utf-8").read())
    vue = parse_vue(open(VUE, encoding="utf-8").read())
    problems = []

    md_map = {v: (d, items) for v, d, items in md}
    vue_map = {v: (d, items) for v, d, items in vue}
    if [v for v, _, _ in md] != [v for v, _, _ in vue]:
        only_md = [v for v, _, _ in md if v not in vue_map]
        only_vue = [v for v, _, _ in vue if v not in md_map]
        problems.append(f"版本条目集合不一致：md 独有={only_md} vue 独有={only_vue}（或顺序不同）")
    for v, d, items in md:
        if v not in vue_map:
            continue
        vd, vitems = vue_map[v]
        if d != vd:
            problems.append(f"{v} 日期漂移：md={d} vue={vd}")
        if norm_items(items) != norm_items(vitems):
            problems.append(f"{v} items 文本漂移：md {len(items)} 条 vs vue {len(vitems)} 条")
            for a, b in zip(norm_items(items), norm_items(vitems)):
                if a != b:
                    problems.append(f"  md:   {a[:90]}")
                    problems.append(f"  vue:  {b[:90]}")
            break

    # 版本常量对账：两处最新版本必须等于 version.go 的 App
    ver_text = open(VER, encoding="utf-8").read()
    m = re.search(r'const App = "([\d.]+)"', ver_text)
    app = m.group(1) if m else None
    latest_md = md[0][0].lstrip("v") if md else None
    if app and latest_md and app != latest_md:
        problems.append(f"版本常量漂移：version.go App={app}，两处记录最新条目={latest_md}（每次发版必须递增 App）")

    if problems:
        print("FAIL 更新记录同源校验：")
        for p in problems:
            print("  -", p)
        return 1
    print(f"OK 更新记录同源校验：md 与 vue 各 {len(md)} 版一致；version.go App={app} 对齐")
    return 0


if __name__ == "__main__":
    sys.exit(main())
