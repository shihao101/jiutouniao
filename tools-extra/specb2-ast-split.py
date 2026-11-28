#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""specB2 AST 模块切分（v7.8.0 优化①）"""
import argparse, json, os, re, sys

def extract_modules(src):
    """define() match positions as module boundaries (next define = current end).
    Approximate but O(n) zero-recursion — sufficient for audit probe search."""
    pat = re.compile(r'define\("([^"]+)",\s*function\s*\(([^)]*)\)\s*\{')
    matches = list(pat.finditer(src))
    mods = []
    for i, m in enumerate(matches):
        start = m.end()
        end = matches[i + 1].start() if i + 1 < len(matches) else len(src)
        mods.append({"path": m.group(1), "start": start, "end": end})
    return mods

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--bundle", required=True)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()
    src = open(args.bundle, encoding="utf-8", errors="replace").read()
    mods = extract_modules(src)
    os.makedirs(args.out, exist_ok=True)
    index = {"bundle": args.bundle, "modules_total": len(mods), "modules": []}
    for mod in mods:
        safe = mod["path"].replace("/", "_") + ".js"
        open(os.path.join(args.out, safe), "w", encoding="utf-8").write(
            f'// 模块: {mod["path"]}\n// 来源: {args.bundle}（v7.8.0 AST 切分）\n\n' + src[mod["start"]:mod["end"]])
        index["modules"].append({"path": mod["path"], "file": safe, "bytes": mod["end"] - mod["start"]})
    open(os.path.join(args.out, "_index.json"), "w", encoding="utf-8").write(json.dumps(index, ensure_ascii=False, indent=2))
    print(f"模块切分完成：{len(mods)} 个 → {args.out}/")

if __name__ == "__main__":
    main()
