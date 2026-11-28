#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""specB2 沙箱原语标准件（v7.8.0 优化⑥）"""
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

PROBE_TEMPLATES = {
    "crypto_deterministic": {"desc": "加解密确定性", "targets": ["encryptByAes", "decryptByAes", "encryptByDes", "decryptByDes", "sign", "md5", "sha256"]},
    "toWebView": {"desc": "web-view URL 构造", "targets": ["toWebView", "menuUrlReplace", "setUrl", "navigateTo"]},
    "postMessage": {"desc": "postMessage 桥接", "targets": ["postMessage", "onMessage"]},
    "storage_keys": {"desc": "存储键枚举", "targets": ["setStorageSync", "getStorageSync", "token", "openId", "userInfo"]},
    "auth_flow": {"desc": "登录态构造", "targets": ["code2Session", "session_key", "wx.login"]},
    "price_calc": {"desc": "金额计算", "targets": ["tPrice", "price", "amount", "totalPrice"]},
    "hidden_pages": {"desc": "隐藏页路由", "targets": ["navigateTo", "redirectTo", "switchTab"]},
    "url_append": {"desc": "URL 参数拼接", "targets": ["?token=", "&token=", "?sessionId="]},
}

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--bundle", required=True)
    ap.add_argument("--out", default="")
    args = ap.parse_args()
    src = open(args.bundle, encoding="utf-8", errors="replace").read()
    mods = extract_modules(src)
    results = {"bundle": args.bundle, "modules_total": len(mods), "probes": [], "summary": {}}
    for mod in mods:
        body = src[mod["start"]:mod["end"]]
        for pname, pconf in PROBE_TEMPLATES.items():
            hits = {t: len(re.findall(re.escape(t), body)) for t in pconf["targets"]}
            hits = {t: n for t, n in hits.items() if n > 0}
            if hits:
                results["probes"].append({"module": mod["path"], "probe": pname, "targets_hit": hits, "total_refs": sum(hits.values())})
    for p in results["probes"]:
        results["summary"][p["probe"]] = results["summary"].get(p["probe"], 0) + p["total_refs"]
    output = json.dumps(results, ensure_ascii=False, indent=2)
    if args.out:
        os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
        open(args.out, "w", encoding="utf-8").write(output)
        print(f"沙箱探针完成：{len(results['probes'])} 命中 → {args.out}")
    else:
        print(output)

if __name__ == "__main__":
    main()
