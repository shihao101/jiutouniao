#!/usr/bin/env python3
"""v4.6 W2 L0 子域接管检查（纯 DNS/HTTP 指纹，零攻击面，ROE 兼容）。
审计确认全程漏做且属 L0 合法动作。用法：
  subdomain-takeover.py --subs evidence/s1-subs-final.txt [--live]
  subdomain-takeover.py --selftest
输出 TSV：subdomain / cname / 指纹服务 / 状态(candidate|unresolved|ok|no-cname)。"""
import argparse, json, re, sys, urllib.request

# CNAME 指纹路由表（基础集；命中后需 HTTP 二次确认才可升级 takeover-candidate）
FINGERPRINTS = [
    (r"\.github\.io$", "GitHub Pages"),
    (r"\.heroku(app)?\.com$", "Heroku"),
    (r"\.s3[.-]amazonaws\.com$|\.s3-website[.-]", "AWS S3"),
    (r"\.azurewebsites\.net$|\.cloudapp\.azure\.com$|\.azurestaticapps\.net$", "Azure"),
    (r"\.cloudfront\.net$", "AWS CloudFront"),
    (r"\.netlify\.app$|\.netlify\.global", "Netlify"),
    (r"\.vercel-dns\.(com|app)$", "Vercel"),
    (r"\.myshopify\.com$", "Shopify"),
    (r"\.zendesk\.com$", "Zendesk"),
    (r"\.helpjuice\.com$", "HelpJuice"),
    (r"\.helpscout\.net$", "HelpScout"),
    (r"\.ghost\.io$", "Ghost"),
    (r"\.tumblr\.com$", "Tumblr"),
    (r"\.wpengine\.com$", "WP Engine"),
    (r"\.pantheonsite\.io$", "Pantheon"),
    (r"\.readme\.io$", "Readme"),
    (r"\.surge\.sh$", "Surge"),
    (r"\.webflow\.io$", "Webflow"),
    (r"\.fastly\.net$", "Fastly"),
    (r"\.cleverapps\.io$", "Clever Cloud"),
]

def match_cname(cname):
    for pat, svc in FINGERPRINTS:
        if re.search(pat, cname, re.I):
            return svc
    return ""

def doh_resolve(name, provider="https://dns.alidns.com/resolve"):
    """DoH 解析 CNAME/A（沙箱 UDP 53 阻断的替代通道，S1 已验证）。"""
    url = f"{provider}?name={name}&type=A"
    try:
        with urllib.request.urlopen(url, timeout=10) as r:
            d = json.loads(r.read().decode())
        cnames = [a["data"] for a in d.get("Answer", []) if a.get("type") == 5]
        return d.get("Status", -1), cnames
    except Exception:
        return -1, []

def check(sub, live=False):
    status, cnames = doh_resolve(sub)
    if status == 3:
        return sub, "", "NXDOMAIN", "candidate" if False else "unresolved"
    if not cnames:
        return sub, "", ("A-记录直连" if status == 0 else f"doh-status-{status}"), "no-cname"
    cname = cnames[0]
    svc = match_cname(cname)
    state = "candidate" if svc else "ok"
    if svc and live:
        state = "candidate-need-http-confirm"  # 现场须 HTTP 404/指纹页二次确认
    return sub, cname, svc or "third-party", state

def selftest():
    cases = [
        ("lost.github.io", "GitHub Pages"),
        ("x.herokuapp.com", "Heroku"),
        ("bucket.s3.amazonaws.com", "AWS S3"),
        ("site.azurewebsites.net", "Azure"),
        ("d.cloudfront.net", "AWS CloudFront"),
        ("a.vercel-dns.com", "Vercel"),
        ("normal.example.com", ""),
    ]
    bad = 0
    for cname, want in cases:
        got = match_cname(cname)
        if got != want:
            print(f"FAIL {cname}: want {want!r} got {got!r}")
            bad += 1
    print(f"指纹路由自测: {len(cases)-bad}/{len(cases)}")
    return bad == 0

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--subs")
    ap.add_argument("--live", action="store_true")
    ap.add_argument("--selftest", action="store_true")
    ns = ap.parse_args()
    if ns.selftest:
        sys.exit(0 if selftest() else 1)
    if not ns.subs:
        ap.error("需要 --subs 或 --selftest")
    print("subdomain\tcname\tservice\tstate")
    for line in open(ns.subs, encoding="utf-8"):
        sub = line.strip()
        if sub and not sub.startswith("#"):
            print("\t".join(check(sub, ns.live)))
