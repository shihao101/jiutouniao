#!/usr/bin/env python3
"""v4.6 W3 Authz-Diff 差分扫描器（直连模式；判据与 authz-diff 技能/引擎 E3 语义对齐）。
用法：
  authz-diff.py --base http://t --endpoints eps.txt [--control /sys/login] [--out matrix.tsv] [--delay 2]
  authz-diff.py --selftest   # 起本地 canned 服务验证判读逻辑
输出 TSV：endpoint | class(HIT-DATA/HIT-REACH/MISS/UND) | status | bytes | body_snippet"""
import argparse, json, sys, threading, time, random, string
import urllib.request, urllib.error
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

CONTROL_BODY = '{"msg":"未知异常，请联系管理员","code":500}'
NEG_LEN = len('{"msg":"invalid token","code":401}')

def classify(status, blen, body, ctrl_body, ctrl_len):
    if status == 0:
        return "UND-TIMEOUT"
    if status in (401, 403):
        return "MISS"
    if body and "invalid token" in body:
        return "MISS"           # 200 包裹的鉴权拒绝体（renren 类网关行为）同样判 MISS
    if ctrl_body and body and body.strip() == ctrl_body.strip():
        return "HIT-REACH"      # 穿透网关到达控制器（缺参数异常，与阳性对照同形态）
    if status == 500:
        return "HIT-REACH?"
    if status == 200 and blen > 0:
        return "HIT-DATA"       # 200 + 非鉴权拒绝体 = 未鉴权数据访问候选
    return "MISS-OTHER"

def fetch(url, timeout=10):
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "jt-authz-diff/1.0"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.getcode(), r.read(4096).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read(4096).decode("utf-8", "replace")
    except Exception:
        return 0, ""

def run_scan(base, eps, control, delay, out):
    ctrl_status, ctrl_body = fetch(base + control)
    ctrl_len = len(ctrl_body)
    rows = []
    # v5.1.2 P1 修复：补技能强制的阴性对照——随机乱码路径 ×2（网关通配 200 时以
    # 体长/体内容区分，防 HIT-DATA 假阳性；authz-diff.md 第一节对照②口径）
    import random as _random
    neg_paths = ["/%s" % "".join(_random.choice("abcdefghijklmnopqrstuvwxyz0123456789") for _ in range(16)) + "/",
                 "/%s" % "".join(_random.choice("abcdefghijklmnopqrstuvwxyz0123456789") for _ in range(16)) + ".json"]
    neg_lens = []
    for np_ in neg_paths:
        nst, nbody = fetch(base + np_)
        neg_lens.append(len(nbody))
        rows.append((np_ + " [阴性对照]", "NEG-CTRL" if nst == 200 else f"NEG-{nst}", nst, len(nbody), nbody[:60].replace("\t", " ")))
        time.sleep(delay)
    neg_baseline = max(neg_lens) if neg_lens else 0
    wildcard_200 = all(len(n) > 0 for n in neg_lens) and neg_baseline > 0 and len(set(neg_lens)) <= 1
    for ep in eps:
        ep = ep.strip()
        if not ep or ep.startswith("#"):
            continue
        st, body = fetch(base + ep)
        # 通配 200 环境下：与阴性对照同形态的 200 判 MISS-WILDCARD（防假 HIT-DATA）
        if st == 200 and wildcard_200 and abs(len(body) - neg_baseline) < 32:
            cls = "MISS-WILDCARD"
        else:
            cls = classify(st, len(body), body, ctrl_body if ctrl_status == 500 else "", ctrl_len)
        rows.append((ep, cls, st, len(body), body[:60].replace("\t", " ")))
        time.sleep(delay)
    if out:
        with open(out, "w", encoding="utf-8") as f:
            f.write("endpoint\tclass\tstatus\tbytes\tbody_snippet\n")
            for r in rows:
                f.write("\t".join(map(str, r)) + "\n")
    hits = sum(1 for r in rows if r[1].startswith("HIT"))
    unds = sum(1 for r in rows if r[1].startswith("UND"))
    wc = "（⚠ 检测到网关通配 200 环境，已启用阴性对照分桶）" if wildcard_200 else ""
    print(f"[=] {len(rows)} 行（含 {len(neg_paths)} 阴性对照）：HIT {hits}（需同族复查）/ UND {unds}（needs_follow_up，不得 ruled_out）{wc}")
    return rows

# ---------- selftest：本地 canned 服务 ----------
class Mock(BaseHTTPRequestHandler):
    paths = {}
    def do_GET(self):
        for pfx, (code, body) in Mock.paths.items():
            if self.path.startswith(pfx):
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body.encode())))
                self.end_headers()
                self.wfile.write(body.encode())
                return
        self.send_response(404); self.end_headers()
    def log_message(self, *a): pass

def selftest():
    Mock.paths = {
        "/api/sys/login": (500, CONTROL_BODY),                    # 阳性对照（穿透形态）
        "/api/chargeRule/saveList": (500, CONTROL_BODY),          # HIT-REACH 模拟
        "/api/archPerson": (200, '{"total":24929,"rows":[1,2]}'),  # HIT-DATA 模拟
        "/api/sys/user/list": (200, '{"msg":"invalid token","code":401}'),  # 200+拒绝体=MISS
    }
    srv = ThreadingHTTPServer(("127.0.0.1", 0), Mock)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{port}"
    cs, cb = fetch(base + "/api/sys/login")
    eps = ["/api/chargeRule/saveList", "/api/archPerson", "/api/sys/user/list", "/api/ghost404"]
    bad = 0
    # UND：连接失败（status=0）纯断言（超时形态等价）
    if classify(0, 0, "", "", 0) != "UND-TIMEOUT":
        print("FAIL UND-TIMEOUT 纯断言"); bad += 1
    for ep, want in zip(eps, ["HIT-REACH", "HIT-DATA", "MISS", "MISS-OTHER"]):
        st, body = fetch(base + ep)
        got = classify(st, len(body), body, cb if cs == 500 else "", len(cb))
        mark = "PASS" if got == want else "FAIL"
        if got != want:
            bad += 1
        print(f"{mark} {ep}: want {want} got {got}")
    srv.shutdown()
    print(f"判读自测: {len(eps)-bad}/{len(eps)}")
    return bad == 0

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--base"); ap.add_argument("--endpoints")
    ap.add_argument("--control", default="/sys/login")
    ap.add_argument("--out"); ap.add_argument("--delay", type=float, default=2.0)
    ap.add_argument("--selftest", action="store_true")
    ns = ap.parse_args()
    if ns.selftest:
        sys.exit(0 if selftest() else 1)
    if not ns.base or not ns.endpoints:
        ap.error("需要 --base/--endpoints 或 --selftest")
    run_scan(ns.base, open(ns.endpoints, encoding="utf-8"), ns.control, ns.delay, ns.out)
