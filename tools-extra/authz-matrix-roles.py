#!/usr/bin/env python3
"""v5.4.5 端点级多角色授权矩阵（BFLA 机械化；判据与 api-idor 角色矩阵节/authz-diff 对齐）。
用法：
  authz-matrix-roles.py --base http://t --endpoints eps.txt \
      --role anon: --role low:"Authorization: Bearer XXX" --role high:"Authorization: Bearer YYY" \
      [--method POST --data @body.json --header "X-CSRF-Token: abc" --out matrix-roles.tsv --delay 1]
  authz-matrix-roles.py --selftest   # 起本地 canned 服务验证判读逻辑
首个角色视为匿名/最低权参照，末个角色为高权参照。
v5.6.0：--method/--data/--header（全局头）+ 角色值支持 || 多头（Cookie+CSRF 双头）——
带态矩阵不再限于 GET 单头；凭据经 cred_command 模板或 http_request 均可先取证再喂给本脚本。
输出 TSV：endpoint | admin_path | anon | low | high | classification
分类：
  OPEN-200   全角色同 200 同体（匿名直达——转 authz-diff finding）
  EQUAL-200  低权与高权同 200 同体（BFLA 候选——admin_path=Y 时强信号，需人工核对端点归属）
  TIERED     角色间响应分层（正常）
  GATED      全角色 ≥400（门控一致，negative_valid）
  UND        超时/非 HTTP（needs_follow_up，不得 ruled_out）"""
import argparse, hashlib, json, sys, threading, time
import urllib.request, urllib.error
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ADMIN_PATH_RE = __import__("re").compile(r"/(admin|manage|console|backend|sys)/", __import__("re").I)


def classify(statuses, bodies, anon_first=True):
    """statuses/bodies: 各角色 (status, body) 列表，顺序=角色顺序。
    v5.6.1：anon_first（默认 True）=首角色为匿名参照——全 200 同体判 OPEN-200（匿名直达）；
    --no-anon-first（首角色=最低权认证用户）时，相邻低权 vs 高权同 200 同体判 EQUAL-200，
    双角色（low/high 最常见形态）不再漏报（审计缺陷#16）。"""
    sts = [s for s, _ in statuses]
    if any(s == 0 for s in sts):
        return "UND"
    if all(s >= 400 for s in sts):
        return "GATED"
    if anon_first and all(s == 200 for s in sts):
        sigs = {hashlib.md5(b.encode("utf-8", "replace")).hexdigest()[:8] for _, b in statuses}
        return "OPEN-200" if len(sigs) == 1 else "TIERED"
    low_sig = hashlib.md5(statuses[-2][1].encode("utf-8", "replace")).hexdigest()[:8] if len(statuses) >= 2 else None
    high_sig = hashlib.md5(statuses[-1][1].encode("utf-8", "replace")).hexdigest()[:8]
    if (len(statuses) >= 2 and statuses[-2][0] == 200 and statuses[-1][0] == 200
            and low_sig == high_sig):
        return "EQUAL-200"
    return "TIERED"


def fetch(url, headers, timeout=10, method="GET", data=None):
    """v5.6.0：支持任意方法与请求体（POST/PUT 端点矩阵；data 为 bytes 或 None）。"""
    try:
        req = urllib.request.Request(url, headers=headers or {"User-Agent": "jt-authz-roles/1.0"},
                                     data=data, method=method)
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.getcode(), r.read(8192).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read(8192).decode("utf-8", "replace")
    except Exception:
        return 0, ""


def parse_role_headers(spec):
    """v5.6.0 角色头解析：支持 || 分隔多头（如 Cookie+CSRF 双头）；'名: 值' 按首个冒号切分。"""
    out = {}
    for part in (spec or "").split("||"):
        part = part.strip()
        if not part:
            continue
        i = part.find(":")
        if i > 0:
            out[part[:i].strip()] = part[i + 1:].strip()
    return out


def run(base, eps, roles, out, delay, method="GET", data=None, extra_headers=None, anon_first=True):
    roles_order = [name for name, _ in roles]
    rows, counts = [], {"OPEN-200": 0, "EQUAL-200": 0, "TIERED": 0, "GATED": 0, "UND": 0}
    for ep in eps:
        ep = ep.strip()
        if not ep or ep.startswith("#"):
            continue
        results = []
        for _, hdr in roles:
            merged = {"User-Agent": "jt-authz-roles/1.0", **(extra_headers or {}), **hdr}
            st, body = fetch(base + ep, merged, method=method, data=data)
            results.append((st, body))
            time.sleep(delay)
        cls = classify(results, roles_order, anon_first=anon_first)
        counts[cls] += 1
        admin = "Y" if ADMIN_PATH_RE.search(ep) else "-"
        sigs = [f"{n}:{s}:{hashlib.md5(b.encode('utf-8','replace')).hexdigest()[:6]}"
                for (s, b), n in zip(results, roles_order)]
        rows.append((ep, admin, "\t".join(sigs), cls))
        if cls in ("OPEN-200", "EQUAL-200"):
            print(f"[!] {cls} {ep}（admin_path={admin}）——需人工核对端点归属与数据必要性")
    if out:
        with open(out, "w", encoding="utf-8") as f:
            f.write("endpoint\tadmin_path\trole:status:sig\tclassification\n")
            for r in rows:
                f.write("\t".join(map(str, r)) + "\n")
    print(f"[=] {len(rows)} 端点 × {len(roles_order)} 角色：OPEN-200={counts['OPEN-200']}（转 authz-diff） "
          f"EQUAL-200={counts['EQUAL-200']}（BFLA 候选） TIERED={counts['TIERED']} GATED={counts['GATED']} UND={counts['UND']}（needs_follow_up）")
    print("[i] EQUAL-200 行做同族复查（api-idor BFLA 节：确认端点本应高权专属）后再 record_finding")
    return rows


# ---------- selftest：本地 canned 服务 ----------
class Mock(BaseHTTPRequestHandler):
    def do_GET(self):
        auth = self.headers.get("Authorization", "")
        tier = "high" if "high" in auth else ("low" if "low" in auth else "anon")
        table = {
            "/admin/users": {"anon": (401, '{"msg":"denied"}'), "low": (200, '{"users":["a"]}'),
                             "high": (200, '{"users":["a"]}')},          # EQUAL-200（admin_path）
            "/user/me": {"anon": (401, '{"msg":"denied"}'), "low": (200, '{"role":"user"}'),
                         "high": (200, '{"role":"admin"}')},             # TIERED
            "/public/info": {"anon": (200, '{"v":1}'), "low": (200, '{"v":1}'),
                             "high": (200, '{"v":1}')},                  # OPEN-200
            "/api/secret": {"anon": (403, "{}"), "low": (403, "{}"),
                            "high": (403, "{}")},                        # GATED
        }
        entry = table.get(self.path)
        if entry is None:
            st, body = 404, "not found"
        else:
            st, body = entry.get(tier, (404, "not found"))
        b = body.encode()
        self.send_response(st)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def log_message(self, *a): pass


def selftest():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), Mock)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{port}"
    roles = [("anon", {}), ("low", {"Authorization": "low"}), ("high", {"Authorization": "high"})]
    # 直接取 (status, body) 对做纯函数断言
    res = {p: [fetch(base + p, h) for _, h in roles] for p in
           ["/admin/users", "/user/me", "/public/info", "/api/secret"]}
    expect = {"/admin/users": "EQUAL-200", "/user/me": "TIERED", "/public/info": "OPEN-200", "/api/secret": "GATED"}
    bad = 0
    for p, want in expect.items():
        c = classify(res[p], [b for _, b in res[p]])
        mark = "PASS" if c == want else "FAIL"
        if c != want:
            bad += 1
        print(f"{mark} {p}: want {want} got {c}")
    if classify([(0, ""), (0, ""), (0, "")], ["", "", ""]) != "UND":
        print("FAIL UND 纯断言"); bad += 1
    # v5.6.1：双角色 low/high 同 200 同体 → EQUAL-200（审计缺陷#16 修复锁定）
    two = classify([(401, '{"m":"d"}'), (200, '{"users":["a"]}')], ["anon", "high"])
    if two != "TIERED":
        print("FAIL 双角色 anon401/high200 应 TIERED:", two); bad += 1
    two_eq = classify([(200, '{"users":["a"]}'), (200, '{"users":["a"]}')], ["low", "high"], anon_first=False)
    if two_eq != "EQUAL-200":
        print("FAIL 双角色同 200 同体(--no-anon-first)应 EQUAL-200:", two_eq); bad += 1
    two_open = classify([(200, '{"v":1}'), (200, '{"v":1}')], ["anon", "high"])
    if two_open != "OPEN-200":
        print("FAIL 匿名参照同 200 同体应 OPEN-200:", two_open); bad += 1
    srv.shutdown()
    print(f"判读自测: {8-bad}/8")
    return bad == 0


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--base"); ap.add_argument("--endpoints")
    ap.add_argument("--role", action="append", default=[],
                    help='角色:头。格式 name:"Header: value"（多头用 || 分隔，如 Cookie+CSRF 双头；首个=匿名/最低权参照，末个=高权参照）')
    ap.add_argument("--header", action="append", default=[],
                    help="全局附加头（全部角色共享，可重复，如 CSRF 头）格式 '名: 值'")
    ap.add_argument("--method", default="GET", help="v5.6.0：矩阵请求方法（GET/POST/PUT/…）")
    ap.add_argument("--data", help="v5.6.0：请求体（内联串或 @file 路径；全部角色共用同一请求体）")
    ap.add_argument("--content-type", default="application/x-www-form-urlencoded")
    ap.add_argument("--no-anon-first", dest="anon_first", action="store_false",
                    help="v5.6.1：首角色不是匿名参照而是最低权认证用户（low/high 双角色矩阵必选，否则同 200 会误判 OPEN-200）")
    ap.add_argument("--out"); ap.add_argument("--delay", type=float, default=1.0)
    ap.add_argument("--selftest", action="store_true")
    ns = ap.parse_args()
    if ns.selftest:
        sys.exit(0 if selftest() else 1)
    if not ns.base or not ns.endpoints or len(ns.role) < 2:
        ap.error("需要 --base/--endpoints/--role（至少两个角色）或 --selftest")
    roles = []
    for spec in ns.role:
        name, _, hdr = spec.partition(":")
        # v5.6.0：角色值支持 || 多头
        headers = parse_role_headers(hdr)
        roles.append((name or f"role{len(roles)}", headers))
    extra = {}
    for h in ns.header or []:
        k, _, v = h.partition(":")
        if k.strip():
            extra[k.strip()] = v.strip()
    data = None
    if ns.data:
        if ns.data.startswith("@"):
            with open(ns.data[1:], "rb") as f:
                data = f.read()
        else:
            data = ns.data.encode("utf-8")
        extra.setdefault("Content-Type", ns.content_type)
    run(ns.base, open(ns.endpoints, encoding="utf-8"), roles, ns.out, ns.delay,
        method=ns.method.upper(), data=data, extra_headers=extra, anon_first=ns.anon_first)
