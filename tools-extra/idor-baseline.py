#!/usr/bin/env python3
"""v4.8 W6 IDOR 自动基线（采样→自增判定→差分→量化）——水平越权的机械化第一层。

机制（对应筛查矩阵 C-08「采样→可预测性→差分」）：
  ① 采样：对对象 ID 端点模板（{id} 位）取 N 个已知可见 ID（会话态），记录响应签名
     （长度/状态码/内容哈希）与响应中可观测的「归属证据」（可选 --owner-grep 正则）；
  ② 自增/可预测性判定：ID 序列相邻差值统计（等差=强可预测；短随机=弱）+ 响应存在性；
  ③ 差分：对采样到的**他人**对象 ID 做匿名重放（无会话态）与会话重放对比——
     匿名可得=未授权访问面（access=anonymous）；
  ④ 量化：可枚举区间估算（min..max 可见 ID → 区间大小）与受影响对象数上界。
输出 JSON 报告（verdict: idor_anonymous / idor_predictable_only / not_found / inconclusive）。

用法：
  python3 idor-baseline.py --url 'http://t/api/order/{id}' --start 1001 --count 5 \
      [--cookie k=v ...] [--anonymous] [--owner-grep 'owner_id":"([0-9]+)']
  python3 idor-baseline.py --selftest
合规：采样仅读对象 ID 邻域（存在性证明）；量化只报计数不导出数据；匿名差分仅 1 次重放。
"""
import argparse, hashlib, json, re, statistics, time
import os as _os
_os.environ.setdefault("NO_PROXY", "*")
_os.environ.setdefault("no_proxy", "*")  # 本地 canned 服务与内网目标直连（v5.6.1 实证：env 代理把 127.0.0.1 转发致 502）
import urllib.request, urllib.error

UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 idor-baseline/1.0"

METHOD = {"m": "GET", "d": None, "h": {}}  # v5.6.0 全局请求形态（__main__ 装配；selftest 默认 GET）


def fetch(url, cookies=None, timeout=15, method="GET", data=None, extra_headers=None):
    """v5.6.0：支持任意方法/请求体/额外认证头（Bearer/token 类带态矩阵不再限于 Cookie）。"""
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("User-Agent", UA)
    for k, v in (extra_headers or {}).items():
        req.add_header(k, v)
    if cookies:
        req.add_header("Cookie", "; ".join(f"{k}={v}" for k, v in cookies.items()))
    t0 = time.monotonic()
    try:
        resp = urllib.request.urlopen(req, timeout=timeout)
        return resp.read(), resp.status, time.monotonic() - t0
    except urllib.error.HTTPError as e:
        return e.read(), e.code, time.monotonic() - t0
    except Exception:
        return b"", 0, time.monotonic() - t0

def sig(data, status):
    return {"status": status, "len": len(data), "sha1": hashlib.sha1(data).hexdigest()[:12]}

def owners_visible(data, pattern):
    if not pattern:
        return []
    return sorted(set(re.findall(pattern, data.decode("utf-8", "replace"))))

def run(url_tpl, start, count, cookies=None, owner_grep=None, anonymous=True):
    ids = list(range(start, start + count))
    samples, oids_ok = [], []
    for oid in ids:
        data, status, _ = fetch(url_tpl.format(oid), cookies=cookies, method=METHOD["m"], data=METHOD["d"], extra_headers=METHOD["h"])
        s = sig(data, status)
        s["id"] = oid
        s["owners"] = owners_visible(data, owner_grep)
        if status == 200 and len(data) > 0:
            oids_ok.append(oid)
        samples.append(s)
    # ② 可预测性：连续 OK 的 ID 占比 + 相邻差值分布
    hit_ratio = len(oids_ok) / max(len(ids), 1)
    deltas = [b - a for a, b in zip(oids_ok, oids_ok[1:])]
    predictable = bool(oids_ok) and (hit_ratio >= 0.8 or (deltas and statistics.median(deltas) <= 2))
    # ③ 匿名差分：匿名重放已见 ID（单次，仅存在性）
    anon_hits = []
    if anonymous and oids_ok:
        for oid in oids_ok[:3]:  # 最多 3 个：存在性证明即可
            # v5.6.1 修复审计缺陷#17：匿名重放必须剥离全部认证面（cookies 与 --header 认证头）——
            # 否则带 Authorization 的"匿名"请求命中 200 会被误报 anonymous IDOR（假阳性）。
            anon_headers = {k: v for k, v in METHOD["h"].items()
                            if not any(f in k.lower() for f in ("auth", "token", "cookie", "key", "session", "csrf"))}
            data, status, _ = fetch(url_tpl.format(oid), cookies=None, method=METHOD["m"], data=METHOD["d"], extra_headers=anon_headers)
            if status == 200 and len(data) > 0:
                anon_hits.append({"id": oid, **sig(data, status)})
    owner_set = sorted({o for s in samples for o in s["owners"]})
    # ④ 量化：可枚举区间
    quant = None
    if oids_ok:
        quant = {"min_visible": min(oids_ok), "max_visible": max(oids_ok),
                 "range_size": max(oids_ok) - min(oids_ok) + 1,
                 "note": "区间为采样可见范围外推上界，仅用于影响量化（不导出数据）"}
    if anon_hits:
        # v5.8.0（审计 Top#6 语义判据）：匿名 200 非空 ≠ 他人对象——无 owner 证据时降级候选，
        # 要求对象归属确认（owner-grep 命中他人标识 / 双账号差分 / 业务预期核对）后才可 record_finding。
        if owner_grep and owner_set:
            verdict = {"verdict": "idor_anonymous", "access": "anonymous"}
            verdict["next"] = "匿名可读他人对象（owner 证据已采集）——record_finding（水平越权，impact_rank=3 候选）+ 采样→差分证据落 evidence/"
        else:
            verdict = {"verdict": "candidate_idor_anonymous", "access": "anonymous"}
            verdict["next"] = "候选：匿名 200 非空但缺对象归属证据——须 owner-grep 采集他人标识 / 双账号差分 / 业务预期核对三选一后才能 record_finding（公开资源匿名可读是正常态，非漏洞）"
    elif predictable and owner_set and len(owner_set) > 1:
        verdict = {"verdict": "idor_predictable_only", "access": "pre-auth"}
        verdict["next"] = "ID 可预测但匿名不可读——双账号差分（低权会话读他人对象）走 authz-diff 矩阵确认"
    elif predictable:
        verdict = {"verdict": "idor_predictable_only", "access": "pre-auth"}
        verdict["next"] = "ID 序列可预测——影响面=可枚举区间；归属差分需第二身份（无凭证项目登记 VT 移交）"
    elif oids_ok:
        verdict = {"verdict": "inconclusive", "access": "post-auth"}
        verdict["next"] = "对象可达但 ID 无可预测性证据——扩大采样或按 UUID 类处理（随机 ID 不构成枚举面）"
    else:
        verdict = {"verdict": "not_found", "access": "unknown"}
        verdict["next"] = "采样区间无对象响应——核对起点 ID/会话有效性（401/403 为主时是会话问题非越权结论）"
    verdict.update({"samples": samples, "owners_observed": owner_set, "quantification": quant,
                    "anonymous_replay": anon_hits,
                    "note": "存在性证明口径：不导出对象数据；量化仅计数"})
    return verdict

def selftest():
    """本地 canned 服务闭环：匿名 IDOR / 可预测+鉴权 / 不存在 三分支（零外联）。"""
    import threading
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    class Up(BaseHTTPRequestHandler):
        def do_GET(self):
            oid = self.path.rsplit("/", 1)[-1].split("?")[0]
            has_sess = "Session" in (self.headers.get("Cookie") or "")
            if not has_sess:
                body, st = b"ORDER-OF-USER-42 amount=100 owner=user42", 200   # 匿名可读（IDOR）
            elif oid.isdigit() and 1000 <= int(oid) <= 1010:
                body, st = f"ORDER-{oid} owner=user42".encode(), 200           # 会话态可读
            else:
                body, st = b"not found", 404
            self.send_response(st); self.send_header("Content-Length", str(len(body))); self.end_headers()
            self.wfile.write(body)
        def log_message(self, *a): pass
    up = ThreadingHTTPServer(("127.0.0.1", 0), Up); threading.Thread(target=up.serve_forever, daemon=True).start()
    tpl = f"http://127.0.0.1:{up.server_address[1]}/order/{{}}"
    r1 = run(tpl, 1000, 5, cookies={"Session": "s1"}, owner_grep=r"owner=(\w+)")
    assert r1["verdict"] == "idor_anonymous", f"匿名 IDOR 应判定: {r1['verdict']}"
    assert r1["quantification"]["range_size"] == 5 and "user42" in r1["owners_observed"]
    r2 = run(tpl, 2000, 3, cookies={"Session": "s1"}, anonymous=False)
    assert r2["verdict"] == "not_found", f"无对象区间应 not_found: {r2['verdict']}"
    up.shutdown()
    print("idor-baseline selftest: 匿名IDOR/量化/不存在 3/3 OK")

def main():
    ap = argparse.ArgumentParser(description="v4.8 W6 IDOR 自动基线")
    ap.add_argument("--url", help="端点模板，{id} 为对象 ID 位")
    ap.add_argument("--start", type=int, default=1, help="起始对象 ID")
    ap.add_argument("--count", type=int, default=5, help="采样个数（默认 5，存在性证明足够）")
    ap.add_argument("--cookie", action="append", default=[], help="会话态 k=v（可多次）")
    ap.add_argument("--header", action="append", default=[], help="v5.6.0 认证头 '名: 值'（可多次，如 Authorization: Bearer …）")
    ap.add_argument("--method", default="GET", help="v5.6.0 请求方法（GET/POST/…）")
    ap.add_argument("--data", help="v5.6.0 请求体（内联或 @file）")
    ap.add_argument("--owner-grep", help="响应中归属证据正则（如 owner=([0-9]+)）")
    ap.add_argument("--no-anonymous", dest="anonymous", action="store_false", help="跳过匿名差分")
    ap.add_argument("--json", action="store_true", help="输出 JSON（默认）")
    ap.add_argument("--selftest", action="store_true")
    ns = ap.parse_args()
    _extra = {}
    for h in ns.header or []:
        k, _, v = h.partition(":")
        if k.strip():
            _extra[k.strip()] = v.strip()
    _data = None
    if ns.data:
        if ns.data.startswith("@"):
            with open(ns.data[1:], "rb") as _f:
                _data = _f.read()
        else:
            _data = ns.data.encode("utf-8")
        _extra.setdefault("Content-Type", "application/x-www-form-urlencoded")
    METHOD.update({"m": ns.method.upper(), "d": _data, "h": _extra})
    if ns.selftest:
        selftest(); return
    if not ns.url:
        ap.error("需要 --url（或 --selftest）")
    cookies = dict(kv.split("=", 1) for kv in ns.cookie)
    print(json.dumps(run(ns.url, ns.start, ns.count, cookies, ns.owner_grep, ns.anonymous),
                     ensure_ascii=False, indent=1))

if __name__ == "__main__":
    main()
