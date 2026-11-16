#!/usr/bin/env python3
"""v4.8 W6 注入通道标准件：channel-snapshot 快照态 → 上游代理链（sqlmap/nuclei 带挑战态运行）。

机制：读取 channel-snapshot 产物（cookie.jar + meta.json），以三种方式投递挑战态：
  ① emit  —— 直接输出 sqlmap/nuclei 就绪参数（--cookie/--header 拼装）；
  ② serve —— 启动本地上游代理（默认 127.0.0.1:8099），转发请求时自动附加挑战态
             cookie/UA/头（sqlmap --proxy http://127.0.0.1:8099 即「带挑战态运行」；
             mitmproxy 环境存在时同样可用作上游脚本，本标准件为无 mitmproxy 环境的等价通道）；
  ③ selftest —— 本地 canned 服务闭环验证（命令生成 + 代理转发 + 态注入），零外联。

用法：
  python3 chain-proxy.py --from-snapshot evidence/channel-snapshot-<ts> --emit --url http://t/api
  python3 chain-proxy.py --from-snapshot evidence/channel-snapshot-<ts> --serve 127.0.0.1:8099 --upstream http://target
合规：仅转发授权范围内目标；本地代理只附加快照中已有的会话态，不构造新的攻击流量形态。
"""
import argparse, json, os, sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import urllib.request

UA_DEFAULT = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"

def parse_cookie_jar(path):
    """Netscape cookie.jar → {name: value}（跳过注释行与 #HttpOnly_ 前缀）。"""
    out = {}
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line or (line.startswith("# ") and not line.startswith("#HttpOnly_")):
                continue
            if line.startswith("#HttpOnly_"):
                line = line[len("#HttpOnly_"):]
            parts = line.split("\t")
            if len(parts) >= 7 and parts[5] and parts[6]:
                out[parts[5]] = parts[6]
    return out

def load_state(snapshot_dir):
    """快照目录 → (cookie dict, user_agent, meta)。缺 meta.json 时 UA 用缺省并标注。"""
    jar = os.path.join(snapshot_dir, "cookie.jar")
    if not os.path.isfile(jar):
        raise SystemExit(f"错误: {jar} 不存在——先跑 channel-snapshot.py --cdp … --out {snapshot_dir}")
    cookies = parse_cookie_jar(jar)
    ua, meta = UA_DEFAULT, {}
    metap = os.path.join(snapshot_dir, "meta.json")
    if os.path.isfile(metap):
        meta = json.load(open(metap, encoding="utf-8"))
        ua = meta.get("user_agent") or UA_DEFAULT
    return cookies, ua, meta

def emit_args(url, cookies, ua, extra_headers):
    """输出 sqlmap/nuclei 就绪参数与完整命令建议。"""
    cookie_str = "; ".join(f"{k}={v}" for k, v in cookies.items())
    lines = [
        f"URL: {url}",
        f"Cookie 数: {len(cookies)}（{'、'.join(list(cookies)[:8])}{'…' if len(cookies) > 8 else ''}）",
        f"User-Agent: {ua}",
        f"--cookie 参数: --cookie \"{cookie_str}\"",
        f"--header 参数: --header \"User-Agent: {ua}\"",
        "sqlmap 建议: sqlmap -u <URL> --cookie \"{cs}\" --user-agent \"{ua}\" --batch --level 1 --threads 1（先 probe 后 batch）",
        "nuclei 建议: nuclei -u <URL> -H \"Cookie: {cs}\" -H \"User-Agent: {ua}\"（小批量模板组）",
        f"上游代理建议: python3 {os.path.abspath(__file__)} --from-snapshot <SNAP> --serve 127.0.0.1:8099 --upstream <UPSTREAM> 然后 sqlmap --proxy http://127.0.0.1:8099",
    ]
    for k, v in (extra_headers or {}).items():
        lines.append(f"附加头: -H \"{k}: {v}\"")
    return "\n".join(lines).format(cs=cookie_str, ua=ua)

class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """v5.1.2 P1 修复：禁用自动重定向——原实现 30x 会带着注入的挑战态 Cookie 跟随到
    任意 Location 主机（挑战态泄露到出站目标之外的合规红线）。重定向一律原样回传客户端，
    由客户端自行决定是否跟进（跳转目标在授权范围内时客户端会再次经代理发起）。"""
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None

class ProxyHandler(BaseHTTPRequestHandler):
    upstream = ""       # 上游基址
    cookies, ua, extra_headers = {}, UA_DEFAULT, {}
    _opener = urllib.request.build_opener(_NoRedirect)

    def _forward(self):
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else None
        url = self.upstream.rstrip("/") + self.path
        # v5.1.2 P1 修复：跨主机 Location 判定——重定向目标脱离上游主机即剥除挑战态头
        from urllib.parse import urlparse
        upstream_host = urlparse(self.upstream).netloc
        req = urllib.request.Request(url, data=body, method=self.command)
        hop = {"host", "connection", "proxy-connection", "content-length", "accept-encoding"}
        for k, v in self.headers.items():
            if k.lower() in hop:
                continue
            req.add_header(k, v)
        # 挑战态注入：快照 cookie 合并（快照优先于请求自带同名项），UA/附加头覆盖
        if self.cookies:
            merged = {}
            raw = self.headers.get("Cookie", "")
            for kv in raw.split(";"):
                if "=" in kv:
                    k, _, v = kv.strip().partition("=")
                    merged[k] = v
            merged.update(self.cookies)
            req.add_header("Cookie", "; ".join(f"{k}={v}" for k, v in merged.items()))
        req.add_header("User-Agent", self.ua)
        for k, v in self.extra_headers.items():
            req.add_header(k, v)
        try:
            resp = self._opener.open(req, timeout=30)
            data, status, headers = resp.read(), resp.status, resp.headers
            loc = headers.get("Location", "")
            if loc and urlparse(loc).netloc and urlparse(loc).netloc != upstream_host:
                # 跨主机重定向：剥除挑战态 Cookie/UA 后回传（30x 本身原样透传）
                for hk in ("Cookie", "User-Agent"):
                    for h in list(headers.keys()):
                        if h.lower() == hk.lower():
                            del headers[h]
                data = b""  # 跨主机跟随体不回传（防挑战态页面内容外泄）
        except urllib.error.HTTPError as e:
            data, status, headers = e.read(), e.code, e.headers
        self.send_response(status)
        for k, v in headers.items():
            if k.lower() in ("transfer-encoding", "connection", "content-encoding"):
                continue
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("X-Chain-Proxy", "challenge-state-injected")
        self.end_headers()
        self.wfile.write(data)

    do_GET = do_POST = do_PUT = do_DELETE = do_HEAD = do_OPTIONS = _forward

    def log_message(self, fmt, *args):  # 静默：代理日志不打进执行流
        pass

def serve(addr, upstream, cookies, ua, extra_headers):
    ProxyHandler.upstream, ProxyHandler.cookies = upstream, cookies
    ProxyHandler.ua, ProxyHandler.extra_headers = ua, extra_headers or {}
    srv = ThreadingHTTPServer(addr, ProxyHandler)
    print(f"上游代理链就绪: http://{addr[0]}:{addr[1]} → {upstream}（cookie {len(cookies)} 项/UA 已注入；Ctrl-C 退出）")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\n代理已停止")

def selftest():
    """本地 canned 服务闭环：快照解析 → 命令生成 → 代理转发态注入验证（零外联）。"""
    import threading, tempfile, http.cookiejar
    # ① canned 上游：校验收到的 Cookie/UA
    seen = {}
    class Up(BaseHTTPRequestHandler):
        def do_GET(self):
            seen["cookie"] = self.headers.get("Cookie", "")
            seen["ua"] = self.headers.get("User-Agent", "")
            seen["x-extra"] = self.headers.get("X-Probe", "")
            self.send_response(200); self.send_header("Content-Length", "2"); self.end_headers(); self.wfile.write(b"ok")
        def log_message(self, *a): pass
    up = ThreadingHTTPServer(("127.0.0.1", 0), Up); threading.Thread(target=up.serve_forever, daemon=True).start()
    # ② 假快照
    snap = tempfile.mkdtemp()
    with open(os.path.join(snap, "cookie.jar"), "w") as f:
        f.write("# Netscape HTTP Cookie File\n127.0.0.1\tFALSE\t/\tFALSE\t0\tJTSESSION\tabc123\t\n")
    json.dump({"user_agent": "TestUA/1.0", "ts": "t"}, open(os.path.join(snap, "meta.json"), "w"))
    cookies, ua, _ = load_state(snap)
    assert cookies.get("JTSESSION") == "abc123" and ua == "TestUA/1.0", "快照解析失败"
    # ③ 命令生成
    emitted = emit_args("http://t/x", cookies, ua, {"X-Probe": "1"})
    assert "--cookie" in emitted and "JTSESSION=abc123" in emitted, "命令生成失败"
    # ④ 代理转发：请求无 cookie → 代理注入快照态
    ProxyHandler.upstream = f"http://127.0.0.1:{up.server_address[1]}"
    ProxyHandler.cookies, ProxyHandler.ua, ProxyHandler.extra_headers = cookies, ua, {}
    px = ThreadingHTTPServer(("127.0.0.1", 0), ProxyHandler); threading.Thread(target=px.serve_forever, daemon=True).start()
    req = urllib.request.Request(f"http://127.0.0.1:{px.server_address[1]}/api?id=1")
    req.add_header("X-Probe", "chain")
    resp = urllib.request.urlopen(req, timeout=5)
    assert resp.status == 200 and resp.headers.get("X-Chain-Proxy") == "challenge-state-injected", "代理转发失败"
    assert "JTSESSION=abc123" in seen["cookie"] and seen["ua"] == "TestUA/1.0" and seen["x-extra"] == "chain", f"态注入不完整: {seen}"
    up.shutdown(); px.shutdown()
    print("chain-proxy selftest: 快照解析/命令生成/代理转发态注入 4/4 OK")

def main():
    ap = argparse.ArgumentParser(description="v4.8 W6 注入通道标准件（挑战态上游代理链）")
    ap.add_argument("--from-snapshot", help="channel-snapshot 产物目录（cookie.jar+meta.json）")
    ap.add_argument("--emit", action="store_true", help="输出 sqlmap/nuclei 就绪参数")
    ap.add_argument("--url", help="目标 URL（emit 用）")
    ap.add_argument("--serve", help="本地代理监听地址 127.0.0.1:8099")
    ap.add_argument("--upstream", help="上游目标基址 http://target")
    ap.add_argument("--header", action="append", default=[], help="附加头 K: V（可多次）")
    ap.add_argument("--selftest", action="store_true", help="本地闭环自测")
    ns = ap.parse_args()
    if ns.selftest:
        selftest(); return
    if not ns.from_snapshot:
        ap.error("需要 --from-snapshot（或 --selftest）")
    cookies, ua, _ = load_state(ns.from_snapshot)
    extra = {}
    for h in ns.header:
        k, _, v = h.partition(":")
        extra[k.strip()] = v.strip()
    if ns.emit:
        print(emit_args(ns.url or "<URL>", cookies, ua, extra))
    elif ns.serve:
        host, _, port = ns.serve.partition(":")
        if not ns.upstream:
            ap.error("--serve 需要 --upstream")
        serve((host or "127.0.0.1", int(port or 8099)), ns.upstream, cookies, ua, extra)
    else:
        ap.error("选择 --emit 或 --serve（或 --selftest）")

if __name__ == "__main__":
    main()
