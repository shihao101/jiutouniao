#!/usr/bin/env python3
"""v4.6 K1 通道快照标准件：从运行中的 chromium CDP 导出 cookie+UA → curl 可用 jar + meta。
用法：channel-snapshot.py --cdp http://127.0.0.1:9222 --out evidence/channel-snapshot-<ts>
依赖：websocket-client（引擎环境自带）。重放：curl -b <out>/cookie.jar -A "$UA"（UA 取自 meta.json）
"""
import argparse, base64, json, os, sys, time
import urllib.request
import websocket

def cdp(ws, mid, method, params=None, timeout=15):
    ws.settimeout(timeout)
    ws.send(json.dumps({"id": mid, "method": method, "params": params or {}}))
    while True:
        m = json.loads(ws.recv())
        if m.get("id") == mid:
            return m

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--cdp", default="http://127.0.0.1:9222")
    ap.add_argument("--out", required=True)
    ns = ap.parse_args()
    tabs = json.loads(urllib.request.urlopen(f"{ns.cdp}/json/list", timeout=5).read())
    page = next((t for t in tabs if t.get("type") == "page"), None)
    if not page:
        sys.exit("错误: CDP 无 page target")
    ws = websocket.create_connection(page["webSocketDebuggerUrl"], timeout=15)
    ua = cdp(ws, 1, "Runtime.evaluate",
             {"expression": "navigator.userAgent", "returnByValue": True})["result"]["result"].get("value", "")
    cookies = cdp(ws, 2, "Storage.getCookies", {"browserContextId": None})["result"]["cookies"]
    os.makedirs(ns.out, exist_ok=True)
    lines = ["# Netscape HTTP Cookie File", f"# channel-snapshot {time.strftime('%Y-%m-%dT%H:%M:%S%z')}"]
    names = []
    for c in cookies:
        names.append(c["name"])
        dom = c.get("domain", "")
        flag = "TRUE" if dom.startswith(".") else "FALSE"
        path = c.get("path", "/")
        secure = "TRUE" if c.get("secure") else "FALSE"
        exp = int(c.get("expires", 0)) or 0
        lines.append("\t".join([dom, flag, path, secure, str(exp), c["name"], c.get("value", "")]))
    with open(os.path.join(ns.out, "cookie.jar"), "w") as f:
        f.write("\n".join(lines) + "\n")
    meta = {"user_agent": ua, "cookie_names": names, "ts": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
            "hint": "重放必须带本 UA；瑞数类 cookie TTL 按 30 分钟对待"}
    with open(os.path.join(ns.out, "meta.json"), "w") as f:
        json.dump(meta, f, ensure_ascii=False, indent=1)
    print(f"快照完成: {len(cookies)} cookies → {ns.out}/cookie.jar；重放: curl -b {ns.out}/cookie.jar -A <meta.user_agent>")

if __name__ == "__main__":
    main()
