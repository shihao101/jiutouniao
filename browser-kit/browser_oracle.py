#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
browser_oracle.py — 加密预言机：让目标页面自己的 JS 为任意载荷加密/解密（九头鸟 browser-kit v2.8.0）

用途：登录成功后，若部分业务端点同样走 JS/WASM 加密（如改密、敏感操作），
无需离线逆向协议——本工具在真实浏览器上下文中执行页面的加密函数，取回密文后
由 CLI（curl/nuclei）发送，兼得「协议保真」与「测试可控」。

会话上下文：--cookies（browser_login.py 产出的 cookies.txt）与 --storage（storage.json）
可同时注入，使预言机运行在已登录上下文中（sessionStorage 中的挑战值/密钥随取随用）。

示例：
  # 页面函数加密（已登录上下文，sessionStorage.CHALLENGE_CODE 参与派生）
  /opt/venv/bin/python /opt/tools/browser-kit/browser_oracle.py \
      --url https://10.0.0.1/index.html \
      --cookies evidence/browser-login/cookies.txt \
      --storage evidence/browser-login/storage.json \
      --wait-js "typeof _encryptPayload !== 'undefined'" \
      --eval "_encryptPayload('newPassword!')" \
      --out evidence/oracle-changepwd.json
  # 返回 {"ok": true, "result": "...密文..."} → 取值填入 curl 请求体发送
"""
import argparse
import json
import os
import shutil
import sys
import time
from pathlib import Path

EXIT_OK, EXIT_USAGE, EXIT_NAV, EXIT_EVAL = 0, 1, 2, 4
PROXY_KEYS = ("http_proxy", "https_proxy", "HTTP_PROXY", "HTTPS_PROXY",
              "all_proxy", "ALL_PROXY", "ftp_proxy", "FTP_PROXY")


def parse_netscape(path):
    cookies = []
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        if not line.strip() or line.startswith("#"):
            continue
        parts = line.split("\t")
        if len(parts) != 7:
            continue
        domain, _, p, secure, exp, name, value = parts
        cookies.append({"name": name, "value": value, "domain": domain, "path": p,
                        "secure": secure == "TRUE", "httpOnly": False,
                        "expires": float(exp) if float(exp) > 0 else -1})
    return cookies


def main():
    ap = argparse.ArgumentParser(description="browser_oracle.py — 页面 JS 加密预言机")
    ap.add_argument("--url", required=True, help="承载目标加密函数的页面 URL")
    ap.add_argument("--eval", required=True, help="要执行的 JS 表达式（返回值即密文）")
    ap.add_argument("--wait-js", default="", help="执行前等待该表达式为真（如函数已定义），默认不等待")
    ap.add_argument("--wait-timeout", type=float, default=15, help="等待秒数（默认 15）")
    ap.add_argument("--cookies", default="", help="复用登录会话：cookies.txt（Netscape 格式）")
    ap.add_argument("--storage", default="", help="复用登录上下文：storage.json（localStorage/sessionStorage）")
    ap.add_argument("--out", default="", help="结果另存 JSON 文件（可选）")
    ap.add_argument("--ua", default="", help="覆盖 User-Agent")
    ap.add_argument("--proxy", default="", help="显式代理（默认剥离代理环境变量，目标直连）")
    ap.add_argument("--interval-sec", type=float, default=2.0, help="加载后静置秒数（默认 2）")
    args = ap.parse_args()

    browser_path = os.environ.get("JT_BROWSER_PATH") or next(
        (shutil.which(n) for n in ("chromium", "chromium-browser", "google-chrome",
                                   "google-chrome-stable") if shutil.which(n)), None)
    if not browser_path:
        print(json.dumps({"ok": False, "error": "未找到 chromium 可执行文件"}))
        return EXIT_USAGE

    from playwright.sync_api import sync_playwright, TimeoutError as PWTimeout

    # 对目标直连：剥离代理环境变量（--proxy 显式开启除外）
    for k in PROXY_KEYS:
        os.environ.pop(k, None)
    if args.proxy:
        os.environ["http_proxy"] = os.environ["https_proxy"] = args.proxy

    result = {"ok": False, "url": args.url, "eval": args.eval}
    ret = EXIT_EVAL
    with sync_playwright() as pw:
        browser = pw.chromium.launch(executable_path=browser_path, headless=True,
                                     args=["--no-sandbox", "--disable-dev-shm-usage", "--disable-gpu"])
        ctx = browser.new_context(ignore_https_errors=True, user_agent=args.ua or None)
        try:
            if args.cookies:
                cookies = parse_netscape(args.cookies)
                if cookies:
                    ctx.add_cookies(cookies)
                    result["cookies_loaded"] = len(cookies)
            page = ctx.new_page()
            if args.storage:
                storage_text = Path(args.storage).read_text(encoding="utf-8")
                # 以 JS 字符串字面量安全嵌入（json.dumps 产出合法 JS 字符串），还原两处 storage
                page.add_init_script(
                    "(function(){ try { const o = JSON.parse(" + json.dumps(storage_text) + ");"
                    " for (const [k,v] of Object.entries(o.localStorage||{})) localStorage.setItem(k,v);"
                    " for (const [k,v] of Object.entries(o.sessionStorage||{})) sessionStorage.setItem(k,v);"
                    " } catch(e) { console.warn('storage restore failed', e); } })();")
            page.goto(args.url, wait_until="domcontentloaded", timeout=30000)
            time.sleep(args.interval_sec)
            if args.wait_js:
                page.wait_for_function(args.wait_js, timeout=args.wait_timeout * 1000)
            value = page.evaluate(args.eval)
            result["ok"] = True
            result["result"] = value
            ret = EXIT_OK
        except PWTimeout as e:
            result["error"] = f"等待条件超时（--wait-js 未就绪）: {e}"
            ret = EXIT_NAV
        except Exception as e:
            result["error"] = f"{type(e).__name__}: {e}"
            ret = EXIT_EVAL
        finally:
            try:
                browser.close()
            except Exception:
                pass

    payload = json.dumps(result, ensure_ascii=False)
    if args.out:
        Path(args.out).write_text(payload, encoding="utf-8")
    print(payload)
    return ret


if __name__ == "__main__":
    sys.exit(main())
