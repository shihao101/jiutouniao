#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
mock_server.py — browser-kit 自测靶场（仅监听 127.0.0.1，零外部流量）

模拟「加密登录协议」站点，覆盖 browser-auth 技能的全部关键路径：
  1. 挑战值协议：页面 JS 启动时 GET /home/System/System//random/ 取挑战值存入
     sessionStorage.CHALLENGE_CODE，提交时前端 encrypt(密码, 挑战值) 加密后 POST
     （对齐安全设备管理面「WASM 加密 + 动态挑战」形态，验证码默认隐藏 fd-hide）
  2. 参数名陷阱：登录真实参数为 name（非 username）——只有真实浏览器提交
     页面自己的表单才会带对参数名（curl 明文构造必然失败，正是实战踩坑点）
  3. 验证码人机协同：?captcha=on 显示验证码输入框；cmode=1 时代码必填
  4. 多步登录（MFA）：?flow=otp——第一步凭据通过后返回 {"result":"mfa"}，
     页面展开 OTP 输入位（name=otp），第二步提交 otp=123456 才放行
  5. SPA 慢挂载：?flow=slow——登录表单延迟 2.5s 渲染（探测重试覆盖）
  6. 会话：成功登录 Set-Cookie SESSID=MOCKSESSID123（HttpOnly/SameSite=Strict）
  7. CLI 接管验证：GET /api/secret 需要 SESSID Cookie——供 selftest 以 curl 复用
     cookies.txt 验证「浏览器进门 → CLI 测试」混合流水线

用法：python3 mock_server.py [port]   # 默认 8765
"""
import base64
import json
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

CHALLENGE = "MOCK-CHALLENGE-2026"
MOCK_USER = "admin"
MOCK_PASS = "MockPass!2026"
MOCK_OTP = "123456"
SESSID = "MOCKSESSID123"


def encrypt(pw: str, chal: str) -> str:
    raw = bytes(ord(pw[i]) ^ ord(chal[i % len(chal)]) for i in range(len(pw)))
    return base64.b64encode(raw).decode()


def render_page(mode: str) -> str:
    """mode: std | otp | slow —— 三种登录形态共用同一挑战值协议骨架"""
    if mode == "otp":
        otp_input = '<input type="text" name="otp" id="otp" class="fd-hide" aria-label="动态口令">'
        submit_js = """
    var otpEl = document.getElementById('otp');
    var body = 'name=' + encodeURIComponent(this.username.value) +
               '&enc=' + encodeURIComponent(encrypt(this.password.value, sessionStorage.CHALLENGE_CODE)) +
               '&code=' + encodeURIComponent(this.code.value) +
               '&cmode=' + this.cmode.value + '&fmode=1' +
               (otpEl.classList.contains('fd-hide') ? '' : '&otp=' + encodeURIComponent(otpEl.value));
    fetch('/home/login/', {method: 'POST', headers: {'Content-Type': 'application/x-www-form-urlencoded'},
                           body: body, credentials: 'same-origin'})
      .then(function (r) { return r.json(); })
      .then(function (j) {
        if (j.result === true) { location.href = '/main.html'; }
        else if (j.result === 'mfa') {
          otpEl.classList.remove('fd-hide');
          document.querySelector('input[name=username]').classList.add('fd-hide');
          document.querySelector('input[name=password]').classList.add('fd-hide');
          document.getElementById('code').classList.add('fd-hide');
        }
        else { document.getElementById('hint').innerText = '登录失败: ' + j.data; }
      });"""
    else:
        otp_input = ""
        submit_js = """
    var body = 'name=' + encodeURIComponent(this.username.value) +
               '&enc=' + encodeURIComponent(encrypt(this.password.value, sessionStorage.CHALLENGE_CODE)) +
               '&code=' + encodeURIComponent(this.code.value) +
               '&cmode=' + this.cmode.value + '&fmode=0';
    fetch('/home/login/', {method: 'POST', headers: {'Content-Type': 'application/x-www-form-urlencoded'},
                           body: body, credentials: 'same-origin'})
      .then(function (r) { return r.json(); })
      .then(function (j) {
        if (j.result === true) { location.href = '/main.html'; }
        else { document.getElementById('hint').innerText = '登录失败: ' + j.data; }
      });"""
    if mode == "otp":
        fmode_hidden = '<input type="hidden" name="fmode" value="1">'
    else:
        fmode_hidden = '<input type="hidden" name="fmode" value="0">'
    slow_style = ' style="display:none"' if mode == "slow" else ""
    slow_js = ("setTimeout(function(){document.getElementById('loginBox').style.display='block';}, 2500);"
               if mode == "slow" else "")
    return """<!DOCTYPE html>
<html lang="zh"><head><meta charset="utf-8"><title>MOCK · 加密登录靶场</title>
<style>.fd-hide{display:none}</style></head>
<body>
<div id="loginBox\"""" + slow_style + """>
<h3 id="hint">MOCK 设备管理登录</h3>
<form id="loginForm" action="/home/login/" method="POST">
  <input type="text" name="username" aria-label="用户名">
  <input type="password" name="password" aria-label="密码">
  <input type="text" name="code" id="code" class="fd-hide" aria-label="验证码">
  """ + otp_input + """
  <input type="hidden" name="cmode" id="cmode" value="0">
  """ + fmode_hidden + """
  <button type="submit" id="btnLogin">登 录</button>
</form>
</div>
<script>
  function encrypt(pw, chal) {
    var out = '';
    for (var i = 0; i < pw.length; i++) {
      out += String.fromCharCode(pw.charCodeAt(i) ^ chal.charCodeAt(i % chal.length));
    }
    return btoa(out);
  }
  // 页面自己的挑战值协议：启动即取随机码存 sessionStorage（真实站点的加密原料）
  fetch('/home/System/System//random/').then(function (r) { return r.json(); }).then(function (j) {
    sessionStorage.CHALLENGE_CODE = j.data.code;
  });
  if (new URLSearchParams(location.search).get('captcha') === 'on') {
    document.getElementById('code').classList.remove('fd-hide');
    document.getElementById('cmode').value = '1';
  }
  document.getElementById('loginForm').addEventListener('submit', function (e) {
    e.preventDefault();
""" + submit_js + """
  });
  """ + slow_js + """
</script>
</body></html>"""


MAIN = """<!DOCTYPE html>
<html lang="zh"><head><meta charset="utf-8"><title>MOCK · 系统首页</title></head>
<body>
<h3 id="home">MOCK 系统首页（已登录）</h3>
<ul>
  <li><a href="/home/auth/userManage/">用户管理</a></li>
  <li><a href="/home/System/System//changePwd/">修改口令</a></li>
  <li><a href="/api/report/list">报表列表</a></li>
</ul>
<script>
  sessionStorage.priv = 'super-rw';
  sessionStorage.powers = 'PMSN-DEMO-2026';
</script>
</body></html>"""


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *a):  # 静默访问日志
        pass

    def _send(self, code, body, ctype="text/html; charset=utf-8", headers=None):
        data = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        for k, v in (headers or []):
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        u = urlparse(self.path)
        q = parse_qs(u.query)
        if u.path == "/index.html":
            mode = q.get("flow", ["std"])[0]
            self._send(200, render_page(mode if mode in ("otp", "slow") else "std"))
        elif u.path == "/main.html":
            self._send(200, MAIN)
        elif u.path == "/home/System/System//random/":
            self._send(200, json.dumps({"result": True, "data": {"code": CHALLENGE}}),
                       "application/json")
        elif u.path == "/api/secret":
            if "SESSID=" + SESSID in (self.headers.get("Cookie") or ""):
                self._send(200, "TOP-SECRET-CONTENT", "text/plain")
            else:
                self._send(401, "Authentication fail", "text/plain")
        else:
            self._send(404, "404 Not Found")

    def do_POST(self):
        u = urlparse(self.path)
        length = int(self.headers.get("Content-Length") or 0)
        form = parse_qs(self.rfile.read(length).decode("utf-8"))
        if u.path == "/home/login/":
            name = (form.get("name") or [""])[0]
            code = (form.get("code") or [""])[0]
            cmode = (form.get("cmode") or ["0"])[0]
            fmode = (form.get("fmode") or ["0"])[0]
            # 多步登录第二步：OTP 校验
            if "otp" in form:
                if name != MOCK_USER or (form.get("otp") or [""])[0] != MOCK_OTP:
                    self._send(200, json.dumps({"result": False, "data": "bad otp"}),
                               "application/json")
                    return
                self._send(200, json.dumps({"result": True, "data": "welcome"}),
                           "application/json",
                           [("Set-Cookie", f"SESSID={SESSID}; Path=/; HttpOnly; SameSite=Strict")])
                return
            # 多步登录第一步（otp 流）：凭据通过 → 返回 mfa，等待口令
            if fmode == "1":
                enc = (form.get("enc") or [""])[0]
                if name != MOCK_USER or enc != encrypt(MOCK_PASS, CHALLENGE):
                    self._send(200, json.dumps({"result": False, "data": "bad credentials"}),
                               "application/json")
                    return
                self._send(200, json.dumps({"result": "mfa", "data": "otp required"}),
                           "application/json")
                return
            # 单步流：验证码模式必填 + 凭据校验
            if cmode == "1" and not (len(code) == 4 and code.isdigit()):
                self._send(200, json.dumps({"result": False, "data": "code required"}),
                           "application/json")
                return
            enc = (form.get("enc") or [""])[0]
            if name != MOCK_USER or enc != encrypt(MOCK_PASS, CHALLENGE):
                self._send(200, json.dumps({"result": False, "data": "bad credentials"}),
                           "application/json")
                return
            self._send(200, json.dumps({"result": True, "data": "welcome"}),
                       "application/json",
                       [("Set-Cookie", f"SESSID={SESSID}; Path=/; HttpOnly; SameSite=Strict")])
        else:
            self._send(404, "404 Not Found")


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8765
    ThreadingHTTPServer(("127.0.0.1", port), Handler).serve_forever()
