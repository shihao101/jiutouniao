#!/bin/bash
# browser-kit 自测：本地 mock 靶场全链路验证（仅 127.0.0.1，零外部流量）
# 覆盖：真实浏览器登录（挑战值协议/参数名陷阱/隐藏验证码）→ 会话抓取 →
#       CLI 接管（curl 复用 cookies）→ 加密预言机（含已登录上下文）→
#       验证码人机协同（exit 42）→ 错误口令失败路径（exit 3）
PY=/opt/venv/bin/python
KIT=/opt/tools/browser-kit
PORT=${BK_SELFTEST_PORT:-8765}
BASE="http://127.0.0.1:${PORT}"
OUT=$(mktemp -d /tmp/bk-selftest.XXXX)
PASS=0; FAIL=0

say()  { echo "[$1] $2"; }
check(){ if [ "$1" = "0" ]; then PASS=$((PASS+1)); say PASS "$2"; else FAIL=$((FAIL+1)); say FAIL "$2"; fi; }

${PY} ${KIT}/selftest/mock_server.py ${PORT} & MOCK_PID=$!
trap 'kill ${MOCK_PID} 2>/dev/null' EXIT
sleep 1

# ---- T1 默认登录（挑战值协议 + 隐藏验证码 + name 参数陷阱由页面自身规避）----
JT_PASS='MockPass!2026' ${PY} ${KIT}/browser_login.py \
  --url "${BASE}/index.html" --user admin --password-env JT_PASS \
  --success-url-contains "/main.html" --interval-sec 1 \
  --out "${OUT}/login1" >/dev/null 2>&1
check $? "T1 浏览器登录 exit=0"
grep -q "SESSID" "${OUT}/login1/cookies.txt" 2>/dev/null; check $? "T1a cookies.txt 含 SESSID"
grep -q "CHALLENGE_CODE" "${OUT}/login1/storage.json" 2>/dev/null; check $? "T1b storage 含挑战值 CHALLENGE_CODE"
grep -q "priv" "${OUT}/login1/storage.json" 2>/dev/null; check $? "T1c storage 含登录后 priv"
grep -q "/home/auth/userManage/" "${OUT}/login1/postlogin-links.txt" 2>/dev/null; check $? "T1d 端点清单含菜单 API"
[ -s "${OUT}/login1/network.har" ]; check $? "T1e HAR 已落盘"

# ---- T2 CLI 接管：curl 复用浏览器会话 ----
BODY=$(curl -s -b "${OUT}/login1/cookies.txt" "${BASE}/api/secret")
[ "${BODY}" = "TOP-SECRET-CONTENT" ]; check $? "T2 curl 复用 cookies 拿到受限数据"

# ---- T3 加密预言机（登录页上下文，页面自身 encrypt 函数）----
EXPECT=$(${PY} -c "
import base64
chal='MOCK-CHALLENGE-2026'
print(base64.b64encode(bytes(ord(c)^ord(chal[i%len(chal)]) for i,c in enumerate('abc'))).decode())")
ORACLE=$(${PY} ${KIT}/browser_oracle.py --url "${BASE}/index.html" \
  --wait-js "typeof encrypt === 'function' && !!sessionStorage.CHALLENGE_CODE" \
  --eval "encrypt('abc', sessionStorage.CHALLENGE_CODE)" --interval-sec 1 2>/dev/null)
echo "${ORACLE}" | grep -q "\"result\": \"${EXPECT}\""; check $? "T3 预言机密文与本地推导一致"

# ---- T4 预言机复用已登录上下文（cookies + storage 注入）----
ORACLE2=$(${PY} ${KIT}/browser_oracle.py --url "${BASE}/main.html" \
  --cookies "${OUT}/login1/cookies.txt" --storage "${OUT}/login1/storage.json" \
  --eval "sessionStorage.priv + '|' + sessionStorage.powers" --interval-sec 1 2>/dev/null)
echo "${ORACLE2}" | grep -q "super-rw|PMSN-DEMO-2026"; check $? "T4 已登录上下文还原（priv/powers）"

# ---- T5 验证码人机协同：可见验证码未给值 → exit 42；给值 → 成功 ----
JT_PASS='MockPass!2026' ${PY} ${KIT}/browser_login.py \
  --url "${BASE}/index.html?captcha=on" --user admin --password-env JT_PASS \
  --success-url-contains "/main.html" --interval-sec 1 \
  --out "${OUT}/login2" >/dev/null 2>&1
[ $? -eq 42 ]; check $? "T5a 可见验证码未给值 exit=42"
[ -s "${OUT}/login2/shots/login.png" ]; check $? "T5b 42 路径已截登录页图"
JT_PASS='MockPass!2026' ${PY} ${KIT}/browser_login.py \
  --url "${BASE}/index.html?captcha=on" --user admin --password-env JT_PASS \
  --captcha 8888 --success-url-contains "/main.html" --interval-sec 1 \
  --out "${OUT}/login3" >/dev/null 2>&1
check $? "T5c 人工读码后（--captcha 8888）登录成功"

# ---- T6 错误口令 → exit 3 ----
JT_PASS='WrongPass!' ${PY} ${KIT}/browser_login.py \
  --url "${BASE}/index.html" --user admin --password-env JT_PASS \
  --success-url-contains "/main.html" --interval-sec 1 \
  --out "${OUT}/login4" >/dev/null 2>&1
[ $? -eq 3 ]; check $? "T6 错误口令 exit=3"

# ---- T7 HAR 脱敏：明文口令不得出现在 HAR ----
if grep -q "MockPass" "${OUT}/login3/network.har" 2>/dev/null; then check 1 "T7 HAR 已脱敏"; else check 0 "T7 HAR 已脱敏"; fi

# ---- T8 SPA 慢挂载：表单延迟 2.5s 渲染，探测重试覆盖 ----
JT_PASS='MockPass!2026' ${PY} ${KIT}/browser_login.py \
  --url "${BASE}/index.html?flow=slow" --user admin --password-env JT_PASS \
  --success-url-contains "/main.html" --interval-sec 1 --detect-timeout 10 \
  --out "${OUT}/login5" >/dev/null 2>&1
check $? "T8 SPA 慢挂载（探测重试）登录成功"
grep -q "SESSID" "${OUT}/login5/cookies.txt" 2>/dev/null; check $? "T8a 慢挂载会话已捕获"

# ---- T9 多步登录（MFA-OTP）：口令经环境变量注入 / 缺失转人工 ----
JT_PASS='MockPass!2026' JT_OTP='123456' ${PY} ${KIT}/browser_login.py \
  --url "${BASE}/index.html?flow=otp" --user admin --password-env JT_PASS \
  --otp-env JT_OTP --success-url-contains "/main.html" --interval-sec 1 \
  --out "${OUT}/login6" >/dev/null 2>&1
check $? "T9 OTP 两步自动登录成功"
JT_PASS='MockPass!2026' ${PY} ${KIT}/browser_login.py \
  --url "${BASE}/index.html?flow=otp" --user admin --password-env JT_PASS \
  --success-url-contains "/main.html" --interval-sec 1 \
  --out "${OUT}/login7" >/dev/null 2>&1
[ $? -eq 45 ]; check $? "T9a OTP 未配置 exit=45 转人工"

echo "----------------------------------------"
echo "browser-kit selftest: PASS=${PASS} FAIL=${FAIL} (workdir ${OUT})"
[ ${FAIL} -eq 0 ]
