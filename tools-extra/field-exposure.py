#!/usr/bin/env python3
"""v5.3.9 API 字段级过度暴露差分（API Top10 2023·API3；判据与 api-field-exposure 技能对齐）。
用法：
  field-exposure.py --base http://t --endpoint /Api/User/Info \
      --role anon: --role low:"Authorization: Bearer XXX" [--role high:"..."] \
      [--out fields.tsv] [--delay 1]
  field-exposure.py --selftest   # 起本地 canned 服务验证判读逻辑
输出 TSV：field | present_in | sensitive | masked_sample | classification
判定：over_exposed_anon（匿名多吐敏感字段）/ suspicious_low_only（低权特有字段）/ info_only"""
import argparse, json, sys, threading, time, re
import urllib.request, urllib.error
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# 敏感字段名判据（api-field-exposure.md 第二节⑤，中英双语词根）
SENSITIVE_RE = re.compile(
    r"(pass|pwd|token|secret|api_?key|access_?key|salt|hash|session|cookie|"
    r"id_?card|identity|ssn|phone|mobile|tel|email|birth|salary|bank|card_?no|"
    r"diagnosis|medical|record|role|permission|internal|created_by)", re.I)

MASK_KEYS = ("password", "phone", "mobile", "idcard", "id_card", "email", "name")


def flatten(obj, prefix=""):
    """JSON 展平为点路径字段集合；数组取首元素代表（技能第二节②口径）。"""
    keys = set()
    if isinstance(obj, dict):
        for k, v in obj.items():
            p = f"{prefix}.{k}" if prefix else k
            keys.add(p)
            keys |= flatten(v, p)
    elif isinstance(obj, list) and obj:
        keys |= flatten(obj[0], prefix + "[]")
    return keys


def mask_sample(obj, field):
    """按字段路径取值做掩码（前 2 字符+***；非标量记类型）。"""
    cur = obj
    for part in field.replace("[]", "").split("."):
        if not isinstance(cur, dict) or part not in cur:
            return "?"
        cur = cur[part]
    if isinstance(cur, (dict, list)):
        return f"<{type(cur).__name__}>"
    s = str(cur)
    return (s[:2] + "***len=" + str(len(s))) if s else "<empty>"


def _lookup(obj, field):
    """点路径取值（[] 段取首元素，同 flatten 口径）；缺失返回 None。"""
    cur = obj
    for part in field.replace("[]", "").split("."):
        if isinstance(cur, list):
            cur = cur[0] if cur else None
            continue
        if not isinstance(cur, dict) or part not in cur:
            return None
        cur = cur[part]
    return cur


def _has_content(v):
    if isinstance(v, (dict, list)):
        return len(v) > 0
    if isinstance(v, str):
        return bool(v.strip())
    return v is not None


def classify(role_fields, roles_order, field, role_objs=None):
    """v5.6.1（审计缺陷#12）：over_exposed_anon 要求值非空——空值/占位符命中只算
    candidate_over_exposed（候选），需人工确认非空+业务不必要后才能升级 record_finding。
    role_objs 提供原始 JSON（flatten 集合只有路径无值）；缺省 None 时按旧口径兼容。"""
    present = {r for r in roles_order if field in role_fields.get(r, set())}
    if roles_order[0] in present and SENSITIVE_RE.search(field):
        if role_objs is None:
            return "over_exposed_anon"
        has_content = any(_has_content(_lookup(role_objs.get(r), field))
                          for r in present if role_objs.get(r) is not None)
        if has_content:
            return "over_exposed_anon"
        return "candidate_over_exposed"
    highest = roles_order[-1]
    if len(roles_order) >= 2 and present and highest not in present:
        # 属性级异常：字段存在于任一非最高权角色（匿名/低权）而高权角色反而无
        return "suspicious_low_only"
    return "info_only"


def fetch(url, headers, timeout=10):
    try:
        req = urllib.request.Request(url, headers=headers or {"User-Agent": "jt-field-exposure/1.0"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.getcode(), r.read(65536).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read(65536).decode("utf-8", "replace")
    except Exception:
        return 0, ""


def run(base, endpoint, roles, out, delay):
    roles_order = [name for name, _ in roles]
    role_fields, role_objs, rows = {}, {}, []
    for name, hdr in roles:
        st, body = fetch(base + endpoint, {"User-Agent": "jt-field-exposure/1.0", **hdr})
        try:
            obj = json.loads(body)
            fields = flatten(obj)
        except Exception:
            obj, fields = None, set()
        role_fields[name], role_objs[name] = fields, obj
        rows.append((endpoint, name, st, len(fields), "JSON_OK" if obj is not None else "NON_JSON"))
        time.sleep(delay)
    if role_objs.get(roles_order[0]) is None:
        print(f"[!] 匿名角色响应非 JSON（HTTP {rows[0][2]}）——端点先过 authz-diff 三态，再回本工具（needs_follow_up）")
        verdict = "needs_follow_up"
    else:
        verdict = "scanned"
        for f in sorted(set().union(*role_fields.values())):
            cls = classify(role_fields, roles_order, f, role_objs)
            sensitive = "Y" if SENSITIVE_RE.search(f) else "-"
            owner = next((r for r in roles_order if f in role_fields[r]), "-")
            sample = mask_sample(role_objs[owner], f) if owner != "-" else "?"
            rows.append((f, ",".join(r for r in roles_order if f in role_fields[r]), sensitive, sample, cls))
        over = sum(1 for r in rows if r[4] == "over_exposed_anon")
        lo = sum(1 for r in rows if r[4] == "suspicious_low_only")
        verdict_note = f"over_exposed_anon={over}（需人工核对业务必要性，PII 掩码登记）/ suspicious_low_only={lo}"
        print(f"[=] 字段总数 {len(set().union(*role_fields.values()))}：{verdict_note}")
    if out:
        with open(out, "w", encoding="utf-8") as f:
            f.write("field\tpresent_in\tsensitive\tmasked_sample\tclassification\n")
            for r in rows:
                f.write("\t".join(map(str, r)) + "\n")
    return verdict


# ---------- selftest：本地 canned 服务 ----------
class Mock(BaseHTTPRequestHandler):
    def do_GET(self):
        auth = self.headers.get("Authorization", "")
        if "high" in auth:
            body = {"id": 1, "name": "张三", "phone": "13800000000", "role": "admin", "created_by": "sys"}
        elif "low" in auth:
            body = {"id": 1, "name": "张三", "phone": "13800000000", "role": "user", "admin_flag": True}
        else:
            body = {"id": 1, "name": "张三", "phone": "13800000000", "password_hash": "ab12cd34"}
        b = json.dumps(body, ensure_ascii=False).encode()
        self.send_response(200)
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
    roles = [("anon", {}), ("low", {"Authorization": "Bearer low"}), ("high", {"Authorization": "Bearer high"})]
    fields = {n: flatten(json.loads(fetch(base + "/u", {"Authorization": h.get("Authorization", "")} or h)[1])) for n, h in roles}
    bad = 0
    if classify(fields, [n for n, _ in roles], "password_hash") != "over_exposed_anon":
        print("FAIL password_hash 应判 over_exposed_anon"); bad += 1
    if classify(fields, [n for n, _ in roles], "admin_flag") != "suspicious_low_only":
        print("FAIL admin_flag 应判 suspicious_low_only"); bad += 1
    if classify(fields, [n for n, _ in roles], "created_by") != "info_only":
        print("FAIL created_by（高权特有，正常层级）应判 info_only"); bad += 1
    if classify(fields, [n for n, _ in roles], "name") != "info_only":
        print("FAIL name 应判 info_only"); bad += 1
    # v5.6.1：空值敏感字段只算候选（审计缺陷#12 修复锁定）
    fields_c = {"anon": {"secret_key"}, "low": set(), "high": {"secret_key"}}
    objs_c = {"anon": {"secret_key": ""}, "low": {}, "high": {"secret_key": ""}}
    if classify(fields_c, [n for n, _ in roles], "secret_key", objs_c) != "candidate_over_exposed":
        print("FAIL 空值敏感字段应判 candidate_over_exposed"); bad += 1
    objs_v = {"anon": {"secret_key": "real-value-123"}, "low": {}, "high": {"secret_key": "x"}}
    if classify({"anon": {"secret_key"}}, [n for n, _ in roles], "secret_key", objs_v) != "over_exposed_anon":
        print("FAIL 非空值敏感字段应判 over_exposed_anon"); bad += 1
    if mask_sample({"phone": "13800000000"}, "phone") != "13***len=11":
        print("FAIL 掩码规则"); bad += 1
    srv.shutdown()
    print(f"判读自测: {6-bad}/6")
    return bad == 0


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--base"); ap.add_argument("--endpoint")
    ap.add_argument("--role", action="append", default=[],
                    help='角色:头。格式 name:"Header: value"（首个角色视为最低权/匿名，末个为高权参照）')
    ap.add_argument("--out"); ap.add_argument("--delay", type=float, default=1.0)
    ap.add_argument("--selftest", action="store_true")
    ns = ap.parse_args()
    if ns.selftest:
        sys.exit(0 if selftest() else 1)
    if not ns.base or not ns.endpoint or not ns.role:
        ap.error("需要 --base/--endpoint/--role（至少匿名角色）或 --selftest")
    roles = []
    for spec in ns.role:
        name, _, hdr = spec.partition(":")
        headers = {}
        if hdr.strip():
            hk, _, hv = hdr.strip().partition(":")
            headers = {hk.strip(): hv.strip()}
        roles.append((name or f"role{len(roles)}", headers))
    run(ns.base, ns.endpoint, roles, ns.out, ns.delay)
