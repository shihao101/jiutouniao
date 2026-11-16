#!/usr/bin/env python3
"""ROE Profile 校验器（v4.6 T8）：YAML 子集（2 空格嵌套）解析 + schema 校验。
用法：roe_validate.py <profile.yaml>；--selftest 跑内置正反例。退出码 0=合法。"""
import sys, re

SCHEMA = {
    "profile": r"^[A-Za-z0-9_.\-]+$",
    "windows": r"^(none|\{.*\})$",
    "write_policy": r"^(full|existence-proof)$",
    "expansion": r"^(auto|auto-with-approval|deny)$",
    "offline_challenge": r"^(allow|deny)$",
    "rotation": r"^(unlimited|capped:\d+)$",
    "max_conn_per_s": r"^\d+$",
    "cooldown_protocol": r"^(full-silence|canary-exp)$",
    "auto_register": r"^(allow|deny)$",
    "dict_size": r"^\d+$",
    "lockout_aware": r"^(true|false)$",
    "residential_proxy": r"^(allow|deny)$",
    "oob_callback": r"^(allow|deny)$",
}
REQUIRED = {"profile", "write_policy", "scope", "waf_policy", "identity", "outbound"}

def parse(path):
    tree = {}
    stack = [(-1, tree)]
    with open(path, encoding="utf-8") as f:
        for ln, raw in enumerate(f, 1):
            line = raw.rstrip("\n")
            if not line.strip() or line.strip().startswith("#"):
                continue
            indent = len(line) - len(line.lstrip(" "))
            if indent % 2 != 0:
                raise ValueError(f"第{ln}行缩进非 2 空格倍数")
            while stack and stack[-1][0] >= indent:
                stack.pop()
            parent = stack[-1][1]
            m = re.match(r"^([\w_]+):\s*(.*)$", line.strip())
            if not m:
                raise ValueError(f"第{ln}行非法语法")
            key, val = m.group(1), re.sub(r"\s+#.*$", "", m.group(2)).strip()
            if val == "":
                parent[key] = {}
                stack.append((indent, parent[key]))
            else:
                val = val.strip('"').strip("'")
                parent[key] = val
    return tree

def validate(tree):
    errs = []
    flat = {}
    def walk(d, prefix=""):
        for k, v in d.items():
            fk = (prefix + "." + k) if prefix else k
            if isinstance(v, dict):
                walk(v, fk)
            else:
                flat[fk] = v
    walk(tree)
    for r in REQUIRED:
        if not any(k == r or k.startswith(r + ".") for k in flat):
            errs.append(f"缺少必填节: {r}")
    for k, v in flat.items():
        leaf = k.split(".")[-1]
        if leaf in SCHEMA and not re.match(SCHEMA[leaf], str(v)):
            errs.append(f"{k}={v} 不合法（允许: {SCHEMA[leaf]}）")
    return errs, flat

if __name__ == "__main__":
    if "--selftest" in sys.argv:
        import os
        ex = os.path.join(os.path.dirname(os.path.abspath(__file__)), "roe-profile.example.yaml")
        good, bad = parse(ex), None
        e1, _ = validate(good)
        open("/tmp/roe-bad.yaml", "w").write("profile: bad name!\nwrite_policy: whatever\n")
        try:
            e2, _ = validate(parse("/tmp/roe-bad.yaml"))
        except ValueError as ex:
            e2 = [f"解析拒绝: {ex}"]
        ok = (not e1) and (len(e2) > 0)
        print(f"合法样例通过={not e1}；非法样例被拒={len(e2) > 0}（{e2[:1]}）")
        sys.exit(0 if ok else 1)
    errs, flat = validate(parse(sys.argv[1]))
    for e in errs:
        print("错误:", e)
    print(f"叶子参数 {len(flat)} 项；{'合法' if not errs else '非法'}")
    sys.exit(0 if not errs else 1)
