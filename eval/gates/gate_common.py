# -*- coding: utf-8 -*-
"""v4.6 离线质量门公共库：断言模式与归一化（与引擎 orchestrator/store 同口径）。
审计依据：《优化方案_全任务审计执行可靠性整改_v4.5增补层》11 例实证误判。"""
import json, os, re, sys, glob

NEG_RE = re.compile(r"(空文件|jar\s*为空|为空|无\s*cookie|未暴露|被拒|协议版本|0\s*命中|"
                    r"全部.{0,6}0{2,}|不依赖|不存在|无差异|同文案|无枚举信号|未捕获|全部.{0,8}(响应|数据|端点))")
PENDING_RE = re.compile(r"(待.{0,10}验证|未实测|待实测|待确认|尚未验证|未执行验证)")
TERMINAL = {"ruled_out", "no_issue_found"}
BAD_OBSERVED = {"undetermined_timeout", "blocked_ratelimit", "blocked_waf", "not_tested"}
EVID_RE = re.compile(r"evidence/[A-Za-z0-9_\-./~*]+")

def norm_title(t):
    out = []
    for ch in (t or "").lower():
        o = ord(ch)
        if 0xFF00 <= o <= 0xFF5E:
            ch = chr(o - 0xFEE0)
        if ch not in (" ", "\t", "　"):
            out.append(ch)
    return "".join(out)

def norm_ep(ep):
    e = (ep or "").strip()
    for p in ("https://", "http://"):
        if e.startswith(p):
            e = e[len(p):]
    return e.rstrip("/")

def load_findings(proj):
    fp = os.path.join(proj, "findings.json")
    if not os.path.exists(fp):
        return []
    with open(fp, encoding="utf-8") as f:
        d = json.load(f)
    return d if isinstance(d, list) else d.get("findings", [])

def load_coverage(proj):
    fp = os.path.join(proj, "coverage.json")
    if not os.path.exists(fp):
        return []
    with open(fp, encoding="utf-8") as f:
        d = json.load(f)
    return d if isinstance(d, list) else d.get("entries", [])

def read_text(proj, rel):
    fp = os.path.join(proj, rel)
    if not os.path.isfile(fp):
        return None
    try:
        with open(fp, "rb") as f:
            return f.read().decode("utf-8", "replace")
    except OSError:
        return None
