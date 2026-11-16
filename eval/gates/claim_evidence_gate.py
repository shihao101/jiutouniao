# -*- coding: utf-8 -*-
"""E1 离线门：结论-证据硬校验（对 findings.json）。
拦截形态：否定性断言+确证无 claims / 确证+待验证矛盾 / 空置信度 / claims 判据未命中 /
引用证据文件缺失（5D5B s6-t08-frpc.log 案）。"""
import os, sys, json
from gate_common import NEG_RE, PENDING_RE, EVID_RE, load_findings, read_text

def run(proj):
    issues = []
    findings = load_findings(proj)
    for f in findings:
        title, detail = f.get("title", ""), f.get("detail", "")
        conf = f.get("confidence", "")
        blob = title + detail
        fid = f.get("id", "?")
        if not conf:
            issues.append(f"[E1] {fid} confidence 为空（14A1 同案）——补 确证/疑似/待查")
        if conf == "确证" and PENDING_RE.search(blob):
            issues.append(f"[E1] {fid}「{title[:30]}」确证与待验证表述矛盾（sendSMS 案形态）——完成验证或降级")
        claims = f.get("claims") or []
        if conf == "确证" and NEG_RE.search(blob) and not claims:
            issues.append(f"[E1] {fid}「{title[:30]}」否定性断言+确证但无 claims 判据（jar 案形态）——补 claims 或降级疑似")
        for i, c in enumerate(claims):
            fp, need = c.get("file", ""), c.get("must_contain", "")
            content = read_text(proj, fp)
            if content is None:
                issues.append(f"[E1] {fid} claims[{i}] 引用文件不存在: {fp}")
            elif need and need not in content:
                issues.append(f"[E1] {fid} claims[{i}] 判据串未命中: {fp} 中无 {need[:40]!r}")
        for m in EVID_RE.finditer(blob):
            rel = m.group(0).rstrip(".,;、）)")
            if read_text(proj, rel) is None and not os.path.isdir(os.path.join(proj, rel)):
                issues.append(f"[E1] {fid} 引用的证据文件缺失: {rel}（5D5B frpc 案形态）")
    return issues

if __name__ == "__main__":
    for iss in run(sys.argv[1]):
        print(iss)
