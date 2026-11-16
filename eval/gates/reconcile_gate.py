# -*- coding: utf-8 -*-
"""E6/B2 离线门：报告↔发现库↔证据引用 三方对账。
拦截形态：报告 R- 条目多于 findings（1E8B 案）/ 归一化标题重复（1AC8 案）/ 报告引用 evidence 路径缺失。"""
import os, re, sys
from gate_common import load_findings, norm_title, read_text

def run(proj):
    issues = []
    findings = load_findings(proj)
    report = read_text(proj, "report.md")
    if report:
        r_ids = re.findall(r"^### R-\d+", report, re.M)
        if r_ids and len(r_ids) > len(findings):
            issues.append(f"[E6] 报告定级条目（{len(r_ids)}）多于 findings 记录（{len(findings)}）——存在确证发现未入库（1E8B 案形态）")
        for m in re.finditer(r"evidence/[A-Za-z0-9_\-./~*]+", report):
            rel = m.group(0).rstrip(".,;、）)")
            if read_text(proj, rel) is None and not os.path.isdir(os.path.join(proj, rel)):
                issues.append(f"[E6] 报告引用的证据文件缺失: {rel}")
    seen = {}
    for f in findings:
        k = norm_title(f.get("title", ""))
        if k and k in seen:
            issues.append(f"[B2] 归一化标题完全一致的重复发现: {seen[k]} 与 {f.get('id','?')}「{(f.get('title') or '')[:30]}」（1AC8 案形态）——同根因合并")
        elif k:
            seen[k] = f.get("id", "?")
    return issues

if __name__ == "__main__":
    for iss in run(sys.argv[1]):
        print(iss)
