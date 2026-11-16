#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""v5.3.3 P2-4 端到端闭环验证门：漏洞发现 → 证据绑定 → 阶段回环 → 最终报告 四环校验。

对既有项目目录（ROOT/projects/<id>/，含 findings.json/coverage.json/evidence//deliverables//report.md）
做四环断言（离线，不依赖 API/靶场）：
  E2E-1 证据绑定：每条 finding 有 evidence_ids 或 claims 绑定；claims 引用的证据文件存在；
  E2E-2 阶段回环：覆盖账本 needs_follow_up/vulnerable 单元存在复测痕迹（count≥2），
        或交付物链 s3→s4→s5→s8 逐级承接（回环=上一阶段缺口进入下一阶段并在后续闭环/移交）；
  E2E-3 覆盖↔发现闭环：每个 vulnerable 覆盖单元必须有对应 finding（title/detail/vuln_class
        关键词重叠）；终态真阴性必须 observed_result=negative_valid（E3 口径复用）；
  E2E-4 最终报告：report.md 存在且引用 ≥80% finding（编号/标题前缀）；覆盖账本存在
        needs_follow_up 时报告含「待续/移交」承接节。

--selftest 构造合成项目夹具自验（正例 0 issues / 反例 4 issues 各断言）。
退出码 0=闭环成立。"""
import argparse
import json
import os
import re
import sys
import tempfile
import time

ROOT = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
AUTHZ_RE = re.compile(r"鉴权|authz|越权|未授权|idor", re.I)


def norm(t):
    return (t or "").lower()


def load_json(fp, default):
    if not os.path.exists(fp):
        return default
    with open(fp, encoding="utf-8") as f:
        d = json.load(f)
    return d


def check_e2e(proj):
    issues = []
    findings = load_json(os.path.join(proj, "findings.json"), [])
    if isinstance(findings, dict):
        findings = findings.get("findings", [])
    coverage = load_json(os.path.join(proj, "coverage.json"), [])
    if isinstance(coverage, dict):
        coverage = coverage.get("entries", [])
    report_fp = os.path.join(proj, "report.md")
    report = open(report_fp, encoding="utf-8", errors="replace").read() if os.path.exists(report_fp) else ""

    # E2E-1 证据绑定
    unbound = []
    for f in findings:
        ev_ids = f.get("evidence_ids") or []
        claims = f.get("claims") or []
        if not ev_ids and not claims:
            unbound.append(f.get("id", "?"))
            continue
        for c in claims:
            fp = c.get("file", "")
            if fp and not os.path.exists(os.path.join(proj, fp)) and not os.path.exists(os.path.join(proj, "evidence", fp)):
                issues.append(f"[E2E-1] {f.get('id', '?')} claims 引用证据文件缺失: {fp}")
    if unbound:
        issues.append(f"[E2E-1] {len(unbound)} 条 finding 无证据绑定（evidence_ids 与 claims 均空）: {', '.join(unbound[:5])}")

    # E2E-2 阶段回环：复测痕迹 或 交付物链承接
    retested = [c for c in coverage if c.get("count", 0) >= 2]
    deliverables = sorted(os.listdir(os.path.join(proj, "deliverables"))) if os.path.isdir(os.path.join(proj, "deliverables")) else []
    stages_seen = sorted({m.group(1) for d in deliverables for m in [re.match(r"^s(\d)", d)] if m})
    chain_ok = len(stages_seen) >= 3  # 至少三个阶段的交付物承接（如 s2/s3/s4/s5/s8）
    if coverage and not retested and not chain_ok:
        issues.append(f"[E2E-2] 覆盖账本 {len(coverage)} 单元零复测痕迹（count 均 <2）且交付物链不足 3 阶段（{stages_seen}）——回环缺失")
    if not coverage and len(findings) > 0 and not chain_ok:
        issues.append("[E2E-2] 无覆盖账本且交付物链不足 3 阶段——回环不可证")

    # E2E-3 覆盖↔发现闭环
    ftext = [norm(f.get("title", "") + " " + f.get("detail", "")) for f in findings]
    for c in coverage:
        if c.get("status") == "vulnerable":
            key = norm(c.get("vuln_class", "") + " " + c.get("endpoint", ""))
            toks = [t for t in re.split(r"[^a-z0-9\u4e00-\u9fff]+", key) if len(t) >= 2]
            if not any(any(t in ft for t in toks) for ft in ftext):
                issues.append(f"[E2E-3] vulnerable 覆盖单元无对应 finding: {c.get('endpoint', '')} [{c.get('vuln_class', '')}]")
        if c.get("status") in ("ruled_out", "no_issue_found") and c.get("observed_result", "") != "negative_valid":
            issues.append(f"[E2E-3] 终态真阴性未声明 negative_valid: {c.get('endpoint', '')}（E3 口径）")

    # E2E-4 最终报告闭环
    if not report:
        issues.append("[E2E-4] report.md 缺失——最终报告环断裂")
    else:
        covered = 0
        for f in findings:
            fid = f.get("id", "")
            title = f.get("title", "")
            if (fid and fid in report) or (title and norm(title)[:20] in norm(report)):
                covered += 1
        if findings and covered / len(findings) < 0.8:
            issues.append(f"[E2E-4] 报告仅引用 {covered}/{len(findings)} 条 finding（<80%）——报告与发现库 1:1 断裂")
        nf = [c for c in coverage if c.get("status") == "needs_follow_up"]
        if nf and not re.search(r"待续|移交|needs_follow_up|复测建议", report, re.I):
            issues.append(f"[E2E-4] 覆盖账本含 {len(nf)} 个 needs_follow_up 但报告无「待续/移交」承接节")
    return issues


def make_fixture(base, good):
    """合成项目夹具：good=True 正例（闭环成立）/ False 反例（四环各断一处）。"""
    os.makedirs(os.path.join(base, "deliverables"), exist_ok=True)
    os.makedirs(os.path.join(base, "evidence"), exist_ok=True)
    if good:
        findings = [
            {"id": "F-1", "title": "/api/exec 命令注入（回显确证）", "detail": "GET /api/exec cmd=id 回显 uid=0，证据 evidence/e2e-1.log",
             "confidence": "确证", "severity": "高", "evidence_ids": ["EV-X"], "claims": [{"file": "evidence/e2e-1.log", "must_contain": "uid=0"}]},
            {"id": "F-2", "title": "越权读取他人订单", "detail": "GET /api/order/2 越权越权，证据 evidence/e2e-2.log", "confidence": "确证",
             "severity": "高", "evidence_ids": ["EV-Y"], "claims": []},
        ]
        coverage = [
            {"endpoint": "POST /api/exec", "vuln_class": "命令注入", "status": "vulnerable", "count": 2, "notes": "回显确证"},
            {"endpoint": "GET /api/order/2", "vuln_class": "越权", "status": "vulnerable", "count": 1, "notes": "越权"},
            {"endpoint": "GET /api/config", "vuln_class": "信息泄露", "status": "ruled_out", "observed_result": "negative_valid", "count": 1},
        ]
    else:
        findings = [
            {"id": "F-1", "title": "命令注入疑似", "detail": "无证据未验证", "confidence": "待查", "severity": "低", "evidence_ids": [], "claims": []},
        ]
        coverage = [
            {"endpoint": "POST /api/exec", "vuln_class": "命令注入", "status": "vulnerable", "count": 1, "notes": ""},
            {"endpoint": "GET /api/config", "vuln_class": "信息泄露", "status": "ruled_out", "observed_result": "", "count": 1},
        ]
    json.dump(findings, open(os.path.join(base, "findings.json"), "w", encoding="utf-8"), ensure_ascii=False)
    json.dump(coverage, open(os.path.join(base, "coverage.json"), "w", encoding="utf-8"), ensure_ascii=False)
    with open(os.path.join(base, "evidence", "e2e-1.log"), "w") as f:
        f.write("uid=0\n")
    with open(os.path.join(base, "deliverables", "s3-筛查矩阵判定表.md"), "w", encoding="utf-8") as f:
        f.write("| C-01 | 命令注入 | 假设 |\n| C-02 | 越权 | 假设 |\n| C-03 | xss | 不适用 |\n")
    with open(os.path.join(base, "deliverables", "s4-验证与利用记录.md"), "w", encoding="utf-8") as f:
        f.write("承接 s3 假设清单逐条处置\n")
    if good:  # 反例：交付物链只有 2 阶段（回环不可证），正例补 s5 凑足承接链
        with open(os.path.join(base, "deliverables", "s5-利用与深测记录.md"), "w", encoding="utf-8") as f:
            f.write("承接 s4 队列\n")
    if good:
        with open(os.path.join(base, "report.md"), "w", encoding="utf-8") as f:
            f.write("# 测试报告\n\nF-1 /api/exec 命令注入\nF-2 越权读取他人订单\n\n## 待续清单\n\n- 无\n")
    else:
        with open(os.path.join(base, "report.md"), "w", encoding="utf-8") as f:
            f.write("# 测试报告\n\n（与发现库不同步的正文）\n")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--project-id", default="", help="ROOT/projects/<id>（离线四环校验）")
    ap.add_argument("--selftest", action="store_true", help="合成夹具自验（正例 0 issues / 反例命中 E2E 各环）")
    a = ap.parse_args()
    if a.selftest:
        tmp = tempfile.mkdtemp(prefix="e2e-loop-")
        good = os.path.join(tmp, "good")
        bad = os.path.join(tmp, "bad")
        make_fixture(good, True)
        make_fixture(bad, False)
        gi = check_e2e(good)
        bi = check_e2e(bad)
        ok = True
        if gi:
            print(f"FAIL 正例夹具应零 issues: {gi}")
            ok = False
        rings = {"E2E-1": False, "E2E-2": False, "E2E-3": False, "E2E-4": False}
        for i in bi:
            for k in rings:
                if i.startswith(f"[{k}]"):
                    rings[k] = True
        missing = [k for k, v in rings.items() if not v]
        if missing:
            print(f"FAIL 反例夹具未命中环: {missing}（got {bi}）")
            ok = False
        print(f"e2e_loop_check selftest: {'4/4 环校验生效' if ok else '未过'}（正例 {len(gi)} issues / 反例 {len(bi)} issues）")
        return 0 if ok else 1
    if not a.project_id:
        ap.print_help()
        return 2
    proj = os.path.join(ROOT, "projects", a.project_id)
    if not os.path.isdir(proj):
        print(f"FAIL 项目目录不存在: {proj}")
        return 1
    issues = check_e2e(proj)
    rings = {}
    for i in issues:
        rings[i.split("]")[0][1:]] = rings.get(i.split("]")[0][1:], 0) + 1
    for i in issues:
        print(i)
    print(f"\ne2e 闭环: {'成立' if not issues else '断裂'}（{len(issues)} 项问题；命中环 {rings or '无'}）")
    return 0 if not issues else 1


if __name__ == "__main__":
    sys.exit(main())
