# -*- coding: utf-8 -*-
"""V6/E3 离线门：覆盖矩阵键归一化僵尸检测 + 负结果语义校验 + 端点表↔鉴权差分对账（v5.1 V8）。
拦截形态：同义单元键漂移产生僵尸 needs_follow_up（0935 案）；
超时/阻断类观测支撑真阴性终态（14A1 Druid 案）；终态无证据摘要；
端点表 N 行只测抽样（某高校网关案：APIList 67 端点 diffed 12）/端点表存在但矩阵未执行。"""
import os, sys, re, glob
from collections import defaultdict
from gate_common import load_coverage, norm_ep, TERMINAL, BAD_OBSERVED

AUTHZ_CLASS_RE = re.compile(r"(鉴权|authz|未授权|越权|blsa|bfla)", re.I)

def _load_endpoint_table(proj):
    """收集端点表行。来源①：evidence/*endpoints*.txt（/ 开头行）；来源②（v5.1.3 修复③）：
    deliverables/*端点表*.md 的 markdown 表格——实战实证智能体把端点表写成 deliverable md
    （表格行内含 / 前缀路径），仅 glob txt 会让 V8 对账失明。"""
    eps = []
    for fp in sorted(glob.glob(os.path.join(proj, "evidence", "*endpoints*.txt"))):
        try:
            with open(fp, encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line.startswith("/") and not line.startswith("//"):
                        eps.append(line)
        except OSError:
            pass
    # 来源②：deliverables 端点表 md（表格行抽取 / 开头路径 token，剥查询串）
    ep_re = re.compile(r"(/[A-Za-z0-9_][A-Za-z0-9_./-]*)")
    for fp in sorted(glob.glob(os.path.join(proj, "deliverables", "*端点表*.md")) +
                     glob.glob(os.path.join(proj, "deliverables", "*endpoints*.md"))):
        try:
            with open(fp, encoding="utf-8") as f:
                for line in f:
                    if not line.lstrip().startswith("|"):
                        continue
                    for tok in ep_re.findall(line):
                        tok = tok.split("?")[0].rstrip("/")
                        if tok.count("/") >= 1 and len(tok) > 1:
                            eps.append(tok)
        except OSError:
            pass
    return eps

def run(proj):
    issues = []
    cov = load_coverage(proj)
    groups = defaultdict(list)
    for i, c in enumerate(cov):
        key = (norm_ep(c.get("endpoint", "")), c.get("param", ""), c.get("vuln_class", ""))
        groups[key].append(i)
    for key, idxs in groups.items():
        if len(idxs) > 1:
            statuses = {cov[i].get("status", "") for i in idxs}
            raw_keys = {cov[i].get("endpoint", "") for i in idxs}
            if len(raw_keys) > 1 and (statuses & TERMINAL) and ("needs_follow_up" in statuses):
                issues.append(f"[V6] 同义单元键漂移产生僵尸 NF: {key[0]} | {key[2]} 共 {len(idxs)} 条原始键 {sorted(raw_keys)}——归一化合并并回填终态（0935 案形态）")
    for i, c in enumerate(cov):
        status, observed, notes = c.get("status", ""), c.get("observed_result", ""), c.get("notes", "")
        cid = c.get("endpoint", "?")
        if status in TERMINAL:
            if observed in BAD_OBSERVED:
                issues.append(f"[E3] {cid} 终态 {status} 由 observed_result={observed} 支撑（Druid 案形态）——超时/阻断只能 needs_follow_up")
            elif not observed:
                issues.append(f"[E3] {cid} 终态 {status} 未声明 observed_result——真阴性须显式 negative_valid（引擎已强制，离线历史数据同检）")
            if not notes:
                issues.append(f"[E3] {cid} 终态 {status} notes 为空——负结果必须留证据摘要")
    # v5.1 V8：端点表↔鉴权差分矩阵全量对账（authz-diff 第五节硬门的离线执行层）
    eps = _load_endpoint_table(proj)
    if eps:
        uniq = sorted(set(eps))
        authz_eps = {norm_ep(c.get("endpoint", "")) for c in cov if AUTHZ_CLASS_RE.search(c.get("vuln_class", ""))}
        if not authz_eps:
            issues.append(f"[V8] 端点表存在（{len(uniq)} 行，evidence/*endpoints*.txt）但鉴权差分矩阵未执行——v5.1 全量未授权检测硬门：无 token 列纯匿名、禁止推迟/抽样（authz-diff 第五节）")
        else:
            covered = [e for e in uniq if any(e in a for a in authz_eps)]
            if len(covered) < len(uniq):
                miss = [e for e in uniq if e not in covered][:5]
                issues.append(f"[V8] 端点表↔矩阵覆盖率缺口: diffed={len(covered)}/total={len(uniq)}——缺如 {miss}（authz-diff v5.1 硬门：100% 入矩阵+diffed/total 记账，缺口行须三态处置）")
    return issues

if __name__ == "__main__":
    for iss in run(sys.argv[1]):
        print(iss)
