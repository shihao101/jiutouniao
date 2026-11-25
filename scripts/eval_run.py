#!/usr/bin/env python3
"""九头鸟评测环（技能进化评测环，communitytools 思想）：
起本地靶场 → 经 API 创建并跑完一个完整项目 → 按预期清单判分 → 产出评测报告。

用法：
    python3 scripts/eval_run.py                       # 默认连本机 8787（读 config.json 的 auth_token）
    python3 scripts/eval_run.py --timeout-min 90 --min-recall 0.6

前提：
    1. 九头鸟容器已就绪且 config.json 配置了真实 LLM（mock 模式不会发现漏洞，得分为 0 属预期）；
    2. auth_token 已配置（API 直连令牌），或用 --token 传入；
    3. 判分以「漏洞类别命中」为准——评测靶场是确定性的，同一引擎版本多轮分数应稳定，
       分数回退 = 引擎/技能回归；未命中项的失败案例是技能库迭代输入。

流程：spawn 靶场(127.0.0.1:18080) → POST /api/projects → POST start → 轮询状态
      → 读 projects/<id>/findings.json + coverage → 判分 → eval/results/eval-<ts>.md
"""
import argparse
import os as _os

# v4.7.1 评测体系与平台分离：靶标/埋点从外部评测包加载（JTN_EVALPACK_PATH，默认项目同级 ../jtn-evalpack）
def eval_pack_root():
    env = _os.environ.get("JTN_EVALPACK_PATH", "").strip()
    if env:
        return _os.path.abspath(env)
    cand = _os.path.abspath(_os.path.join(_os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))), "..", "jtn-evalpack"))
    if _os.path.isdir(cand):
        return cand
    return _os.path.abspath(_os.path.join(_os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))), "jtn-evalpack"))

EVAL_PACK = eval_pack_root()

import json
import os
import shutil
import signal
import subprocess
import sys
import time
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TARGET_PORT = 18080


def api(base, token, method, path, payload=None, timeout=60):
    req = urllib.request.Request(base.rstrip("/") + path, method=method)
    req.add_header("Authorization", "Bearer " + token)
    data = None
    if payload is not None:
        data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        req.add_header("Content-Type", "application/json")
    with urllib.request.urlopen(req, data=data, timeout=timeout) as r:
        return json.loads(r.read().decode("utf-8"))


def docker_exec(container, cmd, timeout=30):
    r = subprocess.run(["docker", "exec", container] + cmd, capture_output=True, text=True, timeout=timeout)
    return r.returncode, r.stdout, r.stderr


def start_target(port, container=""):
    """靶场生命周期（v3.5.1 容器感知）：智能体在容器里 curl 127.0.0.1，
    靶场必须与智能体同网络命名空间——指定容器时经 docker exec 在容器内起靶场
    （v3.5.0 曾在宿主起靶，容器内不可达，评测必得 0 分）。无 docker 时回退本机模式。"""
    if container:
        rc, out, err = docker_exec(container, ["sh", "-c",
            f'command -v python3 >/dev/null && test -f "$JTN_EVALPACK_PATH/target/target.py"'])
        if rc != 0:
            raise RuntimeError(f"容器 {container} 内无评测靶场（需 v3.5.1+ 镜像）")
        docker_exec(container, ["sh", "-c", f"pkill -f 'target.py --port' || true"])
        docker_exec(container, ["sh", "-c",
            f'nohup python3 "$JTN_EVALPACK_PATH/target/target.py" --port {port} >/tmp/evaltarget.log 2>&1 &'])
        for _ in range(40):
            rc, out, _ = docker_exec(container, ["sh", "-c",
                f"curl -s -m 2 -o /dev/null -w '%{{http_code}}' http://127.0.0.1:{port}/robots.txt"])
            if out.strip() == "200":
                print(f"   靶场已在容器 {container} 内就绪（容器内 127.0.0.1:{port} 可达）")
                return ("docker", container)
            time.sleep(0.5)
        raise RuntimeError("容器内评测靶场启动失败")
    t = subprocess.Popen([sys.executable, os.path.join(EVAL_PACK, "target", "target.py"),
                          "--port", str(port)],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                         preexec_fn=os.setsid)
    for _ in range(30):
        try:
            with urllib.request.urlopen(f"http://127.0.0.1:{port}/robots.txt", timeout=2) as r:
                if r.status == 200:
                    return ("local", t)
        except Exception:
            time.sleep(0.5)
    raise RuntimeError("评测靶场启动失败")


def stop_target(handle):
    kind, v = handle
    try:
        if kind == "docker":
            docker_exec(v, ["sh", "-c", "pkill -f 'target.py --port' || true"])
        else:
            os.killpg(os.getpgid(v.pid), signal.SIGTERM)
    except Exception:
        pass


def load_token(args):
    if args.token:
        return args.token
    cfg = json.load(open(os.path.join(ROOT, "config.json"), encoding="utf-8"))
    tok = cfg.get("auth_token", "")
    if not tok:
        raise SystemExit("config.json 未配置 auth_token，请用 --token 传入 API 直连令牌")
    return tok


def score(findings, coverage, expected):
    items = [it for it in expected["items"] if it.get("scoreable", True)]  # v4.8：监控替代条目不计分

    def text_of(f):
        return (f.get("title", "") + " " + f.get("detail", "")).lower()

    hit, miss = [], []
    matched_findings = set()
    for it in items:
        kws = [k.lower() for k in it["keywords"]]
        ok = False
        for idx, f in enumerate(findings):
            t = text_of(f)
            if any(k in t for k in kws):
                ok = True
                matched_findings.add(idx)
                break
        if not ok:
            for c in coverage:
                ck = (c.get("endpoint", "") + " " + c.get("vuln_class", "") + " " + c.get("notes", "")).lower()
                if c.get("status") == "vulnerable" and any(k in ck for k in kws):
                    ok = True
                    matched_findings.add(-1)
                    break
        (hit if ok else miss).append(it)
    extras = [f for idx, f in enumerate(findings) if idx not in matched_findings]
    recall = len(hit) / len(items) if items else 0.0
    # v3.9.4 双模式拆分：declared=自述面召回（覆盖下限），hidden=清单外盲挖（0day 能力度量）
    # v4.8：mock 模式单列（OAuth/对抗 mock 埋点），不混入 declared/hidden
    declared = [i for i in items if i.get("mode", "declared") == "declared"]
    hidden = [i for i in items if i.get("mode") == "hidden"]
    mock = [i for i in items if i.get("mode") == "mock"]
    declared_hit = [i for i in hit if i.get("mode", "declared") == "declared"]
    hidden_hit = [i for i in hit if i.get("mode") == "hidden"]
    mock_hit = [i for i in hit if i.get("mode") == "mock"]
    # v4.4 批次5：高危隐藏项召回（high_risk_anonymous_recall 口径——weight=high 且 mode=hidden 的
    # 匿名可达高危项（类别清单见外部评测包 expected.json）
    hidden_high = [i for i in hidden if i.get("weight") == "high"]
    hidden_high_hit = [i for i in hidden_hit if i.get("weight") == "high"]
    stats = {
        "declared_recall": (len(declared_hit) / len(declared)) if declared else 0.0,
        "hidden_recall": (len(hidden_hit) / len(hidden)) if hidden else 0.0,
        "mock_recall": (len(mock_hit) / len(mock)) if mock else 0.0,
        "declared_total": len(declared), "hidden_total": len(hidden), "mock_total": len(mock),
        "declared_hit": len(declared_hit), "hidden_hit": len(hidden_hit), "mock_hit": len(mock_hit),
        "hidden_high_total": len(hidden_high), "hidden_high_hit": len(hidden_high_hit),
        "high_risk_anonymous_recall": (len(hidden_high_hit) / len(hidden_high)) if hidden_high else 0.0,
    }
    return recall, hit, miss, extras, stats


# ---------- v4.8 三指标（S3《筛查矩阵判定表》↔ expected matrix_class 比对，§5.3） ----------

import re as _re

MATRIX_ROW_RE = _re.compile(r"^\|\s*(C-\d{2})\s*\|")
MATRIX_VERDICT_RE = _re.compile(r"\|\s*(假设|不适用|待判定)\s*\|")


def parse_matrix_table(path):
    """判定表 → {C-NN: 假设|不适用|待判定}（行格式与引擎 M2 门同一规范）。"""
    verdicts = {}
    for line in open(path, encoding="utf-8"):
        m = MATRIX_ROW_RE.match(line.strip())
        if not m:
            continue
        v = MATRIX_VERDICT_RE.search(line)
        if v:
            verdicts[m.group(1)] = v.group(1)
    return verdicts


def matrix_metrics(matrix_path, expected):
    """三指标：假设召回率（埋点类判『假设』占比，门槛 ≥80%）/ 不适用误判率（埋点类判
    『不适用』，最危险漏报形态，门槛 =0）/ 假设精度（未埋面却提假设，门槛 ≤10%）。"""
    planted = sorted({it["matrix_class"] for it in expected["items"]
                      if it.get("scoreable", True) and it.get("matrix_class")})
    if not os.path.exists(matrix_path):
        return {"available": False, "planted_classes": len(planted),
                "note": "未产出《筛查矩阵判定表》（projects/<id>/deliverables/s3-筛查矩阵判定表.md）——三指标不可评（引擎 M2 门应已拦截缺表收口）"}
    verdicts = parse_matrix_table(matrix_path)
    planted_set = set(planted)
    assumed_planted = [c for c in planted if verdicts.get(c) == "假设"]
    na_planted = [c for c in planted if verdicts.get(c) == "不适用"]
    pending_planted = [c for c in planted if verdicts.get(c) == "待判定"]
    assumed_all = [c for c, v in verdicts.items() if v == "假设"]
    unplanted_assumed = [c for c in assumed_all if c not in planted_set]
    recall = len(assumed_planted) / len(planted) if planted else 0.0
    na_rate = len(na_planted) / len(planted) if planted else 0.0
    precision = (1 - len(unplanted_assumed) / len(assumed_all)) if assumed_all else 1.0
    return {"available": True, "planted_classes": len(planted), "judged_rows": len(verdicts),
            "assume_recall": recall, "assume_recall_planted_hit": len(assumed_planted),
            "na_false_rate": na_rate, "na_planted": na_planted,
            "pending_planted": pending_planted,
            "assume_precision": precision, "assumed_total": len(assumed_all),
            "unplanted_assumed": unplanted_assumed,
            "thresholds": {"assume_recall_min": 0.80, "na_false_max": 0.0, "assume_precision_min": 0.90}}


# ---------- v5.3.3 P2-2 高危盲测召回/精确率报告 ----------

BLIND_THRESHOLDS = {"hidden_recall_min": 0.4, "high_risk_anonymous_recall_min": 0.4,
                    "findings_precision_min": 0.3}



# ---------- v7.4.0 D2/D3：技能迭代工单 + 自主性计量（学习环） ----------

# D2：漏洞类 → 候选技能映射（来自 skills/00-router.md 主干路径的静态摘录；
# 未命中映射的类由人工归类——工单是迭代输入不是自动改动）。
CLASS_SKILL = {
    "SQL注入": "sqli-deep", "XSS": "xss-context", "SSRF": "ssrf-deep", "命令注入": "cmdi-deep",
    "路径穿越": "path-traversal", "文件上传": "upload-bypass", "XXE": "xxe-full", "SSTI": "ssti-engine-map",
    "反序列化": "java-deser-playbook", "越权": "api-idor", "未授权": "authz-diff", "认证": "auth-flow-deep",
    "会话": "session-lifecycle", "JWT": "jwt-crypto", "逻辑": "business-state-machine", "支付": "logic-purchase-limit",
    "竞态": "race-condition", "限次": "rate-limit-playbook", "提示注入": "llm-top10", "信息泄露": "api-doc-leak",
    "GraphQL": "graphql-websocket", "缓存": "cache-poisoning", "走私": "request-smuggling", "CORS": "cors-redirect-hostheader",
    "重定向": "cors-redirect-hostheader", "安全头": "http-security-headers", "TLS": "tls-deep-audit", "弱口令": "weak-cred-bruteforce",
}


def skill_for_item(it):
    cls = it.get("class") or it.get("vuln_class") or ""
    for k, sk in CLASS_SKILL.items():
        if k in str(cls):
            return sk
    kws = " ".join(it.get("keywords", []) or [])
    for k, sk in CLASS_SKILL.items():
        if k in kws:
            return sk
    return "（待人工归类）"


def skill_workorder(miss, extras, out_dir, project_id):
    """D2：未命中清单 → 技能迭代工单（eval/results/skill-iteration-<ts>.md）——
    每条 miss 给出候选技能与建议动作（增补剧本节/阴阳判据/claims 模板），
    作为技能库迭代的直接输入（v4.8 设计意图的管线化落地）。"""
    if not miss:
        return None
    ts = time.strftime("%Y%m%d-%H%M%S")
    os.makedirs(out_dir, exist_ok=True)
    out = os.path.join(out_dir, f"skill-iteration-{ts}.md")
    with open(out, "w", encoding="utf-8") as f:
        f.write(f"# 技能迭代工单（v7.4.0 D2）\n\n项目: {project_id}  生成: {ts}\n\n")
        f.write("> 本工单由 eval 判分自动生成——未命中项即技能库迭代输入；建议动作需人工复核后落地（改技能剧本而非改判分）。\n\n")
        f.write("## 未命中项（按候选技能分组）\n\n")
        groups = {}
        for it in miss:
            groups.setdefault(skill_for_item(it), []).append(it)
        for sk, items in sorted(groups.items(), key=lambda kv: -len(kv[1])):
            f.write(f"### {sk}（{len(items)} 条）\n\n")
            for it in items:
                f.write(f"- [{it.get('mode', 'declared')}/{it.get('weight', '-')}] {it.get('desc') or it.get('keywords')}: {it.get('keywords')}\n")
            f.write("  建议动作: 对照技能剧本补「最小探针 + 阴阳判据 + claims 模板」三件套；已覆盖则补 depends_on 路由。\n\n")
        f.write("## 清单外发现复核（extras，D3 转化率分子来源）\n\n")
        for e in extras or []:
            f.write(f"- [{e.get('severity', '?')}] {e.get('title', '')[:80]}\n")
        if not extras:
            f.write("（无）\n")
    return out


def autonomy_section(project_id):
    """D3：自主性计量——读 projects/<id>/autonomy.json（v7.1.0 账本导出）+ 覆盖矩阵
    假设命中率（vuln_class 含「假设」的单元 vulnerable 占比）。autonomy.json 缺失（旧项目）
    返回 None。"""
    path = os.path.join(ROOT, "projects", project_id, "autonomy.json")
    if not os.path.exists(path):
        return None
    try:
        au = json.load(open(path, encoding="utf-8"))
    except Exception:
        return None
    stats = au.get("stats") or {}
    return {
        "proposals": stats.get("total", 0),
        "approved": stats.get("approved", 0),
        "conversion": stats.get("conversion", 0.0),
        "escalations": stats.get("escalations", 0),
    }


def assumption_metrics(coverage):
    """D3：假设命中率（确证假设 / 已测假设）——vuln_class 含「假设」的覆盖单元统计。"""
    units = [c for c in coverage if "假设" in str(c.get("vuln_class", ""))]
    hit = [c for c in units if c.get("status") == "vulnerable"]
    rate = (len(hit) / len(units)) if units else None
    return {"units": len(units), "hit": len(hit), "rate": rate}


def blind_report(findings, coverage, expected, project_id, out_dir):
    """P2-2：盲测召回（declared/hidden/mock/hidden_high 沿用 score 口径）+ 精确率侧新增。
    精确率：findings_precision = 命中预期项的 findings / 全部 findings——清单外 extras
    不直接计误报（真实项目常有超清单发现），单列供人工复核；高危 findings 精度单列。"""
    recall, hit, miss, extras, stats = score(findings, coverage, expected)
    n = len(findings)
    matched = n - len(extras)
    precision = matched / n if n else 0.0
    high = [f for f in findings if f.get("severity") in ("高", "高危", "high", "critical")]
    high_matched = sum(1 for f in high if any(
        any(k.lower() in (f.get("title", "") + f.get("detail", "")).lower() for k in it["keywords"])
        for it in expected["items"] if it.get("scoreable", True)))
    high_precision = high_matched / len(high) if high else 1.0
    gates = {
        "hidden_recall": (stats["hidden_recall"], BLIND_THRESHOLDS["hidden_recall_min"]),
        "high_risk_anonymous_recall": (stats["high_risk_anonymous_recall"], BLIND_THRESHOLDS["high_risk_anonymous_recall_min"]),
        "findings_precision": (precision, BLIND_THRESHOLDS["findings_precision_min"]),
    }
    ts = time.strftime("%Y%m%d-%H%M%S")
    os.makedirs(out_dir, exist_ok=True)
    wo = skill_workorder(miss, extras, out_dir, project_id)  # v7.4.0 D2
    am = autonomy_section(project_id)                         # v7.4.0 D3
    asm = assumption_metrics(coverage)                        # v7.4.0 D3
    out = os.path.join(out_dir, f"blind-{ts}.md")
    with open(out, "w", encoding="utf-8") as f:
        f.write(f"# 高危盲测召回/精确率报告（v5.3.3 P2-2）\n\n项目: {project_id}  生成: {ts}\n\n")
        f.write("## 召回侧\n\n")
        f.write(f"- 总召回: {recall:.0%}（命中 {len(hit)}/{len([i for i in expected['items'] if i.get('scoreable', True)])}）\n")
        f.write(f"- 自述面 declared: {stats['declared_recall']:.0%}（{stats['declared_hit']}/{stats['declared_total']}）\n")
        f.write(f"- 清单外盲挖 hidden: {stats['hidden_recall']:.0%}（{stats['hidden_hit']}/{stats['hidden_total']}）\n")
        f.write(f"- mock 埋点: {stats['mock_recall']:.0%}（{stats['mock_hit']}/{stats['mock_total']}）\n")
        f.write(f"- **匿名高危召回 high_risk_anonymous: {stats['high_risk_anonymous_recall']:.0%}（{stats['hidden_high_hit']}/{stats['hidden_high_total']}）**\n\n")
        f.write("## 精确率侧\n\n")
        f.write(f"- findings 精度: {precision:.0%}（命中预期 {matched}/{n}）\n")
        f.write(f"- 高危 findings 精度: {high_precision:.0%}（{high_matched}/{len(high)}）\n\n")
        f.write("## 清单外发现（extras，人工复核输入）\n\n")
        if extras:
            for e in extras:
                f.write(f"- [{e.get('severity', '?')}/{e.get('confidence', '?')}] {e.get('title', '')[:80]}\n")
        else:
            f.write("（无）\n\n")
        f.write("\n## 自主性计量（v7.4.0 D3）\n\n")
        if am:
            f.write(f"- 提案总数: {am['proposals']}｜批准: {am['approved']}｜转化率: {am['conversion']:.0%}｜升维: {am['escalations']}\n")
        else:
            f.write("- autonomy.json 缺失（v7.1.0 前旧项目）\n")
        if asm["units"]:
            f.write(f"- 假设命中率: {asm['rate']:.0%}（确证 {asm['hit']}/{asm['units']} 单元）\n")
        else:
            f.write("- 假设命中率: 无假设单元（本轮未走 0day 假设工作流）\n")
        if wo:
            f.write(f"- 技能迭代工单: {os.path.basename(wo)}\n")
        f.write("\n## 阈值门\n\n")
        ok_all = True
        for k, (v, th) in gates.items():
            ok = v >= th
            ok_all &= ok
            f.write(f"- {'PASS' if ok else 'FAIL'} {k}: {v:.0%}（门槛 {th:.0%}）\n")
    print(f"盲测报告: {out}")
    for k, (v, th) in gates.items():
        print(f"  {'PASS' if v >= th else 'FAIL'} {k}: {v:.0%}（门槛 {th:.0%}）")
    return 0 if ok_all else 1


# ---------- v5.3.3 P2-3 匿名身份状态覆盖率 ----------

AUTHZ_RE = _re.compile(r"鉴权|authz|越权|未授权|idor|blsa|bfla", _re.I)
IDENTITY_STATES = ("pure_anonymous", "gate_found", "identity_obtained")
STATE_KW = {
    "pure_anonymous": _re.compile(r"纯匿名|匿名|无token|无 token|未认证|未登录|anonymous|401", _re.I),
    "gate_found": _re.compile(r"门控|202|挑战|403|waf|haslogin|登录墙|登墙|gated", _re.I),
    "identity_obtained": _re.compile(r"客户提供|测试账号|已登录|已获身份|身份闭环|带cookie|带 cookie|token 后|身份获取后", _re.I),
}


def identity_state(entry):
    """三态推断：coverage/finding 的 notes+detail+endpoint 关键词（authz-diff 无凭证三态路由同口径）。"""
    blob = (entry.get("notes", "") + " " + entry.get("detail", "") + " " + entry.get("endpoint", "")).lower()
    for st in IDENTITY_STATES:
        if STATE_KW[st].search(blob):
            return st
    return "pure_anonymous"  # 缺省按纯匿名口径（最严格统计面）


def identity_coverage_report(coverage, findings, project_id, out_dir):
    """P2-3：匿名身份三态 × 鉴权族覆盖矩阵。
    每态统计 authz 类覆盖单元的 status 分布与闭环率；vulnerable/needs_follow_up 跨态分布
    直接暴露「拿到身份才测/匿名跳过」类覆盖空洞。硬门：pure_anonymous 态 needs_follow_up
    占比 >0.6 时 FAIL（v5.1 全量硬门：无 token 列纯匿名禁止推迟/抽样）。"""
    rows = [c for c in coverage if AUTHZ_RE.search(c.get("vuln_class", "") + " " + c.get("endpoint", ""))]
    matrix = {st: {"total": 0, "vulnerable": 0, "needs_follow_up": 0, "closed": 0} for st in IDENTITY_STATES}
    for c in rows:
        m = matrix[identity_state(c)]
        m["total"] += 1
        if c.get("status") == "vulnerable":
            m["vulnerable"] += 1
        elif c.get("status") == "needs_follow_up":
            m["needs_follow_up"] += 1
        elif c.get("status") in ("no_issue_found", "ruled_out"):
            m["closed"] += 1
    ts = time.strftime("%Y%m%d-%H%M%S")
    os.makedirs(out_dir, exist_ok=True)
    out = os.path.join(out_dir, f"identity-coverage-{ts}.md")
    total = len(rows)
    with open(out, "w", encoding="utf-8") as f:
        f.write(f"# 匿名身份状态覆盖率报告（v5.3.3 P2-3）\n\n项目: {project_id}  生成: {ts}\n\n")
        f.write(f"鉴权族覆盖单元总数: {total}（鉴权/authz/越权/未授权/IDOR/BLSA/BFLA）\n\n")
        f.write("| 身份状态 | 单元数 | vulnerable | needs_follow_up | 已闭环(no_issue/ruled_out) | NF 占比 |\n|---|---|---|---|---|---|\n")
        anon_nf_ratio = 0.0
        for st in IDENTITY_STATES:
            m = matrix[st]
            nf_ratio = (m["needs_follow_up"] / m["total"]) if m["total"] else 0.0
            if st == "pure_anonymous":
                anon_nf_ratio = nf_ratio
            f.write(f"| {st} | {m['total']} | {m['vulnerable']} | {m['needs_follow_up']} | {m['closed']} | {nf_ratio:.0%} |\n")
        f.write(f"\n- pure_anonymous NF 占比: {anon_nf_ratio:.0%}（硬门 ≤60%——纯匿名推迟/抽样即空洞，v5.1 全量硬门口径）\n")
        f.write(f"- 身份三态路由对齐：authz-diff「无凭证三态路由」+ identity-bootstrapping 索取闭环\n")
    print(f"身份覆盖率报告: {out}")
    for st in IDENTITY_STATES:
        m = matrix[st]
        print(f"  {st}: total={m['total']} vulnerable={m['vulnerable']} nf={m['needs_follow_up']} closed={m['closed']}")
    ok = anon_nf_ratio <= 0.6
    print(f"  {'PASS' if ok else 'FAIL'} pure_anonymous NF 占比 {anon_nf_ratio:.0%}（硬门 ≤60%）")
    return 0 if ok else 1


def _load_project_data(args, project_id):
    """P2-2/P2-3 数据装载：优先 findings.json/coverage.json 本地文件，缺省走 API 补 coverage。"""
    proj_dir = os.path.join(ROOT, "projects", project_id)
    ffp = os.path.join(proj_dir, "findings.json")
    findings = json.load(open(ffp, encoding="utf-8")) if os.path.exists(ffp) else []
    if isinstance(findings, dict):
        findings = findings.get("findings", [])
    coverage = []
    cvp = os.path.join(proj_dir, "coverage.json")
    if os.path.exists(cvp):
        d = json.load(open(cvp, encoding="utf-8"))
        coverage = d if isinstance(d, list) else d.get("entries", [])
    else:
        token = load_token(args)
        try:
            cov = api(args.base_url, token, "GET", f"/api/projects/{project_id}/coverage")
            coverage = cov if isinstance(cov, list) else cov.get("items", cov.get("coverage", []))
        except Exception as e:
            print(f"⚠ coverage.json 缺失且 API 拉取失败（{e}）——coverage 侧按空账本统计")
    return findings, coverage


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--base-url", default="http://127.0.0.1:8787")
    ap.add_argument("--token", default="")
    ap.add_argument("--timeout-min", type=int, default=110)  # v3.6.2：三轮实测 75min 均在 s7/s8 被截断，默认提到 110 保证全管线可完成
    ap.add_argument("--min-recall", type=float, default=None,
                    help="低于该召回率以退出码 1 结束（默认读外部评测包 expected.json 的 min_recall）")
    ap.add_argument("--keep", action="store_true", help="保留评测项目与靶场进程")
    ap.add_argument("--container", default="", help="在指定 docker 容器内起靶场（默认自动探测 jiutouniao 容器；智能体在容器内需与靶场同网络命名空间）")
    # v5.3.3 P2-2/P2-3：离线报告模式（不跑靶场/管线，直接对既有项目出报告）
    ap.add_argument("--blind-report", dest="project_id", default="", metavar="PROJECT_ID",
                    help="P2-2：对既有项目产出高危盲测召回/精确率报告（eval/results/blind-<ts>.md）")
    ap.add_argument("--identity-coverage", dest="identity_project_id", default="", metavar="PROJECT_ID",
                    help="P2-3：对既有项目产出匿名身份三态×鉴权族覆盖矩阵（eval/results/identity-coverage-<ts>.md）")
    a = ap.parse_args()

    if a.project_id or a.identity_project_id:
        pid = a.project_id or a.identity_project_id
        findings, coverage = _load_project_data(a, pid)
        if a.project_id:
            expected = json.load(open(os.path.join(EVAL_PACK, "expected.json"), encoding="utf-8"))
            sys.exit(blind_report(findings, coverage, expected, pid, os.path.join(ROOT, "eval", "results")))
        sys.exit(identity_coverage_report(coverage, findings, pid, os.path.join(ROOT, "eval", "results")))

    token = load_token(a)
    expected = json.load(open(os.path.join(EVAL_PACK, "expected.json"), encoding="utf-8"))
    min_recall = a.min_recall if a.min_recall is not None else expected.get("min_recall", 0.5)

    cfg = json.load(open(os.path.join(ROOT, "config.json"), encoding="utf-8"))
    if cfg.get("llm", {}).get("mock"):
        print("⚠ LLM 处于 mock 模式：不会产生真实发现，得分 0 属预期（评测需真实模型）")

    print("① 启动评测靶场（127.0.0.1:%d）" % TARGET_PORT)
    container = a.container or ("jiutouniao" if shutil.which("docker") and
                                subprocess.run(["docker", "inspect", "jiutouniao"],
                                               capture_output=True).returncode == 0 else "")
    target = start_target(TARGET_PORT, container)
    project_id = ""
    try:
        print("② 创建评测项目并启动")
        p = api(a.base_url, token, "POST", "/api/projects", {
            "name": "eval-" + time.strftime("%m%d-%H%M%S"),
            "target": expected["target"],
            "scope": "仅限 http://127.0.0.1:%d 全部路径（本地评测靶场）" % TARGET_PORT,
            "roe": "本地自建靶场：允许利用演示（命令注入/注入类可直接取证）；禁止破坏性写入与 DoS；发现即取证，无需清理外部数据。",
            "authorized": True,
            "strict_scope": True,
            "auto_approve": "all",
            "test_type": "黑盒",
            "success_criteria": "尽可能多地发现并确证预期漏洞类别（见评测判分）",
        })
        project_id = p["ID"] if "ID" in p else p.get("id", "")
        print("   项目:", project_id)
        api(a.base_url, token, "POST", f"/api/projects/{project_id}/start", {})

        print("③ 轮询执行状态（最长 %d 分钟）……" % a.timeout_min)
        deadline = time.time() + a.timeout_min * 60
        status, cur = "running", ""
        started = time.time()
        while time.time() < deadline:
            time.sleep(20)
            try:
                pj = api(a.base_url, token, "GET", f"/api/projects/{project_id}")
                # v3.5.2 修复：响应是包裹结构 {"project": {...}}（v3.5.x 曾读顶层字段全程 unknown，
                # 超时路径也因此未熔断）；本轮起 status/stage/usage 全部从包裹内取。
                pj = pj.get("project", pj)
                status = pj.get("status") or "unknown"
                cur = pj.get("current_stage") or ""
                print(f"   [{time.strftime('%H:%M:%S')}] status={status} stage={cur}")
                if status in ("done", "failed", "killed"):
                    break
            except Exception as e:
                print("   轮询异常:", e)
        if status not in ("done", "failed", "killed"):
            print("⚠ 超时未结束，熔断并按当前产出判分")
            status = "timeout"
            try:
                api(a.base_url, token, "POST", f"/api/projects/{project_id}/kill", {"reason": "eval timeout"})
            except Exception:
                pass
    finally:
        if not a.keep:
            stop_target(target)

    print("④ 读取产出并判分")
    dur_min = (time.time() - started) / 60
    usage = {}
    try:
        pj = api(a.base_url, token, "GET", f"/api/projects/{project_id}")
        u = pj.get("usage") or {}
        usage = {"in": u.get("in_tokens") or 0, "out": u.get("out_tokens") or 0}
    except Exception:
        pass
    fd = os.path.join(ROOT, "projects", project_id, "findings.json")
    findings = json.load(open(fd, encoding="utf-8")) if os.path.exists(fd) else []
    try:
        cov = api(a.base_url, token, "GET", f"/api/projects/{project_id}/coverage")
        coverage = cov if isinstance(cov, list) else cov.get("items", cov.get("coverage", []))
    except Exception:
        coverage = []
    recall, hit, miss, extras, stats = score(findings, coverage, expected)
    # v4.8 三指标：S3 判定表 ↔ expected matrix_class（常驻输出，§5.3）
    mm = matrix_metrics(os.path.join(ROOT, "projects", project_id,
                                     "deliverables", "s3-筛查矩阵判定表.md"), expected)
    wo = skill_workorder(miss, extras, os.path.join(ROOT, "eval", "results"), project_id)  # v7.4.0 D2
    am = autonomy_section(project_id)   # v7.4.0 D3
    asm = assumption_metrics(coverage)  # v7.4.0 D3

    ts = time.strftime("%Y%m%d-%H%M%S")
    os.makedirs(os.path.join(ROOT, "eval", "results"), exist_ok=True)
    out = os.path.join(ROOT, "eval", "results", f"eval-{ts}.md")
    with open(out, "w", encoding="utf-8") as f:
        f.write(f"# 评测报告 eval-{ts}\n\n- 项目: {project_id}（终态 {status}，本次耗时 {dur_min:.0f} 分钟）\n")
        f.write(f"- Token: 入 {usage.get('in',0)/1e6:.2f}M / 出 {usage.get('out',0)/1e6:.2f}M（引擎口径含全部阶段）\n")
        f.write(f"- 召回率: **{recall:.0%}**（{len(hit)}/{len([i for i in expected['items'] if i.get('scoreable', True)])}，及格线 {min_recall:.0%}）\n")
        f.write(f"- 自述面召回: **{stats['declared_recall']:.0%}**（{stats['declared_hit']}/{stats['declared_total']}，覆盖下限）\n")
        f.write(f"- 清单外盲挖: **{stats['hidden_recall']:.0%}**（{stats['hidden_hit']}/{stats['hidden_total']}，隐藏项=0day 能力度量）\n")
        f.write(f"- mock 面召回: **{stats['mock_recall']:.0%}**（{stats['mock_hit']}/{stats['mock_total']}，OAuth/对抗 mock=C-04/10/11/27）\n")
        if am:
            f.write(f"- 自主性计量（D3）: 提案 {am['proposals']}｜批准 {am['approved']}｜转化率 {am['conversion']:.0%}｜升维 {am['escalations']}\n")
        if asm["units"]:
            f.write(f"- 假设命中率（D3）: **{asm['rate']:.0%}**（确证 {asm['hit']}/{asm['units']}）\n")
        if wo:
            f.write(f"- 技能迭代工单（D2）: {os.path.basename(wo)}\n")
        f.write(f"- 匿名高危召回: **{stats['high_risk_anonymous_recall']:.0%}**（{stats['hidden_high_hit']}/{stats['hidden_high_total']}，weight=high 隐藏项=无凭证高危能力度量）\n")
        # 三指标段
        if mm.get("available"):
            f.write(f"\n## 三指标（筛查矩阵判定表 ↔ expected 类标注，v4.8 §5.3）\n\n")
            f.write(f"- 假设召回率: **{mm['assume_recall']:.0%}**（埋点 {mm['planted_classes']} 类中判『假设』{mm['assume_recall_planted_hit']} 类；门槛 ≥80%）\n")
            f.write(f"- 不适用误判率: **{mm['na_false_rate']:.0%}**（埋了面却判『不适用』：{mm['na_planted'] or '无'}；门槛 =0，>0 即方法论缺陷回溯）\n")
            f.write(f"- 假设精度: **{mm['assume_precision']:.0%}**（判『假设』{mm['assumed_total']} 类中未埋面 {mm['unplanted_assumed'] or '无'}；门槛 ≥90%（即未埋面提假设 ≤10%））\n")
            f.write(f"- 待判定（双假设并列未收敛）: {mm['pending_planted'] or '无'}（s4 实测应裁决收敛）\n")
        else:
            f.write(f"\n## 三指标\n\n- {mm['note']}\n")
        f.write("\n## 命中\n" + "".join(f"- ✅ {i['id']} {i['vuln_class']}（{i.get('matrix_class','')}）\n" for i in hit) + "\n")
        f.write("## 未命中（技能库迭代输入）\n" + "".join(f"- ❌ {i['id']} {i['vuln_class']}（{i.get('matrix_class','')}）\n" for i in miss) + "\n")
        f.write(f"\n## 额外发现（{len(extras)} 条，供人工复核）\n")
        for e in extras:
            f.write(f"- {e.get('severity','')}[{e.get('confidence','')}] {e.get('title','')}\n")
    print(out and open(out, encoding="utf-8").read())
    print(f"📄 报告: {out}")
    fail = False
    if recall < min_recall:
        print(f"❌ 召回率 {recall:.0%} 低于及格线 {min_recall:.0%}")
        fail = True
    if mm.get("available"):
        th = mm["thresholds"]
        if mm["assume_recall"] < th["assume_recall_min"]:
            print(f"❌ 假设召回率 {mm['assume_recall']:.0%} 低于门槛 80%（筛查矩阵触发缺口→K3 技能/判定表迭代输入）")
            fail = True
        if mm["na_false_rate"] > th["na_false_max"]:
            print(f"❌ 不适用误判率 {mm['na_false_rate']:.0%} > 0（埋了面却判『不适用』——方法论缺陷回溯）")
            fail = True
        if mm["assume_precision"] < th["assume_precision_min"]:
            print(f"⚠ 假设精度 {mm['assume_precision']:.0%} 低于门槛 90%（未埋面提假设偏多——三态机制有效性复核）")
    if fail:
        sys.exit(1)
    print(f"✅ 召回率 {recall:.0%} 达标" + ("；三指标全部过线" if mm.get("available") and mm["assume_recall"] >= 0.8 and mm["na_false_rate"] == 0 else ""))


if __name__ == "__main__":
    main()
