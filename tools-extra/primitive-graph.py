#!/usr/bin/env python3
"""v4.8 W7 原语图引擎（承 v4.6 W7-lite 链式推荐器升级）：低危→高危凑链的确定性图引擎。

从 findings.json 提取 primitive: 标注（READ/WRITE/EXEC/SSRF/SQLI/AUTHZ/CRED/LFI/XXE/RCE/PII/
DB-READ/ADMIN-REACH），从 loot.json（可选，store 战利品导出）注入 CRED 节点，构建原语图后：
  ① 正向扩展：从已具备原语 BFS 到链终点（EXEC/RCE/PII/DB-READ），输出多跳路径；
  ② 反向回推：从高危目标原语反推缺失前置（缺口链）；
  ③ 缺口自动 record_vt：每缺口输出可直接提交的 record_vt JSON 参数块（title/ready_assets/
     start_conditions），配合验证队列承接；
  ④ 战利品网络扇出：CRED 节点（凭据/会话）→ 新入口推荐（登录面→会话→认证后队列面）。

CLI 兼容 v4.6：--findings/--out/--selftest；新增 --loot/--json。
用法：primitive-graph.py --findings <项目>/findings.json [--loot loot.json] [--out chains.md]；--selftest。
"""
import argparse, json, re, sys
from collections import deque

# v5.1.2 P0 修复：原 PRIM_RE 仅大写无连字符 + extract 对文本 .upper() 后匹配小写前缀正则
# → 对任何输入永远返回空列表（核心函数死路，S5 收口产出恒空）。改为忽略大小写并支持连字符原语。
PRIM_RE = re.compile(r"primitive:\s*([A-Za-z][A-Za-z-]{2,10})")
ALL_PRIMS = {"READ", "WRITE", "EXEC", "SSRF", "SQLI", "AUTHZ", "CRED", "LFI", "XXE", "RCE", "PII", "DB-READ", "ADMIN-REACH"}
GOALS = {"EXEC", "RCE", "PII", "DB-READ"}  # 高危终点（影响证明目标）

# 链模板 = 图边集（a→b 表示「具备 a 后推荐获取 b」）；desc 为边语义，act 为获取 b 的下一动作
CHAIN_TEMPLATES = [
    {"chain": ["LFI", "CRED", "DB-READ"], "desc": "LFI 读配置→数据库凭据→DB 只读清点", "act": "LFI 命中后优先读 conn.php/config.* 类（路径穿越字典）"},
    {"chain": ["SQLI", "DB-READ"], "desc": "SQLi→information_schema→数据存在性证明", "act": "UNION/group_concat 分段抽样（不拖全量）"},
    {"chain": ["SSRF", "ADMIN-REACH", "EXEC"], "desc": "SSRF→内网管理面→命令执行原语", "act": "回连确认后探测 10/172.16-31/192.168 网段管理端点（范围确认后）"},
    {"chain": ["EXEC", "CRED"], "desc": "RCE→配置/环境→凭据收割", "act": "读 env/conn/密钥文件与进程环境（cmdi-deep 口径）"},
    {"chain": ["AUTHZ", "PII"], "desc": "越权→PII 批量枚举（量化存在性证明）", "act": "对象 ID 采样→自增判定→差分枚举→计数/哈希摘要（idor-baseline.py）"},
    {"chain": ["WRITE", "EXEC"], "desc": "任意写→可执行落点（上传/模板/计划任务）", "act": "上传 bypass 或模板注入落点（upload-bypass/ssti-engine-map）"},
    {"chain": ["XXE", "READ"], "desc": "XXE→php://filter 文件读取", "act": "filter 链读配置（xxe-full 口径）"},
    {"chain": ["READ", "CRED"], "desc": "文件读→配置凭据提取", "act": "对已读文件做密钥/连接串模式扫描（intel-factory 密钥材料）"},
    {"chain": ["CRED", "AUTHZ"], "desc": "凭据→新入口→越权差分", "act": "凭据建会话（session-state-chain）后 authz-diff 全端点差分矩阵"},
]

def extract(findings_path):
    out = []
    try:
        with open(findings_path, encoding="utf-8") as f:
            d = json.load(f)
    except Exception as e:
        print(f"错误: findings.json 不可读: {e}"); sys.exit(1)
    items = d if isinstance(d, list) else d.get("findings", [])
    for f in items:
        # v5.1.2 P0 修复：去掉 .upper()（大小写错配死点），匹配原始文本（PRIM_RE 已忽略大小写）
        prims = sorted(set(p.upper() for p in PRIM_RE.findall((f.get("title", "") + " " + f.get("detail", "")))))
        prims = [x for x in prims if x in ALL_PRIMS]
        if prims:
            out.append({"id": f.get("id", "?"), "title": (f.get("title") or "")[:60], "prims": prims})
    return out

def load_loot(loot_path):
    """loot.json（store 战利品导出：[{type,target,masked,verified}]）→ CRED 节点清单。"""
    if not loot_path or not __import__("os").path.isfile(loot_path):
        return []
    try:
        d = json.load(open(loot_path, encoding="utf-8"))
    except Exception:
        return []
    items = d if isinstance(d, list) else d.get("loots", d.get("loot", []))
    out = []
    for l in items:
        if not isinstance(l, dict):
            continue
        out.append({"id": "LOOT-" + str(l.get("id", len(out) + 1)),
                    "title": f"[战利品] {l.get('type','?')} @ {str(l.get('target','?'))[:40]}（{l.get('masked','***')}，{l.get('verified','unverified')}）",
                    "prims": ["CRED"] if l.get("verified") == "verified" else [],
                    "loot": True})
    return out

def build_graph():
    """链模板 → 邻接表 {prim: [(next, desc, act)]}。"""
    adj = {}
    for t in CHAIN_TEMPLATES:
        c = t["chain"]
        for i in range(len(c) - 1):
            adj.setdefault(c[i], []).append((c[i + 1], t["desc"], t["act"]))
    return adj

def forward_paths(owned, adj):
    """正向 BFS：owned 各原语到 GOALS 的全部无环路径（≤5 跳），返回 [(path, edge_meta)]。"""
    results = []
    for start in owned:
        q = deque([[start]])
        while q:
            path = q.popleft()
            if len(path) > 5:
                continue
            last = path[-1]
            if last in GOALS and len(path) > 1:
                results.append(path)
                continue
            for nxt, desc, act in adj.get(last, []):
                if nxt not in path:
                    q.append(path + [nxt])
    # 去重（同路径只留一条）
    seen, uniq = set(), []
    for p in results:
        k = "→".join(p)
        if k not in seen:
            seen.add(k)
            uniq.append(p)
    return uniq

def backward_gaps(owned, adj):
    """反向回推：GOALS 中未达成的，反推最短缺口链（从 goal 反向 BFS 到任一 owned）。"""
    radj = {}
    for a, edges in adj.items():
        for b, _, _ in edges:
            radj.setdefault(b, []).append(a)
    owned_set = set(owned)
    gaps = []
    for goal in GOALS:
        if goal in owned_set:
            continue
        q = deque([[goal]])
        best = None
        while q and best is None:
            path = q.popleft()
            last = path[0]
            if last in owned_set and len(path) > 1:
                best = path  # path = [owned..., goal] 反序
                break
            if len(path) > 5:
                continue
            for prev in radj.get(last, []):
                if prev not in path:
                    q.append([prev] + path)
        if best:
            gaps.append({"goal": goal, "chain": best, "missing": [x for x in best if x not in owned_set]})
    return gaps

def vt_suggestion(missing, goal):
    """缺口 → record_vt JSON 参数块（直接可提交，验证队列承接 W7 缺口）。"""
    m = "、".join(missing)
    return {"title": f"[W7缺口] 获取原语 {m} → 闭合 {goal} 链",
            "ready_assets": "对应技能剧本（load_skill 按原语类检索）",
            "start_conditions": f"已具备前置原语；目标原语 {m} 获取后重跑 primitive-graph 确认链闭合",
            "cost_note": "1-3 轮/原语（按对应技能口径）", "priority": 2, "status": "ready"}

def loot_fanout(loot_items):
    """战利品网络扇出：CRED 节点 → 新入口推荐（凭据→会话→认证后队列）。"""
    out = []
    for l in loot_items:
        if "CRED" in l.get("prims", []):
            out.append({"loot": l["id"], "title": l["title"],
                        "recommend": [
                            "凭据→新入口①：登录面建会话（load_skill session-state-chain），登记 access=post-auth 后续队列",
                            "凭据→新入口②：同型面板复用（密码复用面：管理后台/运维面/数据库口）",
                            "凭据→新入口③：凭据过期/锁定判定（锁定预言机探针，weak-cred-bruteforce 口径）",
                            "凭据→横向：search_memory 查战利品关联目标，authz-diff 矩阵全端点差分（CRED→AUTHZ 链）"]})
    return out

def selftest():
    """夹具：LFI 链 / SSRF 多跳 / 反向缺口 / VT 块 / 战利品扇出（v4.8 图引擎口径）。"""
    adj = build_graph()
    # ① 正向：LFI→CRED→DB-READ（v4.6 兼容语义保持）
    p = forward_paths(["LFI"], adj)
    assert ["LFI", "CRED", "DB-READ"] in [list(x) for x in p], f"LFI 链: {p}"
    # ② 正向多跳：SSRF→ADMIN-REACH→EXEC
    p2 = forward_paths(["SSRF"], adj)
    assert ["SSRF", "ADMIN-REACH", "EXEC"] in [list(x) for x in p2], f"SSRF 链: {p2}"
    # ③ 反向缺口：仅 WRITE → EXEC 目标无缺口，但 DB-READ/PII/RCE 有缺口链
    gaps = backward_gaps(["WRITE"], adj)
    ggoals = {g["goal"] for g in gaps}
    assert "DB-READ" in ggoals and all(g["missing"] for g in gaps), f"反向缺口: {gaps}"
    vt = vt_suggestion(gaps[0]["missing"], gaps[0]["goal"])
    assert vt["title"].startswith("[W7缺口]") and vt["status"] == "ready", "VT 块"
    # ④ 战利品扇出
    loots = [{"id": "LOOT-1", "title": "[战利品] credential @ admin", "prims": ["CRED"], "loot": True}]
    fan = loot_fanout(loots)
    assert len(fan) == 1 and "session-state-chain" in fan[0]["recommend"][0], "战利品扇出"
    # ⑤ 已闭合链不再给缺口：owned 含全部 GOALS → 无 gap
    assert backward_gaps(set(GOALS), adj) == [], "全目标已具备应零缺口"
    print("原语图引擎自测: 正向×2/反向缺口/VT块/战利品扇出/零缺口 6/6 OK")
    return True

if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="v4.8 W7 原语图引擎")
    ap.add_argument("--findings", help="findings.json（primitive:XXX 标注来源）")
    ap.add_argument("--loot", help="loot.json（战利品导出，可选——CRED 节点注入与扇出）")
    ap.add_argument("--out", help="推荐报告落盘路径")
    ap.add_argument("--json", action="store_true", help="输出 JSON（VT 块机读）")
    ap.add_argument("--selftest", action="store_true")
    ns = ap.parse_args()
    if ns.selftest:
        sys.exit(0 if selftest() else 1)
    if not ns.findings:
        ap.error("需要 --findings（或 --selftest）")
    fs = extract(ns.findings) + load_loot(ns.loot)
    owned = sorted({p for f in fs for p in f["prims"]})
    adj = build_graph()
    fwd = forward_paths(owned, adj)
    gaps = backward_gaps(owned, adj)
    fan = loot_fanout(load_loot(ns.loot))
    if ns.json:
        print(json.dumps({"owned": owned, "forward_paths": fwd,
                          "gaps": gaps, "vt_suggestions": [vt_suggestion(g["missing"], g["goal"]) for g in gaps],
                          "loot_fanout": fan}, ensure_ascii=False, indent=1))
        sys.exit(0)
    lines = ["# 原语图引擎推荐（v4.8 W7）", "", f"- 已具备原语: {', '.join(owned) if owned else '（无）'}", ""]
    if fwd:
        lines.append("## 正向扩展（可达影响证明路径）")
        for pth in fwd:
            edges = [d for a, d in [(pth[i], next((dd for nn, dd, _ in adj.get(pth[i], []) if nn == pth[i + 1]), "")) for i in range(len(pth) - 1)]]
            lines.append(f"- {'→'.join(pth)}（{'；'.join(x for x in edges if x)}）")
        lines.append("")
    if gaps:
        lines.append("## 反向回推缺口（record_vt 承接）")
        for g in gaps:
            lines.append(f"- 目标 {g['goal']}：链 {'→'.join(g['chain'])}；缺口 {g['missing']}")
            v = vt_suggestion(g["missing"], g["goal"])
            lines.append(f"  - record_vt 参数块: {json.dumps(v, ensure_ascii=False)}")
        lines.append("")
    if fan:
        lines.append("## 战利品网络扇出（CRED→新入口）")
        for f in fan:
            lines.append(f"- {f['title']}")
            lines += [f"  - {r}" for r in f["recommend"]]
        lines.append("")
    if not (fwd or gaps or fan):
        lines.append("（无带 primitive 标注的发现/战利品——record_finding 时补 primitive:XXX、record_loot 登记后重跑）")
    text = "\n".join(lines)
    print(text)
    if ns.out:
        with open(ns.out, "w", encoding="utf-8") as fh:
            fh.write(text + "\n")
