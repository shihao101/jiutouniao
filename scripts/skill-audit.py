#!/usr/bin/env python3
"""skill-audit.py v6.0.5 P0 —— 技能库接线可达性审计（在仓库根目录运行: python3 scripts/skill-audit.py）

三分类（消除"router 有条目但流程不可达"的假覆盖）：
  head-reachable    = 从任一阶段头显式 load_skill 出发，经 depends_on/handoff_to 闭包可达
  router-only       = 仅被 00-router 收录，无 head 可达路径（假覆盖候选——需人工判定价值）
  unreferenced      = 三路全无（真孤儿）
另输出：悬挂引用（load_skill/depends_on/handoff_to 指向不存在 id）、stage_fit 与实际引用阶段的不一致清单。
"""
import json, re, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SK = ROOT / "skills"
HEADS = ROOT / "heads"

files = {p.stem: p for p in SK.glob("*.md")}
ids = set(files) - {"00-router"}
manifest = json.loads((SK / "manifest.json").read_text(encoding="utf-8"))
meta = {x["id"]: x for x in manifest.get("skills", [])}

def norm(v):
    if isinstance(v, str):
        v = [v]
    return [str(x).strip() for x in (v or [])]

# 引用提取：head 全文按词边界匹配技能 id（含目录式点名）；显式 load 单列
load_re = re.compile(r"\bload_skill\s*\(?\s*([\w-]+)")
mentioned, loaded = {}, {}
for h in HEADS.glob("*.md"):
    text = h.read_text(encoding="utf-8")
    mn = set(i for i in ids if re.search(r"(?<![\w-])" + re.escape(i) + r"(?![\w-])", text))
    mentioned[h.stem] = mn
    loaded[h.stem] = set(load_re.findall(text)) & ids

router_text = (SK / "00-router.md").read_text(encoding="utf-8")
router_ids = set(i for i in ids if re.search(r"(?<![\w-])" + re.escape(i) + r"(?![\w-])", router_text))

# 图遍历：seeds = 显式 load 的技能；边 = depends_on + handoff_to
edges = {sid: set(norm(meta.get(sid, {}).get("depends_on", [])) + norm(meta.get(sid, {}).get("handoff_to", []))) & ids
         for sid in ids}
seeds = set().union(*loaded.values()) if loaded else set()
head_reachable = set()
stack = list(seeds)
while stack:
    cur = stack.pop()
    if cur in head_reachable:
        continue
    head_reachable.add(cur)
    stack.extend(edges.get(cur, ()) - head_reachable)

router_only = sorted((router_ids | ids) - head_reachable - {i for i in ids if i not in router_ids})
router_only = sorted(i for i in ids if i not in head_reachable and i in router_ids and i != "00-router")
unreferenced = sorted(i for i in ids if i not in head_reachable and i not in router_ids)

# 悬挂引用
dangling = []
for sid in ids:
    text = files[sid].read_text(encoding="utf-8")
    for ref in load_re.findall(text):
        if ref not in ids and ref != "00-router":
            dangling.append((sid, "load_skill", ref))
    for key in ("depends_on", "handoff_to"):
        for ref in norm(meta.get(sid, {}).get(key, [])):
            if ref not in ids and ref:
                dangling.append((sid, key, ref))

# stage_fit vs 实际引用阶段
stage_mismatch = []
for head, mn in loaded.items():
    mm = re.fullmatch(r"s([1-8])", head)
    if not mm:
        continue
    for sid in mn:
        fit = norm(meta.get(sid, {}).get("stage_fit", []))
        digits = [re.sub(r"\D", "", x) for x in fit]
        if fit and mm.group(1) not in digits:
            stage_mismatch.append((sid, head, fit))

print(f"skillfiles={len(ids)} manifest={len(meta)} router_cover={len(router_ids)}")
print(f"head_load_seeds={len(seeds)} head_reachable={len(head_reachable)} "
      f"router_only={len(router_only)} unreferenced={len(unreferenced)}")
print("head_reachable:", sorted(head_reachable))
print("router_only(假覆盖候选):", router_only)
print("unreferenced(真孤儿):", unreferenced)
print("dangling:", dangling)
print("stage_fit_mismatch:", stage_mismatch)

# 退出码：有真孤儿或悬挂 → 非零（供 CI/预检使用）
sys.exit(2 if (unreferenced or dangling) else 0)
