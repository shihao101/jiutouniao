#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""v5.3.3 P2-1 技能检索准确率门。

两层校验：
  ① 结构层（恒跑）：golden.json 夹具良构——query 非空、any_in_top3 引用的技能 id 真实存在、
     stage 合法、min_pass_rate 在 [0.5,1]、用例 ≥30（知识面漂移即 FAIL）；
  ② 实跑层（go 工具链在位时）：`go test ./internal/engine/ -run TestV533GoldenRetrieval`
     用真实 SkillRegistry（manifest 元数据）跑金标，低于 min_pass_rate 即 FAIL。

退出码 0=全过。run_comprehensive.sh 桥接；纯净部署包缺夹具时 SKIP（退出 0）。
"""
import json
import os
import re
import shutil
import subprocess
import sys

ROOT = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
GOLDEN = os.path.join(ROOT, "eval", "gates", "fixtures", "skill-retrieval", "golden.json")
SKILLS = os.path.join(ROOT, "skills")
STAGE_RE = re.compile(r"^(s[1-8]|specA|specB1|specB2|)$")


def main():
    if not os.path.isfile(GOLDEN):
        print("SKIP 金标夹具不存在（纯净部署包口径）")
        return 0
    bad = []
    gf = json.load(open(GOLDEN, encoding="utf-8"))
    cases = gf.get("cases", [])
    rate = gf.get("min_pass_rate", 0.85)
    if len(cases) < 30:
        bad.append(f"用例数 {len(cases)} < 30")
    if not 0.5 <= rate <= 1.0:
        bad.append(f"min_pass_rate 非法: {rate}")
    real_ids = {f[:-3] for f in os.listdir(SKILLS) if f.endswith(".md")}
    for c in cases:
        if not str(c.get("q", "")).strip():
            bad.append(f"空查询: {c}")
        if not STAGE_RE.match(str(c.get("stage", ""))):
            bad.append(f"stage 非法: {c.get('stage')}（{c.get('q')}）")
        if not c.get("any_in_top3"):
            bad.append(f"缺 any_in_top3: {c.get('q')}")
        for sid in c.get("any_in_top3", []):
            if sid not in real_ids:
                bad.append(f"期望技能 {sid} 不存在（{c.get('q')}）")
    if bad:
        print(f"FAIL 结构层 {len(bad)} 项: " + "; ".join(bad[:6]))
        return 1
    print(f"PASS 结构层（{len(cases)} 用例，金标线 {rate:.0%}）")
    # ② 实跑层：go 工具链在位则跑真实检索回归
    go, _ = shutil.which("go"), None
    server_dir = os.path.join(ROOT, "server")
    if go and os.path.isdir(server_dir):
        r = subprocess.run(["go", "test", "./internal/engine/", "-run", "TestV533GoldenRetrieval", "-count=1", "-v"],
                           cwd=server_dir, capture_output=True, text=True, timeout=300)
        m = re.search(r"检索准确率: (\d+)/(\d+)（(\d+)%）", r.stdout)
        if r.returncode != 0:
            detail = (m.group(0) if m else (r.stdout or r.stderr).strip()[-200:])
            print(f"FAIL 实跑层（金标回归未过）: {detail}")
            return 1
        if m:
            print(f"PASS 实跑层（top3 召回 {m.group(1)}/{m.group(2)}={m.group(3)}%）")
        else:
            print("PASS 实跑层")
    else:
        print("SKIP 实跑层（go 工具链不在位——结构层已过）")
    return 0


if __name__ == "__main__":
    sys.exit(main())
