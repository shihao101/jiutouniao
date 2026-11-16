# -*- coding: utf-8 -*-
"""v4.6 全面核查汇总器。
用法：①python3 run_all_gates.py <project_dir>...  ——对真实项目跑全部门，输出 PASS/FAIL
     ②python3 run_all_gates.py --selftest        ——夹具回归：12 个审计误判案例必须全部被拦截
                                                   （case→expected.txt 指定的门），clean 夹具必须零误伤。
退出码：0=全过；1=有 FAIL。达标线=12/12 拦截+clean 全过；优秀线=单门零误伤且输出全中文可读。"""
import os, sys, subprocess, glob

HERE = os.path.dirname(os.path.abspath(__file__))
GATES = ["claim_evidence_gate.py", "async_marker_gate.py", "reconcile_gate.py", "coverage_gate.py"]

def run_gate(gate, proj):
    r = subprocess.run([sys.executable, os.path.join(HERE, gate), proj],
                       capture_output=True, text=True)
    return [l for l in (r.stdout or "").splitlines() if l.strip()]

def check_project(proj, quiet=False):
    ok = True
    for g in GATES:
        issues = run_gate(g, proj)
        if issues:
            ok = False
            if not quiet:
                print(f"  FAIL {g}（{len(issues)} 项）")
                for i in issues:
                    print(f"    - {i}")
        elif not quiet:
            print(f"  PASS {g}")
    return ok

def selftest():
    fixtures = sorted(d for d in glob.glob(os.path.join(HERE, "fixtures", "*")) if os.path.isdir(d))
    total_ok, total = 0, 0
    for fx in fixtures:
        name = os.path.basename(fx)
        expected_path = os.path.join(fx, "expected.txt")
        if not os.path.isfile(expected_path):
            continue  # v5.3.3：非门夹具目录（如 skill-retrieval 金标集）不参与门回归
        with open(expected_path, encoding="utf-8") as f:
            expected = {l.strip() for l in f if l.strip()}
        total += 1
        bad = []
        for g in GATES:
            issues = run_gate(g, fx)
            flagged = len(issues) > 0
            if name.startswith("clean"):
                if flagged:
                    bad.append(f"误伤: {g} 报了 {len(issues)} 项（clean 夹具必须零误伤）: {issues[0][:80]}")
            elif g in expected and not flagged:
                bad.append(f"漏拦: {g} 未拦截该案例（必须命中）")
            elif g not in expected and flagged:
                bad.append(f"越界: {g} 不应命中该案例却报了 {len(issues)} 项: {issues[0][:80]}")
        if bad:
            print(f"FAIL {name}: " + "；".join(bad))
        else:
            total_ok += 1
            print(f"PASS {name}")
    print(f"\n夹具回归: {total_ok}/{total}")
    return total_ok == total

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--selftest":
        sys.exit(0 if selftest() else 1)
    ok = True
    for proj in sys.argv[1:]:
        print(f"== {proj} ==")
        ok = check_project(proj) and ok
    sys.exit(0 if ok else 1)
