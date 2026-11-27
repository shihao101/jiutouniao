#!/usr/bin/env python3
"""token_regression_check.py —— v7.5.0 发版门 F1：版本间 token 回归核对。

对比两次 tokdump（scripts/token_audit）导出的分账报告，按项目计算单次调用均值涨幅；
任一项目涨幅 >10% 即退出码 1（须在更新记录附原因说明）。

v7.6.0（A1 发版门 aux 线）：`--aux <usage_calls.jsonl> [...]` 模式逐行核验辅助智能线
（reflect/adversary/brain/mentor）明细——历史故障特征为 out_tokens 恰=1024（aux 预算撞顶、
思考型模型正文恒空）或 out_tokens=0（零产出）；v7.6.0 起出现任一即为发版门拦截
（aux_max_tokens 下限护栏 2048 生效后不应再出现，双任务实证 27 次零产出的教训）。
兼容两种行格式：store 原生（{"project_id","kind","out_tokens"}）与 jtdump 导出
（{"_bucket":"usage_calls","_value":{...}}）。

用法：
    ./tokdump snapshot_old.db > old.tsv
    ./tokdump snapshot_new.db > new.tsv
    python3 scripts/token_regression_check.py old.tsv new.tsv [--threshold 10]
    python3 scripts/token_regression_check.py --aux usage_calls.jsonl [more.jsonl ...]
"""
import json
import sys

KIND_KINDS = ("main", "subagent", "reflect", "mentor", "brain", "adversary", "summary", "chat")
AUX_KINDS = ("reflect", "adversary", "brain", "mentor")


def check_aux(paths):
    """A1 发版门：辅助线明细核验——撞顶（out==1024）/零产出（out==0）任一即拦截。"""
    total = suspicious = 0
    for path in paths:
        for line in open(path, encoding="utf-8"):
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            val = rec.get("_value", rec)  # jtdump 导出壳 / store 原生行
            kind = str(val.get("kind", ""))
            if kind not in AUX_KINDS:
                continue
            total += 1
            out = int(val.get("out_tokens") or 0)
            pid = val.get("project_id", "?")
            if out == 1024:
                suspicious += 1
                print(f"❌ [{pid}] {kind} out=1024——疑似 aux 预算撞顶（思考型模型正文恒空形态，v7.5.2 前实证特征）")
            elif out == 0:
                suspicious += 1
                print(f"❌ [{pid}] {kind} out=0——零产出调用")
    print(f"\n辅助线核验 {total} 行；可疑 {suspicious} 行（撞顶/零产出）")
    if suspicious:
        print("发版门拦截：辅助线存在零产出/撞顶调用——先排查 aux_max_tokens 配置与模型行为，附原因说明后放行")
        sys.exit(1)
    print("辅助线通过（A1 发版门）。")




def parse(path):
    """解析 tokdump 输出：项目行 → {id: (calls, total_k)}；TOTAL 行与分账节忽略。"""
    out = {}
    for line in open(path, encoding="utf-8"):
        cols = line.rstrip("\n").split("\t")
        if len(cols) < 7 or not cols[0].startswith("JT-"):
            continue
        try:
            calls = int(cols[3])
            total_k = float(cols[6])
        except ValueError:
            continue
        if calls > 0:
            out[cols[0]] = (calls, total_k)
    return out


def main():
    if "--aux" in sys.argv:
        idx = sys.argv.index("--aux")
        files = [a for a in sys.argv[idx + 1:] if not a.startswith("--")]
        if not files:
            print(__doc__)
            sys.exit(2)
        check_aux(files)
        return
    if len(sys.argv) < 3:
        print(__doc__)
        sys.exit(2)
    old, new = parse(sys.argv[1]), parse(sys.argv[2])
    threshold = 10.0
    if "--threshold" in sys.argv:
        threshold = float(sys.argv[sys.argv.index("--threshold") + 1])
    regressions = []
    for pid, (nc, nk) in sorted(new.items()):
        if pid not in old:
            continue
        oc, ok_ = old[pid]
        old_mean = ok_ / oc * 1000  # tokens/call
        new_mean = nk / nc * 1000
        if old_mean <= 0:
            continue
        delta = (new_mean - old_mean) / old_mean * 100
        flag = " ⚠ 超阈值" if delta > threshold else ""
        print(f"{pid}  单调用均值 {old_mean:8.1f} → {new_mean:8.1f}  {delta:+6.1f}%{flag}")
        if delta > threshold:
            regressions.append(pid)
    print(f"\n核对项目 {len(set(old) & set(new))} 个；超 {threshold}% 阈值 {len(regressions)} 个")
    if regressions:
        print("发版门拦截：以下项目 token 回归超阈值，须附原因说明后放行：", ", ".join(regressions))
        sys.exit(1)
    print("通过。")


if __name__ == "__main__":
    main()
