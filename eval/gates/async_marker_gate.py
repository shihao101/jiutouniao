# -*- coding: utf-8 -*-
"""E2 离线门：后台任务终态标记 + 空证据文件。
拦截形态：.async 日志无 [JT-JOB-END]（被截杀任务与完成任务不可区分——nuclei 洗白案）；0 字节证据文件。"""
import os, sys, glob, json
from gate_common import read_text

def run(proj):
    issues = []
    adir = os.path.join(proj, ".async")
    if os.path.isdir(adir):
        for lp in sorted(glob.glob(os.path.join(adir, "job-*.log"))):
            content = read_text(proj, os.path.relpath(lp, proj))
            if content is not None and "[JT-JOB-END]" not in content:
                issues.append(f"[E2] {os.path.basename(lp)} 无终态标记 [JT-JOB-END]——任务被截杀/中断，关联覆盖单元不得标 ruled_out/no_issue_found")
        for sp in sorted(glob.glob(os.path.join(adir, "job-*.json"))):
            try:
                with open(sp, encoding="utf-8") as f:
                    d = json.load(f)
                if not d.get("state"):
                    issues.append(f"[E2] {os.path.basename(sp)} sidecar 无终态 state——完成标记缺失")
            except Exception as e:
                issues.append(f"[E2] {os.path.basename(sp)} sidecar 解析失败: {e}")
    for root, _dirs, files in os.walk(proj):
        if ".async" in root:
            continue
        for fn in files:
            fp = os.path.join(root, fn)
            rel = os.path.relpath(fp, proj)
            if rel.startswith("evidence" + os.sep) and os.path.getsize(fp) == 0:
                issues.append(f"[E2] 空证据文件: {rel}（nuclei 0 字节案形态——空文件不是证据）")
    return issues

if __name__ == "__main__":
    for iss in run(sys.argv[1]):
        print(iss)
