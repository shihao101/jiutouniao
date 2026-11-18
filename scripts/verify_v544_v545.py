#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""v5.4.4+v5.4.5 两次优化交付核查矩阵（连续三轮无异常=完成）。

覆盖用户三项要求：
  R1 全面补充   —— 6 新技能 + 2 新工具 + 13 处既有技能增补节全部在位且结构完整（命令/判据/纪律/通道声明）
  R2 接线不孤儿 —— 路由表/manifest/互引/宪法硬门/容器工具位/发版三件套全链路
  R3 通用实战   —— 结构要素齐备 + 引擎门测试 + 部署实测（容器内自测/API/数据完整性）
用法：python3 scripts/verify_v544_v545.py [run 标注]
退出码 0=本轮零异常；1=有异常。"""
import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path("/root/jiutouniao")
SKILLS = ROOT / "skills"
NEW_SKILLS = ["api-field-exposure", "osint-leak-intel", "history-recon",
              "session-lifecycle", "share-link-abuse", "org-member-abuse"]
NEW_TOOLS = ["field-exposure.py", "authz-matrix-roles.py"]
OSINT_HOSTS = ["fofa.info", "quake.360.net", "zoomeye.org", "hunter.qianxin.com",
               "api.pwnedpasswords.com", "virustotal.com", "shodan.io", "censys.io", "haveibeenpwned.com"]
PATCHED = ["authz-diff.md", "request-smuggling.md", "frontend-sca.md", "api-doc-leak.md",
           "weak-cred-bruteforce.md", "recon-playbook.md", "identity-bootstrapping.md",
           "api-idor.md", "session-state-chain.md", "jwt-crypto.md", "auth-flow-deep.md"]

fails, passes = [], []


def check(name, ok, detail=""):
    (passes if ok else fails).append(f"{name}{(' | ' + detail) if detail and not ok else ''}")
    print(("PASS " if ok else "FAIL ") + name + ((" —— " + detail) if detail and not ok else ""))


def sh(cmd):
    r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=180)
    return r.returncode, (r.stdout + r.stderr)


print(f"===== 核查轮次：{sys.argv[1] if len(sys.argv) > 1 else 'manual'} =====")
# ---------- R1 全面补充 ----------
for s in NEW_SKILLS:
    p = SKILLS / f"{s}.md"
    t = p.read_text(encoding="utf-8") if p.exists() else ""
    check(f"R1 技能文件 {s}.md 存在+frontmatter", bool(t) and t.startswith("---") and re.search(r'^id: "?'+s+r'"?$', t, re.M))
    # R3 结构要素：实战命令/判据/纪律/通道声明
    check(f"R3 结构 {s}（命令+判据+纪律+M6）", all(k in t for k in ["```", "判据", "纪律", "工具通道"]))
for tool in NEW_TOOLS:
    p = ROOT / "tools-extra" / tool
    check(f"R1 工具源码 {tool}", p.exists() and p.stat().st_size > 3000)
rc, out = sh(f"python3 {ROOT}/tools-extra/field-exposure.py --selftest")
check("R1 自测 field-exposure.py（宿主机）", rc == 0 and "5/5" in out)
rc, out = sh(f"python3 {ROOT}/tools-extra/authz-matrix-roles.py --selftest")
check("R1 自测 authz-matrix-roles.py（宿主机）", rc == 0 and "5/5" in out)
patch_expect = {
    "authz-diff.md": "字段级过度暴露差分", "request-smuggling.md": "h2c 明文升级走私",
    "frontend-sca.md": "SRI", "api-doc-leak.md": "history-recon", "weak-cred-bruteforce.md": "泄露口令字典",
    "recon-playbook.md": "history-recon", "identity-bootstrapping.md": "osint-leak-intel",
    "api-idor.md": "角色矩阵", "session-state-chain.md": "session-lifecycle",
    "jwt-crypto.md": "session-lifecycle", "auth-flow-deep.md": "session-lifecycle",
}
for f, kw in patch_expect.items():
    t = (SKILLS / f).read_text(encoding="utf-8")
    check(f"R1 增补节 {f}（含 '{kw}'）", kw in t)

# ---------- R2 接线不孤儿 ----------
router = (SKILLS / "00-router.md").read_text(encoding="utf-8")
for s in NEW_SKILLS:
    check(f"R2 路由表含 {s}", s in router)
manifest = json.loads((SKILLS / "manifest.json").read_text(encoding="utf-8"))
ids = {e["id"] for e in manifest["skills"]}
for s in NEW_SKILLS:
    check(f"R2 manifest 含 {s}", s in ids)
check("R2 manifest 计数=条目数", manifest["count"] == len(manifest["skills"]), f"count={manifest['count']}")
rc, out = sh(f"python3 {ROOT}/scripts/gen_skill_manifest.py --check")
check("R2 manifest 与生成器一致（--check）", rc == 0)
# 互引无悬挂
refs = set()
for p in list(SKILLS.glob("*.md")) + [ROOT / "prompts" / "loop-core.md"]:
    refs |= set(re.findall(r"load_skill ([a-z0-9-]+)", p.read_text(encoding="utf-8")))
dangling = sorted(r for r in refs if not (SKILLS / f"{r}.md").exists())
check("R2 load_skill 互引零悬挂", not dangling, str(dangling))
check("R2 loop-core 角色矩阵双硬门", "角色矩阵双硬门" in (ROOT / "prompts" / "loop-core.md").read_text(encoding="utf-8"))
# 发版三件套
ver = re.search(r'const App = "([\d.]+)"', (ROOT / "server/internal/version/version.go").read_text(encoding="utf-8")).group(1)
check("R2 version.go=5.4.5", ver == "5.4.5", ver)
md = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
vue = (ROOT / "web-app/src/pages/ChangelogPage.vue").read_text(encoding="utf-8")
check("R2 CHANGELOG.md 含 v5.4.5+v5.4.4", "## v5.4.5" in md and "## v5.4.4" in md)
check("R2 ChangelogPage.vue 含 v5.4.5+v5.4.4", "v5.4.5" in vue and "v5.4.4" in vue)
rc, out = sh(f"python3 {ROOT}/scripts/changelog_sync_check.py")
check("R2 更新记录同源门（109 版逐字一致）", rc == 0, out.strip()[:120])
check("R2 Dockerfile COPY 两个新工具", all(f"tools-extra/{t} /opt/tools/{t}" in (ROOT / "Dockerfile").read_text(encoding="utf-8") for t in NEW_TOOLS))

# ---------- R2/R3 引擎 ----------
orch = (ROOT / "server/internal/engine/orchestrator.go").read_text(encoding="utf-8")
check("R2 护栏白名单九源", all(h in orch for h in OSINT_HOSTS))
rc, out = sh("cd /root/jiutouniao/server && go build ./... && go test ./... -count=1")
check("R3 引擎 build+全量测试零失败", rc == 0 and "FAIL" not in out, out.strip()[-200:])

# ---------- R3 部署实测（容器） ----------
rc, out = sh("curl -s -m 10 http://127.0.0.1:8787/api/public/info")
info = json.loads(out) if out.strip().startswith("{") else {}
check("R3 线上版本 5.4.5", info.get("version") == "5.4.5", str(info.get("version")))
rc, out = sh("curl -s -m 10 -H 'Authorization: Bearer REDACTED-AUTH-TOKEN' http://127.0.0.1:8787/api/skills")
items = json.loads(out)
items = items if isinstance(items, list) else items.get("skills", [])
live_ids = {s.get("id") for s in items}
check("R3 线上技能总数 115", len(items) == 115, str(len(items)))
check("R3 线上 6 新技能可检索", all(s in live_ids for s in NEW_SKILLS))
for tool in NEW_TOOLS:
    rc, out = sh(f"docker exec jiutouniao python3 /opt/tools/{tool} --selftest 2>&1")
    check(f"R3 容器内自测 {tool}", rc == 0 and "5/5" in out)
# 技能引用的 /opt/tools 路径在容器内全部存在
opt_refs = set()
for p in SKILLS.glob("*.md"):
    opt_refs |= set(re.findall(r"/opt/tools/[A-Za-z0-9_./-]+", p.read_text(encoding="utf-8")))
missing_tools = []
for ref in sorted(opt_refs):
    rc, out = sh(f"docker exec jiutouniao sh -c 'test -e {ref} && echo OK'")
    if "OK" not in out:
        missing_tools.append(ref)
check("R3 技能引用的 /opt/tools 路径容器内全部存在", not missing_tools, str(missing_tools))
# 二进制一致性：容器内运行 = 源码最新构建
rc, out = sh("md5sum /root/jiutouniao/jiutouniao | cut -d' ' -f1; docker exec jiutouniao md5sum /app/jiutouniao | cut -d' ' -f1")
h = out.split()
check("R3 容器二进制=宿主机最新构建", len(h) == 2 and h[0] == h[1], str(h))
# 前端：线上 index 资产 = 本地 dist
rc, out = sh("curl -s -m 10 http://127.0.0.1:8787/ | grep -oE 'index-[A-Za-z0-9_-]+\\.js' | head -1")
served = out.strip()
dist = subprocess.run("grep -oE 'index-[A-Za-z0-9_-]+\\.js' /root/jiutouniao/web-app/dist/index.html | head -1",
                      shell=True, capture_output=True, text=True).stdout.strip()
check("R3 线上前端=本地最新 dist", served == dist and served, f"served={served} dist={dist}")
# 项目数据完整性
rc, out = sh("curl -s -m 10 -H 'Authorization: Bearer REDACTED-AUTH-TOKEN' http://127.0.0.1:8787/api/projects")
n = len(json.loads(out))
check("R3 项目数据完整（34 个）", n == 34, str(n))

print(f"\n===== 本轮结果：PASS {len(passes)} / FAIL {len(fails)} =====")
if fails:
    print("异常清单：")
    for f in fails:
        print("  -", f)
sys.exit(1 if fails else 0)
