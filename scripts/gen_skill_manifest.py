#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""v5.3.2 P1-2：skills/manifest.json 单源生成器。

此前 manifest 为手工维护（v5.3.0 引入时无生成器），schema 只有 frontmatter 三字段的镜像；
本生成器将其升级为「扫描 + 启发式推导 + 关键技能人工策展」的单源管线：
  - 扫描 skills/*.md frontmatter（id/title/tags）
  - stage_fit：tags 中 s1..s8/specA/specB1/specB2
  - depends_on：00-router.md「配合」列反向归集 + 技能正文 load_skill/配合引用扫描
  - aliases / handoff_to：关键技能策展覆盖表（CURATED），其余技能不硬造
  - lab_only：正文含「Execution Profile 标注」节或策展清单（与 engine/profile.go 策展兜底一致）
  - execution_profile_default / lab_only_actions：沿用 v5.3.0 schema 并在标注在位时指向真实节

用法：python3 scripts/gen_skill_manifest.py [--check]（--check 只校验不写盘，CI/核查用）
退出码 0=一致；1=漂移。
"""
import argparse
import json
import os
import re
import sys

ROOT = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
SKILLS_DIR = os.path.join(ROOT, "skills")
ROUTER = os.path.join(SKILLS_DIR, "00-router.md")
OUT = os.path.join(SKILLS_DIR, "manifest.json")
VERSION = "5.8.0"

STAGE_RE = re.compile(r"^(s[1-8]|specA|specB1|specB2)$")

# v6.6.0（SP-④）：短标签映射——frontmatter 中的 a/b1/b2 归一化为 specA/specB1/specB2。
# 此前短标签不匹配 STAGE_RE 被静默丢弃，7 个专项相关技能 stage_fit 落成 s4 或空，
# spec 阶段 load_skill 检索 +3 加成仅覆盖 4/12（审计实证）。
SHORT_STAGE_TAG = {"a": "specA", "b1": "specB1", "b2": "specB2"}
DROPPED_STAGE_TAGS = set()

# 关键技能策展覆盖表：aliases（检索同义词）/ handoff_to（交接去向）。
# 覆盖路由器与高危/家族卡技能；其余技能 aliases/handoff 不硬造（宁缺勿滥，检索正文兜底）。
CURATED = {
    "00-router": {"aliases": ["路由", "技能索引", "总索引"], "handoff_to": ["project-warmup", "scan-tiering"]},
    "sqli-deep": {"aliases": ["sql注入", "盲注", "堆叠注入"], "handoff_to": ["evidence-standard"]},
    "authz-diff": {"aliases": ["越权", "未授权", "水平越权", "idor"], "handoff_to": ["evidence-standard"]},
    "api-idor": {"aliases": ["idor", "越权对象"], "depends_on": ["authz-diff"], "handoff_to": ["evidence-standard"]},
    "api-field-exposure": {"aliases": ["过度暴露", "字段泄露", "api3", "多吐字段"], "depends_on": ["authz-diff"], "handoff_to": ["evidence-standard"]},
    "session-lifecycle": {"aliases": ["会话吊销", "登出", "token生命周期", "refresh", "改密踢会话"], "depends_on": ["session-state-chain", "jwt-crypto"], "handoff_to": ["evidence-standard"]},
    "share-link-abuse": {"aliases": ["分享", "分享链接", "签名伪造", "keyId"], "depends_on": ["intel-factory"], "handoff_to": ["api-idor", "crypto-offensive"]},
    "org-member-abuse": {"aliases": ["邀请", "成员管理", "角色传播", "权限残留", "多租户"], "depends_on": ["api-idor", "session-lifecycle"], "handoff_to": ["instance-diff"]},
    "osint-leak-intel": {"aliases": ["泄露库", "hibp", "密钥扫描", "测绘"], "handoff_to": ["weak-cred-bruteforce"]},
    "history-recon": {"aliases": ["wayback", "历史接口", "影子api", "旧版本"], "handoff_to": ["authz-diff"]},
    "upload-bypass": {"aliases": ["文件上传", "上传绕过"], "handoff_to": ["webshell-memshell"]},
    "webshell-memshell": {"aliases": ["webshell", "内存马", "后门"]},
    "persistence": {"aliases": ["权限维持", "后门驻留"]},
    "cleanup-handover": {"aliases": ["收尾", "清理移交", "影响量化", "待续处置", "移交清单"]},
    "logic-csrf-deser": {"aliases": ["反序列化", "csrf"]},
    "identity-bootstrapping": {"aliases": ["身份获取", "账号获取"], "handoff_to": ["session-state-chain"]},
        "session-state-chain": {"aliases": ["会话链", "会话构造"]},
    "whitebox-source-audit": {"aliases": ["白盒", "源码审计", "代码审计", "危险模式"], "handoff_to": ["whitebox-sca-taint", "hypothesis-0day"]},
    "whitebox-sca-taint": {"aliases": ["sca", "依赖分析", "污点", "sink"], "depends_on": ["whitebox-source-audit"], "handoff_to": ["cve-weaponization", "patch-diffing"]},
    "patch-diffing": {"aliases": ["补丁差分", "patch diff", "1day", "nday无poc"], "depends_on": ["cve-weaponization"], "handoff_to": ["hypothesis-0day"]},
    "fuzzing-workflow": {"aliases": ["模糊测试", "fuzz", "崩溃", "harness"], "handoff_to": ["fuzz-harness-go", "hypothesis-0day"]},
    "fuzz-harness-go": {"aliases": ["go fuzz", "native fuzz", "崩溃复现"], "depends_on": ["fuzzing-workflow"], "handoff_to": ["whitebox-source-audit"]},
    "tls-deep-audit": {"aliases": ["tls", "ssl", "证书", "协议降级", "mtls"], "handoff_to": ["cve-weaponization"]},
    "thick-client": {"aliases": ["electron", "桌面应用", "客户端", "自动更新劫持"], "handoff_to": ["whitebox-source-audit", "api-idor"]},
    "wifi-nearfield": {"aliases": ["wifi", "无线", "蓝牙", "ble", "nfc", "门禁"], "handoff_to": ["password-offline", "intranet-lateral"]},
    "iot-firmware": {"aliases": ["iot", "固件", "binwalk", "嵌入式"], "depends_on": ["whitebox-source-audit"], "handoff_to": ["cve-weaponization"]},
    "ics-ot": {"aliases": ["ics", "ot", "scada", "plc", "modbus", "工业"], "handoff_to": ["cve-weaponization", "intranet-lateral"]},
    "social-engineering": {"aliases": ["社工", "钓鱼", "红队演练", "现场"], "depends_on": ["phishing-infra"], "handoff_to": ["osint-leak-intel"]},
    "evidence-standard": {"aliases": ["证据", "取证标准"]},
    "hypothesis-matrix": {"aliases": ["筛查矩阵", "k3"]},
    "hypothesis-0day": {"aliases": ["0day", "nday假设"]},
    "cve-weaponization": {"aliases": ["cve", "漏洞武器化", "poc"]},
    "cmdi-deep": {"aliases": ["命令注入", "rce"], "handoff_to": ["evidence-standard"]},
    "ssrf-deep": {"aliases": ["ssrf", "服务端请求伪造"]},
    "xxe-deep": {"aliases": ["xxe", "xml实体"]},
    "js-challenge-waf-playbook": {"aliases": ["js挑战", "瑞数", "waf挑战"], "handoff_to": ["channel-snapshot"]},
    "rate-limit-playbook": {"aliases": ["限速", "频控"], "handoff_to": ["channel-snapshot"]},
    "gateway-filter-playbook": {"aliases": ["网关", "waf绕过", "边界"]},
    "auth-bypass": {"aliases": ["认证绕过", "登录绕过"]},
    "edu-family": {"aliases": ["教育", "高校"]},
    "idp-family": {"aliases": ["统一身份", "cas", "shibboleth"]},
    "oa-family": {"aliases": ["oa", "办公系统"]},
    "framework-priors": {"aliases": ["框架指纹", "先验"]},
    "report-writing": {"aliases": ["报告", "报告编写"]},
    "subdomain-takeover": {"aliases": ["子域接管", "接管"]},
    # v6.6.0（SP-⑤）：三大专项新增条目配套技能（P0 批 A12/D7/W7 + P1 批 A13/A14/D8/W8/W9 + P2 W10）
    "llm-agent-protocol-boundaries": {"aliases": ["mcp", "a2a", "agent协议", "信任边界", "受众绑定", "混淆代理"], "depends_on": ["llm-agent-toolchain", "auth-flow-deep", "evidence-standard"], "handoff_to": ["api-idor", "report-writing"]},
    "app-integrity-server-verify": {"aliases": ["play integrity", "app attest", "设备完整性", "完整性判定", "防重放"], "depends_on": ["app-dynamic-audit", "evidence-standard"], "handoff_to": ["evidence-standard", "report-writing"]},
    "miniapp-platform-login": {"aliases": ["授权码", "code2session", "登录态", "会话绑定", "身份映射"], "depends_on": ["miniapp-audit", "miniapp-server"], "handoff_to": ["api-idor", "session-lifecycle", "report-writing"]},
    "llm-agent-memory-integrity": {"aliases": ["agent记忆", "记忆投毒", "长期记忆", "上下文投毒"], "depends_on": ["rag-attack", "evidence-standard"], "handoff_to": ["evidence-standard", "report-writing"]},
    "llm-gateway-policy-chain": {"aliases": ["llm网关", "防护链", "内容安全", "策略链", "误报漏报"], "depends_on": ["llm-top10", "evidence-standard"], "handoff_to": ["evidence-standard", "report-writing"]},
    "app-sdk-privacy-behavior": {"aliases": ["sdk数据行为", "隐私清单", "privacy manifest", "sdk治理"], "depends_on": ["app-privacy-compliance", "app-static-audit"], "handoff_to": ["report-writing"]},
    "miniapp-host-isolation": {"aliases": ["宿主桥接", "跨小程序", "宿主能力", "隔离边界"], "depends_on": ["miniapp-audit"], "handoff_to": ["api-idor", "report-writing"]},
    "miniapp-cloud-identity": {"aliases": ["云函数身份", "部署边界", "云资源身份", "iam"], "depends_on": ["miniapp-audit", "miniapp-server", "cloud-security"], "handoff_to": ["evidence-standard", "report-writing"]},
    "miniapp-privacy-governance": {"aliases": ["备案", "隐私披露", "sdk治理证据", "个人信息"], "depends_on": ["app-privacy-compliance"], "handoff_to": ["report-writing"]},
}

# Lab Only 技能集（与 server/internal/engine/profile.go labOnlySkillIds 保持一致——策展兜底同源）。
LAB_ONLY = {"persistence", "webshell-memshell", "upload-bypass", "logic-csrf-deser",
            "database-postex", "tunnel-pivot", "cve-weaponization", "crypto-offensive",
            "hypothesis-0day"}


def parse_frontmatter(path):
    with open(path, encoding="utf-8") as f:
        head = f.read(400)
    m = re.search(r"---\nid:\s*\"?(.*?)\"?\ntitle:\s*(.*?)\ntags:\s*(.*?)\n---", head, re.S)
    if not m:
        return None
    tags = [t.strip().strip('"') for t in m.group(3).split(",") if t.strip().strip('"')]
    return m.group(1).strip(), m.group(2).strip(), tags


def router_pairs():
    """00-router.md 两张表：| 遇到什么 | 首选技能 | 配合 | → 首选→配合依赖归集。"""
    deps = {}
    if not os.path.isfile(ROUTER):
        return deps
    for line in open(ROUTER, encoding="utf-8"):
        m = re.match(r"^\|[^|]+\|\s*([a-z0-9-]+)\s*\|\s*([a-z0-9\-+ 、/]+)\s*\|", line)
        if not m:
            continue
        primary, partners = m.group(1), m.group(2)
        ids = re.findall(r"[a-z0-9][a-z0-9-]{2,}", partners)
        deps.setdefault(primary, set()).update(i for i in ids if i != primary)
    return deps


def body_refs(body):
    """正文引用扫描：load_skill <id> / 配合技能 <id>。"""
    refs = set()
    refs.update(re.findall(r"load_skill\s+([a-z0-9][a-z0-9-]{2,})", body))
    refs.update(re.findall(r"配合技能[:：]?\s*([a-z0-9][a-z0-9-]{2,})", body))
    refs.update(re.findall(r"`([a-z0-9][a-z0-9-]{3,})\.md`", body))
    return refs


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true", help="只校验不写盘（漂移退出码 1）")
    ns = ap.parse_args()

    files = sorted(f for f in os.listdir(SKILLS_DIR) if f.endswith(".md"))
    skills = []
    for fname in files:
        sid = fname[:-3]
        fm = parse_frontmatter(os.path.join(SKILLS_DIR, fname))
        if not fm:
            print(f"FAIL frontmatter 缺失: {fname}")
            sys.exit(1)
        _id, title, tags = fm
        if _id != sid:
            print(f"FAIL frontmatter id 与文件名不一致: {fname} id={_id}")
            sys.exit(1)
        with open(os.path.join(SKILLS_DIR, fname), encoding="utf-8") as f:
            body = f.read()
        stage_fit = []
        for t in tags:
            if STAGE_RE.match(t):
                if t not in stage_fit:
                    stage_fit.append(t)
            elif t in SHORT_STAGE_TAG:
                full = SHORT_STAGE_TAG[t]
                if full not in stage_fit:
                    stage_fit.append(full)
            elif re.fullmatch(r"s\d+|spec\w+", t):
                # 形似阶段标签但不在白名单——记录而非静默丢弃（消除再次漂移的盲区）
                DROPPED_STAGE_TAGS.add(f"{sid}:{t}")
        stage_fit.sort()
        cur = CURATED.get(sid, {})
        deps = set(cur.get("depends_on", []))
        deps |= router_pairs().get(sid, set())
        for r in body_refs(body):
            if os.path.isfile(os.path.join(SKILLS_DIR, r + ".md")) and r != sid:
                deps.add(r)
        deps.discard(sid)
        annotated = "Execution Profile 标注" in body
        lab_only = annotated or sid in LAB_ONLY
        entry = {
            "id": sid,
            "file": f"skills/{fname}",
            "title": title,
            "tags": tags,
        }
        if cur.get("aliases"):
            entry["aliases"] = cur["aliases"]
        if deps:
            entry["depends_on"] = sorted(deps)
        if cur.get("handoff_to"):
            entry["handoff_to"] = cur["handoff_to"]
        if stage_fit:
            entry["stage_fit"] = stage_fit
        entry["execution_profile_default"] = "production_safe"
        if lab_only:
            entry["lab_only"] = True
            entry["lab_only_actions"] = "见技能正文「Execution Profile 标注」节（v5.3.2 起高危技能已逐项标注）" if annotated \
                else "策展 Lab Only（待正文标注补齐）"
        skills.append(entry)

    manifest = {
        "version": VERSION,
        "generated": "2026-11-14",
        "description": "机器可读技能清单（v5.3.2：gen_skill_manifest.py 单源生成——aliases/depends_on/handoff_to/stage_fit/lab_only 全量结构化，"
                       "引擎 SkillRegistry 消费；重新生成请跑 scripts/gen_skill_manifest.py）",
        "route_file": "skills/00-router.md",
        "count": len(skills),
        "skills": skills,
    }
    out_json = json.dumps(manifest, ensure_ascii=False, indent=1) + "\n"

    if ns.check:
        try:
            cur_raw = open(OUT, encoding="utf-8").read()
        except FileNotFoundError:
            print("FAIL manifest.json 不存在")
            sys.exit(1)
        if cur_raw == out_json:
            print(f"OK manifest 与生成器输出一致（{len(skills)} 技能）")
            return
        cur = json.loads(cur_raw)
        if cur.get("count") != len(skills):
            print(f"FAIL count 漂移: manifest={cur.get('count')} 生成器={len(skills)}")
            sys.exit(1)
        cur_map = {s["id"]: s for s in cur.get("skills", [])}
        new_map = {s["id"]: s for s in skills}
        drift = []
        for sid in sorted(set(cur_map) | set(new_map)):
            a, b = cur_map.get(sid), new_map.get(sid)
            if a is None or b is None:
                drift.append(f"{sid} 存在性漂移")
            elif json.dumps(a, sort_keys=True, ensure_ascii=False) != json.dumps(b, sort_keys=True, ensure_ascii=False):
                drift.append(sid)
        print("FAIL manifest 与生成器输出漂移: " + ", ".join(drift[:10]))
        sys.exit(1)

    with open(OUT, "w", encoding="utf-8") as f:
        f.write(out_json)
    n_dep = sum(1 for s in skills if s.get("depends_on"))
    n_ali = sum(1 for s in skills if s.get("aliases"))
    n_lab = sum(1 for s in skills if s.get("lab_only"))
    n_stage = sum(1 for s in skills if s.get("stage_fit"))
    print(f"OK manifest 重生成: {len(skills)} 技能 | depends_on {n_dep} | aliases {n_ali} | stage_fit {n_stage} | lab_only {n_lab}")
    if DROPPED_STAGE_TAGS:
        print(f"WARN 形似阶段标签但未入白名单（请核对 STAGE_RE/SHORT_STAGE_TAG）: {', '.join(sorted(DROPPED_STAGE_TAGS))}")


if __name__ == "__main__":
    main()
