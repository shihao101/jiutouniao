#!/usr/bin/env python3
"""subdomain-dict-probe.py — 本地字典型子域/vhost 枚举（D6 离线情报纵深件 v7.6.0）。

用途：CT/测绘/OSINT 出网通道全灭时的本地补偿——对目标域并发解析内置前缀字典，
产出 JSONL（前缀/全称/解析结果/来源）。被动 DNS 历史镜像与 CT 本地缓存属可选
数据集（未内置），缺数据时如实标 not_checked，不做阴性断言。

用法：
  python3 subdomain-dict-probe.py --domain example.com [--wordlist path] \
      [--concurrency 30] [--timeout 3] [--out evidence/s2-dict-probe.jsonl]

纪律：仅对授权目标域解析（DNS 查询不接触目标服务，S1 被动口径兼容）；
阴性结果不作「不存在」断言（NXDOMAIN 与丢包不可区分——双任务实测纪律）。
"""
import argparse
import concurrent.futures
import json
import shutil
import socket
import subprocess
import sys
import time

# 内置通用前缀字典（120 条，通用型：门户/邮件/认证/运维/基础设施/环境，无行业特化）
DEFAULT_PREFIXES = [
    "www", "mail", "smtp", "imap", "pop3", "webmail", "relay", "mx", "ns1", "ns2",
    "vpn", "vpn2", "oa", "portal", "sso", "auth", "oauth", "login", "sso2", "id",
    "admin", "manage", "manager", "console", "dashboard", "backend", "api", "api2",
    "apiv2", "api-doc", "apis", "gateway", "gw", "open", "openapi", "wap", "h5",
    "m", "mobile", "app", "apps", "app1", "app2", "dev", "dev1", "dev2", "test",
    "test1", "test2", "uat", "staging", "stage", "pre", "preprod", "gray", "beta",
    "demo", "sandbox", "trial", "qa", "sit", "git", "gitlab", "github", "svn",
    "jenkins", "ci", "cd", "build", "nexus", "harbor", "registry", "hub", "wiki",
    "doc", "docs", "help", "support", "faq", "kb", "confluence", "jira", "bug",
    "monitor", "zabbix", "grafana", "prometheus", "kibana", "es", "elastic", "log",
    "logs", "syslog", "ntp", "cdn", "static", "img", "images", "download", "dl",
    "upload", "uploads", "file", "files", "ftp", "sftp", "share", "pan", "db",
    "mysql", "redis", "mongo", "pg", "sql", "backup", "bak", "old", "new", "shop",
    "pay", "pay2", "bbs", "forum", "community", "crm", "erp", "hr", "ehr", "oa2",
    "web", "web1", "web2", "www2", "www3", "proxy", "gate", "edge", "node",
]


DIG_AVAILABLE = shutil.which("dig") is not None


def resolve(prefix: str, domain: str, timeout: float) -> dict:
    host = f"{prefix}.{domain}"
    rec = {"prefix": prefix, "host": host, "answers": [], "error": "", "resolver": "dig" if DIG_AVAILABLE else "getaddrinfo"}
    # dig 优先：+time/+tries 可硬性限界（getaddrinfo 是阻塞 libc 调用，不受 socket 超时控制，
    # DNS 受损链路下单次可挂 30s+——沙箱实测教训）
    if DIG_AVAILABLE:
        try:
            cp = subprocess.run(
                ["dig", "+short", f"+time={max(1, int(timeout))}", "+tries=1", host, "A"],
                capture_output=True, text=True, timeout=timeout + 2)
            for ln in cp.stdout.splitlines():
                ln = ln.strip()
                if ln and not ln.endswith("."):
                    rec["answers"].append(ln)
            if cp.returncode != 0 and not rec["answers"]:
                rec["error"] = (cp.stderr or "dig rc=%d" % cp.returncode).strip()[:120]
        except Exception as e:  # noqa: BLE001
            rec["error"] = repr(e)
        return rec
    try:
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
        seen = set()
        for info in infos:
            ip = info[4][0]
            if ip not in seen:
                seen.add(ip)
                rec["answers"].append(ip)
    except socket.gaierror as e:
        rec["error"] = str(e)
    except Exception as e:  # noqa: BLE001 — 工具健壮性优先
        rec["error"] = repr(e)
    return rec


def main() -> int:
    ap = argparse.ArgumentParser(description="本地字典型子域枚举（D6 离线补偿件）")
    ap.add_argument("--domain", required=True, help="授权目标根域（如 example.com）")
    ap.add_argument("--wordlist", default="", help="自定义前缀字典文件（每行一个前缀；缺省用内置 120 条）")
    ap.add_argument("--concurrency", type=int, default=30)
    ap.add_argument("--timeout", type=float, default=3.0, help="单次解析超时秒（socket 级）")
    ap.add_argument("--out", default="", help="JSONL 输出文件（缺省 stdout；留证建议 evidence/s2-dict-probe.jsonl）")
    args = ap.parse_args()

    socket.setdefaulttimeout(args.timeout)
    prefixes = list(DEFAULT_PREFIXES)
    if args.wordlist:
        with open(args.wordlist, encoding="utf-8") as fh:
            extra = [ln.strip() for ln in fh if ln.strip() and not ln.startswith("#")]
        prefixes = list(dict.fromkeys(prefixes + extra))  # 合并去重，保序
    domain = args.domain.lstrip(".").lower()

    t0 = time.time()
    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, args.concurrency)) as ex:
        futures = {ex.submit(resolve, p, domain, args.timeout): p for p in prefixes}
        for fut in concurrent.futures.as_completed(futures):
            results.append(fut.result())
    results.sort(key=lambda r: (0 if r["answers"] else 1, r["prefix"]))

    out = sys.stdout if not args.out else open(args.out, "w", encoding="utf-8")
    hit = 0
    for r in results:
        if r["answers"]:
            hit += 1
        out.write(json.dumps(r, ensure_ascii=False) + "\n")
    summary = {
        "tool": "subdomain-dict-probe v7.6.0 (D6)",
        "domain": domain,
        "probed": len(results),
        "resolved": hit,
        "elapsed_sec": round(time.time() - t0, 1),
        "note": "阴性（未解析）不作不存在断言：NXDOMAIN 与丢包不可区分——复验项走 record_vt",
        "resolver": "dig" if DIG_AVAILABLE else "getaddrinfo(无硬超时，建议安装 dig)",
    }
    out.write(json.dumps(summary, ensure_ascii=False) + "\n")
    if args.out:
        out.close()
        print(json.dumps(summary, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
