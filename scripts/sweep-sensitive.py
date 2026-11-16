#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
sweep-sensitive.py — 开源发布前敏感信息扫描（v3.0.0 固化）

用途：git 提交/开源发布前，扫描「将被纳入版本库的文件」是否携带客户项目痕迹或密钥。
扫描域与 .gitignore 同步（被忽略的 projects/config.json 等天然不在扫描范围）。

用法：
  python3 scripts/sweep-sensitive.py            # 扫描，命中即退出码 1（可挂 CI/Makefile）
  python3 scripts/sweep-sensitive.py -v         # 逐条打印命中行

维护：新增敏感模式时在 PATTERNS 追加；误报（如 vendor 库自带词）加入 IGNORE 匹配前缀。
"""
import os
import json
import re
import sys

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# —— 敏感模式（正则，大小写不敏感）——
PATTERNS = [
    (r"\bJT-[0-9A-F]{10}\b", "项目 ID"),
    (r"ark-[0-9a-f]{8}-[0-9a-f-]{20,}", "LLM API Key 形态"),
    (r"sk-[a-zA-Z0-9]{32,}", "API Key 形态（sk-）"),
    (r"(api_?key|secret|token)\s*[=:]\s*[\"'][A-Za-z0-9+/_-]{16,}[\"']", "硬编码密钥赋值"),
    (r"jt-c[0-9a-f]{10,}", "平台 auth_token 形态"),
]

# v4.7.1 目标特定模式外置（JTN_SWEEP_PATTERNS，默认 ../jtn-private/sweep-target-patterns.json）——
# 新机部署/分发包不携带历史目标痕迹；文件缺失时仅通用模式生效。
_TARGET_PATTERNS_FILE = os.environ.get(
    "JTN_SWEEP_PATTERNS",
    os.path.join(os.path.dirname(REPO_ROOT), "jtn-private", "sweep-target-patterns.json"))
try:
    with open(_TARGET_PATTERNS_FILE, encoding="utf-8") as _f:
        for _k, _v in json.load(_f).get("sweep", []):
            PATTERNS.append((_k, _v))
except Exception:
    pass

# 已知误报（vendor 库/底座自带内容，按行前缀豁免）
IGNORE_LINE_SUBSTR = ["golang.org/x/", "StringToSid"]

# 扫描域排除（与 pack.py 排除纪律同源，v5.1 修复：独立运行缺常量 NameError）——
# git 开源扫描域 = 将纳入版本库的文件；projects/docs/web 构建产物/依赖目录不入扫描。
EXCLUDE_FILES = {"config.json", "docker-compose.override.yml", ".env",
                 "jiutouniao.db", "secret.key", "sb.log", "tunnel.log", "server.log",
                 "pack_sensitive_patterns.txt"}
EXCLUDE_DIRS = {"projects", ".git", "backup-before-wipe", "dist", "docs", "web",
                "__pycache__", ".zcode", ".jiutouniao", "wheelhouse-tmp", "results",
                "node_modules", "vendor"}
EXCLUDE_SUBSTR = ("node_modules", "server/vendor", "wheelhouse", ".min.js",
                  "tools-extra/sqlmap")  # vendored GPL 上游（pack.py 同口径豁免：自带字典词/历史常量）
EXCLUDE_EXT = (".log", ".zip", ".tar.gz", ".db", ".png", ".jpg", ".jpeg", ".gif",
               ".ico", ".woff", ".woff2", ".ttf", ".eot", ".wasm", ".gz", ".pdf", ".mp4")
EXCLUDE_PREFIX = ("backup",)


def iter_files():
    for root, dirs, files in os.walk(REPO_ROOT):
        rel_root = os.path.relpath(root, REPO_ROOT)
        dirs[:] = [d for d in dirs if d not in EXCLUDE_DIRS
                   and not any(p in d for p in EXCLUDE_SUBSTR)]
        if any(p in rel_root for p in EXCLUDE_SUBSTR):
            continue
        for name in files:
            if name in EXCLUDE_FILES or name.startswith(EXCLUDE_PREFIX):
                continue
            if name.startswith(EXCLUDE_PREFIX) or any(p in name for p in EXCLUDE_SUBSTR):
                continue
            ext = os.path.splitext(name)[1].lower()
            if ext in EXCLUDE_EXT:
                continue
            yield os.path.join(root, name)


def main():
    verbose = "-v" in sys.argv
    hits = []
    scanned = 0
    for path in iter_files():
        scanned += 1
        try:
            with open(path, encoding="utf-8", errors="replace") as f:
                for i, line in enumerate(f, 1):
                    if any(s in line for s in IGNORE_LINE_SUBSTR):
                        continue
                    for pat, label in PATTERNS:
                        if re.search(pat, line, re.I):
                            hits.append((path, i, label, line.strip()[:120]))
                            break
        except (OSError, UnicodeError):
            continue
    print(f"扫描文件 {scanned} 个，命中 {len(hits)} 处")
    for path, i, label, text in hits:
        rel = os.path.relpath(path, REPO_ROOT)
        print(f"  [{label}] {rel}:{i}: {text}")
    if hits and not verbose:
        print("（加 -v 查看逐条；确认为真敏感后清理，误报模式加入 IGNORE_LINE_SUBSTR）")
    sys.exit(1 if hits else 0)


if __name__ == "__main__":
    main()
