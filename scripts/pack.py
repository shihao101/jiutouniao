#!/usr/bin/env python3
"""九头鸟部署包打包脚本（symlink-safe zip + 敏感信息扫描 + 包完整性自检）。

用法:
    python3 scripts/pack.py            # 自动读版本号 → dist/jiutouniao_v<版本>_部署包.zip
    python3 scripts/pack.py 2.6.0      # 指定版本号

排除纪律（新部署包不得含测试专属/敏感信息；v3.1.0 开源口径）:
    - config.json            → 含 auth_token / 管理口令（部署时单独提供）
    - projects/ jiutouniao.db secret.key → 运行数据与密钥
    - docker-compose.override.yml .env    → 环境专属地址（内网代理/IP 钉住）
    - *.log backup* dist/ docs/ .git     → 日志/备份/内部文档
    - 旧二进制（jiutouniao, server/jiutouniao）
    - web/（v5.1.4 P0 修复：仅根目录级排除——曾按名匹配误剪 server/internal/web
      Go Web 路由源码致包内 go build 必失败，现已改为 rel=="web" 精确匹配）
打包含符号链接节点（web-app/node_modules/.bin 等，create_system=3 + S_IFLNK 保留）。
打包完成后：包内敏感扫描 + 包完整性自检（源码/技能/门/禁入清单），任一失败即退出非零。
"""
import os
import re
import stat
import sys
import time
import zipfile


def _load_target_patterns():
    """v4.7.1：目标特定敏感模式外置加载（新机分发包零历史痕迹）。

    v5.1.2 修复：与 sweep-sensitive.py 同源路径（仓库外 ../jtn-private）——
    原路径指向仓库内 jtn-private（不存在）导致打包扫描的目标特定模式静默未加载。
    v5.1.4 修复：外置模式为 (模式, 标签) 元组形态——取首元素为正则串
    （原直接返回 tuple 传入 re.compile 触发 TypeError——路径修正后首次暴露的潜在 bug）。
    """
    import json as _json
    path = os.environ.get("JTN_SWEEP_PATTERNS",
        os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), os.pardir, "jtn-private", "sweep-target-patterns.json"))
    try:
        with open(path, encoding="utf-8") as f:
            return [str(x[0]) if isinstance(x, (list, tuple)) else str(x)
                    for x in _json.load(f).get("pack", [])]
    except Exception:
        return []


ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

EXCLUDE_FILES = {
    "config.json", "docker-compose.override.yml", ".env",
    "jiutouniao.db", "secret.key",
    "jiutouniao", "jiutouniao-v2.1", "jiutouniao-v2.2", "jiutouniao-v2.3",
    "sb.log", "tunnel.log", "server.log",
    "pack_sensitive_patterns.txt", "sweep-sensitive.py.bak",
}
# v3.1.0 开源口径：.gitignore/.dockerignore 随包分发（收包人可直接 git init / docker build）；
# v5.1.4 P0 修复：EXCLUDE_DIRS 全部改为根目录级路径匹配——原按名匹配两级误伤：
#   ① "web" 剪掉 server/internal/web（Go Web 路由源码）→ 包内 go build 必失败；
#   ② "dist" 剪掉 web-app/node_modules/vite/dist（vite 运行时本体）→ 包内 febuilder npm 构建必失败。
# 任意级仅保留 "__pycache__"（字节码缓存，任何层级都不该入包）。
EXCLUDE_ROOT_DIRS = {"projects", ".git", "backup-before-wipe", "dist", "docs", "web", "jtn-private",
                     ".zcode", ".jiutouniao", "wheelhouse-tmp",
                     "results"}  # v3.6.0：eval/results 为运行产物（含项目 ID，命中敏感模式），不入包
EXCLUDE_ANY_DIRS = {"__pycache__"}
# v4.4.3 纯净开源部署包口径：评测靶场（故意脆弱应用 + 预期漏洞清单）不入包，
# 仅保留 eval/README.md 占位说明——Dockerfile 的 COPY eval/ 仍可正常构建。
EXCLUDE_PATHS = ("eval/target/", "eval/expected.json", "web-app/dist/",
                 "eval/results/")  # v5.3.3 修复：v3.6.0 的 "results" 根目录名排除只匹配根级，eval/results（运行产物，含项目 ID）实际漏入包——按前缀排除

EXCLUDE_SUFFIX = (".log", ".zip", ".tar.gz", ".db")
EXCLUDE_PREFIX = ("backup",)

# 敏感模式：命中即视为包被污染（按行扫描文本内容）。
# 注：config.go/README 中的出厂默认管理口令为随源码分发的文档化默认值（部署强制修改），
#     不属环境敏感信息；真实口令/令牌所在文件（config.json/.env）已整体排除。
SENSITIVE_PATTERNS = [
    r"192\.168\.56\.\d+",          # 测试内网地址
    r"118\.196\.65\.\d+",          # 测试环境钉住的端点 IP
    r"auth_token['\"]?\s*[:=]\s*['\"]?jt-",
    r"jt-c[0-9a-f]{8,}",
    r"\bJT-[0-9A-F]{10}\b",
    # v4.7.1 目标特定模式外置（JTN_SWEEP_PATTERNS，默认 ../jtn-private/sweep-target-patterns.json）——
    # 分发包不携带历史目标痕迹；外部文件缺失时仅通用模式生效（与 scripts/sweep-sensitive.py 双保险）
    *_load_target_patterns(),
]
BINARY_EXT = {".png", ".jpg", ".jpeg", ".gif", ".ico", ".woff", ".woff2",
              ".ttf", ".eot", ".mp4", ".webm", ".gz", ".zip", ".pdf"}

# 扫描豁免（不影响打包内容，仅敏感扫描跳过）：
#   - vendored 上游代码（sqlmap GPL 源码自带字典词、Go vendor 自带标识符）
#   - 扫描器自身的模式字面量（自匹配）
#   - npm 依赖二进制（esbuild 等随机字节偶合模式词，另有 null-byte 二进制探测兜底）
SCAN_SKIP_PREFIX = ("tools-extra/sqlmap/", "server/vendor/", "web-app/node_modules/",
                    "scripts/pack.py", "scripts/sweep-sensitive.py")


def excluded(rel: str) -> bool:
    if rel in EXCLUDE_PATHS or any(rel.startswith(p) for p in EXCLUDE_PATHS):
        return True
    # v5.1.4 P0 修复：目录排除全部根目录级（rel 精确匹配），任意级仅 __pycache__；
    # web-app/dist（前端构建产物）显式排除——node_modules/vite/dist 必须保留（febuilder 依赖）。
    if rel in EXCLUDE_ROOT_DIRS or rel == "web-app/dist":
        return True
    parts = rel.split(os.sep)
    if any(p in EXCLUDE_ANY_DIRS for p in parts):
        return True
    base = parts[-1]
    if base in EXCLUDE_FILES or base.startswith(EXCLUDE_PREFIX):
        return True
    return any(base.endswith(s) for s in EXCLUDE_SUFFIX)


def read_version() -> str:
    raw = open(os.path.join(ROOT, "server", "internal", "version", "version.go"), encoding="utf-8").read()
    m = re.search(r'App = "([^"]+)"', raw)
    return m.group(1) if m else "unknown"


def human(n: float) -> str:
    return f"{n/1024/1024:.1f}MB" if n >= 1024 * 1024 else f"{n/1024:.0f}KB"


def verify_package_integrity(out: str) -> None:
    """v5.1.4 P0-2：打包后包完整性自检——源码/技能/门/禁入清单断言，缺失即退出非零。
    （此前按名排除误剪 server/internal/web 致包内源码不可构建，抽查未覆盖源码完备性。）"""
    with zipfile.ZipFile(out) as z:
        names = z.namelist()

    def go_cnt(prefix: str) -> int:
        return sum(1 for x in names if x.startswith("jiutouniao/" + prefix) and x.endswith(".go"))

    def has(p: str) -> bool:
        return ("jiutouniao/" + p) in names

    checks = [
        ("server/go.mod 存在", has("server/go.mod")),
        ("server/internal/web Go 源码 ≥3 文件", go_cnt("server/internal/web/") >= 3),
        ("server/internal/engine Go 源码 ≥10 文件", go_cnt("server/internal/engine/") >= 10),
        ("server/internal/store Go 源码 ≥1 文件", go_cnt("server/internal/store/") >= 1),
        ("skills 剧本 ≥100", sum(1 for x in names if x.startswith("jiutouniao/skills/") and x.endswith(".md")) >= 100),
        ("eval/gates/coverage_gate.py 存在", has("eval/gates/coverage_gate.py")),
        ("web-app/package-lock.json 存在", has("web-app/package-lock.json")),
        ("web-app/node_modules/vite/dist/node/cli.js 存在（febuilder 依赖）", has("web-app/node_modules/vite/dist/node/cli.js")),
        ("config.example.json 存在", has("config.example.json")),
        ("docker-compose.yml 存在", has("docker-compose.yml")),
        ("禁入: config.json", not has("config.json")),
        ("禁入: projects/ 运行数据", not any(x.startswith("jiutouniao/projects/") for x in names)),
        ("禁入: .env", not has(".env")),
        ("禁入: jiutouniao.db", not has("jiutouniao.db")),
    ]
    bad = []
    for name, ok in checks:
        print(("  ✓ " if ok else "  ✗ ") + name)
        if not ok:
            bad.append(name)
    if bad:
        print(f"❌ 包完整性自检失败 {len(bad)} 项：{bad}")
        sys.exit(1)
    print(f"  包完整性: 通过（web 源码 {go_cnt('server/internal/web/')} 文件 / engine {go_cnt('server/internal/engine/')} 文件）")


def sensitive_scan(out: str) -> None:
    """包内文本敏感扫描（排除 vendored/扫描器自体/二进制），命中即删包退出。"""
    hits = []
    pats = [re.compile(p, re.I) for p in SENSITIVE_PATTERNS]
    with zipfile.ZipFile(out) as z:
        for name in z.namelist():
            if any(name.lower().endswith(e) for e in BINARY_EXT):
                continue
            if any(name.startswith("jiutouniao/" + p) for p in SCAN_SKIP_PREFIX):
                continue
            try:
                raw = z.read(name)
                if b"\x00" in raw[:8192]:        # 二进制探测：含 null 字节即跳过
                    continue
                text = raw.decode("utf-8", "ignore")
            except Exception:
                continue
            for p in pats:
                m = p.search(text)
                if m:
                    hits.append(f"{name}: {m.group(0)[:40]}")
    if hits:
        os.remove(out)
        print("❌ 敏感信息扫描未通过，包已删除：")
        for h in hits[:20]:
            print("  -", h)
        sys.exit(1)


def main() -> None:
    version = sys.argv[1] if len(sys.argv) > 1 else read_version()
    os.makedirs(os.path.join(ROOT, "dist"), exist_ok=True)
    out = os.path.join(ROOT, "dist", f"jiutouniao_v{version}_部署包.zip")
    if os.path.exists(out):
        os.remove(out)

    count, total, links = 0, 0, 0
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED, compresslevel=6) as z:
        for dirpath, dirnames, filenames in os.walk(ROOT):
            dirnames[:] = [d for d in dirnames
                           if not excluded(os.path.relpath(os.path.join(dirpath, d), ROOT))]
            for fn in filenames:
                full = os.path.join(dirpath, fn)
                rel = os.path.relpath(full, ROOT)
                if excluded(rel):
                    continue
                st = os.lstat(full)
                arc = "jiutouniao/" + rel.replace(os.sep, "/")
                if stat.S_ISLNK(st.st_mode):
                    target = os.readlink(full)
                    zi = zipfile.ZipInfo(arc, date_time=time.localtime(st.st_mtime)[:6])
                    zi.create_system = 3
                    zi.external_attr = (stat.S_IFLNK | 0o777) << 16
                    z.writestr(zi, target)
                    links += 1
                else:
                    z.write(full, arc)
                count += 1
                total += st.st_size

    sensitive_scan(out)
    verify_package_integrity(out)

    size = os.path.getsize(out)
    print(f"✅ 部署包完成: {out}")
    print(f"   文件 {count} 个（含符号链接 {links}）| 原始 {human(total)} → 压缩 {human(size)}")
    print(f"   敏感扫描: 通过（{len(SENSITIVE_PATTERNS)} 类模式 0 命中）")


if __name__ == "__main__":
    main()
