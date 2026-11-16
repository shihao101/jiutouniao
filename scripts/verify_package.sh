#!/usr/bin/env bash
# v5.1.4 收包方轻量验收（不依赖 go/容器/config.json）：包完整性 + 关键路径 + 敏感排除
# 用法: bash scripts/verify_package.sh dist/jiutouniao_v<版本>_部署包.zip
set -u
Z="${1:-}"
[ -f "$Z" ] || { echo "❌ 包不存在: $Z"; exit 1; }
unzip -tqq "$Z" >/dev/null || { echo "❌ ZIP 结构损坏"; exit 1; }
FAIL=0
need() { unzip -l "$Z" | grep -q "jiutouniao/$1" && echo "  ✓ $1" || { echo "  ✗ 缺失 $1"; FAIL=1; }; }
ban()  { unzip -l "$Z" | grep -qE "jiutouniao/$1" && { echo "  ✗ 禁入项泄漏: $1"; FAIL=1; } || echo "  ✓ 已排除 $1"; }
echo "== 部署包验收: $(basename "$Z") =="
need "server/go.mod"
W=$(unzip -l "$Z" | grep -c "jiutouniao/server/internal/web/.*\.go"); [ "$W" -ge 3 ] && echo "  ✓ server/internal/web 源码 ($W 文件)" || { echo "  ✗ web 源码缺失 ($W)"; FAIL=1; }
E=$(unzip -l "$Z" | grep -c "jiutouniao/server/internal/engine/.*\.go"); [ "$E" -ge 10 ] && echo "  ✓ engine 源码 ($E 文件)" || { echo "  ✗ engine 源码不足 ($E)"; FAIL=1; }
S=$(unzip -l "$Z" | grep -c "jiutouniao/skills/.*\.md"); [ "$S" -ge 100 ] && echo "  ✓ 技能库 ($S)" || { echo "  ✗ 技能不足 ($S)"; FAIL=1; }
need "eval/gates/coverage_gate.py"; need "web-app/package-lock.json"
V=$(unzip -l "$Z" | grep -c "jiutouniao/web-app/node_modules/vite/dist/node/cli.js"); [ "$V" -ge 1 ] && echo "  ✓ vite 运行时完整" || { echo "  ✗ vite/dist 缺失（febuilder 将失败）"; FAIL=1; }; need "config.example.json"; need "docker-compose.yml"; need "Dockerfile"; need "scripts/deploy.sh"
ban "config.json"; ban "projects/"; ban ".env"; ban "jiutouniao.db"
[ "$FAIL" -eq 0 ] && echo "✅ 包验收通过" || { echo "❌ 包验收失败"; exit 1; }
