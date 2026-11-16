#!/usr/bin/env bash
# 九头鸟部署守卫（v3.7.7）：部署前检查有无运行中项目，避免重建容器打断正在执行的渗透任务。
# 用法: bash scripts/deploy.sh [--force]   （--force 跳过守卫，风险自担）
set -e
R="$(cd "$(dirname "$0")/.." && pwd)"
cd "$R"
FORCE="${1:-}"

TOKEN=$(python3 -c "import json;print(json.load(open('config.json')).get('auth_token',''))" 2>/dev/null || echo "")
if [ -z "$TOKEN" ]; then echo "⚠ config.json 无 auth_token，跳过运行检查"; else
  RUNNING=$(curl -s -m 5 -H "Authorization: Bearer $TOKEN" http://localhost:8787/api/projects | \
    python3 -c "import json,sys;ps=json.load(sys.stdin);print(','.join(p['id']+' '+p['name'] for p in ps if p['status']=='running'))" 2>/dev/null || true)
  if [ -n "$RUNNING" ] && [ "$FORCE" != "--force" ]; then
    echo "❌ 有项目正在运行，部署会将其打断并置为 paused："
    echo "$RUNNING" | sed 's/^/    /'
    echo "   等任务完成后再部署，或确认无碍后用 --force 强制部署（项目会自动进入断点续跑）。"
    exit 1
  fi
  [ -n "$RUNNING" ] && echo "⚠ --force：有运行中项目将被打断（断点续跑兜底）"
fi

echo "① 构建镜像…"; docker compose build jiutouniao
echo "② 替换容器…"; docker compose up -d jiutouniao
sleep 6
# v5.1.2：就绪检查重试 6 次（防 Kali 大镜像冷启动 >6s 误报失败且无回滚）
echo "③ 就绪检查…"
INFO=""
for i in 1 2 3 4 5 6; do
  INFO=$(curl -s -m 5 http://localhost:8787/api/public/info) && [ -n "$INFO" ] && break
  [ "$i" = "6" ] && { echo "❌ 就绪检查失败（排查：docker logs jiutouniao | tail -20）"; exit 1; }
  echo "   第 $i 次未就绪，5s 后重试…"; sleep 5
done
echo "$INFO"
echo; echo "✅ 部署完成"
