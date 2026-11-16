#!/usr/bin/env bash
# 九头鸟发版全项核查（verify_release.sh）
# 用法：bash scripts/verify_release.sh   → 逐项 PASS/FAIL，最后一行给出总结论
# 纪律：连续单轮零 FAIL 才算核查完成；任何 FAIL 修复后必须重跑本脚本。
set -u
R="$(cd "$(dirname "$0")/.." && pwd)"
cd "$R/server" || exit 1
PASS=0; FAIL=0; FAILED_ITEMS=()

item() { # item 名称 命令...
  local name="$1"; shift
  if "$@" >/tmp/vr_out.log 2>&1; then
    echo "PASS  $name"; PASS=$((PASS+1))
  else
    echo "FAIL  $name"; tail -5 /tmp/vr_out.log | sed 's/^/      /'
    FAIL=$((FAIL+1)); FAILED_ITEMS+=("$name")
  fi
}

VER=$(grep -oP 'App = "\K[^"]+' internal/version/version.go)
SKILL_N=$(ls "$R"/skills/*.md | wc -l)

GO_BIN="$(command -v go || echo /usr/local/go/bin/go)"   # v5.1.2：换机 go 不在 /usr/local/go 时自动发现
echo "== 九头鸟发版核查 v$VER =="
item "Go 编译"            "$GO_BIN" build ./...
item "Go vet"            "$GO_BIN" vet ./...
item "Go 全量测试"        "$GO_BIN" test -count=1 ./...
item "版本更新记录含当前版本" bash -c "grep -q \"v$VER\" $R/web-app/src/pages/ChangelogPage.vue"
item "README 版本行一致"     bash -c "grep -qF \"当前版本 **v$VER**\" $R/README.md"
item "README 技能数一致($SKILL_N)" bash -c "grep -q \"目录 $SKILL_N 个中文攻击剧本\" $R/README.md"
item "技能引用零悬空"        bash -c "cd $R && grep -rhoE 'load_skill[ （]+[a-zA-Z0-9_-]+' heads/ skills/ prompts/ | grep -oE '[a-zA-Z0-9_-]+$' | grep -v '^query$' | sort -u | while read id; do [ -f \"skills/\$id.md\" ] || echo \"dangling: \$id\"; done | wc -l | grep -q '^0$'"
item "技能 id=文件名"        bash -c "cd $R/skills && for f in *.md; do id=\$(head -6 \"\$f\" | grep -oP '^id: \\K.*' | tr -d '\"'); [ \"\$id\" = \"\${f%.md}\" ] || exit 1; done"
item "Python 语法（评测器/浏览器套件）" bash -c "python3 -m py_compile $R/scripts/eval_run.py $R/browser-kit/browser_login.py"
item "打包（含敏感扫描）"     bash -c "cd $R && python3 scripts/pack.py | grep -q '敏感扫描: 通过'"
item "部署包存在"           bash -c "ls $R/dist/jiutouniao_v${VER}_部署包.zip >/dev/null"
item "容器运行中"           bash -c "docker ps --filter name=jiutouniao --filter status=running | grep -q jiutouniao"
item "镜像与容器一致"        bash -c "[ \"\$(docker inspect jiutouniao --format '{{.Image}}' | cut -c8-19)\" = \"\$(docker images jiutouniao:latest --format '{{.ID}}' | cut -c1-12)\" ]"
item "API 版本=版本常量"     bash -c "curl -s -m 5 http://localhost:8787/api/public/info | grep -q \"\\\"version\\\":\\\"$VER\\\"\""
item "Web 可达"            bash -c "curl -s -m 5 -o /dev/null -w '%{http_code}' http://localhost:8787/ | grep -q 200"
item "新引擎符号在镜像内"     bash -c "docker exec jiutouniao sh -c 'strings /app/jiutouniao | grep -q spawn_subagent && strings /app/jiutouniao | grep -q barrier_timeout_sec'"
item "评测体系随镜像分发"      bash -c "docker exec jiutouniao sh -c 'test -f /app/eval/eval_run.py && test -f /app/eval/README.md && test -d /app/eval/roe'"
item "新状态层 API 可达"     bash -c "TOK=\$(python3 -c \"import json;print(json.load(open('$R/config.json'))['auth_token'])\"); PID=\$(curl -s -m 5 -H \"Authorization: Bearer \$TOK\" http://localhost:8787/api/projects | python3 -c \"import json,sys;print(json.load(sys.stdin)[0]['id'])\" 2>/dev/null); for ep in \"projects/\$PID/facts\" \"projects/\$PID/loot\" \"projects/\$PID/subagents\" lessons; do curl -s -m 5 -H \"Authorization: Bearer \$TOK\" http://localhost:8787/api/\$ep >/dev/null || exit 1; done"

echo "== 结论 =="
if [ $FAIL -eq 0 ]; then
  echo "✅ 全部 $PASS 项通过，零 FAIL —— 核查完成"
  exit 0
else
  echo "❌ $FAIL 项失败：${FAILED_ITEMS[*]} —— 修复后重跑"
  exit 1
fi
