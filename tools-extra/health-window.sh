#!/bin/bash
# 健康窗口包裹器（v5.3.9 批次④）：目标抖动（000/连接失败）时不烧探测轮次——
# 健康检查循环等待窗口恢复，恢复后自动执行探针；全部结果带窗口健康标注。
# 用法:
#   health-window.sh --url URL [--tries N] [--interval S] -- <probe-cmd...>
# 参数:
#   --url       健康检查目标（GET，任何 HTTP 响应=健康；000/超时=不健康）
#   --tries     健康检查最大尝试次数（默认 6）
#   --interval  检查间隔秒（默认 60）
#   --          之后为探针命令（原样执行，退出码透传）
# 退出码:
#   0  探针正常结束（透传探针退出码）
#   10 健康检查超限未恢复（探针未执行——调用方按 needs_follow_up 登记）
#   2  参数错误
# 示例:
#   bash tools-extra/health-window.sh --url http://target.example/ --tries 6 --interval 60 \
#        -- curl -sS -m 30 -o evidence/s8-probe.body -w '%{http_code}' 'http://target.example/api/x'
set -u
URL=""; TRIES=6; INTERVAL=60
while [ $# -gt 0 ]; do
  case "$1" in
    --url) URL="$2"; shift 2 ;;
    --tries) TRIES="$2"; shift 2 ;;
    --interval) INTERVAL="$2"; shift 2 ;;
    --) shift; break ;;
    *) echo "[health-window] 未知参数: $1" >&2; exit 2 ;;
  esac
done
[ -n "$URL" ] || { echo "[health-window] 缺少 --url" >&2; exit 2; }
[ $# -gt 0 ] || { echo "[health-window] 缺少探针命令（-- 之后）" >&2; exit 2; }

TS() { date '+%F %T'; }
ok=0
i=1
while [ $i -le "$TRIES" ]; do
  code=$(curl -sS -o /dev/null -w '%{http_code}' -m 15 "$URL" 2>/dev/null)
  if [ -n "$code" ] && [ "$code" != "000" ]; then
    echo "[health-window] $(TS) 窗口恢复（http=$code，第 $i/$TRIES 次检查）——执行探针"
    ok=1
    break
  fi
  echo "[health-window] $(TS) 目标不可达（$code，第 $i/$TRIES 次）——等待 ${INTERVAL}s"
  sleep "$INTERVAL"
  i=$((i+1))
done
if [ $ok -ne 1 ]; then
  echo "[health-window] $(TS) 健康检查超限未恢复（${TRIES} 次）——探针未执行，按 needs_follow_up 登记"
  exit 10
fi
"[health-window] $(TS) 窗口健康，探针启动" >/dev/null # 留痕由调用方重定向采集
"$@"
rc=$?
echo "[health-window] $(TS) 探针结束 exit=$rc（本次执行处于健康窗口内，证据有效）"
exit $rc
