#!/usr/bin/env bash
# v4.6 全面核查编排器：引擎测试 + 离线门夹具回归 + 文件层核查 + ROE 自测
set -u
J=/root/jiutouniao
RUN_ID="${1:-manual}"
PASS=0; TOTAL=0
step() { TOTAL=$((TOTAL+1)); if [ "$1" -eq 0 ]; then PASS=$((PASS+1)); echo "[PASS] $2"; else echo "[FAIL] $2"; fi }
echo "=== 全面核查 RUN $RUN_ID @ $(date '+%F %T') ==="
OUT=$(cd $J/server && docker run --rm -v "$J":/repo -w /repo/server jt-gotest:local sh -c "go build ./... && go vet ./internal/... && go test ./... 2>&1" | tail -8)
echo "$OUT" | sed 's/^/    /'
FAILS=$(echo "$OUT" | grep -c "^FAIL" || true)
step $([ "$FAILS" -eq 0 ] && echo 0 || echo 1) "引擎 build+vet+全量单测"
python3 $J/eval/gates/run_all_gates.py --selftest >/tmp/gates_$RUN_ID.log 2>&1
step $? "离线门夹具回归 $(tail -1 /tmp/gates_$RUN_ID.log)"
python3 $J/eval/gates/file_layer_check.py >/tmp/file_$RUN_ID.log 2>&1
step $? "文件层核查 $(grep '文件层核查' /tmp/file_$RUN_ID.log)"
python3 $J/eval/gates/skill_retrieval_gate.py >/tmp/skillret_$RUN_ID.log 2>&1
step $? "技能检索准确率门 $(tail -1 /tmp/skillret_$RUN_ID.log)"
python3 $J/scripts/e2e_loop_check.py --selftest >/tmp/e2e_$RUN_ID.log 2>&1
step $? "端到端闭环门自测 $(tail -1 /tmp/e2e_$RUN_ID.log)"
python3 $J/eval/roe/roe_validate.py $J/eval/roe/roe-profile.example.yaml >/tmp/roe_$RUN_ID.log 2>&1
step $? "ROE Profile 校验 $(tail -1 /tmp/roe_$RUN_ID.log)"
echo "=== 结果: $PASS/$TOTAL ==="
[ "$PASS" -eq "$TOTAL" ]
