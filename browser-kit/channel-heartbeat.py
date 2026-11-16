#!/usr/bin/env python3
"""v4.6 K5 完整心跳（通道状态机标准件）：空闲窗口期由 run_async 调度，周期性 dump-dom 基线
自检并落盘 channel-status.json（字节判定：≥100KB=healthy / <100B=degraded / 超时=down_candidate，
连续 2 次 down → down）。S5/S6 开工读本文件即知通道状态，不沿用上一阶段结论。
用法：channel-heartbeat.py --url https://t/pages/home --out evidence/channel-status.json
      [--interval 600] [--times 12] [--profile /tmp/hb-profile]
selftest：纯状态机转换测试（无网络）。"""
import argparse, json, subprocess, sys, time, os

def classify(total_bytes, timeout):
    if timeout:
        return "down_candidate"
    if total_bytes >= 100 * 1024:
        return "healthy"
    if total_bytes <= 100:
        return "degraded"
    return "partial"

def next_state(prev, cur, down_streak):
    if cur == "down_candidate":
        down_streak += 1
        return ("down" if down_streak >= 2 else "down_candidate"), down_streak
    down_streak = 0
    if cur == "healthy":
        return "healthy", down_streak
    # degraded/partial：连续两次 degraded → down_candidate
    if prev in ("degraded", "down_candidate") and cur == "degraded":
        return "down_candidate", 1
    return cur, down_streak

def measure(url, profile):
    d = f"/tmp/hb-{abs(hash(url))%10000}"
    os.makedirs(d, exist_ok=True)
    try:
        r = subprocess.run(["timeout", "90", "chromium", "--headless=new", "--no-sandbox",
                            "--disable-gpu", f"--user-data-dir={d}",
                            "--virtual-time-budget=15000", "--dump-dom", url],
                           capture_output=True, timeout=100)
        return len(r.stdout), False
    except subprocess.TimeoutExpired:
        return 0, True

def selftest():
    cases = [
        (None, 200000, False, "healthy"),
        (None, 0, True, "down_candidate"),
        (None, 50, False, "degraded"),
        (None, 5000, False, "partial"),
    ]
    bad = 0
    st, streak = "healthy", 0
    for _, b, to, want in cases:
        got = classify(b, to)
        st, streak = next_state(st, got, streak)
        if got != want:
            print(f"FAIL classify {b}/{to}: want {want} got {got}"); bad += 1
        else:
            print(f"PASS classify {b}B/{to} → {got}（状态机→{st}）")
    # 连续 down_candidate ×2 → down
    st, streak = next_state("down_candidate", "down_candidate", 1)
    if st != "down":
        print("FAIL 连续两次 down_candidate 应升级 down"); bad += 1
    else:
        print("PASS 连续两次 down_candidate → down")
    print(f"状态机自测: {5-bad}/5")
    return bad == 0

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--url"); ap.add_argument("--out", default="evidence/channel-status.json")
    ap.add_argument("--interval", type=int, default=600)
    ap.add_argument("--times", type=int, default=12)
    ap.add_argument("--profile", default="/tmp/hb-profile")
    ap.add_argument("--selftest", action="store_true")
    ns = ap.parse_args()
    if ns.selftest:
        sys.exit(0 if selftest() else 1)
    if not ns.url:
        ap.error("需要 --url 或 --selftest")
    st, streak = "unknown", 0
    for i in range(ns.times):
        b, to = measure(ns.url, ns.profile)
        cur = classify(b, to)
        st, streak = next_state(st, cur, streak)
        rec = {"ts": time.strftime("%Y-%m-%dT%H:%M:%S%z"), "bytes": b, "timeout": to,
               "round": i + 1, "classify": cur, "state": st}
        os.makedirs(os.path.dirname(ns.out) or ".", exist_ok=True)
        with open(ns.out, "w", encoding="utf-8") as f:
            json.dump(rec, f, ensure_ascii=False, indent=1)
        print(json.dumps(rec, ensure_ascii=False), flush=True)
        if st == "down":
            break
        time.sleep(ns.interval)
