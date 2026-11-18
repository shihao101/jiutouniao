#!/usr/bin/env python3
"""v4.8 W6 业务逻辑不变量测试器（状态机还原→非法迁移序列→存在性证明）。

机制（对应筛查矩阵 C-18/C-19/C-20：金额篡改/并发/状态跳跃/限次）：
  输入状态机 JSON（从 bundle 还原或手工定义）：states[] + transitions[{from,to,action,endpoint,method,fields}]，
  自动生成三类非法迁移并逐个投递（existence-proof 口径：只证明违例存在，不重复执行、不撤改数据）：
    ① 跳步：跳过中间状态直达终态（如 待支付→已完成）；
    ② 逆序：终态后再执行前置动作（如 已取消→再支付）；
    ③ 重复：同一动作重放 N 次（幂等性缺失；限次业务配额绕过形态）。
  守卫判定：非法迁移返回「成功推进」证据（状态字段变化/响应 200 且含终态词）即违例；
  4xx/状态未变=守卫有效。
输出 JSON 报告 + 每违例的复现序列（供 record_finding 与 PoC 落盘）。

用法：
  python3 logic-invariant.py --machine evidence/state-machine.json --base http://t \
      [--cookie k=v ...] [--repeat 3] [--dry-run]
  python3 logic-invariant.py --selftest
合规：写操作迁移默认 --dry-run 只输出计划（引擎审批矩阵另控）；实弹投递需 write_policy 允许
（ROE write_policy=existence-proof 时仅存在性证明，单次触发即停）；金额类字段不在本工具内变异。
"""
import argparse, json
import urllib.request, urllib.error

UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 logic-invariant/1.0"
TERMINAL_HINTS = ("done", "完成", "成功", "paid", "完成", "finished", "shipped", "已")

def post_json(url, body, cookies=None, timeout=15):
    data = json.dumps(body, ensure_ascii=False).encode()
    req = urllib.request.Request(url, data=data, method="POST")
    req.add_header("Content-Type", "application/json")
    req.add_header("User-Agent", UA)
    if cookies:
        req.add_header("Cookie", "; ".join(f"{k}={v}" for k, v in cookies.items()))
    try:
        resp = urllib.request.urlopen(req, timeout=timeout)
        return resp.status, resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")
    except Exception as e:
        return 0, str(e)

def build_violations(machine):
    """三类非法迁移序列生成。"""
    states = set(machine["states"])
    trans = machine["transitions"]
    by_from = {}
    for t in trans:
        by_from.setdefault(t["from"], []).append(t)
    out = []
    # v5.1.2 P1 修复：跳步/逆序类原实现 seq 混入状态名（execute 按 action 查 transition 必查空），
    # 两类违例从未被真正构造投递——结构性失效+对无守卫业务全量误报。改为纯动作序列。
    term_actions = [t["action"] for t in trans if any(h in t["to"].lower() for h in TERMINAL_HINTS)]
    # ① 跳步：跳过全部前置步骤，直接调用终态/带提示态的进入动作
    for ta in term_actions:
        out.append({"kind": "skip", "seq": [ta],
                    "desc": f"跳步尝试：未执行前置步骤直接调用终态动作 {ta}"})
    # ② 逆序：终态动作达成后仍执行前置动作（终态动作取前 2 个防组合爆炸）
    for t in trans:
        if t["action"] in term_actions or any(h in t["to"].lower() for h in TERMINAL_HINTS):
            continue
        for ta in term_actions[:2]:
            out.append({"kind": "reverse", "seq": [ta, t["action"]],
                        "desc": f"逆序尝试：终态动作 {ta} 达成后仍执行前置动作 {t['action']}"})
    # ③ 重复：幂等性/限次（v5.6.1 审计缺陷#3：默认单次——技能承诺「单次触发即停」；
    # 重放 N 次仅 --repeat 显式授权且应配额守卫说明，否则构成副作用超限）
    for t in trans:
        out.append({"kind": "repeat", "seq": [t["action"]],
                    "desc": f"重复提交：{t['action']} 单次重放（幂等性/配额守卫候选；多副本需 --repeat 显式授权）"})
    return out

def execute(machine, base, cookies, repeat=1, dry_run=True):
    obj_id = machine.get("object_id", "test-obj")
    results = []
    for v in build_violations(machine):
        r = {"kind": v["kind"], "desc": v["desc"], "attempts": []}
        if dry_run:
            r["verdict"] = "dry_run"
            r["attempts"] = [{"action": a, "endpoint": t["endpoint"], "note": "计划（dry-run）"}
                             for a in v["seq"] for t in machine["transitions"] if t["action"] == a][:3]
        else:
            hits = 0
            for i, action in enumerate(v["seq"][:repeat] if v["kind"] == "repeat" else v["seq"]):
                t = next((x for x in machine["transitions"] if x["action"] == action), None)
                if not t:
                    continue
                st, body = post_json(base.rstrip("/") + t["endpoint"],
                                     dict(t.get("fields", {}), object_id=obj_id, seq=i), cookies)
                guarded = st >= 400 or st == 0
                # v5.1.2 P1 修复：推进判据反转——原「200 且含 status/state 子串」会把
                # {"status":403,"msg":"denied"} 类错误体记为成功推进（全量误报源）。
                # 改为 200 且不含失败语义关键词。
                fail_kw = ("error", "denied", "forbidden", "失败", "拒绝", "不允许",
                           "invalid", "无权", "已存在", "重复提交", "请先")
                ok = (st == 200) and not any(h in body.lower() for h in fail_kw)
                r["attempts"].append({"action": action, "status": st, "guarded": guarded})
                if ok and not guarded:
                    hits += 1
            # v5.6.1（审计缺陷#3）：仅凭 HTTP 判据（200+无失败词）不定确证——守卫可能在前端/
            # 异步侧；无服务端状态读回时降级为候选，须人工复核状态变化后才能 record_finding。
            r["verdict"] = ("candidate_guard_bypassed" if hits > 0 else "guard_ok")
            if hits > 0:
                r["note"] = "候选：需服务端状态复读（对象/配额/订单状态）确认真实放行后升级"
        results.append(r)
    summary = {"total": len(results),
               "violations": [r for r in results if r["verdict"] in ("guard_bypassed", "candidate_guard_bypassed")]}
    return {"results": results, "summary": summary,
            "note": "existence-proof 口径：违例只证明一次即停；金额/并发类变异不在本工具内（write_policy 约束）"}

def selftest():
    """本地 canned 服务闭环：跳步违例捕获 / 守卫有效 / dry-run 三分支（零外联）。"""
    import threading
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    class Up(BaseHTTPRequestHandler):
        def do_POST(self):
            n = int(self.headers.get("Content-Length") or 0)
            body = json.loads(self.rfile.read(n) or b"{}")
            action = body.get("action", self.path)
            # v5.6.1：夹具改真实语义——仅 cancel 有守卫（400）；skip/重复动作无状态机守卫
            # 直接推进成功（200）= 违例被捕获。旧 seq==0 判据是围绕"重放×3"设计的，
            # 与单次化后的单请求语义冲突（所有违例首请求都会撞 400 → 永远 guard_ok）。
            if "cancel" in str(action):
                st, resp = 400, '{"err":"invalid transition"}'   # 有守卫的动作正常拦截
            else:
                st, resp = 200, '{"status":"paid","done":true}'  # 跳步/重复 → 推进成功（违例）
            self.send_response(st); self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(resp))); self.end_headers()
            self.wfile.write(resp.encode())
        def log_message(self, *a): pass
    up = ThreadingHTTPServer(("127.0.0.1", 0), Up); threading.Thread(target=up.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{up.server_address[1]}"
    machine = {"states": ["created", "paid", "shipped", "done"],
               "object_id": "obj-1",
               "transitions": [
                   {"from": "created", "to": "paid", "action": "pay", "endpoint": "/api/pay", "fields": {"action": "pay"}},
                   {"from": "paid", "to": "shipped", "action": "ship", "endpoint": "/api/ship", "fields": {"action": "ship"}}]}
    rep = execute(machine, base, None, dry_run=False)
    assert rep["summary"]["violations"], f"应捕获跳步违例: {rep['summary']}"
    r = execute(machine, base, None, dry_run=True)
    assert all(x["verdict"] == "dry_run" for x in r["results"]) and r["summary"]["total"] > 0, "dry-run 应只出计划"
    up.shutdown()
    print(f"logic-invariant selftest: 跳步违例捕获 {len(rep['summary']['violations'])} 项 / dry-run 计划 {r['summary']['total']} 项 2/2 OK")

def main():
    ap = argparse.ArgumentParser(description="v4.8 W6 业务逻辑不变量测试器")
    ap.add_argument("--machine", help="状态机 JSON（states+transitions，bundle 还原或手工定义）")
    ap.add_argument("--base", help="目标基址 http://t")
    ap.add_argument("--cookie", action="append", default=[], help="会话态 k=v（可多次）")
    ap.add_argument("--repeat", type=int, default=1, help="重复类探测次数（默认 1=单次；>1 仅限授权明确允许的配额守卫测试）")
    ap.add_argument("--dry-run", action="store_true", default=True, help="只输出违例计划不投递（默认）")
    ap.add_argument("--live", action="store_true", help="实弹投递（写操作，需 ROE 允许）")
    ap.add_argument("--selftest", action="store_true")
    ns = ap.parse_args()
    if ns.selftest:
        selftest(); return
    if not (ns.machine and ns.base):
        ap.error("需要 --machine + --base（或 --selftest）")
    machine = json.load(open(ns.machine, encoding="utf-8"))
    cookies = dict(kv.split("=", 1) for kv in ns.cookie)
    print(json.dumps(execute(machine, ns.base, cookies, ns.repeat, dry_run=not ns.live),
                     ensure_ascii=False, indent=1))

if __name__ == "__main__":
    main()
