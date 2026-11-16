#!/usr/bin/env python3
"""v4.8 W5 出口池标准件：多出口 IP 轮换 + WAF 会话状态按出口分片 + 健康检查降级。

机制（对应总案 §四 W5「单出口降级即全链瘫痪」缺口）：
  ① 出口清单：JSON 配置（exits[]：{name, kind: mock|http|socks5, endpoint}）——
     kind=mock 为离线演示/回归通道；真实住宅代理/机房代理为外部资源决策（配置即接），
     本标准件不含任何代理资源（零硬编码端点）；
  ② 轮换接口：--next 按序轮换输出当前出口（name/kind/endpoint）+ 该出口的会话分片目录约定
     （evidence/exit-<name>/——channel-snapshot 快照按出口分片，WAF 会话态不跨出口混用）；
  ③ 健康检查：--health 对每出口做 1 次探活（mock 恒通；代理做无目标外联的自检——
     只验证本地协议握手参数合法性，不做对目标的连通验证，目标连通由 agent probe 承担）；
  ④ 降级：探活失败出口标记 degraded 并在 --next 跳过；全降级时返回显式错误（不静默回退单出口）。

用法：
  python3 exit-pool.py --config exits.json --next [--state-dir evidence]
  python3 exit-pool.py --config exits.json --health
  python3 exit-pool.py --selftest
合规：出口池只做通道管理；对目标流量仍受 ROE/限速纪律约束（行为预算器引擎级生效）。
"""
import argparse, json, os, sys, time

EXIT_ORDER = []  # 轮换游标存文件（跨进程持久）：state_dir/exit-cursor.json

def load_config(path):
    cfg = json.load(open(path, encoding="utf-8"))
    exits = cfg.get("exits") or []
    if not exits:
        raise SystemExit("错误: 配置无 exits[]——格式 {\"exits\":[{\"name\":\"e1\",\"kind\":\"mock\",\"endpoint\":\"\"}]}")
    for e in exits:
        if not e.get("name"):
            raise SystemExit("错误: 每个 exit 必须有 name")
        e.setdefault("kind", "http")
        if e["kind"] not in ("mock", "http", "socks5"):
            raise SystemExit(f"错误: 未知出口类型 {e['kind']}（mock/http/socks5）")
    return exits

def shard_dir(state_dir, name):
    """出口会话分片目录约定：WAF 会话状态按出口分片，跨出口混用=挑战态污染。"""
    d = os.path.join(state_dir, f"exit-{name}")
    os.makedirs(d, exist_ok=True)
    return d

def probe_exit(e):
    """探活：mock 恒通；http/socks5 做本地参数自检（不做对目标外联）。"""
    if e["kind"] == "mock":
        return True, "mock"
    endpoint = e.get("endpoint") or ""
    if e["kind"] == "http" and not endpoint.startswith(("http://", "https://")):
        return False, "http 出口 endpoint 需 http(s):// 前缀"
    if e["kind"] == "socks5" and not endpoint:
        return False, "socks5 出口缺 endpoint"
    return True, "参数自检通过（目标连通性由 agent probe 承担）"

def next_exit(exits, state_dir):
    cur_path = os.path.join(state_dir, "exit-cursor.json")
    degraded_path = os.path.join(state_dir, "exit-degraded.json")
    degraded = {}
    if os.path.isfile(degraded_path):
        degraded = json.load(open(degraded_path, encoding="utf-8"))
    idx = 0
    if os.path.isfile(cur_path):
        idx = json.load(open(cur_path, encoding="utf-8")).get("idx", 0)
    for _ in range(len(exits)):
        e = exits[idx % len(exits)]
        idx += 1
        if degraded.get(e["name"]) and time.time() - degraded[e["name"]] < 300:
            continue  # 5 分钟内降级的出口跳过
        json.dump({"idx": idx}, open(cur_path, "w"))
        return e
    raise SystemExit("错误: 全部出口处于降级态——不静默回退单出口；等待降级过期或修复出口后重试（显式错误，防单出口静默接管）")

def mark_degraded(exits, state_dir, name):
    degraded_path = os.path.join(state_dir, "exit-degraded.json")
    degraded = {}
    if os.path.isfile(degraded_path):
        degraded = json.load(open(degraded_path, encoding="utf-8"))
    degraded[name] = time.time()
    json.dump(degraded, open(degraded_path, "w"))
    print(f"出口 {name} 已标记降级（5 分钟内 --next 跳过）；其余出口: {', '.join(e['name'] for e in exits if e['name'] != name)}")

def health(exits):
    rows = []
    for e in exits:
        ok, note = probe_exit(e)
        rows.append((e["name"], e["kind"], ok, note))
    return rows

def selftest():
    """离线闭环：配置校验/轮换游标/降级跳过/全降级显式错误 四分支（零外联）。"""
    import tempfile
    d = tempfile.mkdtemp()
    cfgp = os.path.join(d, "exits.json")
    json.dump({"exits": [{"name": "a", "kind": "mock"}, {"name": "b", "kind": "mock"}, {"name": "c", "kind": "mock"}]},
              open(cfgp, "w"))
    exits = load_config(cfgp)
    assert len(exits) == 3, "配置加载"
    n1 = next_exit(exits, d); n2 = next_exit(exits, d); n3 = next_exit(exits, d); n4 = next_exit(exits, d)
    assert [n1["name"], n2["name"], n3["name"], n4["name"]] == ["a", "b", "c", "a"], "轮换顺序"
    sd = shard_dir(d, "a"); assert os.path.isdir(sd), "分片目录"
    mark_degraded(exits, d, "b")
    names = [next_exit(exits, d)["name"] for _ in range(3)]
    assert "b" not in names, "降级跳过"
    json.dump({e["name"]: time.time() for e in exits}, open(os.path.join(d, "exit-degraded.json"), "w"))
    try:
        next_exit(exits, d); assert False, "全降级应显式错误"
    except SystemExit:
        pass
    print("exit-pool selftest: 配置/轮换/分片/降级跳过/全降级显式错误 5/5 OK")

def main():
    ap = argparse.ArgumentParser(description="v4.8 W5 出口池标准件（多出口轮换+会话分片+降级）")
    ap.add_argument("--config", help="出口配置 JSON（资源决策外部化：真实代理端点写这里）")
    ap.add_argument("--next", action="store_true", help="轮换输出下一可用出口")
    ap.add_argument("--health", action="store_true", help="全部出口探活")
    ap.add_argument("--degrade", help="标记指定出口降级（通道失效时调用）")
    ap.add_argument("--state-dir", default="evidence", help="游标/降级状态与会话分片根目录")
    ap.add_argument("--selftest", action="store_true")
    ns = ap.parse_args()
    if ns.selftest:
        selftest(); return
    if not ns.config:
        ap.error("需要 --config（或 --selftest）")
    exits = load_config(ns.config)
    os.makedirs(ns.state_dir, exist_ok=True)
    if ns.health:
        for name, kind, ok, note in health(exits):
            print(f"[{'OK ' if ok else 'DEG'}] {name} ({kind}): {note}")
        return
    if ns.degrade:
        mark_degraded(exits, ns.state_dir, ns.degrade); return
    if ns.next:
        e = next_exit(exits, ns.state_dir)
        sd = shard_dir(ns.state_dir, e["name"])
        print(json.dumps({"exit": e["name"], "kind": e["kind"], "endpoint": e.get("endpoint", ""),
                          "session_shard": sd,
                          "note": "WAF 会话状态按出口分片：channel-snapshot 快照写 session_shard 目录，跨出口不混用；出口失效用 --degrade 标记"},
                         ensure_ascii=False, indent=1))
        return
    ap.error("选择 --next / --health / --degrade（或 --selftest）")

if __name__ == "__main__":
    main()
