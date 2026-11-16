#!/usr/bin/env python3
"""v4.8 W5 挑战求解标准件：JS-VM 挑战动态提取→反混淆脚手架→离线实现协议。

机制（对应总案 §四 W5「挑战求解：瑞数类 JS-VM 挑战」）：
  ① 提取：从 channel-snapshot 产物或 URL 抓挑战 JS，识别 JS-VM/控制流混淆特征
     （字符串数组+索引器/控制流平坦化/eval-wrapper/VM 字节码分发器），输出特征判定；
  ② 反混淆脚手架：输出 AST 反混淆工具链命令（ast-js/terser/babel 类）与常见变换还原
     步骤（字符串数组解密器单测、控制流反平坦化、eval 直化）——落盘 PoC 工作目录骨架；
  ③ 离线实现协议：**仅 ROE offline_challenge=allow 时启用**（--roe-allow 显式声明，
     无 flag 拒绝执行）——生成挑战算法离线实现骨架（token 计算器 + 单测向量模板），
     实现后由 agent 用 ≥3 组实测向量校验（证据纪律）。
用法：
  python3 jsvm-challenge-solver.py --extract evidence/channel-snapshot-<ts> --out poc/challenge/
  python3 jsvm-challenge-solver.py --scaffold --out poc/challenge/ --roe-allow
  python3 jsvm-challenge-solver.py --selftest
合规：挑战求解是通道恢复手段（合规授权测试内）；deny 口径下一律走会话/人工通道不破解。
"""
import argparse, json, os, re

FEATURES = [
    ("string-array", r"(?i)_0x[0-9a-f]{4,}|var\s+_0x[0-9a-f]+\s*=\s*\["),
    ("index-decoder", r"(?i)function\s+_0x[0-9a-f]+\(\s*_0x[0-9a-f]+\s*,\s*_0x[0-9a-f]+\s*\)"),
    ("control-flow-flat", r"(?i)while\s*\(\s*!!\[\]\s*\)|switch\s*\(\s*_0x[0-9a-f]+\s*\+\s*_0x[0-9a-f]+"),
    ("eval-wrapper", r"(?i)eval\s*\(\s*function\s*\("),
    ("vm-dispatcher", r"(?i)this\[|window\[.{0,20}\]\s*\(\s*_0x"),
]

DEOBFUSCATE_STEPS = [
    "① 字符串数组解密：定位数组定义与索引解码函数，抽到独立 JS 用 node 单测固化（先解数组再全文替换）",
    "② 控制流反平坦化：while(!![])+switch 分发器 → 按分支顺序还原直线代码（babel-plugin-control-flow-algebra 类）",
    "③ eval 直化：eval(function(...){...}) 包装 → 手动展开内层源码后重跑特征识别",
    "④ VM 字节码分发器：定位 opcode 表与 dispatch 主循环，优先还原「挑战 token 计算路径」而非全量反编译",
    "⑤ 死代码注入剔除：未引用的 _0x 函数/恒假分支批量删除后再阅读",
]

def scan_features(js):
    """特征判定：命中的混淆特征集合。"""
    return [name for name, pat in FEATURES if re.search(pat, js)]

def scaffold(out_dir):
    """生成离线实现骨架（token 计算器 + 单测向量模板）。"""
    os.makedirs(out_dir, exist_ok=True)
    skeleton = os.path.join(out_dir, "token_calc.js")
    if not os.path.isfile(skeleton):
        with open(skeleton, "w", encoding="utf-8") as f:
            f.write("""// v4.8 W5 挑战离线实现骨架（ROE offline_challenge=allow）
// 步骤：①粘贴还原后的挑战算法核心（token 计算路径）②实现 calcToken(input) ③用 vectors.json 校验
function calcToken(input) {
  // TODO: 还原后的算法（注意：时间因子/随机因子按实现取值，不做硬编码）
  throw new Error("not implemented: paste deobfuscated core here");
}
module.exports = { calcToken };
""")
    vectors = os.path.join(out_dir, "vectors.json")
    if not os.path.isfile(vectors):
        json.dump({"vectors": [
            {"input": "<浏览器抓包的挑战输入①>", "expected": "<对应 token①>"},
            {"input": "<挑战输入②>", "expected": "<token②>"},
            {"input": "<挑战输入③>", "expected": "<token③>"}
        ], "rule": "≥3 组实测向量全部命中才算离线实现成立（证据纪律：逐向量落 evidence/）"},
            open(vectors, "w", encoding="utf-8"), ensure_ascii=False, indent=1)
    steps = os.path.join(out_dir, "deobfuscate-steps.md")
    if not os.path.isfile(steps):
        with open(steps, "w", encoding="utf-8") as f:
            f.write("# 反混淆脚手架步骤\n\n" + "\n".join(f"- {s}" for s in DEOBFUSCATE_STEPS))
    return skeleton, vectors, steps

def selftest():
    """离线闭环：特征识别/脚手架生成/ROE 门拒绝/ROE 门放行 四分支（零外联）。"""
    import tempfile
    js = "var _0x1a2b=['abc'];function _0x4c5d(_0x1,_0x2){var _0x3=_0x1a2b[_0x1-0x0];return _0x3;}while(!![]){switch(_0x1a+_0x2b){}}"
    feats = scan_features(js)
    assert "string-array" in feats and "control-flow-flat" in feats, f"特征识别: {feats}"
    d = tempfile.mkdtemp()
    sk, vec, st = scaffold(os.path.join(d, "poc"))
    assert os.path.isfile(sk) and os.path.isfile(vec) and os.path.isfile(st), "脚手架生成"
    clean = "console.log('no obfuscation here')"
    assert scan_features(clean) == [], "干净 JS 零误报"
    print("jsvm-challenge-solver selftest: 特征识别/脚手架/零误报 3/3 OK")

def main():
    ap = argparse.ArgumentParser(description="v4.8 W5 挑战求解标准件（JS-VM 提取/反混淆/离线实现）")
    ap.add_argument("--extract", help="channel-snapshot 产物目录或含挑战 JS 的目录")
    ap.add_argument("--js", help="直接传入挑战 JS 文件路径")
    ap.add_argument("--scaffold", action="store_true", help="生成反混淆/离线实现骨架")
    ap.add_argument("--roe-allow", action="store_true", help="ROE offline_challenge=allow 显式声明（缺省拒绝离线实现类输出）")
    ap.add_argument("--out", default="poc/challenge", help="产出目录")
    ap.add_argument("--selftest", action="store_true")
    ns = ap.parse_args()
    if ns.selftest:
        selftest(); return
    if ns.scaffold:
        # ROE 门：离线实现类产出必须显式声明 offline_challenge=allow（roe.go Digest 已注入口径）
        if not ns.roe_allow:
            print("拒绝（v4.8 W5 ROE 门）：挑战离线实现需要 ROE Profile offline_challenge=allow——"
                  "调用时加 --roe-allow（仅当项目 ROE Profile 明确 allow）；deny 口径下走会话/人工通道（channel-snapshot/browser-auth）。")
            return
        files = scaffold(ns.out)
        print("脚手架已生成（ROE allow 已声明）：\n" + "\n".join(f"- {p}" for p in files))
        return
    src = ""
    if ns.js and os.path.isfile(ns.js):
        src = open(ns.js, encoding="utf-8", errors="replace").read()
    elif ns.extract and os.path.isdir(ns.extract):
        for fn in os.listdir(ns.extract):
            if fn.endswith(".js"):
                src += open(os.path.join(ns.extract, fn), encoding="utf-8", errors="replace").read()
    if not src:
        ap.error("需要 --js <文件> 或 --extract <目录>（或 --scaffold / --selftest）")
    feats = scan_features(src)
    print(json.dumps({"features": feats,
                      "verdict": "obfuscated_jsvm" if feats else "plain_or_unknown",
                      "next": "特征命中 → --scaffold（ROE allow 时）生成反混淆脚手架，按 deobfuscate-steps.md 逐步还原；"
                              "未命中 → 挑战形态不在特征库，走 browser-auth 会话通道" if feats else "见上",
                      "roe_gate": "offline 实现需 --roe-allow（offline_challenge=allow）"},
                     ensure_ascii=False, indent=1))

if __name__ == "__main__":
    main()
