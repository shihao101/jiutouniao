#!/usr/bin/env python3
"""v4.8 W5 浏览器农场标准件：profile/UA/时区/Canvas 噪声池化轮换 + CDP 泄露面清洗清单。

机制（对应总案 §四 W5「浏览器农场」）：
  ① 池化组合：按池大小生成 N 组浏览器指纹组合（profile 目录 + UA + 时区 + locale +
     Canvas 噪声种子 + WebGL vendor 混淆选择），--next 轮换输出；
  ② CDP 启动参数：输出 Chromium/CDP 就绪参数（--user-data-dir/--lang/--tz 注入建议与
     evaluateOnNewDocument 注入脚本：Canvas 噪声/WebGL vendor/时区/navigator 语言）；
  ③ 泄露面清洗清单：CDP 环境常见泄露项逐项核对（WebGL renderer/字体枚举/性能时间差/
     CDP Runtime.enable 痕迹）——输出核对清单供 S5/S6 会话建立时自查；
  ④ 挑战态池化衔接：每组合配独立快照分片目录（evidence/farm-profile-<i>/），与
     channel-snapshot/exit-pool 会话分片约定一致。
用法：
  python3 browser-farm.py --size 3 --next
  python3 browser-farm.py --size 3 --all
  python3 browser-farm.py --selftest
合规：指纹轮换用于对抗环境会话管理（合规授权测试内）；不用于规避侦查或真实身份伪装。
"""
import argparse, json, os

UA_TEMPLATE = "Mozilla/5.0 ({platform}) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{ver}.0.0.0 Safari/537.36"
PLATFORMS = ["X11; Linux x86_64", "Windows NT 10.0; Win64; x64", "Macintosh; Intel Mac OS X 10_15_7"]
TIMEZONES = ["Asia/Shanghai", "Asia/Shanghai", "Asia/Shanghai"]  # 时区池默认与目标地区一致（避免时区矛盾指纹）
WEBGL_VENDORS = [("Intel Inc.", "Intel Iris OpenGL Engine"),
                 ("Google Inc. (NVIDIA)", "ANGLE (NVIDIA, NVIDIA GeForce Direct3D)"),
                 ("Google Inc. (AMD)", "ANGLE (AMD, AMD Radeon Direct3D)")]

def build_pool(size):
    """生成 size 组指纹组合（确定性轮换，参数空间组合均匀覆盖）。"""
    pool = []
    for i in range(max(size, 1)):
        plat = PLATFORMS[i % len(PLATFORMS)]
        ver = 120 + (i % 8) * 2
        vendor, renderer = WEBGL_VENDORS[i % len(WEBGL_VENDORS)]
        pool.append({
            "name": f"profile-{i}",
            "user_agent": UA_TEMPLATE.format(platform=plat, ver=ver),
            "timezone": TIMEZONES[i % len(TIMEZONES)],
            "locale": "zh-CN",
            "canvas_noise_seed": 1000 + i * 7,
            "webgl_vendor": vendor,
            "webgl_renderer": renderer,
            "profile_dir": f"/tmp/jt-farm/profile-{i}",
            "snapshot_shard": f"evidence/farm-profile-{i}",
        })
    return pool

INJECT_SCRIPT = """
// v4.8 W5 浏览器农场指纹注入（evaluateOnNewDocument）
(() => {
  const seed = __SEED__;
  const noise = (ctx) => { // Canvas 像素级噪声（种子确定性，跨会话稳定）
    const orig = ctx.getImageData.bind(ctx);
    ctx.getImageData = (...a) => { const d = orig(...a); for (let i = 0; i < d.data.length; i += 997) d.data[i] ^= (seed + i) % 7; return d; };
  };
  HTMLCanvasElement.prototype.getContext = new Proxy(HTMLCanvasElement.prototype.getContext, {
    apply: (t, c, a) => { const r = Reflect.apply(t, c, a); if (r && r.getImageData) noise(r); return r; }});
  Object.defineProperty(navigator, 'webdriver', {get: () => undefined});       // CDP 泄露面①
  Object.defineProperty(navigator, 'languages', {get: () => ['zh-CN', 'zh']});  // ②语言一致性
})();
"""

def launch_args(p):
    """CDP/Chromium 启动参数组合 + 注入脚本。"""
    return {"args": [f"--user-data-dir={p['profile_dir']}", f"--lang={p['locale']}",
                     "--disable-blink-features=AutomationControlled",
                     "--no-first-run", "--no-default-browser-check"],
            "timezone": p["timezone"],
            "evaluate_on_new_document": INJECT_SCRIPT.replace("__SEED__", str(p["canvas_noise_seed"])),
            "webgl_override": {"vendor": p["webgl_vendor"], "renderer": p["webgl_renderer"]}}

LEAK_CHECKLIST = [
    "navigator.webdriver 必须 undefined（CDP Runtime 泄露面①）",
    "WebGL vendor/renderer 与声明平台一致（Linux 声明 + Windows renderer = 秒穿）",
    "Canvas/ImageData 噪声跨会话稳定（同 profile 同种子；漂移=指纹自矛盾）",
    "时区/locale/Accept-Language 三者一致（Asia/Shanghai + en-US = 矛盾指纹）",
    "字体枚举面：Chromium 默认字体集与声明平台匹配（Windows 平台声明勿出现 mac 专属字体）",
    "性能时间差：CDP 注入脚本勿在关键路径产生 >5ms 可测延迟（Navigation Timing 自查）",
    "channel-snapshot 快照写对应 profile 分片目录（farm-profile-<i>），跨 profile 不混用挑战态",
]

def selftest():
    pool = build_pool(3)
    assert len(pool) == 3 and pool[0]["user_agent"] != pool[1]["user_agent"], "组合多样性"
    a = launch_args(pool[0])
    assert "--user-data-dir=/tmp/jt-farm/profile-0" in a["args"], "CDP 参数"
    assert "__SEED__" not in a["evaluate_on_new_document"], "种子注入"
    assert "webdriver" in a["evaluate_on_new_document"], "泄露面①覆盖"
    assert len(LEAK_CHECKLIST) == 7 and all(isinstance(x, str) for x in LEAK_CHECKLIST), "清洗清单"
    print("browser-farm selftest: 池化组合/CDP参数/注入脚本/清洗清单 4/4 OK")

def main():
    ap = argparse.ArgumentParser(description="v4.8 W5 浏览器农场标准件（指纹池化轮换）")
    ap.add_argument("--size", type=int, default=3, help="池大小（默认 3）")
    ap.add_argument("--next", action="store_true", help="轮换输出下一组合（含 CDP 启动参数与泄露面清洗清单）")
    ap.add_argument("--all", action="store_true", help="输出全池")
    ap.add_argument("--selftest", action="store_true")
    ns = ap.parse_args()
    if ns.selftest:
        selftest(); return
    pool = build_pool(ns.size)
    cur_path = "/tmp/jt-farm/farm-cursor.json"
    os.makedirs("/tmp/jt-farm", exist_ok=True)
    if ns.all:
        for p in pool:
            print(json.dumps({**p, "launch": launch_args(p), "leak_checklist": LEAK_CHECKLIST},
                             ensure_ascii=False, indent=1))
        return
    if ns.next:
        idx = 0
        if os.path.isfile(cur_path):
            idx = json.load(open(cur_path)).get("idx", 0)
        json.dump({"idx": idx + 1}, open(cur_path, "w"))
        p = pool[idx % len(pool)]
        print(json.dumps({**p, "launch": launch_args(p), "leak_checklist": LEAK_CHECKLIST},
                         ensure_ascii=False, indent=1))
        return
    ap.error("选择 --next / --all（或 --selftest）")

if __name__ == "__main__":
    main()
