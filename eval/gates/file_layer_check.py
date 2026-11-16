# -*- coding: utf-8 -*-
"""v4.6 文件层核查器：技能/路由/提示词补丁/ROE/快照脚本 逐项核验。退出码 0=全过。"""
import os, re, subprocess, sys, glob, py_compile, json

ROOT = "/root/jiutouniao"

def _load_sweep_tokens():
    """v4.8.1：零靶场 token 词表外置（与 pack/sweep 同源机制）——包内核查器不携带历史靶场字面量。
    加载顺序：JTN_SWEEP_PATTERNS → 项目同级 jtn-private/sweep-target-patterns.json 的 filelayer 键；
    外部文件缺失时回退通用占位（新机无历史，无 tripwire 属预期）。"""
    path = os.environ.get("JTN_SWEEP_PATTERNS",
                          "/root/jtn-private/sweep-target-patterns.json")
    try:
        return [str(t) for t in json.load(open(path, encoding="utf-8")).get("filelayer", [])]
    except Exception:
        return []
SKILLS = ["channel-snapshot", "js-challenge-waf-playbook", "rate-limit-playbook",
          "closed-site-playbook", "gateway-filter-playbook", "appliance-mgmt-playbook",
          "intel-factory", "crypto-offensive", "authz-diff", "hypothesis-matrix"]
CHECKS = []

def check(name, ok, detail=""):
    CHECKS.append((name, ok, detail))

# ① 技能文件与 frontmatter
for sid in SKILLS:
    fp = os.path.join(ROOT, "skills", sid + ".md")
    if not os.path.isfile(fp):
        check(f"技能 {sid}.md 存在", False); continue
    head = open(fp, encoding="utf-8").read(400)
    m = re.search(r'---\nid:\s*"(.*?)"\ntitle:\s*(.*?)\ntags:\s*(.*?)\n---', head, re.S)
    check(f"技能 {sid}.md frontmatter", bool(m and m.group(1) == sid),
          "" if m else "缺 id/title/tags 头")

# ② 路由器索引含全部新技能
router = open(os.path.join(ROOT, "skills", "00-router.md"), encoding="utf-8").read()
for sid in SKILLS:
    check(f"路由器含 {sid}", sid in router)

# ③ 快照脚本可编译
try:
    py_compile.compile(os.path.join(ROOT, "browser-kit", "channel-snapshot.py"), doraise=True)
    check("channel-snapshot.py 可编译", True)
except Exception as e:
    check("channel-snapshot.py 可编译", False, str(e))

# ④ loop-core v4.6 纪律七条
lc = open(os.path.join(ROOT, "prompts", "loop-core.md"), encoding="utf-8").read()
check("loop-core 含 v4.6 纪律节", "v4.6 执行可靠性纪律" in lc)
for kw in ["claims", "observed_result", "ready_but_unexecuted", "channel-snapshot.py",
           "behavior_class", "command_idle", "update_finding"]:
    check(f"loop-core 含 {kw}", kw in lc)

# ⑤ 阶段头增补
for h, kws in {
    "s1": ["behavior_class"], "s4": ["ready_but_unexecuted", "破解即终点"],
    "s5": ["channel-snapshot", "就绪度优先"], "s7": ["JT-JOB-END", "三选一"],
    "s8": ["三方对账" if False else "双栏呈现", "1:1"],
}.items():
    body = open(os.path.join(ROOT, "heads", h + ".md"), encoding="utf-8").read()
    for kw in kws:
        check(f"heads/{h}.md 含 {kw}", kw in body)

# ⑤b 新工具 selftest（authz-diff 判读/子域接管指纹）
for tool in ["authz-diff.py", "subdomain-takeover.py"]:
    r2 = subprocess.run([sys.executable, os.path.join(ROOT, "tools-extra", tool), "--selftest"],
                        capture_output=True, text=True)
    check(f"{tool} selftest", r2.returncode == 0, (r2.stdout or r2.stderr).strip()[-60:])

# ⑤b2 v4.7 新工具 selftest
for tool in ["captcha-ocr.py", "primitive-graph.py"]:
    r2 = subprocess.run([sys.executable, os.path.join(ROOT, "tools-extra", tool), "--selftest"],
                        capture_output=True, text=True)
    last = [l for l in (r2.stdout or "").splitlines() if l.strip()][-1:]
    check(f"{tool} selftest", r2.returncode == 0, (last[0] if last else r2.stderr[-60:]).strip())
r2 = subprocess.run([sys.executable, os.path.join(ROOT, "browser-kit/channel-heartbeat.py"), "--selftest"],
                    capture_output=True, text=True)
check("channel-heartbeat.py 状态机 selftest", r2.returncode == 0, (r2.stdout or "").strip()[-60:])

# ⑤c 对抗 mock 冒烟（v4.8：15 场景——限速5+JS挑战3+gateway6+OAuth组）
# v5.3.1 去抖：mock 服务端口/时序敏感（实测全局核查第 3 轮 13/15 抖动）——最多 3 次尝试，任一成功即过；
# 原 8/8 检查与 15 场景冒烟共用同一返回码（if False 死代码已清理），改为同一判定的遗留名引用。
_pack = os.environ.get("JTN_EVALPACK_PATH", "/root/jtn-evalpack")
import time as _time
if os.path.isdir(os.path.join(_pack, "mocks")):
    sm_ok, sm_detail = False, ""
    for _attempt in range(1, 4):
        r3 = subprocess.run([sys.executable, os.path.join(_pack, "mocks", "smoke_test.py")],
                            capture_output=True, text=True, timeout=300)
        last = [l for l in (r3.stdout or "").splitlines() if "冒烟测试" in l]
        sm_detail = (last[0].strip() if last else (r3.stderr or "")[-100:])
        if r3.returncode == 0 and "15/15" in sm_detail:
            sm_ok = True
            break
        _time.sleep(3)
    check("对抗 mock 冒烟 15/15（≤3 次尝试去抖）", sm_ok, sm_detail)
    check("对抗 mock 冒烟 8/8（遗留名，同一判定）", sm_ok, sm_detail)
else:
    check("对抗 mock 冒烟（评测包未挂载，跳过）", True, "JTN_EVALPACK_PATH 未指向有效包")
    check("对抗 mock 冒烟 8/8（遗留名，同一判定）", True, "评测包未挂载，跳过")

# ⑤d 版本↔更新记录对齐（单一事实源：version.go App == Changelog 首条 v；web 构建产物含版本串）
import importlib.util as _iu
_vspec = _iu.spec_from_file_location("jtv", os.path.join(ROOT, "server", "internal", "version", "version.go"))
app = ""
mm = re.search(r'App\s*=\s*"(\d+\.\d+\.\d+)"', open(os.path.join(ROOT, "server/internal/version/version.go"), encoding="utf-8").read())
if mm:
    app = mm.group(1)
check("version.go App 常量存在", bool(app))
chlog = open(os.path.join(ROOT, "web-app/src/pages/ChangelogPage.vue"), encoding="utf-8").read()
first_v = re.search(r"\{ v: 'v([0-9.]+)'", chlog)
check("更新记录首条版本 == version.App", bool(first_v and first_v.group(1) == app), f"App={app} first={first_v.group(1) if first_v else '?'}")
web_hit = False
for a in glob.glob(os.path.join(ROOT, "web", "assets", "*Changelog*.js")):
    if f"v{app}" in open(a, encoding="utf-8", errors="replace").read():
        web_hit = True
check("web 构建产物含更新记录版本串", web_hit)

# ⑤d2 镜像 COPY 路径存在性（防部署链假绿——本轮 eval_run.py 路径写错致构建失败仍报 OK）
for m2 in re.finditer(r'^COPY\s+(\S+)\s+(\S+)\s*$', open(os.path.join(ROOT, "Dockerfile"), encoding="utf-8").read(), re.M):
    src, dst = m2.group(1), m2.group(2)
    if src.startswith(("http", "$")):
        continue
    srcp = os.path.join(ROOT, src)
    if not os.path.exists(srcp):
        check(f"镜像 COPY 源存在: {src}", False, "构建上下文中不存在——Dockerfile 与仓库漂移")
        continue
    # 目录 COPY：至少含一个文件；文件 COPY：存在即可
    if os.path.isdir(srcp):
        has = any(files for _, _, files in os.walk(srcp))
        check(f"镜像 COPY 源非空: {src}", has)

# ⑤e 部署范围零靶场信息（v4.7.1 绝对口径）：镜像 COPY 清单内文件 grep 埋点/靶标词
SWEEP_TOKENS = _load_sweep_tokens()
if not SWEEP_TOKENS:
    check("零靶场 token 词表（外置加载）", True, "外部词表缺失，跳过 token 类检查（新机口径）")
for tok in SWEEP_TOKENS:
    hits = []
    for fp in ["Dockerfile", "README.md", "scripts/eval_run.py", "scripts/sweep-sensitive.py"]:
        try:
            if tok in open(os.path.join(ROOT, fp), encoding="utf-8").read():
                hits.append(fp)
        except Exception:
            pass
    check(f"部署范围零靶场 token[{tok}]", not hits, f"命中: {hits}" if hits else "")
# ⑤e2 v4.8 部署核验扩围（部署核验曾捕获：K2 卡通用术语撞历史 token / 历史更新记录残留靶场端点细节
# ——核验口径从 COPY 清单扩到进镜像的提示词面与 web 产物源码）
for tok in SWEEP_TOKENS:
    hits = []
    for fp in (glob.glob(os.path.join(ROOT, "skills", "*.md")) +
               glob.glob(os.path.join(ROOT, "heads", "*.md")) +
               [os.path.join(ROOT, "prompts", "loop-core.md"),
                os.path.join(ROOT, "web-app/src/pages/ChangelogPage.vue")]):
        try:
            if tok in open(fp, encoding="utf-8").read():
                hits.append(os.path.relpath(fp, ROOT))
        except Exception:
            pass
    check(f"部署范围零靶场 token 扩围[{tok}]", not hits, f"命中: {hits}" if hits else "")
# 判分器加载契约检查：允许引用外部包（EVAL_PACK/JTN_EVALPACK_PATH），禁止包内路径硬编码
er = open(os.path.join(ROOT, "scripts/eval_run.py"), encoding="utf-8").read()
check("判分器无靶场包内路径硬编码", "/app/eval/target" not in er)
check("判分器使用外部包加载契约", "EVAL_PACK" in er)

# pack.py 的 EXCLUDE_PATHS 防护声明（明确排除靶场路径）属合规配置
try:
    pk = open(os.path.join(ROOT, "scripts/pack.py"), encoding="utf-8").read()
    check("pack.py 排除声明含靶场路径", "eval/target/" in pk and "eval/expected.json" in pk)
except Exception as e:
    check("pack.py 排除声明含靶场路径", False, str(e))

# ⑥ ROE 校验器自测
r = subprocess.run([sys.executable, os.path.join(ROOT, "eval/roe/roe_validate.py"), "--selftest"],
                   capture_output=True, text=True)
check("ROE 校验器自测", r.returncode == 0, (r.stdout or r.stderr).strip()[:80])

# ⑦ 离线门夹具回归（14/14，case13=端点表对账 V8）
r = subprocess.run([sys.executable, os.path.join(ROOT, "eval/gates/run_all_gates.py"), "--selftest"],
                   capture_output=True, text=True)
last = [l for l in (r.stdout or "").splitlines() if l.strip()][-1:]
check("离线门夹具回归 14/14", r.returncode == 0, (last[0] if last else "").strip())

# ⑧ v4.8 批1：筛查矩阵（K3）+ R6/R7-第一层 + M6 工具通道声明
k3 = open(os.path.join(ROOT, "skills", "hypothesis-matrix.md"), encoding="utf-8").read()
k3_ids = set(re.findall(r'\|\s*(C-\d{2})\s*\|', k3))
check("K3 矩阵含 27 类（C-01..C-27）", len([i for i in k3_ids if i >= "C-01" and i <= "C-27"]) == 27,
      f"命中 {len(k3_ids)} 类")
for kw in ["假设", "不适用", "待判定", "s3-筛查矩阵判定表.md", "extends", "replaces", "creates"]:
    check(f"K3 含 {kw}", kw in k3)
s3h = open(os.path.join(ROOT, "heads", "s3.md"), encoding="utf-8").read()
for kw in ["hypothesis-matrix", "S3-9", "S3-10", "筛查矩阵判定表", "三态"]:
    check(f"heads/s3.md 含 {kw}", kw in s3h)
s4h = open(os.path.join(ROOT, "heads", "s4.md"), encoding="utf-8").read()
for kw in ["S4-10", "extends TH-", "replaces TH-", "creates", "search_memory 对照原清单"]:
    check(f"heads/s4.md 含 {kw}", kw in s4h)
for kw in ["先 probe 后 batch", "M6", "hypothesis-matrix"]:
    check(f"loop-core 含 {kw}", kw in lc)
# M6 覆盖：≥25 个技能含声明节；规范工具清单每个至少被 1 个技能声明
m6_files = 0
m6_corpus = ""
for fp in glob.glob(os.path.join(ROOT, "skills", "*.md")):
    raw = open(fp, encoding="utf-8").read()
    if "v4.8 M6 工具通道兼容性声明" in raw:
        m6_files += 1
        m6_corpus += raw
check("M6 声明技能数 ≥25", m6_files >= 25, f"实际 {m6_files}")
for t in ["nmap", "masscan", "httpx", "whatweb", "arjun", "ffuf", "gobuster", "nuclei",
          "sqlmap", "searchsploit", "interactsh-client", "wafw00f", "curl",
          "channel-snapshot.py", "authz-diff.py", "subdomain-takeover.py", "captcha-ocr.py",
          "browser_login.py", "browser_oracle.py", "channel-heartbeat.py",
          "primitive-graph.py", "strip-fcaps.py"]:
    check(f"M6 工具声明覆盖 {t}", t in m6_corpus)

# ⑨ v4.8 批2：M2/M4/M5 确定性门 + R7 第二层引擎钩子 + 版本定型
orch = open(os.path.join(ROOT, "server/internal/engine/orchestrator.go"), encoding="utf-8").read()
for kw in ["v4.8 M2", "v4.8 M4", "matrixTableIssues", "deliverableDateIssues",
           "matrixTotalClasses", "deliverableDateRe"]:
    check(f"orchestrator.go 含 {kw}", kw in orch)
exp = open(os.path.join(ROOT, "server/internal/engine/expert.go"), encoding="utf-8").read()
for kw in ["adversarialAssumptionPass", "R7-ADVERSARIAL", "parseAdversarialHypotheses"]:
    check(f"expert.go 含 {kw}", kw in exp)
stg = open(os.path.join(ROOT, "server/internal/store/store.go"), encoding="utf-8").read()
check("store.go StageState 含 reflect_failures", "reflect_failures" in stg)
check("v4.8 门专项测试存在", os.path.isfile(os.path.join(ROOT, "server/internal/engine/v48_gate_test.go")))
check("version 定型 v5.3.8", app == "5.3.8", f"App={app}")

# ⑯ v5.0：代理模块 + 设备连接启用按钮
try:
    _v50 = open(os.path.join(ROOT, "server/internal/web/v50_proxy_devices.go"), encoding="utf-8").read()
    for kw in ["handleProxySave", "handleProxyTest", "handleDeviceAction", "rebuildCommandEnv",
               "writeExitPoolFile", "JT_EXIT_POOL", "wireless_pair", "shared_adb_test"]:
        check(f"v50_proxy_devices.go 含 {kw}", kw in _v50)
except Exception as e:
    check("v50_proxy_devices.go 存在", False, str(e))
sv = open(os.path.join(ROOT, "server/internal/web/server.go"), encoding="utf-8").read()
for route in ["/api/settings/proxy", "/api/settings/proxy/test", "/api/devices/action"]:
    check(f"server.go 路由 {route}", route in sv)
pc = open(os.path.join(ROOT, "skills", "proxy-channels.md"), encoding="utf-8").read()
for kw in ["$TOOL_PROXY", "$JT_EXIT_POOL", "工具代理旗标映射", "出口池会话纪律"]:
    check(f"skills/proxy-channels.md 含 {kw}", kw in pc)
check("路由器含 proxy-channels", "proxy-channels" in router)
vsp = open(os.path.join(ROOT, "web-app/src/pages/SettingsPage.vue"), encoding="utf-8").read()
for kw in ["代理配置", "saveProxy", "testProxy", "JT_EXIT_POOL"]:
    check(f"SettingsPage 含 {kw}", kw in vsp)
vdp = open(os.path.join(ROOT, "web-app/src/pages/DevicesPage.vue"), encoding="utf-8").read()
for kw in ["devices/action", "wireless_pair", "tcpip_env_check", "cloud_platform_check", "禁用（privileged"]:
    check(f"DevicesPage 含 {kw}", kw in vdp)
check("v5.0 单测存在", os.path.isfile(os.path.join(ROOT, "server/internal/web/v50_proxy_devices_test.go")))

# ⑮ v4.8.1 上传渐进验证 + 全域驻留只记录不处置
ub = open(os.path.join(ROOT, "skills", "upload-bypass.md"), encoding="utf-8").read()
for kw in ["渐进式上传验证协议", "先常规文件类型", "才尝试可执行脚本", "上传文件记录清单"]:
    check(f"skills/upload-bypass.md 含 {kw}", kw in ub)
wm = open(os.path.join(ROOT, "skills", "webshell-memshell.md"), encoding="utf-8").read()
for kw in ["只记录不处置", "禁止执行删除", "不触发应用重启", "需人工清理清单"]:
    check(f"skills/webshell-memshell.md 含 {kw}", kw in wm)
for kw in ["包含但不限于上传类", "只记录不处置"]:
    check(f"loop-core 驻留铁律含 {kw}", kw in lc)
s7hb = open(os.path.join(ROOT, "heads", "s7.md"), encoding="utf-8").read()
for kw in ["驻留工件豁免执行", "一律不执行删除/重启/还原", "上传文件记录清单"]:
    check(f"heads/s7.md 含 {kw}", kw in s7hb)
s5hb = open(os.path.join(ROOT, "heads", "s5.md"), encoding="utf-8").read()
check("heads/s5.md 含渐进上传口径", "先常规文件类型再可执行脚本" in s5hb)
s6hb = open(os.path.join(ROOT, "heads", "s6.md"), encoding="utf-8").read()
check("heads/s6.md S6-4 含只记录移交口径", "S7 只记录移交，不执行删除/重启/还原" in s6hb)

# ⑩ v4.8 批3：K1 行业模板六件 + K2 框架先验卡四件（模板字段完整性）
k1 = open(os.path.join(ROOT, "skills", "industry-templates.md"), encoding="utf-8").read()
for ind in ["医疗行业", "金融行业", "教育行业", "政务行业", "企业通用", "互联网业务"]:
    check(f"K1 含 {ind}", ind in k1)
check("K1 升格表×6", k1.count("升格表") >= 6, f"实际 {k1.count('升格表')}")
check("K1 数据类具象表×6", k1.count("数据类具象表") >= 6, f"实际 {k1.count('数据类具象表')}")
for field in ["组件归属映射", "批量枚举面", "二阶落点"]:
    check(f"K1 具象表字段 {field}×6", k1.count(field) >= 6, f"实际 {k1.count(field)}")
k2 = open(os.path.join(ROOT, "skills", "framework-priors.md"), encoding="utf-8").read()
for card in ["卡一", "卡二", "卡三", "卡四"]:
    check(f"K2 含 {card}", card in k2)
for field, n in [("指纹特征", 4), ("先验假设", 4), ("首查清单", 4), ("常见坑", 4)]:
    check(f"K2 字段 {field}×{n}", k2.count(field) >= n, f"实际 {k2.count(field)}")
# K1/K2 与 K3/头的挂接
check("K3 引用 K1/K2", "industry-templates" in k3 and "framework-priors" in k3)
check("s3 头引用 K1/K2", "industry-templates" in s3h and "framework-priors" in s3h)

# ⑪ v4.8 批4：W4 六轨编排器 + W6 注入通道/业务逻辑标准件
for tool in ["chain-proxy.py", "blind-inject-adjudicator.py", "idor-baseline.py", "logic-invariant.py"]:
    r2 = subprocess.run([sys.executable, os.path.join(ROOT, "tools-extra", tool), "--selftest"],
                        capture_output=True, text=True)
    last = [l for l in (r2.stdout or "").splitlines() if l.strip()][-1:]
    check(f"{tool} selftest", r2.returncode == 0, (last[0] if last else r2.stderr[-80:]).strip())
for kw in ["v4.8 W4", "identityTrackIssues", "loginSurfacePresent", "[W4-L1]"]:
    check(f"orchestrator.go 含 {kw}", kw in orch)
for kw in ["W4-L1", "W4-L6"]:
    check(f"heads/s4.md 含 {kw}", kw in s4h)
check("s4 头含 W6 标准件", "chain-proxy" in s4h and "idor-baseline" in s4h and "logic-invariant" in s4h)
for sid, kw in [("identity-bootstrapping", "六轨编排协议"), ("sqli-deep", "chain-proxy"),
                ("api-idor", "idor-baseline"), ("logic-purchase-limit", "logic-invariant")]:
    raw_s = open(os.path.join(ROOT, "skills", sid + ".md"), encoding="utf-8").read()
    check(f"skills/{sid}.md 含 {kw}", kw in raw_s)
# W6 工具进镜像（部署链）
dfl = open(os.path.join(ROOT, "Dockerfile"), encoding="utf-8").read()
for tool in ["chain-proxy.py", "blind-inject-adjudicator.py", "idor-baseline.py", "logic-invariant.py"]:
    check(f"Dockerfile COPY {tool}", f"tools-extra/{tool}" in dfl)

# ⑫ v4.8 批5：W5 出口池/浏览器农场/挑战求解 + 行为预算器
for tool in ["exit-pool.py", "browser-farm.py", "jsvm-challenge-solver.py"]:
    r2 = subprocess.run([sys.executable, os.path.join(ROOT, "tools-extra", tool), "--selftest"],
                        capture_output=True, text=True)
    last = [l for l in (r2.stdout or "").splitlines() if l.strip()][-1:]
    check(f"{tool} selftest", r2.returncode == 0, (last[0] if last else r2.stderr[-80:]).strip())
for kw in ["v4.8 W5 行为预算器", "batchBudgetGate", "batchResultFeedback", "BatchQuotaPer10Min"]:
    check(f"orchestrator.go/config.go 含 {kw}", kw in orch or kw in open(os.path.join(ROOT, "server/internal/config/config.go"), encoding="utf-8").read())
for tool in ["exit-pool.py", "browser-farm.py", "jsvm-challenge-solver.py"]:
    check(f"Dockerfile COPY {tool}", f"tools-extra/{tool}" in dfl)
check("挑战求解 ROE 门（--roe-allow）", "--roe-allow" in open(os.path.join(ROOT, "tools-extra/jsvm-challenge-solver.py"), encoding="utf-8").read())
for sid, kw in [("js-challenge-waf-playbook", "jsvm-challenge-solver"), ("channel-snapshot", "exit-"),
                ("rate-limit-playbook", "exit-pool")]:
    raw_s = open(os.path.join(ROOT, "skills", sid + ".md"), encoding="utf-8").read()
    check(f"skills/{sid}.md 含 {kw}", kw in raw_s)

# ⑬ v4.8 批6：W7 图引擎 + E1 埋点扩展 + 三指标判分
try:
    py_compile.compile(os.path.join(ROOT, "scripts/eval_run.py"), doraise=True)
    check("eval_run.py 可编译（f-string 语法修复锁定）", True)
except Exception as e:
    check("eval_run.py 可编译（f-string 语法修复锁定）", False, str(e)[-100:])
pg = open(os.path.join(ROOT, "tools-extra/primitive-graph.py"), encoding="utf-8").read()
for kw in ["build_graph", "forward_paths", "backward_gaps", "vt_suggestion", "loot_fanout"]:
    check(f"primitive-graph.py 图引擎含 {kw}", kw in pg)
exp_raw = json.load(open(os.path.join(_pack, "expected.json"), encoding="utf-8")) if os.path.isdir(_pack) else {"items": []}
mcs = {it.get("matrix_class") for it in exp_raw.get("items", []) if it.get("scoreable", True)}
check("expected.json 可种植类覆盖 25", len([c for c in mcs if c]) == 25, f"实际 {sorted(mcs)}")
check("expected.json 监控替代条目（C-24/C-26）", {it.get("matrix_class") for it in exp_raw.get("items", []) if not it.get("scoreable", True)} == {"C-24", "C-26"})
oauth_ok = subprocess.run([sys.executable, os.path.join(_pack, "mocks", "oauth_mock.py"), "--selftest"],
                          capture_output=True, text=True) if os.path.isdir(_pack) else None
check("oauth_mock selftest 5/5", oauth_ok is not None and oauth_ok.returncode == 0,
      (oauth_ok.stdout or oauth_ok.stderr)[-60:] if oauth_ok else "评测包未挂载")
for kw in ["行为预算器", "primitive-graph"]:
    check(f"loop-core 含 {kw}", kw in lc)
# ⑭ v4.8.1：存量持久化痕迹排查（S6-6，前人遗留后门只读清点）
s6h = open(os.path.join(ROOT, "heads", "s6.md"), encoding="utf-8").read()
for kw in ["S6-6 存量持久化痕迹排查", "只发现、只登记、不处置", "需人工清理清单"]:
    check(f"heads/s6.md 含 {kw}", kw in s6h)
per = open(os.path.join(ROOT, "skills", "persistence.md"), encoding="utf-8").read()
for kw in ["存量持久化痕迹排查", "排查清单", "Linux 排查清单", "Windows 排查清单", "处置口径", "存量风险"]:
    check(f"skills/persistence.md 含 {kw}", kw in per)
check("loop-core 含存量排查纪律", "存量持久化痕迹排查" in lc)
check("version 定型 v5.3.8", app == "5.3.8", f"App={app}")

# ⑰ v5.1：全量未授权检测硬门 + 身份政策（批次 A）
azd = open(os.path.join(ROOT, "skills", "authz-diff.md"), encoding="utf-8").read()
for kw in ["全量覆盖率硬门", "无 token 列纯匿名", "禁止以", "等拿到身份再测", "diffed/total",
           "三态处置", "破坏性端点只测门控存在性"]:
    check(f"skills/authz-diff.md 含 {kw}", kw in azd)
itf = open(os.path.join(ROOT, "skills", "intel-factory.md"), encoding="utf-8").read()
for kw in ["# total=N", "100% 全量入矩阵"]:
    check(f"skills/intel-factory.md 含 {kw}", kw in itf)
for kw in ["全量接口未授权检测", "新端点入表即入矩阵", "coverage_gate 端点表↔矩阵对账拦截"]:
    check(f"loop-core 含 {kw}", kw in lc)
for kw in ["v5.1 全量覆盖率硬门", "diffed/total"]:
    check(f"heads/s4.md 含 {kw}", kw in s4h)
cvg = open(os.path.join(ROOT, "eval/gates/coverage_gate.py"), encoding="utf-8").read()
for kw in ["_load_endpoint_table", "[V8]", "AUTHZ_CLASS_RE"]:
    check(f"coverage_gate.py 含 {kw}", kw in cvg)
# A2 写接口探测补偿
adl = open(os.path.join(ROOT, "skills", "api-doc-leak.md"), encoding="utf-8").read()
for kw in ["写端点门控判定", "只测门控不实调，禁止静默跳过", "并入端点表"]:
    check(f"skills/api-doc-leak.md 含 {kw}", kw in adl)
# A3 无凭证三态路由推广（≥8 技能含统一模板）
_ncr = sum(1 for fp in glob.glob(os.path.join(ROOT, "skills", "*.md"))
           if "无凭证三态路由（v5.1）" in open(fp, encoding="utf-8").read())
check("无凭证三态路由覆盖技能数 ≥8", _ncr >= 8, f"实际 {_ncr}")
# A4 身份政策翻转
ibs = open(os.path.join(ROOT, "skills", "identity-bootstrapping.md"), encoding="utf-8").read()
for kw in ["身份索取闭环", "identity.auto_register", "只评估不注册", "八、v4.8 W4 六轨编排协议",
           "禁止窃取或重放"]:
    check(f"skills/identity-bootstrapping.md 含 {kw}", kw in ibs)
ssc = open(os.path.join(ROOT, "skills", "session-state-chain.md"), encoding="utf-8").read()
for kw in ["ROE auto_register=deny", "身份索取闭环", "禁止硬磕"]:
    check(f"skills/session-state-chain.md 含 {kw}", kw in ssc)
roe_yaml = open(os.path.join(ROOT, "eval/roe/roe-profile.example.yaml"), encoding="utf-8").read()
check("ROE 示例 auto_register=deny", "auto_register: deny" in roe_yaml)
check("heads/s5.md 含 v5.1 身份政策", "v5.1 身份政策" in s5hb and "禁止窃取/重放真实用户活跃会话" in s5hb)
# A5 未授权利用口径
gfp = open(os.path.join(ROOT, "skills", "gateway-filter-playbook.md"), encoding="utf-8").read()
for kw in ["读端点量化三件套", "量级证明", "可达性边界"]:
    check(f"skills/gateway-filter-playbook.md 含 {kw}", kw in gfp)
# A6 家族覆盖
for sid in ("edu-family", "idp-family"):
    fp2 = os.path.join(ROOT, "skills", sid + ".md")
    if os.path.isfile(fp2):
        head2 = open(fp2, encoding="utf-8").read(400)
        m2 = re.search(r'---\nid:\s*"(.*?)"\ntitle:\s*(.*?)\ntags:\s*(.*?)\n---', head2, re.S)
        check(f"技能 {sid}.md frontmatter", bool(m2 and m2.group(1) == sid))
        check(f"路由器含 {sid}", sid in router)
    else:
        check(f"技能 {sid}.md 存在", False)
efam = open(os.path.join(ROOT, "skills", "edu-family.md"), encoding="utf-8").read()
for kw in ["APIList", "authz-diff 全量矩阵", "checkExist"]:
    check(f"skills/edu-family.md 含 {kw}", kw in efam)
fpk = open(os.path.join(ROOT, "skills", "framework-priors.md"), encoding="utf-8").read()
check("framework-priors 兜底硬规则", "指纹未命中任何卡（v5.1 兜底硬规则）" in fpk)
oaf = open(os.path.join(ROOT, "skills", "oa-family.md"), encoding="utf-8").read()
check("oa-family 逐厂商首查清单", "逐厂商未授权首查清单" in oaf)
nuc = open(os.path.join(ROOT, "skills", "nuclei-usage.md"), encoding="utf-8").read()
check("nuclei-usage 指纹→模板组映射表", "指纹→模板组映射表" in nuc)

# ⑱ v5.1 C 批次：tool-channels 单源 + 家族补全 + subdomain-takeover
for sid in ("tool-channels", "subdomain-takeover"):
    fp2 = os.path.join(ROOT, "skills", sid + ".md")
    if os.path.isfile(fp2):
        head2 = open(fp2, encoding="utf-8").read(400)
        m2 = re.search(r'---\nid:\s*"(.*?)"\ntitle:\s*(.*?)\ntags:\s*(.*?)\n---', head2, re.S)
        check(f"技能 {sid}.md frontmatter", bool(m2 and m2.group(1) == sid))
        check(f"路由器含 {sid}", sid in router)
    else:
        check(f"技能 {sid}.md 存在", False)
tc = open(os.path.join(ROOT, "skills", "tool-channels.md"), encoding="utf-8").read()
for kw in ["先 probe 后 batch", "channel-snapshot.py", "netexec", "searchsploit", "引用规范"]:
    check(f"tool-channels.md 含 {kw}", kw in tc)
check("内网技能 M6 已单源化（ad-attack 引用 tool-channels）", "tool-channels.md" in open(os.path.join(ROOT, "skills/ad-attack.md"), encoding="utf-8").read())
check("tunnel-pivot M6 存在", "v4.8 M6 工具通道兼容性声明" in open(os.path.join(ROOT, "skills/tunnel-pivot.md"), encoding="utf-8").read())
cld = open(os.path.join(ROOT, "skills", "cloud-security.md"), encoding="utf-8").read()
for kw in ["metadata.tencentyun.com", "IMDSv2", "myqcloud.com", "IMDSv2 防护生效"]:
    check(f"cloud-security.md 含 {kw}", kw in cld)
mw = open(os.path.join(ROOT, "skills", "middleware-web.md"), encoding="utf-8").read()
for kw in ["RocketMQ", "Kibana", "Dubbo", "ZooKeeper", "Druid", "APISIX"]:
    check(f"middleware-web.md 含 {kw}", kw in mw)
evb = open(os.path.join(ROOT, "skills", "edge-vpn-bastion.md"), encoding="utf-8").read()
for kw in ["华为 USG", "H3C SecPath", "网康", "安恒明御"]:
    check(f"edge-vpn-bastion.md 含 {kw}", kw in evb)
jcw = open(os.path.join(ROOT, "skills", "js-challenge-waf-playbook.md"), encoding="utf-8").read()
check("js-challenge 通用特征表", "通用 JS 挑战特征表" in jcw)
prv = open(os.path.join(ROOT, "skills", "privesc-checklist.md"), encoding="utf-8").read()
for kw in ["AlwaysInstallElevated", "出口（v5.1）", "docker.sock"]:
    check(f"privesc-checklist.md 含 {kw}", kw in prv)
rpw = open(os.path.join(ROOT, "skills", "report-writing.md"), encoding="utf-8").read()
for kw in ["漏洞编号规范（v5.1）", "密级与分发（v5.1）", "复测章节（v5.1）"]:
    check(f"report-writing.md 含 {kw}", kw in rpw)
rlp = open(os.path.join(ROOT, "skills", "rate-limit-playbook.md"), encoding="utf-8").read()
check("rate-limit W5 判定顺序", "W5 与冷却协议的判定顺序" in rlp)

# ⑲ v5.1.1 复核修复（对抗复审 P1/P2 锁定）：自建账号残留清零 + W4 注入文本 + ROE Digest
lcr = open(os.path.join(ROOT, "skills", "logic-csrf-deser.md"), encoding="utf-8").read()
for kw in ["客户提供的**两个测试账号", "仅 ROE allow 执行；deny 下转 record_vt",
           "评估态仅做流程还原与响应差异观测", "禁止指向真实用户账号"]:
    check(f"skills/logic-csrf-deser.md 含 {kw}", kw in lcr)
check("logic-csrf-deser 无『自建账号』残留", "自建账号" not in lcr)
abp = open(os.path.join(ROOT, "skills", "auth-bypass.md"), encoding="utf-8").read()
for kw in ["无凭据口径（v5.1）", "评估态只做流程还原"]:
    check(f"skills/auth-bypass.md 含 {kw}", kw in abp)
s5v = open(os.path.join(ROOT, "heads", "s5.md"), encoding="utf-8").read()
check("s5 头 S5-2 已改决策树路由", "按决策树路由" in s5v and "标准链（注册→登录" not in s5v)
ibv = open(os.path.join(ROOT, "skills", "identity-bootstrapping.md"), encoding="utf-8").read()
for kw in ["命中轨分类处置（v5.1）", "先执行一a节身份索取闭环"]:
    check(f"skills/identity-bootstrapping.md 含 {kw}", kw in ibv)
aiv = open(os.path.join(ROOT, "skills", "api-idor.md"), encoding="utf-8").read()
for kw in ["同角色两个账号", "idor_anonymous"]:
    check(f"skills/api-idor.md 含 {kw}", kw in aiv)
for sid in ("auth-flow-deep", "upload-bypass"):
    raw_s = open(os.path.join(ROOT, "skills", sid + ".md"), encoding="utf-8").read()
    check(f"skills/{sid}.md 含索取闭环口径", "客户提供/索取闭环" in raw_s)
orch_v = open(os.path.join(ROOT, "server/internal/engine/orchestrator.go"), encoding="utf-8").read()
for kw in ["L1 为评估轨", "身份索取闭环", "v4.8 W4·v5.1 修订"]:
    check(f"orchestrator.go W4 注入含 {kw}", kw in orch_v)
roev = open(os.path.join(ROOT, "server/internal/engine/roe.go"), encoding="utf-8").read()
check("roe.go Digest 输出 auto_register", "identity.auto_register=" in roev)
rtv = open(os.path.join(ROOT, "skills", "00-router.md"), encoding="utf-8").read()
check("00-router L1 评估轨措辞", "L1 评估轨→L6 决策树" in rtv and "注册面评估" in rtv)

# ⑳ v5.1.2 无死角终审修复锁定（引擎 P0/工具 P0-P1/知识库结构/交付链）
check("orchestrator 收口 HasPrefix 修复", "strings.HasPrefix(results[i], \"阶段已收口\")" in orch)
check("orchestrator shell_write 受控", "会话注入输入与 run_command 同等受控" in orch)
check("orchestrator install_tool 接审批", "install_tool: 安装" in orch)
check("orchestrator 三振出局降级门", "三振出局降级门" in orch and "deterministicGate(p, stageID); len(issues) > 0" in orch)
check("orchestrator chatTurnDone cancel", "轮结束同时取消该轮 ctx" in orch)
check("orchestrator s8 nil 防御", "nil StageState 防御" in orch)
check("subagent ID 随机后缀", "crand.Read(rb[:])" in open(os.path.join(ROOT, "server/internal/engine/subagent.go"), encoding="utf-8").read())
roev2 = open(os.path.join(ROOT, "server/internal/engine/roe.go"), encoding="utf-8").read()
check("roe.go 前缀栈扁平化", "前缀栈随缩进出栈" in roev2 and ".lastSection" not in roev2 and "p.lastSection" not in roev2)
check("config 破坏性禁令补全", "rm\\s+-fr\\s+/" in open(os.path.join(ROOT, "server/internal/config/config.go"), encoding="utf-8").read())
for t, kw in [("primitive-graph", "大小写错配死点"), ("chain-proxy", "禁用自动重定向"),
              ("logic-invariant", "纯动作序列"), ("blind-inject-adjudicator", "status!=200/无响应"),
              ("captcha-ocr", "PBM P1"), ("authz-diff", "阴性对照")]:
    raw_t = open(os.path.join(ROOT, "tools-extra", t + ".py"), encoding="utf-8").read()
    check(f"tools/{t}.py v5.1.2 修复标记", "v5.1.2" in raw_t and kw in raw_t)
pg_test = os.popen(f"printf '[{{\"id\":\"F-1\",\"title\":\"越权\",\"detail\":\"primitive:DB-READ\"}}]' > /tmp/pg-audit.json && python3 {ROOT}/tools-extra/primitive-graph.py --findings /tmp/pg-audit.json 2>&1").read()
check("primitive-graph extract 实弹复活", "DB-READ" in pg_test)
rtv2 = open(os.path.join(ROOT, "skills", "00-router.md"), encoding="utf-8").read()
for sid in ("recon-playbook", "web-top10", "app-dynamic-audit", "miniapp-audit", "poc-template"):
    check(f"路由器含孤儿补收 {sid}", sid in rtv2)
check("s6 指针修正第五节", "persistence 第五节" in open(os.path.join(ROOT, "heads/s6.md"), encoding="utf-8").read())
check("loop-core 规则12 索取闭环", "先执行 identity-bootstrapping 一a节**身份索取闭环**" in lc)
import json as _json2
_cm = _json2.load(open(os.path.join(ROOT, "docker-compose.yml"), encoding="utf-8").read().replace("```", "")) if False else None
_dc = open(os.path.join(ROOT, "docker-compose.yml"), encoding="utf-8").read()
check("compose 8787 可配置绑定", "${JT_WEB_BIND:-0.0.0.0}:8787:8787" in _dc)
pkv = open(os.path.join(ROOT, "scripts/pack.py"), encoding="utf-8").read()
check("pack.py jtn-private 对齐+排除", "os.pardir" in pkv and '"jtn-private",' in pkv)
check("README 新机部署 Quickstart", "新机部署 Quickstart" in open(os.path.join(ROOT, "README.md"), encoding="utf-8").read())

# ㉑ v5.1.3 批量整改锁定（监控八项发现 + 用户政策）
check("orchestrator 代收口确定性门照跑", "代收口路径确定性门照跑" in orch)
check("orchestrator coverage.json 落盘", 'WriteFile(p.ID, "coverage.json"' in orch)
check("orchestrator M4 年份级日期", "deliverableYearRe" in orch and "年份级日期" in orch)
check("orchestrator ROE 文本默认口径", "ROE 运行时默认口径" in orch and "identity.auto_register=deny（平台默认）" in orch)
check("loop-core 自建数据不删除", "自建数据同样只记录不删除" in lc and "先 SELECT 后登记" in lc)
check("loop-core E1 逐条字面路径", "禁止 `a..b` 范围式" in lc or "禁止 a..b 范围式" in lc)
check("loop-core 空响应体占位", "空响应体留占位" in lc)
s7v2 = open(os.path.join(ROOT, "heads/s7.md"), encoding="utf-8").read()
check("heads/s7 自建数据只登记", "自建数据同样只登记不删除" in s7v2 and "先 SELECT 后登记" in s7v2)
check("heads/s5 承接反蒸发", "承接反蒸发" in open(os.path.join(ROOT, "heads/s5.md"), encoding="utf-8").read())
check("session-state-chain 登记不删除", "只登记不删除" in open(os.path.join(ROOT, "skills/session-state-chain.md"), encoding="utf-8").read())
cvg2 = open(os.path.join(ROOT, "eval/gates/coverage_gate.py"), encoding="utf-8").read()
check("V8 读 deliverables 端点表 md", "*端点表*.md" in cvg2)

# ㉒ v5.1.4：P0 包完整性修复锁定 + 收包验收 + 工具 selftest + 切换边界
pk = open(os.path.join(ROOT, "scripts/pack.py"), encoding="utf-8").read()
check("pack.py web 仅根目录排除", bool(re.search(r'EXCLUDE_ROOT_DIRS = \{[^}]*"web"', pk)) and 'EXCLUDE_ANY_DIRS = {"__pycache__"}' in pk and 'if rel in EXCLUDE_ROOT_DIRS or rel == "web-app/dist":' in pk)
check("pack.py 包完整性自检", "verify_package_integrity" in pk and "server/internal/web/" in pk)
check("scripts/verify_package.sh 存在可执行", os.access(os.path.join(ROOT, "scripts/verify_package.sh"), os.X_OK))
vp = open(os.path.join(ROOT, "scripts/verify_package.sh"), encoding="utf-8").read()
for kw in ("server/internal/web", "禁入项泄漏", "config.example.json"):
    check(f"verify_package.sh 含 {kw}", kw in vp)
r2 = subprocess.run([sys.executable, os.path.join(ROOT, "tools-extra/strip-fcaps.py"), "--selftest"],
                    capture_output=True, text=True)
check("strip-fcaps --selftest", r2.returncode == 0, (r2.stdout or r2.stderr).strip()[-60:])
rm = open(os.path.join(ROOT, "README.md"), encoding="utf-8").read()
check("README 切换边界说明", "切换边界（v2.7 A8）" in rm and "供应商拒绝类错误" in rm)
check("README 无陈旧包名 v5.1.1", "jiutouniao_v5.1.1_部署包.zip" not in rm)

# ㉓ v5.2.0 治理批次锁定（P1-1/P1-2/P1-3）
orch2 = open(os.path.join(ROOT, "server/internal/engine/orchestrator.go"), encoding="utf-8").read()
for kw in ["registrationGate", "scopeGate", "roeAutoRegisterDeny", "defaultScopeAllowlist", "strict_scope=true：命令引用范围外目标"]:
    check(f"orchestrator 治理门含 {kw}", kw in orch2)
ex = open(os.path.join(ROOT, "server/internal/tools/executor.go"), encoding="utf-8").read()
check("executor 未知命令保持 L1+默认 manual 注释", "v5.2.0 起默认审批策略 manual" in ex)
cfg = open(os.path.join(ROOT, "server/internal/config/config.go"), encoding="utf-8").read()
check("config 默认 manual", 'c.AutoApprove = "manual"' in cfg)
for kw in ["管道执行与系统路径写入属利用形态", "ScopeAllowlist"]:
    check(f"config 含 {kw}", kw in cfg)
dfl2 = open(os.path.join(ROOT, "Dockerfile"), encoding="utf-8").read()
for kw in ["sha256:7f803e5be80ec33dcf4228d9702ea1264658b43301e9d6bf3bce6cf8b1077399",
           "@sha256:a2012b4a1d1f9f7e9f44e0d39b805a901e856b1dd80b4e6ee4338db547050308",
           "@sha256:862263c612aa437e3037674b85419622a9d93bff80aa1eee5398dfe686375532",
           "@v3.11.1", "@v2.17.0", "@v1.12.0", "@v2.3.0",
           "1cb2d50b4f0f5cbdb600165b0afe556b4623f29a", "08ea40e77db3f42ef8f20c65196f3936a19b6c86",
           "46207ff7c9b1a84ab5f7d02338163f00ea6ddd56"]:
    check(f"Dockerfile pin {kw[:28]}", kw in dfl2)
check("v52 门单测存在", os.path.isfile(os.path.join(ROOT, "server/internal/engine/v52_gate_test.go")))
rm2 = open(os.path.join(ROOT, "README.md"), encoding="utf-8").read()
check("README 供应链锁定说明", "供应链已锁定（v5.2.0）" in rm2 and "离线边界" in rm2)

# ㉔ v5.3.0：Skills/Prompts 深度重构锁定（外部方案 P0/P1/P2）
lc3 = open(os.path.join(ROOT, "prompts/loop-core.md"), encoding="utf-8").read()
check("loop-core 配额证据化", "证据化深挖" in lc3 and "不以" in lc3 and "绕过数量" in lc3)
check("loop-core 身份三态", "surface_found ≠ identity_obtained" in lc3)
check("loop-core 中性化已删", "目标引用中性化（供应商风控降触发）" not in lc3 and "如实表述" in lc3)
check("loop-core 双运行模式", "execution_profile" in lc3 and "production_safe" in lc3 and "isolated_lab" in lc3)
check("loop-core Lab 快照回滚", "Isolated Lab 快照回滚" in lc3)
s7v3 = open(os.path.join(ROOT, "heads/s7.md"), encoding="utf-8").read()
check("s7 就地中和已废止", "「就地中和」" not in s7v3.replace("不再有「就地中和」", "") and "v5.3.0 废止" in s7v3)
check("s7 执行侧矛盾废止", "先 SELECT 后 DELETE 铁律不变" not in s7v3)
for sid, kw in [("upload-bypass", "逐项登记四元组并入《需人工清理清单》移交"), ("logic-csrf-deser", "只登记移交、不执行还原")]:
    raw_s = open(os.path.join(ROOT, "skills", sid + ".md"), encoding="utf-8").read()
    check(f"skills/{sid} 清理措辞", kw in raw_s)
azd2 = open(os.path.join(ROOT, "skills/authz-diff.md"), encoding="utf-8").read()
for kw in ["仅记为可达候选", "清点率 ≠ 测试执行率"]:
    check(f"authz-diff 含 {kw}", kw in azd2)
mn = open(os.path.join(ROOT, "heads/main.md"), encoding="utf-8").read()
check("main 诚实化", "指挥室与任务规划策略头" in mn)
s2h = open(os.path.join(ROOT, "heads/s2.md"), encoding="utf-8").read()
check("s2 扫描条件化", "v5.3.0 策略档" in s2h)
for sid in ("framework-priors", "industry-templates", "llm-top10", "llm-payloads", "rag-attack", "app-static-audit", "miniapp-audit"):
    raw_s = open(os.path.join(ROOT, "skills", sid + ".md"), encoding="utf-8").read()
    check(f"skills/{sid} v5.3.0 契约", "v5.3.0" in raw_s)
mf = os.path.join(ROOT, "skills/manifest.json")
check("skills/manifest.json 存在", os.path.isfile(mf))
if os.path.isfile(mf):
    import json as _j
    mdata = _j.load(open(mf, encoding="utf-8"))
    check("manifest 技能数 107", mdata.get("count") == 107, f"实际 {mdata.get('count')}")
check("policies/coverage-contract.json", os.path.isfile(os.path.join(ROOT, "policies/coverage-contract.json")))
check("policies/execution-profiles.yaml", os.path.isfile(os.path.join(ROOT, "policies/execution-profiles.yaml")))
orc3 = open(os.path.join(ROOT, "server/internal/engine/orchestrator.go"), encoding="utf-8").read()
for kw in ["premise_failed", "patch_pending_retest", "evidence_ids", "非法 coverage status"]:
    check(f"orchestrator 含 {kw}", kw in orc3)
sk = open(os.path.join(ROOT, "server/internal/engine/skills.go"), encoding="utf-8").read()
check("skills.go 确定性排序", "v5.3.0 P1-2：确定性排序" in sk)
check("Search top-5", '.SearchCtx(s("query"), stageID, 5)' in orc3)

# ㉕ v5.3.0：ROE 模板政策对齐锁定（用户反馈：模板残留旧清理/自建账号口径）
cpj = open(os.path.join(ROOT, "web-app/src/pages/CreateProjectPage.vue"), encoding="utf-8").read()
check("ROE 模板自建数据只登记", "只登记移交、不执行删除/还原/清理" in cpj)
check("ROE 模板无精确清理残留", "精确清理" not in cpj)
check("ROE 模板禁自建账号", "注册面只评估不注册" in cpj and "自建账号默认禁止" in cpj)
check("前端默认审批 manual", "policy: 'manual'" in cpj)
check("Web 专项条款禁自建", "使用客户提供的测试账号" in cpj)

# ㉖ v5.3.1：Execution Profile 运行时 + 治理门全通道接线锁定（P0——纸面承诺落地）
pf = os.path.join(ROOT, "server/internal/engine/profile.go")
check("profile.go 存在", os.path.isfile(pf))
pv = open(pf, encoding="utf-8").read()
for kw in ["LoadExecutionProfiles", "profileGate", "profileViolations", "productionSafeForbidden",
           "isolatedLabForbidden", "labOnlyBanner", "ProfileProductionSafe", "ProfileIsolatedLab",
           "植入 webshell/内存马", "上传可执行文件", "批量导出业务数据/凭据", "修改/删除目标数据",
           "真实订单/支付/短信状态变更", "向公网分发测试产物", "接触生产数据"]:
    check(f"profile.go 含 {kw}", kw in pv)
orc4 = open(os.path.join(ROOT, "server/internal/engine/orchestrator.go"), encoding="utf-8").read()
for kw in ['governanceGates(p, stageID, command, "run_command", false)',
           'governanceGates(p, stageID, command, "run_async", false)',
           'governanceGates(p, stageID, input, "shell_write", false)',
           'governanceGates(p, stageID, command, "shell_open", false)',
           'governanceGates(p, stageID, cmd, "hexstrike_command", false)',
           'governanceGates(p, stageID, st.cmd, "install_tool", true)',
           "SetExecutionProfile", "Execution Profile 声明已加载", "labOnlyBanner(p, sk.ID)",
           "profiles, perr := LoadExecutionProfiles"]:
    check(f"orchestrator 治理门接线 {kw}", kw in orc4)
stg2 = open(os.path.join(ROOT, "server/internal/store/store.go"), encoding="utf-8").read()
check("store Project 执行档持久化", "execution_profile" in stg2 and "production_safe" in stg2)
sv2 = open(os.path.join(ROOT, "server/internal/web/server.go"), encoding="utf-8").read()
check("web createReq 执行档", "execution_profile" in sv2)
check("web handlePolicy 切档", "SetExecutionProfile" in sv2)
cfgv = open(os.path.join(ROOT, "server/internal/config/config.go"), encoding="utf-8").read()
check("config 含 execution_profiles_path", "execution_profiles_path" in cfgv)
check("v5.3.1 门单测存在", os.path.isfile(os.path.join(ROOT, "server/internal/engine/v531_profile_test.go"))
      and os.path.isfile(os.path.join(ROOT, "server/internal/engine/v531_channel_gates_test.go")))
cpp2 = open(os.path.join(ROOT, "web-app/src/pages/CreateProjectPage.vue"), encoding="utf-8").read()
for kw in ["execution_profile", "isolated_lab", "隔离靶场确认", "逐动作强制"]:
    check(f"CreateProjectPage 执行档选择器 {kw}", kw in cpp2)
# 声明层↔执行层双源对照：YAML forbidden 语义行 ↔ profile.go 规则名（防两源漂移）
epv = open(os.path.join(ROOT, "policies/execution-profiles.yaml"), encoding="utf-8").read()
for kw in ["植入 webshell/内存马/持久化/隧道/新增账号", "上传可执行文件", "批量导出业务数据/凭据",
           "修改/删除/覆盖目标数据", "真实订单/支付/短信状态变更", "向公网分发测试产物", "接触生产数据",
           "gate: 引擎按 execution_profile+scope+risk+approval 每工具动作校验"]:
    check(f"execution-profiles.yaml 锁定 {kw[:24]}", kw in epv)
# P0-4：双模式高影响限制统一锁定（loop-core/头措辞与引擎口径一致）
lc4 = open(os.path.join(ROOT, "prompts/loop-core.md"), encoding="utf-8").read()
check("loop-core 引擎强制已落地表述", "v5.3.1 起引擎逐动作强制" in lc4)
for h, kws in {"s5": ["执行模式契约（v5.3.1", "快照恢复/环境重置", "登记移交"],
               "s6": ["执行模式契约（v5.3.1", "production_safe", "isolated_lab"],
               "s7": ["执行模式契约（v5.3.1", "快照恢复", "production_safe"]}.items():
    body = open(os.path.join(ROOT, "heads", h + ".md"), encoding="utf-8").read()
    for kw in kws:
        check(f"heads/{h}.md 执行模式契约含 {kw}", kw in body)

# ㉗ v5.3.2：manifest 单源生成 + Go 消费 + 检索升级 + 子任务优先级自调锁定（P1）
check("gen_skill_manifest.py 存在", os.path.isfile(os.path.join(ROOT, "scripts/gen_skill_manifest.py")))
_gm = subprocess.run([sys.executable, os.path.join(ROOT, "scripts/gen_skill_manifest.py"), "--check"],
                     capture_output=True, text=True)
check("manifest 与生成器输出一致（--check）", _gm.returncode == 0, (_gm.stdout or _gm.stderr).strip()[-80:])
mdata2 = json.load(open(os.path.join(ROOT, "skills/manifest.json"), encoding="utf-8"))
check("manifest count 107", mdata2.get("count") == 107, f"实际 {mdata2.get('count')}")
_ms = mdata2.get("skills", [])
check("manifest aliases 字段就位", sum(1 for s in _ms if s.get("aliases")) >= 20, f"实际 {sum(1 for s in _ms if s.get('aliases'))}")
check("manifest depends_on 字段就位", sum(1 for s in _ms if s.get("depends_on")) >= 60, f"实际 {sum(1 for s in _ms if s.get('depends_on'))}")
check("manifest stage_fit 字段就位", sum(1 for s in _ms if s.get("stage_fit")) >= 90, f"实际 {sum(1 for s in _ms if s.get('stage_fit'))}")
check("manifest lab_only 标注 9", sum(1 for s in _ms if s.get("lab_only")) == 9, f"实际 {sum(1 for s in _ms if s.get('lab_only'))}")
_ids = {s["id"] for s in _ms}
check("manifest 引用零悬空", all(d in _ids for s in _ms for d in s.get("depends_on", []) + s.get("handoff_to", [])))
_lab_annot = sum(1 for s in _ms if s.get("lab_only") and "待正文标注补齐" not in s.get("lab_only_actions", ""))
check("lab_only 全部有正文标注", _lab_annot == 9, f"实际 {_lab_annot}")
for sid in ["persistence", "webshell-memshell", "upload-bypass", "logic-csrf-deser", "database-postex",
            "tunnel-pivot", "cve-weaponization", "crypto-offensive", "hypothesis-0day"]:
    raw_s = open(os.path.join(ROOT, "skills", sid + ".md"), encoding="utf-8").read()
    check(f"skills/{sid} Execution Profile 标注", "Execution Profile 标注（v5.3.2）" in raw_s)
sk2 = open(os.path.join(ROOT, "server/internal/engine/skills.go"), encoding="utf-8").read()
for kw in ["loadManifest", "SearchCtx", "Bundle", "searchScored", "tokenize", "LabOnly",
           "manifest.json 缺失（降级 markdown-only）", "aliases", "stage_fit"]:
    check(f"skills.go 含 {kw}", kw in sk2)
orc5 = open(os.path.join(ROOT, "server/internal/engine/orchestrator.go"), encoding="utf-8").read()
for kw in ["o.skills.SearchCtx(s(\"query\"), stageID, 5)", "o.skills.Bundle(s(\"query\"), stageID, 5)",
           "o.skills.LabOnly(h.ID)", "rerankSubtasks", "overlapKey", "rerankSubtasks(p, stageID)", "P1-5"]:
    check(f"orchestrator v5.3.2 含 {kw}", kw in orc5)
stg3 = open(os.path.join(ROOT, "server/internal/store/store.go"), encoding="utf-8").read()
check("Subtask Priority/PriorityWhy 落库", '"priority,omitempty"' in stg3 and '"priority_why,omitempty"' in stg3)
check("项目删除接口存在", "DELETE /api/projects/{id}" in open(os.path.join(ROOT, "server/internal/web/server.go"), encoding="utf-8").read())
check("store.DeleteProject 存在", "func (s *Store) DeleteProject" in open(os.path.join(ROOT, "server/internal/store/store.go"), encoding="utf-8").read())
check("v5.3.5 删除单测存在", os.path.isfile(os.path.join(ROOT, "server/internal/store/v535_delete_test.go")))
orc7 = open(os.path.join(ROOT, "server/internal/engine/orchestrator.go"), encoding="utf-8").read()
check("v5.3.8 死锁修复: 收口门无 quality-pending 硬拒", "用 update_finding 不适用、直接编辑清除标记" not in orc7)
check("v5.3.8 死锁修复: 软提示+确认参数", "applyQualityReviewConfirm" in orc7 and "confirm_quality_review" in orc7 and "quality-reviewed（v5.3.8 复核确认）" in orc7)
check("v5.3.8 死锁单测存在", os.path.isfile(os.path.join(ROOT, "server/internal/engine/v538_quality_deadlock_test.go")))
cpp3 = open(os.path.join(ROOT, "web-app/src/pages/CreateProjectPage.vue"), encoding="utf-8").read()
for kw in ["post_exploit", "后渗透阶段", "默认不执行", "DEFAULT_SCOPE", "DEFAULT_ROE", "DEFAULT_SUCCESS",
           "重置标准 ROE", "重置标准范围", "【七、专项条款】", "【授权目标（in-scope）】", "【明确排除（out-of-scope）】"]:
    check(f"CreateProjectPage v5.3.7 含 {kw}", kw in cpp3)
check("创建页锁定短语仍在（合规口径不丢）", "只登记移交、不执行删除/还原/清理" in cpp3
      and "注册面只评估不注册" in cpp3 and "自建账号默认禁止" in cpp3 and "使用客户提供的测试账号" in cpp3)
check("P0 工具 schema 严格性单测存在", os.path.isfile(os.path.join(ROOT, "server/internal/engine/v533_tool_schema_test.go")))
orc6 = open(os.path.join(ROOT, "server/internal/engine/orchestrator.go"), encoding="utf-8").read()
check("v5.3.6 evidence_ids 参数已废弃（schema 无该参数）", '"evidence_ids"' not in orc6 and "arrStr(" not in orc6)
check("v5.3.6 record_finding 接收 poc/remediation", '"remediation"' in orc6 and '"poc"' in orc6 and "f.EvidenceIDs = o.store.LastEvidenceIDs" in orc6)
stg6 = open(os.path.join(ROOT, "server/internal/store/store.go"), encoding="utf-8").read()
check("v5.3.6 FindingPOC/Remediation 字段", "FindingPOC" in stg6 and "Remediation" in stg6)
webv = open(os.path.join(ROOT, "server/internal/web/server.go"), encoding="utf-8").read()
check("v5.3.6 web 证据回填", "backfillPOC" in webv)
fpv = open(os.path.join(ROOT, "web-app/src/pages/FindingsPage.vue"), encoding="utf-8").read()
for kw in ["pocOf(f)", "f-card", "f-head", "POC 展示", "修复建议", "open[f.id]"]:
    check(f"FindingsPage v5.3.6 含 {kw}", kw in fpv)
rwp = open(os.path.join(ROOT, "skills/report-writing.md"), encoding="utf-8").read()
check("report-writing v5.3.6 字段对齐", "detail/poc/remediation" in rwp)
s8p = open(os.path.join(ROOT, "heads/s8.md"), encoding="utf-8").read()
check("s8 v5.3.6 三字段引用", "detail/poc/remediation" in s8p)
check("v5.3.2 单测存在", os.path.isfile(os.path.join(ROOT, "server/internal/engine/v532_skills_test.go"))
      and os.path.isfile(os.path.join(ROOT, "server/internal/engine/v532_plan_priority_test.go")))

# ㉘ v5.3.3：实战能力评测四件套锁定（P2——检索准确率/盲测报告/身份覆盖/e2e 闭环）
golden_fp = os.path.join(ROOT, "eval/gates/fixtures/skill-retrieval/golden.json")
check("P2-1 金标集存在", os.path.isfile(golden_fp))
if os.path.isfile(golden_fp):
    gdata = json.load(open(golden_fp, encoding="utf-8"))
    check("P2-1 金标 ≥30 条", len(gdata.get("cases", [])) >= 30, f"实际 {len(gdata.get('cases', []))}")
    check("P2-1 金标线合理", 0.5 <= gdata.get("min_pass_rate", 0) <= 1.0)
check("skill_retrieval_gate.py 存在", os.path.isfile(os.path.join(ROOT, "eval/gates/skill_retrieval_gate.py")))
check("P2-1 Go 金标回归存在", os.path.isfile(os.path.join(ROOT, "server/internal/engine/v533_golden_retrieval_test.go")))
_e2e = subprocess.run([sys.executable, os.path.join(ROOT, "scripts/e2e_loop_check.py"), "--selftest"],
                      capture_output=True, text=True, timeout=60)
check("P2-4 e2e 闭环门 selftest", _e2e.returncode == 0 and "4/4" in (_e2e.stdout or ""), (_e2e.stdout or _e2e.stderr).strip()[-60:])
er = open(os.path.join(ROOT, "scripts/eval_run.py"), encoding="utf-8").read()
for kw in ["blind_report", "identity_coverage_report", "--blind-report", "--identity-coverage",
           "high_risk_anonymous_recall_min", "pure_anonymous", "BLIND_THRESHOLDS"]:
    check(f"eval_run.py P2 含 {kw}", kw in er)
rcs = open(os.path.join(ROOT, "eval/run_comprehensive.sh"), encoding="utf-8").read()
check("run_comprehensive 桥接检索准确率门", "skill_retrieval_gate.py" in rcs)
check("run_comprehensive 桥接 e2e 闭环门", "e2e_loop_check.py" in rcs)
rag = open(os.path.join(ROOT, "eval/gates/run_all_gates.py"), encoding="utf-8").read()
check("run_all_gates 跳过非门夹具", "skill-retrieval" in rag or "非门夹具目录" in rag)

fails = [c for c in CHECKS if not c[1]]
for name, ok, detail in CHECKS:
    print(("PASS " if ok else "FAIL ") + name + (("  " + detail) if detail and not ok else ""))
print(f"\n文件层核查: {len(CHECKS)-len(fails)}/{len(CHECKS)}")
sys.exit(0 if not fails else 1)
