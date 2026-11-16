#!/usr/bin/env python3
"""v4.6 W4-C1 验证码 OCR 产品化（审计实证方法：列投影分割 + 字形去噪 + 位移对齐模板匹配）。
来源：历史实战任务样本集（任务号已泛化）：自聚类+ASCII 判读样本、模板匹配 6/6 + e2e 负例样本。
纯 python 实现（无 PIL 依赖）；真实图片用 --image <PBM P1 文件>；--selftest 用内置合成验证码闭环。
纪律（evidence-standard）：OCR 输出必须「取码→识别→立即提交」单会话闭环验证，跨会话复用会因
验证码 TTL 过期得到假阴性 faild00（教训库已收录）。"""
import argparse, random, sys

FONT = {  # 5x7 数字位图（'#'=笔画）
'0':["01110","10001","10011","10101","11001","10001","01110"],
'1':["00100","01100","00100","00100","00100","00100","01110"],
'2':["01110","10001","00001","00010","00100","01000","11111"],
'3':["11110","00001","00001","01110","00001","00001","11110"],
'4':["00010","00110","01010","10010","11111","00010","00010"],
'5':["11111","10000","11110","00001","00001","10001","01110"],
'6':["00110","01000","10000","11110","10001","10001","01110"],
'7':["11111","00001","00010","00100","01000","01000","01000"],
'8':["01110","10001","10001","01110","10001","10001","01110"],
'9':["01110","10001","10001","01111","00001","00010","01100"],
}

# 字模统一编码为 '#'/'.':（源定义曾用 0/1，加载时归一——笔画判定单一口径）
FONT = {k: [r.replace("0", ".").replace("1", "#") for r in v] for k, v in FONT.items()}

def seg_cols(bm):
    w = max(len(r) for r in bm)
    cols = [any(row[c] == '#' for row in bm) for c in range(w)]
    out, cur = [], []
    for c in range(w):
        if cols[c]:
            cur.append(c)
        elif cur:
            out.append(cur); cur = []
    if cur:
        out.append(cur)
    chars = []
    for cols_idx in out:
        c0, c1 = cols_idx[0], cols_idx[-1] + 1
        chars.append([row[c0:c1] for row in bm])
    return chars

def denoise(bm):
    h, w = len(bm), len(bm[0])
    g = [list(r) for r in bm]
    for y in range(h):
        for x in range(w):
            if g[y][x] == '#':
                n = sum(1 for dy, dx in ((1,0),(-1,0),(0,1),(0,-1)) if 0 <= y+dy < h and 0 <= x+dx < w and bm[y+dy][x+dx] == '#')
                if n == 0:
                    g[y][x] = '.'
    return ["".join(r) for r in g]

def crop_rows(bm):
    top = next((y for y, r in enumerate(bm) if '#' in r), 0)
    bot = next((y for y in range(len(bm)-1, -1, -1) if '#' in bm[y]), len(bm)-1)
    return bm[top:bot+1]

def match(char_bm, templates=FONT):
    best, bestd = None, 10**9
    ch = crop_rows(denoise(char_bm))
    for d, tpl in templates.items():
        cand = [r + '.' * max(0, len(tpl[0]) - len(r)) for r in ch]
        for dy in (-1, 0, 1):
            for dx in (-1, 0, 1):
                dd = 0
                for y in range(len(tpl)):
                    yy = y + dy
                    row = cand[yy] if 0 <= yy < len(cand) else '.' * len(tpl[y])
                    for x in range(len(tpl[y])):
                        xx = x + dx
                        cv = row[xx] if 0 <= xx < len(row) else '.'
                        if cv != tpl[y][x]:
                            dd += 1
                if dd < bestd:
                    bestd, best = dd, d
    return best, bestd

def read_digits(bm, expect=None):
    segs = seg_cols(bm)
    if expect is not None and len(segs) != len(expect):
        return None  # 分割数与期望不符（字形粘连/断裂）——调用方应降级人工判读
    return "".join(match(c)[0] for c in segs)

def synth(digits, seed):
    rng = random.Random(seed)
    h, gap = 9, rng.randint(2, 3)
    glyphs, width = [], 0
    for dch in digits:
        g = FONT[dch][:]
        dy = rng.choice((0, 1))
        g = ["." * 5] * dy + g + ["." * 5] * (h - len(g) - dy)  # 行填充按模板宽度 5
        gw = 5 + (1 if rng.random() < .3 else 0)
        glyphs.append((g, gw))
        width += gw + gap
    rows = [['.'] * width for _ in range(h)]
    x = 0
    for g, gw in glyphs:
        for y in range(h):
            for xi, cv in enumerate(g[y]):
                if cv == '#':
                    xx = x + xi
                    if 0 <= xx < width:
                        rows[y][xx] = '#'
        x += gw + gap
    bm = ["".join(r) for r in rows]
    # 噪声设计：①挖 2 个笔画孔（测鲁棒性，不影响分割）②加 1 个附着点（落在已有笔画列相邻位，永不落间隙）
    holes = [(y, x) for y in range(h) for x in range(width) if bm[y][x] == '#']
    for y, x in rng.sample(holes, min(2, len(holes))):
        bm[y] = bm[y][:x] + '.' + bm[y][x+1:]
    occupied = [x for x in range(width) if any(bm[y][x] == '#' for y in range(h))]
    if occupied:
        x = rng.choice(occupied)
        ys = [y for y in range(h) if bm[y][x] == '.']
        if ys:
            y = rng.choice(ys)
            bm[y] = bm[y][:x] + '#' + bm[y][x+1:]
    return bm

def selftest():
    rng = random.Random(2026)
    total, ok = 0, 0
    for t in range(6):
        digits = "".join(rng.choice("0123456789") for _ in range(4))
        bm = synth(digits, 100 + t)
        got = read_digits(bm, expect=digits)
        total += 1
        if got == digits:
            ok += 1
            print(f"PASS #{t}: {digits} → {got}")
        else:
            print(f"FAIL #{t}: {digits} → {got}")
    print(f"OCR 合成闭环: {ok}/{total}")
    return ok == total

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--image"); ap.add_argument("--selftest", action="store_true")
    ns = ap.parse_args()
    if ns.selftest:
        sys.exit(0 if selftest() else 1)
if not ns.image:
    ap.error("需要 --image（PBM P1 或 #/. 文本位图）或 --selftest")
# v5.1.2 P1 修复：原加载器只接受 #/. 文本行，按文档喂标准 PBM P1（P1 头+0/1 数字）会
# 得到空位图 → max() on empty 崩溃。现双格式兼容：P1 头识别 + 0/1→#/. 映射（1=黑=#）。
_bm_lines = [l.strip() for l in open(ns.image, encoding="utf-8") if l.strip()]
if _bm_lines and _bm_lines[0].upper().startswith("P1"):
    _bm_lines = [l for l in _bm_lines[1:] if l and not l.startswith("#")]
    _bm_lines = [l for l in _bm_lines if set(l) <= {"0", "1", " "}]
    bm = [l.replace(" ", "").replace("0", ".").replace("1", "#") for l in _bm_lines if l]
else:
    bm = [l for l in _bm_lines if set(l) <= {"#", "."}]
if not bm:
    print("错误: 位图为空——输入须为 PBM P1（P1 头+0/1）或 #/. 文本位图"); sys.exit(1)
print(read_digits(bm))
