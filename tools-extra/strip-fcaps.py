#!/usr/bin/env python3
"""剥离越界文件能力位（v2.5.2 工具修复；v5.1.4 函数化 + --selftest）。

背景：vxcontrol/kali 底座的 nmap 二进制带 fcap=cap_net_admin|cap_net_raw|net_bind_service，
而 Docker 默认不给容器 cap_net_admin（不在 bounding set）→ exec 时内核直接 EPERM。

用法：python3 strip-fcaps.py [--dry-run] ；--selftest 本地合成位图校验解码与越界判定。
"""
import os, struct, sys

# Docker 默认 capability 集合（不含 cap_net_admin）
BOUNDING = ((1 << 0) | (1 << 1) | (1 << 3) | (1 << 4) | (1 << 5) | (1 << 6) | (1 << 7) |
            (1 << 8) | (1 << 10) | (1 << 13) | (1 << 18) | (1 << 27) | (1 << 29) | (1 << 31))
NAMES = {12: "net_admin", 13: "net_raw", 10: "net_bind_service"}
SCAN_DIRS = ["/usr/bin", "/usr/sbin", "/usr/lib", "/bin", "/sbin", "/usr/local/bin", "/opt"]

def permitted_of(raw: bytes):
    """security.capability xattr → permitted 位集（<8 字节非法返回 None）。"""
    if len(raw) < 8:
        return None
    return struct.unpack("<I", raw[4:8])[0]

def extra_names(permitted: int):
    extra = permitted & ~BOUNDING
    return [NAMES.get(b, str(b)) for b in range(41) if extra >> b & 1]

def selftest() -> bool:
    # 合成 xattr：v3 头 + permitted=BOUNDING|net_admin(12)|未知位20 → 应判越界 [net_admin, 20]
    bad = struct.pack("<II", 0x00030000, BOUNDING | (1 << 12) | (1 << 20)) + b"\x00" * 4
    ok1 = extra_names(permitted_of(bad)) == ["net_admin", "20"]
    # 合成干净位集（permitted=BOUNDING）→ 无越界
    ok2 = extra_names(permitted_of(struct.pack("<II", 0x00030000, BOUNDING) + b"\x00" * 4)) == []
    # 短 raw → None
    ok3 = permitted_of(b"\x01") is None
    ok = ok1 and ok2 and ok3
    print(f"selftest: 越界判定={ok1} 干净放行={ok2} 短raw拒绝={ok3} → {'OK' if ok else 'FAIL'}")
    return ok

def main() -> None:
    if "--selftest" in sys.argv:
        sys.exit(0 if selftest() else 1)
    dry = "--dry-run" in sys.argv
    fixed = 0
    for d in SCAN_DIRS:
        for root, _, files in os.walk(d):
            for f in files:
                p = os.path.join(root, f)
                try:
                    raw = os.getxattr(p, "security.capability")
                except OSError:
                    continue
                permitted = permitted_of(raw)
                if permitted is None:
                    continue
                extra = permitted & ~BOUNDING
                if not extra:
                    continue
                names = extra_names(permitted)
                print(f"[fix] {p}  越界能力: {','.join(names)}")
                if not dry:
                    try:
                        os.removexattr(p, "security.capability")
                        fixed += 1
                    except OSError as e:
                        print(f"      剥离失败: {e}")
    print(f"完成：剥离 {fixed} 个" + ("（dry-run 未实际修改）" if dry else ""))

if __name__ == "__main__":
    main()
