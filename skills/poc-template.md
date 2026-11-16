---
id: poc-template
title: PoC 脚本编写规范与模板
tags: poc,脚本,python,s5
---
# PoC 脚本规范与模板（write_file 写入工作区 poc/ 后运行）

## 规范
1. 每个漏洞一个独立脚本：`poc/<编号>_<漏洞名>.py`。
2. 目标/参数从命令行或环境变量读取，不硬编码。
3. 输出结构化结论：`[VULN]`/`[SAFE]`/`[ERROR]` + 证据（响应片段）。
4. 默认最小影响：只读验证优先；破坏性动作不存在于九头鸟的 PoC 中。
5. 超时与重试内置；失败 2 次即停。

## 模板
```python
#!/usr/bin/env python3
"""PoC: <标题>  用法: python3 poc.py <base_url> <param>
判定纪律（v5.1，与 hypothesis-0day/evidence-standard 对齐）：
单变量差异 + 归一化基线 + 每组 2 遍复测——禁止仅凭长度差/状态码下 [VULN]。"""
import sys, time, requests

def norm(t):  # 归一化：剥离动态位（时间戳/nonce/token/轮播序号），按位符提取
    import re
    return re.sub(r"\d{10,13}|[a-f0-9]{16,}", "", t or "")

def probe(base, param):
    # 1) 基线 ×1 + 载荷 ×2（复测排除抖动）
    r0 = requests.get(base, timeout=10)
    verdicts = []
    for _ in range(2):
        r1 = requests.get(base, params={param: "' OR '1'='1"}, timeout=10)
        diff = norm(r1.text) != norm(r0.text)          # 归一化内容差分（非长度）
        verdicts.append((r1.status_code == 200, diff, r1.text[:200]))
        time.sleep(2)
    # 2) 判定：两遍复测结论一致才可输出
    if all(v[0] and v[1] for v in verdicts):
        print(f"[VULN] 参数 {param} 差异稳定复现（归一化内容差分×2）")
        print("证据:", verdicts[0][2]);  return True
    if any(v[1] for v in verdicts):
        print("[SUSPECT] 差异不稳定——按 hypothesis-0day 单变量排查动态位后复测")
        return False
    print(f"[SAFE] {param} 无差异");  return False

if __name__ == "__main__":
    probe(sys.argv[1], sys.argv[2])
```

## 上线前检查单
- [ ] 仅针对授权目标；- [ ] 无破坏性语句；- [ ] 超时已设置；- [ ] 输出含证据；
- [ ] 运行命令走审批（L2）；- [ ] 结果 update_coverage。

## 复现证据标准（Burp 原文对照，强制）

- **单一事实源（v5.1）**：复现证据的捕获方式与呈现格式以 `report-writing.md`「复现证据标准」节为准（本文件原内联副本已去除——双维护曾致口径漂移风险）；PoC 输出证据按该标准落 `evidence/` 并在 findings claims 引用。
- **v5.3.6 字段化承载**：登记发现（record_finding）时把实测的原始请求/响应对写入 `poc` 参数（逐字誊写、≤5 组，Web 漏洞页 Burp 式双栏展示），修复措施写入 `remediation` 参数——证据编号由引擎自动关联，无需显式提供。
