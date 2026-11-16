---
id: password-offline
title: 离线密码攻击与字典工程（hashcat/口令生成/撞库口径）
tags: 密码,hashcat,字典,离线破解,kerberoast,s5,s6
---
# 离线密码攻击与字典工程

**定位**：拿到哈希/票据/密文后的离线破解（与 weak-cred-bruteforce 的在线爆破、ad-attack 的 Kerberoast 对接）。**合规门**：离线破解对象仅限测试中自获的哈希/票据；ROE 未明确允许破解用户真实口令时，只做"可破解性证明"（跑前 1000 条常用候选）。

## 一、hashcat 模式速查（按来源选 -m）

| 哈希来源 | -m 模式 |
|---|---|
| Windows NTLM（SAM/ secretsdump） | 1000 |
| Kerberos TGS（Kerberoast） | 13100 |
| Kerberos AS-REP | 18200 |
| Linux sha512crypt（/etc/shadow） | 1800 |
| MySQL 5.x | 300 |
| MSSQL | 1717（2012+） |
| bcrypt（Web 应用常见） | 3200（慢，限 2-3 条候选） |
| JWT 密钥爆破 | 16500 |

## 二、字典工程（国内场景命中率优先）

1. **基础层**：rockyou 前 1000（可破解性证明口径）。
2. **规则层**：`best64.rule` + 中文站常见变换（`@`/`#`/`123`/`!`/年份 2024-2026 后缀）。
3. **生成层**（从 OSINT 合规材料生成候选，不做社工库查询）：
   - 单位拼音缩写 + 年份（如 `abc@2024`、`Abc2024!`）——仅用名称公开片段；
   - 默认口令族：`admin123/Aa123456/admin@123/test123/123qwe`；
   - 技术栈默认：`spring/k8s 中间件默认凭据清单`（devops-exposed 对接）。
4. **掩码策略**：已知格式时用掩码（`?u?l?l?l?d?d?d?d`）而非纯枚举。

## 三、执行纪律

- **限资源**：hashcat 用 `--limit`/规则分段，禁全字典+全规则组合（评测与生产机都拖不起）；
- **结果口径**：破解成功 → record_loot(type=hash, masked=`前3***后2`, verified=verified) + 记录明文**不落库**；破解失败 → upsert_fact(deprecated, "前 1000 候选未命中") 防重复跑；
- **撞库（credential stuffing）默认禁止**：需 ROE 明确允许 + 目标方书面同意 + 严格限速（≤1 次/账号/分钟）；未允许则只在报告"风险推演"章节做数学评估（如同一口令在两个系统的复用面）。
- 与 Kerberoast 对接：TGS 票据破解只跑弱口令层，命中即证明"服务账号口令强度不足"这一影响，不追求全部破解。
