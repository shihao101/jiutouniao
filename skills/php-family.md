---
id: php-family
title: PHP 生态武器化手册（反序列化/phar/session/upload_progress）
tags: php,反序列化,phar,session,filter-chain,s4
---
# PHP 生态手册（三通道之③组件剧本；cms-playbook 覆盖具体 CMS，本手册覆盖语言级面）

## 一、反序列化面

```bash
# 探测： unserialize 入口定位（参数直接进 unserialize；Cookie/日志/缓存载体）
# POP 链判据：目标源码可得（path-traversal php://filter 读）→ 现场分析可用 gadget（框架魔法函数）
# 无源码：框架指纹 → 对应框架已知 gadget 链检索（cve-weaponization: phpggc 库命中判断）
# phar:// 触发（file 参数/上传校验函数）：phar 读任意文件判据 + phar 反序列化触发条件（仅判据）
```

## 二、LFI→RCE 候选链（判据级，利用转 S5）

- **filter 链**（无依赖 require 任意文件 → 内容可控）：php://filter 链式编码判据（产出已知前缀字符串）→ RCE 候选转 S5。
- **session 包含**：session 文件路径约定（/tmp/sess_）+ 用户可控 session 内容判据。
- **upload_progress**：session.upload_progress.enabled + PHP7.x → 竞态包含判据（受控并发，race-condition 纪律）。
- **日志包含**：access/error log 回写可控内容判据 → S5。

## 三、语言级配置面

```bash
# phpinfo 泄露面（upload_tmp_dir/open_basedir/disable_functions 现状）
# /proc/self/environ（PHP-FPM）→ 环境变量存在性
# PHP8 JIT/字符串注入等年代差异；eval 类型面（代码注入位：e modifier 旧函数/create_function 历史）
```

## 四、纪律

- gadget 链构造属利用级：**源码级分析与判据在 s4；实际 pop 链执行转 S5 审批**（与 java-deser 同口径）。
- 禁止在目标写 PHP 探针文件（上传写文件走 upload-bypass 判据+S7 清理）。
