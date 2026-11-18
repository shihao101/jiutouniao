---
id: whitebox-sca-taint
title: SCA 依赖分析 + 污点候选细化（source/sink 表 + 跨函数路径三问）
tags: 白盒,SCA,依赖,污点,sink,0day,s4
---
# SCA 依赖分析 + 污点候选细化

whitebox-source-audit 的细化层：先依赖面（已知组件已知坑），再污点面（未知组合的 sink 候选）。产出全部是**候选**——未经动态验证不得进 findings。

## 一、SCA 依赖分析

1. **依赖清单提取**（按栈）：
   - Go：`go list -m all`（有 go.mod）；Java：`mvn dependency:tree` / 解析 pom.xml；Python：`pip list --format=json` / requirements.txt；JS：`npm ls --depth=1` / package.json+lock。
2. **版本风险比对**：对每个依赖+版本在本地知识内比对已知 CVE/Advisory（离线优先；联网查询仅限 scopeGate 白名单数据源）。命中 → 直接走 cve-weaponization。
3. **间接依赖降级面**：lockfile 缺失时，间接依赖版本不可信 → upsert_fact（confidence=tentative）+ VT 注明「版本未锁定，需运行时指纹核对」。
4. **判据**：依赖风险成立需「版本精确匹配 + 可达入口（该依赖真的被业务代码调用）」两要件；只匹配版本不核对调用面 = 疑似。

## 二、sink/source 检索表（按语言）

| 语言 | source（外部输入入口） | sink（高危汇聚点） |
|---|---|---|
| Java | request.getParameter/getHeader/getInputStream、@PathVariable | Runtime.exec、ProcessBuilder、Statement.execute、ObjectInputStream.readObject、JNDI lookup、SpelExpressionParser.parse |
| Python | request.args/form/files、sys.argv、socket.recv | eval/exec、pickle.loads、os.system/popen、subprocess(shell=True)、yaml.load(非safe)、sqlalchemy.text 拼接 |
| Go | r.URL.Query()/FormValue/Body、Header.Get | exec.Command(拼接)、sql.Query(fmt.Sprintf)、template.HTML、unmarshal 到 interface{} 后反射 |
| JS/TS | req.query/body/params、window.location | child_process.exec、eval、vm.runInContext、innerHTML、node-serialize serialize |
| PHP | $_GET/$_POST/$_REQUEST、php://input | eval、assert、system/shell_exec/passthru、unserialize、include/$var 文件包含 |

探针示例（ripgrep，Java）：
`rg -n "Runtime\.getRuntime\(\)\.exec|ProcessBuilder|readObject\(|InitialContext.*lookup" source/ --type java`
每条命中 → 追溯调用链三问（外部可达？拦截？前置条件？）→ record_vt。

## 三、污点候选细化为可验证假设

每个 sink 候选输出四元组：`source 位置 → 传播路径（函数链）→ 拦截点（有/无/可绕）→ 最小验证请求`。验证请求交给对应黑盒技能实测（hypothesis-0day 差异法兜底）。

## 判据与记账

- 静态命中 ≠ 漏洞：无传播路径证据的 sink 命中 = tentative 事实，不入 findings。
- 每条候选 record_vt（priority：可达路径完整=1-2、路径推断=3-4、仅命中=6）。
- 排除候选必须引用代码行号（update_vt closed-roe + evidence 摘录）。

## 工具可用性探针

`which semgrep go mvn npm pip rg`——缺失逐项降级（semgrep→rg 正则表；包管理器缺失→手工解析 manifest 文件），全部降级仍可出候选，VT 注明分析精度。

## Execution Profile 标注（v5.3.2）

全只读（L0）生产档可执行；依赖库联网比对仅限 scopeGate 白名单数据源；源码不外传。

## 关联技能

whitebox-source-audit（上层流水线）、patch-diffing（版本差分）、cve-weaponization（SCA 命中已知 CVE）、hypothesis-0day（候选验证）。
