---
id: "00-router"
title: 技能路由器（资产类型/症状 → 技能映射总索引）
tags: 路由,索引,总览,s2,s3,s4,s5
---
# 技能路由器（先查我，再动手）

> 用法：按「资产类型」或「症状」找到技能 id → load_skill(id) 载入。本表是全集索引；各阶段头仅列目录，**以本表为准**。

## 一、按资产/指纹类型

| 遇到什么 | 首选技能 | 配合 |
|---|---|---|
| Java 中间件/反序列化特征（rO0AB/Shiro/Fastjson/Log4j） | java-deser-playbook | cve-weaponization |
| Spring Boot/Actuator/SpEL 特征 | spring-family | cve-weaponization |
| Tomcat/WebLogic/Nacos/Jenkins/MinIO 等中间件 | middleware-web | cve-weaponization |
| ThinkPHP/WordPress/通用 CMS | cms-playbook | cve-weaponization |
| 已知组件版本（任何） | cve-weaponization | nuclei-usage |
| 登录口/后台/默认口令面 | weak-cred-bruteforce | — |
| 登录口加密协议（JS/WASM 加密/动态挑战 token/验证码渲染/UA 指纹过滤） | browser-auth | auth-bypass |
| 测试项需要登录态（登录后注入/越权矩阵/存储型/逻辑滥用/注册面评估） | session-state-chain | auth-bypass |
| 前端 bundle/依赖/ source map | frontend-sca | — |
| 侦察/资产测绘/子域与端口方法论总纲（S2） | recon-playbook | intel-factory |
| 常规 Web 面 OWASP Top10 逐项清单 | web-top10 | injection-points |
| APP 动态链实操（root/抓包/Frida/绕过） | app-dynamic-audit | app-static-audit |
| 小程序解包与客户端审计实操 | miniapp-audit | miniapp-server |
| PoC 脚本编写规范与模板 | poc-template | report-writing |
| SQL 注入（任意位置） | sqli-deep | injection-points |
| 模板渲染异常/报错 | ssti-engine-map | — |
| XML/文档解析入口 | xxe-full | oob-interactsh |
| 文件上传点 | upload-bypass | — |
| 路径/文件参数 | path-traversal | — |
| 命令执行迹象（回显/耗时/外联） | cmdi-deep | oob-interactsh |
| 盲注/无回显类（SSRF/XXE/RCE/SQLi） | oob-interactsh（先架回连） | 对应漏洞技能 |
| Web 缓存/CDN 特征 | cache-poisoning | — |
| 前后端参数长度不一致/超长值异常 | request-smuggling | — |
| Node.js 应用/JSON merge 行为 | prototype-pollution | — |
| OAuth/重置/MFA/会话面 | auth-flow-deep | jwt-crypto |
| GraphQL 端点 / WebSocket | graphql-websocket | api-idor |
| 云元数据/容器/k8s 特征 | cloud-security | privesc-checklist |
| K8s API/kubelet/etcd/Dashboard/SA token | k8s-attack | cloud-security |
| 拿到哈希/票据/密文（离线破解面） | password-offline | weak-cred-bruteforce |
| 权限维持演示/计划任务/启动项 | persistence | webshell-memshell |
| 邮件域 SPF/DMARC/钓鱼可达性 | phishing-infra | mail-postex |
| 短信验证码/改绑/激活流程 | logic-sms-otp-matrix | auth-flow-deep |
| JS 挑战型 WAF（$_ts/瑞数）特征 | js-challenge-waf-playbook | channel-snapshot |
| 限速/连接级阻断（000 突发、扫描后全 filtered） | rate-limit-playbook | scan-tiering |
| 全封闭站（未授权路径统一 403/508/502） | closed-site-playbook | payload-mutation-algebra |
| 网关统一 token 鉴权 + 精确白名单（401 invalid token） | gateway-filter-playbook | api-idor |
| 安全设备/管理面（自签证书、登录加密、UA 过滤） | appliance-mgmt-playbook | browser-auth |
| 通道快照/cookie 重放/通道失效判定 | channel-snapshot | browser-auth |
| 主 bundle/chunk/运行时配置/source map 情报提取 | intel-factory | frontend-sca |
| 前端加密/签名协议（MD5 拼接/SM4/WASM）已还原待投递 | crypto-offensive | authz-diff |
| 鉴权差分矩阵（无 token 端点批量判读） | authz-diff | api-idor |
| 教育信息化族（金智 ehall/正方/青果教务、VSB/博达网站群、超星） | edu-family | anon-attack-surface |
| 统一身份认证（CAS/Shibboleth IdP/深澜 srun） | idp-family | auth-flow-deep |
| 子域 CNAME 悬挂/接管指纹判定 | subdomain-takeover | anon-attack-surface |
| 工具在挑战型 WAF/封闭站下的通道适配（M6 单源） | tool-channels | channel-snapshot |
| 限购/首单/会员/订阅/签到权益 | logic-purchase-limit | race-condition |
| 4-6 位验证码有效期长/响应含 code | logic-sms-otp-matrix | weak-cred-bruteforce |
| 支付地址可重复付款/首单可重复 | logic-purchase-limit | logic-csrf-deser |
| 按次付费接口（实名/短信/活体） | capability-primitive-search（BURN 原语） | api-idor |
| 模板/样式表/公式渲染入口 | xslt-injection | ssti-engine-map |
| LDAP/XPath/SSI/LaTeX 解析入口 | extra-injection-types | injection-points |
| 点击劫持（无 XFO/frameable） | clickjacking | report-writing |
| PHP 弱比较/0e 哈希/strcmp 数组 | type-juggling | php-family |
| 内部包名泄露/私有 registry | dependency-confusion | devops-exposed |
| 同名参数多次出现 | hpp-http-parameter-pollution | injection-points |
| 响应头参数反射（Location/Set-Cookie） | crlf-injection | cors-redirect-hostheader |
| 教育/高校资产（edu.cn） | edu-src-playbook | edge-vpn-bastion |
| Jenkins/GitLab/制品库 | devops-exposed | middleware-web |
| 内网立足点（已获访问） | intranet-lateral | privesc-checklist |
| 提权（Linux/Windows/容器） | privesc-checklist | — |
| AI/LLM 应用 | llm-top10 + llm-payloads | specA 头 |
| APP/小程序 | specB1/B2 头 | app-static-audit |
| 致远/泛微/用友/通达/蓝凌 OA | oa-family | weak-cred-bruteforce |
| Go 生态/pprof/etcd/consul/Prometheus/Grafana/Harbor | go-backend | cve-weaponization |
| PHP 反序列化/phar/filter 链 | php-family | path-traversal |
| .NET/ViewState/IIS 短文件名 | dotnet-family | path-traversal |
| 域环境/AD/Kerberos/ADCS | ad-attack | intranet-lateral |
| Windows 主机横向/凭据转储/密码喷洒 | windows-lateral | ad-attack |
| 边界设备/SSL VPN/防火墙管理面 | edge-vpn-bastion | cve-weaponization |
| 堡垒机（JumpServer/商用堡垒机） | edge-vpn-bastion | weak-cred-bruteforce |
| 命令执行落点/webshell/内存马驻留 | webshell-memshell | capability-primitive-search |
| 数据库后渗透（redis/mysql/mssql/pgsql/mongo） | database-postex | privesc-checklist |
| 内网隧道/流量中转 | tunnel-pivot | intranet-lateral |
| 邮件系统 OWA/EWS/Exchange | mail-postex | intranet-lateral |
| 加固 APP（梆梆/爱加密/乐固/360） | app-hardening-bypass | app-static-audit |
| iOS APP（IPA） | app-ios-audit | app-static-audit |
| 小程序服务端 API（解包后） | miniapp-server | api-idor |
| Agent/Function calling/MCP 后端 | llm-agent-toolchain | specA 头 |
| 多模态（图片/PDF/语音注入） | llm-multimodal | rag-attack |
| RAG/知识库/向量库 | rag-attack | llm-top10 |
| APP/小程序个人信息合规取证 | app-privacy-compliance | report-writing |
| 无凭证开工 / 认证后功能待测（没有任何账号） | identity-bootstrapping | weak-cred-bruteforce / browser-auth |
| 多目标项目暴露面普查（S2→S4 首轮） | anon-attack-surface | middleware-web / devops-exposed |
| WAF/过滤器特征识别 | waf-fingerprint | payload-mutation-algebra |
| 网关统一路由/多异构后端确证（前置代理+多栈指纹） | request-smuggling | intranet-lateral |
| JWT/会话令牌机制确证或密钥材料泄露（预览/部分密钥） | jwt-crypto | auth-flow-deep |
| SSO/票据/扫码登录机制确证（ticket/QR/回调） | auth-flow-deep | jwt-crypto |
| 同应用多实例/多节点（灰度/双活/同构换实例） | instance-diff | authz-diff |
| 登录态不可得（身份索取闭环走完仍无账号） | observable-degradation | session-state-chain |

## 二、按症状

| 症状 | 查什么 |
|---|---|
| 响应长度/时间随输入变化 | sqli-deep（布尔/时间）+ hypothesis-0day |
| 响应中出现报错/堆栈/SQL 片段 | sqli-deep（报错）+ cve-weaponization（组件版本） |
| 请求无回显但行为可疑（外联/耗时/状态跳变） | oob-interactsh + 对应漏洞技能 |
| 参数怎么改响应都不变 | injection-points（先确认注入点完整性，再 hypothesis-0day 生成差异假设） |
| 模板表达式被原样/求值返回 | ssti-engine-map |
| 同接口不同用户结果不同 | api-idor / logic-csrf-deser（越权矩阵） |
| 明文凭据构造的登录请求连续失败（404/参数名不符/前端加密链路） | browser-auth（真实浏览器代执行页面加密链路，协议逆向降级为可选） |
| CORS 头随 Origin 回显 / 重定向参数可控 / 密码重置链接域可控 | cors-redirect-hostheader |
| 单次操作可被并发多次生效（双花/重复领取/重复兑换） | race-condition |
| swagger/doc.html/api-docs 文档面暴露 | api-doc-leak |
| 导出文件被 Excel 打开出现公式执行 | csv-injection |
| 重定向/URL 拼接点 | ssrf-deep / path-traversal |
| 发现无法解释的异常 | hypothesis-0day（异常→假设→差异→定性四步法） |
| 输入反射到 HTML/JS（页面回显输入） | xss-context / ssti-engine-map |
| MongoDB/JSON 查询语法暴露（$ne/$gt/$regex） | sqli-deep（NoSQL 段） |
| 只有零散低危、无单点高危（各类测试收尾仍构不成 RCE/接管） | capability-primitive-search（原语标注 → RCE 六等式凑链，正向/反向搜索缺口）+ hypothesis-0day |
| 需要证明长期驻留影响 / 域内口令强度 | persistence（四元组登记）+ password-offline（离线可破解性证明） |
| 找 RCE 无头绪（有源码/有组合原语） | rce-hunting-map（信号判据 → 组合拳决策树 → 白盒清单）+ capability-primitive-search |
| 验证码/改绑/限购/支付逻辑存疑 | logic-sms-otp-matrix + logic-purchase-limit（六路径/五变体互备） |
| payload 被拦截/过滤/403/改了没差异 | payload-mutation-algebra（先指纹 12 探针再按七步链变异）+ waf-fingerprint |
| 疑似高危待确证（record_finding 定级前） | evidence-standard（逐类判据+反例）+ hypothesis-0day |
| 无凭证且认证后项待测 | identity-bootstrapping（L1 评估轨→L6 决策树；L2-L6 命中即 session-state-chain；全轨未命中走一a身份索取闭环） |
| 代理配置后工具怎么走代理（$TOOL_PROXY/$JT_EXIT_POOL/工具旗标） | proxy-channels（v5.0 代理通道手册） | exit-pool / rate-limit-playbook |
| s3 威胁建模（筛查矩阵判定/假设三态判定表） | hypothesis-matrix（K3 假设模式库：27 类×三态判定+判定表规范） | industry-templates / framework-priors |
| 行业目标（医疗/金融/教育/政务/企业/互联网）优先级升格与数据类具象 | industry-templates（K1 行业模板六件） | hypothesis-matrix |
| 框架指纹命中（Java/PHP/Python/Node 系）先验假设与首查清单 | framework-priors（K2 框架先验卡四件） | hypothesis-matrix / cve-weaponization |

## 三、开工三件套

project-warmup（预热）→ scan-tiering（分级扫描）→ parallel-execution（后台化/并行）；全程纪律见 loop-core「深度测试纪律 / 速度纪律」。
