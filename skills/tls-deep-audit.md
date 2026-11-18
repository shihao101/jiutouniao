---
id: tls-deep-audit
title: TLS 深度审计（协议套件/证书链/降级/客户端证书/应用层信任）
tags: tls,ssl,证书,降级,协议,s2,s4
---
# TLS 深度审计

此前 TLS 仅作为假设矩阵筛查行存在；本手册给出独立的协议级深度审计闭环。适用：存在 HTTPS/TLS 服务的目标（几乎所有项目）。

## 步骤

1. **套件与协议版本测绘**：`nmap --script ssl-enum-ciphers -p 443 <host>`（逐版本套件枚举）+ `testssl.sh`（若 install_tool 可得）。判据：TLS1.0/1.1 在用=中危；3DES/RC4/EXPORT 套件=高危（CWE-327）。
2. **证书链与生命周期**：`openssl s_client -connect host:443 -showcerts`——链完整性（缺中间证书）、自签/域名不匹配/过期（低危信息类）、弱签名算法（SHA-1=中危）、SAN 覆盖缺口。Wildcard 滥用面（`*.t` 泄露 → 联动子域接管面评估私钥暴露影响）。
3. **降级与重协商**：`openssl s_client -tls1` 强制旧版本是否被接受；insecure renegotiation（`openssl s_client` + R 标志）；TLS1.3 降级诱导（SSRF 内网场景 SDK 强制旧版——联动 ssrf-deep 元数据接口）。
4. **客户端证书（mTLS）面**：服务端是否 RequestClientCert；缺失时匿名可访问"预期 mTLS"端点=认证缺口；证书可复用性（client cert 无绑定 → 联动凭据仓库 origin=real kind=header 登记 p12 指纹）。
5. **应用层信任缺陷**：服务端忽略 SNI/Host 校验；HTTP→HTTPS 混合内容与 HSTS 缺失（低危）；**证书校验被禁用的客户端**（App 侧联动 app-static-audit 的网络安全配置检查——`allowBackup`/`networkSecurityConfig`）。
6. **记账**：每项 update_coverage（vuln_class="tls-<子类>"）；负结果 observed_result=negative_valid。

## 判据

- 确证：弱协议/套件被真实握手接受（非仅声明）；mTLS 缺失匿名可达；降级成功。
- 排除：仅"建议升级"类信息项 severity=低/信息，不标"中"。

## 工具探针

`which testssl.sh nmap openssl`——openssl 基线必有；testssl 缺失 → nmap 脚本+openssl 手工矩阵降级，VT 注明降级。

## Execution Profile 标注（v5.3.2）

全只读（L0）生产档可执行；客户端证书导入属凭据仓库纪律（掩码登记）。

## 关联技能

hypothesis-matrix（TLS 筛查行）、ssrf-deep（SDK 降级组合）、app-static-audit（客户端侧证书校验）、weak-cred-bruteforce（mTLS 缺失后的认证面）。
