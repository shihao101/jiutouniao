---
id: dotnet-family
title: .NET 生态武器化手册（ViewState/反序列化/IIS 面）
tags: dotnet,aspnet,viewstate,machinekey,iis,s4
---
# .NET 生态手册（三通道之③组件剧本）

## 一、ViewState 面（ASP.NET WebForms 高频）

```bash
# 探测：__VIEWSTATE 参数存在；mac 校验判定：
#   改动 ViewState 字节后提交 → 500 MAC 验证失败=已启用 MAC（无利用面）
#   200 正常响应=未启用验证 → 反序列化面（cwe-502，高危）
# machineKey 泄露源：web.config 经 path-traversal/上传覆盖/git 泄露（frontend-sca 联动）
#   → machineKey 已知时 ViewState 反序列化可用（判据=无害 payload 回显差异）→ S5
# ASP.NET 版本指纹：X-AspNet-Version 头、aspxerrorpath 行为、404 页样式
```

## 二、IIS 面

```bash
# 短文件名枚举：GET /*~1*/a.aspx / *~1* 404 vs 403 差异判据（IIS 短文件名猜解，限速）
# web.config 泄露：/web.config、/bin/*.dll 直下（判据 404/200）
# 解析形态：x.asp;.jpg、/x.asp/ 目录（upload-bypass 联动）
# WebDeploy/远程管理端口 8172 → 版本/证书指纹 → S5
```

## 三、反序列化面（.NET Framework/Core）

- BinaryFormatter/DataContractSoap/Json.NET TypeNameHandling 入口定位（Cookie/视图状态/配置载体）。
- 报错含 `TypeResolver`/`$type` 字段回显 → 反序列化可控判据；gadget（ObjectDataProvider 等）**仅做存在性判断，执行转 S5**（ysoserial.net 类工具经授权现场使用）。

## 四、纪律

- ViewState 未验证场景 = 直接 record_finding（确证级）；machineKey 已知场景升级定级并注明泄露源。
- 全部判据无害（字节改动/报错差异）；.NET gadget 执行属高危利用，S5 强审批。
