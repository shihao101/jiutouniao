---
id: miniapp-audit
title: 小程序测试手册（wxapkg/云开发）
tags: 小程序,wxapkg,云开发,specB2
---
# 小程序测试手册


> **v5.3.0 专项前置契约（结构化记录）**：每条任务登记 artifact_source（客户提供包/合法测试包/公共包）、device_owner（客户设备/测试设备）、test_account（测试账号/租户）、network_route（隔离网络/抓包通道）、test_data（合成数据）、runtime_access（动态环境可用性）、limitations（缺失前置）。**静态线索不得替代动态确证**——设备/账号/包缺失时逐条 needs_follow_up（reason=precondition_missing），不误记为无漏洞。

## 解包还原
```bash
wxappUnpacker ./xxx.wxapkg    # 还原 wxml/wxss/js/json（unveilr 已停止分发，环境内置 wxappUnpacker）
```
- 优先读 app.js（全局逻辑）、app.json（页面树/隐藏页面）、project.config.json（appid）。

### PC 加密包解密（V1MMWX 魔数）
- 判别：`xxd -l 16 xxx.wxapkg` 首字节为 `5631 4d4d 5758`（`V1MMWX`）= PC 端微信下载的加密包，wxappUnpacker 直接解会报 wuLib 读文件错误——**必须先解密再解包，不要盲试变体**。
- 标准算法（对齐 BlackTrace/pc_wxapkg_decrypt，实测验证）：
  1. `key = PBKDF2-HMAC-SHA1(AppID, salt="saltiest", 1000 轮, 32 字节)`；`iv = "the iv: 16 bytes"`（固定 16 字节字符串）
  2. AES-256-CBC 解密 `data[6:1030]`（1024B 密文块，含 1B PKCS7 填充），取解密结果前 **1023B** 作为输出头部
  3. 尾部 `data[1030:]` 与单字节 `appid[len-2]`（AppID 倒数第二字符）逐字节 XOR
  4. 输出 = 头部 1023B + XOR 尾部；自校验判据：`out[0]==0xBE`、`out[13]==0xED`、infoList/dataLength 长度自洽——不匹配再考虑变体，不要先盲试
- 现成脚本（openssl 实现，无第三方依赖）：

```python
#!/usr/bin/env python3
"""PC 微信加密 wxapkg 解密（V1MMWX）。用法: decrypt_wxapkg.py <加密包> <AppID> <输出>"""
import hashlib, sys, subprocess, tempfile, os
def decrypt(src, appid, dst):
    data = open(src, "rb").read()
    if data[:6] != b"V1MMWX": print("[!] 非 V1MMWX 格式"); return False
    dk = hashlib.pbkdf2_hmac("sha1", appid.encode(), b"saltiest", 1000, 32)
    with tempfile.NamedTemporaryFile(delete=False) as tf:
        tf.write(data[6:1030]); t = tf.name
    r = subprocess.run(["openssl","enc","-d","-aes-256-cbc","-K",dk.hex(),
                        "-iv",b"the iv: 16 bytes".hex(),"-in",t,"-out",t+".d"], capture_output=True)
    os.unlink(t)
    if r.returncode != 0: print("[!] AES 失败:", r.stderr.decode()[:150]); return False
    head = open(t+".d","rb").read()[:1023]; os.unlink(t+".d")
    xk = appid[-2].encode()[0]
    out = head + bytes(b ^ xk for b in data[1030:])
    open(dst,"wb").write(out)
    ok = out[0]==0xBE and len(out)>14 and out[13]==0xED
    print(f"[{'✓' if ok else '!'}] {dst} ({len(out)}B)"); return ok
sys.exit(0 if decrypt(*sys.argv[1:4]) else 1)
```
- 解密成功后再走 wxappUnpacker 还原；插件包（`__PLUGINCODE__`）单独报错属正常，需主包配合分析。

## 配置与密钥审计（W2）
- `grep -rn "AppSecret\|envId\|accessKey" 还原目录/` —— Secret/envId 泄露=高危。
- request 合法域名清单 → 未覆盖的接口域名往往是后台/测试环境。
- source map 残留：`*.map` 文件 → 直接还原源码。

## 前端逻辑（W3）
- 会员/优惠券/抽奖判定：找 `if (price`、`if (vip`、`amount` 前端可控点 → 服务端是否复算？
- 隐藏页面：app.json 未挂 tabbar 的管理/调试页。

## 接口与鉴权（W4）
- 抓包（PC 端微信 + 代理）取签名规律；Agent 复用签名构造：
  - 水平越权：替换 userId/openId/orderId（测试账号 B）。
  - token 刷新缺陷、签名时间戳重放。

## 云开发（W5）
- 云函数：未授权调用（无登录态）、参数注入。
- 云数据库：security rules `read: true/write: true` 即越权读写；云存储遍历。

## 纪律
- 只用测试账号/测试环境；涉及支付与真实用户数据先审批；解包产物禁止分发。

## 小程序反编译精确流程

- PC 微信缓存目录 `WeChat Files/Applet/` 取 wxapkg
- 主包：`node wuWxapkg.js 主包.wxapkg`；**子包必须带 `-s=主包路径`**：`node wuWxapkg.js __WITHOUT_MULTI_PLUGINCODE__.wxapkg -s=...主包.wxapkg`——主包与子包都要解码，漏 -s 会丢页面依赖