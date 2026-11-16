---
id: app-static-audit
title: APP 静态审计手册（jadx/frida）
tags: app,android,静态,frida,specB1
---
# APP 静态审计手册


> **v5.3.0 专项前置契约（结构化记录）**：每条任务登记 artifact_source（客户提供包/合法测试包/公共包）、device_owner（客户设备/测试设备）、test_account（测试账号/租户）、network_route（隔离网络/抓包通道）、test_data（合成数据）、runtime_access（动态环境可用性）、limitations（缺失前置）。**静态线索不得替代动态确证**——设备/账号/包缺失时逐条 needs_follow_up（reason=precondition_missing），不误记为无漏洞。

## 获取与画像
```bash
apktool d app.apk -o out/        # 资源与 manifest
jadx -d jadx-out app.apk         # Java 源码
aapt dump badging app.apk        # 权限、组件、SDK 版本
```
- 识别加固：lib 中 360/腾讯乐固/爱加密特征 so。

## 高危点清单
1. **硬编码密钥**：`grep -rn "AKID\|LTAI\|secret\|api[_-]key" jadx-out/ --include="*.java"`。
2. **加密还原**：AES/DES key 常量、`javax.crypto` 调用点。
3. **WebView**：`setJavaScriptEnabled(true)` + `addJavascriptInterface`、`setAllowFileAccessFromFileURLs(true)`。
4. **导出组件**：manifest 中 `exported=true` 的 Activity/Service/Receiver/Provider；DeepLink scheme。
5. **网络**：`okhttp`/`network_security_config` 配置与证书校验禁用点（TrustManager 空实现）。

## Frida 动态配合
```js
Java.perform(function(){
  var Cipher = Java.use('javax.crypto.Cipher');
  Cipher.doFinal.overload('[B').implementation = function(input){
    var r = this.doFinal(input);
    console.log('[Cipher] ' + this.getAlgorithm() + ' -> ' + bytesToHex(r));
    return r;
  };
});
```

## 纪律
- 静态结论标「待动态验证」；hook 产物仅授权测试用；写操作（支付/下单）先审批。
