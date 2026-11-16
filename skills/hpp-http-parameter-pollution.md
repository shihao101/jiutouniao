---
id: hpp-http-parameter-pollution
title: HTTP 参数污染 HPP（框架行为矩阵+组合拳）
tags: HPP,参数污染,WAF绕过,s4
---
# HTTP 参数污染（HPP）

**定位**：同名参数出现多次时，**前端校验器与后端取值可能取不同那份**——差值即绕过空间。

## 一、框架取值矩阵（9 框架）

PHP/Apache：**last**；ASP.NET：逗号拼接（`1,1`）；JSP/Go/servlet：**first**；Flask：first vs Django：last；Rack：last；Express：变数组。判据：注入探针（`?id=1&id=PROBE`）看后端 echo/行为取哪份。

## 二、组合拳四场景

1. **WAF 绕过**：`?id=1&id=1 UNION SELECT...`（WAF 检查 first、应用取 last）；
2. **SSRF**：`?url=合法域&url=169.254.169.254`（校验器取 first、fetcher 取 last）；
3. **CSRF**：`?csrf=真token&csrf=假`（校验与执行各取一份）；
4. **支付**：`?amount=1&amount=5000`（价格校验与入账差值）。

## 三、变体

JSON 重复键（JSON.parse 保 last）：`{"id":1,"id":2}`；Content-Type 混淆（form ↔ JSON 双发）；HPP+缓存键差异。

## 四、纪律

先单变量探针确认框架行为再组合；支付类差值验证走最小金额；命中 record_finding（CWE-436）。

### 载荷形态补全

四类形态：数组 `id[]=1&id[]=2`；数组+标量混合 `item[]=a&item=b`；编码 & 差分 `param=v1%26other=v2`（字面 & vs 新键对）；嵌套括号键 `user[name]=a&user[role]=user&user[role]=admin`。multipart 重复 part（POST body 变体，同 name 两段）。顺序敏感性：`a=1&a=2` 与 `a=2&a=1` 都发。支付变体：`quantity=1&quantity=-1`、`price=9.99&price=0.01`、`user=alice&user=admin`。