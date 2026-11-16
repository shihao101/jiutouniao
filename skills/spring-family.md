---
id: spring-family
title: Spring 全家桶武器化手册（Actuator/SpEL/H2/Spring4Shell）
tags: spring,actuator,rce,s4
---
# Spring 全家桶（三通道之③组件剧本）

## 一、Actuator 滥用（/actuator/* 暴露面）

```bash
for ep in env heapdump mappings beans configprops gateway/restart logfile jolokia; do
  curl -sk -o /dev/null -w "$ep %{http_code} %{size_download}\n" "https://目标/actuator/$ep"
done
# /env：查看明文属性与占位符；敏感项（password/key）只记录存在+前4字符
# /heapdump：下载后 strings 检索 password/token/jdbc（数据不出证，只做存在性证明）
# /gateway（Spring Cloud Gateway）：结合 CVE-2022-22947 路由注入 → 无害回连探针 → S5
```

## 二、SpEL 注入（参数化表达式）

```bash
# 探针：算术求值差异（无害）
curl -sk 'https://目标/search?name=${7*7}' | grep -o '49\|${7*7}'
# 位置：搜索框/排序参数/REST 路径变量/错误消息回显点
# 确证后 T（Runtime）类利用转 S5
```

## 三、H2 Console / Spring4Shell 前提检测

```bash
curl -sk -o /dev/null -w "h2console %{http_code}\n" https://目标/h2-console
# Spring4Shell（CVE-2022-22965，ClassLoader 模块访问变动——编号以检索输出为准）前提：JDK9+ + war 部署 + Tomcat +
# 参数绑定到非基础 POJO——逐项核对后再构造探针，前提不满足即 ruled_out
```

## 纪律

- Actuator 信息只做存在性证明（计数/哈希），敏感值不下载不外传
- RCE 类验证一律 S5 审批；本阶段到「探针确证可达」为止
