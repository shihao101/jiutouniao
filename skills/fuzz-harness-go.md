---
id: fuzz-harness-go
title: Go 原生 Fuzz Harness 模板与 checkpoint 长作业纪律
tags: fuzzing,go,harness,模板,长任务,s4
---
# Go 原生 Fuzz Harness（模板 + 长作业纪律）

Go ≥1.18 内置 fuzzing（无插桩依赖，最快的落地路径）；本手册给 harness 模板与 run_async 长作业的 checkpoint 纪律。仅用于**自建/副本环境**（fuzzing-workflow 档位约束）。

## Harness 模板

```go
// fuzz/fuzz_<target>_test.go（与被测包同 module；go test -run=^$ -fuzz=FuzzXxx）
package <pkg>

import (
    "testing"
    // 被测解析器：如 "target/parser"
)

func FuzzParse(f *testing.F) {
    // 1) 种子语料：真实样本 + 边界值（空/超长/全 0xFF/嵌套深）
    f.Add([]byte("normal-payload-line"))
    f.Add([]byte{0xFF, 0xFE, 0x00})
    f.Add([]byte(strings.Repeat("A", 4096)))
    // 2) 变异入口：把字节流转成被测入口（还原真实输入路径）
    f.Fuzz(func(t *testing.T, data []byte) {
        // 前置纪律：禁网络/禁文件写/禁 panic 逃逸——被测函数必须是纯解析
        _, err := parser.Parse(data)
        // 3) 不吞错：err 允许返回，但 panic/index-out-of-range/data-race 会被 fuzzer 捕获
        _ = err
    })
}
```

判据：fuzzer 捕获的 **panic/越界/死锁/race** = 候选；业务层返回的 err 不是候选。

## 执行（run_async 长作业纪律）

1. smoke：`go test -run=^$ -fuzz=FuzzParse -fuzztime=30s`——确认 harness 能跑、种子有效；
2. 批次：`go test -run=^$ -fuzz=FuzzParse -fuzztime=30m` 每批 run_async 提交（timeout 对齐）；
3. checkpoint：每批产出的 corpuscache/崩溃样本随工作区持久化，下一批续跑（`-fuzztime` 分批等效长时；**禁止**为躲 7200s 上限一次提交超长任务）；
4. 收口：批次内 poll_async 确认终态；[JT-JOB-END] 缺失 = 被截杀 → 覆盖单元 needs_follow_up。

## 崩溃处理

- fuzzer 写出 `testdata/fuzz/FuzzParse/<hash>` 用例 → 即最小复现输入（Go 已自动归档）；
- 复现：`go test -run=FuzzParse`（非 fuzz 模式跑 testdata 用例）3 次稳定 → 按 fuzzing-workflow 去重归因；
- 栈归因：panic 栈顶三帧定位 sink → whitebox-source-audit 三问分析。

## 判据与记账

- 同 fuzzing-workflow（签名去重/最小化/复现三件套）；每批 evidence 带 job id 与 fuzztime；
- coverage 单元 vuln_class=`fuzz-go-<pkg>`。

## 工具可用性探针

`go version`（需 ≥1.18）；被测包无法编译 → 记录编译错误 needs_follow_up，不得谎报"已 fuzz 无崩溃"。

## Execution Profile 标注（v5.3.2）

Go native fuzz 仅限 isolated_lab 自建环境（编译+高吞吐属 Lab Only）；production_safe 禁止对生产目标提交 fuzz 批次；语料与 testdata 崩溃样本不出工作区。

## 关联技能

fuzzing-workflow（总闭环）、whitebox-source-audit（归因）、parallel-execution（run_async/poll_async 编排）。
