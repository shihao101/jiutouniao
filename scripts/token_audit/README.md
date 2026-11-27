# token_audit 逐项目 token 分账对账工具（v7.5.0 F2）

只读 bbolt 快照，导出 usage 分账（项目/阶段/调用数/输入输出），用于月度对账与版本间
token 回归核对（发版门：单项目均值涨幅 >10% 须附原因说明）。

用法（对运行中的库先 cp 快照再读，避免文件锁）：

    cp projects/jiutouniao.db /tmp/snapshot.db
    cd scripts/token_audit && go build -o tokdump .
    ./tokdump /tmp/snapshot.db > usage_report.tsv

输出：项目明细表 + TOTAL 行 + 各项目按阶段分账 + 全库阶段聚合。
