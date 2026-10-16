# NoMount 本轮 CFI 记录问题登记

详见 [Developer 跟进记录](../../reports/2026-10-13-nomount-round-followup.md)。

[issues.json](issues.json) 提供 DEV-033（Tester）和 DEV-034（Auditor）两条 record 问题，供维护者追加到 `metadata/modules/nomount.json` 的 issues。已核对仓库编号未占用。原报告、测试结果和既有验收记录保持原样，报告作者通过追加更正处理。

本提案不判断实际 CFI hook 是否失败，不撤销已记录的 VFS 读取结果。CFI 的加载前证据应由实际 KP 及本次运行记录支持；两条问题均需独立复核后关闭。
