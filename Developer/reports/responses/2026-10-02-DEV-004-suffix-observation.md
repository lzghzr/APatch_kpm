# DEV-004：本地 KP 后缀过滤未排除 CFI jump table

角色 Developer，严重度中，归属 Developer（外部依赖适配）；状态 open。这是外部依赖的兼容性发现，不修改第三方核心，不替上游或 Auditor 写结论。

- 绑定来源：KP 0.13.9 完整提交 `b51197aaba8f2272dd8a3e30c85698a29aa928c9`，kernel/base/start.c 的 suffix_contains_cfi 与 symbol_has_compiler_suffix。原静态版依赖该 helper 的全部实例见 [前轮清单](../handoffs/2026-10-02-re-kernel-static-native-cleanup-exploration.json)。本轮改用原名查找的身份见 [新清单](../handoffs/2026-10-02-re-kernel-static-kp-lookup-exploration.json)。
- 证据：匹配器接收 `trace_event_define_fields_block_rq_remap$4fc695cdd5c41595837c2e5534214bdf.cfi_jt` 和 `kretprobe_event_define_fields$97b5c6919a91cd68ba846770dcb98bea.cfi_jt`。代码中 cfi 后边界没有下划线，结果与 skip .cfi_jt 注释不一致。抽取生产谓词的主机试验在 local/static-kp-lookup-20261002-01/suffix-predicate-observation.c/.log；初始反例断言失败记录也保留。
- 影响：完整原名缺失、cfi_bypass 开启时，后缀 helper 可能选择 CFI 跳板；得到地址不等于得到真实函数体。将其直接用于实现体反汇编、偏移推导或假定入口布局的 hook 可能出现兼容性错误。未证实具体内核崩溃、设备发生率或用户给出的函数实际被模块调用，不能据此报告真机后果。
- frequency：未知；confidence：已确认（匹配谓词行为），hook/实际调用后果未验证。
- 建议：后续模块后缀适配明确区分 CFI 跳板和实现体；第三方过滤修正交上游/维护者处理。本轮 B2N 导入修复没有使用该 helper，B2N 必需原名已核对。
- 关闭条件：独立角色复核后缀匹配、符号选择及真实目标入口；实际设备后果由 Tester 核验。Developer 不关闭，元数据登记交维护者。


## 模板字段索引（维护者整理，2026-10-03）

| 项 | 原记录对应内容 |
| --- | --- |
| 问题编号 | DEV-004 |
| 修复 commit | 本响应记录依赖观察，未声明已完成修复；依赖提交 `b51197aaba8f2272dd8a3e30c85698a29aa928c9` |
| Build ID | [探索清单](../handoffs/2026-10-02-re-kernel-static-kp-lookup-exploration.json)逐变体登记 |
| 证据 | 原响应所列生产谓词反例与本地自检；真实设备后果保持未验证 |
