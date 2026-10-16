# NoMount 0.1.0 版本登记

开发者已从 `c35ecd34ecb6a06c1d54ebda6e6a0e900065f16a` 构建四份候选，清单见 [基础交接](../../reports/handoffs/2026-10-13-nomount-0.1.0.json)，首轮派生件见 [目标交接](../../reports/handoffs/2026-10-13-nomount-0.1.0-target.json)。

常规门禁的 version_consistency 因 metadata 当前版本为空而失败。按角色规则，当前版本声明由维护者维护。

[version.patch](version.patch) 将 `metadata/modules/nomount.json` 的 version_declared 设为0.1.0，并在 version_sources 中记录 Makefile 版本0.1.0。其余字段、历史记录和结论逐字节保持原样。补丁已对隔离副本执行 git apply --check，通过；原 metadata 未改。

请维护者核对并落地版本登记，同时导入基础候选清单、核对目标派生清单。导入后再由维护者补登记时间及追加本轮记录；本补丁不写审计、测试或验收结论。
