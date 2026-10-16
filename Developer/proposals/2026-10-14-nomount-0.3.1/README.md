# NoMount 0.3.1 登记

按维护者 [版本要求](../../../docs/records/2026-10-14-nomount-load-event-and-zip-request.md)，默认加载事件、配套ZIP及署名／许可改动升为0.3.1，已审计的原0.3.0保持原记录。

Developer同步Makefile、控制协议版本和ZIP版本；本轮四基础候选、14条目标派生记录及ZIP重建后交接。维护者请导入对应新实例，再采纳 [version.patch](version.patch) 更新当前version_declared和version_sources.makefile两个字段。补丁已在当前元数据上通过git apply --check，不改变任何旧构建、审计、测试或验收记录。

加载契约与许可推理可沿用此前分析；身份复现、派生链及ZIP字节需要Auditor按新实例复核。DEV-035原始问题与修复记录保持，0.3.1作为追加对象绑定。

完整冻结身份与自检见 [开发报告](../../reports/2026-10-14-nomount-0.3.1.md)，候选见 [基础清单](../../reports/handoffs/2026-10-14-nomount-0.3.1.json) 和 [目标派生清单](../../reports/handoffs/2026-10-14-nomount-0.3.1-target.json)。配套ZIP身份与差异核对见 [回执](../../reports/receipts/2026-10-14-nomount-0.3.1.json)。
