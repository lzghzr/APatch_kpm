# NoMount 0.2.0 候选登记提案

Developer 已完成 B2N 4.4 静态适配候选，源码冻结为 `c5c49e98164e0129e29b4bd3ba05c8affcd0b352`。开发自检与完整身份见 [开发报告](../../reports/2026-10-13-nomount-4.4.md)。

请维护者：

1. 导入 [四份候选清单](../../reports/handoffs/2026-10-13-nomount-0.2.0.json) 与 [四份目标派生清单](../../reports/handoffs/2026-10-13-nomount-0.2.0-target.json)，逐项重算身份。静态基准件附配套 JSON；派生件在清单指定的内容寻址归档路径中。
2. 复核 [version.patch](version.patch)：仅同步当前 `version_declared` 与 `version_sources.makefile` 两处字段。历史 builds、audits、tests、reports 与 RA-002 原文均保留。
3. 为 0.2.0 的 4.4 验证确认常驻风险范围及实际 KP 身份。现有 RA-002 明确只覆盖 0.1.0、4.19 与所记 KP，需另行追加本轮适用记录；加载前由维护者和 Tester 核对。生命周期仍为开机 `post-kernel-init` 加载、参数留空、驻留到重启。
4. 交 Auditor 独立复现布局、调用 ABI 与二进制转换，随后交 Tester 在 B2N 4.4 上验证。普通/debug 分别绑定字节；旧 KP 派生件按实际 KP 导出能力选用。

本提案由 Developer 提供机制和身份事实。版本登记、风险接受与验收结论归维护者，独立审计和真机结论归各自角色。
