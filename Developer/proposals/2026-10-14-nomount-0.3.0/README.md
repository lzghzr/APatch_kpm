# NoMount 0.3.0 候选登记

Developer 已按固定上游 LKM 的挂载上下文语义，完成 Sony/GKI 5.15 与 Android13 5.10 的候选。完整提交、实例、产物和自检范围见 [开发报告](../../reports/2026-10-14-nomount-mount-abis.md)。

请维护者导入 [四份候选](../../reports/handoffs/2026-10-14-nomount-0.3.0.json) 与 [目标派生清单](../../reports/handoffs/2026-10-14-nomount-0.3.0-target.json)，复算身份及目标配置。清单有14个目标／变体记录，10份唯一派生字节；三份5.15配置相同而共享派生件，记录实际首次生成命令和各自目标身份。

[version.patch](version.patch)仅同步当前version_declared与version_sources.makefile两处为0.3.0，旧构建、测试、审计及风险记录保留。请为新实例和实际测试KP确认常驻风险适用范围，再交Auditor独立复现并交Tester验证Sony5.15。普通/debug逐次选择一种，使用post-kernel-init，参数留空，常驻至重启。

B2N和Sony4.19的v3配置及B2N旧KP派生件用于新代码回归复核，已有真机结论仍绑定原版本。本轮未完成其他无BTF厂商配置，也未完成6.1/6.6/6.12的后续接口适配；6.18暂缓。未改共享判据、元数据或其他角色的报告。
