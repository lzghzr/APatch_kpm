# re_kernel 11.7 与 re_kernel_x 1.6-20261008 工程记录

本记录保存维护者的候选身份复算、报告索引、证据范围与公开文件整理。本轮当前版本分别为 `11.7` 与 `1.6-20261008`，模块状态保持 `candidate`。

## 候选身份

| 模块 / 变体 | 完整 source_commit | instance_id | 产物 SHA-256 |
| --- | --- | --- | --- |
| `re_kernel` / `base` | `2074106d835b7a20f7e11ab29febc86ec54b7bb2` | `re_kernel-11.7+gb51704088a2f.rc7733a0a.kpb51197a.ndk26.3.11579264#1` | `d00c3f45d8af3be7dcfe5b9d699d43a1f4b81e27e9a81a256901b2c96f6d4404` |
| `re_kernel` / `debug` | `2074106d835b7a20f7e11ab29febc86ec54b7bb2` | `re_kernel-11.7_debug+gb51704088a2f.r30402fd1.kpb51197a.ndk26.3.11579264#1` | `5c68c7d44270a6a85894dd541b94b8ed3e204c98cfdf5985f28d8719ff6e8f68` |
| `re_kernel_x` / `base` | `60eef5e4e79255e03c3a6090aad345f92851c4cd` | `re_kernel_x-1.6-20261008+g1fe307661935.r04f95ebd.kpb51197a.ndk26.3.11579264#1` | `931e941bf9db2626209147e48d23e8d75a6595476fdfda072f656f9ec9d13937` |
| `re_kernel_x` / `debug` | `60eef5e4e79255e03c3a6090aad345f92851c4cd` | `re_kernel_x-1.6-20261008_debug+g1fe307661935.rf96e63f5.kpb51197a.ndk26.3.11579264#1` | `2eea221f9c6649932afb74c6ebc0e9510dae886037e8a98daaafd11a67a73ee0` |

## 工程证据与覆盖

- [新版独立审计报告](../../Auditor/reports/2026-10-08-re-kernel-11.7-and-rekx-version-audit.md)记录四份候选的独立重编译与源码审查；该结论来源为 Auditor。
- `Tester/reports/runs/2026-10-08-re_kernel-11.7_dual_live#1.md`记录 4.4 / 5.15 设备的热加载、版本、ctl0 与清理日志；该结论来源为 Tester。
- `Tester/reports/runs/2026-10-08-re_kernel_x-1.6-20261008_dual_live#1.md`以两项候选为移植基线。实际执行的目标字节经过偏移补丁，报告没有列出逐设备派生产物 SHA-256；基线身份不等于实测文件身份。
- DEV-013 的旧测试字节核对响应待 Tester 补充；[DEV-015 响应](../../Developer/reports/responses/2026-10-08-DEV-015-re-kernel-boot-event.md)记录嵌入启动事件说明与待执行的启动复验。热加载结果不覆盖嵌入启动事件。
- 本记录不新增验收或交付绑定；问题状态按其已有独立复核证据保存。

## 版本声明与 Git 组织

当前版本声明已落入模块元数据。两份版本声明补丁的建议已由维护者应用。源码、构建参数、测试与角色记录分别组织提交；DEV-011 的 20→25 指令测试窗口变更单独保存，独立复核依据见 [Genl 修复审计](../../Auditor/reports/2026-10-08-re-kernel-genl-fix-audit.md)。

本轮整理起点为 `3d0f8b937a74830f4d5d18cd37b886db442a456b`。构建登记仍绑定原始冻结提交，主分支提交整理不改变旧 builds、封存 KPM 或 MANIFEST。原始冻结提交通过本地 `codex/frozen-source-evidence-20261008` 引用保留，供本地身份核验与工作副本同步使用。

## 工程文件位置

| 原位置 | 当前位置 / 保留方式 | 原文件 SHA-256 |
| --- | --- | --- |
| `Developer/reports/handoffs/2026-10-08-re-kernel-freeze-selfcheck.json` | `Developer/reports/data/2026-10-08-re-kernel-freeze-selfcheck.json` | `c79dff3262de90c614f71cc292ce3843cb1403c536085375aef93124012f9306` |
| `Developer/reports/handoffs/re_kernel_x-1.6-20261008-layouts.json` | `Developer/reports/data/re_kernel_x-1.6-20261008-layouts.json` | `3cf466819893a70bb499c6803feb438f4a6885a0c4e088303d2df36b0caa21d1` |
| `Developer/reports/2026-10-03-async-binder-cleanup-discussion.md` | 本地原文归档 | `2398c41cee8ec561aea132c9a0b44b039353337b3ce748f9f362e383f2ede9eb` |
| `Developer/reports/responses/2026-10-08-re-kernel-version-metadata.patch` | 本地原文归档 | `7f6ae1b6aa9d69ba767c96d60cca0bbafa6c0db06e9d2520e633b2515bd000ec` |
| `Developer/reports/responses/2026-10-08-re-kernel-x-version-metadata.patch` | 本地原文归档 | `1491ed7f5a05ccc44c22e8669ad01d6e239de5e16e6fbb6385a5fc68f613fbb4` |

候选清单继续存放在 Developer/reports/handoffs；辅助自检与布局回执存放在 Developer/reports/data。迁移后的 JSON 字节及哈希保持原样，元数据追加位置映射，原历史引用保留。

## 公开副本处理

维护者对公开报告中的启动标识使用 SHA-256 表示，对设备特权 UID 和日志进程标识使用占位符。策略所需的 UID 0/1000/2000、目标设备接口路径、源码与产物哈希、判据计数保留。受影响报告附维护者范围说明与原文哈希；原文留在本地证据归档。

| 公开报告 | 原文 SHA-256 | 整理范围 |
| --- | --- | --- |
| `Developer/reports/2026-10-07-development-selfchecks.md` | `9126b4701ae88bcf852ed0721fa246c23a0bd42425913b401819b3be6f9e35b7` | 工程记录引用路径整理 |
| `Developer/reports/2026-10-08-re-kernel-cleanup-sync.md` | `4c7d2ec984959e0afb09d60e1369fb2a8913c6efbd984081cc5a3203c85267d7` | 工程记录引用路径整理 |
| `Developer/reports/2026-10-08-re-kernel-version-review.md` | `076a07411ee9c09ddfd43fa87af0f8a4b9bacbb9f30b689e7a32426bb0af0521` | 工程记录引用路径整理 |
| `Developer/reports/handoffs/2026-10-08-re_kernel-cleanup-candidate.md` | `0875815890e0e7a758d56148ed8e944caba84a1e688721b047f16f31063642bd` | 工程记录引用路径整理 |
| `Developer/reports/handoffs/2026-10-08-re_kernel_x-version-candidate.md` | `d74dbd923e3a2dae478c06c675935124c71aee96b69dd22670a2524e7a8b4337` | 工程记录引用路径整理 |
| `Auditor/reports/2026-10-07-AUD-005-006-re-kernel-verification.md` | `3065392c6722a78d32b153817847652685e9f1a0f683cf8d314862d690e53502` | 启动标识改为 SHA-256，保留相等关系；核验结论与候选身份保持原文 |
| `Auditor/reports/2026-10-08-AUD-003-re-kernel-x-verification.md` | `13d08f3b6e838fbefa00c48c2887eb4269be164befb6cd9c24cfae272d953ea2` | 启动标识改为 SHA-256，保留相等关系；核验结论与候选身份保持原文 |
| `Auditor/reports/2026-10-08-re-kernel-11.7-and-rekx-version-audit.md` | `253f1bae28d251d10ef305595da102d655cb4a01ecc30bc28bf55f7b4310c5fe` | 启动标识改为 SHA-256，保留相等关系；核验结论与候选身份保持原文 |
| `Auditor/reports/2026-10-08-re-kernel-genl-fix-audit.md` | `f828016a64412d0e809fe1e07228c55635057f4afa33ffa64f0545c0720e0085` | 启动标识改为 SHA-256，保留相等关系；核验结论与候选身份保持原文 |
| `Tester/reports/environments/2026-10-08-48b7ee2f.md` | `8e9be1b328de6098efe76f4137509d4716567b0281617fb22d808ac3e271559d` | 启动标识改为 SHA-256，保留相等关系；核验结论与候选身份保持原文 |
| `Tester/reports/environments/2026-10-08-b754dad7.md` | `1c2e9f6107841821a6e61effe9840b7c62c2507675cf01867ae6d3671a99c258` | 启动标识改为 SHA-256，保留相等关系；核验结论与候选身份保持原文 |
| `Tester/reports/runs/2026-10-08-re_kernel-11.7_dual_live#1.md` | `190f8a3b703b8126ccf5ebd8c2aff6dd9defdbbaab964acb8a1f6091b5b2934f` | 启动标识改为 SHA-256，保留相等关系；特权执行通道的设备 UID 使用占位符；日志进程与应用 UID 使用占位符；核验结论与候选身份保持原文 |
| `Tester/reports/runs/2026-10-08-re_kernel-8.0.0_4.4_live#1.md` | `f9be07c74342da7d1676605c9b50b6b1a833025b658f0e5dd36dee215afa756f` | 启动标识改为 SHA-256，保留相等关系；特权执行通道的设备 UID 使用占位符；核验结论与候选身份保持原文 |
| `Tester/reports/runs/2026-10-08-re_kernel-8.0.0_5.15_genl_live#1.md` | `e7d52afaee6b91eb259c84c7b44443ca9369d306a33aa3fd15b190362392f3b6` | 启动标识改为 SHA-256，保留相等关系；特权执行通道的设备 UID 使用占位符；日志进程与应用 UID 使用占位符；核验结论与候选身份保持原文 |
| `Tester/reports/runs/2026-10-08-re_kernel-8.0.0_5.15_live#1.md` | `aec1aa5eb050c1c5b01c616dd6b83b767c0b2aa9b3769e7b7a9bc9e79e819d15` | 启动标识改为 SHA-256，保留相等关系；特权执行通道的设备 UID 使用占位符；核验结论与候选身份保持原文 |
| `Tester/reports/runs/2026-10-08-re_kernel_x-1.6-20261008_dual_live#1.md` | `6fd254d45ed74404f41d989e07b1bec8ed15ab6665346c6a3aff49b92c654a86` | 启动标识改为 SHA-256，保留相等关系；特权执行通道的设备 UID 使用占位符；核验结论与候选身份保持原文 |
| `Tester/reports/runs/2026-10-08-re_kernel_x-1.6_4.4_port_live#1.md` | `db5a39d3daef44cb44ba17c0dac8009f9832e2c2f15b321a268f7ff33f43b84b` | 启动标识改为 SHA-256，保留相等关系；特权执行通道的设备 UID 使用占位符；核验结论与候选身份保持原文 |
| `Tester/reports/runs/2026-10-08-re_kernel_x-1.6_unified_port_live#1.md` | `789b60bbeab2d65b6e83e01a9fd32cf3228bee524435827e72f524b15f697c33` | 启动标识改为 SHA-256，保留相等关系；特权执行通道的设备 UID 使用占位符；核验结论与候选身份保持原文 |
| `Developer/reports/responses/2026-10-08-DEV-015-re-kernel-boot-event.md` | `98133bc5f882575ad31fcd13412d8b6a39d9689e95d809a3feb6890f452e0a2e` | 文档修复身份字段索引，保留原有待复验状态 |
