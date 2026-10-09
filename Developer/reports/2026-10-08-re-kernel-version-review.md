# rek / rekx 上游版本核对

角色：Developer。2026-10-08 通过 GitHub API 核对公开上游提交与版本，并按提交下载 LKM-Source 文件进行源码对比。

## 上游与功能范围

| 模块 | 上游 | 核对提交 | 当前版本 |
| --- | --- | --- | --- |
| rek（re_kernel） | [Sakion-Team/Re-Kernel](https://github.com/Sakion-Team/Re-Kernel) | ac08296174d7fb2801c0eee1084f067a34f8a0fe | 11.7 |
| rekx（re_kernel_x） | [myflavor/ReKernel-X](https://github.com/myflavor/ReKernel-X) | 8c217319d7d73c40667650a43a485e9f185e3a92 | 1.6 |

rek 已支持 Sakion 当前的 Generic Netlink family、事件组播、网络监控 UID 增删和版本查询，Binder、信号、TCP 事件亦已具备。但以下行为仍不同，不能据此宣布功能完全一致或直接同步到 11.7：

- 本地异步 Transaction 仍仅上报 code 29～32；上游对符合冻结与 UID 条件的异步 Transaction 不设此 code 范围。
- 本地在 binder_proc_transaction 的 before 中清理，每次至少有两条匹配旧消息才移除最早一条，不要求 TF_UPDATE_TXN。上游等待 binder_write_done，在 Workqueue 中重新确认队列身份，要求 TF_UPDATE_TXN 和无对象缓冲，保留最新匹配消息。
- 本地冻结判断沿用 jobctl 与 cgroup_freezing；上游还检查 cgroup_task_frozen、任务组 leader 的 frozen/freezing 状态。事件选择亦有本地同 UID 过滤等差异。

依据分别为上游 [Binder 实现](https://github.com/Sakion-Team/Re-Kernel/blob/ac08296174d7fb2801c0eee1084f067a34f8a0fe/LKM-Source/rekernel_binder.c) 与 [冻结判断](https://github.com/Sakion-Team/Re-Kernel/blob/ac08296174d7fb2801c0eee1084f067a34f8a0fe/LKM-Source/rekernel_internal.h)，以及本地 re_kernel.c。以上是源码差异核对，未改变业务策略。

## 版本修改与自检

rek 保持 8.0.0。rekx 改为 1.6-20261008，基版本沿用上游 1.6，日期后缀区分本轮 KPM 移植。更新 Makefile、README 当前条目及移植示例；旧更新记录保持原样。

本轮以 a7cf9633fe468ca0a36e19e825e618bc2a348390 为工作树基点，版本修改尚未提交。产物属于探索构建，未登记 instance_id，不作为冻结候选交接。

工具链为 NDK 26.3.11579264，KP SDK 提交 b51197aaba8f2272dd8a3e30c85698a29aa928c9。在新的本地输出目录执行 re_kernel_x 的 all/debug 目标，OUT_DIR 与 LAYOUT_DIR 指向该目录：

| 产物 | 字节数 | SHA-256 |
| --- | --- | --- |
| re_kernel_x_1.6-20261008.kpm | 42136 | 931e941bf9db2626209147e48d23e8d75a6595476fdfda072f656f9ec9d13937 |
| re_kernel_x_1.6-20261008_debug.kpm | 41512 | 2eea221f9c6649932afb74c6ebc0e9510dae886037e8a98daaafd11a67a73ee0 |

两个构建均成功，各有 5 条现有 SDK 警告。逐节读取 ELF 的 .kpm.info，版本分别为 1.6-20261008 和 1.6-20261008_d；配套布局 JSON 均为 schema 2、45 个字段、默认 binder_abi=6。check_build.py 核对两份产物的 18 项导入均存在于 SDK 导出源码，未发现 FP/SIMD/SVE/x18 操作数或裸 memset/memcpy 导入。git diff --check 通过。

构建前后核对 artifacts 下文件及两个模块目录已有 KPM，共 161 份文件哈希不变。未修改测试 Oracle、独立角色报告、历史构建记录或已冻结清单。自检仅证明本轮构建与元信息，不能代替独立审计或真机测试。

## 维护者后续处理

当前版本声明归维护者管理，已准备 [元数据补丁](../../docs/records/2026-10-08-round-finalization.md)，只更新 re_kernel_x 的 version_declared 与 version_sources.makefile，不改历史 builds。此补丁尚未应用，当前源码版本与元数据声明暂不一致；维护者应用并核对后恢复版本一致性门禁。

## 后续使用者确认

使用者确认 rek 保留 code 29～32 上报过滤，异步清理与本项目 rekx 的基础策略一致即可。按此范围将 rek 版本更新为 11.7，并补齐清理资源与锁内状态处理；两者保留已有冻结判断和协议差异。实现、are-you-sure 复核及本轮新产物见 [清理同步记录](2026-10-08-re-kernel-cleanup-sync.md)。本节追加后续状态，不改写上述初次核对事实。

## 冻结交接补充（2026-10-08）

源码提交 `60eef5e4e79255e03c3a6090aad345f92851c4cd` 已无签名冻结。统一候选构建从干净提交执行，release/debug 字节与上述探索产物一致；完整 instance_id、产物 SHA-256 与自检边界见 [候选交接](handoffs/2026-10-08-re_kernel_x-version-candidate.md)。元数据补丁尚待维护者落地，新候选等待独立审计和真机测试。

> 维护者公开整理（2026-10-08）：工程记录引用路径整理。原文 SHA-256：`076a07411ee9c09ddfd43fa87af0f8a4b9bacbb9f30b689e7a32426bb0af0521`；原文保存在本地证据归档。
