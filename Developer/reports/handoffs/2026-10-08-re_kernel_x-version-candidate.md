# re_kernel_x 1.6-20261008 冻结候选交接

角色：Developer。本轮仅本地交接；候选尚待维护者导入、Auditor 独立审计与 Tester 真机测试。

源码冻结提交：`60eef5e4e79255e03c3a6090aad345f92851c4cd`（无签名）。

KernelPatch：`b51197aaba8f2272dd8a3e30c85698a29aa928c9`；NDK 26.3.11579264。

变更范围：仅将版本更新为 1.6-20261008，并同步 README 与移植示例；本轮没有修改 rekx 的 C 代码或清理策略。

自检：release/debug 构建和元信息检查通过，配套布局 schema=2、45 个字段、默认 binder_abi=6。版本更新未增加行为或设备覆盖。

统一候选入口从干净冻结工作树构建 all/debug，构建事务复核输入未变；每变体有 5 条已有 SDK 警告。四份 KPM 均与前述探索产物字节相同。ELF 导入在 SDK 导出源码中存在，未发现裸 memset/memcpy 或 FP/SIMD/SVE/x18 操作数；这些结果不证明目标设备的符号完备或实际加载行为。

## 身份

- 变体：`base`；Build ID：`re_kernel_x-1.6-20261008+g1fe307661935.r04f95ebd.kpb51197a.ndk26.3.11579264`。
- instance_id：`re_kernel_x-1.6-20261008+g1fe307661935.r04f95ebd.kpb51197a.ndk26.3.11579264#1`。
- 产物：`re_kernel_x_1.6-20261008.kpm`，42136 字节；SHA-256：`931e941bf9db2626209147e48d23e8d75a6595476fdfda072f656f9ec9d13937`。
- 归档：`artifacts/re_kernel_x-1.6-20261008+g1fe307661935.r04f95ebd.kpb51197a.ndk26.3.11579264/re_kernel_x_1.6-20261008.kpm`；同目录 `MANIFEST.json` 保留统一构建记录。

- 变体：`debug`；Build ID：`re_kernel_x-1.6-20261008_debug+g1fe307661935.rf96e63f5.kpb51197a.ndk26.3.11579264`。
- instance_id：`re_kernel_x-1.6-20261008_debug+g1fe307661935.rf96e63f5.kpb51197a.ndk26.3.11579264#1`。
- 产物：`re_kernel_x_1.6-20261008_debug.kpm`，41512 字节；SHA-256：`2eea221f9c6649932afb74c6ebc0e9510dae886037e8a98daaafd11a67a73ee0`。
- 归档：`artifacts/re_kernel_x-1.6-20261008_debug+g1fe307661935.rf96e63f5.kpb51197a.ndk26.3.11579264/re_kernel_x_1.6-20261008_debug.kpm`；同目录 `MANIFEST.json` 保留统一构建记录。

配套布局随 KPM 保存在各自新归档目录；布局文件的 SHA-256、大小与对应 KPM 身份见 [布局回执](../data/re_kernel_x-1.6-20261008-layouts.json)。统一构建器登记 KPM，布局回执单独绑定，未改写生成的 MANIFEST。

## 交接与边界

[统一交接清单](re_kernel_x-1.6-20261008-version.json)；[开发记录](../2026-10-08-re-kernel-version-review.md)。

四项候选均通过 identity.verify_build(profile="candidate") 核验，配方指纹、源提交输入与产物哈希可复算，problems=[]。实现方核验原有 161 份受保护文件，哈希保持不变。

维护者需导入新候选，并处理 [当前版本声明补丁](../../../docs/records/2026-10-08-round-finalization.md)。本轮未覆盖历史身份、旧资产或他人报告，也未关闭问题单。

本候选未执行真机加载/卸载、Genl 收发或应用级清理测试；旧候选的审计和实机结论不自动继承。以上是 Developer 自检，不是独立审计或实机结论。

## 交接门禁状态

regular 门禁 16 项中 15 项通过，唯一失败项为 version_consistency：rek 11.7 对应元数据仍为 8.0.0，rekx 1.6-20261008 对应元数据仍为 1.6。维护者需应用当前版本声明补丁并导入候选后重新核验；本轮未降低门禁要求。四项候选独立通过严格身份核验，详见 [Developer 自检回执](../data/2026-10-08-re-kernel-freeze-selfcheck.json)。

> 维护者公开整理（2026-10-08）：工程记录引用路径整理。原文 SHA-256：`d74dbd923e3a2dae478c06c675935124c71aee96b69dd22670a2524e7a8b4337`；原文保存在本地证据归档。
