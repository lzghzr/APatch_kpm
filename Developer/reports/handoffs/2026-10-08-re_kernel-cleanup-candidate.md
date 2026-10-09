# re_kernel 11.7 冻结候选交接

角色：Developer。本轮仅本地交接；候选尚待维护者导入、Auditor 独立审计与 Tester 真机测试。

源码冻结提交：`2074106d835b7a20f7e11ab29febc86ec54b7bb2`（无签名）。

KernelPatch：`b51197aaba8f2272dd8a3e30c85698a29aa928c9`；NDK 26.3.11579264。

变更范围：基础异步清理与本项目 rekx 对齐，补齐锁内死亡/冻结状态复核、纯数据消息约束、未投递事务释放及可选 fixup；新增 is_dead 短锚点推导。版本为 11.7，保留 code 29～32 上报过滤和已有冻结判断。

自检：八组 ASan/UBSan 主机套件通过，包含四种释放 ABI 的 40 个 before 清理场景；宿主自检 receipt 的全部输入哈希已与此提交 blob 核对。十份已成功提取的内核语料执行生产 C 推导均返回 0，原 37 个字段不变；6.1/6.6 的新增字段与各自 BTF 一致。两份此前无法提取的 4.14 输入仍未覆盖。

审计关注：锁顺序、事务摘除与计数、对象/FD 排除、可选 fixup 的生命周期、原生去重交互、旧 Binder 短锚点，以及应用对被清理消息的依赖。任务冻结状态复核仅缩小窗口，不保证消除所有解冻竞态。

统一候选入口从干净冻结工作树构建 all/debug，构建事务复核输入未变；每变体有 5 条已有 SDK 警告。四份 KPM 均与前述探索产物字节相同。ELF 导入在 SDK 导出源码中存在，未发现裸 memset/memcpy 或 FP/SIMD/SVE/x18 操作数；这些结果不证明目标设备的符号完备或实际加载行为。

## 身份

- 变体：`base`；Build ID：`re_kernel-11.7+gb51704088a2f.rc7733a0a.kpb51197a.ndk26.3.11579264`。
- instance_id：`re_kernel-11.7+gb51704088a2f.rc7733a0a.kpb51197a.ndk26.3.11579264#1`。
- 产物：`re_kernel_11.7.kpm`，48248 字节；SHA-256：`d00c3f45d8af3be7dcfe5b9d699d43a1f4b81e27e9a81a256901b2c96f6d4404`。
- 归档：`artifacts/re_kernel-11.7+gb51704088a2f.rc7733a0a.kpb51197a.ndk26.3.11579264/re_kernel_11.7.kpm`；同目录 `MANIFEST.json` 保留统一构建记录。

- 变体：`debug`；Build ID：`re_kernel-11.7_debug+gb51704088a2f.r30402fd1.kpb51197a.ndk26.3.11579264`。
- instance_id：`re_kernel-11.7_debug+gb51704088a2f.r30402fd1.kpb51197a.ndk26.3.11579264#1`。
- 产物：`re_kernel_11.7_debug.kpm`，57752 字节；SHA-256：`5c68c7d44270a6a85894dd541b94b8ed3e204c98cfdf5985f28d8719ff6e8f68`。
- 归档：`artifacts/re_kernel-11.7_debug+gb51704088a2f.r30402fd1.kpb51197a.ndk26.3.11579264/re_kernel_11.7_debug.kpm`；同目录 `MANIFEST.json` 保留统一构建记录。

## 交接与边界

[统一交接清单](re_kernel-11.7-20261008-cleanup.json)；[开发记录](../2026-10-08-re-kernel-cleanup-sync.md)。

四项候选均通过 identity.verify_build(profile="candidate") 核验，配方指纹、源提交输入与产物哈希可复算，problems=[]。实现方核验原有 161 份受保护文件，哈希保持不变。

维护者需导入新候选，并处理 [当前版本声明补丁](../../../docs/records/2026-10-08-round-finalization.md)。本轮未覆盖历史身份、旧资产或他人报告，也未关闭问题单。

本候选未执行真机加载/卸载、Genl 收发或应用级清理测试；旧候选的审计和实机结论不自动继承。以上是 Developer 自检，不是独立审计或实机结论。

## 交接门禁状态

regular 门禁 16 项中 15 项通过，唯一失败项为 version_consistency：rek 11.7 对应元数据仍为 8.0.0，rekx 1.6-20261008 对应元数据仍为 1.6。维护者需应用当前版本声明补丁并导入候选后重新核验；本轮未降低门禁要求。四项候选独立通过严格身份核验，详见 [Developer 自检回执](../data/2026-10-08-re-kernel-freeze-selfcheck.json)。

> 维护者公开整理（2026-10-08）：工程记录引用路径整理。原文 SHA-256：`0875815890e0e7a758d56148ed8e944caba84a1e688721b047f16f31063642bd`；原文保存在本地证据归档。
