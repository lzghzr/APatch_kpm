# rek 基础异步清理与 rekx 对齐

角色：Developer。根据使用者确认，rek 保留 code 29～32 的异步事件上报过滤，清理使用本项目 rekx 的基础去重策略；不引入 rekx 的 RPC 规则控制协议。rek 版本改为 11.7，rekx 保持本轮更新的 1.6-20261008。冻结判断沿用各模块当前实现。

## 实现

rek 仍在 binder_proc_transaction 的 before 中清理，至少两条匹配旧消息才摘除最早一条，每次至多删除一条，新事务尚未入队。原有队列选择已符合这一策略，本轮补齐以下资源与状态处理：

- 比较相同 binder_proc，而不是只比较 tsk；不处理带对象/FD、offsets 或额外缓冲区的消息。
- 取得 node/inner 锁后复核 is_dead、Binder is_frozen、任务组冻结状态和 has_async_transaction，再扫描并摘除。
- 摘除后解除 transaction/buffer 双向关联，锁外同步释放；ABI4/5/6 使用 is_failure=true，ABI3 保留 failed_at=NULL。binder_free_txn_fixups 按 rekx 现有方式可选调用。

新增 binder_proc_is_dead 动态字段。已有冻结字段时复用经过源码和 BTF 核对的 is_dead/is_frozen/sync_recv 连续 bool 片段；旧 Binder 从 binder_proc_dec_tmpref 的前 0x20 条指令读取 proc 参数的 LDRB，并核对后续三个指令内同寄存器的 32 位 CBZ。找不到证据就返回错误，扫描不扩展到整个函数，不按版本号选择偏移。

## are-you-sure 只读复核

复核对象是锁内状态检查与 is_failure=true。按使用者提供的 are-you-sure 技能完成只读反例检查，并另做一项限范围的并行证据复核。

**决定：保留（Retain）。**

- 有效性：myflavor 当前 rkx_binder_kp.c 在 inner_lock 内检查 is_dead/is_frozen；Sakion 当前 rekernel_binder.c 的 worker 在锁内复核死亡、Binder 冻结和任务冻结状态。is_failure=true 来自 Linux 上游 [22c135635fdd9816c0ef140d6de7b2e4fdf73e89](https://github.com/torvalds/linux/commit/22c135635fdd9816c0ef140d6de7b2e4fdf73e89)，修正未投递 FDA 的错误 FD 关闭；myflavor 当前仍传 false，Sakion 当前释放路径不使用该 wrapper。不能把 Linux 修复归为这两个 ReKernel 上游均已采用。
- 简洁性：一次锁内状态复核和一个释放参数即可，不加入另一套状态同步或异步清理框架。当前清理已排除 offsets_size/extra_buffers_size 非零事务，对允许清理的纯数据消息，true/false 不产生对象或 FD 释放差异；true 保持未投递事务的正确语义。
- 后果：Binder inner_lock 不保护 jobctl/cgroup 冻结状态，锁内复核仅缩小等待 Binder 锁期间的解冻窗口，不能宣布完全消除解冻竞态。原有应用级去重语义与卸载限制继续保留，不由主机自检代替真机结论。

来源快照：myflavor 8c217319d7d73c40667650a43a485e9f185e3a92；Sakion ac08296174d7fb2801c0eee1084f067a34f8a0fe。Linux 修复已在前轮 [静态清理开发记录](2026-10-02-re-kernel-static-native-cleanup.md) 中采用。

## 自检与身份边界

源码工作树基点为完整提交 a7cf9633fe468ca0a36e19e825e618bc2a348390；本轮修改尚未提交，产物为探索构建，未登记 instance_id，不能作为冻结候选交接。

使用 NDK 26.3.11579264、KP SDK b51197aaba8f2272dd8a3e30c85698a29aa928c9，将动态模块构建输入复制到新的隔离目录后执行 all/debug。SDK 每个变体各 5 条现有警告。

| 产物 | 字节数 | SHA-256 |
| --- | --- | --- |
| re_kernel_11.7.kpm | 48248 | d00c3f45d8af3be7dcfe5b9d699d43a1f4b81e27e9a81a256901b2c96f6d4404 |
| re_kernel_11.7_debug.kpm | 57752 | 5c68c7d44270a6a85894dd541b94b8ed3e204c98cfdf5985f28d8719ff6e8f68 |

ELF .kpm.info 版本分别为 11.7、11.7_d。check_build.py 检查每份 17 项导入均存在于 SDK 导出源码；未发现裸 memset/memcpy、FP/SIMD/SVE/x18 操作数。diff 与 .clang-format 检查通过。

原有 Genl/context、网络、指令、FIFO、Genl 短锚点和 Binder from 自检保持通过。追加生产 before 路径测试：四种释放 ABI 下共 40 个队列、死亡、冻结、等待锁时 Binder 冻结、对象/额外缓冲区、可选 fixup 场景，核对锁顺序、摘除后的关联解除、释放参数、计数和新事务保持。追加 is_dead 短锚点负例，核对 debug 全局、错误寄存器/分支宽度、RET、缺失符号和固定窗口。总共八组 ASan/UBSan 主机自检通过。

新宿主夹具第一次运行暴露的是夹具中 stats 数据符号未按 SDK 指针形式建模，修正夹具后保持原断言；另一新夹具补齐 bool 头文件。未删改已有断言，未为宿主测试改变生产架构。

此前已选择并成功提取的 10 份语料直接执行完整生产 C 推导：B2N-416G_boot.img、boot_67.2.A.3.178.img、kernel_4.4、kernel_4.9、kernel_4.9_miui、kernel_4.14、kernel_4.19、kernel_5.15、kernel_6.1、kernel_6.6，均返回 0；原有 37 个字段与前轮最终输出一致。新增 is_dead 在 6.1、6.6 均为 0x70，与各自 BTF 一致；旧内核的 0x8c/0x94 由相应短 helper 数据流取得。两份此前无法提取的 4.14 语料未增加覆盖。首次比较误用了 6.1 早期失败的探索输出，改与前轮最终输出比较后原字段一致，未改变参考判据。

构建前后核对原有模块 KPM 与 artifacts 下共 161 份文件，哈希不变。自检是 Developer 的源码、离线与主机证据，不是独立审计或真机结论。

## 元数据交接

rek 的当前版本声明修改见 [维护者补丁](../../docs/records/2026-10-08-round-finalization.md)，rekx 见 [前轮补丁](../../docs/records/2026-10-08-round-finalization.md)。仅提出当前声明更新，维护者落地后恢复版本一致性门禁；历史构建、候选和他人报告均未改动。

## 冻结交接补充（2026-10-08）

源码提交 `2074106d835b7a20f7e11ab29febc86ec54b7bb2` 已无签名冻结。统一候选构建从干净提交执行，release/debug 字节与上述探索产物一致；完整 instance_id、产物 SHA-256 与自检边界见 [候选交接](handoffs/2026-10-08-re_kernel-cleanup-candidate.md)。元数据补丁尚待维护者落地，新候选等待独立审计和真机测试。

> 维护者公开整理（2026-10-08）：工程记录引用路径整理。原文 SHA-256：`4c7d2ec984959e0afb09d60e1369fb2a8913c6efbd984081cc5a3203c85267d7`；原文保存在本地证据归档。
