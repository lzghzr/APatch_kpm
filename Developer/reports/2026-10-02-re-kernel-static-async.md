# 开发记录：re_kernel_static 异步 Binder 清理

角色：Developer。按用户要求小步推进清理和必要自检，本轮为探索构建，不是冻结候选、独立审计或真机结论。

## 身份

基础完整提交：`40d33aca895cc4778deb1925ec12e4a635b5612f`；`source_dirty=true`。实际工作树与配方指纹见 [最终探索清单](handoffs/2026-10-02-re-kernel-static-async-exploration-03.json)。KernelPatch 固定为 `b51197aaba8f2272dd8a3e30c85698a29aa928c9`。统一入口使用 `--allow-dirty --no-archive --target baselines`，未登记维护者元数据、未签名。此前两份探索清单和旧产物保留，以下只绑定最终第三份清单。

| 变体 | instance_id | SHA-256 |
| --- | --- | --- |
| abi3 | `re_kernel_static-8.0.0_abi3+gd380b1588494.r021bf0c0.kpb51197a.ndk26.3.11579264#1` | `2dfad6d87521b49b44d58ac0d2552fe948a1e5991c195e0f8161b73ea0097ac1` |
| abi3_debug | `re_kernel_static-8.0.0_abi3_debug+gd380b1588494.rb6c795e2.kpb51197a.ndk26.3.11579264#1` | `82fdc5f1fba36fdbe8c8b6fa82b11f611f450c8727793a0adfc696c2e9c2f530` |
| abi4 | `re_kernel_static-8.0.0_abi4+gd380b1588494.r8dc2d8cc.kpb51197a.ndk26.3.11579264#1` | `136362e8da7bd1f8e37603eb7187b0c1d8b1fd372323b23cf229b9162b39c1ae` |
| abi4_debug | `re_kernel_static-8.0.0_abi4_debug+gd380b1588494.r6291e6b6.kpb51197a.ndk26.3.11579264#1` | `78c246c985285cd0458c37f44d8580eab1b71621c4f99e1114b507257a208a17` |
| abi5 | `re_kernel_static-8.0.0_abi5+gd380b1588494.rec7f70c7.kpb51197a.ndk26.3.11579264#1` | `fb5492495d7237f3809ead1ba470da76b19aa364ef5bce5473ac7a1d3a65dba8` |
| abi5_debug | `re_kernel_static-8.0.0_abi5_debug+gd380b1588494.rf41d1efc.kpb51197a.ndk26.3.11579264#1` | `86570b3fa256a08faf85cc5aa7097791b0c34b8c4fc6dd9b3f6b07d070e9af77` |
| abi6 | `re_kernel_static-8.0.0_abi6+gd380b1588494.r33c89bb3.kpb51197a.ndk26.3.11579264#1` | `d091551a8759359aaca27e8cdffdae24325cd06ca1a04c0ed87a2d05c5d8462d` |
| abi6_debug | `re_kernel_static-8.0.0_abi6_debug+gd380b1588494.rda449b05.kpb51197a.ndk26.3.11579264#1` | `9171c339cd25e4606c407ff6a10ba87d69da87353e25456c6911200607853cc2` |

## 实现与取舍

- 保留已有“留下最早一条，摘除第二条匹配消息”的语义。额外要求目标 proc 相同；NULL buffer/node、带对象/FD 的 offsets_size、额外缓冲区跳过。带对象消息不再仅凭 code 相同被清除。这并不能证明普通 RPC 的业务语义允许去重，RPC/code 策略规则仍待下一轮实现。
- node->lock、proc->inner_lock 下再次检查 proc 未退出、未 Binder 冻结、有正在处理的 async 事务。仅修改 async_todo，不碰正在处理的事务或 has_async_transaction。先分配释放任务，摘除时增加 tmp_ref，减少 outstanding_txns，并清除 transaction/buffer 双向关联。
- 任务发布和 queue_work_on 在短临界区内完成。入队失败时，仍持有 Binder 锁，恢复准确的原链表位置、关联和两个计数。成功后 worker 独占释放任务，生产者不再访问它。释放 buffer/transaction 和统计更新完成后才调用原生 binder_proc_dec_tmpref，此后不再访问 proc。
- Workqueue 使用 UNBOUND|MEM_RECLAIM、max_active=1，不使用 FREEZABLE。队列在首个符合条件的 Binder 调用中、取 Binder 锁之前创建；KP init 只解析符号和安装回调 hook，避免把 Workqueue 创建放入 KP 的 RCU 读侧。多个首次调用只由一方创建，其余未得到队列就保留消息。创建失败允许下一次调用尝试，尚未摘除任何消息。
- 待释放列表上限 64 项，worker 摘取后减计数；最多额外一个正在执行的任务。满时保留 Binder 消息，避免列表扫描和内存积压无界增长。
- work_struct 复用 data/entry/func 公共前缀，预留 0x100 字节容量；目标 BTF 生成器断言大小和字段位置。新增 binder_proc_tmp_ref、binder_proc_is_dead、work_offq_pool_shift、work_cpu_unbound，偏移表为 46 个 int16、92 字节。所有默认值与现有目标 BTF 生成器一致；不据此宣称其它镜像兼容。shift 和 CPU 哨兵必须来自目标配置，离线 JSON/blob 补丁工具检查 shift=5/6 与正 NR_CPUS，不在模块中加入动态推导。
- 内核 work.func 指向原生 lru_add_drain_per_cpu，优先用其 .cfi_jt 地址；hook 实现入口，只处理模块自己 pending 列表中的 work，其它内核 work 继续原路径。缺少原生引用管理或 Workqueue 必需符号、hook 失败、发现 LOCKDEP 初始化函数时停止清理，不回退同步释放。LOCKDEP 布局暂未实现。

## 自检

八个 release/debug 基准构建通过。最终登记的八个 KPM 与已测试的 cfi-baselines 字节一致，SHA-256 对照探索清单通过；所有未定义导入均在当前 KP 导出源码表内，无 get_task_ext 导入；对实际 ARM64 反汇编检查未发现 FP/SIMD/SVE 寄存器指令。编译保留既有 SDK 的五条警告。

`tools/test_static.py` 保留既有真实 ELF 补丁往返、协议、任务上下文和 Genl 测试。新增生产清理函数 ASan/UBSan 主机测试，分别编译 ABI 3/4/5/6，验证四种实际释放参数（包括 ABI5 的 ALIGN(data_size)+offsets_size）。覆盖分配失败、入队失败原位恢复、Binder 冻结/进程退出/非冻结任务、无在途异步消息、同步消息和 code 不匹配、对象/额外缓冲区及 NULL 成员、只有一条匹配消息、延迟释放、proc 在 worker 前死亡、worker 在 queue 时立即启动、八个生产者、非 LIFO worker 执行、非本模块 work 原路径、64 项容量满、缺失符号、LOCKDEP、hook/队列创建失败、首次创建竞争、CFI jump-table 指针选择、模拟销毁排空。计数、链表、buffer 关联和每次释放都断言。

离线补丁工具新增 JSON/blob 的负 shift/过大 shift、零/负 CPU 哨兵拒绝测试。未缩小原有断言或检查范围。早期测试失败包括新增合法值约束后测试数据未更新、对象用例尚有两条普通消息可去重；修正测试输入和断言后通过。没有以放宽断言处理失败。

已有 5.15.189-android13-8-00016 镜像：本轮直接读其 binder_transaction_buffer_release 入口反汇编，第四参数 x3 被作为 off_end_offset 保存，与已有 ver5 标志一致，应选择 abi5。符号表包含五个 Workqueue/引用管理必需符号，且有 lru_add_drain_per_cpu.cfi_jt；未找到 __init_work 和两个 LOCKDEP 初始化符号。该事实只证明符号存在和函数签名，尚未执行设备加载或业务测试。

## DEV-002（高，Developer）Workqueue 销毁和并发卸载生命周期未完成

- 证据：当前 KP `kernel/patch/module/module.c:527` 的 unload_module 在 rcu_read_lock 后调用模块 exit，忽略 exit 返回是否失败并继续释放模块代码。当前 stop_rekernel_async 中 destroy_workqueue 可能等待 worker；退出期间尚在创建队列或进入回调的生产者也没有完成全面同步。绑定上表全部最终探索构建。
- 影响：卸载期间可能在 RCU 读侧等待或让活跃回调访问已释放模块；存在内核卡死/崩溃风险。按影响列高，不能因未在设备观察而降级。
- frequency：依赖卸载与并发时机，未知。confidence：调用顺序和缺少同步由源码确认，具体设备后果未验证。
- 状态：open，依用户此前明确要求暂缓卸载，不声称可安全卸载。初始化失败后 async hook 尚未启用；本轮未测试卸载或创建与卸载竞争。
- 建议：在可等待的上下文中停止生产者并确认回调退出，排空释放任务，再移除 hook 和释放模块；需要结合 KP 加载器生命周期设计。
- 关闭条件：由独立 Auditor 复核生命周期修复，并由 Tester 在新完整身份构建上验证并发退出；Developer 不自行关闭。元数据登记交维护者，本轮未改其文件。

## 验证边界与下一步

主机锁为 pthread 模型，原生 Binder/Workqueue 函数为受控桩；不证明目标机锁、CFI 或应用解冻后的业务状态正常。模拟排空测试不证明真实 KP 卸载安全。真机仍需验证冻结期间连续 oneway、解冻后消息进度和 app 响应、退出竞争、异步空间恢复；出现无响应应按仓库流程立即停止测试。

下一轮应接入 RPC/code 清理规则及 ADD_FREE_ASYNC/DEL_FREE_ASYNC，区分可替换的状态消息与不可丢弃的增量消息。Workqueue 改变释放时机，不解决按 code 去重的业务语义。旧 DEV-001 的独立复核状态未改变。

参考：上游 ReKernel-X `8c217319d7d73c40667650a43a485e9f185e3a92` 的 rkx_binder_kp.c；[Linux v5.15 Binder 调用与引用管理](https://github.com/torvalds/linux/blob/v5.15/drivers/android/binder.c)、[Workqueue 执行与释放约束](https://github.com/torvalds/linux/blob/v5.15/kernel/workqueue.c)、[原生 work 回调入口](https://github.com/torvalds/linux/blob/v5.15/mm/swap.c)。回调返回后 work 可已释放，原生执行结束 trace 仅保留其地址；借用入口的模块处理仍需要目标 CFI 实机确认。
