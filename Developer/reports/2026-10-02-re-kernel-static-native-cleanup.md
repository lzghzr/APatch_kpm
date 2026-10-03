# 开发记录：低版本 Binder 自行去重与原生释放

角色：Developer。用户同意采用原生同步释放流程，并再次确认主打低版本、不依赖 TF_UPDATE_TXN。本轮小步修改静态版；这是实现方探索自检，不是冻结候选、独立审计或真机结论。

## 身份

完整基础提交：`40d33aca895cc4778deb1925ec12e4a635b5612f`；`source_dirty=true`，没有新的修复提交。实际模块输入指纹：`25fe94e00b5dd09960ffd39309f93f0bd83dead31a3d6ead535e96a9afba626c`。KernelPatch：`b51197aaba8f2272dd8a3e30c85698a29aa928c9`。产物身份与逐文件来源见 [探索清单](handoffs/2026-10-02-re-kernel-static-native-cleanup-exploration.json)。八个登记产物与已测试基准逐字节一致，旧清单及旧产物均保留；未登记维护者元数据、未签名。

| 变体 | instance_id | SHA-256 |
| --- | --- | --- |
| abi3 | `re_kernel_static-8.0.0_abi3+g25fe94e00b5d.r492c7065.kpb51197a.ndk26.3.11579264#1` | `8ec3f616a482a9cf43e5a0edd8dce8b3b41c91f8d2a2302a0819286e40c8770e` |
| abi3_debug | `re_kernel_static-8.0.0_abi3_debug+g25fe94e00b5d.r735e455e.kpb51197a.ndk26.3.11579264#1` | `b524675ac91abdae6c348e3e4c5e91977c4268aa490b5edc1999533ce287d9a6` |
| abi4 | `re_kernel_static-8.0.0_abi4+g25fe94e00b5d.r934530cd.kpb51197a.ndk26.3.11579264#1` | `2624296f1f9fde38e33be28fea051cb1d8393b84e7894001df6f2a09f57f0b60` |
| abi4_debug | `re_kernel_static-8.0.0_abi4_debug+g25fe94e00b5d.rdc45dbb7.kpb51197a.ndk26.3.11579264#1` | `1a0266dfae7f061e99859e9e5429e5d9b72134317560fcb50a2a69bc927d00a2` |
| abi5 | `re_kernel_static-8.0.0_abi5+g25fe94e00b5d.rec817455.kpb51197a.ndk26.3.11579264#1` | `13ce961721e2136609d8383ca240e96eb0afa12ac0af2154163ef37aa4502c58` |
| abi5_debug | `re_kernel_static-8.0.0_abi5_debug+g25fe94e00b5d.rd50bb491.kpb51197a.ndk26.3.11579264#1` | `47d883d0db216d63888aa233b805fedc5f6354121f7e51376418aa0d43ead65f` |
| abi6 | `re_kernel_static-8.0.0_abi6+g25fe94e00b5d.rffa8a214.kpb51197a.ndk26.3.11579264#1` | `8b640219105f990715df268d0daf40c4302b80c4065539c3ea76674639e5e2b0` |
| abi6_debug | `re_kernel_static-8.0.0_abi6_debug+g25fe94e00b5d.r1263623e.kpb51197a.ndk26.3.11579264#1` | `be39f1618537fbcefb585072ba901adb1654786cb0349201d89199e13113c304` |

## 实现

- binder_can_update_transaction 继续由模块实现，只要求双方 TF_ONE_WAY，不要求 TF_UPDATE_TXN。匹配目标 proc、code、flags、可用时的发送 PID、node ptr/cookie；保留最早一条，摘除第二条。任务组冻结、Binder 未冻结、proc 未退出及 node 有在途 async 的条件保持。
- node/inner_lock 下摘除并减少 outstanding_txns，解锁后清除 transaction/buffer 双向关联，释放整个 buffer、归还 alloc 缓冲，再回收 fixup（如有）、transaction，最后更新删除统计。原生调用方持有 target_proc 引用直到 binder_proc_transaction 返回，模块不加减 tmp_ref。没有调用 binder_free_transaction，因为该函数还会再次减少 outstanding_txns。
- ABI4/5/6 使用 is_failure=true，消息尚未投递；ABI3 沿用 failed_at=NULL。ABI5 的第四参数仍是 ALIGN(data_size, sizeof(void*))+offsets_size。
- binder_free_txn_fixups 仅按符号可选调用，不作为加载或清理硬依赖，不复刻 FD fixup 内部布局。所有内核上的含 Binder 对象/FD 或额外缓冲区事务均保留整条消息，继续原生流程；只有无对象消息参与本轮去重。缺少 helper 时不会丢弃事务并留下 FD。
- 删除 Workqueue、借用原生 lru work 回调的 hook、私有释放队列/锁和额外 proc 引用。删除 binder_proc_tmp_ref、work_offq_pool_shift、work_cpu_unbound 配置，保留 binder_proc_is_dead；新表 43 个 int16、86 字节。旧表和新表只使用各自 JSON 描述，不能混用。UID/调用上下文自己的锁未改变。

## 上游核对与低版本边界

只下载单个 binder.c、提交元数据及两个补丁，共约 1 MB，没有克隆内核源码仓库。

Android android15-6.6 固定提交 `57b7d85c3513c067bd2ee1eb49e670eba186220f`，android16-6.12 固定提交 `3a7d1771d4925a56f7eeb8a5ba1faff0c544a9ef`：选取的六个 Binder 匹配/投递/释放函数去除空白后相同。android-mainline 固定提交 `cf30e7ec90005bf4c5da240add00afb33199ca4f` 的相关同步清理流程仍相同。它们在 Binder 锁内摘除、锁外同步释放，没有在这段原生清理流程中使用 Workqueue。KPM 保留自己的第二条去重与冻结判断，未照搬 Android 的 TF_UPDATE_TXN 门槛。

正式 Linux 修复 [c4c02084d6687d5cd5edccaf52cc45e5160f1184](https://github.com/torvalds/linux/commit/c4c02084d6687d5cd5edccaf52cc45e5160f1184) 增加 fixup 回收，[22c135635fdd9816c0ef140d6de7b2e4fdf73e89](https://github.com/torvalds/linux/commit/22c135635fdd9816c0ef140d6de7b2e4fdf73e89) 将未投递事务的 is_failure 改为 true。上述三个 Android 固定快照的 outdated 清理块尚缺这两项；本轮取其释放修正，并保留更保守的对象过滤。

[Linux v4.14](https://github.com/torvalds/linux/blob/v4.14/drivers/android/binder.c) 与 [v4.19](https://github.com/torvalds/linux/blob/v4.19/drivers/android/binder.c) 的单文件确认不存在 binder_free_txn_fixups。binder_get_node_refs_for_txn 增加 proc 引用，调用 binder_proc_transaction 后才 binder_proc_dec_tmpref。旧内核不因 helper 缺失禁用无对象去重。本轮不按 Linux 版本号判断，沿用静态偏移与实际 Binder 释放 ABI 配置。

现有 5.15.189-android13-8-00016 镜像符号表含 binder_free_txn_fixups；前轮已确定释放 ABI 为 abi5。本轮未重新分析其它镜像，也未把默认 BTF 模板当作该镜像完整偏移验证。

## 自检

- 八个 abi3/4/5/6 release/debug 探索构建通过；实际 ELF JSON/blob 往返仅改表字节，非法输入和覆盖输出拒绝测试通过。
- ASan/UBSan 主机测试抽取生产清理函数，四 ABI 均通过：只带 TF_ONE_WAY、缺少 helper 仍清理、第二条删除/第一条和 has_async 保留、释放顺序和参数、原生调用方引用不被修改、proc 在锁外释放期间退出、八发送方并发、非事务 work、同步/不同 code/flags/PID/node、NULL buffer/node、Binder 冻结和无在途消息、对象/额外缓冲区消息保留、负偏移字段缺失，以及解冻后最早消息仍可消费。计数与关联均有断言。
- 既有协议、任务上下文和 Genl 自检继续通过，包含 20000 随机报文与八线程 UID 测试。
- 登记产物与已测试字节相同，SHA-256 对照清单通过；全部未定义导入在 KP 导出源码表中，无 get_task_ext；实际 ARM64 指令检查未发现 FP/SIMD/SVE 使用。编译仍有既有 SDK 五条警告，无新增模块编译警告。
- 43 个模板配置与已有 vmlinux.h 生成器完全相同；不据此外推其它目标镜像。clang-format 和 git diff --check 通过。

复现入口：`make -C re_kernel_static baselines OUT_DIR=../local/<新的空目录>`，`python3 re_kernel_static/tools/test_static.py --baselines local/<该目录>`。统一留痕入口采用 `--allow-dirty --no-archive --target baselines --handoff`。日志与身份自检在 `local/static-native-cleanup-20261002-01/`；只对其八个产物报告本轮验证。

## 测试范围变化与未覆盖

Workqueue 的分配失败、queue 回滚、CFI work 回调、容量上限、创建竞争和销毁排空测试已移除：对应实现本轮完全删除。保留原 ELF/协议/Genl 判据，清理改测实际同步释放行为；没有放宽仍存在路径的断言。离线补丁器保留旧 46 项基准的 work 配置校验，新 43 项基准不包含这些字段。

主机锁是 pthread，原生 Binder 函数是受控桩，只证明模型中的业务临界区和资源顺序，不证明 Android 真机锁或 hook 生命周期。未测设备加载、实际 fd 行为、异步空间回收、解冻后的 app 响应、退出/卸载或 CFI。RPC/code 业务规则和 ADD_FREE_ASYNC/DEL_FREE_ASYNC 仍待移植；按 code 匹配不能保证所有消息业务语义可丢弃。

DEV-002 的 Workqueue 相关等待点已从本轮移除，Genl/业务回调的 KP 卸载生命周期仍未完成；修复响应见 [追加响应](responses/2026-10-02-DEV-002-native-cleanup.md)，不关闭问题单，也不更改他方结论。
