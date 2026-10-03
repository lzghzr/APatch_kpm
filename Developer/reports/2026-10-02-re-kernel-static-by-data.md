# Developer 记录：BY_DATA 异步事务去重

角色 Developer。按用户授权接入 BY_DATA，复用上轮 RPC 的内核缓冲读取入口；不新增结构体偏移。实现方探索自检，不是独立审计、冻结候选或真机结论。

## 身份

完整基础提交 `40d33aca895cc4778deb1925ec12e4a635b5612f`，source_dirty=true；实际构建输入指纹 `946cd5cf892429a94ac30715f07061c79c3184e7d1112edb3cca99ef32cbef35`。SDK KP 0.13.9 `b51197aaba8f2272dd8a3e30c85698a29aa928c9`，工具链 ndk26.3.11579264。统一 build_candidate.py 入口使用 --target baselines --allow-dirty --no-archive --handoff，复核输入未变，旧产物保留。八个登记字节与先前自检构建逐字节相同。未修改维护者元数据、旧清单或报告，未提交、签名或执行设备操作。

完整身份见 [探索清单](handoffs/2026-10-02-re-kernel-static-by-data-exploration.json)。

| 变体 | instance_id | SHA-256 |
| --- | --- | --- |
| abi3 | `re_kernel_static-8.0.0_abi3+g946cd5cf8924.r9595641f.kpb51197a.ndk26.3.11579264#1` | `1e2ec204b41f6fd555784ac3000afa2f5df5ce480fadec55bc23d9ce5351e8e7` |
| abi3_debug | `re_kernel_static-8.0.0_abi3_debug+g946cd5cf8924.r81f109d6.kpb51197a.ndk26.3.11579264#1` | `70b1798cfd5e1e502be9f9594f3d4bf80c689c40a08e958ee8cf8cde408d6576` |
| abi4 | `re_kernel_static-8.0.0_abi4+g946cd5cf8924.r006e500f.kpb51197a.ndk26.3.11579264#1` | `8d8585ed504bef16e45464b46a0d4eaec8e47244f0c6a3d9e125214d1b7bf0a6` |
| abi4_debug | `re_kernel_static-8.0.0_abi4_debug+g946cd5cf8924.rdd866aeb.kpb51197a.ndk26.3.11579264#1` | `347574a92521ee7ec6f42d085b079d57001cc5990d2752489b7308b18aa48955` |
| abi5 | `re_kernel_static-8.0.0_abi5+g946cd5cf8924.r3f4d70b6.kpb51197a.ndk26.3.11579264#1` | `a9bdb3aeb5b416399da8566d04353a3b5bf6876e96c7175b607f185e3263ad26` |
| abi5_debug | `re_kernel_static-8.0.0_abi5_debug+g946cd5cf8924.r32c12fc1.kpb51197a.ndk26.3.11579264#1` | `538b592cb91c4168718c6b7c9ced03546a3563d44b5938a6874d38edc98cb499` |
| abi6 | `re_kernel_static-8.0.0_abi6+g946cd5cf8924.r2892f61a.kpb51197a.ndk26.3.11579264#1` | `9330200ba7d0f35acb4e69b146c51c456b4ed9008fe3c3fc2d8431caeb8d3015` |
| abi6_debug | `re_kernel_static-8.0.0_abi6_debug+g946cd5cf8924.r1ab2e216.kpb51197a.ndk26.3.11579264#1` | `797dfcd55a0735ae8d1d3b0921f340bac453eb80be6281e701764d78e4d58d48` |

## 行为与实现

ADD_FREE_ASYNC 现在接受 strategy=3/BY_DATA；SKIP、BY_CODE、RPC 名称与 code 的精确/通配优先级和数组增删保持。接收编号不改变，BY_DATA 不再返回“不支持”；目标缺少 binder_alloc_copy_from_buffer 时，所有新增规则仍返回 -EOPNOTSUPP，基础去重继续可用。低版本缓冲读取兼容仍未实现，本轮没有按版本号猜页、alloc 或 buffer 偏移。

策略从锁外 RPC 解析传入队列扫描和事务匹配。BY_DATA 先通过既有 proc、code、flags、PID（可用时）及 node ptr/cookie 匹配；双方 buffer/node 必须存在，offsets_size 与 extra_buffers_size 必须为零，带对象/FD 的消息继续保留。然后比较完整 data_size，按 64 字节小栈缓冲读取双方全部 data，逐块 memcmp，任何不同均不视为重复。保留最早完整相同者，仍只摘除第二条完整相同消息。原生 node/inner 锁保护比较、队列和计数，摘除后的原生锁外释放顺序与四种 ABI 不改变。

持锁比较采用每次扫描共用的 64 KiB 读取预算，两侧计入，比较前按双方完整长度预扣，避免乘法溢出。早期不相同也不退还预留预算，是保守上限；预算不足则停止扫描、保留事务。两次相同候选至少消耗 4*data_size，故仅就预算而言，超过 16 KiB 的消息本轮不会被此规则清理。所有候选共享预算，不能逐项重置。任何缓冲读取错误立即终止本轮扫描、保留队列；不退成 BY_CODE。BY_CODE 不读完整 data，也不消耗此预算。字节预算限制读取工作量，不是实际持锁毫秒数保证。

偏移表仍为 43 项/86 字节；自定义常量在 re_kernel.h，内核定义未改。未加入新分配、Workqueue 或模块私有锁到 Binder 摘除/释放路径。源码按 .clang-format。

## 来源核对

参考上一轮已读取的 [ReKernel-X 数据比较](https://github.com/myflavor/ReKernel-X/blob/8c217319d7d73c40667650a43a485e9f185e3a92/LKM-Source/rkx_binder_kp.c)：同一内核缓冲复制入口、完整长度和 64 字节分块比较。本轮增加共享预算及读取错误停止整轮的保留行为，不将其描述为完全照抄上游。

另仅读取 [Android android14-6.1 binder_alloc.c](https://android.googlesource.com/kernel/common/+/refs/heads/android14-6.1/drivers/android/binder_alloc.c)，访问日期 2026-10-02，单文件 36266 字节，快照 SHA-256 `c625975a8d88174d202c1ace00df0feb63718161839e7e997a63458336db9d01`。copy_from_buffer 进入边界检查与页内 memcpy 路径，该源码路径没有分配、mutex 或用户页缺页读取；读取偏移按 4 字节对齐，64 字节递增满足。未下载整个内核，未对当前目录所有镜像做推导。该上游源码核对不能代替目标厂商实现、内核锁调用约束和函数 ABI 的验证。

## 自检与覆盖

八个最终真实 ELF 的补丁 JSON/blob 边界、SHA 与保存副本一致；全部 19 项未定义导入在当前 KP 导出源码表中找到，新增比较使用 kf_memcmp，无裸 C 运行库/task_ext 依赖。ARM64 实际指令无 FP/SIMD/SVE。编译仅保留既有五类 SDK 警告；格式 dry-run 和 git diff --check 通过。

生产函数抽取的 ASan/UBSan 测试在 ABI3/4/5/6 全部通过：Genl 接受/查找/删除 BY_DATA，原规则和 UID 边界继续通过；相同完整数据、长度不同、头部/64 字节块边界/4096 字节边界/尾字节不同、空数据/短尾/SIZE_MAX 溢出拒绝；两次候选比较的每一次复制失败均保留队列和计数；最早相同事务保留；对象/FD/额外缓冲区保护；16 KiB 预算边界、20 条候选共享预算、八个并发发送方计数和释放一致。原协议、全 code 上报、上下文、Genl 生命周期、四 ABI 释放顺序、proc 死亡等检查继续通过。

主机边界测试使用数组模拟内核页数据，验证偏移与尾块处理，没有实际映射内核页；锁用 pthread 模拟。binder_proc_alloc 测试替身原先只被锁外路径调用，现在兼容已持有 proc 锁时的偏移访问，避免替身重复加锁；既有调用方引用、释放顺序和生命周期断言保留。Genl 原“拒绝策略 3”断言依授权变更为“接受并可查询/删除策略 3”；未知策略仍拒绝，其余检查不缩小。

证据位于 local/static-by-data-20261002-01/ 的 build.log、expanded-tests.log、registered-build.log、registered-tests.log、identity-selfcheck.json 与 registered/ 保存字节。未测实机 ACK、厂商函数原子上下文、持锁实际耗时或应用解冻后响应；不能据此保证所有目标不会假死。卸载生命周期和既有外部依赖问题保持未解决，Developer 不关闭他方问题单。
