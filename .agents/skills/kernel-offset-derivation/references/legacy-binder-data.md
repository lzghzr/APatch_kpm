# 旧 Binder 数据读取经验

适用场景：目标镜像没有 `binder_alloc_copy_from_buffer`，需要读取已复制的 InterfaceToken 或比较异步事务 data。以下偏移是 B2N-416G 单一镜像的结果，不是整个 4.4 系列的默认值。

## 查找顺序

先枚举目标的 Binder 符号，再查当时源码：功能可能仍内联在 `binder_transaction`、使用不同名称，或者旧内存模型已经能直接复制。优先复用内核入口；只有确实没有入口才提取必要逻辑。

[Android wahoo 4.4 的 binder_alloc.h](https://android.googlesource.com/kernel/msm/+/android-msm-wahoo-4.4-pie/drivers/android/binder_alloc.h) 定义 `binder_buffer.data` 为内核映射指针。[binder.c](https://android.googlesource.com/kernel/msm/+/android-msm-wahoo-4.4-pie/drivers/android/binder.c) 把用户事务数据直接复制到这个地址。[binder_alloc.c](https://android.googlesource.com/kernel/msm/+/android-msm-wahoo-4.4-pie/drivers/android/binder_alloc.c) 建立内核映射，并维护用户/内核地址差值。无需照搬后来按页映射的复制函数。

## 用目标镜像验证

B2N-416G_boot.img 的裸 Image SHA-256：`7633fbac5ce30b726a1acdbf57f730aa847a9510984a25bc23f9ddcdb0956e1c`。

- `binder_alloc_buffer_size`：`alloc+0x38` 取得映射基址，`alloc+0x78` 取得容量，`buffer+0x58` 取得数据地址；末块和相邻块两条分支共同核对。
- `binder_alloc_mmap_handler`：映射基址写入 `alloc+0x38`，首块 `data` 写入 `buffer+0x58`，交叉验证这两个字段。
- 因而该目标 `binder_buffer.data=0x58`、`binder_alloc.buffer=0x38`。旧表曾有 `alloc.buffer=0x40`，必须按镜像修正，不能凭已有表直接复用。

详细开发证据见 [本轮报告](../../../../Developer/reports/2026-10-02-re-kernel-static-binder-read.md)。这些值只覆盖本轮读取适配，完整目标配置仍需核对其它字段。

## 静态模块如何使用

`re_kernel_x` 的读取入口先调用原生 `binder_alloc_copy_from_buffer`。缺少原生函数时，仅在离线确认并配置 `binder_buffer_data>=0` 后读取该内核映射指针；默认 -1 表示未配置。新内核的 `user_data` 是用户地址，不能填入这里直接解引用。

读取当前未投递事务或由 node/inner_lock 保护的队列事务，沿用 Binder 的资源生命期，避免另造异步释放流程。检查消息数据长度和复制范围，读取失败保留事务。RPC 匹配和 BY_DATA 比较共用这个入口，整次比较预算不能因切换读取方式而失效。

测试应覆盖两种入口、原生优先、未配置、空指针、free 缓冲、长度/溢出/对齐、分块与跨页尾字节、RPC 策略匹配、保留最早消息和共享预算。主机模型不证明目标内核映射生命周期或真机应用响应。
