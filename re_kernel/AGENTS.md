# re_kernel 工程约定

本目录由 Developer 维护，遵循仓库根目录及 docs/ 的角色与身份规则。README 面向普通用户；加载机制、协议、移植和排查细节在本文件维护。更新记录在 README 保留原文。

## 与上游的既定差异

以下偏离是**有意决定**，不是缺陷；审计、测试与维护者复查都不得按上游语义判为错误。

- **同步与回复事件直接放行**：不参与 code／RPC 名判断，因此这类上报里 `code=0`、`rpc_name` 为空。
- **同 UID 事件不上报**：应用自己拉起自己的场景会产生误导性事件，由维护者决定抑制。
- **异步清理只要求 `TF_ONE_WAY`，不要求 `TF_UPDATE_TXN`**：为兼容 5.4 等缺少该标志的内核而定的取舍；代价是普通同 code 异步消息也会被清理。
- **容量固定 32 项**：规则与监控 UID 使用数组而非哈希表，满时返回 `-ENOSPC`；为 KPM 移植形态与查找性能考虑，不用上游的无上限链表。
- **控制命令仅接受 UID 1000**：已与上游作者确认，LKM 形态不会出现越权调用，KPM 形态需要显式约束；UID 0 同样拒绝。

## 接入、排查与静态移植

基于 Re:Kernel 的 KernelPatch 移植，向配套墓碑应用发送 Binder、信号和网络事件通知，由应用决定是否解冻；模块同时清理冗余异步 Binder 消息。

模块管理名称为 `re_kernel`，使用 Re:Kernel 的消息协议。需要配套墓碑应用支持该协议。

## 选择版本

| 版本 | 文件 | 使用方式 |
| --- | --- | --- |
| 动态版 | `re_kernel.kpm` | 加载时自动获取目标内核偏移 |
| 静态基线 | `re_kernel_baselines.kpm` | 根据目标内核修改偏移后加载 |

两种版本在 APatch 中都叫 `re_kernel`，选择一种加载即可。文件名带 `_debug` 的版本用于排查问题。

适配目标为 Android ARM64，内核 4.4～6.12，按目标能力和布局核对。动态版优先使用 BTF；缺少必要数据或查询接口时，尝试从内核函数推导。获取失败时停止加载，具体原因见内核日志。

## 加载

在 APatch 的内核模块页面加载动态版或已移植的静态版，再由配套墓碑应用连接。网络监控 UID 由墓碑应用配置。

### 安装方式

需要 APatch/KP 支持目录自动加载。在内核模块页选择“安装”（不是“立即加载”），安装器按管理名称将文件保存为 `/data/adb/ap/kpm/re_kernel/re_kernel.kpm`，即 `/data/adb/ap/kpm/<id>/<id>.kpm`；输入文件的版本后缀不影响此路径。启用时应无该目录下的 `disable` 标记。

重启后，KP 在 `post-fs-data` 的 `before` 事件处理期间读取目录加载，无需设置嵌入用的 `-V`。核对模块版本、`load_source=file`、`load_event=post-fs-data` 及对应目录加载日志 `rc=0`；仅有 `load_source=file` 也可能是手动加载，不能单独作自动加载判据。再确认 `rekernel` family，由配套应用连接、订阅并配置网络 UID。模块不会补发加载或订阅前的通知。

**已实机验证自动加载及 family 建立**：结论仅来自 4.19 / XQ-AT52 / KP d09 单机，5.15 未测，不能外推；墓碑应用业务链路未验证。候选身份与实测记录见 [Tester 报告]。该实验以手动复制文件完成，不代表管理器“安装”按钮全流程已实测。

### 嵌入方式

嵌入启动镜像时，**建议**选择 `post-kernel-init`，让原生 Generic Netlink 先完成初始化。符号与偏移检查通过后，若 `init_net->genl_sock` 仍为空，初始化直接返回 `-107`（`-ENOTCONN`）。`pre-kernel-init` 仅在 Genl socket 已建立且其余依赖满足时可行；事件名本身不保证可用。事后 family 存在不能反推加载瞬间已可通信。

使用 kptools 时，在该模块的 `-M <kpm>` 或 `-E <已嵌入名称>` 后指定 `-V post-kernel-init`。加载事件属于嵌入配置，修改后需要更新该配置。

### 更新、停用与边界

- 同管理名 `re_kernel` 冲突返回 `-EEXIST`（-17），不会替换旧实例。嵌入/安装及静态/动态均只选一份，改文件名不能避开冲突。
- `/data/adb/ap/kpm/re_kernel/disable` **只阻止目录加载**，不卸载当前实例，也不禁用嵌入副本。停用已安装文件时设置标记；嵌入件需取消嵌入，再重启并确认实际来源。
- 不要热卸载或热换版；本模块卸载生命周期尚未验证，更换或移除须重启。替换已安装文件后当前仍运行旧版，必须重启才生效；嵌入件更新须更新启动镜像。
- 保留 userdata 通常会保留已安装文件，但**不保证 OTA 后兼容**。新 boot 仍须带支持目录加载的 KP，并满足用户态 `before` 上报、内核导出及布局/ABI 条件；静态偏移须重新核对，重启后再确认 family 和应用连接。

## 静态移植

准备目标设备的 `boot.img`、静态基线及同一构建的 `.kpm.json`，分析目标偏移后填写到 JSON 的 `offsets` 中。基线是移植模板，须先完成目标适配。

在仓库根目录运行：

```sh
python3 patch_offsets.py patch re_kernel_baselines.kpm --offsets target-offsets.json --output target.kpm
```

配套布局文件应放在基线旁，命名为 `re_kernel_baselines.kpm.json`。替换工具只依赖 Python 标准库，用户侧无需 NDK。

## Binder 厂商入口与清理

优先注册 `android_vh_binder_transaction_record`：完整拷贝后、入队加锁前触发，但回调仍禁止抢占。
不能在回调内调用可能获取 mutex 的 `binder_alloc_free_buf`。动态版从目标 BTF 核对 record 的四参数
（`__data`, `tr`, `t`, `in_reply_to`）、`binder_proc_dec_tmpref(binder_proc*) -> void` 与 signed int32
`binder_proc.tmp_ref`，静态移植离线核对同一契约。厂商路径还要求原生 Binder 通知 tracepoint 注册成功及
`copy_from_user_nofault`；缺少能力、ABI 不符或注册失败时，回退到独立 `binder_proc_transaction` before。
两个清理入口都不可用则拒绝加载，不静默跳过异步清理。

record 只处理非 reply、`current` 与 `tr` 均匹配的当前调用，每次调用最多摘除一条旧事务；分配失败
不借用外层调用。按 node → inner 顺序锁内复核，至少有两条匹配旧消息才摘除最早一条，并递增模块自己的
`tmp_ref`、递减 outstanding。`binder_transaction_after` 先脱离模块上下文链表并解锁，再释放旧事务／
缓冲区／fixups，最后调用原生 `binder_proc_dec_tmpref` 归还引用。独立 before 路径沿用外层原生引用，
锁外同步释放。去重仍保留带对象、FD 或额外缓冲的事务；本模块没有 rekx 的用户可配置清理策略或缓冲区读取依赖。

RPC 读取优先使用 140 字节栈缓冲与 `copy_from_user_nofault`，失败跳过该次上报。旧目标缺少此 API 时保留
`memdup_user` 路径，其 tracepoint 原子上下文风险仍待独立处理；本轮 6.12 证据不覆盖该路径。厂商入口在
Genl 初始化成功后最后注册，失败按已安装状态撤销自有 wrap／tracepoint 与 family；热卸载仍不允许。

静态表为 46 个 int16（92 字节）：原前 44 项不动，在末项 `binder_release_abi` 前增加
`binder_proc_tmp_ref`，默认 -1（动态初始化也为 -1）。只在厂商能力验证时写入该字段；老的独立入口不要求
它。`binder_buffer_data` 在本模块业务中未使用，动态常规 BTF 仍只查询原 38 项，不增加 rekx 的读取依赖。
旧 45 项基线必须用旧配套 JSON；不可与本轮表混用。

新分配器 `__kmalloc_noprof` 仅在 `kmalloc`／`__kmalloc` 都不可用时绑定 SDK 同 ABI 封装，此时分配、
Genl 广播统一使用共同 `__GFP_HIGH` 位以避免旧 GFP 高位含义冲突。skb 优先 `kfree_skb`，否则
`consume_skb`，每次只释放一个引用；两者都缺少则拒绝加载。

## 异步清理 debug 观测

两个模块各自维护 `binder_free_outdated`，公共释放顺序与完成日志保持一致。debug 在整个 native buffer／
allocator／fixups／transaction 释放链及删除统计返回后输出一条：
`free_outdated pid=...,uid=...,data_size=...,code=...,stage=done`。诊断值在回收前保存，不读取已释放对象；
日志位于 Binder 锁外，厂商路径在 outer after 内执行，归还模块 proc 引用之前。release 不增加此日志或快照。

一条 done 表示模块完成一次旧事务清理；不是用户态新消息送达或解冻成功。无日志不能单独认定清理次数为0，
还需确认实际 debug 产物、日志采集窗口和过滤、冻结条件、匹配旧消息数及策略。至少已有两条匹配旧消息才删最早
一条，每次最多一条。`re_kernel` 的29～32只约束通知上报；`re_kernel_x` 的SKIP/BY_CODE/BY_DATA策略各自保留。

自检入口：`python3 Developer/tools/test_rekernel_cleanup_logs.py --output <新目录>`；同时核对两份独立函数一致、
release静默、debug日志内容／时序、空消息和可选fixups，以及原生外层归还引用后的延迟回收。

