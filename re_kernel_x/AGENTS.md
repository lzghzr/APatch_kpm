# re_kernel_x 开发说明

本文件适用于 `re_kernel_x/`，结合仓库根目录 `AGENTS.md` 与 `docs/` 的角色规则执行。模块源码、移植工具和实现方自检由 Developer 维护；审计与真机结论分别引用独立角色报告。

## 文件约定

模块注册名、目录名与产物名前缀为 `re_kernel_x`，Generic Netlink family 为 `rekernel_x2`。模块自己的定义放 `re_kernel.h`，核对过的内核结构放 `re_structs.h`，KP 风格封装放 `re_utils.h`，公共宏放 `../kpm_utils.h`。缩进遵循仓库 `.clang-format`。

README 面向使用者，保留用途、移植入口、公开控制接口和更新记录；实现细节、分析步骤与自检说明维护在本文件。静态移植方法见 [静态二进制移植技能](../.agents/skills/kpm-static-binary-port/SKILL.md)，偏移依据见 [偏移分析技能](../.agents/skills/kernel-offset-derivation/SKILL.md)。

## 静态移植方式
针对目标内核 img 离线分析结构体偏移和字段宽度，替换 `re_offsets.c` 中的固定值后构建对应 KPM；有目标 BTF 时，也可以用 `re_vmlinux.c` 提取。模块直接使用这些固定值，偏移核对在移植阶段完成。

函数签名或调用逻辑无法共用时，沿用 `binder_transaction_buffer_release` 的条件编译方式，依据目标内核的实际 ABI 选择构建配置，例如 `make -C re_kernel_x REKERNEL_BINDER_ABI=3 all debug`。Makefile 将同一编号传给条件编译和二进制 ABI 标记，默认值为 6。共同布局复用结构体定义，变化的字段保留静态偏移。运行时保留符号缺失、输入边界和内核调用错误等正常处理。

使用 KP SDK 的 kfunc_lookup_name/kvar_lookup_name，保留原名查找与编译器后缀查找。当前 SDK 0.13.9 的这两个宏依赖 kallsyms_lookup_name_by_suffix；该函数从 KP 0.13.6 开始导出。运行端需提供这一导出，建议更新至本轮构建使用的 KP 0.13.9。必需内核符号仍在初始化检查；旧 KP 缺少导出时会在初始化之前加载失败。

偏移表单独放在 `.data.re_offsets`，使用 `volatile` 防止编译器把固定值折叠进指令。当前为 44 个小端 `int16_t`，共 88 字节；字段顺序、文件位置、Binder ABI 和 KPM SHA-256 随构建写入同名 `.kpm.json`。这些信息由离线工具使用，模块直接读表。

Releases 发布 ABI3/4/5/6 的非 debug 基准及各自的布局 JSON，debug 和全部基准布局文件同时保存在对应 Actions artifacts。缺少配套 JSON 时，可用同一构建提交的 `tools/patch_offsets.py` 和 `re_offsets.c` 执行 `baseline <基准.kpm> --output <基准.kpm.json>` 生成，无需 NDK；不能用不同提交的字段顺序代替。

准备四种 Binder 释放函数 ABI 的 release/debug 基准版，输出目录使用新的空目录：

```bash
make -C re_kernel_x baselines OUT_DIR=../local/baselines-round1
```

`abi3` 为 `(proc, buffer, failed_at*)`，`abi4` 为 `(proc, buffer, failed_at, is_failure)`，`abi5` 为 `(proc, thread, buffer, off_end_offset, is_failure)`，`abi6` 为 `(proc, thread, buffer, failed_at, is_failure)`。编号沿用原条件编译分支，依据镜像中实际函数签名选择。

将对应 `.kpm.json` 的 `offsets` 按目标 img 分析结果填写完整，生成新的 KPM：

```bash
python3 re_kernel_x/tools/patch_offsets.py patch local/baselines-round1/re_kernel_x_1.6_abi6.kpm --offsets local/target-offsets.json --output local/target.kpm
```

也可用 `dump <kpm> --output local/offsets.bin` 导出原始偏移表，按基准 JSON 的 `fields` 顺序修改，再用 `patch <kpm> --blob local/offsets.bin --output local/target.kpm` 替换。工具仅改数据段，保留代码与重定位；输出文件和伴随 JSON 均不覆盖已有文件。基准中的初始偏移是模板，移植前需核对目标镜像。

异步清理仍由模块自行去重：仅要求 TF_ONE_WAY，不要求低版本没有的 TF_UPDATE_TXN；在 node/inner_lock 下摘除第二条匹配消息，保留最早一条。只处理任务组已冻结、proc 未退出、未 Binder 冻结且 node 有在途 async 事务的情况。带对象/FD 或额外缓冲区的事务保留。

摘除时减少 outstanding_txns，解锁后清除 transaction/buffer 双向关联，同步释放 buffer 和 transaction。原生 Binder 调用方的 target_proc 引用保护释放过程，模块不额外操作 tmp_ref。ABI4/5/6 使用 is_failure=true 表示消息尚未投递；ABI3 保留原有 failed_at=NULL 签名。binder_free_txn_fixups 是可选函数：目标内核有时调用，没有时仍可清理无对象消息，不移植其内部 FD 布局。

保留 binder_proc_is_dead 静态偏移；移除 tmp_ref 和两个 work 配置，当前偏移表为 44 项。旧基准 JSON/blob 与新基准不混用。Binder 摘除与释放路径不使用 Workqueue；规则数组使用模块短临界区锁。按 code 去重的业务语义、目标锁和应用解冻后的响应仍需真机确认，卸载生命周期继续暂缓。

## 消息协议
自定义常量、命令和事件结构体放在 `re_kernel.h`；内核定义放在 `re_structs.h`；内核调用与 KP 风格封装放在 `re_utils.h`。

`struct rekernel_event` 是模块内部的 176 字节事件。发送层按 ReKernel-X 的编号转换为 Generic Netlink 嵌套 attributes：外层 `EVENT=1`，内层 Binder=10、Signal=20、Network=30；内部 Binder 子类型转换为上游的 Transaction=1、Reply=2、Overflow=3。异步 Transaction 上报所有 code，RPC 名称最多 139 字节。三类事件发送到 `rekernel_x2` family 的 `events` 组播组，version=1、cmd=EVENT（1）。用户态通过 Generic Netlink 控制器查询 family 和组播组 ID，订阅后接收 attributes。

接收支持 `ADD_MONITOR_NET=2`、`DEL_MONITOR_NET=3`，参数为 `UID=40` 的 4 字节小端 u32 attribute。UID 数组容量保留 32 项，重复添加和删除不存在的 UID 返回成功；删除后压紧，满时返回 `-ENOSPC`。读写使用模块自己的短临界区锁；容量满不再扩大到监控全部 UID。

控制命令只允许内核消息凭据中的 UID 1000，其他 UID 返回 `-EPERM`；包括 UID 0。凭据来自 `NETLINK_CB(skb).creds.uid`，报文中的目标 UID 与 PID 不用于鉴权。`sk_buff.cb` 和凭据复用核对过的共同布局，目标头文件生成器会检查其位置与宽度；偏移表仍为 44 项。此限制作用于控制命令，组播订阅仍由内核与 SELinux 决定。

接收侧 hook 内核 `genl_rcv_msg`，只拦截本 family 的请求，返回值交给内核接收流程生成 ACK；设置 `NLM_F_ACK` 可获得处理结果。其它 family 保留原流程。本 family 限定 init_net，检查报文长度、版本和 UID attribute 的长度/标志，拒绝重复 UID、截断报文以及 dump 请求。`ADD_FREE_ASYNC=4` 使用 `STRATEGY=41`（u8）、`RPC_NAME=42`（NUL 结尾字符串，最多 139 字节）、`CODE=43`（小端 s32）；`DEL_FREE_ASYNC=5` 使用 RPC_NAME 和 CODE。code 从 -1 起，-1 为 RPC 通配规则，精确 code 优先。重复添加更新策略，删除不存在的规则返回成功；32 项固定数组满时返回 `-ENOSPC`，删除用尾项填补空位。

清理规则支持 `SKIP=1`（保留消息）、`BY_CODE=2`（沿用原有 code 去重）、`BY_DATA=3`（code 和完整 data 都相同）。BY_DATA 先核对事务身份和 data_size，再在 Binder 锁内按 64 字节分块比较；带对象/FD 或额外缓冲区的消息仍保留。单次清理扫描共享 64 KiB 的两侧读取预算，候选比较前预扣两侧完整长度；预算不足或读取失败就停止扫描并保留事务，数据不同则继续寻找，保留最早的数据相同消息。BY_CODE 不消耗此预算。无规则或没有匹配项时沿用基础去重。规则匹配在 Binder 锁外通过共用读取入口，读取已复制缓冲中固定 PARCEL_OFFSET=16 的 ASCII UTF-16 InterfaceToken，完整 NUL 终止后才匹配；读取失败、截断或非 ASCII Token 时保留消息。读取入口优先调用内核 `binder_alloc_copy_from_buffer`。旧 Binder 直接映射内核数据地址时，将 `binder_buffer_data` 配成目标 `binder_buffer.data` 的偏移，缺少原生函数时按该偏移复制；该字段默认 -1，不能填写 `user_data` 的偏移。B2N-416G 的镜像确认 `data=0x58`、`alloc.buffer=0x38`，不能沿用模板 allocator 偏移；这些是局部分析结果，完整目标配置仍需核对。既没有原生读取函数又未配置内核 data 时，添加规则返回 `-EOPNOTSUPP`，基础去重仍可使用。未注册 `genl_ops`，控制器不会公布命令列表；客户端按以上编号发送。

原有私有 Netlink unit、固定 port 100 和 `/proc/rekernel` 发现路径已移除。现有冻结判断、事件过滤和 Binder 清理行为保留，因此通信格式对齐不表示所有上游业务行为已对齐。

## 当前移植进度
Generic Netlink family 沿用静态内存块，`hdrsize/name/version/maxattr` 复用共同配置段，变化字段使用静态偏移。填写 family 和组播组配置后调用 `genl_register_family` 或 `__genl_register_family`。接收侧避免引入 `genl_ops`、`genl_info` 的跨内核布局，只新增 `sock_sk_net` 偏移来核对请求所在网络命名空间；默认值来自已有目标 BTF。

注册失败时撤销新增接收 hook；Genl 初始化失败时撤销本轮安装的业务回调并返回错误。无组播订阅者（`-ESRCH`）按正常情况处理，发送失败按内核 skb 所有权约定返回错误。偏移生成器继续在编译期核对共同配置段、存储容量和计数字段宽度。

当前 KernelPatch 在 RCU 读锁内执行模块 `exit`；family 注销与回调生命周期的卸载问题依本轮范围继续暂缓。

四种 Binder ABI 的 release/debug 共 8 个完整 KPM 已完成探索构建。真实产物的 JSON/二进制补丁往返，以及生产消息、Genl 收发函数的 ASan/UBSan 主机自检通过。自检入口为 `python3 re_kernel_x/tools/test_static.py --baselines <基准目录>`。

RPC 参数由模块自己的调用上下文保存：`binder_transaction` 的 before 登记任务与 hook 参数地址，事件读取当前任务最内层调用的 `tr`，after 按调用地址删除并释放。上下文分配失败时暂时跳过 RPC 读取，防止嵌套调用误用外层数据；before/after 主机测试覆盖任务隔离、嵌套、分配失败与 8 线程并发。

Genl 自检包含实际报文字节、139 字节 RPC、attribute 写入失败与 skb 所有权、UID 与规则数组容量/更新/删除、精确及通配规则、BY_DATA 全字节/长度/读取失败/预算/并发清理、旧内核 data 读取及无读取入口时的降级、命名空间隔离、注册失败回滚、20000 个随机输入和 8 线程并发。主机锁以 pthread 模拟，只验证临界区业务逻辑；目标内核锁、ACK、hook 与组播订阅的真机行为待验证。

审计与实机覆盖以绑定完整提交、构建实例和产物哈希的角色报告为准；旧测试结论只绑定旧产物。
