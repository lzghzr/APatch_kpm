# NoMount：基础入口与 inode 存储推导

两份目标现在都能通过完整的基础对象推导入口，inode 存储新增四项取值。每份目标共23项与绑定布局一致。完整无 BTF 初始化仍缺操作表复制尺寸及后续接口布局；本轮保存为探索构建，没有实机或独立审计结论。

源码冻结提交：`012f607fe5d5c3e630cccb0d99f15d2ded60ef71`。前两阶段见[文件字段](2026-10-14-nomount-function-file-phase1.md)和[规则／文件回调](2026-10-14-nomount-function-rule-file-phase2.md)。

## 共同定义与变化项

偏移不需要逐个推导。能覆盖目标的完整定义或连续片段直接复用，仅取得变化的起点、完整尺寸和 ABI；短入口也可用于核对共同定义是否适用。

- path 的16字节定义与 dentry 前部继续共用。规则入口核对这段的实际基址链，未增加成员偏移。
- 本轮以 nm_inode_file_locks 表示连续的 i_fop／i_flctx，i_data 紧随其后。只从 inode_init_always 取得起点，并核对连续关系。
- kstat 采用两个已核对的前部及时间／blocks 片段。mode／uid／gid 读写决定格式；后续成员位置使用对应定义，不按内核版本选择。
- address_space 的完整尺寸随目标配置变化，从原生完整清零长度取得。inode／super／dentry 操作表也有条件成员、厂商扩展或对齐，不能把本地片段大小外推为完整复制范围。

约定已写入[模块 AGENTS](../../nomount/AGENTS.md)。新增结构在[nm_structs.h](../../nomount/nm_structs.h)，取值、验证和调度仍在[nm_offsets.c](../../nomount/nm_offsets.c)，BTF 查询独立在[nm_btf.c](../../nomount/nm_btf.c)。

## 4.4 基础路径修正

上一阶段的自检执行了规则／文件组件，基础 file_inode_ops／file_mapping 由目标参考预置，没有证明4.4的基础入口可用。本轮从未填状态执行 calculate_function_offsets，发现并修正这些原有未覆盖形态：

- iterate_dir 分开加载 f_op／f_inode；连续四条核对同一入口对象、相邻片段关系及回调测试，不线性穿越调用。
- generic_file_mmap 在最终指针检查前设置 W2=-8；只接受这一明确的 MOVN 形态，不能覆盖待测寄存器，所有前瞻仍在8条内。
- generic_fillattr 的旧 kstat 前部不同；通过 mode／uid／gid 恰好匹配一种共同定义，再取得 sb／ino／size。superblock 读取中的独立 ADD 不得覆盖对象参数或中间寄存器。
- set_nlink 的非零输入边跳过 clear_nlink 调用。核对入口保存及 CBNZ W1，分支目标必须落在原8条窗口内并直接从 X0 读取 nlink；不扫描被跳过的调用路径。
- d_set_d_op 的首条读取与 CBZ 对应 WARN_ON_ONCE(dentry->d_op)；只核对前两条，不穿越告警块。原 CBNZ／setter 形态继续保留。

这些修正属于既有非 BTF 缺项的开发工作；DEV-039/040 提案及他方报告状态不由本轮修改。

## inode 存储

| 本轮取得项 | B2N 4.4 | Sony 4.19 |
| --- | ---: | ---: |
| inode_file_ops | 328 | 368 |
| inode_data | 344 | 384 |
| inode_data_size | 152 | 264 |
| inode_blocks | 152 | 144 |
| kstat_inode_first | 1 | 0 |

inode_init_always 限定前21条，追踪静态 no_open_fops 的 ADRP／ADD／STR，核对 i_data 起点。address_space_init_once 限定前8条，核对 memset 目标、零填充和长度。两个目标的原生源码都明确清零完整 address_space；这取得的是完整尺寸，不是分配桶容量。

整对象长度识别共用有界函数：tty_default_fops 仍为7条，address_space_init_once 为8条。新增 MOV W1,WZR 形态保留原有参数保护；未知指令失败。scalar-copy 使用已观察指令白名单，不跨调用、分支、带写回 pair 或未知原子指令。

inode BTF 查询增加 unavailable 输出；只有明确缺数据／接口才走存储推导。其后仍执行完整公共校验：hash、回调槽或 ABI 未取得时继续失败。本轮没有把取得四个存储字段等同于 inode 阶段完成。

## 尺寸查找范围

对 Sony 准确提交读取54012个C／头文件，对 Nokia语义参考提交读取43024个。以显式类型名做词法过滤，保存相关文件及固定提交来源；此过滤不能证明其他表达形式不存在。

两树均找到 ISOFS 的 dentry_operations 数组和取元素代码，可作为寻找步长锚点的方向；两份镜像 CONFIG_ISO9660_FS 都未启用，且没有对应符号，不能用于当前目标。目前仍没有可用的 inode_operations／super_operations／dentry_operations 完整复制尺寸锚点。检索范围与来源见[阶段数据](data/2026-10-14-nomount-function-object-storage-phase3.json)。

B2N头文件来自4.4.196语义参考，字段与实际4.4.192镜像机器码核对；不将该源码称为镜像的准确构建源码。

## 自检与冻结身份

- 新增 test_function_object_storage.py，保留上一阶段规则／文件组件断言，从未填状态执行真实基础入口，并执行 inode 存储推导。两份真实镜像各23项核对通过，ASan／UBSan通过。
- 新增错位、缺依赖、构造长度／调用错误、隐式寄存器覆盖、分支越界及共同布局变化反例；公共校验仍拒绝不完整 inode 布局。原生函数不执行，BTF路由由API夹具提供。
- 原基础Oracle在Sony4.19入口及合成BTF上通过。私有副本只补当前日志宏、后缀查找API别名和源码定位，全部断言保持。首次缺日志宏导致宿主编译失败，补齐夹具声明后通过；未更改生产日志接口来迁就夹具。
- Sony5.15真实BTF的46项查询和原拒绝断言通过。私有副本仅给规则／inode查询调用传新增 unavailable 参数并调整源码定位。原47个工具文件逐字节保持。
- 辅助挑战发现 FP赋值与SCS写回会留下过期地址追踪；分别清除 X29／X18 的状态，并补两种构造反例。修正后本段判定保留（Retain）。源码中已有目标窗口和连续片段是更小的可用实现基础；无需全函数扫描。未知形态保留失败。这是Developer辅助检查，不是Auditor结论。
- 统一构建入口从干净提交冻结140个输入，dynamic／static构建通过。只有SDK既有 READ_ONCE／WRITE_ONCE 重定义警告；探索档复算输入、配方参数及产物哈希通过，ELF与92字节默认表通过。静态件与前一阶段逐字节一致，静态JSON校验后以独占创建附入新归档。

清单：[阶段身份](handoffs/2026-10-14-nomount-function-object-storage-phase3.json)。两件均为 exploration。

| 模式 | instance_id | KPM SHA-256 |
| --- | --- | --- |
| dynamic | `nomount-2.1.1-20261014+g4e73d7400044.rdf8f5ea6.kpb51197a.ndk26.3.11579264#1` | `c802b79b3e65b17a06aba12e090321ca71642e4299e868151c0e1426f01684ad` |
| static | `nomount-2.1.1-20261014_baselines+g4e73d7400044.r7aa60b6f.kpb51197a.ndk26.3.11579264#1` | `76e220cd0c7a6c2f5002d5f26148483baa06ccccad61f4838060159b7f2adac2` |

are-you-sure 已核对具体覆盖反例、共享结构与短窗口的必要性及未知形态后果；respect-the-oracle 保留原工具和断言，并限定宿主证据；no-negative-echo 回读源码、报告及回执。没有设备操作、发布或问题关闭。完整候选及其旧KP派生件待剩余缺项完成后再交接。
