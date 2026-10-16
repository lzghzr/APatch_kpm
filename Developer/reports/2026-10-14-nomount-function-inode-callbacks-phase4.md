# NoMount：inode 哈希与 getattr 入口

两份目标新增5项取值：inode 哈希链起点、getattr 回调位置、回调参数数、原生入口参数数和挂载上下文类型。现在各有28/46项与绑定布局一致。完整无 BTF 初始化仍未完成；操作表尺寸及目录、控制等布局继续缺失。

源码冻结提交：`aa085fa53af8d0370b0b8f4ad4f2e980fb206ca0`。上一阶段见[基础入口与存储](2026-10-14-nomount-function-object-storage-phase3.md)。本轮是 Developer 探索构建与宿主自检，没有独立审计或实机结论。

## 取得方式

| 字段 | B2N 4.4 | Sony 4.19 |
| --- | ---: | ---: |
| inode_hash | 224 | 224 |
| iop_getattr | 144 | 128 |
| getattr_callback_args | 3 | 4 |
| getattr_function_args | 2 | 4 |
| getattr_context_kind | 0 | 0 |

`generic_drop_inode` 在两个目标均内联。`ext4_drop_inode` 入口先检查已取得的 nlink，再检查 hlist.pprev；窗口最多12条，实际4.4止于第9条，4.19止于第12条。hlist 的 next／pprev 连续定义放进 nm_structs.h，只从入口取得起点，不重复推导其内部成员。

`vfs_getattr_nosec` 的旧入口在12条内将 mount、dentry、stat 转给回调；另一入口在29条内以 path、stat、request_mask、flags 调用回调，包含原有CFI检查。连续核对对象链、回调寄存器和参数来源；不跳过未知指令追找后续调用。`simple_getattr` 另在首9条内核对回调参数位置及准确的 generic_fillattr 直接调用。共同 path／dentry 定义继续复用，ABI依据机器码选择。

指令解码统一扩展 kpm_utils.h 的 SUB immediate、SUB/SUBS shifted register 和 EXTR；消费者核对位宽、寄存器、移位及立即数。BTF 查询接口保持上一阶段状态。无数据／接口时 inode 降级先取得存储，再取得本轮字段，最后仍执行完整公共校验。

目标源码引用沿用前阶段：Sony提交与镜像版本标记一致；B2N使用4.4.196的Nokia语义参考，实际镜像为4.4.192，变化字段以镜像访存核对。

## 自检

- 新增 test_function_inode_callbacks.py，执行真实镜像窗口的生产推导代码。两目标各28项断言及 ASan／UBSan 通过；原生内核函数没有执行。
- 上一阶段脚本中的61条断言文本均保留，原47个工具文件逐字节未变。新增缺符号、逐条未知调用、参数来源、间接调用、分支位置、错误字段和寄存器覆盖反例。
- 首次4.4新测试把取得证据之后的指令也纳入“每条改为未知调用必须拒绝”，失败于已不再读取的后续指令。本轮新增用例改为只覆盖实际消费的9条；原脚本及原断言保持。首次失败日志保存在本地探索目录，未据此扩大生产扫描范围。
- Sony5.15真实BTF的46项查询及原拒绝断言通过。沿用上一阶段的私有API适配副本；BTF查询、断言及生产接口没有新增迁就。
- 干净冻结提交的141个输入经统一构建入口生成dynamic／static。探索档复算源码blob、配方参数、归档产物哈希通过，ELF及92字节默认表通过。只有SDK已有 READ_ONCE／WRITE_ONCE 重定义警告。静态件与上一阶段逐字节一致；静态JSON核对后以独占创建附入新归档。

逐项结果、源文件哈希及剩余18项见[阶段数据](data/2026-10-14-nomount-function-inode-callbacks-phase4.json)，完整身份见[构建清单](handoffs/2026-10-14-nomount-function-inode-callbacks-phase4.json)。

| 模式 | instance_id | SHA-256 |
| --- | --- | --- |
| dynamic | `nomount-2.1.1-20261014+gfa2f32c623be.r9e38a8ed.kpb51197a.ndk26.3.11579264#1` | `94400d78ace89f2c9217ad35be2376d40e82e6da3d600d5c055af21191790e60` |
| static | `nomount-2.1.1-20261014_baselines+gfa2f32c623be.r72e5f7b8.kpb51197a.ndk26.3.11579264#1` | `76e220cd0c7a6c2f5002d5f26148483baa06ccccad61f4838060159b7f2adac2` |

## 挑战结论：保留（Retain）

**有效性**：辅助反例检查发现 nlink 的窄加载可能覆盖 inode 基址，或保存 inode 时覆盖待测 nlink。修正后拒绝 W0／WZR，以及保存 X19 时的 W19，新增反例通过。本轮5个字段在两目标上与参考一致；完整初始化仍受缺项限制。

**简洁性**：共同结构覆盖 hlist、path 和 dentry 内部位置；只取变化的起点、槽位和ABI。已有短入口是当前较小的可用依据，不需要全函数扫描或按版本分派。

**后果**：新增符号或编译形态不匹配时会拒绝推导；有BTF的原路径不受影响。完整操作表复制范围继续要求独立尺寸证据。此挑战由Developer辅助检查完成，不代替Auditor复核。

respect-the-oracle 已核对旧断言、真实BTF回归及宿主证据边界；no-negative-echo 已回读源码、身份清单和本报告。没有设备操作、发布或问题关闭。

## 后续缺项

仍缺4类完整对象尺寸、super回调、目录操作与控制布局等18项。原生操作表复制阶段仍早于本轮 inode 阶段；当前完整动态入口仍会因无BTF的尺寸缺项停止。本轮组件成功不表示加载失败点已经越过该阶段。

头文件确有可影响复制范围的差异，例如Sony的super／dentry操作表有Android KABI尾部，super还包含条件QUOTA成员。其共同前部可以共用，完整尺寸继续需要目标证据。下一段优先处理目录及控制的短入口，并继续寻找可用的完整尺寸来源。完整候选和旧KP二进制派生件待缺项补齐后交接。
