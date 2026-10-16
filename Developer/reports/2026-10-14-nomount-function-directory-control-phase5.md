# NoMount：目录与控制布局

两份目标新增7项核对，现在各完成35/46项。共同结构覆盖的成员直接复用；变化的起点和接口形态取自短入口。完整无 BTF 初始化仍缺11项及后续原生接口核验，本轮保存为探索构建。

源码冻结提交：`87b020dc1cd86b8651f8ec67627ab2ec4008cf02`。上一阶段见[inode 哈希与 getattr](2026-10-14-nomount-function-inode-callbacks-phase4.md)。本轮是 Developer 宿主自检，没有独立审计或实机结论。

## 新增取值

| 字段 | B2N 4.4 | Sony 4.19 |
| --- | ---: | ---: |
| mutex_size | 40 | 32 |
| mutex_no_lockdep | 1 | 1 |
| key_preparse_data | 40 | 40 |
| fillattr_abi | 2 | 2 |
| dentry_lock | 88 | 88 |
| fop_iterate | 48 | 48 |
| fop_iterate_shared | -1 | 56 |

- mutex 使用两份完整无调试定义。`__mutex_init` 的所有初始化和正常RET逐条匹配：计数型10条、owner型7条，然后取相应 sizeof，保留尾部对齐。结果写入布局表，目录与控制准备共用缓存；未知初始化形态失败。
- `user_preparse` 前11条核对 datalen 范围、data 非空和二者连续关系。两条分支须向前跳到同一拒绝块；不读取后续分配流程，也不按固定40填值。
- 上阶段 `simple_getattr` 已核对 generic_fillattr 的两个实参；本轮将其ABI保存到 fillattr_abi，复用同一证据。
- 两目标的 lockref.lock／count 与 d_op 连续。mutex 完整初始化确认4字节spinlock形态后，以已有 d_op 起点复用 nm_dentry_lockref_ops，不新增 dget_parent 扫描。
- 从已确认完整 file_operations 范围中的 simple_dir_operations 找唯一 dcache_readdir，再与 iterate_dir 首12条的对象链、槽读取和检查核对。iterate／shared 的连续声明放进 nm_structs.h；实际匹配决定 shared 是否存在。

BTF 查询新增 unavailable 输出，目录／控制准备仅在数据或接口缺失时降级，随后保留完整公共校验。控制构造入口改调用该准备层；静态模式也先检查控制布局，后续仍按原顺序准备管理锁并注册key type。协议、回调集合及驻留生命周期保持本轮原有实现。

## 尺寸与配置边界

mutex 的完整初始化形态只用于核对这两种已知定义和spinlock宽度，不能推出整个内核的LOCKDEP配置。key_type 的完整尺寸继续缺失。

辅助挑战发现两项具体限制：lock_class_key 的空类型条件为 CONFIG_LOCKDEP；Sony key_type 带 __randomize_layout，link 后可能仍有非空字段。因此 list 节点起点不能单独证明完整key_type边界。本轮保留完整尺寸要求，目录和控制公共校验仍拒绝缺失的表或ABI。

声明与配置沿用目标绑定：Sony源码提交与镜像版本标记一致，B2N头文件为Nokia4.4.196语义参考，实际镜像为4.4.192；本轮变化项均以目标机器码核对。新增固定提交的 mutex、lockref 和配置声明来源及哈希见阶段数据。

## 自检

- 新工具 test_function_directory_control.py 在两份真实镜像的重定位窗口和表上运行生产代码，各35项匹配参考；ASan／UBSan通过。原生内核函数未执行，BTF路由使用API夹具。
- 上阶段75条断言文本全部保留，原48个工具文件逐字节未变。新增逐条未知调用、终止RET、错误字段、回调缺失／重复、前部变化、缓存复用和反向分支等边界断言。
- 首次新增目录反例发现锁起点减法与 sizeof 的有符号／无符号比较可能接受负值。修正为有符号起点和下界检查，原失败断言保留，两目标通过。首次失败日志仍保存于本地探索目录。
- IMM19位移在 kpm_utils.h 统一符号扩展为字节距离，同时补齐上阶段 inode／getattr 的反向分支拒绝。测试覆盖正负边界和不匹配指令；没有在模块内另写解码掩码。
- Sony5.15真实BTF的46项查询和原拒绝断言通过。私有副本只调整源码定位及目录／控制的 unavailable 实参，保留原断言。
- 从干净冻结提交的142个输入经统一入口构建dynamic／static，探索档复算源码blob、参数、配方和产物哈希通过；ELF及92字节默认表通过。只有SDK已有 READ_ONCE／WRITE_ONCE 重定义警告。静态JSON核对后以独占创建附入新归档。

静态件因控制准备层的公共校验也参与编译而产生新字节，不继承上阶段静态件的审计／实机结论。两种产物均为 exploration，未登记为正式候选。

## 冻结身份

完整清单见[构建身份](handoffs/2026-10-14-nomount-function-directory-control-phase5.json)，逐项结果及原工具保持情况见[阶段数据](data/2026-10-14-nomount-function-directory-control-phase5.json)。

| 模式 | instance_id | SHA-256 |
| --- | --- | --- |
| dynamic | `nomount-2.1.1-20261014+gf2ead8156bf6.r0562ea27.kpb51197a.ndk26.3.11579264#1` | `f3d20cac31d7fcbf8fba0202230acfc2c465afa1734223b2a8d841f8d760bfd9` |
| static | `nomount-2.1.1-20261014_baselines+gf2ead8156bf6.r28836b70.kpb51197a.ndk26.3.11579264#1` | `b922daa76f010c4a623a3b32f8f35d6055cc2f3fa209bf34808923b66f7d3c7f` |

## 修正后保留（Retain）

**有效性**：本段7项分别有完整初始化、连续定义或调用入口证据，两目标匹配。key_type边界的初始推断经挑战后收窄，完整尺寸继续独立查证；整个动态初始化仍受缺项限制。

**简洁性**：mutex／lockref／枚举片段用已核对定义覆盖，不逐成员扫描。mutex只解析一次，fillattr复用已核对调用；现有完整文件表识别用于目录回调，无需扩大原生对象读取范围。

**后果**：新增编译形态不匹配时返回错误，有效BTF错误不被覆盖。数据来源、完整表尺寸及未知ABI保持明确边界；本段字段成功不授权发布回调。辅助挑战属于Developer检查，不代替Auditor。

respect-the-oracle 已核对断言保持和宿主证据边界；no-negative-echo 已回读本轮源码、报告和身份清单。没有设备操作、发布或问题关闭。

## 剩余工作

尚缺 inode／super／dentry／key_type 的4类完整尺寸、super的2个回调、dentry的2个回调、key回调起点、permission ABI和actor ABI，共11项；此外还需补齐各原生准备接口的无BTF核验。完整复制尺寸阶段仍早于本轮目录和控制阶段，当前完整动态入口仍会在那里停止。
