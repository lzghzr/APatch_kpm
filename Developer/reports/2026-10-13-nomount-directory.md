# NoMount：原生父目录查找与枚举

本轮接入已有目录下的文件查找、目录枚举和 dentry 重验证。普通文件规则与隐藏规则已有生产回调；规则和 UID 变化会使对应缓存失效。新增虚拟目录、目录拓扑管理和 keyring 控制接口继续待接入，目前只有对象文件，没有可加载的 KPM。

角色为 Developer，源码检查点 `88bb0a4518f7192959fe0b0750f4439af67a6976`。尚无 Build ID / instance_id；本报告的对象哈希不作为 KPM 候选身份。以下是实现方自检，独立审计与真机结论仍由 Auditor、Tester 分别给出。

## 输入与布局

首轮目标保持为 `kernel_img/boot_los23.2.img`，内核 `4.19.325-cip134-st18-perf-g7fc8455b2fa8`。

- boot SHA-256：`199658639f7389153ee8a7efe00154f0892e272ddc872728ea326e3e1ce2383b`。
- 按 boot 头界定提取的内核 SHA-256：`299f7e2580c54684c3b825bea57f1b16c53055f485ebd2b937593ac57ff9b0d2`。
- 原版 NoMount 提交：`1ded61dc908c511072162fa0bee44e6ccdb7b4c7`。
- 匹配内核声明：`LineageOS/android_kernel_sony_sm8250` 的 `7fc8455b2fa84be76364c2457e6503b867ceb12a`。
- 配置 SHA-256：`5a03d694a8a1fb015c1e977ada538e8eb7b259dc119a7a771e577481e1d9d450`。

先比较 SDK 和共同声明，再增加剩余偏移。SDK 已提供 current/thread_info 与 task/cred 布局；本轮通过根目录 `kpm_utils.h` 新增的 task_fsuid 取得 fsuid，通过 SDK thread_info 和 TIF_32BIT 判断用户态目录 cookie 的宽度。没有另建 task/cred 偏移表。目标声明中的 flags 前部及 TIF_32BIT 已核对，SDK 导入已与当前 KP 导出对应。

| 可直接使用的共同片段 | 范围与用法 |
| --- | --- |
| inode_operations.lookup | 首成员，8 字节；动态模式另核对三参数回调 ABI |
| dentry 的 d_op / d_sb / d_time / d_fsdata | 连续 32 字节，以已有 d_op 偏移定位 |
| dentry_operations 前部 | revalidate、weak_revalidate、hash、compare、delete，共 40 字节 |

上述片段已对 4.4、4.9、4.14、4.19、5.15、6.6 和目标厂商声明做 ARM64 编译断言。这只证明片段在已核对声明及配置下成立，不代表这些版本均已完成运行适配。4.4 的 dentry_operations 没有 d_init，d_release 位于 40；目标 d_init / d_release 位于 40 / 48。因此 init/release 不放入共同前部，init 允许缺失，release 位置单独核对。

| 共同片段无法覆盖的新字段 | 目标值 | 取得依据 |
| --- | ---: | --- |
| dentry.d_lockref.lock | 88 | 匹配声明；d_drop、dget_parent 的入口地址计算 |
| file_operations.iterate | 48 | 完整目标声明 |
| file_operations.iterate_shared | 56 | 完整目标声明 |
| dentry_operations.d_init | 40 | 完整目标声明；允许缺失 |
| dentry_operations.d_release | 48 | 完整目标声明 |

共同访问器和偏移检查放在 nm_offsets.c，BTF 查询放在 nm_btf.c。首轮目标无 BTF，使用对应镜像的静态配置。完整表尺寸及新增槽位的动态获取目前依赖 BTF；缺必要证据时停止该层准备。入口窗口仅作离线印证，没有新增运行时扫描器。

## 目录回调与生命周期

管理层在持锁且保有原生 inode 引用时安装空目录视图，先发布完整 i_op/i_fop 代理，再发布 children。代理保留完整原生操作表和尾部，替换 lookup、llseek 和目标实际存在的 iterate 槽。原生目录 evict 时先恢复操作表，再调用原生 evict；私有节点和代理在 RCU 宽限期后释放。

lookup 按 fsuid 选择规则。普通文件交给已完成的 inode 物化，隐藏规则生成负项；普通原生查找保留原返回值语义。包装失败会摘除目标哈希，并释放原生 alias 返回引用后传播错误。注入对象目前只接新建、无原生私有数据、无需原生 d_init/d_release 的 dentry；其他形态返回 EOPNOTSUPP，保留原表。

重验证在 ref-walk 中通过原生 dget_parent/dput 稳定父目录引用，LOOKUP_RCU 返回 ECHILD。规则撤销、替换或 UID 排除使原注入项失效；普通原生项分别转发原 revalidate 和 weak_revalidate。

枚举先输出未被当前规则替换或隐藏的原生项，再追加虚拟项。原生 iterate 直接使用外层 VFS 已取得的 inode 锁。虚拟项在 RCU 内复制名称与元数据，解锁后调用 actor；缓冲区满时保留当前位置，下一次可继续。沿用原版 32/64 位 cookie，32 位索引超出表示范围返回 EOVERFLOW。叶节点的虚拟 inode 号由已有 full_name_hash 和完整虚拟路径计算。

## 方案复核

**简化（Simplify）**，已完成相应实现。

### 有效性

已有父目录视图所需的 lookup、枚举、fsuid 选择、缓存失效和原生回调转发已通过生产代码自检。原生 dentry 操作表以完整字节和 NULL 形态作为共享条件，同地址换内容仍得到新快照；相同内容复用已发布快照。

### 简洁性

使用驻留的不可变完整表快照，只替换两项重验证回调。原生 d_release、其他回调和每个 dentry 的 d_fsdata 原样保留。发布采用 CAS，未发布的竞争失败分配可以释放，已发布表驻留到重启；不需要每个 dentry 的额外回收对象。快照保存原表字节，不保存历史原表地址。

### 后果

已发布快照会随模块驻留，其数量取决于遇到的不同原生表内容。对目标 fs/super.c、fs/filesystems.c 和 OverlayFS release 的有界走查确认：原生 superblock 生命周期保有文件系统模块引用，release 使用原 d_fsdata；共享元数据本身不调用历史回调。此复核及辅助只读挑战均属于 Developer 范围，不替代 Auditor 对原生文件系统、RCU 并发及 CFI 的检查，也不证明 Android 应用扫描已成功。

按 are-you-sure 完成上述方案挑战和简化；按 no-negative-echo 回读最终源码、README 和报告；按 respect-the-oracle 核对生产路径及已有基准。本轮没有修改既有八组自检脚本的断言或范围。新增目录自检复用并完整执行已有 inode Oracle，再追加目录用例。

## 自检与对象

最终证据存于新的 `local/nomount-directory-20261013/` 子目录，早期诊断输出保留。

- test_directory_layout：七组共同片段编译断言、真实生产 BTF 处理、可选 d_init/iterate 槽、尺寸与重叠边界；不匹配的 actor 和 revalidate ABI 均被拒绝。ASan/UBSan 通过。
- test_directory：原生及注入 lookup、规则/UID 缓存变化、父目录引用平衡、快照按内容复用、原生 release 保存、alias 分配失败清理、枚举过滤与续读、32 位索引边界和 inode evict 恢复。ASan/UBSan 通过。夹具不能证明真实文件系统锁、并发或系统应用发现。
- 既有布局、规则、规则前部、原生封装、文件回调、文件布局、inode、inode 布局八组回归通过。inode Oracle 的输出位于 directory-selfcheck-06/inode-contract；其余对应本阶段各 regression-01 目录。
- NDK 26.3.11579264 编译 ARM64 dynamic/static 对象通过；实际目录回调和快照缓存均进入对象。每份对象有两条 SDK 既有 READ_ONCE/WRITE_ONCE 重定义警告，其余使用 Wall/Werror。
- 导入为当前 KP 的符号查询、kf_memcpy/kf_memcmp/kf_strncmp、printk，以及已导出的 current/task/cred 布局变量。静态对象不导入 kallsyms_lookup_name 和 kf_strncmp；两份对象均无裸 libc 导入。实际目标 KP 初始化及 CFI 仍待真机验证。
- 编译回执记录完整生产输入哈希，逐项与源码检查点 Git blob 匹配；KernelPatch SDK 输入提交为 `b51197aaba8f2272dd8a3e30c85698a29aa928c9`。
- 常规仓库门禁 13 项检查：0 失败，1 项既有 zram_zstd 交接字段警告（handoff_by / handoff_at 缺失）。

| 证据 | SHA-256 |
| --- | --- |
| native-reference-02/reference.json | `3854aec142bab37e323cfdb96a7b42231f9d1b828a2b02c98a86e32ae65d756a` |
| target-entry-proof-01/receipt.json | `d36d9dab31c054cd474ed698c28493d410d3ee64fa5c391fb4070ce0676fc25a` |
| directory-layout-04/receipt.json | `cb247520ec34a2960050bec009a031a36d7ef94e3a05245022222fc7be9cd8f3` |
| directory-selfcheck-06/receipt.json | `096623d53bd25daaf221e15fbc47df74b11e5c7a6861e0b4cbccaa9e93d01100` |
| compile-03/receipt.json | `e226f54558710c412ddb3d23238c3ff4034d149a91da30d32f92e1d08be95129` |
| compile-03/dynamic.o | `501c784ddebe28f1c65eb6a4744c2715b1cba1c3824520706303f1070b0d6f88` |
| compile-03/static.o | `9780fe98b88b63dbf98a9afe16de47f7fdb8538be8d6c62a983e31809f5f1557` |

下一阶段接新增虚拟目录的 inode 物化和目录拓扑，再接 keyring 控制及 KPM 入口、构建规则。可加载候选须从冻结输入经统一入口构建，真机测试仍交由 Tester。
