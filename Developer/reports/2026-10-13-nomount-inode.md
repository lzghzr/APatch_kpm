# NoMount：普通文件 inode 物化

本轮把已完成的只读文件回调接到普通文件 inode：通过原生 new_inode 分配，持有 backing 规则引用，设置操作表和映射，再交给 d_splice_alias。目录查找、枚举、dentry 重验证、拓扑管理及 keyring 注册继续待接入，目前没有可加载的 KPM。

角色为 Developer，源码检查点 `dcac55ee3717931b7501248bff0a0c1fee183e36`。本轮只有源码、自检证据和 ARM64 对象，尚无 Build ID / instance_id；对象哈希不作为 KPM 候选身份。以下是实现方自检，独立审计和真机结论由 Auditor、Tester 分别给出。

## 输入与共同结构

目标为 `kernel_img/boot_los23.2.img`，版本 `4.19.325-cip134-st18-perf-g7fc8455b2fa8`。

- boot SHA-256：`199658639f7389153ee8a7efe00154f0892e272ddc872728ea326e3e1ce2383b`。
- 有界提取内核 SHA-256：`299f7e2580c54684c3b825bea57f1b16c53055f485ebd2b937593ac57ff9b0d2`。
- 原版 NoMount 提交：`1ded61dc908c511072162fa0bee44e6ccdb7b4c7`。
- 目标源码参考：`LineageOS/android_kernel_sony_sm8250` 的 `7fc8455b2fa84be76364c2457e6503b867ceb12a`。
- 配置 SHA-256：`5a03d694a8a1fb015c1e977ada538e8eb7b259dc119a7a771e577481e1d9d450`。

继续按 SDK／共同结构优先的约定处理。当前 SDK 对 inode、superblock 只有前向声明；比较 Linux 4.4、4.9、4.14、4.19、5.15、6.6 与目标声明，取得以下连续片段：

| 共同片段 | 使用方法 |
| --- | --- |
| i_op / i_sb / i_mapping | 共 24 字节，以已有 i_sb 偏移定位整个片段 |
| i_size / atime / mtime / ctime | ARM64 共 56 字节，以已有 i_size 偏移定位；6.6 的 ctime 名称为 __i_ctime |
| superblock 前部至 s_op | 共 56 字节，直接使用已核对的前部 |

共同片段均通过七组声明的 ARM64 编译断言，条件是未启用结构重排。它们不证明完整结构跨版本一致，也不代表七组内核的回调 ABI 都已支持。动态准备另用 BTF 核对片段及当前调用的 ABI，必要接口不匹配时停止。

目标配置启用了 RWSEM_PRIO_AWARE，且 address_space 的页索引已回移为 xarray。根据匹配声明和目标配置编译出的 rw_semaphore 为 48 字节、address_space 为 264 字节、inode 为 728 字节；没有沿用普通上游 4.19 的整份布局。

| 共同片段无法覆盖的字段 | 目标值 | 证据 |
| --- | ---: | --- |
| inode.i_fop | 368 | 匹配声明；inode_init_always 的前 32 条访存 |
| inode.i_data | 384 | 匹配声明；inode_init_always 的映射地址计算 |
| inode.i_hash | 224 | 匹配声明；__remove_inode_hash 的入口窗口 |
| inode.i_blocks | 144 | 匹配声明；generic_fillattr 的复制对 |
| inode_operations.getattr | 128 | 前轮完整目标操作表声明 |
| super_operations.drop_inode / evict_inode | 40 / 48 | 前轮完整目标操作表声明 |

generic_fillattr 的入口还核对了三个时间片段和 s_dev。静态输入记录 address_space 完整尺寸，检查 i_data 与其他已使用字段的重叠。上述窗口用于离线印证，不新增运行时扫描器。首轮目标无 BTF，仍走对应镜像的静态配置；动态物化层缺必要 BTF 时停止准备。

## 物化与回收

`nm_inode.c` 准备普通文件的 inode 表和 super_operations 代理。inode 表只填写 getattr；原生 getattr_nosec 从 backing 返回完整属性，模块替换虚拟 inode 号和所在 superblock 的设备号。

物化函数只接有 backing 的普通文件。它另取一份规则引用交给 inode，复制 mode、uid、gid、size、时间及 blocks，绑定只读操作表，并将 i_mapping 转接到 backing。原生分配器设置的锁、链表、引用计数和嵌入 i_data 保持原样。d_splice_alias 接收 inode 引用，模块不重复 iput。

super_operations 按完整目标尺寸复制，保留原生 alloc_inode、destroy_inode、free_inode 和全部尾部，只替换 drop/evict。私有头部与表先完成初始化，CAS 成功后驻留；发布竞争失败释放尚未公开的代理，保留新出现的原表。调用者须持有管理锁和 superblock 的路径引用。

普通原生 inode 转发原 drop/evict；没有原回调时遵循原生 fallback。虚拟 inode 强制 drop，evict 清除私有指针、将 i_mapping 恢复为自己的 i_data，清理嵌入映射并调用 clear_inode。规则路径引用在进程上下文释放，RCU 回调只 vfree 私有元数据；后续原生 VFS 继续执行文件系统的 destroy/free。

直接回看目标 inode.c、dcache.c，以及 ext4、f2fs、EROFS、OverlayFS 的分配和销毁路径。原生分配对象与析构回调需要配套，不能用模块私有内存代替完整 inode。源码走查不能替代实际挂载文件系统、RCU 和页缓存的运行验证。

## 方案复核

**保留（Retain）**。

### 有效性

普通文件物化、规则引用、getattr、完整操作表保存和回收调用已有生产代码执行证据。仍需目录层发布与 dentry 生命周期接入，才能完成系统应用的发现流程；这轮不会声明应用已可安装或启动。

### 简洁性

使用原生 new_inode、d_splice_alias、truncate_inode_pages_final、clear_inode 管理 VFS 对象。共同连续片段复用已有偏移；只为剩下的对象字段、完整嵌入映射尺寸及三个实际使用的回调槽增加配置。完整代理表随模块驻留，无需构造新的全局对象索引。

### 后果

模块驻留并不取消 inode 回收，虚拟 inode 仍须处理 backing 引用和自身映射。首轮读取限制继续生效；动态查询会拒绝当前四参数 getattr 或单 inode 参数 drop/evict 的 ABI 不匹配。SELinux、CFI、原生文件系统析构、并发与应用启动仍需独立审计和 Tester 的目标事实。

按 are-you-sure 做上述有界源码复核；按 no-negative-echo 回读最终代码、README 和记录；按 respect-the-oracle 核对既有断言和生产路径。既有 test_native 宿主前置声明新增 `typedef uint8_t u8`，用于容纳 superblock 片段的 8 位成员；没有改动其断言或检查范围，也没有为此更改生产结构。

## 自检与对象

本轮输出位于新的 `local/nomount-inode-20261012/` 子目录；后续日期记录为 2026-10-13，目录沿用本阶段开始日期。旧报告与旧输出均保留。

- test_inode_layout：七组共同片段编译、BTF 字段和回调 ABI 拒绝边界，ASan/UBSan 通过。
- test_inode：实际物化、分配失败、原生表尾部保存、CAS 竞争失败清理、原回调转发和 fallback、getattr、规则撤销后的 inode 引用及回收，ASan/UBSan 通过。合成接口夹具只检查引用消耗与调用契约，不证明原生文件系统析构。
- 既有布局、规则、规则前部、原生封装、文件回调、文件布局六组回归通过，最终源码对应的新输出分别为 layout-regression-02、rules-regression-02、rule-layout-regression-02、native-regression-03、file-regression-02、file-layout-regression-02。
- NDK 26.3.11579264 编译 dynamic / static 对象通过，包含实际物化、getattr、drop/evict 和文件回调。每份对象有两条 SDK 既有 READ_ONCE/WRITE_ONCE 重定义警告；其余使用 Wall/Werror。
- 未解析导入为当前 KP 的 kallsyms_lookup_name、kallsyms_lookup_name_by_suffix、kf_memcpy、kf_strncmp、printk；静态版只用其中三项。没有裸 libc 导入。
- 完整生产源文件哈希与源码检查点 Git blob 逐一匹配。常规仓库门禁 13 项检查：0 失败，1 既有 zram_zstd 交接字段警告。

| 证据 | SHA-256 |
| --- | --- |
| native-reference-02/reference.json | `f89ab7d90f1982818996fe4d4147acfb90ef59bc0bba0e2f201cc526f41e568e` |
| target-entry-proof-01/receipt.json | `81303279dee0a4691f13834df7f4c2c99b0b4eda6c9fcbc060b9f47da9d7eebe` |
| inode-layout-02/receipt.json | `305cc722f5f119664e2576a39d3eae927ca709d7ee5e5c6e14bc7930fa8ed9be` |
| inode-selfcheck-03/receipt.json | `1df802e4cb769c710f40724fce96e9a4d595bf00c5f293163ed86dc2bcc085ea` |
| compile-02/receipt.json | `40a0cb753273e4cdbc7efbac8f56ccf9dc595f456e8a226d16692cda20e336ed` |
| compile-02/dynamic.o | `7cd579bbb44e68f7c3166a1df0194132f0e1498e5bce61cff290555a94960d66` |
| compile-02/static.o | `d738f356ea4e8b07969ee019f511e4f6650fd09571e6f1b2a784520392008371` |

下一阶段接目录 lookup/枚举、dentry 重验证及规则拓扑，随后实现 keyring 控制与 KPM 入口。可加载候选仍须从冻结源码经统一入口构建，实机测试仍由 Tester 进行。
