# NoMount：新增虚拟目录

本轮把纯虚拟目录接入已有 lookup 层，完成目录 inode 复用、子项查找、属性、点项和子项枚举、seek 及回收。规则与目录节点变化会使对应缓存失效。路径自动建树、目录 backing 合并、keyring 控制和 KPM 入口继续待接入。

角色为 Developer。源码检查点 `0d1c533d3db5422e5773bdecbc566c10517eeca2`；本轮只有源码、自检和 ARM64 探索对象，没有 Build ID / instance_id，也没有可加载 KPM。对象输入在源码冻结后逐项与 Git blob 核对一致，这不作为正式候选构建事务。以下是实现方自检，独立审计与真机结论仍由 Auditor、Tester 分别给出。

## 输入与结构

目标保持为 `kernel_img/boot_los23.2.img`，内核 `4.19.325-cip134-st18-perf-g7fc8455b2fa8`。

- boot SHA-256：`199658639f7389153ee8a7efe00154f0892e272ddc872728ea326e3e1ce2383b`。
- 有界提取内核 SHA-256：`299f7e2580c54684c3b825bea57f1b16c53055f485ebd2b937593ac57ff9b0d2`。
- 原版 NoMount 提交：`1ded61dc908c511072162fa0bee44e6ccdb7b4c7`。
- 匹配目标声明：`LineageOS/android_kernel_sony_sm8250` 的 `7fc8455b2fa84be76364c2457e6503b867ceb12a`。
- 配置 SHA-256：`5a03d694a8a1fb015c1e977ada538e8eb7b259dc119a7a771e577481e1d9d450`。

本轮没有新增偏移字段。file 的 f_path / f_inode / f_op 为连续 32 字节，以已有 f_inode 偏移向前 16 字节取得路径。4.4、4.9、4.14、4.19、5.15、6.6 及目标厂商声明均已通过该片段的 ARM64 编译断言；它不证明完整 file 结构或七个版本的运行支持。访问器仍放 nm_offsets.c，共同定义放 nm_structs.h。

目标 fs.h 中的 iget5_locked、unlock_new_inode、generic_fillattr、set_nlink 和 generic_file_llseek 声明已编译核对，目标 kallsyms 也含这些函数及对应 CFI 跳板。动态模式在 nm_btf.c 核对 f_path 位置、五个函数的 ABI，以及 iget test/set 的嵌套回调 ABI；类型缺失或不匹配时停止准备。已有操作表 BTF 检查复用同一个原型核对函数，既有判据保持。

## inode 与目录行为

lookup 在原生 RCU 内选中规则，同时取得 this_dir 节点引用，然后退出读侧再物化目录。纯虚拟目录只接 IS_DIR | VIRTUAL_DIR 规则和有效节点。其操作表通过已核对的目标完整尺寸分配，lookup 与已有父目录共用实现；没有选中子项规则时产生负项。

目录沿用原版的原生 iget5_locked，以规则和节点身份匹配缓存。先分配 info，再调用 iget；set 只设置模块私有信息和操作表。返回 inode 的 i_private 等于本次 info 时，完成新对象初始化、取得独立规则和节点引用，并调用 unlock_new_inode；缓存命中只释放本次未发布 info。未读取额外 i_state 字段。NULL、错误指针、splice 错误和返回别名分别按原生引用契约处理。

目录权限为 root:root 0755，nlink 由原生 set_nlink 设置为 2，时间继承创建时的父目录，size / blocks 为 4096 / 8。保留原生嵌入映射，用 generic_fillattr 返回属性。文件表保留只读 open/release；字节读取返回 EISDIR，枚举先输出 . 和 ..，再按 fsuid 输出子项。缓冲区满时保留对应位置，父目录点项通过 dget_parent/dput 保有引用，actor 调用时不持 RCU。普通 seek 交给原生 generic_file_llseek，虚拟 cookie 延续前轮编码。

虚拟目录与普通虚拟文件共用 super_operations 回收入口。drop 强制回收；evict 清除 i_private，恢复自身映射，执行原生 truncate/clear，释放规则和节点引用，RCU 回调只释放私有 info。原生 VFS 继续完成文件系统对象的 destroy/free。

leaf.this_dir 的所有权由后续拓扑层管理：发布前持有节点引用，摘除或替换后保留至原生 RCU 宽限期结束，再释放。本轮接口自检直接建立这类视图，尚未提供按路径自动建树的控制入口。

## 方案复核

**修改（Modify）**，修正已完成。

### 有效性

目标 iget5_locked / inode_insert5 只对最终插入的新 inode 调用 set，旧对象返回前等待初始化完成。因此比较本次 info 可正确区分新建和命中。目录与普通文件的缓存重验证已接在相同规则视图上，新增节点身份比较避免继续使用已替换的目录节点。

### 简洁性

复用原生 inode 缓存和现有引用回收，不新增模块 inode 索引，也不增加 I_NEW 偏移。已有完整操作表、共同字段与 cookie 处理继续使用；file 路径仅增加共同片段访问器。

### 后果

辅助只读挑战指出，目标 find_inode 先调用 test，再检查 I_FREEING；evict 又先清私有信息，后移除 inode 哈希。inode_hash_lock 不能保护模块 info，缓存 test 因此补上原生 RCU 读锁，并用 acquire 读取 i_private；回调不分配或等待。该走查和接口夹具属于 Developer 范围，原生 inode 哈希竞争、文件系统私有析构、CFI 与 Android 扫描仍需独立审计和真机事实。

已按 are-you-sure 完成上述有界挑战及修正，按 no-negative-echo 回读最终源码和文档，按 respect-the-oracle 核对调用路径与断言。本轮新增两个自检脚本，既有十个自检脚本逐字节保持原样；目录与 inode Oracle 被完整执行。

## 自检与对象

证据位于新的 `local/nomount-virtual-directory-20261013/` 子目录，早期诊断输出保留。

- selfcheck-03：生产虚拟目录代码的准备失败、新建与缓存命中、创建和 splice 失败、别名返回、子项普通文件查找、目录节点替换、点项续读、UID 筛选、两种 cookie 和引用回收，ASan/UBSan 通过。原生 inode 缓存使用接口夹具，不能证明真实内核并发。
- layout-01：七组共同片段编译、目标五个原生函数声明、生产 BTF 的字段与外层／嵌套 ABI 拒绝边界，ASan/UBSan 通过。
- 既有布局、规则、规则前部、原生封装、文件回调、文件布局、inode 布局、目录布局回归通过。目录和 inode Oracle 的输出在 selfcheck-03/directory-contract 中；其余分别为本阶段各 regression 目录。目录布局最终输出为 directory-layout-regression-02。
- NDK 26.3.11579264 编译 dynamic / static ARM64 对象通过，实际虚拟目录物化、缓存 test/set、getattr 和枚举回调均进入对象。每份对象有两条 SDK 既有 READ_ONCE/WRITE_ONCE 重定义警告，其余使用 Wall/Werror。
- 两份对象的未解析导入与前轮一致，均为当前 KP 导出；没有裸 libc 或原子辅助导入。反汇编检查实际覆盖动态 8940 条、静态 3934 条指令，未发现 FP/SIMD/SVE 寄存器或 x18 操作数。
- compile-01、selfcheck-03 和 layout-01 的生产输入哈希均与冻结源码 Git blob 匹配。SDK 输入提交为 `b51197aaba8f2272dd8a3e30c85698a29aa928c9`。
- 常规仓库门禁 13 项检查：0 失败，1 项既有 zram_zstd 交接字段警告（handoff_by / handoff_at 缺失）。

| 证据 | SHA-256 |
| --- | --- |
| freeze-binding-01/receipt.json | `ea6b3aff16ecb4fcdf27358523a87cb2e2d65e4ecfcf99db9537f0ef3beceb97` |
| selfcheck-03/receipt.json | `2097338822e4080e351cf79d3beac7a8a098b0c308ed63d9b3734277b7e51f9e` |
| layout-01/receipt.json | `ec17d2cb40fd993902a77cee9f57d2955cf2f0dbad7efa84c100bd998b337964` |
| compile-01/receipt.json | `312fcec83c3452d6ddfd89973b19df0827895e7daa097cff5bc36ce787491d74` |
| object-check-01/receipt.json | `d97f49acd5b8ce6cb6204d42090ce92b2b0a450813cf26c906205531aacad0ba` |
| compile-01/dynamic.o | `fbef03b321612f6232f6d7315a281a64951a665a76e4125fe98289aaae2cf941` |
| compile-01/static.o | `5f854f60255f9d5dac2da476cbfe5294c18deb770782486aa3ebf9e37e378174` |

下一阶段实现按路径建立和裁剪目录树，再接目录 backing、keyring 控制、KPM 入口与构建规则。可加载候选从冻结输入经统一入口构建；真机测试交由 Tester。
