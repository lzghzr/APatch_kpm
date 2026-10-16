# NoMount：路径建树与裁剪

本轮接入按路径新增、替换、删除和清空规则：缺失的虚拟父目录自动补齐，最后一个子项撤销后裁剪自动建立的空目录。打开中的虚拟目录继续持有节点，子树撤销后读取空视图。目录 backing 合并、实际管理锁、keyring 控制和 KPM 入口继续待接入。

角色为 Developer。源码检查点 `633e1a046da165380b86e327c8ee7a88600f0dd4`。本轮只有源码、自检与 ARM64 探索对象，没有可加载 KPM 或 Build ID / instance_id；冻结后核对对象输入与 Git blob 一致，不作为正式候选构建事务。独立审计和真机结论仍由 Auditor、Tester 分别给出。

## 输入与接口

目标保持为 `kernel_img/boot_los23.2.img`，内核 `4.19.325-cip134-st18-perf-g7fc8455b2fa8`。

- boot SHA-256：`199658639f7389153ee8a7efe00154f0892e272ddc872728ea326e3e1ce2383b`。
- 有界提取内核 SHA-256：`299f7e2580c54684c3b825bea57f1b16c53055f485ebd2b937593ac57ff9b0d2`。
- 上游 NoMount：`1ded61dc908c511072162fa0bee44e6ccdb7b4c7`。
- 匹配目标声明：`LineageOS/android_kernel_sony_sm8250` 的 `7fc8455b2fa84be76364c2457e6503b867ceb12a`。
- 配置 SHA-256：`5a03d694a8a1fb015c1e977ada538e8eb7b259dc119a7a771e577481e1d9d450`。

本轮没有新增结构体偏移。路径、qstr、inode 与目录操作表继续使用已有定义和访问器。新调用的 d_hash_and_lookup / shrink_dcache_parent 已在匹配目标的 dcache.h 编译核对，目标 kallsyms 含函数和 CFI 跳板。BTF 原型核对独立放在 nm_btf.c，缺少数据或 ABI 不匹配时停止准备。

nm_topology.c 维护管理锁内的路径记录和原生 anchor；热路径继续使用既有子项哈希数组。nm_topology_entry.c 保留增删、清空和批次回收的对象编译入口。接口要求控制层在进程上下文持管理锁，解锁后执行 nm_finish_topology_updates；本轮尚未接入实际锁，不宣称管理并发已完成。

## 发布与回收

新增路径只把 ENOENT 当作缺失父目录，其他原生解析错误直接保留。缺失链先在私有新节点中建立，最高边界子项数组和全部记录提前分配；原生父目录安装成功后，只发布已备齐的子树和索引。自动父目录不再次解析并采用原生节点，保持整棵待发布子树的私有边界。输入规则成功转交引用，失败时仍归调用者，已存在的规则和数组保持。

规则和子项数组的构造、发布分开，原有 set/insert/remove 共用同一构造器。替换规则时先备齐数组和必要目录节点，再发布。原生缓存目标在发布前经 d_hash_and_lookup 取得引用，错误指针使操作停止；成功后摘哈希、释放该引用并清理父目录缓存。纯虚拟父目录的缓存沿用模块重验证。

真实父目录 anchor 持有原生 path 和节点引用。再次建立 anchor 时复用 inode 已安装的视图节点，因为 path_put 不保证 inode 退出缓存。原生目录纳入显式规则后，只要目录记录仍拥有该节点，即使子项为空也保留 anchor；其余空 anchor 在管理锁内摘下，宽限期后释放路径。

删除最后规则先确定可裁剪的自动父目录链，预分配最高边界替换数组，再撤销入口并清空所有被摘下节点的 children。目录仍有子项时保留必要的虚拟目录规则。清空全部规则不分配新数组。owner 只供管理锁内使用，摘下时清除；解锁后的回收不再写 owner。

一次原生 RCU 宽限期覆盖本批次退役的规则、叶节点和 anchor。历史读者退出后才释放叶节点，节点引用可继续由存活 inode 持有；path_put 始终在进程上下文执行。规范路径裁掉尾部斜线，拒绝根目录规则、空分量、点分量和超长名称；通过另一条路径解析到模块虚拟 inode 的原生 anchor 暂以 EXDEV 拒绝。

## 方案复核

**修改（Modify）**，修正已完成。

### 有效性

私有链预构造、边界一次发布、摘下节点清空视图后统一等待宽限期，覆盖新增和撤销规则的目标。源码走查和新用例还约束自动父节点始终私有，防止前缀探测后的命名空间变化使其采用已公开的原生视图。

### 简洁性

复用既有规则／子项数组、目录节点、原生路径解析和 RCU。路径索引仅供低频管理操作使用；业务回调不增加路径全表扫描。原生锁布局在实际控制层接入时核对，本轮不构造猜测的 mutex。

### 后果

辅助只读挑战确认，新增最高边界数组必须先于原生视图安装分配；目标 iput_final 可将目录 inode 留在 LRU，因此删除后再添加须复用已安装节点。相应首次接管与缓存复用用例均已加入。anchor 还需保持至其目录记录退役，避免原生视图丢失。挂载变化、文件系统回调、CFI、实际管理锁和 Android 扫描仍需独立审计及真机事实。

按 are-you-sure 完成上述有界挑战；按 no-negative-echo 回读最终源码和文档；按 respect-the-oracle 保持既有 13 个自检脚本逐字节不变。新增两个脚本，完整执行既有虚拟目录／目录／inode 及虚拟目录布局 Oracle。

## 自检与对象

最终证据在新的 `local/nomount-topology-20261013/` 子目录，早期诊断输出保留。

- selfcheck-05：建树、规则替换和升级、多 UID 删除、裁剪、清空、缓存节点复用、anchor 保留、命名空间前缀变化及存活 inode 的空视图，ASan/UBSan 通过。分配失败覆盖首次接管 15 项、缓存父目录复用 18 项，另外检查删除和升级时的分配失败。路径和 inode 缓存是接口夹具，不证明真实命名空间或并发。
- layout-01：完整执行既有虚拟目录布局 Oracle，并核对目标缓存接口声明及生产 BTF 原型拒绝边界，ASan/UBSan 通过。
- rules-regression-01：既有规则数组、UID、失败状态保持和原生路径引用回归通过。
- compile-02：NDK 26.3.11579264 编译 dynamic / static ARM64 对象通过，真实增删／清空及回收入口均进入对象。每份对象有两条 SDK 既有 READ_ONCE/WRITE_ONCE 重定义警告，其余使用 Wall/Werror。
- 全部未解析导入与当前 KP 导出逐项对应；新增 kf_memchr 来自已导出的 SDK 包装，目标也含 memchr 及 CFI 跳板。没有裸 libc 或原子辅助导入。动态 11290 条、静态 6139 条指令的操作数检查未发现 FP/SIMD/SVE 寄存器或 x18。
- 编译与自检输入哈希已与冻结 Git blob 核对。SDK 输入提交为 `b51197aaba8f2272dd8a3e30c85698a29aa928c9`。
- 常规仓库门禁 13 项检查：0 失败，1 项既有 zram_zstd 交接字段警告（handoff_by / handoff_at 缺失）。

| 证据 | SHA-256 |
| --- | --- |
| freeze-binding-01/receipt.json | `edf2eb1cfe24bea1fbc09d452c4f387471f512cc37a886424908ff74e99377f5` |
| selfcheck-05/receipt.json | `35dfa004d0ca514e426346030b2fc4f0f32fa2f670f27ef73da1323291da5f10` |
| layout-01/receipt.json | `b5b5088da7451d2bae718deacbd0c5a71026a70bbc374d6b8e68fd0336e1db7e` |
| rules-regression-01/receipt.json | `49630de925481bdc7b7651f439dbed99e248f47378e071eac40393beceab2134` |
| compile-02/receipt.json | `81b39908820a5b1a07d0ded02a9cec9c0c1f6923803c4f841fd17fd7a43b2b39` |
| compile-02/dynamic.o | `54f98425e5419774f70345b53dd15dfeaf1246c5fd5f52dfb103830c1f76ad36` |
| compile-02/static.o | `2b819a4bfe9d50a8db1d831c148fe662bb700f51f1965c342cb897fb80ecd871` |

下一阶段接目录 backing 合并及控制层，再完成 KPM 初始化、构建规则和正式候选。真机测试仍交由 Tester。
