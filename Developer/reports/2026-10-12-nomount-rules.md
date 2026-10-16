# NoMount：规则核心移植

本轮完成规则数组、子项索引和 UID 筛选的移植，接入原生路径引用及 RCU 回收。目录查找、inode 物化、文件回调和 keyring 注册仍待接入；目前没有可加载的 KPM。

角色：Developer。源码检查点为 `35b715494e70a5f1181dbba2dfcf232d0cfc3f6a`。本轮只有宿主自检与 ARM64 对象编译，尚无 KPM Build ID / instance_id；下列对象哈希不作为 KPM 产物身份，也不构成独立审计或实机结论。

## 输入

- 目标：`kernel_img/boot_los23.2.img`，版本 `4.19.325-cip134-st18-perf-g7fc8455b2fa8`。
- boot SHA-256：`199658639f7389153ee8a7efe00154f0892e272ddc872728ea326e3e1ce2383b`。
- 有界提取内核 SHA-256：`299f7e2580c54684c3b825bea57f1b16c53055f485ebd2b937593ac57ff9b0d2`。
- 上游 NoMount：子模块 `nomount/nomount`，完整提交 `1ded61dc908c511072162fa0bee44e6ccdb7b4c7`。移植后的规则代码保留来源，采用上游 kernel 部分的 GPL-2。
- 目标头文件：`LineageOS/android_kernel_sony_sm8250` 的 `7fc8455b2fa84be76364c2457e6503b867ceb12a`；与目标版本字符串一致。

旧开发报告、归档产物和 Oracle 保持原记录。本轮证据另存 `local/nomount-vfs-20261012/`。

## 实现

`nm_rules.h` / `nm_rules.c` 从原版移植模块私有数据与规则处理：

- 指定 UID 优先，未匹配时回退 UID 0；按 UID 排序替换/删除规则。
- 子项保留原版 Bloom 筛选、全名哈希及二分查找。全名哈希使用目标原生 `full_name_hash`；相同哈希仍比较完整名字。
- UID 例外列表、按 Android app ID 范围筛选 isolated UID，以及 4068 字节缓冲区内的 UID 分页。
- backing 路径由原生 `kern_path` 持有引用；普通文件/目录类型由实际 inode 取得。输入路径验证绝对路径、长度和内嵌 NUL；原版用户工具已将输入解析为绝对路径。
- 数组不可变，使用 acquire/release 发布。修改者需要持有管理锁；规则选择与索引读者需要持有原生 RCU 读锁，带出读侧范围的规则先增加引用。
- 规则替换/删除保留原版的批量退役方式。修改阶段只积累旧规则，管理层解锁后统一等待原生 `synchronize_rcu`，再释放路径引用。数组的 `call_rcu` 回调只释放私有 `vzalloc` 内存。
- 新规则首次发布后永久标记 `published`。同一对象再次进入同叶或其他叶节点均返回 `EINVAL`，保持原状态及调用者引用，防止退役链重复入链。
- 数组分配失败保持旧数组；规则交给叶节点前的失败仍由调用者持有引用。

叶节点引用、父目录关系、含子目录规则的虚拟目录保留，由后续拓扑层处理。当前数组操作不发布 VFS 回调，也没有对外开放的管理入口；不能据此认为文件注入已经可用。

原生结构片段放在 `nm_structs.h`，访问器在 `nm_offsets.c`，BTF 核对在 `nm_btf.c`；指令和 BTF 工具继续使用根目录 `kpm_utils.h`。新增 `nm_rules_entry.c` 为独立对象编译入口，与其他临时入口分别编译。

## 结构证据

已取目标对应提交的 `path.h`、`dcache.h`、`fs.h`、`seqlock.h` 和 `list_bl.h` 声明片段，按目标配置编译核对生产结构片段。`DEBUG_LOCK_ALLOC` 与 RANDSTRUCT 未开启。

| 字段/片段 | 编译结果 |
| --- | ---: |
| path 完整尺寸 | 16 |
| path.mnt / path.dentry | 0 / 8 |
| dentry.d_inode | 48 |
| inode owner 前部尺寸 | 16 |
| inode.i_mode / i_uid / i_gid | 0 / 4 / 8 |

这是匹配目标的声明片段核对，未把 dentry 或 inode 前部当成完整类型尺寸。参考源码、头文件和配置哈希记录在 `prefix-reference-01/reference.json`。

动态规则层调用 BTF 核对 path 尺寸、两个 path 字段及 dentry inode 指针位置/宽度；必要类型缺失或布局不一致时停止准备。首轮目标没有 BTF，因此仍使用有对应证据的静态模式；尚未发布静态 KPM 配置文件。

## 自检

所有输出目录为新建目录。新增测试执行实际生产规则代码；原生调用、引用与 RCU 接口使用宿主契约夹具。它们验证调用顺序和边界，不证明内核并发、CFI 或文件系统行为。

- `test_rules.py`：UID 优先级、规则转交与读者保留引用、批量宽限期、替换/删除、拒绝重复发布、分配失败保持状态、路径错误/负 dentry 清理、全名哈希碰撞、不同哈希的排序/删除和 UID 分页。ASan/UBSan 通过，分配与释放计数平衡。
- `test_rule_layout.py`：真实生产 BTF 核对函数，覆盖正确片段、字段错位、完整 path 尺寸错误、指针宽度错误、缺类型、查询错误及无 BTF。ASan/UBSan 通过；合成 BTF 不作为原生目标布局证据。
- 原有 `test_layout.py`、`test_native.py` 针对新增结构与 BTF 源码运行回归，通过；已有断言和夹具未改动。
- NDK `26.3.11579264` 对 `nm_rules_entry.c` 的动态与静态模式编译通过。每份对象仅有两条 SDK 既有的 READ_ONCE/WRITE_ONCE 重定义警告，其余使用 `-Wall -Werror`。这是编译检查入口，未生成 KPM；未被入口引用的静态业务函数可以被优化移除。
- 新增/修改 C 文件通过仓库 clang-format 检查，`git diff --check` 通过。回读证据中的源码和工具哈希均与当前文件一致。
- 常规门禁：13 项检查，0 失败、1 警告。警告来自已有 zram_zstd 交接清单缺少 `handoff_by` / `handoff_at`；本轮未改该历史清单。

| 证据（相对本轮 local 目录） | SHA-256 |
| --- | --- |
| `rules-selfcheck-06/receipt.json` | `a92c94969080a5f8e80642c3a41dc5be5a43213469f0d9f48ee58ba03ab365f7` |
| `prefix-selfcheck-01/receipt.json` | `da14a46863a20bed2a4cff5c21adc5b0ed765d9469dba6dcdf907e9fd20d0eeb` |
| `layout-selfcheck-01/receipt.json` | `e21c9c8b03e73f5c14bfe9e6f5fa20820b2485743eda9f1abd45e42df6d4352c` |
| `native-selfcheck-01/receipt.json` | `c72a9861797ee55a90ddf00adb6e6d8e7610a523775f2b74671895728cc54217` |
| `prefix-reference-01/reference.json` | `54ccce477fd61d3084459509b2e96c842003f07316d1ac497f28a0011accafd1` |
| `compile-03/receipt.json` | `a038fb9fb77cced415e9507e073eb36a6520341838e0cf6da3044b477a107f4c` |
| `compile-03/dynamic.o` | `12ccfc96ff6fdd13aa281d125a8bec43a1858e6d76b5e27ce8ca0d9bfa015719` |
| `compile-03/static.o` | `120db96f724c95ab41a0fa92f5597d10dfd47e6ba38904a9d2d6cfcf0e7e7efe` |

## 方案复核：保留（Retain）

有效性：规则的 UID 优先级、索引与引用路径已有宿主执行证据。额外只读挑战复现了同一规则重复退役的自环边界；发布约束及反例覆盖已补齐，随后回看确认原反例被拒绝。这是 Developer 内部复核。

简洁性：继续使用原版不可变数组、规则引用和批量退役，未扩展为共享规则对象容器。原生 vfree 在本目标的中断上下文有延后释放机制；当前私有数组不需要另建工作队列，路径析构留在进程上下文。

后果：接入 VFS 时必须落实管理锁、叶节点摘除后的宽限期和规则引用转交。原版目录/superblock 接管分配失败会静默返回，后续接管函数需要传播错误；已经发布的表及引用需要继续存活。驻留到重启的约定不能替代这些对象生命周期要求。

README 按当前可用状态更新；报告、源码注释和检查点说明回读通过 `no-negative-echo` 检查。按 `respect-the-oracle` 检查，旧 Oracle 没有变化，也没有为宿主夹具改写原生锁或路径契约。

下一步接入目录 lookup/枚举、inode 物化与文件 open/read/mmap，再接 keyring 管理入口；完成可加载候选后交 Auditor 与 Tester 按流程处理。
