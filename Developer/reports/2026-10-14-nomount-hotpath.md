# NoMount 0.4.2：同步主线查找优化

Developer实现与自检记录，不替代独立审计、实机验证及维护者验收。

## 范围与依据

本轮同步上游主线两项查找优化。2026-10-14查询master仍为7046c7ad3ee0bf4ae66e80f6b93b1e30db0cb4e3（v2.1.1）；子模块已在此前0.4.1冻结到该点。

- [043ea66](https://github.com/maxsteeel/nomount/commit/043ea665953e133c0306ffd7f4095a73b1b0254c)：子项不超过2个时跳过Bloom表和完整名称哈希，使用快速筛选及精确名称比较。
- [27d4f0e](https://github.com/maxsteeel/nomount/commit/27d4f0e16e581f2c9ad16321ee3a9891c503ebf2)、[6319390](https://github.com/maxsteeel/nomount/commit/63193900c1b8c5a0a3efebd953cd4f1a1a18fd84)：UID 256位预筛选，直接按UID取位，命中后精确比较。

同用主线简化的nm_qhash和名称首末字节比较，二分查找的entries只取得一次。UID为空时在隔离UID判断后直接返回；非空数组必须在原生RCU内重新取得再读取。

本轮变化为模块私有数组及查找函数；规则引用、原生path、RCU宽限期和发布顺序继续使用当前KPM机制，未改变上游LKM另套规则内联存储／inode解耦／整批ADD方案。静态偏移表仍为46项、92字节，七份目标配置无需迁移。6.1无实机，5.15设备暂不可用；现有4.4／4.19结论继续绑定其原实例。

## 自检

新增test_hotpath_rules.py从0.4.0冻结的两种目录Oracle生成物读取完整用例，替换本次受影响的生产函数及私有结构，原每种645条assert表达式和顺序保持。版本宏从当前协议头取得；宿主ASan／UBSan执行实际规则、目录和加载入口。

新增用例覆盖：0/1/2子项无Bloom；2增为3、3减为2及旧快照；名称快速哈希碰撞仍精确区分；小目录完整名称哈希调用为0；UID同位碰撞不误屏蔽、删除一个碰撞UID保留另一个、删除后的mask重建；分配失败保留旧数组；UID零值、63/64、255/256、最大32位值、隔离和多用户边界；清空与退役队列。这里的调用次数是宿主夹具证据，尚无实机延迟、吞吐或CPU性能结论。

## 复核决定（Decision）

**保留（Retain）**

### 有效性

生产路径执行上游查找策略，碰撞均回到精确匹配，2/3边界和UID删除后重建有反例覆盖。

### 简洁性

只修改私有结构与已有查找／快照构造函数，无新增内核偏移和原生依赖。相比原实现少执行小目录完整哈希，并可跳过部分UID未命中扫描。

### 后果

UID数组增加256位mask，小目录去掉原32字节Bloom区域。mask错误可造成假阴性，故必须先构造完整快照再发布；零words路径禁止索引Bloom。新字节需独立审计及可用设备验证。

### 建议

冻结0.4.2，交接四基础件、目标派生件和配套ZIP。测试者在可用4.4／4.19设备回归；6.1记为未执行。

## 候选身份

用户已确认本轮只同步两项查找优化。源码冻结提交：`39c7e474b86464dd6defd3bbe5677c4ce493d278`；固定KP SDK为`b51197aaba8f2272dd8a3e30c85698a29aa928c9`，上游为`7046c7ad3ee0bf4ae66e80f6b93b1e30db0cb4e3`。127项输入，指纹`2b2dfdf74950204cc2a3f328344def2de58723137a9dbe7ab5b9fc0c899a8cba`。

| 变体 | instance_id | SHA-256 |
| --- | --- | --- |
| base | `nomount-0.4.2+g2b2dfdf74950.rd7ec55e4.kpb51197a.ndk26.3.11579264#1` | `74e0092007df12f1a9d28d353a1d6e00d21533429a8495f26ac6e5e6b9771958` |
| baselines | `nomount-0.4.2_baselines+g2b2dfdf74950.rf4359fda.kpb51197a.ndk26.3.11579264#1` | `bd6e7d15fd9aa76b620732909b76defdbd7b88cd5d25f805cbad915cdd1076aa` |
| baselines_debug | `nomount-0.4.2_baselines_debug+g2b2dfdf74950.r21d7581e.kpb51197a.ndk26.3.11579264#1` | `9423d50f2190f3712b4facc530703bedadddc5616ac5c2224baeb03681a2f23c` |
| debug | `nomount-0.4.2_debug+g2b2dfdf74950.r327c9008.kpb51197a.ndk26.3.11579264#1` | `5d95975111d501cea784015432687d691c4bed3efe5aa418ecdddd7e78b941d9` |

目标派生16条记录、12份不同KPM字节，包含七目标配置的普通／debug和B2N可选旧KP导入转换件。每条绑定base实例、base SHA、source_commit、目标配置／镜像、工具哈希、真实命令及派生SHA。配置段仍为92字节，JSON和blob路径一致且可还原base；旧KP变换另核对指定导入范围。候选档4/4通过，基础及派生ELF、导入、指令及布局检查通过，无未解析SDK导入和FP/SIMD/SVE/x18操作数。

ZIP实例：`nomount-zip-0.4.2+g68443b1fb5d4.ndk26.3.11579264#1`，SHA-256：`9798982ea8d114c6faed4e322882cc2ba2735ac7ec0522c1c65c3024a337138a`，79475字节、32项。与0.4.1包仅module.prop和README.md不同，其余30项（含CLI、WebUI、来源文件、安装／启动／卸载脚本）逐字节相同。

最终源码在contracts-final-01重新执行自检，两种目录ABI各保留645条原断言并通过追加反例。内核布局／偏移、原生接口、控制及拓扑寿命代码均保持原字节，未重复不受影响的BTF查询和ZIP控制流测试。此前test_*.py脚本全部保持。独立有界代码挑战结论Retain，最终回执已包含空UID列表快速返回；该挑战不构成独立产物审计或性能结论。

常规门禁0FAIL、1项既有zram_zstd字段WARN；版本声明为在途，由维护者登记0.4.2并导入本轮候选。

- [基础候选](handoffs/2026-10-14-nomount-0.4.2.json)
- [目标派生](handoffs/2026-10-14-nomount-0.4.2-target.json)
- [ZIP清单](data/2026-10-14-nomount-0.4.2-zip.json)
- [自检回执](data/2026-10-14-nomount-0.4.2-selfcheck.json)
- [版本登记提案](../proposals/2026-10-14-nomount-0.4.2/README.md)

## 现有规则与批量加载方案

用户确认的范围之外仍使用已有实现，相关功能已接入，区别在内部组织：

| 部分 | 当前KPM | 上游2.1.1 |
| --- | --- | --- |
| 规则存储 | 独立引用计数规则＋不可变指针数组，多个inode可共享 | 数组内联规则及字符串，减少独立分配 |
| inode引用 | inode持rule/node引用，rule持源path，最后引用释放后回收 | inode持独立源path，与管理rule解耦 |
| 批量ADD | 锁外解析源path，逐条短时持锁发布，批次末统一退役 | 管理锁一次覆盖整批ADD，降低锁切换 |

这三项上游重构会替换现有机制。KPM锁外解析用于避免进入模块VFS回调时锁重入。后续如需同步，应分别核对引用、解析依赖、回收上下文和实测收益。

are-you-sure复核为Retain；no-negative-echo已复核最终命名、README和交接范围；respect-the-oracle确认断言及旧工具保持，测试结果限定Developer宿主层级。
