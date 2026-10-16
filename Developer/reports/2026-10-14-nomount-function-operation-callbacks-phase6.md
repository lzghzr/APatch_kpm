# NoMount：原生操作回调与 ABI

两份目标新增6项核对，现在各完成41/46项。剩下 inode／super／dentry／key_type 的完整尺寸和 key 回调起点；完整无 BTF 初始化尚未完成。

源码冻结提交：`2c937a3ff8ff540dd3779bbaaa8f6e60a331fb6e`。上一阶段见[目录与控制布局](2026-10-14-nomount-function-directory-control-phase5.md)。本轮是 Developer 探索构建及宿主自检，没有独立审计或实机结论。

## 新增取值

| 字段 | B2N 4.4 | Sony 4.19 |
| --- | ---: | ---: |
| sop_drop_inode | 32 | 40 |
| sop_evict_inode | 40 | 48 |
| dop_init | -1 | 40 |
| dop_release | 40 | 48 |
| dir_actor_abi | 0 | 0 |
| permission_abi | 0 | 0 |

**super回调**：generic_drop_inode为内联逻辑，generic_delete_inode只返回常量，evict的回调位于较长流程。这里使用 generic_shutdown_super 前35／25条，先确认sb和s_op来源，再取得put_super槽。保存的sb／s_op在x19／x20，跨原生BL依AAPCS64保持；其余指令只接受明确白名单。security释放分支恰好跳过一次释放与对应清零，不越过槽读取。drop／evict／put的连续声明放入nm_structs.h，前两项由同一起点取得；完整super表尺寸仍需独立证据。

**dentry回调**：__dentry_kill前23／17条核对DCACHE_OP_PRUNE标志、实际prune槽、参数和调用。release／prune使用共同连续片段；实际槽与共同控制前部的间隔决定init是否存在。取得字段的读取在前15条，窗口继续到原生调用，以核对参数及分支跳过范围。

**actor ABI**：empty_dir_readdir只有点项枚举，比dcache_readdir更短。前30／20条核对context、name、len、pos、ino、type六个实参与首个返回检查。当前两目标都是int返回，零表示继续；未知返回形态失败。

**权限 ABI**：inode_permission首7条确认NULL mount、inode和32位mask传给准确的inode_permission2入口；后者首8／4条确认inode及mask参数用途。结果为Android mount ABI。BTF查询增加unavailable输出，只有数据／接口不可用才降级，业务准备保留既有ABI与上下文校验。

BTF、函数推导与共同定义仍分别位于nm_btf.c、nm_offsets.c、nm_structs.h。新增CSEL、TBZ／TBNZ位编号和有符号位移统一放kpm_utils.h。函数调用与操作表回调复用有界单B跳板识别，保持原表扫描范围与唯一性要求。

## 自检与修正

- 新工具test_function_operation_callbacks.py在两份真实镜像的重定位窗口和表上执行生产代码，各41项与绑定布局一致；ASan／UBSan通过。原生内核函数未执行，BTF路由为API夹具。
- 上阶段111条断言文本保留，原49个工具文件逐字节未变。旧阶段用原有符号集合保持“actor不可取得”的拒绝检查；新用例显式启用新符号，验证回调取得后仍因完整表缺失而拒绝。两类场景及其错误码分别保留。
- 新增逐条未知指令、位宽／位编号、字段错位、寄存器覆盖、调用目标、返回约定和分支落点反例。super前缀明确拒绝callee-saved来源覆写、写回加载及未知原子指令。
- 辅助挑战发现共用CFI识别器的固定跨度不能覆盖actor较长的参数准备。其B.HS +16会绕过部分实参设置却仍到达调用。现由调用点指定必须越过的跨度：getattr为12字节，actor为44，prune／put_super为8。对应反例已加入，prune标志分支和put_super空指针分支也须越过实际调用。
- 首次新增prune负例将槽移动8字节，恰好变为另一种受支持布局，因而未被拒绝。用例改为移动24字节至支持集合之外，保留同一拒绝断言；原冻结工具与断言未改。首次生成脚本的换行错误及该用例失败均留在本地探索目录，未据此放宽生产判据。
- Sony5.15真实BTF的46项查询及原拒绝断言通过。沿用私有API适配副本，本轮只给权限查询传入unavailable实参；原Oracle文件保持。

目标源码范围沿用前阶段：Sony提交与镜像版本标记一致；B2N使用Nokia4.4.196语义参考，镜像为4.4.192，变化字段逐项核对实际机器码。固定提交的声明与实现来源、源文件哈希及窗口字节见阶段数据。

## 冻结身份

统一构建入口冻结143个输入，dynamic／static构建通过。探索档复算源码blob、参数、配方及产物哈希通过，ELF与92字节默认表通过。只有SDK已有READ_ONCE／WRITE_ONCE重定义警告。静态件与上一阶段逐字节一致，静态JSON校验后以独占创建附入新归档。

完整清单见[构建身份](handoffs/2026-10-14-nomount-function-operation-callbacks-phase6.json)，逐项结果见[阶段数据](data/2026-10-14-nomount-function-operation-callbacks-phase6.json)。两件均为exploration。

| 模式 | instance_id | SHA-256 |
| --- | --- | --- |
| dynamic | `nomount-2.1.1-20261014+ge6e1bab0a1cf.rac8ac08a.kpb51197a.ndk26.3.11579264#1` | `ec64c67b96feaa5dbf258c7eee2f5c0bc07eb51fdc0822f04204e536fcbe3aee` |
| static | `nomount-2.1.1-20261014_baselines+ge6e1bab0a1cf.ra0ca3ca6.kpb51197a.ndk26.3.11579264#1` | `b922daa76f010c4a623a3b32f8f35d6055cc2f3fa209bf34808923b66f7d3c7f` |

## 修正后保留（Retain）

**有效性**：本段6项有原生字段链、共同连续声明或调用约定证据，两目标匹配。CFI跨调用跨度问题已修正并复现拒绝。公共完整布局校验继续保留；本段字段成功不等于整个动态入口可加载。

**简洁性**：release／prune及drop／evict／put分别复用一个连续片段；actor选更短的empty_dir_readdir。CFI识别与单B跳板规则共用，前瞻与分支仍受固定窗口约束。

**后果**：未匹配的编译形态、类型或调用约定拒绝推导，有效BTF错误保留。共享CFI规则的原回调拒绝用例继续通过。辅助挑战和本轮复核属于Developer检查，不代替Auditor。

respect-the-oracle已核对原断言、夹具分组和宿主证据边界；no-negative-echo已回读源码、报告与身份清单。没有设备操作、发布或问题关闭。

## 剩余工作

剩余5个字段为inode_ops_size、super_ops_size、dentry_ops_size、key_type_size、key_callbacks。完整复制尺寸阶段仍早于本轮回调准备，当前完整动态入口仍在那里停止。取得这些字段后，还需补齐其他原生准备接口的无BTF核验，再交接完整候选及其旧KP二进制派生件。
