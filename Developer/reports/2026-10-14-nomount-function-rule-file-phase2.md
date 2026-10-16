# NoMount：规则入口与文件回调推导

规则阶段和文件阶段已接入无 BTF 推导。4.4、4.19 的真实镜像离线自检通过；完整初始化还缺其余操作表尺寸，以及 inode、目录、控制接口布局。这批产物属于 Developer 探索构建，不是完整修复候选，也没有新的独立审计或实机结论。

源码冻结提交：`c8e190d9acdb1462b09f53078ac3e5f74b849bbf`。前一阶段见[文件字段与表尺寸](2026-10-14-nomount-function-file-phase1.md)，完整缺项见[初始化分析](2026-10-14-nomount-non-btf-assessment.md)。

## 修改

- [nm_offsets.c](../../nomount/nm_offsets.c)从 full_name_hash 前4／6条区分两参和三参形式。仅取得调用 ABI，保留原版名称哈希算法。
- 复用 nm_structs.h 的共同定义，通过 dentry_open 前5条、vfs_open 前10条核对 path.mnt、path.dentry 到 dentry.d_inode 的基址链。匹配止于调用、分支或未知指令；全部前瞻在窗口内，相关 LDP／STP 不允许基址写回。
- 在 tty_default_fops 已证实的完整 file_operations 尺寸内扫描 def_blk_fops，找四个原生回调的唯一位置。两份参考源码都明确指定这四个函数。重复匹配或缺依赖返回错误。
- Sony4.19 的表使用 CFI 跳板。直接地址不匹配时，仅在原生 _stext／_etext 范围内读取对齐地址的一条指令，接受直接 B 精确到对应函数；不追踪第二跳或间接跳转。没有文本范围时仍可直接匹配，跳板无法确认就失败。
- [nm_btf.c](../../nomount/nm_btf.c)的规则查询增加 unavailable 输出；调度只对明确缺少 BTF 数据／接口的情况回退。有效 BTF 的类型、字段、原型和查询错误继续传播。完整入口与两个独立入口统一调用规则调度。
- 指令识别和字段解码继续统一用 kpm_utils.h；新增 UBFM getter 和 STP 的成对访存立即数 getter。配置表仍为46项／92字节，用户接口和驻留生命周期保持原样。

## 目标结果

| 新取得项 | B2N 4.4 | Sony 4.19 |
| --- | ---: | ---: |
| name_hash_args | 2 | 3 |
| fop_open | 88 | 104 |
| fop_release | 104 | 120 |
| fop_mmap | 80 | 88 |
| fop_splice_read | 184 | 192 |

本轮同时重跑上一阶段的六个文件字段／表尺寸，两目标共22项结果与绑定配置一致。目标镜像／内核哈希、实际窗口机器码、回调槽与跳板指令、固定提交源码链接及自检回执在[阶段数据](data/2026-10-14-nomount-function-rule-file-phase2.json)。B2N参考源码仍为4.4.196的语义参考，不改称镜像的准确构建源码。

## 自检与身份

- 新增 test_function_rule_callbacks.py，直接执行生产函数片段；实际内核地址统一平移到宿主缓冲区，保留机器码相对距离。真实内核函数不执行，BTF路由使用API夹具。
- 两目标在冻结源码上通过 ASan／UBSan。覆盖缺符号、未知入口、共同成员错位、X0覆盖、四个回调自动填入、必要槽缺失拒绝、重复匹配、未对齐／范围外指针、错误／间接 CFI 跳转、源表长度边界和有效 BTF 错误不回退。
- Sony5.15真实BTF的46项查询及原拒绝断言通过。规则查询的C调用声明改变，仅在新的私有 test_target_layout.py 副本传入 unavailable 参数并调整源码定位；原脚本和断言未改。旧 test_function_file_layout.py 的夹具没有 def_blk_fops，且将预置槽缺失设为阶段失败；新增能力会自行取得槽，本轮用新工具检查实际自动取得及公共验证器的缺槽拒绝，不把旧夹具当作当前完整阶段证明。原46个工具文件逐字节保持。
- 统一构建入口从干净提交冻结139个输入，构建 dynamic／static 两件，布局JSON输出到独立 LAYOUT_DIR。仅有SDK既有 READ_ONCE／WRITE_ONCE 重定义警告。
- 探索档核验复算源提交、输入、配方参数和产物哈希；ELF与92字节默认表检查通过。静态件和前一阶段基础件逐字节一致。静态JSON核对后以独占创建附入新归档目录。

构建清单：[阶段身份](handoffs/2026-10-14-nomount-function-rule-file-phase2.json)。两件均为 exploration。

| 模式 | instance_id | KPM SHA-256 |
| --- | --- | --- |
| dynamic | `nomount-2.1.1-20261014+g12e4f7c2ea8b.rc169dcd0.kpb51197a.ndk26.3.11579264#1` | `6a189ccc044ee54e2f67650a40c2221e7b849004a669d5d894d1bf94068a241e` |
| static | `nomount-2.1.1-20261014_baselines+g12e4f7c2ea8b.r636d8ac9.kpb51197a.ndk26.3.11579264#1` | `76e220cd0c7a6c2f5002d5f26148483baa06ccccad61f4838060159b7f2adac2` |

## 复核与剩余工作

are-you-sure 的辅助只读挑战指出：哈希入口不能证明 path／dentry 布局。补上独立入口验证和错位反例后，本段判定为保留（Retain）。有效性由两份真实目标机器码、原生表声明及拒绝边界支撑；简洁性上复用共同结构和短入口，不新增偏移表字段；后果上未知形态继续失败，CFI读取受代码区边界限制。这是Developer辅助复核，不代替Auditor。

respect-the-oracle 保留原工具／原断言字节，声明宿主夹具边界；no-negative-echo回读最终源码、回执及报告。没有设备操作、问题单关闭、版本／发布状态变更。维护者的发布暂停继续有效。

完整入口接下来仍会要求 inode_operations、super_operations、dentry_operations 和 key_type 尺寸，以及后续布局／ABI。原生表代理要复制既有表，必须继续寻找完整尺寸证据；已完成的文件表尺寸与槽位不足以绕过这道缺口。旧KP的二进制派生待完整修复候选时按新基础字节重做，本轮未请求Tester加载探索件。
