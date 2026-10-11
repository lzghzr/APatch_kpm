# run_cmd 偏移模式正向核对

Developer；2026-10-10。复核 `calculate_offsets()` 的全部查找分支，以当前裸内核入口、真实 BTF 成员与目标源码为依据。修改仅涉及 `run_cmd_demo/rc_offsets.c`，按 `.clang-format` 格式化。来源基点 commit：`5b3dc4656b9d1653e6a38d497a1dfa78ca905cfa`；当前为脏树探索，`source_dirty=true`。身份与完整语料 SHA-256 见 [收据](data/2026-10-10-run-cmd-offset-patterns.json) 和 [探索构建清单](data/2026-10-10-run-cmd-offset-patterns-build.json)。

## 复核决定（Decision）

**精简（Simplify）**。保留短窗口和字段数据流，删除 getter 已完成的类型判定。

## 挑战

### 有效性

逐份读取当前 `kernel_img/` 裸内核。核验其 SHA-256 后复用对应符号表，检查真实函数入口，运行原版本和精简后的生产偏移代码。参考值由入口反汇编取得；有 BTF 的镜像再直接解析原始成员记录，核对结果。

| 查找分支 | 实例依据 | 本次处理 |
| --- | --- | --- |
| BTF | 6 份镜像的 path、security、sid、kthread_work 成员记录；原生 resolver 返回类型或错误指针的契约 | 复用类型，删除冗余 NULL 判断；保留字节偏移、宽度和共同布局核对 |
| UMH path | mi6 为 LDR→三次 STR/STRH→CBNZ；mi8 为 LDR→ADD/MOV/STR→CBZ；较新入口有 STP 间隔 | 合并 CBZ/CBNZ，保留入口 X0 指针、同寄存器判空和当前间隔规则 |
| 旧 task getter | mi6/mi8 为栈回读后连续读取凭据、安全指针和 SID，再经过调用与栈回读写到输出；mi9 使用 X20/X19 | 保留凭据槽位、64/32 位宽度、指针链及输出写回，删除重复 opcode 判定 |
| 新 cred getter | mi10 为 LDR→LDR→STR；mi11 和 Android12～16 为 ADRP/LDRSW→ADD→LDR→STR | 保留 blob 全局地址、无移位相加及 SID 写回关系，删除重复 opcode 判定 |
| 旧 worker | mi6 的 ADD 定位 work_list，随后两次 STR 建立自指链表，第三次 STR 清零 task | 保留这条布局链；删除三次重复 STR 类型判定 |

### 简洁性

`inst_get_ldr_*_size()`、`inst_get_str_*_size()` 内部已检查类型，非目标指令返回 `-1`。因此外层指定 size 为 2/3 时，12 处显式类型检查完全重复。MOV 和两处 ADD 同理，改为 `sf == 1` 或 `sf != 1` 后移除 3 处重复检查；不能将返回 `-1` 的 getter 直接作为真假值使用。共删除 15 处重复 opcode 条件，既有宏保持原样。

### 后果

扫描范围仍为原来的 32/16 条入口窗口，保留 RET 停止。UMH 间隔白名单属于当前支持的编译形态，不能仅凭语料通过宣称它是 ARM 指令集的全部必要条件。本轮精简不扩展这项支持范围。旧 worker 的 `list + 32` 来自 16 字节 list_head 及其后 task/current_work 两个指针，是已支持旧布局的分配长度，并非完整任意版本大小推导。

旧 initializer 的语义可由 [Linux 4.4 kthread.c](https://raw.githubusercontent.com/torvalds/linux/v4.4/kernel/kthread.c) 和 [kthread.h](https://raw.githubusercontent.com/torvalds/linux/v4.4/include/linux/kthread.h) 核对（访问：2026-10-10）。两次自指存储和 task 清零在 mi6/B2N 实物入口中均存在。

## 更新后的方案

沿用现有分支与存储位置，使用 getter 同时完成类型和字段判定。后续匹配调整仍以目标入口、BTF 或源码契约作为依据。

## 真实语料结果

| 裸内核 | path | security | 结构内 sid | 路径 |
| --- | --- | --- | --- | --- |
| kernel_android12-5.10 | 0x38 | 0x78 | 0x4 | 函数 |
| kernel_android13-5.10 | 0x38 | 0x78 | 0x4 | 函数、BTF |
| kernel_android13-5.15 | 0x38 | 0x78 | 0x4 | 函数、BTF |
| kernel_android14-5.15 | 0x38 | 0x78 | 0x4 | 函数、BTF |
| kernel_android14-6.1 | 0x38 | 0x78 | 0x4 | 函数、BTF |
| kernel_android15-6.6 | 0x38 | 0x80 | 0x4 | 函数、BTF |
| kernel_android16-6.12 | 0x28 | 0x80 | 0x4 | 函数、BTF |
| kernel_mi10-4.19 | 0x38 | 0x78 | 0x4 | 函数 |
| kernel_mi11-5.4 | 0x38 | 0x78 | 0x4 | 函数 |
| kernel_mi6-4.4 | 0x28 | 0x78 | 0x4 | 函数 |
| kernel_mi8-4.9 | 0x28 | 0x78 | 0x4 | 函数 |
| kernel_mi9-4.14 | 0x28 | 0x78 | 0x4 | 函数 |

12 份函数路径的原版本与精简版本结果一致，并与逐份反汇编参考吻合；其中 6 份 BTF 路径也与原始成员记录吻合。表中的 sid 为结构内偏移；现代 LSM 实际地址还需加启动后 `selinux_blob_sizes.lbs_cred` 的运行时偏移。裸镜像中的该值是初始大小，此次观察器按原始值运行并单独记录，不将其当作运行时偏移。旧 task getter 的凭据槽位参考取自真实 get_task_cred 入口，不外推为其他设备 KP 标签正确的证据。

6.12 仅作为离线字段观察；6.18 按用户指示暂缓兼容。早先全语料观察器绕过加载前检查，在 6.18 缺少旧/新 worker 入口时发生宿主空指针访问，原始记录保留；实际 prepare_run_cmd 已先检查所需入口并返回 -ENOENT。这项夹具观察不用于修改生产匹配。

## 最终自检与身份

原三份测试文件哈希不变，191 条既有 assert 保留并通过 ASan/UBSan 回归。最终代码再对 B2N 已确认的两个 KP 槽位输入离线核对：path=0x28、security=0x78、sid=0x4、worker_size=40；Sony 5.15 的函数/BTF 路径均匹配 path=0x38、security=0x78、sid=0x4。普通/debug 构建与两份旧 KP 兼容件的既有 ELF/指针转接检查通过。

- instance_id：`run_cmd_demo-1.2.0+gf797f17d95bb.r07357428.kpb51197a.ndk26.3.11579264#1`；产物 SHA-256：`79ae3235e5d187ccb8072884efbd61fe084e6b38440fb05ca934cef94e0afd9a`。
- instance_id：`run_cmd_demo-1.2.0_debug+gf797f17d95bb.rd97d3e55.kpb51197a.ndk26.3.11579264#1`；产物 SHA-256：`1755e9195523a3f4df72b6aeda6fd992d9c0f400b841e804ace3aab60c6ec4f1`。

本报告追加覆盖前阶段报告的查找模式复核；前阶段产物与报告均保留。前阶段执行的编码组合诊断为历史探索记录，本轮调整依据是实际宏契约、源码和裸内核入口。

前次自查重点在凭据槽位修复，既没有逐项复核整个查找模式，也没有读清 getter 内部的类型检查，导致冗余条件漏检。测试通过不等于简洁性复核完成，本次将这两项明确补齐。

按 are-you-sure 完成全部分支的有效性、简洁性与后果复核；按 no-negative-echo 复读代码、报告与产物清单；按 respect-the-oracle 复算测试和既有产物哈希。此为 Developer 自检，未提交冻结，不替代独立审计或实机结论。

最终仓库常规门禁：16 项通过，0 失败，0 警告；报告、清单、源码指纹和产物哈希已复读核对。
