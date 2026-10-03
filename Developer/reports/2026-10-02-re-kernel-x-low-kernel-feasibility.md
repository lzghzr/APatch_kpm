# ReKernel-X 1.6：六份旧内核离线移植可行性自检

角色：Developer。源码完整提交 `52b303df659616012077bc95ed7899655295d925`。本轮为独立运行的实现方探索，未使用 Auditor 工具或报告；不构成独立审计、目标候选交接或 Android 实机结论。共享 HEAD、模块代码和既有冻结资产保持原状。

## 结果

静态偏移段替换机制在五份非 CFI 语料上完成了完整字段编码与字节范围验证。每份生成 44 项探索配置、选择实际释放函数 ABI，并用既有 1.6 基准完成 release/debug 的 JSON 与 blob 两条替换路径，共 10 个变体、20 份派生 KPM；同一变体两种路径结果逐字节相同，往返导出相同，偏移段以外字节不变。目标布局仍需独立核对，这些探索文件不作为可加载交接产物。

CFI 语料 `kernel_4.14.186` 不能仅靠替换偏移完成适配。已在本地副本还原符号，但当前模块缺少后缀 hook 查找及缺失数据符号的前置处理，见 DEV-005、DEV-006。

| 语料 | 内嵌版本 | 释放 ABI | 当前覆盖 |
| --- | --- | --- | --- |
| `kernel_4.14` | `4.14.117-perf+` | 4 | 44 项探索配置及替换/往返通过 |
| `kernel_4.14.186` | `4.14.186-gbc682460573f` | 4（本地指令推导） | CFI/数据符号阻塞；未生成目标 KPM |
| `kernel_4.19` | `4.19.324-perf+` | 4 | 44 项探索配置及替换/往返通过 |
| `kernel_4.4` | `4.4.192-black_caps+` | 3 | 44 项探索配置及替换/往返通过 |
| `kernel_4.9` | `4.9.227-perf+` | 4 | 44 项探索配置及替换/往返通过 |
| `kernel_4.9_miui` | `4.9.186-perf-g10af704` | 4 | 44 项探索配置及替换/往返通过 |

## img 输入与语料身份

本轮裸内核只是节省存储的中间语料；实际用户入口仍是 Android img。六份原始内核分别套入模拟 boot v0/v1/v2/v3/v4，另测试裸 Image 与 gzip，共 42 例。生产 `bootimg.unpack_bytes` 还原的 Image 字节及 SHA-256 全部与输入一致；v0/v2/v4 覆盖 gzip payload，v1/v3 覆盖未压缩 payload。模拟头验证了解包与分析的衔接，不覆盖真实厂商包装、ramdisk、vendor_boot 或其他压缩格式。

输入原文件均未改动。范围由用户明确选择为六份 4.4～4.19 内核；5.15、6.1、6.6 仅进入原始文件清单，不参与本轮分析。

| 文件 | 裸 Image SHA-256 |
| --- | --- |
| `kernel_4.14` | `53cde15ec4b0b73aff3436a0c5f3df1c205c5c943a62fdaf015dd65c91159b60` |
| `kernel_4.14.186` | `70642b0e7cd4c575ed27906a7dbcf4dd1f3359d73d22a42f2b4823cdffae7bd1` |
| `kernel_4.19` | `b041d6d634274595cec875806f56af72ca0aa25843f280624e51fb1f46963ce5` |
| `kernel_4.4` | `e8c119c576ac8cffcaadaf0e56592e7a209744572b4a57fa8b967c172dc51a8c` |
| `kernel_4.9` | `a3618cb7ac88ade3c1a4e560b2958979269a58c17391d6ad67ff5d61c73ade70` |
| `kernel_4.9_miui` | `0e95e31b5ed921e29c5e4cd3c3e84cbf0b27dd48de9f305a484893c60356e20d` |

## 目标偏移依据与工具边界

既有 harness 提取五份符号表，旧 31 项推导均返回 PASS。本轮按当前 44 项表额外检查 Genl、凭据、任务名称、socket net、proc is_dead 及旧数据读取；补充证据为目标函数反汇编，配置以单张镜像的哈希绑定，不按 Linux 版本号决定 ABI 或套用相邻版本偏移。

- `kernel_4.4` 的 `binder_alloc_buffer_size` 同时读取 `alloc+0x38`、`alloc+0x78`、`buffer+0x58`，`binder_alloc_mmap_handler` 写入前两种映射基址及首块 data。因而本轮将旧推导结果的 `alloc.buffer=0x40` 修正为 `0x38`，配置 `binder_buffer.data=0x58`。这是该镜像的值，不是 4.4 默认值。其余四份有原生 `binder_alloc_copy_from_buffer`，`binder_buffer_data=-1`。
- `sys_getuid` / `__arm64_sys_getuid` 与 `__get_task_comm` 核对 cred/uid/comm；`genlmsg_put`、family 注册/注销与 `genl_pernet_init` 核对共同配置、mcgrps/count/count-width/group-offset/net socket；`netlink_sendmsg` 和 proc 释放路径核对 socket net 与 is_dead。证据逐目标保存在 `evidence-v2/`、`supplement/`。
- 旧 harness 的 `is_frozen=0` / `outstanding_txns=0` 警告对应现有模块的缺失字段分支，不直接视为完整移植失败。`_end` 可包含 Image 未存储的 BSS，单凭 `_end-_text > file_size` 不能认定符号表来自别的镜像。
- 输入发现器未匹配 `kernel_*` 文件名。为避免改变冻结工具，本轮在新目录按每个目标建立名为 `Image` 的只读输入符号链接；实际分析始终读取原文件，未重命名或覆盖用户输入。
- CFI 镜像配置为 `KALLSYMS=y`、`KALLSYMS_ALL=n`、`KALLSYMS_BASE_RELATIVE=n`、`CFI_CLANG=y`。本地诊断恢复 238963 个 `R_AARCH64_RELATIVE` 写入，符号表有 93687 项、93572 个不同名称。`_text` 不在真实符号表；既有提取器的该断言使其无法接收这一配置。
- 仅在本地诊断中，将 `_text` 存在要求改为 RELA 地址映射、符号内容检查、全部符号地址位于 Image 范围、关键函数及跨函数 BL 目标核对。替代判据适用于该张镜像，尚未进入生产工具，需独立复核。[ARM64 启动重定位实现](https://github.com/torvalds/linux/blob/v4.14/arch/arm64/kernel/head.S) 解释了 RELA 写入语义；目标机器码与实际表项用于核对厂商镜像。
- 诊断初次地址抄录差 0x100 的符号结果被拒绝并单独标记，最终分析仅使用 `relocated-v3`。有效规范化 Image SHA-256 为 `18dc577be5deb52a465c765d976a7da0d82d6f2029f1fe6fd3db74a46dfe6a97`。没有把失败记录改写成通过，也没有放宽 KPM 的字段、ABI、段范围检查。
- 规范化后 CFI 语料的旧推导在 `binder_stats_deleted_transaction` 阶段失败，因为没有 `binder_stats` 数据符号；没有填写猜测偏移或生成该目标 KPM。

## 正式问题单

### DEV-005：原名 hook 查找无法处理目标 CFI 后缀

- 严重度：中；归属：Developer；发现方：Developer；状态：open，未修复，待独立复核。
- frequency：本轮 `kernel_4.14.186` 的查找失败可确定复现；confidence：高（镜像符号与源码/主机生产初始化前缀一致）。
- 影响：`kpm_utils.h` 的 `lookup_name` 使用 `kallsyms_lookup_name`。该镜像 `tcp_v6_do_rcv` 只有 `$ee27caa43c353d9731099fb1ec6d2c19` 及 CFI jump table 形式，初始化在 tracepoint 注册之前返回 -21。`genl_rcv_msg` 同样仅有 `$1309a1e4f601a8e6c1715537ac333319` 及 jump table 形式。偏移替换无法修复符号名称查找。
- 验证：真实镜像符号驱动的主机探针截取生产初始化前缀，返回 -21，tracepoint 调用次数为 0。
- 建议：后续另轮在明确范围内统一 hook 后缀查找，同时处理 DEV-006；不在本轮改动共享宏或冻结源码。
- 关闭条件：独立角色在新冻结提交复核实际后缀解析、CFI 跳板语义及初始化错误路径，Tester 按新产物身份验证。

### DEV-006：缺失 tracepoint 数据符号时存在空指针内核调用路径

- 严重度：高（可致内核空指针异常）；归属：Developer；发现方：Developer；状态：open，未修复，待独立复核。
- frequency：要求前序必需 hook 均可解析、tracepoint 对象不可解析；本轮 CFI 镜像当前被 DEV-005 更早阻止；confidence：高（生产调用边界与目标内核解引用指令已核对）。
- 影响：`re_kernel.c:917` 查找 Binder tracepoint 数据对象，但 `:951` 在未检查其非空时调用内核注册函数。该镜像 `tracepoint_probe_register` 函数存在，数据对象 `__tracepoint_binder_transaction` 不在符号表。如果前序函数可解析（或后续补齐后缀查找），会向原生注册函数传入 NULL。
- 目标证据：`tracepoint_probe_register` 在 `0x2abe1c` 调用 `0x2abb10`；prio 函数 `0x2abb30` 将 x0 保存到 x21，锁调用后 `0x2abb50` 直接 `ldr x19, [x21, #0x10]`，此前没有检查 tp 非空。与 [内核 tracepoint 注册实现](https://github.com/torvalds/linux/blob/v4.14/kernel/tracepoint.c) 一致。
- 主机边界探针只将 IPv6 hook 视为可解析，其余符号仍来自该镜像，生产前缀确实向注册边界传入 NULL；全符号对照组传入非 NULL。探针用 spy 捕获参数，没有在主机执行目标内核，也没有声称该设备已经崩溃。
- 同类依赖：`init_net`、`binder_stats` 也缺失；后缀查找不能生成不存在的数据符号。需要在任何内核调用、hook 或 trace 注册前检查必需变量及函数，先安全拒绝，再另轮研究地址获取/降级方式。
- 关闭条件：新提交在独立的缺失变量负例中证明提前安全失败且无内核注册/hook 副作用，再由独立角色复核。

## 产物身份与证据

本轮基准来自已登记的 1.6 冻结实例（source_commit 同为 `52b303df659616012077bc95ed7899655295d925`）；完整原始构建条目复制到本轮 `parent-identities.json`，未修改 metadata。下表列出 JSON 路径的探索结果；blob 路径字节相同。没有为探索产物伪造候选 instance_id。

| 目标/变体 | 基准 instance_id | 基准 SHA-256 | 探索派生 SHA-256 |
| --- | --- | --- | --- |
| kernel_4.14/abi4 | `re_kernel_x-1.6_abi4+g3ea7f04a4665.r3c69ad06.kpb51197a.ndk26.3.11579264#1` | `4f2b9fbd09d61650b81de114e8cfa3a1522723e95e1dbf36bd7a06dc668b8261` | `e1b6bc87cce06842091ac5f91a0a32e2960689a6bbd965deb2a881d6c4dcf194` |
| kernel_4.14/abi4_debug | `re_kernel_x-1.6_abi4_debug+g3ea7f04a4665.r11816726.kpb51197a.ndk26.3.11579264#1` | `dc63b6008c917dc1ed2ac1c555052e09f9f2ee1d249e372407bc13bd806a469e` | `3ab5d36677009bce88afe5a0a5cc2014c9550292427218d5d4f9ab51f159105d` |
| kernel_4.19/abi4 | `re_kernel_x-1.6_abi4+g3ea7f04a4665.r3c69ad06.kpb51197a.ndk26.3.11579264#1` | `4f2b9fbd09d61650b81de114e8cfa3a1522723e95e1dbf36bd7a06dc668b8261` | `f9b3e3e2e4e0533cd40259dda3779d74bf159c55bf70154475fa2ef374b335f1` |
| kernel_4.19/abi4_debug | `re_kernel_x-1.6_abi4_debug+g3ea7f04a4665.r11816726.kpb51197a.ndk26.3.11579264#1` | `dc63b6008c917dc1ed2ac1c555052e09f9f2ee1d249e372407bc13bd806a469e` | `35d3daaeeb0a1f241eed5665cc676710bdd025b96cd42b5044d7fc58275188ae` |
| kernel_4.4/abi3 | `re_kernel_x-1.6_abi3+g3ea7f04a4665.r5730df8f.kpb51197a.ndk26.3.11579264#1` | `deb58ffc0ebed5a4f22f7df190f75ce2539b53592639911e7fd5c51b1bab2a15` | `45ac8d25480bf9acad0b539bfcbfd5528df9af00466c43294d066d338428f76e` |
| kernel_4.4/abi3_debug | `re_kernel_x-1.6_abi3_debug+g3ea7f04a4665.rbb9ef2a0.kpb51197a.ndk26.3.11579264#1` | `52e22ee6e41e7c9597bdec720ac533238744ba34b0f6fdd89005b9ad6659ae52` | `6fdb51455b508f94880e0155157afd4e5c0018a8c5d4049a0e0cb3cab455f5ca` |
| kernel_4.9/abi4 | `re_kernel_x-1.6_abi4+g3ea7f04a4665.r3c69ad06.kpb51197a.ndk26.3.11579264#1` | `4f2b9fbd09d61650b81de114e8cfa3a1522723e95e1dbf36bd7a06dc668b8261` | `00b3ea80f848f106fdc5d4bac4cb1483ae50da5ac12067348c83039adb19521d` |
| kernel_4.9/abi4_debug | `re_kernel_x-1.6_abi4_debug+g3ea7f04a4665.r11816726.kpb51197a.ndk26.3.11579264#1` | `dc63b6008c917dc1ed2ac1c555052e09f9f2ee1d249e372407bc13bd806a469e` | `25e49feac851200d41f03225c5eb09d8cbb6cacf99103d89663a21829ebd1c89` |
| kernel_4.9_miui/abi4 | `re_kernel_x-1.6_abi4+g3ea7f04a4665.r3c69ad06.kpb51197a.ndk26.3.11579264#1` | `4f2b9fbd09d61650b81de114e8cfa3a1522723e95e1dbf36bd7a06dc668b8261` | `0a73ede958b37ac8a958d3608f939c0306c74f8d841599513a2343b940e9717b` |
| kernel_4.9_miui/abi4_debug | `re_kernel_x-1.6_abi4_debug+g3ea7f04a4665.r11816726.kpb51197a.ndk26.3.11579264#1` | `dc63b6008c917dc1ed2ac1c555052e09f9f2ee1d249e372407bc13bd806a469e` | `8ff033d0d8dfefacb40fc88ed92f148078aa63a7c3b753a4956d15e73e0809fc` |

全部证据位于 `local/rekernel-x-feasibility-20261002-01/`：`inventory.json`、`scope.json`、`img-entry-tests.json`、`legacy/offsets.json`、`inspection-v2.json`、`profiles/`、`patch-results.json`、`relocation-v3.json`、`cfi-offsets.json`、`cfi-evidence/`、`init-prefix-probe.json`、`protected-before.json` / `protected-after.json`。每个脚本、配置、日志和结果的 SHA-256 将写入本轮证据清单。

初始化探针使用 Clang ASan/UBSan，三个控制情形通过。内核回调、锁、网络命名空间、实际 ACK/事件、Binder 对象生命期、应用响应和卸载没有在本轮验证；目标共同结构体前缀和 ABI 的最终核验仍由独立角色完成。

## 资产保护与后续

起点记录的 201 个既有源码/报告/产物条目逐文件 SHA-256 与 mode 均未变；全部 9 份原始输入哈希未变。未向 Auditor/Tester 路径写入、未调用设备、未覆盖 MANIFEST、未构建进旧输出目录、未改写或提交共享源码。只追加本 Developer 报告和新 local 探索目录。

建议优先在审计结束后另轮补齐初始化依赖检查及 hook 后缀处理，再考虑 `KALLSYMS_ALL=n` 的静态数据地址适配。静态偏移替换路线对前五份语料没有发现需要改变函数基准的证据，但不能外推为全部低版本内核都已适配。
