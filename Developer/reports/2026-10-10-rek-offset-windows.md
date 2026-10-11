# rek / rekx 偏移窗口与新语料自检

Developer；2026-10-10。探索源码基准 `7cb89e0c8c065443ac019f147c9bf4995f01db61`，source_dirty=true、kind=exploration。本记录为 Tier-3 开发者自检，不能代替独立审计、设备兼容性或交付验收。

## 实现与范围

动态模式优先查询 BTF；缺少 BTF 或原生查询接口时继续执行固定窗口函数推导。运行时选择依据查询结果，4.4～5.10 是函数推导的主要适配范围，5.15 及以上默认使用 BTF。

- 两模块独立将 binder_proc->alloc 扫描从 256 条缩至入口前 64 条，ADD/BL 组合的两条指令都位于窗口内。七份旧语料匹配位置为 27、38、40、54、46、51、50。
- binder_stats 的外层扫描从 256 条缩至 144 条，并把两层前瞻约束在同一窗口内。七份语料的首次匹配位置为 6、22、17、10、76、127、127。
- rekx 的 socket 偏移先使用 bpf_get_netns_cookie_sock 前 8 条：参数 x0 的第一次 64 位读取就是 sock_net(sk)。两份 5.10 均在索引 2 取得 0x30；没有该短入口或匹配失败时，继续原有 sk_net_capable 前 16 条。源码依据为已保存的 Android common 内核 net/core/filter.c 的 __bpf_get_netns_cookie 与 BPF_CALL_1 调用者；窗口同时处理调用、返回及参数寄存器覆盖。
- binder_get_txn_from_and_acq_inner 继续限定前 26 条，跟踪首次调用前保存的 transaction；BL/BLR 之后的 x0 是返回值，不能重新作为入口参数。4.14 的 x20 因此不会被后续保存返回值的 x19 替换。
- binder_alloc_init 的 pid 写入排除 WZR。Android13-5.10 在 pid 写入前会清零另一成员，原规则把 0xb8 误识别为 pid，实际 BTF 是 0x84。反向扫描限定在入口内，未取得 buffer_size 时失败。
- 公共指令宏在移位前转为无符号类型，修复 ADRP 符号扩展与逻辑立即数旋转的 UBSan 错误；对 reserved logical immediate 在调用 clz 前判零。指令宏保持既有模板与 ARM64 编码。
- Binder 释放 ABI、binder_proc_transaction 和 Genl 的其余窗口沿用现有规则。这些入口还有必要的参数或数据流证据，本轮没有依据进一步缩短。

模块描述已写入所有模式的 .kpm.info：`Re:Kernel. Binder, signal and network notifications.` 与 `ReKernel-X. Binder, signal and network notifications.`。

## 13 份语料

用户确认全部 13 份裸内核，包括 6.12、6.18；两份设备 boot.img 不属于本轮输入。复算源文件与解压 Image 哈希后运行生产 C 查询或推导代码；未执行目标 ARM64 机器码。

| 语料 | 实际结果 |
| --- | --- |
| `kernel_android12-5.10` | 函数推导：两模块完整返回 0；释放 ABI 5 |
| `kernel_android13-5.10` | BTF：rek 38、rekx 45 字段及共同布局通过 |
| `kernel_android13-5.15` | BTF：rek 38、rekx 45 字段及共同布局通过 |
| `kernel_android14-5.15` | BTF：rek 38、rekx 45 字段及共同布局通过 |
| `kernel_android14-6.1` | BTF：rek 38、rekx 45 字段及共同布局通过 |
| `kernel_android15-6.6` | BTF：rek 38、rekx 45 字段及共同布局通过 |
| `kernel_android16-6.12` | BTF：rek 38、rekx 45 字段及共同布局通过 |
| `kernel_android17-6.18` | 前瞻观察：BTF 返回 -ENOENT；binder_alloc.buffer 已变更，待 KP 支持后适配 |
| `kernel_mi10-4.19` | 函数推导：两模块完整返回 0；释放 ABI 4 |
| `kernel_mi11-5.4` | 函数推导：两模块完整返回 0；释放 ABI 5 |
| `kernel_mi6-4.4` | 函数推导：两模块完整返回 0；释放 ABI 3 |
| `kernel_mi8-4.9` | 函数推导：两模块完整返回 0；释放 ABI 4 |
| `kernel_mi9-4.14` | 函数推导：两模块完整返回 0；释放 ABI 4 |

12 份完成默认偏移路径自检；6.18 作为前瞻语料保留观察，使用者说明 KP 尚不支持该目标。6.18 含 BTF 且五个原生查询符号存在，实际生产 BTF 函数返回 -ENOENT：binder_alloc 没有 buffer，出现 vm_start。本轮保留该布局变化记录，后续随 KP 支持推进。

七份 4.4～5.10 分别运行 rek 与 rekx 的完整函数推导，公共字段输出一致。缺少 BTF 的旧目标没有逐字段独立布局参考，返回 0 仅说明当前规则完成。Android13-5.10 同时含 BTF，其 42 项由模块推导的字段与目标 BTF 一致；task_struct_cred、task_struct_comm、cred_uid 由 KP 夹具输入提供，不用于验证真实 KP 或生成目标静态配置。其余五份 BTF 目标分别核对 rek 38 / rekx 45 项及直接复用布局。

四份厂商镜像的现有提取器初始失败，通过本地布局诊断恢复完整 kallsyms（mi8 162946、mi9 136583、mi10 139786、mi11 172911 项）。核对完整 token index、markers、名称/地址计数、_text=0、实际入口及 BL 目标。失败原因是提取器未覆盖零基址与部分 256 字节对齐/u64 markers 布局，不能解释为内核缺少 kallsyms。诊断没有改动正式提取器；这是 Developer 同源证据。

## 自检判据

Genl/上下文、指令、清理、短锚点、Binder from/is_dead 的原有宿主判据保留，新增实际 4.14 返回值保存、5.10 清零写入、ADRP/逻辑立即数及 BPF socket 小窗口案例；运行 ASan/UBSan。test_modes 的夹具补充可选 lookup_name_continue 入口，默认缺失，使原有 socket 判据继续执行；未修改旧断言。静态四种释放 ABI 的数据补丁边界、八种构建模式标签/导入/初始表也通过。

在七份旧镜像的内存副本上分别移除 alloc 或 stats 的首次匹配：13 次返回 -11；5.4 的 stats 仍通过后续真实地址设置取得同一字段，全部输出与原结果一致。该观察没有把后续匹配强行定义为失败，也没有外推为任意优化形态的安全证明。原始期待失败的观察退出码与实际输出均保留。

八份 KPM 的未定义导入与当前 KP SDK 导出逐项匹配，反汇编没有 FP/SIMD/SVE/x18 操作数；这不证明运行端导出。regular 门禁 16/16 通过。516 份既有归档文件与交接清单逐项哈希不变。

私有证据目录为 `local/rek-window-corpus-_y1x_n86/`：function-alloc-verified、各镜像 rek-function / btf-final / btf-observe / window-negative、vendor-symbols、genl-complete、modes-complete、complete-layouts、构建和门禁记录。所有镜像及诊断输出均为本地数据。

## 自查决策（Decision）

**修改（Modify）**：短窗口方向保留，实际语料暴露的寄存器、清零写入和指令算术缺陷须修复。

### 有效性

完整执行两模块生产推导，比对 5.10 实际 BTF 后才确认窗口缩短及新锚点。不能以仅返回成功代替布局参考；6.18 的字段缺失如实保留。

### 简洁性

保留现有函数分组和固定窗口，只添加短入口及必要的参数语义。其余长窗口暂保留，未增加按版本选择偏移、全函数扫描或通用数据流框架。

### 后果

缩短窗口会使位于更后方的新编译器布局失败；这是本轮策略边界。现有实际语料的匹配仍位于范围内，移除匹配的观察与原生 BTF 参考帮助排查误取后续值；最终可靠性仍需要独立审计及真机测试。边界不可为过测自动延长。

### 建议

将本轮源码和身份交由独立角色复核，后续目标按镜像证据适配。已按 no-negative-echo 回读公开记录、描述和清单；按 respect-the-oracle 保留所有旧判据，只补充新用例与宿主接口。

## 开发者问题单

下列问题归属和发现方均为 Developer；未自行关闭，维护者可登记，独立角色复核后关闭。状态均为 fixed(待复核)，修复目前是本记录绑定的未冻结探索输入。

- **DEV-024（中）公共解码宏出现有符号移位 UB**：七份旧语料的 ADRP 解码、5.4/5.10 的逻辑立即数在修改前观察中触发 UBSan。影响偏移运算稳定性，未证明实机崩溃。频率：未知；置信度：已确认。修复为移位前使用无符号数、避免 clz(0)。关闭条件：Auditor 独立核对 ARM64 算术及最终候选，覆盖正负 ADRP 边界和高位逻辑立即数。
- **DEV-025（中）4.14 的 Binder from 参数跟踪被返回值覆盖**：修改前 mi9 完整推导返回 -11，函数索引 3 保存 x20，BL 后索引 5 保存返回值 x19，真正 from 位于 x20+0x20。影响该目标动态加载。频率：未知；置信度：已确认。关闭条件：独立复核新参数跟踪规则、原有错寄存器/覆盖负例及 mi9 入口。
- **DEV-026（中）5.10 的 allocator pid 误取清零字段**：修改前 Android13-5.10 返回成功却得到 184，BTF 为 132；索引 5 的 STR WZR 抢先匹配。影响进程信息和依赖该字段的行为。频率：未知；置信度：已确认。关闭条件：独立 BTF/入口核对、清零写入和反向扫描负例、候选身份一致性。
- **DEV-027（中）5.10 的 socket 能力检查展开超出旧短链**：两份 5.10 在无 BTF 函数路径返回 -EINVAL，内联 LSM 使 user_ns 参数传递位于窗口后方。影响该目标动态加载。频率：未知；置信度：已确认。修复使用前 8 条的 BPF socket cookie 入口，继续原有短链降级。关闭条件：独立核对 helper 实际参数类型/机器码、缺符号与指令变化负例及静态/动态模式。

## 探索产物身份

KernelPatch `b51197aaba8f2272dd8a3e30c85698a29aa928c9`，NDK 26.3.11579264，目标 `all debug -j4`。布局 JSON 在私有 complete-layouts 中；源码输入包含根 patch_offsets.py，配方捕获 LAYOUT_DIR。构建统一入口冻结并复核输入后生成八份产物；此前未捕获 NDK 与布局输出目录的失败尝试保留在私有日志，未登记身份。

两份交接清单为 `handoffs/re_kernel-20261010-offset-windows-exploration.json` 与 `handoffs/re_kernel_x-20261010-offset-windows-exploration.json`。这些清单是探索留痕；正式交接仍需从冻结提交重建。

| 产物 | instance_id | SHA-256 |
| --- | --- | --- |
| `re_kernel_11.7.kpm` | `re_kernel-11.7+g7effd26c21a2.r31d35e72.kpb51197a.ndk26.3.11579264#1` | `3ddb8fc9a69010bd87092f0d6b3d0af4e313585b1630d9c64f8a4517f2f86482` |
| `re_kernel_11.7_baselines.kpm` | `re_kernel-11.7_baselines+g7effd26c21a2.r45fc136e.kpb51197a.ndk26.3.11579264#1` | `eb5d252c45603a23305ea6526d58339549ae92b861fc4ce92477b020c270d60b` |
| `re_kernel_11.7_baselines_debug.kpm` | `re_kernel-11.7_baselines_debug+g7effd26c21a2.r6fdb71ae.kpb51197a.ndk26.3.11579264#1` | `3f28328078a41807b1eb969d608b8c2621ef51e672a16355fc3bd85147c495c1` |
| `re_kernel_11.7_debug.kpm` | `re_kernel-11.7_debug+g7effd26c21a2.r4ba2d9df.kpb51197a.ndk26.3.11579264#1` | `3dba88b800871dac66e8a78ae84775213b0d967aa444d652fa6846065f6895c9` |
| `re_kernel_x_1.6-20261008.kpm` | `re_kernel_x-1.6-20261008+g21d1ec050be5.rf0c7b4af.kpb51197a.ndk26.3.11579264#1` | `151ef48c73afe7703c13778cbaffccf0c5b900bd1e6b98aea2d483933b33030f` |
| `re_kernel_x_1.6-20261008_baselines.kpm` | `re_kernel_x-1.6-20261008_baselines+g21d1ec050be5.r450157fb.kpb51197a.ndk26.3.11579264#1` | `2933c90f15c4ec66872fce0e6f2222e10fd314dfe31a69d7ca998df60201144a` |
| `re_kernel_x_1.6-20261008_baselines_debug.kpm` | `re_kernel_x-1.6-20261008_baselines_debug+g21d1ec050be5.r00915f18.kpb51197a.ndk26.3.11579264#1` | `ed6f97dcf8cdaf8498d22ecc5de410a4887e3492e38aa585f2ffded091ad8b0a` |
| `re_kernel_x_1.6-20261008_debug.kpm` | `re_kernel_x-1.6-20261008_debug+g21d1ec050be5.re57b12cf.kpb51197a.ndk26.3.11579264#1` | `e6ce734b2ad7c60290b495c86244a988e8180462711a63fb57e88cbecdd73304` |
