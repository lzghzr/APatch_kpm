# rek / rekx 头文件职责与共用实现核对

Developer 在源码基准 `7cb89e0c8c065443ac019f147c9bf4995f01db61` 的未提交工作树上整理文件。本轮构建为 exploration，身份清单保存完整源码基准提交、源树指纹、构建实例和产物哈希；冻结后需重新构建候选。

## 文件职责

- `re_kernel.h`：模块常量、命令与协议，包含本模块的 `re_structs.h`。
- `re_structs.h`：核对过的 Binder、Netlink、socket、skb 等内核定义；rek 新增该文件，并按 rekx 的顺序和写法整理。
- `re_utils.h`：KP 风格内核调用封装与模块锁。
- `re_offsets.c`：`struct struct_offset`、偏移表、访问函数和动态推导。rek 的动态表从入口文件迁入，BTF 实现也随偏移入口包含；rekx 已采用此组织。rek 静态配置继续复用 rekx 的基线表。

## 以 rekx 为准核对

rek 的共用内核定义与 rekx 字节一致，额外保留其单播回复使用的 `MSG_DONTWAIT`。Netlink flags、对齐宏及头长度定义已按 rekx 整理。23 个同名偏移访问函数、12 个共用 KP 封装、Genl 指令推导段与 `re_runtime.c` 一致；BTF 查询声明、上下文初始化和 Binder 释放 ABI 判定一致。

业务公共部分已逐函数比较：UID 数组操作、冻结判断、Binder 锁、事务来源与上报入口、网络接收处理等同名实现一致。清理流程的锁内状态复核、匹配旧消息保留量及释放顺序一致。rekx 的清理规则、RPC/data 读取与协议组装按其上游工作，rek 保留自己的协议和 code 过滤；释放分派分别消费 rek 的推导布尔值与 rekx 的配置表 ABI。动态字段清单按各自消费者保留，日志前缀标识各模块。

## 自检与边界

- 两模块的动态、静态基线及各自 debug，共 8 份重新构建成功，与整理前对应 KPM 逐字节一致。
- 两模块 BTF 宿主自检通过；rek 的 Genl、指令、锚点、Binder 状态和清理宿主自检通过。
- 宿主源码提取改读 `re_structs.h` / `re_offsets.c`，复制新增头文件并登记其哈希；现有断言行与范围保持不变。
- 构建输入前后哈希一致，归档产物与清单哈希复算一致；此前已归档资产和交接清单保持原样。
- 按 are-you-sure 复核，决策为保留（Retain）：文件职责清晰，共用实现一致，产物字节证明本轮整理保持编译结果。no-negative-echo 与 respect-the-oracle 的自查覆盖当前代码、记录和生成清单。

这些是 Developer 构建、代码比较和 Tier-3 宿主自检，不能外推为新镜像兼容或实机结论。本轮未操作设备、未提交或冻结。私有证据保存在 `local/rek-headers-xkjpzuna/`。

## 当前探索身份

KernelPatch：`b51197aaba8f2272dd8a3e30c85698a29aa928c9`；工具链：NDK 26.3.11579264。

| 产物 | instance_id | SHA-256 |
| --- | --- | --- |
| `re_kernel_11.7.kpm` | `re_kernel-11.7+g2fcdd041465f.r6b6c9fc0.kpb51197a.ndk26.3.11579264#1` | `72afa556eee88ac418efec8c0b22e455a88cdcb233fc3c9cdb8e4762830767d7` |
| `re_kernel_11.7_baselines.kpm` | `re_kernel-11.7_baselines+g2fcdd041465f.r727f8a41.kpb51197a.ndk26.3.11579264#1` | `a54945f94f1fe7b8c11882204f15099681e2d8136f590e4394ef59a69a4b80ba` |
| `re_kernel_11.7_baselines_debug.kpm` | `re_kernel-11.7_baselines_debug+g2fcdd041465f.r2d6e054f.kpb51197a.ndk26.3.11579264#1` | `3f3e70d7b73cd68317e7d1457446cf6603a47cd147c2999361e1ab437dfbca1b` |
| `re_kernel_11.7_debug.kpm` | `re_kernel-11.7_debug+g2fcdd041465f.rd7c008a8.kpb51197a.ndk26.3.11579264#1` | `49de7837b999b9f29e08fc0ec38254b1618bd547b17eaed34d7fafa3865962ce` |
| `re_kernel_x_1.6-20261008.kpm` | `re_kernel_x-1.6-20261008+g91b86fd6a962.re96e93c3.kpb51197a.ndk26.3.11579264#1` | `edff9d8c00afb220f04e65aede455219e6b9d0c5a89c23783cecb49196097331` |
| `re_kernel_x_1.6-20261008_baselines.kpm` | `re_kernel_x-1.6-20261008_baselines+g91b86fd6a962.r2a9979ef.kpb51197a.ndk26.3.11579264#1` | `023bbae5af28bf5d982aaaf880943c8f5ecf66014165538eb5d7e81c47bf7d69` |
| `re_kernel_x_1.6-20261008_baselines_debug.kpm` | `re_kernel_x-1.6-20261008_baselines_debug+g91b86fd6a962.rf267bc8d.kpb51197a.ndk26.3.11579264#1` | `ade02e8bd50326d3d663d2360fe5ea7a5577ef7fd60e47d059551ef9c35f88f9` |
| `re_kernel_x_1.6-20261008_debug.kpm` | `re_kernel_x-1.6-20261008_debug+g91b86fd6a962.r28d41c64.kpb51197a.ndk26.3.11579264#1` | `e6410674d21fd2c0cf96beac7c97414fed1c110e194c29e8b40587c36835fe5c` |

身份清单：[rek](handoffs/re_kernel-20261010-headers-exploration.json)、[rekx](handoffs/re_kernel_x-20261010-headers-exploration.json)。


## 模块独立性与偏移文件整理

rek、rekx 各自在本模块 `re_offsets.c` 中维护表定义、访问函数及静态/动态入口。rek 的静态配置保留原有 45 项、90 字节的布局与默认值；动态配置保留原有 38 项、76 字节布局。两种模式在模块内共用访问函数。rek 静态表使用 `volatile`，保证离线替换后的值从表读取；动态表在加载时填写，保持普通声明。各模块的 Makefile 只依赖本模块源码和根目录公共工具。

`patch_offsets.py baseline` 通过 `--source <模块>/re_offsets.c` 接收同一构建提交中的表定义。dump/patch 继续依据配套 JSON 工作。rek 的源码和 BTF 中清除已失效的跨模块分支，两个 Makefile 的模块选择宏一并移除。rekx 的独立 Genl 访问函数直接定义。

删除未参与编译的 `re_kernel_x/re_vmlinux.c` 和 `vmlinux.h`；当前模块说明改为从目标 BTF 取得偏移，释放调用方式仍需函数签名或调用点证据。技能更新随维护者补丁建议交接。已绑定历史源码的报告与清单保留原记录。

### 自检

- 两模块各四份 KPM 重新构建成功，全部与整理前逐字节一致。
- 分别复制本模块源码、Makefile 与根目录公共工具，在不包含另一模块目录的隔离副本中构建。8 份 KPM 和 4 份布局 JSON 与统一构建结果逐字节一致。
- BTF、rek Genl/锚点/Binder 状态及清理、双模式 ELF/补丁、rekx 静态协议/Genl/规则/清理自检通过。清理宿主测试使用 ASan/UBSan。
- 宿主源码提取按条件编译选择动态表；布局工具调用新增本模块 `--source` 参数。四个调整脚本的 Python 断言与夹具 C 断言逐项核对保持原样；截断 ELF 负例继续传入有效源码参数。
- 构建清单的源码与产物哈希复算通过；此前 471 个归档文件、MANIFEST 与交接清单保持原哈希。regular 门禁 16/16 通过，补丁适用性和差异格式检查通过。

### 复核（Retain）

有效性：各模块的隔离构建与布局 JSON 比较证明构建输入独立，静态表可继续替换。简洁性：共用访问函数保留在各模块内，移除无消费者的生成器与条件分支。影响：8 份 KPM 字节一致，原有表顺序和编译行为保留。no-negative-echo 回读当前源码、说明、补丁和身份清单；respect-the-oracle 核对现有判据未缩小。

这些是 Developer 构建与 Tier-3 宿主自检，不作为独立审计或实机结论。本轮未提交、未冻结，也未运行镜像或设备测试。私有证据位于 `local/rek-branch-cleanup-f5xgo_m8/`。

### 本轮探索身份

source_commit：`7cb89e0c8c065443ac019f147c9bf4995f01db61`；source_dirty=true。KernelPatch：`b51197aaba8f2272dd8a3e30c85698a29aa928c9`；工具链：NDK 26.3.11579264；目标：`all debug -j4`。

清单：[rek](handoffs/re_kernel-20261010-independent-cleanup-exploration.json)、[rekx](handoffs/re_kernel_x-20261010-independent-cleanup-exploration.json)。

| 产物 | instance_id | SHA-256 |
| --- | --- | --- |
| `re_kernel_11.7.kpm` | `re_kernel-11.7+g9a54e3e1468b.r69fbf164.kpb51197a.ndk26.3.11579264#1` | `72afa556eee88ac418efec8c0b22e455a88cdcb233fc3c9cdb8e4762830767d7` |
| `re_kernel_11.7_baselines.kpm` | `re_kernel-11.7_baselines+g9a54e3e1468b.ra573ff65.kpb51197a.ndk26.3.11579264#1` | `a54945f94f1fe7b8c11882204f15099681e2d8136f590e4394ef59a69a4b80ba` |
| `re_kernel_11.7_baselines_debug.kpm` | `re_kernel-11.7_baselines_debug+g9a54e3e1468b.raec305b4.kpb51197a.ndk26.3.11579264#1` | `3f3e70d7b73cd68317e7d1457446cf6603a47cd147c2999361e1ab437dfbca1b` |
| `re_kernel_11.7_debug.kpm` | `re_kernel-11.7_debug+g9a54e3e1468b.r04bf5bb2.kpb51197a.ndk26.3.11579264#1` | `49de7837b999b9f29e08fc0ec38254b1618bd547b17eaed34d7fafa3865962ce` |
| `re_kernel_x_1.6-20261008.kpm` | `re_kernel_x-1.6-20261008+g992f756f4e4f.r7fdd470c.kpb51197a.ndk26.3.11579264#1` | `edff9d8c00afb220f04e65aede455219e6b9d0c5a89c23783cecb49196097331` |
| `re_kernel_x_1.6-20261008_baselines.kpm` | `re_kernel_x-1.6-20261008_baselines+g992f756f4e4f.r6adf3140.kpb51197a.ndk26.3.11579264#1` | `023bbae5af28bf5d982aaaf880943c8f5ecf66014165538eb5d7e81c47bf7d69` |
| `re_kernel_x_1.6-20261008_baselines_debug.kpm` | `re_kernel_x-1.6-20261008_baselines_debug+g992f756f4e4f.r8e95c717.kpb51197a.ndk26.3.11579264#1` | `ade02e8bd50326d3d663d2360fe5ea7a5577ef7fd60e47d059551ef9c35f88f9` |
| `re_kernel_x_1.6-20261008_debug.kpm` | `re_kernel_x-1.6-20261008_debug+g992f756f4e4f.rf149fd1b.kpb51197a.ndk26.3.11579264#1` | `e6410674d21fd2c0cf96beac7c97414fed1c110e194c29e8b40587c36835fe5c` |
