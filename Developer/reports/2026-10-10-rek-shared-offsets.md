# rek / rekx 偏移组织与公共 BTF 查询

本轮角色为 Developer。当前源码基于 `7cb89e0c8c065443ac019f147c9bf4995f01db61` 的未提交工作树，构建标为 `exploration`。下列身份由本轮构建清单绑定，不能作为冻结候选交接。这是实现方自检记录，独立审计与实机结果由对应角色出具。

## 当前实现

- rekx 自行维护 BTF 字段清单、旧内核推导与 Makefile，源码不依赖 rek。动态推导合入 `re_offsets.c`，同一配置表和访问入口供两种模式使用。
- `CONFIG_KPM_BASELINES` 选择静态基线；未定义时为动态模式。动态产物使用原名，静态产物使用 `_baselines` 后缀，debug 增加 `_debug`。两种 rekx 描述均为 `ReKernel-X, Binder, signal and network wakeups.`。
- `kpm_utils.h` 提供 `kpm_btf_type/member/offset/enum`：类型查询、嵌套及匿名成员解析、成员字节偏移和枚举值查询。调用方先取得有效 BTF 和原生查询函数，再填写 `struct kpm_btf`；查询结果通过 `struct kpm_btf_field` 返回偏移、位域宽度和类型尺寸。
- 每个模块的 `re_btf.c` 保留原生函数查找、自己的字段清单、共同布局核对和 Binder 释放 ABI 判定。公共查询使用四个回调，不增加其他模块的原生符号导入。`int16_t` 配置表的范围限制留在写入处，包含可选 `binder_buffer.data`。
- 公共 BTF 定义置于指令宏区域之前，现有任务与指令宏保持字节一致。run_cmd 的共同 BTF 记录使用同一类型 guard。

## 自检

1. NDK 26.3.11579264 构建 rek/rekx 两种模式及各自 debug，共 8 份 KPM；源输入前后哈希一致，产物与清单哈希一致。检查全部 ELF 未定义符号，无新增裸字符串/内存函数或 BTF 原生函数导入。
2. 删除 rek 目录的隔离副本可构建 rekx 四种产物，KPM 和静态 JSON 与正常构建逐字节一致。
3. BTF 宿主自检覆盖两个模块的字段、匿名与嵌套成员、位域、共同布局及原生错误返回。模式自检验证 8 份 KPM、动态初始表和静态四种 Binder ABI 替换边界。
4. 现有 Genl/指令/清理宿主自检与静态补丁、消息协议、授权和清理自检通过；run_cmd 的宿主控制与偏移自检通过。此处使用合成指令及 Mock，不作为新镜像兼容结果。
5. 在共享头文件修改前后分别构建 run_cmd 和 cgroupv2_freeze 的普通/debug，4 份对应 KPM 逐字节一致。
6. 维护者补丁副本用当前 8 份产物验证发布范围：4 份普通 KPM、2 份静态 JSON，6 个拒绝例通过。补丁建议见 `Developer/proposals/2026-10-10-kpm-modes/`；仓库 Actions/共享门禁由维护者接入。
7. 常规仓库门禁 16 项通过；本轮之前的 372 个归档产物、清单与交接文件哈希未变。

测试入口因文件合并、命名和公共 API 变更调整源码提取与输入路径；已有 BTF、模式和偏移自检的断言行保持一致。静态宿主编译显式选择 `CONFIG_KPM_BASELINES`。没有缩小断言或覆盖范围。按 are-you-sure、no-negative-echo、respect-the-oracle 完成代码、说明及实际生成清单的读回自查。

本轮仅进行构建与宿主自检，未读取替换后的镜像语料、未操作设备，未提交或冻结。当前产物需后续冻结重建后交由 Auditor/Tester 绑定身份复核。

## 构建身份

KernelPatch：`b51197aaba8f2272dd8a3e30c85698a29aa928c9`。完整源码基准提交与 exploration 边界见本文开头；清单同时保存源树指纹及配方指纹。

| 产物 | instance_id | SHA-256 |
| --- | --- | --- |
| `re_kernel_11.7.kpm` | `re_kernel-11.7+g25945b394809.ra245a9c4.kpb51197a.ndk26.3.11579264#1` | `72afa556eee88ac418efec8c0b22e455a88cdcb233fc3c9cdb8e4762830767d7` |
| `re_kernel_11.7_baselines.kpm` | `re_kernel-11.7_baselines+g25945b394809.r9b54ab53.kpb51197a.ndk26.3.11579264#1` | `a54945f94f1fe7b8c11882204f15099681e2d8136f590e4394ef59a69a4b80ba` |
| `re_kernel_11.7_baselines_debug.kpm` | `re_kernel-11.7_baselines_debug+g25945b394809.rbc079d11.kpb51197a.ndk26.3.11579264#1` | `3f3e70d7b73cd68317e7d1457446cf6603a47cd147c2999361e1ab437dfbca1b` |
| `re_kernel_11.7_debug.kpm` | `re_kernel-11.7_debug+g25945b394809.r841890f3.kpb51197a.ndk26.3.11579264#1` | `49de7837b999b9f29e08fc0ec38254b1618bd547b17eaed34d7fafa3865962ce` |
| `re_kernel_x_1.6-20261008.kpm` | `re_kernel_x-1.6-20261008+g91b86fd6a962.ree3710b1.kpb51197a.ndk26.3.11579264#1` | `edff9d8c00afb220f04e65aede455219e6b9d0c5a89c23783cecb49196097331` |
| `re_kernel_x_1.6-20261008_baselines.kpm` | `re_kernel_x-1.6-20261008_baselines+g91b86fd6a962.r026507d5.kpb51197a.ndk26.3.11579264#1` | `023bbae5af28bf5d982aaaf880943c8f5ecf66014165538eb5d7e81c47bf7d69` |
| `re_kernel_x_1.6-20261008_baselines_debug.kpm` | `re_kernel_x-1.6-20261008_baselines_debug+g91b86fd6a962.r54df822f.kpb51197a.ndk26.3.11579264#1` | `ade02e8bd50326d3d663d2360fe5ea7a5577ef7fd60e47d059551ef9c35f88f9` |
| `re_kernel_x_1.6-20261008_debug.kpm` | `re_kernel_x-1.6-20261008_debug+g91b86fd6a962.r18f946c7.kpb51197a.ndk26.3.11579264#1` | `e6410674d21fd2c0cf96beac7c97414fed1c110e194c29e8b40587c36835fe5c` |

清单：

- [rek 本轮探索身份](handoffs/re_kernel-20261010-common-btf-exploration.json)
- [rekx 本轮探索身份](handoffs/re_kernel_x-20261010-common-btf-exploration.json)

私有原始自检证据保存在 `local/rekx-independent-86ccf3xv/`，包括 `btf-common-final/`、`modes-common/`、`genl-common/`、`run-cmd-common/`、`static-common-final.log`、`standalone-common/`、`shared-consumers-before/after`、`release-common/` 和 `common-imports.json`。

后续文件职责整理与共用实现核对见 [开发记录](2026-10-10-rek-headers.md)，最新探索身份以该记录清单为准。
