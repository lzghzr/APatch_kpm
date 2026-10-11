# rek / rekx 项目构建入口

角色：Developer；日期：2026-10-10。本轮为未冻结探索，实现方自检不作为独立审计或实机结论。

## 当前实现

rek 与 rekx 分别在各自 Makefile 中维护工具链、编译选项、四种产物、静态 JSON 生成与清理规则。`all` 生成 static / dynamic，`debug` 生成对应 debug 版，各模式可单独构建。产物命名、条件编译、输出目录及偏移配置契约沿用上一轮。

全项目规范统一模式名称和产物规则，各模块自行维护 Makefile；当前说明见 `Developer/README.md` 和 `re_kernel_x/AGENTS.md`。维护者补丁中的根目录规范也已同步，Actions 与产物门禁建议继续沿用原发布范围。

## 验证

通过统一构建入口重新生成两模块共 8 份 KPM。每份与上一轮对应产物 SHA-256 相同，4 份配套静态 JSON 也逐字节相同。因此上一轮离线和业务自检仍描述相同的 KPM 字节；本轮重新执行双模式产物与补丁自检，通过。内核 C 源码和偏移推导未改动。

`test_modes.py` 仅更新回执捕获的输入路径，改为记录两个 Makefile；所有断言字节保留。未改已有 Oracle。项目补丁可通过 `git apply --check`；`git diff --check` 与 regular 仓库门禁通过。原有 318 个归档文件、MANIFEST 和身份清单保持原哈希。每次编译保留既有 5 个 SDK 头文件警告。

自查使用 are-you-sure（Simplify：各项目直接维护构建规则）、no-negative-echo 和 respect-the-oracle。回读两个 Makefile、当前规范、补丁、回执和产物信息。真机、业务覆盖及卸载边界沿用上一轮报告，当前未新增设备结论。

私有证据目录：`local/rek-makefiles-opy8nc_8/`。`comparison.json` 保存 8 份 KPM 的字节一致性和资产保全；`layout-and-oracle.json` 保存 JSON 与断言核对；`modes/receipt.json` 为双模式自检；`repository.log` 为门禁结果。

## 探索身份

source_commit：`7cb89e0c8c065443ac019f147c9bf4995f01db61`；source_dirty=true。KernelPatch commit：`b51197aaba8f2272dd8a3e30c85698a29aa928c9`。工具链 `ndk26.3.11579264`，目标 `all debug`；共用源码另行捕获为额外输入。基础提交不包含本轮修改，正式交接须冻结后重新构建。

### re_kernel

清单：[re_kernel](handoffs/re_kernel-20261010-project-makefile-exploration.json)。source_tree_sha256：`26b90320b5ddbbf9c58b7df6100498d962d12a77957f04e2b8057cc929722e15`。

- dynamic：`re_kernel-11.7_dynamic+g26b90320b5dd.rda39b466.kpb51197a.ndk26.3.11579264#1`；SHA-256：`fb00ca982319b7e7487085781a09aea4e41da9a3af05b10145149be8565d6fe9`。
- dynamic_debug：`re_kernel-11.7_dynamic_debug+g26b90320b5dd.re65c4ea4.kpb51197a.ndk26.3.11579264#1`；SHA-256：`b1469dfd2f612f16189c337c103fbdd235aecf42a96acde783102790de38347c`。
- static：`re_kernel-11.7_static+g26b90320b5dd.r04cec4db.kpb51197a.ndk26.3.11579264#1`；SHA-256：`a54945f94f1fe7b8c11882204f15099681e2d8136f590e4394ef59a69a4b80ba`。
- static_debug：`re_kernel-11.7_static_debug+g26b90320b5dd.r45cb0f14.kpb51197a.ndk26.3.11579264#1`；SHA-256：`3f3e70d7b73cd68317e7d1457446cf6603a47cd147c2999361e1ab437dfbca1b`。

### re_kernel_x

清单：[re_kernel_x](handoffs/re_kernel_x-20261010-project-makefile-exploration.json)。source_tree_sha256：`4f55a14414fd6d0c5ea63c27a88b96eced515a98db0ec716148ad0fe8b62bdb3`。

- dynamic：`re_kernel_x-1.6-20261008_dynamic+g4f55a14414fd.rcb5028de.kpb51197a.ndk26.3.11579264#1`；SHA-256：`1fc76b126c5d81f14c4edeeef3cb662cd60494211cfbb405a81b926af8d97a45`。
- dynamic_debug：`re_kernel_x-1.6-20261008_dynamic_debug+g4f55a14414fd.r65efbfb3.kpb51197a.ndk26.3.11579264#1`；SHA-256：`e92c9f496ce497991e72f1664a7d6ee144e6a69719c8f33ff91dd07e4955923c`。
- static：`re_kernel_x-1.6-20261008_static+g4f55a14414fd.r748fd6da.kpb51197a.ndk26.3.11579264#1`；SHA-256：`87f62f34151d4bb38dc10fb2b287ff1f3e648f3e5eb043bc3881acf1aa177668`。
- static_debug：`re_kernel_x-1.6-20261008_static_debug+g4f55a14414fd.r208f27f1.kpb51197a.ndk26.3.11579264#1`；SHA-256：`94c61f455a2da621091f60804ae5ba731fe25ea98eb8c72dae9268e96df7b7dc`。


## 后续记录

共用补丁工具移至仓库根目录，当前入口及探索身份见 [补丁工具记录](2026-10-10-rek-patch-tool.md)。

## 项目内编译配方精简

两个模块的 Makefile 各保留一条四产物共用编译配方。`kpm` 保存本模块的输出前缀，`kpms` 列出四个目标；目标专属变量选择 `CONFIG_KPM_BASELINES`、`CONFIG_DEBUG` 和 debug 版本后缀，基线目标生成配套 JSON。现有目标、别名、输出名、头文件依赖及产物保护保留。每份 Makefile 从 83 行减到 70 行。

自检：精简前后 `all debug` 展开的命令逐字节一致；两个模块使用 `all debug -j4` 重新构建，8 份 KPM 与精简前对应产物逐字节一致，每个模块只生成两份基线 JSON。现有模式自检通过，测试文件与断言未变；构建输入、产物哈希及既有归档已核对。私有证据位于 `local/rek-mk-compact-y9dflqv_/`。

are-you-sure 复核决策为保留（Retain）：目标专属变量和共用配方足以表达四种产物，并行构建与字节比较验证参数一致。按 no-negative-echo 和 respect-the-oracle 读回 Makefile、记录和生成清单。上述结果属于 Developer 构建/宿主自检，不作为实机或独立审计结论。本轮未提交、未冻结。

源码基准提交：`7cb89e0c8c065443ac019f147c9bf4995f01db61`；当前为未提交工作树，构建标记 exploration。KernelPatch：`b51197aaba8f2272dd8a3e30c85698a29aa928c9`；工具链：NDK 26.3.11579264。

| 产物 | instance_id | SHA-256 |
| --- | --- | --- |
| `re_kernel_11.7.kpm` | `re_kernel-11.7+gba2d724e4efc.r1d07ee8b.kpb51197a.ndk26.3.11579264#1` | `72afa556eee88ac418efec8c0b22e455a88cdcb233fc3c9cdb8e4762830767d7` |
| `re_kernel_11.7_baselines.kpm` | `re_kernel-11.7_baselines+gba2d724e4efc.rbf3e07e1.kpb51197a.ndk26.3.11579264#1` | `a54945f94f1fe7b8c11882204f15099681e2d8136f590e4394ef59a69a4b80ba` |
| `re_kernel_11.7_baselines_debug.kpm` | `re_kernel-11.7_baselines_debug+gba2d724e4efc.r96e3fac5.kpb51197a.ndk26.3.11579264#1` | `3f3e70d7b73cd68317e7d1457446cf6603a47cd147c2999361e1ab437dfbca1b` |
| `re_kernel_11.7_debug.kpm` | `re_kernel-11.7_debug+gba2d724e4efc.r8ba22d87.kpb51197a.ndk26.3.11579264#1` | `49de7837b999b9f29e08fc0ec38254b1618bd547b17eaed34d7fafa3865962ce` |
| `re_kernel_x_1.6-20261008.kpm` | `re_kernel_x-1.6-20261008+gbd2b65aa980f.ra16a5fcd.kpb51197a.ndk26.3.11579264#1` | `edff9d8c00afb220f04e65aede455219e6b9d0c5a89c23783cecb49196097331` |
| `re_kernel_x_1.6-20261008_baselines.kpm` | `re_kernel_x-1.6-20261008_baselines+gbd2b65aa980f.rb5c99949.kpb51197a.ndk26.3.11579264#1` | `023bbae5af28bf5d982aaaf880943c8f5ecf66014165538eb5d7e81c47bf7d69` |
| `re_kernel_x_1.6-20261008_baselines_debug.kpm` | `re_kernel_x-1.6-20261008_baselines_debug+gbd2b65aa980f.r52bc0d3f.kpb51197a.ndk26.3.11579264#1` | `ade02e8bd50326d3d663d2360fe5ea7a5577ef7fd60e47d059551ef9c35f88f9` |
| `re_kernel_x_1.6-20261008_debug.kpm` | `re_kernel_x-1.6-20261008_debug+gbd2b65aa980f.reb12f1af.kpb51197a.ndk26.3.11579264#1` | `e6410674d21fd2c0cf96beac7c97414fed1c110e194c29e8b40587c36835fe5c` |

探索清单：[rek](handoffs/re_kernel-20261010-compact-make-exploration.json)、[rekx](handoffs/re_kernel_x-20261010-compact-make-exploration.json)。
