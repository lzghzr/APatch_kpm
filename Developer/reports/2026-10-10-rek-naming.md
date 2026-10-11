# rek / rekx 产物命名与动态描述

角色：Developer；日期：2026-10-10。当前为未冻结探索，实现方自检不作为独立审计或实机结论。

## 当前实现

动态普通版沿用 `<模块>_<版本>.kpm`，静态普通版为 `<模块>_<版本>_baselines.kpm`，debug 增加 `_debug`。模块管理名称保持 `re_kernel`、`re_kernel_x`，`offset_mode` 继续记录实际模式。两个项目在自己的 Makefile 中维护构建规则。

rekx 静态描述为 `ReKernel-X, every bit belongs to you.`，动态描述为 `ReKernel-X, Binder, signal and network wakeups.`。协议、业务代码、偏移计算与版本号沿用已有实现。

Actions、根目录规则、身份工具及产物门禁的对应变更在 `Developer/proposals/2026-10-10-kpm-modes/maintainer.patch`，由维护者接入。当前源码树中的维护者文件保持原样。

## 验证

统一构建入口生成 8 份新命名产物和 4 份静态 JSON。8 份 KPM 的 `.text` 与上轮一致，rek 的四份和 rekx 的两份静态 KPM 整体逐字节一致；rekx 的两份动态 KPM 更新描述元信息。逐份核对模块管理名、版本、模式、描述和配套 JSON。

双模式自检、静态补丁及生产消息/清理 ASan/UBSan 自检通过。在维护者补丁副本中，原产物门禁 37 项与发布筛选 4 项 Oracle 全部通过，两个 Oracle 文件保留原字节。新命名实际产物通过发布检查：Releases 包含 4 份普通 KPM 与 2 份静态 JSON，6 类拒绝例全部拒绝。代码修改区域符合 `.clang-format`，补丁应用检查和 `git diff --check` 通过。常规仓库门禁通过。

### 测试调整范围

`re_kernel/tools/test_modes.py` 仅按模式构造新产物名；`verify_modes.py` 的文件名检索与错配样本随新的命名契约更新。已有 assert 行逐条与本轮修改前副本一致，测试数量、通过/拒绝判据保持。原测试副本与逐项对照保存在私有目录，供 Auditor 独立复核。

归档、MANIFEST 和此前身份清单保持原哈希；新身份只追加。私有证据目录：`local/rek-names-mn5ih30f/`，包含构建日志、比较结果、Oracle 哈希、测试日志与发布回执。本轮为宿主自检，不增加内核语料或真机结论。

## 自查决定 (Decision)

**保留 (Retain)**

### 有效性

实际 8 份 ELF 产物符合新名称，发布回执及元信息核对支持本轮目标；模块管理名称与协议保持兼容。

### 简洁性

只调整文件名、模式对应描述及依赖它们的检索位置；共用偏移来源和各模块独立构建规则继续沿用。

### 后果

历史证据保留旧名称，新布局 JSON 记录当前 KPM 名称与哈希。发布工具必须采用随附补丁，当前常规门禁不能代替该补丁的发布验证。

自查同时应用 no-negative-echo 回读当前文件、文档与清单，respect-the-oracle 核对原断言及只读 Oracle。本轮决定保留此实现，交接前从冻结提交重建。

## 探索身份

工具链 `ndk26.3.11579264`，目标 `all debug`，source_dirty=true。基础提交不包含本轮修改，正式交接须冻结后重建。

### re_kernel

清单：[re_kernel](handoffs/re_kernel-20261010-naming-exploration.json)。source_commit：`7cb89e0c8c065443ac019f147c9bf4995f01db61`；KernelPatch commit：`b51197aaba8f2272dd8a3e30c85698a29aa928c9`；source_tree_sha256：`b2286fb122ee5024a2ee2891c51cb56e415a44f14fc0603e965ffb02038a45e6`。

- base：`re_kernel-11.7+gb2286fb122ee.rce440962.kpb51197a.ndk26.3.11579264#1`；SHA-256：`fb00ca982319b7e7487085781a09aea4e41da9a3af05b10145149be8565d6fe9`。
- baselines：`re_kernel-11.7_baselines+gb2286fb122ee.r1023904d.kpb51197a.ndk26.3.11579264#1`；SHA-256：`a54945f94f1fe7b8c11882204f15099681e2d8136f590e4394ef59a69a4b80ba`。
- baselines_debug：`re_kernel-11.7_baselines_debug+gb2286fb122ee.r7c690efd.kpb51197a.ndk26.3.11579264#1`；SHA-256：`3f3e70d7b73cd68317e7d1457446cf6603a47cd147c2999361e1ab437dfbca1b`。
- debug：`re_kernel-11.7_debug+gb2286fb122ee.rd320c5f7.kpb51197a.ndk26.3.11579264#1`；SHA-256：`b1469dfd2f612f16189c337c103fbdd235aecf42a96acde783102790de38347c`。

### re_kernel_x

清单：[re_kernel_x](handoffs/re_kernel_x-20261010-naming-exploration.json)。source_commit：`7cb89e0c8c065443ac019f147c9bf4995f01db61`；KernelPatch commit：`b51197aaba8f2272dd8a3e30c85698a29aa928c9`；source_tree_sha256：`5b322d87c8b571d7fd8543f809249fcfb97579c8ec4b088ff374a2703e323aac`。

- base：`re_kernel_x-1.6-20261008+g5b322d87c8b5.r24694ec1.kpb51197a.ndk26.3.11579264#1`；SHA-256：`ecc24e60dcfa424fa50be6568c7d9010780bca0978b69960f0313ebf5d85b9c4`。
- baselines：`re_kernel_x-1.6-20261008_baselines+g5b322d87c8b5.r30a3e1c3.kpb51197a.ndk26.3.11579264#1`；SHA-256：`87f62f34151d4bb38dc10fb2b287ff1f3e648f3e5eb043bc3881acf1aa177668`。
- baselines_debug：`re_kernel_x-1.6-20261008_baselines_debug+g5b322d87c8b5.r28229fa1.kpb51197a.ndk26.3.11579264#1`；SHA-256：`94c61f455a2da621091f60804ae5ba731fe25ea98eb8c72dae9268e96df7b7dc`。
- debug：`re_kernel_x-1.6-20261008_debug+g5b322d87c8b5.rc73dde6e.kpb51197a.ndk26.3.11579264#1`；SHA-256：`1be20fd9585093ba98984780f768fc71f92659bf9618403879a4961e46dd81ad`。

后续偏移组织与公共 BTF 查询见 [本轮开发记录](2026-10-10-rek-shared-offsets.md)，最新探索身份以该记录列出的清单为准。
