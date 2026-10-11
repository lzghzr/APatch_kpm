# rek / rekx 共用静态偏移补丁工具

角色：Developer；日期：2026-10-10。当前为未冻结探索，实现方自检不作为独立审计或实机结论。

## 当前实现

仓库根目录 `patch_offsets.py` 供两个模块生成布局 JSON 和替换静态偏移表。两个项目各自维护 Makefile，均调用 `../patch_offsets.py` 并登记为构建额外输入。生成基线布局时读取 `re_kernel_x/re_offsets.c` 的字段顺序；替换和导出只需工具、KPM 与匹配的 JSON。模块 C 源码和偏移推导保持原有字节。

模块文档已更新，静态移植技能的路径更新建议附在 `Developer/proposals/2026-10-10-kpm-modes/maintainer.patch`，交由维护者接入。

## 验证

统一构建入口重新生成 8 份 KPM 和 4 份静态 JSON，与上一轮逐字节一致。双模式自检、原静态补丁/消息/清理 ASan 与 UBSan 自检通过；把工具、基线和 JSON 单独放入目录，替换成功且结果等于基线。已存在的归档与身份清单保持原哈希。regular 仓库门禁 16 项通过，`git diff --check` 与维护者补丁应用检查通过。私有证据为 `local/rek-patch-tool-c38sciqe/`。

测试入口 `test_static.py` 仅改工具路径；`test_modes.py` 仅改工具路径和回执输入列表。对照本轮修改前副本验证除此之外字节一致，断言和用例范围保持原样。

自查：are-you-sure（Retain）确认共用工具位置与两个独立构建入口相符，仅调整字段来源相对路径；no-negative-echo 回读当前工具、文档、清单与结果；respect-the-oracle 对照修改前测试入口，保留原断言。宿主验证覆盖路径迁移及现有测试行为，不增加设备结论。

## 探索身份

工具链 `ndk26.3.11579264`，目标 `all debug`，source_dirty=true。基础提交不包含本轮修改，正式交接须冻结后重建。

### re_kernel

清单：[re_kernel](handoffs/re_kernel-20261010-root-patch-tool-exploration.json)。source_commit：`7cb89e0c8c065443ac019f147c9bf4995f01db61`；KernelPatch commit：`b51197aaba8f2272dd8a3e30c85698a29aa928c9`；source_tree_sha256：`41c3405e09f69adadedd1a72df7aca44d7e6a7a95d14f6ea5a224e63c3649204`。

- dynamic：`re_kernel-11.7_dynamic+g41c3405e09f6.r49edae02.kpb51197a.ndk26.3.11579264#1`；SHA-256：`fb00ca982319b7e7487085781a09aea4e41da9a3af05b10145149be8565d6fe9`。
- dynamic_debug：`re_kernel-11.7_dynamic_debug+g41c3405e09f6.re92ec831.kpb51197a.ndk26.3.11579264#1`；SHA-256：`b1469dfd2f612f16189c337c103fbdd235aecf42a96acde783102790de38347c`。
- static：`re_kernel-11.7_static+g41c3405e09f6.ra4c31940.kpb51197a.ndk26.3.11579264#1`；SHA-256：`a54945f94f1fe7b8c11882204f15099681e2d8136f590e4394ef59a69a4b80ba`。
- static_debug：`re_kernel-11.7_static_debug+g41c3405e09f6.rf4314a92.kpb51197a.ndk26.3.11579264#1`；SHA-256：`3f3e70d7b73cd68317e7d1457446cf6603a47cd147c2999361e1ab437dfbca1b`。

### re_kernel_x

清单：[re_kernel_x](handoffs/re_kernel_x-20261010-root-patch-tool-exploration.json)。source_commit：`7cb89e0c8c065443ac019f147c9bf4995f01db61`；KernelPatch commit：`b51197aaba8f2272dd8a3e30c85698a29aa928c9`；source_tree_sha256：`a18817bade3246ef56d475f1490b4ee2a69c6e52622b2c01e909c1b808c11b3f`。

- dynamic：`re_kernel_x-1.6-20261008_dynamic+ga18817bade32.r9015346d.kpb51197a.ndk26.3.11579264#1`；SHA-256：`1fc76b126c5d81f14c4edeeef3cb662cd60494211cfbb405a81b926af8d97a45`。
- dynamic_debug：`re_kernel_x-1.6-20261008_dynamic_debug+ga18817bade32.r86f27e9c.kpb51197a.ndk26.3.11579264#1`；SHA-256：`e92c9f496ce497991e72f1664a7d6ee144e6a69719c8f33ff91dd07e4955923c`。
- static：`re_kernel_x-1.6-20261008_static+ga18817bade32.rbe5e2db6.kpb51197a.ndk26.3.11579264#1`；SHA-256：`87f62f34151d4bb38dc10fb2b287ff1f3e648f3e5eb043bc3881acf1aa177668`。
- static_debug：`re_kernel_x-1.6-20261008_static_debug+ga18817bade32.r6c8dfc86.kpb51197a.ndk26.3.11579264#1`；SHA-256：`94c61f455a2da621091f60804ae5ba731fe25ea98eb8c72dae9268e96df7b7dc`。

## 后续记录

当前产物名称与动态描述见 [命名记录](2026-10-10-rek-naming.md)。

后续偏移组织与公共 BTF 查询见 [本轮开发记录](2026-10-10-rek-shared-offsets.md)，最新探索身份以该记录列出的清单为准。
