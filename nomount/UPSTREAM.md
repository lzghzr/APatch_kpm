# 原版源码基线

- 仓库：<https://github.com/maxsteeel/nomount>
- 完整提交：`7046c7ad3ee0bf4ae66e80f6b93b1e30db0cb4e3`
- 上游元模块版本：`v2.1.1`。
- 上游内核版本标记：`NOMOUNT_BASE_VERSION = 21`。
- 内核实现：[`kernel/src/nomount.c`](https://github.com/maxsteeel/nomount/blob/7046c7ad3ee0bf4ae66e80f6b93b1e30db0cb4e3/kernel/src/nomount.c) 与 [`kernel/src/nomount.h`](https://github.com/maxsteeel/nomount/blob/7046c7ad3ee0bf4ae66e80f6b93b1e30db0cb4e3/kernel/src/nomount.h)。
- 用户态工具和元模块使用同一提交，控制协议与内核端一起核对。KPM业务实现单独维护，管理索引保留独立规则及进程上下文退役；inode持有独立path和目录节点。小对象优先原生slab分配，目录缓存按绑定及属性核对。

上游 README 声明 `kernel/` 为 GPL-2，其余部分为 GPL-3；根目录保留上游 LICENSE。移植文件保留来源与适用许可证。

KPM 的内核实现整体沿用 GPL-2.0-only；线协议取自 GPL-2 的 `kernel/src/nomount.h`。公共辅助代码中 GPL-2.0-or-later 的部分在本 KPM 中按 GPL-2 使用。许可证全文见 [上游内核许可证](nomount/kernel/LICENSE)。

配套 ZIP 的用户态工具、脚本与 WebUI 沿用 GPL-3.0-only，包内附完整许可证、原版用户态源码及编译脚本。KPM 与 ZIP 分开构建，通过 keyring 系统调用通信；GPL-3 用户态实现不链接进 KPM。

原作者：maxsteeel。KPM 移植与配套改造：Codex（OpenAI，AI 开发贡献）。上游其他贡献者的署名保留；配套修改范围和日期见 [来源说明](module/NOTICE.md)。

Git 子模块位于 `nomount/nomount`，由父仓库 gitlink 冻结上述提交。接入建议见 [补丁](../Developer/proposals/2026-10-12-nomount-upstream/submodule.patch)。
