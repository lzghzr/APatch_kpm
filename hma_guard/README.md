# HMA Guard 实现笔记

HMA Guard 是配合 **HMA-OSS** 使用的自用 KPM：应用列表过滤仍由 HMA-OSS 负责，内核侧补齐 UID 枚举防护与 SELinux 查询视图。

参考与移植的实现全部来自开源项目（KernelPatch、KernelSU、SUSFS、selinux_maf_fork、fgetpriority、Linux SELinux、AOSP、HMA-OSS），不含任何闭源组件。这些上游的许可证互不兼容——GPL-2.0-only 与 GPL-3.0／Apache-2.0 不能合并，HMA-OSS 为 AGPL-3.0——因此模块仅供自用，不发布源码或产物。这里分享实现思路和排查经验。

- [实现笔记](DESIGN_NOTES.md)：策略来源、原生语义、生命周期与差分计时。
- [参考资料](SOURCES.md)：采用的上游版本和相关实现。
