# 参考资料

HMA Guard 实现作者：**Astra**。以下列出本地研究采用的固定版本，便于定位原始设计；许可证按该固定版本记录。

| 来源 | 参考内容 | 许可（固定版本） |
| --- | --- | --- |
| [fgetpriority · e0aaedb956cc](https://github.com/aerath-stuff/fgetpriority/tree/e0aaedb956ccee7b1a584638253b24786527f49b) | UID 与 seccomp 范围判定 | GPL-2.0 |
| [KernelPatch · b51197aaba8f](https://github.com/bmax121/KernelPatch/tree/b51197aaba8f2272dd8a3e30c85698a29aa928c9) | KPM SDK、hook 与 SELinux 策略查询 | GPL-2.0 |
| [KernelSU · dbb73665d103](https://github.com/tiann/KernelSU/blob/dbb73665d103da40c7ecbd21ba3b5ac76eb95784/kernel/feature/selinux_hide.c) | 独立策略副本、直接查询与 SID 同步 | GPL-3.0（仓库 `LICENSE`；所引内核文件无独立声明） |
| [selinux_maf_fork · 3110d1e3afb4](https://github.com/741afb7/selinux_maf_fork/blob/3110d1e3afb4afd6fe79b96eb635be5db7db9f3b/selinux_hook/selinux_hook.c) | 状态页工厂、文件输入与早期策略捕获 | GPL-3.0 |
| [SUSFS · 395a8c0c88d3](https://gitlab.com/simonpunk/susfs4ksu/-/blob/395a8c0c88d348e9fe7c14f66a456fde4653287c/kernel_patches/50_add_susfs_in_gki-android16-6.12.patch) | LSM wrapper 入口组织 | GPL-3.0 |
| [Linux SELinux · v6.12](https://github.com/torvalds/linux/tree/v6.12/security/selinux) | 原生策略事务、context、AVD 与状态页语义 | GPL-2.0 |
| [AOSP init · 68be0c2c0006](https://android.googlesource.com/platform/system/core/+/68be0c2c0006a0740d0b1809abe4717308f90d15/init/selinux.cpp) | split-policy 的输入选择与编译流程 | Apache-2.0 |
| [AOSP libgenfslabelsversion · 265f36ce0d43](https://android.googlesource.com/platform/system/sepolicy/+/265f36ce0d43ef13bb8676e08de5f27050339652/compat/libgenfslabelsversion/src/lib.rs) | genfs 版本来源与解析 | Apache-2.0 |
| [HMA-OSS #175](https://github.com/frknkrc44/HMA-OSS/issues/175) | 应用列表过滤与内核侧补齐的分工 | AGPL-3.0（仓库） |

## 记录口径

- 许可证按**所示固定版本**记录；引用具体文件时以该版本的文件头或就近声明为准（文件级优先于仓库级）。KernelSU 行为仓库级许可（所引内核文件无独立声明），HMA-OSS 行只引用议题而非文件。
- 这些上游的许可证能否合并、以及本模块为何不发布，见 [README](README.md)。
