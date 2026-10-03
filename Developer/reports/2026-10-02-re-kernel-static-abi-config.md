# Developer 记录：统一 Binder ABI 编译配置

角色 Developer；实现方探索自检，不是独立审计、冻结候选或真机结论。用户要求简化 ABI 标记并复用 REKERNEL_BINDER_ABI 进行交叉编译。

Makefile 现在仅保留 REKERNEL_BINDER_ABI，默认 6；通过 -DREKERNEL_BINDER_ABI=$(REKERNEL_BINDER_ABI) 传入编译器。源码直接按数字选择四种 Binder 签名，二进制 .rodata.re_abi 标记使用同一值；删除 CONFIG_KERNEL_* 与旧 KERNEL_ABI 构建变量。选择方式为 make -C re_kernel_static REKERNEL_BINDER_ABI=3 all debug，baselines 仍生成四 ABI release/debug。编号和产物命名保持；头文件要求编号在 3～6 内，沿用编译期拒绝无效配置，不新增运行时检查。

完整基础提交 `40d33aca895cc4778deb1925ec12e4a635b5612f`，source_dirty=true，实际输入指纹 `bf6061519a8cf9dc30951ac413db178945875c22fa0f1eea7ca02d5fbd77fc0e`；SDK KP 0.13.9 `b51197aaba8f2272dd8a3e30c85698a29aa928c9`，工具链 ndk26.3.11579264。统一入口 --target baselines --allow-dirty --no-archive --handoff，最终身份见 [探索清单](handoffs/2026-10-02-re-kernel-static-abi-config-exploration-02.json)。旧产物、两次中间探索清单和旧报告保留，未提交、签名或修改维护者元数据。

| 变体 | instance_id | SHA-256 |
| --- | --- | --- |
| abi3 | `re_kernel_static-8.0.0_abi3+gbf6061519a8c.raea7f03e.kpb51197a.ndk26.3.11579264#1` | `1e2ec204b41f6fd555784ac3000afa2f5df5ce480fadec55bc23d9ce5351e8e7` |
| abi3_debug | `re_kernel_static-8.0.0_abi3_debug+gbf6061519a8c.rc49fcc9d.kpb51197a.ndk26.3.11579264#1` | `70b1798cfd5e1e502be9f9594f3d4bf80c689c40a08e958ee8cf8cde408d6576` |
| abi4 | `re_kernel_static-8.0.0_abi4+gbf6061519a8c.rce6da9cc.kpb51197a.ndk26.3.11579264#1` | `8d8585ed504bef16e45464b46a0d4eaec8e47244f0c6a3d9e125214d1b7bf0a6` |
| abi4_debug | `re_kernel_static-8.0.0_abi4_debug+gbf6061519a8c.r198347f8.kpb51197a.ndk26.3.11579264#1` | `347574a92521ee7ec6f42d085b079d57001cc5990d2752489b7308b18aa48955` |
| abi5 | `re_kernel_static-8.0.0_abi5+gbf6061519a8c.r7a2fbc2d.kpb51197a.ndk26.3.11579264#1` | `a9bdb3aeb5b416399da8566d04353a3b5bf6876e96c7175b607f185e3263ad26` |
| abi5_debug | `re_kernel_static-8.0.0_abi5_debug+gbf6061519a8c.r47691806.kpb51197a.ndk26.3.11579264#1` | `538b592cb91c4168718c6b7c9ced03546a3563d44b5938a6874d38edc98cb499` |
| abi6 | `re_kernel_static-8.0.0_abi6+gbf6061519a8c.rfe7601e1.kpb51197a.ndk26.3.11579264#1` | `9330200ba7d0f35acb4e69b146c51c456b4ed9008fe3c3fc2d8431caeb8d3015` |
| abi6_debug | `re_kernel_static-8.0.0_abi6_debug+gbf6061519a8c.ra1e08f2f.kpb51197a.ndk26.3.11579264#1` | `797dfcd55a0735ae8d1d3b0921f340bac453eb80be6281e701764d78e4d58d48` |

八个最终 KPM 与上一轮 BY_DATA 登记产物逐字节相同，因此本轮没有改变模块行为或函数签名字节；补丁工具仍从相同段读取 ABI，偏移表仍是 43 项/86 字节。实际 ELF 的导出依赖、产物身份、副本以及 ARM64 FP/SIMD/SVE 检查通过。现有生产函数主机自检再次通过，测试替身同步使用数字宏，四 ABI 均覆盖；没有缩小检查或新增镜像推导。格式按 .clang-format，git diff --check 通过，编译警告仍来自既有 SDK。

过程证据在 local/static-abi-config-20261002-01/ 的 build-02.log、tests.log、identity-selfcheck.json 与 registered-02/。这是未冻结的实现方证据，不替代独立审计或设备加载。README 已更新构建参数。公共 task_uid 宏与静态版 task_uid 同名函数仍按既有 #undef 隔离；没有修改公共 kpm_utils.h。
