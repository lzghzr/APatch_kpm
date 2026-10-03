# Developer 记录：KP 查找依赖版本与运行基线

本轮按用户“按照用户会更新 KP 来判断”的要求恢复标准 SDK 查找。角色 Developer；探索自检，不是独立审计、冻结候选或真机结论。

## 身份

完整基础提交 `40d33aca895cc4778deb1925ec12e4a635b5612f`，`source_dirty=true`；实际构建输入指纹 `9b5257301bbcbd2102bd89a248d405dd26fceb5a08073616ea4a905f1966be45`。SDK 为 KP 0.13.9 `b51197aaba8f2272dd8a3e30c85698a29aa928c9`。未提交、未签名、未修改维护者元数据；旧清单与产物保留。完整登记见 [探索清单](handoffs/2026-10-02-re-kernel-static-kp-policy-exploration.json)。

| 变体 | instance_id | SHA-256 |
| --- | --- | --- |
| abi3 | `re_kernel_static-8.0.0_abi3+g9b5257301bbc.rd648c6ce.kpb51197a.ndk26.3.11579264#1` | `8ec3f616a482a9cf43e5a0edd8dce8b3b41c91f8d2a2302a0819286e40c8770e` |
| abi3_debug | `re_kernel_static-8.0.0_abi3_debug+g9b5257301bbc.r487c6549.kpb51197a.ndk26.3.11579264#1` | `b524675ac91abdae6c348e3e4c5e91977c4268aa490b5edc1999533ce287d9a6` |
| abi4 | `re_kernel_static-8.0.0_abi4+g9b5257301bbc.ra6b8a3fc.kpb51197a.ndk26.3.11579264#1` | `2624296f1f9fde38e33be28fea051cb1d8393b84e7894001df6f2a09f57f0b60` |
| abi4_debug | `re_kernel_static-8.0.0_abi4_debug+g9b5257301bbc.r44a27625.kpb51197a.ndk26.3.11579264#1` | `1a0266dfae7f061e99859e9e5429e5d9b72134317560fcb50a2a69bc927d00a2` |
| abi5 | `re_kernel_static-8.0.0_abi5+g9b5257301bbc.r67641684.kpb51197a.ndk26.3.11579264#1` | `13ce961721e2136609d8383ca240e96eb0afa12ac0af2154163ef37aa4502c58` |
| abi5_debug | `re_kernel_static-8.0.0_abi5_debug+g9b5257301bbc.rdae26ceb.kpb51197a.ndk26.3.11579264#1` | `47d883d0db216d63888aa233b805fedc5f6354121f7e51376418aa0d43ead65f` |
| abi6 | `re_kernel_static-8.0.0_abi6+g9b5257301bbc.r24b1c0ed.kpb51197a.ndk26.3.11579264#1` | `8b640219105f990715df268d0daf40c4302b80c4065539c3ea76674639e5e2b0` |
| abi6_debug | `re_kernel_static-8.0.0_abi6_debug+g9b5257301bbc.rd6d922cb.kpb51197a.ndk26.3.11579264#1` | `be39f1618537fbcefb585072ba901adb1654786cb0349201d89199e13113c304` |

## 版本核对

核对官方标签 0.13.3 至 0.13.9 的源码和导出。0.13.3、0.13.4、0.13.5 没有 kallsyms_lookup_name_by_suffix；0.13.6 首次包含并导出，0.13.7、0.13.8 也导出，但 kfunc_lookup_name/kvar_lookup_name 仍使用普通查找；0.13.9 两个宏默认使用后缀 helper。

首次加入提交为 [400e18a3493b7fa0925c611939affa072c5b689f](https://github.com/bmax121/KernelPatch/commit/400e18a3493b7fa0925c611939affa072c5b689f)，时间 2026-08-20。首个发布标签为 [0.13.6](https://github.com/bmax121/KernelPatch/releases/tag/0.13.6)，完整提交 d20e772e5dead621b30bec3be578cb58f74bc2ee。默认宏切换提交为 [72a904c412754e25f54353c30f31f5c884ed0673](https://github.com/bmax121/KernelPatch/commit/72a904c412754e25f54353c30f31f5c884ed0673)，时间 2026-09-02，首个包含它的发布标签为 0.13.9。访问日期 2026-10-02。

仅就该导出而言，运行端至少需要 KP 0.13.6；建议更新实际运行的 KP 核心至本轮构建所用 0.13.9。更新应用版本不自动证明实际运行的核心已更新。官方标签导出核对不等于设备二进制或全部运行 ABI 验证。

## 实现与断言调整

删除 re_utils.h 中临时覆盖 kfunc_lookup_name/kvar_lookup_name 的宏，使用 SDK 标准定义；没有新增模块后缀遍历器，没有修改 KP 子模块或公共 kpm_utils.h。模块原有普通 lookup_name hook 查找和可选 fixups 查找保留，不能据此声称所有符号都使用后缀 helper。必需内核符号仍在初始化检查；缺少 KP 导出会在进入初始化之前加载失败。README 已写明依赖与推荐版本。

真实 ELF 导入回归从“拒绝 suffix 导入以兼容 0.13.3”改为“要求 SDK 普通/后缀查找导入，仍拒绝 task_ext 依赖”。这是用户调整支持基线后的断言语义变更，0.13.3 加载兼容不再是本轮判据；其余 ELF、偏移替换、协议、Genl、异步清理断言保持。没有以放宽其它安全检查来获得通过。

## 自检与边界

统一入口 build_candidate.py 使用 --allow-dirty --no-archive --target baselines --handoff，产生八个 ABI 3/4/5/6 release/debug 探索实例；构建事务验证输入未变。八个登记 ELF 与先前测试字节一致，逐个 SHA 与清单相符。实际 ELF 的全部 17 项导入均能在官方 KP 0.13.6 和 0.13.9 标签源码导出表找到；这只是静态导出证据。43 项、86 字节偏移表保持，实际 ARM64 指令无 FP/SIMD/SVE。

持久 test_static.py 的真实 ELF 替换与导入、协议边界、Binder 上下文、Genl 收发与生命周期、四 ABI 清理 ASan/UBSan 主机自检均通过；既有 SDK 编译警告保留。源码格式与 diff 检查通过。原始证据位于 local/static-kp-policy-20261002-01/ 的 build.log、tests.log、kp-history.json、kp-imports.json、identity-selfcheck.json 与 registered-build.log。

本轮不改变目标偏移或冻结判断，不下载整份内核源码，不执行设备操作。ABI 基准不能直接视为已完成 B2N 目标偏移验证。DEV-003 的旧 KP 加载事实仍成立，政策响应另附；DEV-004 的 CFI jump table 匹配观察仍未解决，不声称更新 KP 即修复它。Developer 不关闭问题单。
