# Developer 记录：KP 0.13.3 查找依赖与冻结判断

本轮只修复 B2N 日志暴露的加载依赖，不修改冻结语义或目标偏移。角色 Developer；探索自检，不是冻结候选、独立审计或真机结论。

## 身份

完整基础提交 `40d33aca895cc4778deb1925ec12e4a635b5612f`，`source_dirty=true`；实际模块输入指纹 `29ed505733930b2de6aa3a5fc0697cca71538d167db0011f7ff22f9997019e1a`。构建 SDK 为 KP 0.13.9 `b51197aaba8f2272dd8a3e30c85698a29aa928c9`；用户确认设备 KP 为 0.13.3，官方源码标签完整提交 `043c0c3bae68ddc6f2894b4e483d8f54cb85d112`。设备实际 KP 二进制哈希未提供，不能认为只凭版本号就与该标签字节相同。

完整实例与产物身份见 [探索清单](handoffs/2026-10-02-re-kernel-static-kp-lookup-exploration.json)；八个登记 KPM 与自检基准逐字节一致，旧产物保留，未签名、未修改维护者元数据。

| 变体 | instance_id | SHA-256 |
| --- | --- | --- |
| abi3 | `re_kernel_static-8.0.0_abi3+g29ed50573393.r83403adb.kpb51197a.ndk26.3.11579264#1` | `6a2e6c68645aa825dd7b81b0f9cfe373045321716aaf8d6763c6d49b9b73fd68` |
| abi3_debug | `re_kernel_static-8.0.0_abi3_debug+g29ed50573393.r81a8650c.kpb51197a.ndk26.3.11579264#1` | `7e3ac10cfd6eb925774759cbe6b08af13ec50bb488c37443bf2ddd52ce95a8f7` |
| abi4 | `re_kernel_static-8.0.0_abi4+g29ed50573393.r72ffd4af.kpb51197a.ndk26.3.11579264#1` | `f42256a58b1eb1b12c226b3f78f2fa2b7a09f0f32342495fdbe7d177f8234204` |
| abi4_debug | `re_kernel_static-8.0.0_abi4_debug+g29ed50573393.r84bfee94.kpb51197a.ndk26.3.11579264#1` | `4872cdc27b1dc4b6c07f97baa8efb3efa3f9e3a38e13f3bddc9b31bd680cac2d` |
| abi5 | `re_kernel_static-8.0.0_abi5+g29ed50573393.r2725af2e.kpb51197a.ndk26.3.11579264#1` | `b4fdd3fb32b3a632edc5626924222b816530c1c1f5add48ba0829f5661357e46` |
| abi5_debug | `re_kernel_static-8.0.0_abi5_debug+g29ed50573393.r48f1ac25.kpb51197a.ndk26.3.11579264#1` | `51264614afc66f5a19da9e30eb293d51ab9ea6b92ee0dc809fd1533f86bff1b4` |
| abi6 | `re_kernel_static-8.0.0_abi6+g29ed50573393.r7ee891c8.kpb51197a.ndk26.3.11579264#1` | `21f5bb24772c8589d3c3725a8f51e7ea4cd4997969337cb344913d7869773037` |
| abi6_debug | `re_kernel_static-8.0.0_abi6_debug+g29ed50573393.r0227f228.kpb51197a.ndk26.3.11579264#1` | `b413253d8be7a442b3478404ff5892e4ea14fbea1115afbe6d94004b3e142ccd` |

## DEV-003（中，Developer）：旧 KP 无法解析 suffix 查找导入

- 证据：用户 B2N 日志在重定位阶段出现 `unknown symbol: kallsyms_lookup_name_by_suffix`，尚未进入模块初始化。用户确认 KP 0.13.3。其官方头文件 kfunc/kvar_lookup_name 使用普通 kallsyms_lookup_name，未导出 suffix helper；本地 0.13.9 头文件使用并导出 helper。原八个静态基准 ELF 都导入该函数。原 abi3 身份：基础提交 `40d33aca895cc4778deb1925ec12e4a635b5612f`，实例 `re_kernel_static-8.0.0_abi3+g25fe94e00b5d.r492c7065.kpb51197a.ndk26.3.11579264#1`，SHA-256 `8ec3f616a482a9cf43e5a0edd8dce8b3b41c91f8d2a2302a0819286e40c8770e`。设备上传 KPM 的完整 SHA 未提供，不声称已将设备字节绑定到此实例。
- 影响：在这类旧 KP 构建上模块加载失败，属于跨 KP 构建兼容缺口；不是 Binder 释放 ABI 选择或冻结逻辑执行失败。
- frequency：高频（缺少导出时每次加载都会失败）；confidence：已确认（设备错误及旧/新标签源码、实际 ELF 导入一致）。
- 修复：模块 re_utils.h 局部覆盖 kfunc/kvar_lookup_name，使用普通 kallsyms_lookup_name；仍保留初始化必需符号检查和双注册入口选择，不修改共享 SDK。当前上表全部实例已删除该导入；状态 fixed(待复核)，Developer 不关闭。
- 关闭条件：独立角色检查实际 ELF 与 KP 0.13.3 导出约定，Tester/维护者将目标 B2N 偏移绑定到新身份后验证设备加载，另确认后缀-only 镜像的能力边界。维护者负责元数据登记。

## 自检与范围

八变体真实 ELF 不再导入 suffix helper 或 get_task_ext；其余 16 个导入均在 KP 0.13.3 官方导出源码表内。按旧标签重解析导出，并检查实际 LLVM nm 输出；没有把本地 0.13.9 的导出表当作旧 KP 兼容证据。hook.h/ktypes.h 标签对比没有所用 API 签名改变；hook.h 的 TRANSIT_INST_NUM 存储常量改变仍不代表设备 hook 行为已验证。

新增持久回归从真实 ELF 符号表解析未定义导入，拒绝 suffix helper/task_ext 依赖。对原八个 ELF 的反例检查可检出 suffix 导入，对新八个检查无该项；43 项、86 字节偏移表逐字节相同。实际 ARM64 指令检查无 FP/SIMD/SVE。四 ABI 生产清理和既有协议/Genl 的 ASan/UBSan 主机自检继续通过；既有 SDK 五条编译警告未改变。源码格式及 diff 检查通过。

只读取现有 B2N-416G_boot.img 对应的 `4.4.192-perf+` 已提取符号和反汇编，不运行其它镜像。该镜像所需原名全部可查到；缺少 genl_register_family 时使用 __genl_register_family，缺少 kmalloc 时使用 __kmalloc。binder_free_txn_fixups 缺失是已设计的可选路径。既有释放函数反汇编支持 abi3；这不证明整个静态偏移表适配完毕。

本轮新产物是修复导入的 ABI 基准，偏移与旧基准相同，仍需使用目标 B2N 已验证配置。日志只提供段尺寸，无法读出设备实际偏移表，因此未凭日志合成目标补丁。新产物尚未在设备加载，未测冻结、解冻响应或卸载。复现与导出/指令证据在 `local/static-kp-lookup-20261002-01/`。统一留痕入口采用 --allow-dirty --no-archive --target baselines --handoff。

## 后缀名称与 CFI

KP 0.13.9 helper 先完整原名查找，缺失且 cfi_bypass 启用、可遍历符号时再匹配原名后以 . 或 $ 开始的编译器后缀。普通原名查找不会自动拼接 $哈希.cfi_jt。完整指定符号名可以按该名字查找，但返回跳板还是函数体必须按镜像确认。用户提供的全零文本地址不代表内核内查找为零；可能是地址隐藏，此文本不能直接作为真实地址来源。

初始解读依据代码注释误认为 .cfi_jt 会被过滤。抽取实际 suffix 谓词进行 ASan/UBSan 试验否证了该解读：cfi 后的边界只接受字符串结束、. 或 $，没有下划线，故 .cfi_jt 未被排除。失败断言、修正后的观察程序及输出均保留；修正的是对第三方行为的解读，没有放宽模块产品测试。细节另见 DEV-004。

当前修复按原名查找，只声明 B2N 本次必需入口原名可用；没有声称支持仅存在带后缀名称的所有 CFI 内核，也没有新增符号枚举回调或修改 KP 核心。若后续需要该能力，必须区分实际实现与 CFI 跳板，并解决枚举 ABI/CFI 回调约束。

## 冻结判断

只下载当前上游提交标识和 1163 字节单文件，未克隆源码。最新读取的 ReKernel-X 提交 `8c217319d7d73c40667650a43a485e9f185e3a92`，[rkx_frozen.c](https://github.com/myflavor/ReKernel-X/blob/8c217319d7d73c40667650a43a485e9f185e3a92/LKM-Source/rkx_frozen.c) 组合 cgroup_task_frozen、旧内核 cgroup_task_freeze/较新 jobctl，以及 group_leader 的 frozen()/TASK_FROZEN 或 freezing()。

静态版目前是 jobctl_frozen(task) || cgroup_freezing(task)，沿用模块已有方案。上游组合更多冻结来源，但不是一种全新判断机制，也不证明对于主要 cgroup 冻结场景性能或语义更优。当前没有设备证据要求替换，故本轮保持；同时不将现有判断称为所有内核/冻结方式下“最优”，JOBCTL 位语义和目标偏移仍应由实际镜像核对。
