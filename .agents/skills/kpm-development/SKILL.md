---
name: kpm-development
description: 开发、构建和排查 Android ARM64 KernelPatch 模块（KPM），支持运行时动态推导与离线静态偏移，涵盖生命周期、内核符号调用、函数与 syscall hook、调用上下文和加载错误。动态偏移推导使用 kernel-offset-derivation；静态基准及二进制替换使用 kpm-static-binary-port。
argument-hint: 描述要开发的 KPM 功能、目标内核或实际错误日志
---

# KPM 开发与排错

KPM 是由 KernelPatch 加载到内核空间的 ARM64 可重定位 ELF，不使用普通 LKM 的 `.ko` 构建流程。通常不需要完整内核源码树，但必须核对实际 KP SDK、运行端导出、目标内核函数 ABI 与布局。

进入仓库后先读根目录及模块内 `AGENTS.md`，确认当前角色与路径所有权。新增说明优先用中文，C 标识符沿用模块风格，缩进遵循 `.clang-format`。用户说明放 README，实现约定放模块 AGENTS；独立审计与真机结论引用对应角色的报告。

## 先确定工作方式

本文提供静态、动态模块共用的开发基础。偏移策略按用户需求与模块既有实现选择；提供 img 也可以用于动态算法的离线验证，不自动视为静态移植。

- 动态适配：希望同一产物在加载时取得目标布局，使用 [动态偏移推导](../kernel-offset-derivation/SKILL.md)，复用 KP 已初始化的布局信息或从内核函数数据流推导私有字段。
- 静态适配：先离线分析目标 img，固定布局后构建或替换数据表，使用 [静态二进制移植](../kpm-static-binary-port/SKILL.md)。已有匹配基准时可直接下载并替换，用户侧无需 NDK 或 KP SDK。
- 开发新功能：两种方式均可修改源码并构建候选。动态推导可参考 [re_kernel](../../../re_kernel/re_kernel.c) 的初始化流程；静态实现参考 [re_kernel_x 开发说明](../../../re_kernel_x/AGENTS.md) 与 [Makefile](../../../re_kernel_x/Makefile)。示例模块中的旧接口仍需按当前 SDK 核对。

## 结构体偏移策略

| 方式 | 偏移取得时机 | 验证重点 |
| --- | --- | --- |
| 动态 | 加载时复用 SDK 布局或从运行内核推导 | 算法、扫描边界、初始化结果及失败降级 |
| 静态 | 移植阶段从目标头文件/BTF或镜像分析 | 字段依据、目标配置、实际 ABI 与补丁字节范围 |

这里的静态、动态指布局偏移的取得方式，运行时内核符号查找适用于两者。同一模块也可按字段组合：复用已确认的共同定义，对变化字段采用固定配置或动态推导。

动态模块先解析锚点、推导并核对所需字段，再启用依赖这些字段的 hook。扫描设定范围，处理 CFI 跳板、寄存器数据流和厂商布局变化；推导结果缓存供业务访问，避免每次事件重新扫描。偏移 0 可能合法，未初始化、字段不存在和推导失败要有明确状态，不能统一按 `offset > 0` 判断。

动态提取逻辑与离线 harness 保持一致，在用户选定的镜像上逐字段交叉验证，并核对运行时输出。静态模块核对完整配置表；复用已确认的共同布局，只为变化字段配置偏移。两种方式都不能按版本号猜偏移；函数 ABI 无法共用时据实际签名选择调用方式。困难旧内核允许现场分析，无法确认的字段停止相关功能或初始化失败。

## 源码组织与公共宏

典型模块包含 Makefile、入口 `.c`、自身定义 `.h`，必要时另放偏移推导或配置以及内核调用封装。公共宏在 [kpm_utils.h](../../../kpm_utils.h)，其中的指令解码可用于动态推导。本仓库静态模块 `re_kernel_x` 的约定为：模块定义放 `re_kernel.h`，核对过的内核定义放 `re_structs.h`，KP 风格封装放 `re_utils.h`；其它模块沿用自身组织方式。

使用公共宏前读它的实现：`lookup_name` 查原名，失败直接返回；`hook_func` 失败直接返回，不负责撤销此前安装的 hook。`unhook_func` 调用的是 `unhook`，不能直接当成只删除本模块 wrap 回调的接口。新增实现优先用配对的 wrap/unwrap 并记录安装状态。

`task_uid`、`task_euid` 等公共宏读取 SDK 的 cred 偏移，返回 `kuid_t`，取数字时使用 `.val`；SDK 的布局信息不覆盖所有内核私有结构，也不代替对象生命周期保护。遇到宏冲突先核对包含链，不随意删除公共定义。

## 生命周期与最小入口

实际签名见 [kpmodule.h](../../../KernelPatch/kernel/include/kpmodule.h)。当前加载器要求 init 和 exit；ctl0、ctl1、event 按功能选择。元信息长度限制包含字符串终止符，模块名用于管理命令且须唯一。

```c
#include <kpmodule.h>
#include <kputils.h>
#include <linux/errno.h>
#include <linux/printk.h>

KPM_NAME("example");
KPM_VERSION("1.0.0");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("author");
KPM_DESCRIPTION("示例模块");

static long example_init(const char* args, const char* event, void* reserved) {
  pr_info("example: init, event=%s\n", event ? event : "");
  return 0;
}

static long example_ctl0(const char* args, char __user* out_msg, int outlen) {
  static const char reply[] = "pong";
  if (!out_msg || outlen < (int)sizeof(reply))
    return -EINVAL;
  int copied = compat_copy_to_user(out_msg, reply, sizeof(reply));
  return copied == sizeof(reply) ? 0 : -EFAULT;
}

static long example_exit(void* reserved) { return 0; }

KPM_INIT(example_init);
KPM_CTL0(example_ctl0);
KPM_EXIT(example_exit);
```

init 先解析和核对必需依赖，再安装 hook 或注册对象。记录成功安装的资源，失败按逆序撤销。当前加载器在 init 失败后还会调用 exit，因此清理需能处理部分初始化与已撤销的状态；不要仅依赖退出回调弥补所有失败路径。

## 三种符号来源

| 来源 | 使用方式 | 核对内容 |
| --- | --- | --- |
| KP 导出 | ELF 未定义导入，由模块加载器解析 | 运行端实际导出表是否包含该名字 |
| SDK kfunc/kvar | SDK 已提供的 `kf_*` 函数指针或 `kv_*` 数据指针 | 指针是否已初始化、函数签名和对象是否有效 |
| 模块自行查找 | `kallsyms_lookup_name` 或 SDK 后缀查找接口 | 目标符号实际名称、返回地址及调用 ABI |

`kfunc_def(name)` 展开成 `(*kf_name)`；它声明函数指针，不会因为写了声明就自动解析任意内核函数。SDK 提供并导出的指针可复用；模块自有指针要显式初始化，例如：

```c
#include <ksyms.h>
#include <linux/errno.h>

static int kfunc_def(target_function)(int value);

static long resolve_target(void) {
  kfunc_lookup_name(target_function);
  if (!kfunc(target_function))
    return -ENOENT;
  return 0;
}
```

声明的参数与返回值必须来自目标证据。函数和数据符号均需核对；`KALLSYMS_ALL=n` 的数据对象缺失不能靠函数后缀查找补齐，也不能向内核注册函数传入尚未解析的对象。

当前 [ksyms.h](../../../KernelPatch/kernel/patch/include/ksyms.h) 的 `kfunc_lookup_name` / `kvar_lookup_name` 使用 `kallsyms_lookup_name_by_suffix`。其实现先查原名，后缀扫描还有运行端条件，不能保证所有 CFI 名称都能取得。区分 `$hash` 函数体与 `.cfi_jt` 跳板，核对实际地址和 hook 入口。旧 KP 缺少该导出时会在模块 init 之前报 unknown symbol；不能把延迟查找当作兼容旧导出的办法。

## 函数与 syscall hook

函数 hook 优先使用 [hook.h](../../../KernelPatch/kernel/include/hook.h) 的 `hook_wrap` / `hook_wrapN`，只解除本模块注册的回调：

```c
#include <hook.h>
#include <linux/errno.h>

static void* target;
static int target_hooked;

static void before_target(hook_fargs3_t* args, void* udata) { args->local.data0 = args->arg0; }

static void after_target(hook_fargs3_t* args, void* udata) { /* local 属于本次调用，可把 before 的状态交给 after。 */ }

static long install_target(void) {
  if (!target)
    return -ENOENT;
  hook_err_t err = hook_wrap3(target, before_target, after_target, NULL);
  if (err)
    return -EINVAL;
  target_hooked = 1;
  return 0;
}

static void remove_target(void) {
  if (!target_hooked)
    return;
  hook_unwrap(target, before_target, after_target);
  target_hooked = 0;
}
```

上例的 target 在初始化依赖阶段取得；实际实现记录 hook 错误码。参数数量和 `hook_fargsN_t` 对应真实调用，不能用内核版本猜。`skip_origin` 跳过原函数时还需设置符合原语义的返回值。hook 链容量读取实际 SDK 定义，不把历史上限作为通用限制。

syscall 使用 [syscall.h](../../../KernelPatch/kernel/patch/include/syscall.h) 的 `syscall_argn` / `set_syscall_argn`，适配直接参数与 `pt_regs` wrapper。注册与撤销必须配对：

| 注册 | 撤销 |
| --- | --- |
| `hook_syscalln` | `unhook_syscalln` |
| `fp_hook_syscalln` | `fp_unhook_syscalln` |
| `inline_hook_syscalln` | `inline_unhook_syscalln` |

32 位 compat 入口单独核对。FP 与 inline 方式取决于目标和当前 SDK，不能固定推荐某一种就认定所有内核兼容。

## 用户缓冲区与调用上下文

用户指针通过当前 SDK 的 uaccess/compat 接口访问，不能直接解引用或无限长度读取。ctl0 要检查 outlen、只复制已初始化的实际响应字节，并核对复制结果。当前 [compat_copy_to_user 实现](../../../KernelPatch/kernel/patch/common/utils.c) 返回已复制长度，不是 Linux `copy_to_user` 的未复制长度；其它接口也先核对实现语义再判断成功。字符串读取失败或被截断时，不当作完整请求执行。

`get_task_ext`、`get_current_task_ext`、`reg_task_local` 等必须同时核对定义、底层依赖、导出和运行端。不能假定 `current->task_ext` 存在，也不能从栈尾自行拼扩展地址。当前 SDK 的 get_task_ext 包装依赖 `kf_get_task_ext`；源码里有该实现不等于 KPM 可链接该导入。未核实运行端导出和容量语义之前，不使用该接口存放模块业务状态。

仅需同一 hook 调用的 before/after 状态时，使用 `args->local`。跨 hook 短期读取参数时，可用模块自己的任务/调用映射；本项目 [Binder 调用上下文](../../../re_kernel_x/re_kernel.c) 按任务和参数地址登记，支持嵌套，after 删除，分配失败时跳过相应读取。上下文不能在 after 之后继续引用调用参数；任务隔离、并发、嵌套及失败路径都需核对。

## 锁、回调与退出

按实际调用上下文选择锁、分配标志和可睡眠操作，不能把内核内联锁函数当作必然存在的 kallsyms 符号。模块私有锁仅保护自有数据，不能替代 Binder、RCU 等原生对象锁和引用。

解除 hook 不表示在途回调、work 或内核保存的函数指针已失效。核对目标回调的持有与释放、同步方式和 CFI 要求；移植上游 workqueue 或锁前先确认 KP 可调用的依赖及上下文，不机械照搬高版本实现。

当前 [模块加载器](../../../KernelPatch/kernel/patch/module/module.c) 在 RCU 读锁内执行卸载 exit；不能在该路径直接套用可能等待的注销、flush 或 synchronize 操作。先设计回调退出与资源释放，再验证热卸载。原始指令补丁使用实际 [hotpatch.h](../../../KernelPatch/kernel/include/hotpatch.h) 接口，核对返回值及同步语义，不默认 `hotpatch_nosync` 适合任意代码位置。

## 构建与产物自检

沿用项目 Makefile 的工具链选择。Android NDK clang 或 ARM64 GCC 均需核对版本和真实输出；不默认宿主 cc 能编译 KPM。`-r` 生成 ARM64 ELF64 小端可重定位产物，不依赖 libc。

ARM64 构建使用 `-mgeneral-regs-only -ffixed-x18 -mno-outline-atomics -fno-builtin`，并沿用 `-fno-PIC -fno-asynchronous-unwind-tables -fno-stack-protector -fno-common`。仅设置编译参数不算完成核验：

- 检查真实反汇编的 FP/SIMD/SVE 指令、x18 使用及意外的编译器辅助调用。
- 枚举全部 ELF 未定义导入，与实际 KP 导出表逐项比较；加载器不会把任意内核 kallsyms 自动用作 ELF 导入。
- 检查 `.kpm.info`、init/exit 回调节与重定位。动态模块检查推导状态、越界扫描和失败路径；静态模块核对配置段、基准 ABI 标记及配套布局文件。
- `-fno-builtin` 仍可能产生裸 `memcpy` / `memset` 导入。需要时按 [re_runtime.c](../../../re_kernel_x/re_runtime.c) 提供模块本地转接，并确认它依赖的 `kf_*` 已导出；不能改成同名递归包装。

探索输出用新的空目录。正式候选按仓库统一构建入口从冻结提交生成；记录提交、实例和产物哈希，不覆盖旧产物。动态算法的离线回归、静态补丁往返与主机 ASan/UBSan 都是实现方自检；运行时推导、目标锁、hook、ACK 和应用响应由独立真机测试核验。

## 加载错误定位

先区分失败阶段，使用实际日志，不把所有加载失败都归因于偏移：

| 阶段 | 常见证据 | 下一步 |
| --- | --- | --- |
| ELF 解析或重定位 | 格式错误、节缺失、重定位失败 | 核对 ARM64 ET_REL 与构建参数 |
| KP 导入解析 | `unknown symbol: kf_*` 等 | 查 ELF 未定义符号与运行端导出，尚未进入 init |
| init 依赖检查或动态推导 | 内核符号查不到、字段推导失败、初始化错误码 | 查目标名称、CFI、锚点数据流、字段状态及 ABI |
| hook 或业务运行 | hook 错误码、边界失败、异常日志 | 核对调用上下文、对象生命期、参数与字段证据 |

真机操作遵循 Tester/维护者授权及仓库设备升级流程；无响应后停止重试并保留现场。凭据不落盘，公开报告使用脱敏环境事实。控制协议若限定 UID 1000，不能用 root 调用失败证明协议不可用。

## 按需查阅的当前实现

SDK 头文件、导出与加载器优先于旧教程；构建 SDK 的存在不证明用户运行端具备同一导出。上面的相对链接指向本次核对过的实现，更新 SDK 后重新确认相关接口。

- [模块元信息与生命周期](../../../KernelPatch/doc/zh-CN/module.md)
- [函数 hook](../../../KernelPatch/doc/zh-CN/inline-hook.md)
- [syscall hook](../../../KernelPatch/doc/zh-CN/syscall-hook.md)
- [模块管理命令](../../../KernelPatch/doc/zh-CN/super-command.md)
- [编译环境](../../../KernelPatch/doc/zh-CN/build.md)
