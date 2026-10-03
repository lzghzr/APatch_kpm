---
name: kpm-static-binary-port
description: 获取 GitHub Releases 上按实际函数 ABI 区分的 ARM64 KPM 预编译基准，离线分析目标内核布局后仅替换二进制偏移表，用户侧无需 NDK。用于静态偏移移植、基准发布及 JSON/blob 补丁；动态偏移推导使用 kernel-offset-derivation。
---

# KPM 静态基准与二进制移植

目标：按无法共用的函数签名准备少量基准 KPM。布局变化通过独立数据段配置，目标移植只替换这段字节。说明、报告和新注释优先用中文，标识符沿用项目风格。

## 分清 ABI 与布局

- 基准编号表示实际函数调用约定，不能按 Linux 主版本号选择。通过目标源码、BTF 或调用点寄存器和被调用函数的参数使用确认。
- 同一 ABI 可使用不同结构体偏移。函数参数、调用语义或共同结构体布局无法由数据表表达时，才增加基准分支。
- `re_kernel_x` 用 Makefile 的 `REKERNEL_BINDER_ABI` 同时驱动条件编译和 `.rodata.re_abi` 标记。ABI3/4/5/6 的释放函数签名见 [模块开发说明](../../../re_kernel_x/AGENTS.md)，5.15 也可能使用 ABI5。
- `re_kernel.h` 放模块自己的协议和定义，`re_structs.h` 放核对过的内核定义，`re_utils.h` 放 KP 风格封装；公共宏在 `kpm_utils.h`。缩进遵循仓库 `.clang-format`。

## 获取公开基准（用户侧）

默认从项目 GitHub Releases 下载非 debug 基准，无需本地编译、NDK 或 KP SDK。先从目标镜像确认实际 ABI，再从同一发布 tag 下载基准 `.kpm` 及同名 `.kpm.json`；从该次构建提交取得 `patch_offsets.py`，放入新的本地目录。debug 基准及全部构建产物保留在 Actions artifacts。补丁工具仅依赖 Python 标准库；镜像分析工具的依赖另行准备。

使用旧版本且配套 JSON 未提供时，可用 `python3 re_kernel_x/tools/patch_offsets.py baseline <基准.kpm> --output <基准.kpm.json>` 离线生成；该命令还需同一构建提交中的 `re_offsets.c` 提供字段顺序，不进行编译。

配套 JSON 提供基准 SHA-256、ABI、表位置、长度与字段顺序。替换前核对这些信息，不能混用不同版本的布局文件或将公开基准的模板偏移直接用于目标内核。记录实际 tag、来源和基准哈希；已有核对过的本地基准可复用，没有兼容基准时再转开发构建。

## 构建与发布基准（开发侧）

偏移集中于 `.data.re_offsets`，使用 `volatile` 防止编译器折叠成指令立即数。配置段必须可写、无重定位，不存运行时地址。复用已经核对的共同布局，只把变化字段放入表中。

编译环境由开发者或 GitHub Actions 准备，用户侧只下载与替换。Actions 构建 ABI3/4/5/6 的 release/debug 基准；`re_kernel_x` 在 Releases 上传四个非 debug KPM 及各自的布局 JSON，其他模块沿用原有 Release 发布方式；全部 KPM 和基准布局 JSON 同时保留在 Actions artifacts。公开基准必须能取得配套 JSON 和同版本补丁工具，不能只发布默认 ABI。流程改动按仓库所有权交给维护者落地。

```bash
make -C re_kernel_x baselines OUT_DIR=../local/baselines-round1
```

使用新的空目录保存每轮基准。仓库正式候选与探索登记按 AGENTS.md 的统一构建入口执行；上述 Makefile 命令仅展示基准目标。

每个 KPM 携带同名 `.kpm.json`，记录实际文件 SHA-256、ABI、表的文件偏移、长度、字段顺序及初值。表大小和顺序读取本次布局文件，不能硬编码旧轮次的字节数。

## 目标移植

1. 使用用户指定的 img；多个未指定镜像先列候选。正常入口是 `img → 解包/解压 → Image → 符号与布局分析`；已有裸 Image 与符号表可复用，不能因为回归语料为减小体积保存了裸内核，就要求使用者预先提供裸内核。不下载完整源码树来查少量函数。
2. 有目标 BTF/头文件时提取布局，否则从镜像的实际函数数据流取偏移，使用另一锚点交叉验证。源码解释字段含义，目标镜像确认厂商布局；版本号和相邻版本布局不能充当证据。
3. 基于匹配基准 JSON 填全目标配置，保留缺失字段的约定。未知值应停止相关功能或报告待分析。部分偏移正确不表示完整目标移植完成。
4. 生成新文件，不覆盖基准或之前的补丁产物：

```bash
python3 re_kernel_x/tools/patch_offsets.py patch local/baselines-round1/re_kernel_x_1.6_abi3.kpm --offsets local/target-offsets.json --output local/target.kpm
```

原始表也可用 `dump <kpm> --output local/offsets.bin` 导出，按 JSON 的 `fields` 顺序修改小端 int16，再用 `patch <kpm> --blob local/offsets.bin --output local/target.kpm` 替换。使用配套布局文件校验 ABI、完整字段、长度和基准哈希。

## 碎片化旧内核的现场适配

早期 Android 内核的厂商改动、编译器、CFI 和功能回移差异很大，无法保证一个脚本跑通所有镜像。脚本用于减少重复工作；遇到困难目标，由使用者现场分析该镜像，不要求先扩展成通用脚本才能继续移植。

- 解包、符号提取或锚点识别失败，记录为工具未覆盖。检查目标的真实格式、配置、重定位和函数数据流，不能据此断言内核没有符号或功能。必要时在临时副本上恢复重定位、调整解析器或手工分析。
- 区分带哈希后缀的函数体与 `.cfi_jt` 跳板；核对所需函数及数据符号能否由实际 KP 查找接口取得。离线恢复了地址不代表模块运行时就能查到该符号，`KALLSYMS_ALL=n` 的数据符号缺失也不是填结构体偏移能解决的。
- 按目标函数确认 ABI，逐项填写本次配置表，以另一锚点交叉验证关键偏移。缺函数时检查内联、改名或旧实现，必要时单独移植；不能按版本号猜值，也不能把局部提取成功当作完整适配。
- 必需符号、对象或偏移仍未确认时，保留未完成状态，阻止进入依赖它们的内核调用。确需改模块实现时另产候选，不修改冻结基准。
- 留存镜像哈希、实际分析步骤、临时修正、字段依据及未覆盖项；原镜像、冻结资产和既有报告保持原样。仅某个目标上的修正，不直接推广到其它内核。

## 验证边界

- 补丁前后只允许配置段范围内变化，代码、符号、重定位、ABI 标记和模块元数据保持逐字节一致。对 JSON 和 blob 两种路径都做往返检查。
- 重新枚举 ELF 的全部未定义导入，与实际 KP SDK 导出比较。`-fno-builtin` 仍可能留下裸 `memcpy`/`memset`，不能只看编译成功。
- ARM64 使用 `-mgeneral-regs-only -ffixed-x18 -mno-outline-atomics`，检查真实反汇编的 FP/SIMD/SVE；按指令行解析，避免 `\s` 跨行把符号名认成寄存器。
- 主机 ASan/UBSan 验证业务、边界和失败路径，目标锁、hook、真实 ACK、卸载和应用响应需单独验证。不得把离线检查写成 Android 实机通过。
- 记录完整 commit、构建实例和产物 SHA-256；脏树只记探索，附源树指纹。原报告、清单和归档产物保留。

自检入口：`python3 re_kernel_x/tools/test_static.py --baselines <基准目录>`。

遇到旧 Binder 没有数据复制函数时，先阅读 [旧 Binder 数据读取经验](../kernel-offset-derivation/references/legacy-binder-data.md)，不要将用户地址当作内核指针，也不要因符号缺失直接认定功能无法移植。
