---
name: kpm-static-binary-port
description: 获取 ARM64 KPM 的 baselines 静态预编译基线，离线分析目标 BTF 或函数数据流后替换偏移和调用配置，用户侧无需 NDK。用于双版本中的静态移植、基准发布及 JSON/blob 补丁；运行时偏移获取使用 kernel-offset-derivation。
---

# KPM 静态基准与二进制移植

目标：优先使用统一基线，将布局与可表达的函数调用差异放进独立数据段，目标移植只替换这段字节。说明、报告和新注释优先用中文，标识符沿用项目风格。

## 双版本中的静态基线

rek（`re_kernel`）与 rekx（`re_kernel_x`）分别提供动态普通版 `<模块>_<版本>.kpm` 与静态 `<模块>_<版本>_baselines.kpm`，debug 在末尾增加 `_debug`。`CONFIG_KPM_BASELINES` 选择静态实现，未定义时为动态。两版管理名称相同，每次选择一种加载；仅静态版生成同名布局 JSON，动态版使用加载时 BTF/函数推导。

两模块保留独立 Makefile、结构定义和业务实现，共用根目录 `patch_offsets.py`。静态表的字段定义、实例、访问器及条件编译的动态推导集中于本模块 `re_offsets.c`。run_cmd（`run_cmd_demo`）也提供这两种模式，偏移实现为 `rc_offsets.c`，字段含义见 [模块开发约定](../../../run_cmd_demo/AGENTS.md)。普通偏移表使用 schema 3，既有 Binder 表继续使用 schema 1/2。全项目逐步接入这一规范，无偏移依赖的模块继续生成通用 KPM。

## 分清 ABI 与布局

- 调用配置编号表示实际函数签名，不能按 Linux 主版本号选择。通过目标源码、BTF 或调用点寄存器和被调用函数的参数使用确认。
- 同一份代码可保留多种准确签名，由静态配置选择；不能因为函数参数不同就默认多编译一份。调用语义或共同布局确实无法共用时才增加基线分支。
- `re_kernel_x` 的统一基线通过 `re_offsets.c` 末项 `binder_release_abi` 选择 3/4/5/6；默认模板为 6，移植时必须核对实际调用。签名见 [模块开发说明](../../../re_kernel_x/AGENTS.md)，5.15 也可能使用 5。Genl 接收入口共用，不再通过编译宏区分四份产物。
- `re_kernel.h` 放模块自己的协议和定义，`re_structs.h` 放核对过的内核定义，`re_utils.h` 放 KP 风格封装；公共宏在 `kpm_utils.h`。缩进遵循仓库 `.clang-format`。

## 获取公开基准（用户侧）

默认从项目 GitHub Releases 下载非 debug 的 `_baselines.kpm`，无需本地编译、NDK 或 KP SDK。若模块有调用 ABI 选择项，先确认目标签名。从同一发布 tag 下载静态基线及同名 `.kpm.json`；从该次构建提交取得根目录 `patch_offsets.py`，放入新的本地目录。核对发布清单，确认下载的是静态模式；debug 基准及全部构建产物保留在 Actions artifacts。补丁工具仅依赖 Python 标准库；镜像分析工具的依赖另行准备。

配套 JSON 未提供时，可用 `python3 patch_offsets.py baseline <基准.kpm> --source <同构建的表定义源文件> --output <基准.kpm.json>` 离线生成；源文件必须与基准构建提交一致，用于取得字段顺序，不进行编译。历史基线使用其构建提交配套的工具和布局，不套用当前字段表。

配套 JSON 提供基线 SHA-256、表位置、长度与字段顺序。有 Binder 释放选择项的统一基线使用 schema 2；选择值随目标 offsets 一起替换，生成后的 binder_abi 同步为实际配置。旧固定基线的 schema 1 与 `.rodata.re_abi` 只读标记仍受支持，不能把旧代码改成另一种释放签名。替换前核对这些信息，不能混用不同版本的布局文件或将公开基准的模板偏移直接用于目标内核。记录实际 tag、来源和基准哈希；已有核对过的本地基准可复用，没有兼容基准时再转开发构建。

## 构建与发布基准（开发侧）

偏移集中于 `.data.re_offsets`，使用 `volatile` 防止编译器折叠成指令立即数。配置段必须可写、无重定位，不存运行时地址。复用已经核对的共同布局，只把变化字段放入表中。

以模块 Makefile 为准选择目标：例如 `re_kernel_x` 的 `baselines` 生成静态普通版和静态 debug 版，`run_cmd_demo` 和 `nomount` 的同名目标只生成静态普通版。发布资产以[构建工作流](../../../.github/workflows/build-kpm.yml)为准；公开静态基线须配同次构建的 JSON 和对应提交的补丁工具。

```bash
make -C re_kernel_x baselines OUT_DIR=../local/baselines-round1
```

使用新的空目录保存每轮基准。仓库正式候选与探索登记按 AGENTS.md 的统一构建入口执行；上述 Makefile 命令仅展示基准目标。

按静态 KPM 的同名 `.kpm.json` 核对产物 SHA-256、表的文件偏移、长度、字段顺序及初值；有调用选择项时也核对其含义。字段数与表长从这份旁车读取，不从其他模块或旧版本抄取。默认 JSON 随 KPM 输出，`LAYOUT_DIR` 可指定布局目录；候选构建捕获 `--extra-input patch_offsets.py` 和实际输出参数。

## 目标移植

1. 使用用户指定的 img；多个未指定镜像先列候选。正常入口是 `img → 解包/解压 → Image → 符号与布局分析`；已有裸 Image 与符号表可复用，不能因为回归语料为减小体积保存了裸内核，就要求使用者预先提供裸内核。不下载完整源码树来查少量函数。
2. 有目标 BTF/头文件时提取布局，否则从镜像的实际函数数据流取偏移，使用另一锚点交叉验证。4.4～5.10 是函数推导的主要适配范围，5.15 及以上默认使用 BTF；缺少数据时仍可尝试已有窗口，困难目标现场分析。离线读取 BTF 不依赖运行内核查询接口；使用目标的类型、宽度和实际签名，具体契约见 [BTF 使用指引](../kernel-offset-derivation/references/btf-layout.md)。源码解释字段含义，版本号和相邻版本布局不能充当证据。
3. 基于配套基线 JSON 填全目标配置，若表含 binder_release_abi 则填入已确认的调用配置，保留缺失字段的约定。未知值应停止相关功能或报告待分析。部分偏移正确不表示完整目标移植完成。
4. 生成新文件，不覆盖基准或之前的补丁产物：

```bash
python3 patch_offsets.py patch local/baselines-round1/re_kernel_x_1.6-20261008_baselines.kpm --offsets local/target-offsets.json --output local/target.kpm
```

原始表也可用 `dump <kpm> --output local/offsets.bin` 导出，按 JSON 的 `fields` 顺序修改小端 int16，再用 `patch <kpm> --blob local/offsets.bin --output local/target.kpm` 替换。使用配套布局文件校验调用选择、完整字段、长度和基线哈希。用目标 BTF/头文件取得布局后，另据实际函数原型或调用点确认签名编号，结构体布局不代替函数签名依据。

## 旧 KP 兼容路径已退役

4.4～5.10 的现行做法是使用带 hotpatch 修复的 KernelPatch 和未经 `legacy-kp` 变换的模块。修复在 KP 侧，按机型与内核准备；已有派生件、工具及设备记录仅供历史核查，不再生成新派生件。适用条件与行为判据见[低版本兼容裁定](../../../docs/process/10-binary-adaptation.md)。

## 碎片化旧内核的现场适配

早期 Android 内核的厂商改动、编译器、CFI 和功能回移差异很大，无法保证一个脚本跑通所有镜像。脚本用于减少重复工作；遇到困难目标，由使用者现场分析该镜像，不要求先扩展成通用脚本才能继续移植。

- 解包、符号提取或锚点识别失败，记录为工具未覆盖。检查目标的真实格式、配置、重定位和函数数据流，不能据此断言内核没有符号或功能。必要时在临时副本上恢复重定位、调整解析器或手工分析。
- 区分带哈希后缀的函数体与 `.cfi_jt` 跳板；核对所需函数及数据符号能否由实际 KP 查找接口取得。离线恢复了地址不代表模块运行时就能查到该符号，`KALLSYMS_ALL=n` 的数据符号缺失也不是填结构体偏移能解决的。
- 按目标函数确认 ABI，逐项填写本次配置表，以另一锚点交叉验证关键偏移。缺函数时检查内联、改名或旧实现，必要时单独移植；不能按版本号猜值，也不能把局部提取成功当作完整适配。
- 必需符号、对象或偏移仍未确认时，保留未完成状态，阻止进入依赖它们的内核调用。确需改模块实现时另产候选，不修改冻结基准。
- 留存镜像哈希、实际分析步骤、临时修正、字段依据及未覆盖项；原镜像、冻结资产和既有报告保持原样。仅某个目标上的修正，不直接推广到其它内核。

## 验证边界

- 偏移替换前后只允许配置段范围内变化，代码、符号、重定位和模块元数据保持逐字节一致；统一基线的释放选择只在表内变化，旧固定 ABI 标记保持逐字节一致。对 JSON 和 blob 两种路径都做往返检查。
- 重新枚举 ELF 的全部未定义导入，与实际 KP SDK 导出比较。`-fno-builtin` 仍可能留下裸 `memcpy`/`memset`，不能只看编译成功。
- ARM64 使用 `-mgeneral-regs-only -ffixed-x18 -mno-outline-atomics`，检查真实反汇编的 FP/SIMD/SVE；按指令行解析，避免 `\s` 跨行把符号名认成寄存器。
- 主机 ASan/UBSan 验证业务、边界和失败路径，目标锁、hook、真实 ACK、卸载和应用响应需单独验证。不得把离线检查写成 Android 实机通过。
- 真机分两种输入分别记录：对设计为未配置即拒载的模板，在本次启动从未成功加载同名模块的环境中，检查预期错误、诊断及拒载后的设备存活；对按目标填好的产物，核对实际加载的是该文件，再验证依赖这份配置的功能。模板拒载与配置件加载各自绑定产物身份，不能用一项代替另一项。
- 记录完整 commit、构建实例和产物 SHA-256；脏树只记探索，附源树指纹。原报告、清单和归档产物保留。

自检入口：`python3 re_kernel_x/tools/test_static.py --baselines <基准目录>`。

遇到旧 Binder 没有数据复制函数时，先阅读 [旧 Binder 数据读取经验](../kernel-offset-derivation/references/legacy-binder-data.md)，不要将用户地址当作内核指针，也不要因符号缺失直接认定功能无法移植。
