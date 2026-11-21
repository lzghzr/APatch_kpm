# Developer（实现方）

Developer 拥有「让功能在目标内核上跑起来」的全部工作：内核分析、结构体偏移推导、模块代码、构建器、自检。

- 手册：`docs/process/developer-handbook.md`
- 偏移方法论（必读）：`.agents/skills/kernel-offset-derivation/SKILL.md`
- KPM 编码规范：`.agents/skills/kpm-development/SKILL.md`
- 测试基准守则（必读）：[docs/process/06-antipatterns.md](../docs/process/06-antipatterns.md#测试基准与反向过拟合)
- 开发报告模板：`docs/templates/developer-report.md`

## 上游差异登记

移植项目与上游存在差异时，在该模块的 `UPSTREAM.md` 登记，按「待处理」「已处理」「有意保留」分类。注明比较基线、行为差异与影响：待处理项写下一步，已处理项写实现提交及验证阶段，保留项写理由与适用边界。发现、实现或调整取舍时同步更新；候选完成与独立复核、实测、验收分别记录。

## 偏移获取的默认范围（2026-10-09）

后续 Android 内核偏移开发按使用者确认的范围推进：

- **4.4～5.10**：从函数入口的固定小窗口推导偏移；目标提供可用 BTF 时优先使用 BTF。
- **5.15 及以上**：默认从目标 BTF 获取类型、成员偏移与尺寸，函数推导的新增适配不包含这些版本。
- BTF 数据、必要类型或运行时查询接口缺失时，记录具体缺项，按目标镜像另行分析。版本范围用于安排适配工作，实际偏移仍由目标证据取得。

已有回归用例继续保留；新增适配范围与历史验证覆盖分别记录。

## 拥有的路径

| 路径 | 说明 |
| --- | --- |
| `re_kernel/`、`hosts_redirect/`、`cgroupv2_freeze/`、`dont_kill_freeze/`、`lmkd_dont_kill/`、`qti_battery_charger/`、`xperia_*/` … | 各模块源码、Makefile、模块 README |
| `kpm_utils.h` | 公共头：KP 封装、BTF 查询与指令宏 |
| `kpm_toolchain.mk`、`kpm_runtime.c` | 公共构建输入：工具链选择、按需链接的编译器运行时 |
| `kernel_img/offset_harness/` | 离线偏移推导回归 harness：解包 img、推导偏移、输出矩阵（自检用途） |
| `kernel_img/<大版本>/<小版本>/` | 用户放置的原始 img 与符号表（**不入库**） |
| `local/` | 运行产生的本地文件：提取出的裸 kernel、缓存（**不入库**） |
| `Developer/reports/` | 开发报告 |
| `Developer/reports/responses/` | 修复响应（问题编号 + 修复 commit + Build ID + 证据）：模板见 `docs/templates/developer-response.md` |
| `Developer/reports/handoffs/` | 交接清单（`identity.py record --handoff` 产出，维护者 `import-manifest` 导入） |

## 构建工具链（2026-11-17 起：默认 aarch64-none-elf GCC）

模块通过 `include ../kpm_toolchain.mk` 共享工具链探测。各自的 Makefile 保留版本、源码清单、专用编译选项和产物目标；编译规则将该片段加入依赖。

- **默认 = aarch64-none-elf GCC 12.2.rel1**（Arm GNU Toolchain，与上游
  `KernelPatch/.github/workflows/build.yml` 下载的发行版同一 release，同样是 `gcc -r` 产出 `ET_REL`）。
  共享片段默认选择 GCC，无需设置 `TOOLCHAIN`。
- **GCC 前缀解析顺序**（任一命中即用）：
  1. `TARGET_COMPILE`（上游写法，值已含 `.../bin/aarch64-none-elf-`）；
  2. `AARCH64_NONE_ELF_DIR`（工具链根目录，自动补 `/bin/aarch64-none-elf-`）；
  3. `PATH` 上的 `aarch64-none-elf-gcc`（自动取所在目录拼前缀）。
  三者都没有时 **make 直接报错**并打印安装与配置方式，**不会静默退回 NDK**。
- **NDK clang 退为显式可选**：`make TOOLCHAIN=ndk`（配 `ANDROID_NDK` / `ANDROID_NDK_LATEST_HOME`，
  或直接 `NDK_PATH=<ndk>/toolchains/llvm/prebuilt/<host-tag>/bin`）。历史
  `ndk26.3.11579264` 实例与其产物**不追溯修改**，仍可按原标签核验。
  `TOOLCHAIN` 同时是环境变量（`?=` 语义），所以复现历史 NDK 实例时可直接
  `python3 tools/build_candidate.py <模块> --toolchain ndk26.3.11579264 --env TOOLCHAIN=ndk --env ANDROID_NDK=<ndk>`；
  GCC 侧同理 `--env AARCH64_NONE_ELF_DIR=<工具链根>`。`make` 的目标参数写法也接受
  `--target "all debug TOOLCHAIN=ndk"`。
- **未知工具链名直接失败**（`TOOLCHAIN` 只接受 `gcc` / `ndk`），不做猜测。

CI 的 KPM 构建下载同一 GCC 发行版，并通过 `TARGET_COMPILE` 指定前缀。
**维护者记录（2026-11-20，NoMount 用户态 ZIP）：** [Build-NoMount-zip](../.github/workflows/build-kpm.yml)
使用 Zig 0.17.1 构建静态 musl 版 `bin/nm`。更新配套版本时，从该版本已真机验证的登记中同步 [ZIP 校验记录](../nomount/release-check.json)。DEV-117 仍为 open：按问题单，须核对实际发布 ZIP 内的
`bin/nm` 与已验证字节一致，并确认其在 Android 17 上可执行，才能关闭。

### 编译器运行时按需链接

GCC 可为聚合清零生成外部 `memset`，即使设置了 `-fno-builtin`。SDK 的 `<linux/string.h>` 只为源码调用提供内联函数；需要外部符号的模块将 `../kpm_runtime.c` 单独编译并链接一次。公共运行时经 `kf_memset` 调用原生函数，槽未初始化时逐字节写入；模块自己的加载前依赖检查保持原有契约。

当前由 cgroupv2_freeze、NoMount、ReKernel、ReKernel-X 和 zram_zstd 使用。zram_zstd 仅在编译运行时对象时定义 `KPM_RUNTIME_COPY`，同时提供 `memcpy`、`memmove`；编解码器的内联适配仍由模块的 `zs_memory.h` 和库配置头维护。

候选构建自动记录模块 Makefile 显式引用的 `../kpm_toolchain.mk` 和 `../kpm_runtime.c`。引用使用这两个字面路径；其他共享输入继续用 `--extra-input` 声明，例如生成静态 JSON 所用的 `patch_offsets.py`。

用 `readelf -sW <产物>.kpm` 核对使用公共运行时的最终 ELF 恰有一个已定义的全局 `memset`。启用拷贝包装时，`memcpy`、`memmove` 也各定义一次；`kf_*` 是预期的未定义 KP 导入，不留裸 `UND memset`、`UND memcpy` 或 `UND memmove`。加载器只从 KP 的导出表解析 ELF 导入；导入解析到槽的地址后，模块仍须按原有契约核对槽值。

## 常用命令

```bash
export AARCH64_NONE_ELF_DIR=<Arm GNU Toolchain 12.2.rel1 aarch64-none-elf 根目录>
make -C re_kernel all debug                                   # 默认 GCC：构建 static/dynamic 及各自 debug
make -C re_kernel all debug TOOLCHAIN=ndk ANDROID_NDK=<ndk>    # 显式走 NDK clang（历史路径）
cd kernel_img/offset_harness
python3 extract_kernel.py                                     # img -> local/keep/target/extracted/<标签>/Image
python3 run.py                                                # 全镜像偏移矩阵（自检）
python3 tools/identity.py manifest re_kernel --toolchain gcc12.2.1-aarch64-none-elf
python3 tools/build_candidate.py re_kernel --toolchain gcc12.2.1-aarch64-none-elf --target "all debug"
```

## 边界声明（每份开发报告都要写）

> 本轮结论来自实现方自检（构建 + 离线语料 + 代码走查），**不是独立审计，也不是实机结论**。
> 跨版本正确性、权限与生命周期安全、真机可用性分别由 Auditor 与 Tester 出具。

## 交接与授权（2026-10-02 维护者批复）

- `tools/identity.py record` 只**追加 `builds[]`**，Developer 可以直接运行（不会碰 `status`/`audits`/`issues`）；
  也可以 `--handoff` 只产出清单，交给维护者 `import-manifest` 导入。
- 探索阶段允许工作树不干净；**交接候选必须从冻结提交构建**（推荐 `git worktree add ../APatch_kpm-dev <sha>`），
  产物归档到 `artifacts/<instance_id>/`，封存后不可覆盖。
- 修复别人开的问题单后，在 `Developer/reports/responses/` 写修复响应并把问题单置 `fixed(待复核)`；
  由发现方复核关闭（`DEV-*` 自检问题也需另一位角色复核）。
- 需要改别人的文件时，提补丁建议（`git format-patch`/diff + 说明）给所有者落地。

## 与审计有关的注意事项

- `kernel_img/offset_harness` 与设备上的 C 代码同源：它能证明「移植一致」，不能证明「推导正确」。审计会用独立工具重解析产物字节。
- 自检发现的问题请自己开 `DEV-xxx` 单；Auditor 发现的 `AUD-xxx` / Tester 发现的 `TST-xxx` 由发现方复核关闭，修复者只能置为 `fixed(待复核)`。
- 改动实现、参数或工具链 → 新的 Build ID 与新的 commit；旧产物保留，不覆盖。

## 模块偏移模式默认规范

有结构体偏移依赖的模块默认提供 static / dynamic 两种编译产物，共用业务代码，定义 `CONFIG_KPM_BASELINES` 选择静态基线，未定义时使用动态推导。普通版名称为 `<模块>_<版本>_baselines.kpm`、`<模块>_<版本>.kpm`；debug 版增加 `_debug`。模块信息记录 `offset_mode`，两种产物保留同一管理名称，每次选择一种加载。

static 的偏移表须可通过二进制替换，并生成同名 `.kpm.json`；dynamic 的偏移表在加载时填写，优先使用 BTF，再使用目标支持的固定小窗口推导。已经取得 BTF 但必要类型或布局不符合时停止加载。没有偏移依赖的模块继续生成通用 KPM。

当前接入模块为 rek（`re_kernel`）、rekx（`re_kernel_x`）与 run_cmd（`run_cmd_demo`）。各模块在自己的 Makefile 中维护构建规则，其他模块逐个接入；公共构建输入按上节登记。Releases 发布两种普通版及静态 JSON，debug 留在 artifacts；维护者拥有的 Actions 和门禁调整以补丁建议交接。

各模块独立维护偏移表与推导实现，rek/rekx 使用 `re_offsets.c`，run_cmd 使用 `rc_offsets.c`。仓库根目录的 `patch_offsets.py` 生成和替换静态偏移表：schema 1/2 用于既有 Binder 调用配置，schema 3 用于普通偏移表。生成布局 JSON 时通过 `--source` 指定本模块的表定义；构建时须通过 `--extra-input patch_offsets.py` 捕获该工具。

## 公共 BTF 查询

`kpm_utils.h` 提供 `kpm_btf_type/member/offset/enum`。模块取得有效 BTF 及四个原生查询函数后初始化 `struct kpm_btf`，随后按自己的字段清单读取目标布局。嵌套成员支持点分路径和匿名 struct/union，返回 bit 偏移、位域宽度及类型尺寸；字节偏移入口拒绝位域或非整字节字段。字段清单、配置表的存储范围和函数 ABI 判定留在模块内。实现与自检见该模块的开发报告（本地 `Developer/reports/`）。

## 模块文件职责

模块入口负责生命周期和功能调度；业务按职责放置，如 freezer 与 UID 挂载、Binder 与 Genl。布局位置、推导和访问器留在偏移实现，BTF 查询单列；编译器生成的外部符号由公共运行时提供。检查结构调整前后的默认目标、产物变体、ELF 导入和静态布局，保持原有调用契约。

rek、rekx 的自有常量与协议放 `re_kernel.h`，内核定义放 `re_structs.h`，KP 风格封装放 `re_utils.h`；`struct struct_offset`、配置表、访问函数和推导放 `re_offsets.c`。通用实现以 rekx 为准核对，模块分别维护自己的协议及业务扩展。核对记录见该模块的开发报告（本地 `Developer/reports/`）。
