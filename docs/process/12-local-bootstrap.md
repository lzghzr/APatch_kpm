# 从克隆到可开发：本地环境建立

目标：`git clone` 之后，按本文能在本机把**提取内核 → 推导偏移 → 构建 KPM → 真机加载**这条链路完整跑通，进入开发状态。

前提认知：本仓库只入库**源码、工具、流程与证据记录**。内核镜像、构建产物、积累的本地输入都**不入库**（见 §2）。因此克隆后得到的是**工具齐全 + 按需自备输入**：哪些测试能跑，取决于对应输入是否已在本机备好。

## 1. 前置依赖（按宿主平台）

工具链之所以默认 GCC，起因是发布流水线用 NDK 构建的用户态 `bin/nm` 在 Android 17 上因 `PT_TLS` 对齐不足被 abort（DEV-117），
处置与结论见 `docs/records/2026-11-19-gcc-migration-origin.md`：**用户态 nm 走 musl/Zig，KPM 走 GCC**。

**KPM 默认工具链是 Arm GNU Toolchain 12.2.rel1（`aarch64-none-elf`）**，与上游 KernelPatch CI 同一发行版；
NDK clang 已退为**显式可选**（`make TOOLCHAIN=ndk`）。工具链前缀按 `TARGET_COMPILE` → `AARCH64_NONE_ELF_DIR` →
`PATH` 上的 `aarch64-none-elf-gcc` 顺序解析，都找不到时 Makefile 直接报错并给出安装方式，**不会静默退回 NDK**。

构建 KPM 与运行宿主夹具还需要这些宿主工具：

| 宿主 | 支持状态 | 需要装的东西 |
| --- | --- | --- |
| **Linux x86_64** | ✅ 完整支持（CI 就是这条路） | `python3` ≥ 3.11、`clang`、`make`、`git`、`adb`(可选)、`aarch64-none-elf-gcc` |
| **macOS（Intel / Apple Silicon）** | ✅ 完整支持 | Xcode Command Line Tools（提供 `clang`、GNU Make 3.81）、`python3`、`git`、`aarch64-none-elf-gcc` |
| **Windows** | ⚠ **只支持 WSL2** | WSL2 + Ubuntu，然后按 Linux 那行装 |
| **Windows 原生（MSYS2 / Cygwin / Git Bash）** | ❌ 不支持 | — |

拿工具链（二选一）：

```bash
# A. 官方二进制：解包后把 bin/ 加进 PATH
curl -LO https://armkeil.blob.core.windows.net/developer/Files/downloads/gnu/12.2.rel1/binrel/arm-gnu-toolchain-12.2.rel1-x86_64-aarch64-none-elf.tar.xz
tar xf arm-gnu-toolchain-12.2.rel1-x86_64-aarch64-none-elf.tar.xz
export PATH="$PWD/arm-gnu-toolchain-12.2.rel1-x86_64-aarch64-none-elf/bin:$PATH"

# B. 已有解包目录：显式告知
export AARCH64_NONE_ELF_DIR=/path/to/arm-gnu-toolchain-12.2.rel1-x86_64-aarch64-none-elf
```

显式用 NDK clang 构建（历史实例复现时才需要）：

```bash
export ANDROID_NDK=/path/to/android-ndk-r26c      # 或 ANDROID_NDK_LATEST_HOME
make -C nomount TOOLCHAIN=ndk all
```

Windows 原生无法运行的具体原因：

- Git Bash/MSYS2 下 `uname` 返回 Windows 风格标识，NDK 路径与 `windows-x86_64`／`linux-x86_64` 目录名对不上（`TOOLCHAIN=ndk` 时才涉及）。
- 宿主夹具按固定路径 `/usr/bin/clang` 调用编译器（公共树 13 个脚本），Windows 没有这个路径。
- 多处依赖 POSIX shell（`find`、`xargs`、`mktemp`）与 `/` 分隔的路径假设。

所以文档给 Windows 用户的指令只有一条：**装 WSL2，在 WSL 里按 Linux 走**。

### 三类角色的最小依赖

| 你要做什么 | 最小依赖 |
| --- | --- |
| 只跑门禁 / 读工具 | `git` + `python3` |
| 改模块源码并构建 KPM | 上述 + `make` + `aarch64-none-elf-gcc`（或 `TOOLCHAIN=ndk` + NDK） |
| 跑宿主夹具测试 | 上述 + `clang` |
| 真机测试 | 上述 + `adb` |

## 2. 什么入库，什么不入库

| 路径 | 入库 | 内容 | 可再生性 |
| --- | --- | --- | --- |
| 模块源码（`nomount/`、`zram_zstd/` …） | 是 | `.c/.h`、Makefile、模块脚本 | — |
| `nomount/tools/`、`kernel_img/offset_harness/`、`tools/` | 是 | **生成器**与公共测试（12 个） | — |
| `kernel_img/*.img` | **否** | 目标 boot 镜像 | 由用户提供（设备或 OTA） |
| `local/` | **否** | 本地输入：冻结 oracle、提取的内核、符号表、真机证据 | 部分可从镜像重建；oracle 不可再生 |
| `nomount/local/` | **否** | 模块专属本地输入：`configs/`（目标静态配置）、`tests/`（维护者回归集） | 配置可从目标镜像重新取证 |
| `metadata/` | 部分 | 构建登记与身份记录（`README.md` 入库，其余忽略） | 由构建流程生成 |
| `artifacts/` | **否** | 构建产物 `.kpm` | 由同一 commit + 同一 NDK 重建 |

`.gitignore` 的 `local/` 规则匹配**任意层级**，所以 `nomount/local/` 也自动忽略。

### 本地文件的存放与留存

**干净克隆没有 `local/`、`local/keep/` 及其中的 README。** 本节随仓库提供，是通用留存规则；本地目录由工具或使用者按需创建，无需预建空目录、添加占位文件或复制维护者的本地材料。

- **运行前选位置**：构建中间文件、变异夹具、下载缓存、一次性分析和连续截图放 `local/` 下的任务临时目录，或工具自建的临时目录，不直接堆入 `keep/`。
- **确需持续使用才保留**：`local/keep/` 保存不可再生或重建代价高的必要材料，通常分为 `oracle/`（冻结基准）、`target/`（持续使用的目标输入）、`evidence/`（原始设备证据）。可再生的目标输入只保留仍需复用的那份，不因每次运行复制一套。
- **每轮收尾由执行者整理**：保留必要输入、关键分析状态和原始证据，将自己已结束任务的中间文件移入回收站；不清理其他人的工作或仍在运行的任务。
- **普通中间版本不累积**：同一内容只留仍需使用的版本，用语义区分不同内容，不靠日期或 `-01/-02` 堆放重复副本。
- **冻结材料按身份规则保留**：已绑定候选或验收的 Oracle、归档产物、清单和历史记录不可覆盖或作为普通中间文件清理。未被候选或验收绑定的工具级 Oracle 可原地重生成，由 receipt 记录工具、配置及来源；断言变更仍遵守[测试基准守则](06-antipatterns.md#测试基准与反向过拟合)。

本地存在 `local/keep/README.md` 时，只用它记录本机库存、保留用途和历史路径对照；它不作为克隆者的必读文件。未发布模块按项目约定在对应 `*_test/` 保留完整本地副本。

## 3. 五分钟：验证克隆是好的

```bash
git clone <repo> && cd APatch_kpm
git submodule update --init --recursive

python3 tools/check_repository.py --portable      # 期望：14 项检查，0 失败，0 警告，8 项跳过
python3 tools/selftest_tools.py                   # 期望：35/35 通过，2 项跳过

for t in test_inspect_target test_release_zip test_update_json test_vfs_window_scan test_zip_metadata; do
  python3 nomount/tools/$t.py                     # 期望：5 个都 PASS
done
```

`--portable` 是**克隆者模式**：依赖本地材料的检查会显式 `SKIP`（不计为通过，也不判失败）。维护者本机跑 `--strict` 才要求产物在场且哈希可复算。

## 4. 完整链路：给一个新内核适配

以「手上有一个 `boot.img`」为起点。镜像放 `kernel_img/` 下（可直接放，也可按 `kernel_img/<大版本>/<小版本>/` 分层）。

```bash
cd kernel_img/offset_harness
python3 extract_kernel.py --list                                  # 看有哪些镜像 → 标签
python3 extract_kernel.py --image <名字>                          # boot → 裸 arm64 Image
python3 run.py --image <名字>                                     # 偏移矩阵
cd ../..

python3 nomount/tools/inspect_target.py \
    --image local/keep/target/extracted/<标签>/Image \
    --output local/keep/target/kernel-compat/<标签>               # 符号表 + 目标清单
```

提取产物与偏移矩阵默认落在 `local/keep/target/{extracted,kernel_offset}/`（`--local` / `--out` 可改）。

随后按 `nomount/AGENTS.md` §验证 的顺序做模块侧工作：静态配置 → 布局自检 → 构建。构建：

```bash
# 默认工具链：aarch64-none-elf GCC（Arm GNU Toolchain 12.2.rel1，与上游 KernelPatch CI 同一发行版）
export AARCH64_NONE_ELF_DIR=/path/to/arm-gnu-toolchain-12.2.rel1-x86_64-aarch64-none-elf
make -C nomount all                               # dynamic + static 两份 KPM

# 确需 NDK clang（例如复现历史 ndk26.3.11579264 实例）时显式指定：
#   export ANDROID_NDK=/path/to/android-ndk-r26c
#   make -C nomount all TOOLCHAIN=ndk
```

NoMount 的 Makefile 通过 [kpm_toolchain.mk](../../kpm_toolchain.mk) 按 `TARGET_COMPILE` → `AARCH64_NONE_ELF_DIR` → `PATH` 上的 `aarch64-none-elf-gcc` 选择 GCC；找不到时直接报错，NDK 需要显式选择。
需要编译器外部 `memset` 的模块独立链接 [kpm_runtime.c](../../kpm_runtime.c)。用 `aarch64-none-elf-readelf -sW <产物>.kpm` 核对最终 ELF 恰有一个已定义的全局 `memset`，并确认没有裸 libc 未定义符号。

静态版需按目标镜像取证后填入 `nomount/local/configs/<目标>.json`（模板与字段说明见 `nomount/AGENTS.md`）。**不得按内核版本号猜偏移**：必要字段取不到就停止初始化。

真机加载与测试走 Tester 路径：

```bash
bash Tester/tools/preflight.sh                    # 设备身份与环境事实
bash Tester/tools/run_test.sh --kpm <path>        # 退出码 90 = 设备无响应，按升级流程处理
```

## 5. NDK 获取

Actions 固定使用 **26.3.11579264**；本地尽量与之相同，避免产物差异。

- 平台目录名决定能不能编译：macOS 用 `darwin-x86_64`（Intel 与 Apple Silicon 同一个包），Linux/WSL 用 `linux-x86_64`。
  若看到 `aarch64-linux-android31-clang: No such file or directory`，多半是 NDK 平台与宿主不符。
- 国内镜像：`https://mirrors.cloud.tencent.com/AndroidSDK/android-ndk-r26c-darwin.zip`（Linux 把 `darwin` 换成 `linux`）。
- 校验（Linux 版实测）：`sha1 = 7faebe2ebd3590518f326c82992603170f07c96e`，解压后约 668 MB。

## 6. 三处容易误判为失败的现象

| 现象 | 原因 | 该怎么办 |
| --- | --- | --- |
| `nomount/local/tests/*.py` 全部 `exit=2` | 缺参数：这些测试要冻结 oracle、符号表或目标配置，全在 `local/` 下，不入库 | 属于**维护者本地回归集**，克隆者不需要跑；要跑就先按 §4 备输入 |
| `check_repository.py --portable` 有 8 项 SKIP | 依赖 `metadata/`、`artifacts/`、构建登记 | 正常。`SKIP` 不是通过；`--strict` 才是验收档 |
| `selftest_tools.py` 有 2 项 SKIP | 同上，依赖本地元数据 | 正常 |

反过来，**测试缺输入时报错是设计**：不会静默通过，也不会拿空输入假装跑过。

## 7. 改了路径或规则之后

通用留存规则维护在本文 §2，根 `AGENTS.md` 提供必读入口；模块特有约定维护在对应模块的 `AGENTS.md`。不要把通用规则只写进被忽略的本地文件。

新增或移动本地目录时，确认 `.gitignore` 覆盖到，并更新相关工具入口和文档引用。本机已有库存或历史路径对照的，同步更新本地记录；历史报告保持原样，需要继续使用的旧路径保留别名或恢复对照。
