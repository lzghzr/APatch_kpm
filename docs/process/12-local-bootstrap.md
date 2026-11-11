# 从克隆到可开发：本地环境建立

目标：`git clone` 之后，按本文能在本机把**提取内核 → 推导偏移 → 构建 KPM → 真机加载**这条链路完整跑通，进入开发状态。

前提认知：本仓库只入库**源码、工具、流程与证据记录**。内核镜像、构建产物、积累的本地输入都**不入库**（见 §2）。因此克隆后得到的是**工具齐全 + 按需自备输入**：哪些测试能跑，取决于对应输入是否已在本机备好。

## 1. 前置依赖（按宿主平台）

NDK 只提供交叉编译器；构建 KPM 与运行宿主夹具还需要这些宿主工具：

| 宿主 | 支持状态 | 需要装的东西 | NDK 目录名 |
| --- | --- | --- | --- |
| **Linux x86_64** | ✅ 完整支持（CI 就是这条路） | `python3` ≥ 3.11、`clang`、`make`、`git`、`adb`(可选) | `linux-x86_64` |
| **macOS（Intel / Apple Silicon）** | ✅ 完整支持 | Xcode Command Line Tools（提供 `clang`、GNU Make 3.81）、`python3`、`git` | `darwin-x86_64`（NDK 的 macOS 包就是这个目录；Makefile 已把 `darwin-arm64` 映射过去，Apple Silicon 经 Rosetta 2 运行） |
| **Windows** | ⚠ **只支持 WSL2** | WSL2 + Ubuntu，然后按 Linux 那行装 | `linux-x86_64`（在 WSL 里） |
| **Windows 原生（MSYS2 / Cygwin / Git Bash）** | ❌ 不支持 | — | — |

Windows 原生无法运行的具体原因：

- `nomount/Makefile` 用 `uname` 推 NDK 目录：`HOST_TAG = $(shell uname | tr A-Z a-z)-$(uname -m)`；MSYS2 下 `uname` 返回 Windows 风格标识，拼出的目录名与 NDK 实际的 `windows-x86_64`／`linux-x86_64` 都对不上。
- 宿主夹具按固定路径 `/usr/bin/clang` 调用编译器（公共树 13 个脚本），Windows 没有这个路径。
- 多处依赖 POSIX shell（`find`、`xargs`、`mktemp`）与 `/` 分隔的路径假设。

所以文档给 Windows 用户的指令只有一条：**装 WSL2，在 WSL 里按 Linux 走**。

### 三类角色的最小依赖

| 你要做什么 | 最小依赖 |
| --- | --- |
| 只跑门禁 / 读工具 | `git` + `python3` |
| 改模块源码并构建 KPM | 上述 + `make` + NDK |
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
export ANDROID_NDK=/path/to/android-ndk-r26c      # 平台需匹配宿主
make -C nomount all                               # dynamic + static 两份 KPM
```

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

本仓库的目录约定集中在三处，改动要同步：

- 根 `AGENTS.md`：角色、硬规则、常用入口；
- `nomount/AGENTS.md`：模块约定、验证清单、测试去留判据；
- `local/keep/README.md`：本地输入的保留判据与历史别名。

新增或移动本地目录时，同时确认：`.gitignore` 覆盖到、文档里的路径可点、历史报告里的旧路径有别名对照。
