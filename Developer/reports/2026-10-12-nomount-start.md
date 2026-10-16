# NoMount 4.19 建项与目标分析

角色：Developer。日期：2026-10-12。

本轮完成项目目录、上游接入提案和用户指定镜像的依赖清单。尚未实现 VFS 注入，也未构建或加载 KPM。

## 身份与输入

| 项目 | 值 |
| --- | --- |
| 分析工具源码提交 | `7f535cfb9e57c913ac470c2a3c7b59ecfd5934e7` |
| 原版 NoMount 提交 | `1ded61dc908c511072162fa0bee44e6ccdb7b4c7` |
| 目标镜像 | `kernel_img/boot_los23.2.img` |
| 内核版本 | `4.19.325-cip134-st18-perf-g7fc8455b2fa8` |
| boot 镜像 SHA-256 | `199658639f7389153ee8a7efe00154f0892e272ddc872728ea326e3e1ce2383b` |
| 提取内核 SHA-256 | `299f7e2580c54684c3b825bea57f1b16c53055f485ebd2b937593ac57ff9b0d2` |
| 分析清单 SHA-256 | `aa37ba41a233976fe798c0ad43b7d0625fea0fdd758e75c53d3227e3bd8fdd81` |
| KPM instance_id / 产物 SHA-256 | 不适用，本轮尚未构建 KPM |

上游以隔离检出读取，安装脚本未执行。子模块建议放在 [上游接入提案](../proposals/2026-10-12-nomount-upstream/README.md)，待维护者接入根目录 Git 登记。移植项目位于 [nomount](../../nomount/README.md)。

## 方案复核（Decision）

**修改（Modify）**：保留原版 NoMount LKM 到 KPM 的路线，首轮采用驻留生命周期，并把实际卸载保护列为启用 VFS 回调前的条件。用户选择 4.19 起步，后续按 4.4、5.15 推进。

### 有效性

冻结上游的 `kernel/setup.sh` 只添加源码链接与 Kconfig/Makefile 项；`nomount_init()` 注册 key 类型。文件注入通过操作表接管实现，未发现必须修改原生 VFS 调用点的前提。新目标已取得 keyring、VFS 和 RCU 路径的一批函数入口；符号存在只证明可继续核对接口，不证明 ABI 或运行时可调用。

### 简洁性

按目标编译原版 LKM 可用作行为对照，但通用 KPM 仍需自行确认布局和依赖。沿用原版规则、目录枚举及文件转发机制，可减少重新设计文件语义的工作。首轮聚焦新增目录、APK 与只读文件。

### 后果

原版操作表使用 `THIS_MODULE`，KPM 没有同等原生模块引用计数。仓库 KP 的 `unload_module()` 在 exit 返回错误时仍释放模块代码，单独返回 `-EBUSY` 无法保护仍被 inode、文件或映射持有的回调。实际驻留保护和初始化失败清理须先实现，再安装原生操作表。

本轮反例复核来自独立子任务，只读检查了上游接入前提和项目表述；它属于 Developer 方案复核，不代替 Auditor 审计。

## 目标事实

- 镜像为 Android boot v2。boot 头的 `kernel_size=0x3607818`，arm64 头的 `image_size=0x48ee000`。前者是 boot 文件中的段长度，后者包含运行时内存需求，不能据此读入后续 ramdisk。NoMount 工具按 boot kernel 段限界后提取。
- 提取 257,008 个 kallsyms 符号；本阶段清单中的 31 个函数入口均存在。此清单覆盖入口、虚拟文件、对象回收与 BTF 查询，不是全部移植依赖。
- `CONFIG_KEYS=y`、`CONFIG_KALLSYMS_ALL=y`，页移位为 12。
- `CONFIG_CFI=y`、`CONFIG_CFI_CLANG=y`、`CONFIG_SHADOW_CALL_STACK=y`，`CONFIG_CFI_PERMISSIVE=n`。回调需要核对运行端 KP 的 CFI 接入，编译时保留 x18。
- `CONFIG_DEBUG_INFO_BTF=n`。虽存在 `bpf_get_btf_vmlinux` 和 BTF 查询函数，当前镜像未发现可用 vmlinux BTF，不能据查询函数存在认定可走 BTF 布局路线。
- 保存了 8 个短函数的首 32 条指令，供后续核对布局：`vfs_llseek`、`iterate_dir`、`generic_fillattr`、`set_nlink`、`inc_nlink`、`path_get`、`d_set_d_op`、`generic_file_mmap`。当前工具只保存证据，不生成可用于加载的偏移配置。

## 自检

```bash
python3 kernel_img/offset_harness/extract_kernel.py --image boot_los23.2.img --local local/nomount-port-20261012/target
python3 nomount/tools/inspect_target.py --image kernel_img/boot_los23.2.img --output local/nomount-port-20261012/inspection-02
python3 nomount/tools/test_inspect_target.py
git apply --check Developer/proposals/2026-10-12-nomount-upstream/submodule.patch
git diff --check
```

单目标分析成功，2 项边界回归通过：v0～v4 输入均不跨 kernel 段读取 ramdisk，声明的 kernel 段被截断时拒绝。重复使用同一输出目录返回 2，原清单字节保持不变。子模块补丁通过应用前检查。本轮未改变既有测试断言或判据。

首次 `inspection-01` 复用了原提取器的扩展逻辑，包含 kernel 段之外的字节；其输出原样保留。修正的 `inspection-02` 内核哈希与 boot 头指定的 kernel 段直接哈希一致，31 项函数清单和 8 个入口指令与首次分析一致。本报告只使用 `inspection-02` 的内核身份。原公共提取器的扩展行为留给后续专项复核，本轮改动限于 NoMount 工具。

边界依据见 [AOSP boot 头定义](https://android.googlesource.com/platform/system/tools/mkbootimg/+/refs/heads/main/include/bootimg/bootimg.h) 与 [arm64 启动协议](https://docs.kernel.org/arch/arm64/booting.html)。

`are-you-sure` 对路线、建项内容和 boot 段限界分别复核，最后保留（Retain）本阶段实现；`no-negative-echo` 已读回新项目、提案和生成清单；`respect-the-oracle` 按实现方证据范围执行。

仓库常规门禁：13 项检查，0 失败、1 警告。警告来自既有 `2026-10-11-zram-zstd-1.0.0-binary-ports.json` 缺少 `handoff_by`、`handoff_at`，本轮未改写该历史交接清单。新增文档链接与公开文件卫生检查通过。

## 下一阶段

先把证实可共用的结构片段放入 `nm_structs.h`；剩余字段从目标 BTF 或固定短窗口取得，分别放 `nm_btf.c` 与 `nm_offsets.c`，生产指令解码使用 `kpm_utils.h`。确认操作表的完整大小、回调位置与 ABI 后实现 keyring 控制和只读注入。

当前还缺操作表完整布局、原生对象引用/回收契约及实际卸载保护的实现证据。满足这些条件前不提供可加载候选。候选产生后由 Auditor 独立审计，真机测试交 Tester。

> 本轮是 Developer 建项与离线分析，不是独立审计，也不是实机结论。
