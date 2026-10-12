# zram_zstd 0.4.0 内核适配开发自检

本轮源码检查点：`b86a5f72b6f9c8935661a83c59806cd062cb5d4c`。四个普通 KPM 的身份均为 exploration；不是正式候选、独立审计或真机结论。完整实例与产物哈希见[数据回执](data/2026-10-11-zram-zstd-kernel-compat.json)。

## 实现

模块注册 `zstd-kpm`，可与原生 `zstd` 并存。zram 开机配置显式选择 `zstd-kpm`；现有 zram 的切换仍由设备配置负责。压缩级别 3、ZSTD 1.5.7 静态工作区与常驻生命周期保持。

先复用 `zs_structs.h` 中经原生声明和目标证据核对的共同前缀；flags、ctxsize 和 name 起点直接使用定义。名字数组长度、回调区绝对位置和 transform 上下文仍依赖目标布局。BTF 查询在 `zs_btf.c`，固定窗口函数推导与配置调度在 `zs_offsets.c`；解码使用 `kpm_utils.h`。

缺少 `lzo_init` 的 Android 12 / 5.10 使用 `crypto_cts_exit_tfm` 前 8 条。实际索引 4、5、6 为 child 读取、base 地址计算、对 `crypto_destroy_tfm` 的直接调用，得到 `0x100 - 0x80 = 0x80`。限定入口参数来源、64 位访存、连续指令、未移位 ADD 和真实调用目标。原生 CTS context 的首成员及两个 skcipher 对象的 base 关系分别来自[CTS](https://raw.githubusercontent.com/torvalds/linux/v5.10/crypto/cts.c)、[skcipher](https://raw.githubusercontent.com/torvalds/linux/v5.10/include/crypto/skcipher.h)、[内部接口](https://raw.githubusercontent.com/torvalds/linux/v5.10/include/crypto/internal/skcipher.h)。

## 目标结果

13 份实际输入的六个字段均与另一来源参考一致。共同 flags/name 为 `0x20 / 0x38`；下表依次为 driver / compress / init / ctx。

| 镜像 | 生产路径 | 偏移 |
| --- | --- | --- |
| B2N-416G_boot.img | functions | 0x78 / 0xc0 / 0x100 / 0x80 |
| boot_67.2.A.3.178.img | btf | 0xb8 / 0x140 / 0x160 / 0x80 |
| kernel_android12-5.10 | functions | 0xb8 / 0x140 / 0x160 / 0x80 |
| kernel_android13-5.10 | btf | 0xb8 / 0x140 / 0x160 / 0x80 |
| kernel_android13-5.15 | btf | 0xb8 / 0x140 / 0x160 / 0x80 |
| kernel_android14-5.15 | btf | 0xb8 / 0x140 / 0x160 / 0x40 |
| kernel_android14-6.1 | btf | 0xb8 / 0x140 / 0x160 / 0x40 |
| kernel_android15-6.6 | btf | 0xb8 / 0x140 / 0x160 / 0x20 |
| kernel_mi10-4.19 | functions | 0xb8 / 0x140 / 0x180 / 0x80 |
| kernel_mi11-5.4 | functions | 0xb8 / 0x140 / 0x168 / 0x80 |
| kernel_mi6-4.4 | functions | 0x78 / 0xc0 / 0x100 / 0x80 |
| kernel_mi8-4.9 | functions | 0x78 / 0xc0 / 0x100 / 0x80 |
| kernel_mi9-4.14 | functions | 0xb8 / 0x140 / 0x180 / 0x80 |

函数参考使用原生 AES 名字数组间距、独立的解压入口、`crypto_mod_put` 和 LZO 读取；5.10 ctx 的独立参考来自原生分配器常量。BTF 参考由 Python 成员遍历取得，生产 C 单独执行。4.4 两个目标的 `zcomp_available_algorithm` 确实调用 `crypto_has_alg`，不能把结果外推给未回移 Crypto API 的主线 4.4。

GKI 裸镜像中的 zram 为外部模块，以上结果仅确认 Crypto API 所需布局；未核验对应 zram.ko 的实际注册与选用。6.12、6.18 本轮不移植。

## 验证

- `tools/selfcheck.py`：原有全部断言保留，追加多指令基址失效、pair 第二目标、CTS 调用目标/实参/移位/分支/窗口负例；ASan/UBSan 通过。生产编解码、256 个实际内核页面与独立 libzstd 互解通过；注册名称、重复加载、启动事件与资源清理通过。
- `tools/test_target_functions.py` / `tools/test_target_btf.py`：7 个函数目标、6 个 BTF 目标通过；生成回执逐项绑定镜像/BTF、参考和源码哈希。
- NDK 26.3.11579264：`all debug` 四种普通 KPM 成功。未定义导入对应当前 SDK 的实际导出声明；反汇编未发现 FP/SIMD/SVE 或 x18 使用。
- `Developer/tools/test_legacy_kp_metadata.py`：四个新 KPM、直接调用/原名指针导入、精确修改范围、元信息及静态布局回执全部通过。源码与 Makefile 直接按当前 SDK 构建；转接由 Python 修改产物。

本轮输出全部使用新的空目录。普通 KPM 已复制为模块目录中新的 0.4.0 文件，保留原 0.3.0 产物。身份仅写本地探索清单，未导入维护者 builds[]。

## 三项复核

**are-you-sure：保留（Retain）**。有效性：13 份目标的实际布局与独立参考一致，算法独立命名避免干预原生选择。简洁性：共同结构直接复用，CTX 使用职责明确的 CTS 短回调；独立只读复核确认其语义与目标 BL 地址。后果：未覆盖真机 CFI、原生异步测试、并发和压力；后续仍需独立审计与 Tester。

**respect-the-oracle**：对修改前后断言逐项比较，原断言全部保留。入口数组窗口扩大只为容纳新增实际目标位置，不缩小检查范围。

**no-negative-echo**：读回源码、模块说明、技能约定和本报告，使用当前行为组织说明；保留 README 首行用户注释及旧更新记录。

## 构建身份

共同完整 source_commit：`b86a5f72b6f9c8935661a83c59806cd062cb5d4c`。实例及 SHA-256：

- `zram_zstd-0.4.0+g180f5901ecc6.r30c2dd1b.kpb51197a.ndk26.3.11579264#1`
  - SHA-256：`b77fb5f243f2e756803e5dbf10abeed90de1dafb3768d9db7fe3eed50d03a627`
- `zram_zstd-0.4.0_baselines+g180f5901ecc6.ree62102a.kpb51197a.ndk26.3.11579264#1`
  - SHA-256：`1ab7783d353c1188f9fb469e19cbc3bbfa6c027945d8c61ad7bc69847a88cd53`
- `zram_zstd-0.4.0_baselines_debug+g180f5901ecc6.r6f6b5e7f.kpb51197a.ndk26.3.11579264#1`
  - SHA-256：`31f998e254e8d11f381e6942b5cbd53f0882e5d49d9a40453340c232d86a333a`
- `zram_zstd-0.4.0_debug+g180f5901ecc6.r413ef81e.kpb51197a.ndk26.3.11579264#1`
  - SHA-256：`6cca24562ecac853a86bc4382aaa05b152bc1abbbaa2aba8c8eb3d4c741ad635`
