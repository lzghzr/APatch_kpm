# NoMount：静态差异核对与 4.4 inode storage 修复候选

维护者指出的静态变化属实。此前“静态件相同”指相邻两轮探索件；相对已验收发布集，静态代码和产物确有变化。本轮把比较范围写明，并按维护者请求补齐 4.4 的局部表识别，交接 candidate，等待独立审计与真机验证。

## 身份

- 冻结源码：`846f3d1bce5f7aa9c9f8d180e3c1b2f02b6d3e34`。
- KernelPatch：`b51197aaba8f2272dd8a3e30c85698a29aa928c9`；工具链 `ndk26.3.11579264`。
- 统一入口：`python3 tools/build_candidate.py nomount --toolchain ndk26.3.11579264 --target all --kind candidate --env ANDROID_NDK=<NDK目录> --env LAYOUT_DIR=../local/nomount-inode-storage-20261015-01/candidate-layout-01 --handoff Developer/reports/handoffs/2026-10-15-nomount-inode-storage.json`。
- 构建事务输入未变，源码干净；两件均已按 candidate 档复算指纹、参数与哈希。

| 模式 | instance_id | SHA-256 | 字节数 |
| --- | --- | --- | --- |
| base | `nomount-2.1.1-20261014+g526802555793.r3ac93780.kpb51197a.ndk26.3.11579264#1` | `7e21475004c69deafa8d32d3607ca5359b0df0907a212ba0bbc37772ea5200ae` | 213528 |
| baselines | `nomount-2.1.1-20261014_baselines+g526802555793.rec234bc2.kpb51197a.ndk26.3.11579264#1` | `77a5baa38d3072c4fb63da4cb70b286d83d93cf06fa06179b8c4125f9c2bc15a` | 111864 |

[候选清单](handoffs/2026-10-15-nomount-inode-storage.json)包含完整配方与归档路径；[派生回执](data/2026-10-15-nomount-inode-storage-binary-ports.json)包含父实例、源码提交、父／子哈希、工具哈希、完整命令及 compat 收据位置。配套 ZIP 的源码和产物沿用已有版本。

## 静态版具体变了什么

| 比较对象 | 源码提交 | 静态 SHA-256 |
| --- | --- | --- |
| 已验收发布集 | `e9ab619ea75e7fd611c28dcc0328dbb99ebf1dfb` | `76e220cd0c7a6c2f5002d5f26148483baa06ccccad61f4838060159b7f2adac2` |
| 容量探索件 | `7e668af2213d78a4e7cbb0c72bc9f5660678403d` | `77a5baa38d3072c4fb63da4cb70b286d83d93cf06fa06179b8c4125f9c2bc15a` |
| 末端尺寸探索件 | `b4cf78daff053dea0b5ca987b33782f6bbfda552` | `77a5baa38d3072c4fb63da4cb70b286d83d93cf06fa06179b8c4125f9c2bc15a` |
| 本轮候选 | `846f3d1bce5f7aa9c9f8d180e3c1b2f02b6d3e34` | `77a5baa38d3072c4fb63da4cb70b286d83d93cf06fa06179b8c4125f9c2bc15a` |

发布集到容量探索件，有两处静态可达变化：

1. `nm_prepare_control_engine()` 的控制布局准备改为两种模式均调用。静态模式执行 `nm_validate_control_layout()`，因此比发布集多一次校验；后面的管理锁准备仍会校验。
2. `nm_validate_control_layout()` 将 key 容量读取缓存为局部值，减少对配置表的重复读取，改变编译后的指令。

原始静态件由 111968 变为 111864 字节；`.text` 由 42996 变为 42992 字节。配置段和模块元信息保持相同。本轮 inode 识别修改均在动态条件编译范围，重建静态件仍与两轮探索件逐字节相同。

这份 Developer 比较不替代变体差异审计。相对发布集的新静态字节，仍按维护者请求补测 4.19 与 4.4，或由 Auditor 明确出具可绑定旧证据的差异结论。

## 4.4 拒载原因与修复

绑定的旧动态实例为 `nomount-2.1.1-20261014+g4b49827eb674.ra2d2c48f.kpb51197a.ndk26.3.11579264#1`，源码 `b4cf78daff053dea0b5ca987b33782f6bbfda552`，原件 SHA-256 `1db32ea9a394164a6d3fde01d94875c516eafff953a30bd9ced6ea1c8b7e66ea`。4.4 实测使用派生字节 `d9d7d29785961e15f7db03bf1cc589ef48b0a5ecdf3afe621b9545958949ddc6`，在 inode storage 准备返回 `-ENOENT`。

B2N 镜像的真实表名为 `no_open_fops.36570`，旧函数查询的 `inode_init_always.no_open_fops` 和 `no_open_fops` 均不存在。兼容派生件把查询转接到精确名称接口，无法补齐编译器后缀。三个函数锚点均存在；以真实符号名称执行旧函数，可复现 `-ENOENT`。原宿主夹具合成了表名别名，因而遗漏此失败条件。

本轮在表名查不到时，沿 `inode_init_always` 入口 21 条指令跟踪 ADRP／ADD／STR，先核对 i_fop 到 i_data 的共同声明片段，再读取已确认的 open 槽，验证其回调为原生 `no_open`。CFI 只跟随核心代码区内的一条直接 B；不执行回调。表读取限制在已取得的核心镜像范围内；没有 `_end` 时使用 `__end_rodata`，适用于 B2N 的只读局部表。无符号、无有效边界、窗口或几何不符时继续停止加载。

新增日志分别标注函数锚点缺失、表身份／边界证据缺失，以及初始化器模式或几何被拒绝。源码与 Makefile 继续面向当前 SDK；临时兼容仍只变换构建后的二进制。

| 目标 | i_fop | i_data | i_data_size | i_blocks | 局部表实际名称 |
| --- | --- | --- | --- | --- | --- |
| B2N 4.4 | 328 | 344 | 152 | 152 | `no_open_fops.36570` |
| Sony 4.19 | 368 | 384 | 264 | 144 | `inode_init_always.no_open_fops` |

## 自检与 Oracle 边界

1. 两目标均执行原有 `test_operation_extents.py`，其中原动态准备断言保持原样，操作表尺寸与完整布局准备通过。
2. 新增 `test_inode_storage_lookup.py`，对两次实际表名查询按目标真实符号返回，不提供合成别名。覆盖四个 inode 存储字段、强制缺表名后的完整布局准备、缺锚点／代码边界／数据边界、空或非对齐回调，以及初始化器窗口每条指令被未知调用替换时拒绝。保护页用例检查表地址、槽位和读取范围。
3. Sony 5.15 BTF 的生产查询宿主回归通过，46 字段保持参考值；原生查询 API 由宿主模拟，不代表真机调用。
4. 两个 candidate 的 ELF／布局检查通过，未定义导入均可在冻结 KP 导出中找到，无裸 `memcpy`／`memset`／`memmove`；反汇编检查未见 FP／SIMD／SVE 寄存器操作。编译仍有 SDK 的 READ_ONCE／WRITE_ONCE 重定义警告，每件各两条。
5. 静态配置替换仅变更 92 字节、46 个 int16 的配置段；兼容件与工具变换的预期字节一致。派生步骤完整保存在回执中。

[逐项证据](data/2026-10-15-nomount-inode-storage-selfcheck.json)保存两目标及 BTF 回执、四轮静态身份、节区哈希、旧函数复现信息与新候选导入清单。原有测试脚本和断言均未修改。新夹具仍复用其他准备接口的宿主模拟，因此完整布局准备通过不能推导为全部运行端符号均可取得。

复现顺序：先运行 `test_operation_extents.py --image <镜像> --symbols <符号表> --reference <对应-v4.json> --output <新目录>`，再以该目录的 `dynamic-preparation.c` 为 `--fixture` 运行新增工具，其他目标参数相同。镜像为 `B2N-416G_boot.img` 与 `boot_los23.2.img`；符号表来源和镜像哈希沿用对应检查记录。

## 供审计与测试的派生字节

| 用途 | SHA-256 | 父字节 |
| --- | --- | --- |
| 4.4 动态兼容件 | `971b9e28135bcdfd45c8e223f20d5092ff53e719faaa00f2b08e36f53f5a497b` | `7e21475004c69deafa8d32d3607ca5359b0df0907a212ba0bbc37772ea5200ae` |
| 4.19 静态目标件 | `56fcfd9a7f3490df58a0e3b60d292cad1083ac852375e9cb3ad5dbdd95f42186` | `77a5baa38d3072c4fb63da4cb70b286d83d93cf06fa06179b8c4125f9c2bc15a` |
| 4.4 静态目标件（中间父件） | `283ebfb447afd36709ba9464ac91aa3e07382099704c867d57fb649258fb2a5d` | `77a5baa38d3072c4fb63da4cb70b286d83d93cf06fa06179b8c4125f9c2bc15a` |
| 4.4 静态兼容件 | `9e39293341f225e24bce9384faf531b9a23532d5fc773f38c327c258661f4248` | `283ebfb447afd36709ba9464ac91aa3e07382099704c867d57fb649258fb2a5d` |

4.19 与 5.15 动态使用候选原件。所有派生件路径均为 `artifacts/binary-port/nomount/<sha256>/<文件名>`；4.4 静态经过配置替换与兼容变换两步，回执保留完整父链。

## 方案复核（are-you-sure）

**保留（Retain）。**

有效性：真实名称用例复现了旧失败，新代码在两目标取得参考字段；缺证据与未知指令均拒绝。真机能否继续完成原生注册仍待测试。

简洁性：直接按表名查询仍优先使用；局部表名字不可查时复用已有 21 条入口解析，增加单槽身份核对。只改二进制查询转接不能恢复不可预知的局部名字；无需增加版本表或额外扫描器。

影响：新增读取仅在已核对几何及镜像范围内，协议、回调集合、调用顺序和驻留生命周期保持原样。静态字节已与上一探索件核对相同，发布集到探索件的变化交独立审计。既有 key 容量和末端布局适用边界继续保留。

## 问题与后续

- [DEV-042 提案](../proposals/2026-10-15-nomount-inode-storage/issues.json)：4.4 局部表精确名称失败及宿主别名掩盖；修复已交候选，等待 Auditor 独立复核关闭。
- `AUD-001` 维持 OPEN：无 BTF 的 `key_type` 精确尺寸仍未知，自建容量仍为 512；本轮没有扩大这个结论。末端声明契约只覆盖已核对布局，无法观测的额外尾部不能由本方法排除。
- 维护者导入清单后，Auditor 复核新识别路径、原生读取边界与静态差异；Tester 按请求验证 4.4 动态兼容件、4.19 动态、5.15 动态，以及两目标静态新字节。发布仍待维护者验收。

> 本轮结论来自实现方自检（构建、离线语料与代码走查），不是独立审计或实机结论。跨版本正确性、权限与生命周期安全、真机可用性由 Auditor 与 Tester 分别出具。
