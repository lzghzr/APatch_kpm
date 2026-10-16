# NoMount 0.3.0：挂载上下文与5.15候选

角色：Developer。已对照固定NoMount LKM实现，接入原生权限分派和带挂载上下文的属性回调，为三份5.15及Android13 5.10生成普通/debug静态测试件，四种KPM从冻结提交构建。以下是Developer自检，待Auditor独立审计与Tester真机验证；旧4.4、4.19候选保持原字节。

## 身份与交接件

源码：`f70894744b10d7aab212d18a9262e905eacef7d9`。输入指纹：`ac707667142069f08fe7b692ca6902fbda144b0ff6f6b8d17c3f5223ceae0721`。KernelPatch SDK仍为 `b51197aaba8f2272dd8a3e30c85698a29aa928c9`；上游NoMount gitlink仍为 `1ded61dc908c511072162fa0bee44e6ccdb7b4c7`。本轮不改变上游依赖。

统一入口使用 `build_candidate.py nomount --toolchain ndk26.3.11579264 --target "all debug" --extra-input patch_offsets.py --handoff`；实际NDK、布局目录、有效编译参数、编译器哈希和冻结输入均在 [候选清单](handoffs/2026-10-14-nomount-0.3.0.json)。事务input_unchanged=true且returncode=0，四个实例candidate档指纹与产物复算通过。

| 变体 | instance_id | 产物SHA-256 |
| --- | --- | --- |
| base | `nomount-0.3.0+gac7076671420.r6885ccd2.kpb51197a.ndk26.3.11579264#1` | `34196a10c625b589ce9554f3504ab660a5e67ac93e750fcf3aa39f552e59e569` |
| baselines | `nomount-0.3.0_baselines+gac7076671420.reefab191.kpb51197a.ndk26.3.11579264#1` | `6b2602e0b6bf1fff9f578d5fc31b210c0725ad811265ae14056656f55d236255` |
| baselines_debug | `nomount-0.3.0_baselines_debug+gac7076671420.r6cb8e981.kpb51197a.ndk26.3.11579264#1` | `b7bfac6b5c1a13c8b2c7565565d72bd7e824f332b2aa0c7cb0f7c9b9432b1bb2` |
| debug | `nomount-0.3.0_debug+gac7076671420.rc55c4e1e.kpb51197a.ndk26.3.11579264#1` | `35f233afa58901563db38d6a54aceef35ea637c9bc9e7813b3fc8c668261f230` |

[目标派生清单](handoffs/2026-10-14-nomount-0.3.0-target.json)完整记录base实例、source_commit、配置／工具哈希、实际命令、回执和派生路径。普通派生绑定上述baselines实例，debug派生绑定baselines_debug实例；归档位于 `artifacts/binary-port/nomount/<sha>/<同名KPM>`。

| 目标 | 文件 | 变换 | 派生SHA-256 |
| --- | --- | --- | --- |
| `boot_67.2.A.3.178.img` | nomount_0.3.0_baselines.kpm | 目标配置 | `872840e2e1cf58235816e0eee36470d6414db74f1789209dec47fa7edac09f13` |
| `kernel_android13-5.10` | nomount_0.3.0_baselines.kpm | 目标配置 | `5a7b0da929fe3f58a22927922ec95ea45e0f234562d7f5820aad800aa2091ca9` |
| `kernel_android13-5.15` | nomount_0.3.0_baselines.kpm | 目标配置 | `872840e2e1cf58235816e0eee36470d6414db74f1789209dec47fa7edac09f13` |
| `kernel_android14-5.15` | nomount_0.3.0_baselines.kpm | 目标配置 | `872840e2e1cf58235816e0eee36470d6414db74f1789209dec47fa7edac09f13` |
| `B2N-416G_boot.img` | nomount_0.3.0_baselines.kpm | 目标配置 | `99d3c7c0d82e1df4a1cfc09bc88779767827ad4f98606a3f2447e4b9b11d8bb5` |
| `B2N-416G_boot.img` | nomount_0.3.0_baselines.kpm | 目标配置 + 旧KP转接 | `f9f7608e8c889428b7c323b2ee66f46e8910d394a7aebaca56b9e92b4d2168ca` |
| `boot_los23.2.img` | nomount_0.3.0_baselines.kpm | 目标配置 | `421a9b1b4dbff5e1ca23f9ebdb331ebc0c3593055a1ec60fbb8448ea9da2b8a6` |
| `boot_67.2.A.3.178.img` | nomount_0.3.0_baselines_debug.kpm | 目标配置 | `7523ffacc626d713d49c5fdc57dd16d596d15f66fdb5b222cbac18df9fa3c672` |
| `kernel_android13-5.10` | nomount_0.3.0_baselines_debug.kpm | 目标配置 | `ff0a196962dbe8993915155b8577169fdcf0c4a9bfb0576050cc26d2e8459fbc` |
| `kernel_android13-5.15` | nomount_0.3.0_baselines_debug.kpm | 目标配置 | `7523ffacc626d713d49c5fdc57dd16d596d15f66fdb5b222cbac18df9fa3c672` |
| `kernel_android14-5.15` | nomount_0.3.0_baselines_debug.kpm | 目标配置 | `7523ffacc626d713d49c5fdc57dd16d596d15f66fdb5b222cbac18df9fa3c672` |
| `B2N-416G_boot.img` | nomount_0.3.0_baselines_debug.kpm | 目标配置 | `fcd52ea6822d7fb05386fc0c80379ab9f71cf4f418ae4507b571bd5d067a1c97` |
| `B2N-416G_boot.img` | nomount_0.3.0_baselines_debug.kpm | 目标配置 + 旧KP转接 | `7b53bd8f5d3422cd5b1f6b355786d4d276a0b656904b395502b5c79c11ea8e3f` |
| `boot_los23.2.img` | nomount_0.3.0_baselines_debug.kpm | 目标配置 | `8565bbdcfea919cea605593a82200a8e46582fe591e40bca6f3b8a5630988626` |

共14条目标／变体记录、10份唯一派生字节。Sony5.15与两份GKI5.15的45项配置逐项相同，共享生成件；清单记录实际首次生成配置和命令，并独立绑定各镜像哈希，未覆盖已有文件。B2N与Sony4.19的v3配置是新字段的明确输入迁移；旧配置和历史实例不修改，原实机结论不自动继承。

## LKM参考及实现

参考本地冻结上游 [nomount.h](../../nomount/nomount/kernel/src/nomount.h) 的IDMAP_PATH／IDMAP_ARG、[nomount.c](../../nomount/nomount/kernel/src/nomount.c) 的nm_getattr。LKM通过编译期类型选择原生接口，本KPM按目标证据配置实际签名，业务共用，不按内核版本分支。

- 源文件读取与backing目录搜索保留原生权限语义，分别传MAY_OPEN|MAY_READ和MAY_EXEC。权限分派支持Android的mount/inode/mask、plain inode/mask、user_namespace/inode/mask与准确idmap类型。完整子树准备和搜索权限同时迁移，plain目标不会继续被旧入口要求拒绝。
- 带上下文的源权限读取**源path的挂载成员**；两参plain接口与旧Android接口不访问namespace成员。需要上下文而源mount成员为空时返回错误，保留ACL与原生errno。
- 文件getattr及backed目录仍通过源path调用vfs_getattr_nosec，避免把目标namespace强套到源文件。纯虚拟目录用准确五参回调接收namespace，再传准确三参generic_fillattr。idmap的准确五参回调和masked四参fillattr也保留，但后续布局／actor尚未适配，不能据此宣布6.x可加载。
- `nm_structs.h` 增加已核对挂载前部；context位于24，以对应的typed成员访问。BTF在nm_btf.c核对命名指向类型；Android mount三参与namespace三参不会只凭参数数目被混同。偏移表／验证仍在nm_offsets.c，公共查询使用kpm_utils.h。

## 配置与BTF自检

表从42项／84字节扩为45项／90字节，旧字段顺序不变；新增默认均为-1：permission_abi、fillattr_abi、getattr_context_kind。编号分别表达权限签名、fillattr参数形态和getattr上下文类型；调用不完整或无法确认就停止准备。

| 目标配置 | permission_abi | fillattr_abi | getattr参数／context |
| --- | --- | --- | --- |
| [Sony5.15](../../nomount/configs/boot_67.2.A.3.178.json) | 2：user_namespace | 3 | 5／1 |
| [Android13 5.15](../../nomount/configs/kernel_android13-5.15.json) | 2 | 3 | 5／1 |
| [Android14 5.15](../../nomount/configs/kernel_android14-5.15.json) | 2 | 3 | 5／1 |
| [Android13 5.10](../../nomount/configs/kernel_android13-5.10.json) | 1：inode/mask | 2 | 4／0 |
| [B2N v3](../../nomount/configs/B2N-416G-v3.json)／[Sony4.19 v3](../../nomount/configs/boot_los23.2-v3.json) | 0：Android mount | 2 | 原目标3或4／0 |

四份真实目标BTF已执行生产查询，覆盖对象布局、完整操作表、回调槽、虚拟目录、拓扑、源路径、权限、锁与keyring，并执行公共验证。输出45项与另一套Python逐成员解析全部相等；三份5.15的mnt_userns@24及其user_namespace指向类型已核对。镜像、解包内核和BTF哈希分别记入配套配置，沿用 [镜像盘点](2026-10-14-nomount-kernel-survey.md) 的边界及来源。

新增BTF反例在真实BTF副本中保持参数数目／宽度，改第一参数为vfsmount指针，权限选择返回EOPNOTSUPP；将mnt_userns成员改为vfsmount指针也返回EOPNOTSUPP；移动上下文位置返回EINVAL。还原后正例再次通过。没有把字段错误当作缺数据回退。

| 后续目标 | 当前生产查询停止点 | 含义 |
| --- | --- | --- |
| 6.1 | directory：EOPNOTSUPP | bool actor的继续／停止桥接未完成 |
| 6.6 | file：EINVAL | flags/mode相邻条件已失效，仍待独立flags读取 |
| 6.12 | objects：EINVAL | file inode/ops共同片段重排，仍待新布局与时间访问 |

这些是有证据的未覆盖状态，未修改拒绝断言以放行。6.18按用户要求暂缓。小米4.4/4.9/4.14/4.19、无BTF小米5.4与Android12 5.10仍需逐目标取得完整配置，本轮未宣称其适配完成。

## 宿主、构建与字节检查

新增test_mount_abis.py以原提交校验0.2.0生成Oracle，保留全部602条assert表达式及顺序。仅补旧目标三个新增必需输入，再追加plain完整子树准备、源namespace权限、回调namespace属性、上下文缺失拒绝与原生错误传播用例；ASan/UBSan通过。原有24份测试脚本逐字节对照0.2.0保持不变；此前577条控制断言也在被保留的Oracle中。

四种正式构建通过，SDK的READ_ONCE／WRITE_ONCE重定义为既有警告，其他警告按Werror；本轮C/h格式与差异空白检查通过。静态模板45字段均为-1，新配置只改90字节表；JSON与blob字节相同，恢复后等于base。旧KP转换只在已配置B2N二进制上执行，变更范围核对回执，源码和Makefile继续只面向当前KP。

四候选及派生字节的ELF、内嵌元信息和配套布局通过检查。真实未定义导入均存在于冻结SDK的导出定义；未发现裸memcpy/memset导入、FP/SIMD/SVE操作数或x18使用。原MANIFEST、已归档构建和已通过Tester字节未覆盖。

这些是Developer Tier 3：真实BTF查询仍使用宿主原生API夹具，契约中的权限函数与锁是桩；不能证明目标CFI、原生锁竞争、RCU、SELinux、系统扫包或并发行为。还没有0.3.0真机事实，实际运行端KP导出和CFI由Tester绑定。

### 开发过程与Oracle范围

新宿主生成脚本最初有空格锚点及插入函数顺序两项错误，修正仅在新增工具，最终contracts-04通过。派生生成第一次遇到三份5.15同表产生同哈希路径，由现有防覆盖保护拦截；改为核对共享字节并复用首次生成命令，未放宽转换工具保护。没有修改旧断言、旧报告或生产代码来迁就这些夹具问题。

本地证据前缀 `local/nomount-lkm-port-20261014-01/`：

| 回执 | SHA-256 |
| --- | --- |
| `contracts-04/receipt.json` | `74b5c419d787125e217a3fa70656bb093277da82ec276f99e5f158aead9da7a3` |
| `btf-sony-02/receipt.json` | `e5f994ff77e34d9f2cef7099f50bd8d68bd5040cab56d4f276fcd043e8ec8bb0` |
| `btf-kernel_android13-5.10-02/receipt.json` | `d6a18f337a47140b24633ed5804562f8fba85cd6c73effcb0c3b9a01a951dbb4` |
| `btf-kernel_android13-5.15-02/receipt.json` | `6492fbe6b927c680aafeba4c634b18e55e3fc4fc1c3ebeae4b92ce601de34795` |
| `btf-kernel_android14-5.15-02/receipt.json` | `a90d1166d796d3b8c5603def6e3361a953e5b026a2b8ad4e7128aa46b750a185` |
| `reference-checks.json` | `9583f8b53548ae357404fb374767c04df9760076a26d6a46a9791125ad731b41` |
| `binary-checks.json` | `1722c866dcf2f91671a24d8db9103ef05805ec30fe11fb873f71b3450bb66207` |
| `verification.json` | `e14382b702b39e7ebaa5ba2f479c3e78eea0e0ff5cc339688f57e2d1362485cd` |

## 复核决定（Decision）

**保留（Retain）**。

### 有效性

有界Developer挑战对照LKM确认源权限和纯虚拟属性所用上下文不同；实现与新增用例分别传递它们。四目标BTF全配置通过，plain完整子树与namespace错误路径得到覆盖。5.15候选可交独立审计，再由Tester验证。

### 简洁性

0.2.0仅有旧Android权限和两参fillattr，无法直接满足目标接口。新增三个语义选择及准确函数指针即可共用业务；挂载前部已能覆盖，不再新增namespace绝对偏移。加载参数继续留空。

### 后果

新回调会参与原生VFS调用，实际CFI、挂载权限与生命周期仍需要目标证据。版本及配置必须配套，原低版本Oracle保持。常驻到重启的约束沿用，新实例风险范围由维护者确认；未完成的6.x布局保持拒绝。

## 交接与后续

请Auditor独立复现四候选和目标派生件，重点检查命名空间上下文、准确类型、完整子树初始化、45项配置和共享派生记录。维护者登记及两字段版本提案见 [登记提案](../proposals/2026-10-14-nomount-0.3.0/README.md)。随后Tester先验证Sony5.15的普通派生件，按实际KP／CFI与常驻范围加载；debug另绑定运行。加载仍为post-kernel-init，参数留空，每次选一种，驻留到重启。

下一阶段接6.1的bool actor，再处理6.6 flags及idmap语义和6.12布局；无BTF厂商目标继续逐目标取得证据。按are-you-sure完成一次有界反例挑战，按respect-the-oracle保持原Oracle，按no-negative-echo回读源码、README、配置、清单与报告。

常规仓库门禁13项：0失败、1项既有警告（zram_zstd历史派生清单缺handoff_by／handoff_at）。当前0.3.0与维护者登记0.2.0按在途候选处理；验收前由维护者同步。新增报告及提案相对链接另行核对通过。
