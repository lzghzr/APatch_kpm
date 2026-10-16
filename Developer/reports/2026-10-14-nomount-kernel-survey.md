# NoMount 现有内核扩展盘点

角色：Developer。已核对现有全部输入的扩展范围：16份内核输入中，B2N 4.4和Sony 4.19已有对应版本真机记录，6.18按用户要求暂缓，本轮检查其余13份。结论是**其余目标都有可推进的实现方向，但高版本需要修改原生接口与共同片段，单填偏移表不能完成全部适配**。这里的难度是开发工作估计，不是兼容或安全结论。

本轮完成镜像身份、41个实际必需函数的符号盘点、配置检查、7份真实目标BTF的接口／字段解析，以及当前 nm_structs.h 共同前部比较。没有修改生产代码、重编译候选或操作设备；旧候选及报告保持原样。

## 已通过的基础

0.2.0来源提交 `c5c49e98164e0129e29b4bd3ba05c8affcd0b352`，B2N普通静态基准实例为 `nomount-0.2.0_baselines+geb65e9ed8940.r61a544d0.kpb51197a.ndk26.3.11579264#1`，基准SHA-256 `78a83a9a9ba9008edab6c8dfadb368569d850470ea76eb1d56113b8bbaac61ea`。本轮已核对生产C/h、Makefile、kpm_utils.h和patch_offsets.py仍与冻结构建输入一致。

[Auditor报告](../../Auditor/reports/2026-10-14-nomount-0.2.0-module-audit.md)记录四候选及四B2N派生件复现通过，哈希 `59a27b9d255d9b7385b18518db44fd1cbceff5d036b4f20ca2193175ef71c638`。[Tester报告](../../Tester/reports/runs/2026-10-14-nomount-0.2.0-4.4-boot-live#1.md)记录B2N普通legacy静态派生件15/15，包含文件、whiteout、目录合并、非root UID探针及mmap场景；实测SHA-256为 `7933a58e3e496231274d2de92aecb17a77f153a157af911d56950ca5ca96ced0`，报告哈希 `63133d5e97240e5ba6e5a16f5d40b14a42951400afe7f3e83d336bec2ce758c4`。两份报告复算与当前维护者登记一致。Developer在此引用原角色结论，未独立复现实机。

B2N debug、动态版，以及其他目标没有此次运行证据；应用探针的实际SELinux域与系统PackageManager行为继续按Tester报告边界解读。Sony 4.19原有真机结论对应0.1.0原实例，不自动扩展到新版或小米4.19。

## 新目标难度

| 输入 | 目标内核 | BTF | 预估难度 | 必要工作 |
| --- | --- | --- | --- | --- |
| `boot_67.2.A.3.178.img` | `5.15.189` | 有 | 中 | user_namespace 参数进入 permission/getattr/fillattr |
| `kernel_android12-5.10` | `5.10.257` | 无已取得数据 | 中 | inode_permission2 缺失，无 BTF；补权限接口并离线核对布局 |
| `kernel_android13-5.10` | `5.10.257` | 有 | 中 | 有 BTF；inode_permission 为 inode/mask 两参 |
| `kernel_android13-5.15` | `5.15.211` | 有 | 中 | 同类命名空间接口；以该目标 BTF 独立核对 |
| `kernel_android14-5.15` | `5.15.208` | 有 | 中 | 同类命名空间接口；以该目标 BTF 独立核对 |
| `kernel_android14-6.1` | `6.1.176` | 有 | 中偏高 | 命名空间接口，加上目录 actor 的 bool 行为 |
| `kernel_android15-6.6` | `6.6.77` | 有 | 中偏高 | mnt_idmap、四参 fillattr、bool actor、独立 f_flags |
| `kernel_android16-6.12` | `6.12.81` | 有 | 高 | file 和 fops 重排、inode 时间拆分、vzalloc_noprof |
| `kernel_mi10-4.19` | `4.19.157` | 无已取得数据 | 低～中 | 入口齐全；不能沿用 Sony 4.19 的绝对偏移 |
| `kernel_mi11-5.4` | `5.4.274` | 无已取得数据 | 中 | inode_permission2 缺失，无 BTF；补原生权限接口与目标静态配置 |
| `kernel_mi6-4.4` | `4.4.153` | 无已取得数据 | 低～中 | 入口齐全；核对该厂商完整表、锁与旧 getattr 布局 |
| `kernel_mi8-4.9` | `4.9.186` | 无已取得数据 | 低～中 | 入口齐全；核对哈希／getattr 的过渡签名及完整表 |
| `kernel_mi9-4.14` | `4.14.180` | 无已取得数据 | 中 | 入口齐全；厂商布局和既有 kptools 符号恢复需要交叉核对 |

所有目标均有CONFIG_KEYS=y、KALLSYMS_ALL=y、PREEMPT_RCU=y，已取得配置均未启用DEBUG_LOCK_ALLOC。符号齐全只证明提取表中存在入口；全表尺寸、函数ABI、短锚点语义、运行端KP查询能力还需分别核对。4.14和5.4使用既有Developer kptools提取结果，不将工具成功当作完整适配。

## 已证实的接口差异

当前源码固定调用 `inode_permission2(vfsmount*, inode*, mask)`。小米5.4、两份5.10及全部5.15以上输入的符号清单都缺此入口，必须支持对应原生permission接口，保留源路径、挂载和ACL权限语义。

| 真实BTF目标 | inode_permission | inode_operations.getattr | generic_fillattr | dir_context.actor |
| --- | --- | --- | --- | --- |
| Android13 5.10 | inode/mask，2参 | path/stat/mask/flags，4参 | inode/stat，2参 | int，6参 |
| 三份5.15 | user_namespace/inode/mask，3参 | user_namespace/path/stat/mask/flags，5参 | user_namespace/inode/stat，3参 | int，6参 |
| 6.1 | user_namespace/inode/mask，3参 | user_namespace/path/stat/mask/flags，5参 | user_namespace/inode/stat，3参 | bool，6参 |
| 6.6及6.12 | mnt_idmap/inode/mask，3参 | mnt_idmap/path/stat/mask/flags，5参 | mnt_idmap/request_mask/inode/stat，4参 | bool，6参 |

7份有BTF目标均保留五参vfs_path_lookup和四参vfs_getattr_nosec，可继续共用路径取得与原生属性调用。新增getattr回调需采用准确类型，并把收到的命名空间／idmap上下文传给正确原生接口；`user_namespace*`与`mnt_idmap*`不能仅因寄存器宽度相同就当成同一种ABI。目标配置均有CFI_CLANG=y、CFI_PERMISSIVE=n与SHADOW_CALL_STACK=y，测试需绑定实际KP对该目标的处理证据。

bool actor还改变继续／停止的语义。现有过滤隐藏目录项时返回0，虚拟枚举遇到非零就停止；只能通过明确的int/bool调用与回调桥接适配，不能仅改返回宽度或强转函数指针。后续回归应覆盖隐藏项后继续枚举、buffer满时停在当前cookie、原生／backing转发和dot项。

小米5.4、Android12 5.10没有已取得BTF，上表不能直接作为它们的ABI证明；需从对应声明与实际调用点取得值。低版本四份小米输入的41个当前必需函数全部找到，但getattr、hash、kstat及完整表仍按各自证据取得。

## 共用结构体覆盖与新边界

将实际 `nm_structs.h` 在64位宿主上编译取得offsetof，与7份目标BTF单独解码的位置比较：inode owner前部、dentry前部与superblock止于s_op的片段均吻合。5.10至6.1的file inode/op/path、flags/mode和连续三组时间片段也吻合；6.6保留inode连续时间，仅ctime字段名变为__i_ctime，已有查询支持该名。

| 目标变化 | 目标BTF证据 | 对共用实现的影响 |
| --- | --- | --- |
| 6.6 file flags | f_flags=88，f_mode=20 | 当前相邻片段校验不成立；业务只读f_flags，可直接验证／读取它，保留旧无BTF锚点的局部相邻前提，无需新增全局f_mode偏移 |
| 6.12 file对象 | f_op=16，f_mapping=24，private_data=32，f_inode=40，f_flags=48，f_cred=56，f_path=64，f_pos=128 | f_inode/f_op及f_path连续片段均失效；应独立取得变动字段或使用另一个经过核对的共同片段 |
| 6.12 file_operations | fop_flags=8，llseek/read/write/read_iter/write_iter=16/24/32/40/48 | 当前owner/llseek和止于write_iter的共同前部失效，必须补准确表布局；不能只增加file对象外围偏移 |
| 6.12 inode时间 | i_size=80，i_atime_sec/i_mtime_sec/i_ctime_sec=88/96/104；原timespec成员不存在 | 不能继续整块复制nm_inode_size_times；需核对sec/nsec字段宽度、布局和内核时间访问语义后实现 |
| 6.12内存接口 | 无vzalloc，存在vzalloc_noprof、vzalloc_node_noprof、__vmalloc_noprof | 可复用内核实现，但要确认新入口原型和初始化／分配契约，不能用版本号改名字 |

这些是尚未进入支持范围的目标差异，不是已通过B2N候选的回归。原动态BTF检查会拒绝不匹配布局，暂不填表或绕过检查放行。

## 输入与证据

[逐目标数据](data/2026-10-14-nomount-kernel-survey.json)保存完整符号匹配、BTF函数签名、字段位置、配置和哈希，SHA-256 `e1ab54707152960c773015a0942e70d12736a9cb2259a964c1b7a3513c34eb69`。目标符号复用既有Developer提取样本，此轮把原提取回执的内核哈希与当前解包输入比较；对7份BTF另确认原blob逐字节存在于当前目标。数据文件不是候选交接清单。

Sony5.15旧提取记录包含尾部填充，当前按boot kernel_size截取的内核47512064字节与旧48168960字节Image的前部逐字节相同，所用入口均在当前边界内。记录两种来源，保留旧样本；不把带填充旧哈希替换为当前内核哈希。

| 输入 | 文件SHA-256 | 当前解包内核SHA-256 |
| --- | --- | --- |
| `boot_67.2.A.3.178.img` | `06dbe42eccb4ea14a53e7b34d1f509bc7b176776db89d3280adba44c4b8b3731` | `83a36d57811b16e3742150a72236727300cbceb345850eca6aad0dd826dd0232` |
| `kernel_android12-5.10` | `ae2976e111bf11c8b56955df242757db9c9b2c06d0d12f57679b034ebfe71b0f` | `ae2976e111bf11c8b56955df242757db9c9b2c06d0d12f57679b034ebfe71b0f` |
| `kernel_android13-5.10` | `8eb4ef9fa91eb25ce9da8b8ff434e4c9e7ad3526a8da1b27c3833a378adf5e15` | `8eb4ef9fa91eb25ce9da8b8ff434e4c9e7ad3526a8da1b27c3833a378adf5e15` |
| `kernel_android13-5.15` | `080869136d6fec2592533e2e4e578c32dc981e9af6936c8a2b41de0a41d4811e` | `080869136d6fec2592533e2e4e578c32dc981e9af6936c8a2b41de0a41d4811e` |
| `kernel_android14-5.15` | `d6d02cf8941be4efe6d042a47cdab27699ebc36e3b85c6e553355cc7a1fc752d` | `d6d02cf8941be4efe6d042a47cdab27699ebc36e3b85c6e553355cc7a1fc752d` |
| `kernel_android14-6.1` | `bbb9762942d0142acd1ec8fc316faaced629cee6fd7a9d0303338d19685f7b8c` | `bbb9762942d0142acd1ec8fc316faaced629cee6fd7a9d0303338d19685f7b8c` |
| `kernel_android15-6.6` | `1c613d579069091b153ed786b57c2a51ee5bfa09b2ec350b1cc9092a556c5ef1` | `1c613d579069091b153ed786b57c2a51ee5bfa09b2ec350b1cc9092a556c5ef1` |
| `kernel_android16-6.12` | `8ad7edca7e73173b784aefcb17dfce94d2645d5048fe5451379b4aa1b796c848` | `8ad7edca7e73173b784aefcb17dfce94d2645d5048fe5451379b4aa1b796c848` |
| `kernel_mi10-4.19` | `cedd94d2e9a740075d0cc9853705ebe695a43c63502a62660c30aba018ed6823` | `cedd94d2e9a740075d0cc9853705ebe695a43c63502a62660c30aba018ed6823` |
| `kernel_mi11-5.4` | `4211656a1250a81bdbc9d3710c18bcbca7e90834bab57b639f9dbcacc4ea50c8` | `4211656a1250a81bdbc9d3710c18bcbca7e90834bab57b639f9dbcacc4ea50c8` |
| `kernel_mi6-4.4` | `cd92912fc52a9f422625eaf2db98937a407644b70b2cf5149f6df7eb1f17b930` | `cd92912fc52a9f422625eaf2db98937a407644b70b2cf5149f6df7eb1f17b930` |
| `kernel_mi8-4.9` | `93d2c9ffd6b893bf86728f82db3174f3edff0d18f92977cb49dfedd7f2fd8b64` | `93d2c9ffd6b893bf86728f82db3174f3edff0d18f92977cb49dfedd7f2fd8b64` |
| `kernel_mi9-4.14` | `229bdf7bfbc2c74a4e2fcb553bb10635624bc4d5b42a9b476d00319f2aa879fb` | `229bdf7bfbc2c74a4e2fcb553bb10635624bc4d5b42a9b476d00319f2aa879fb` |

临时分析脚本、共同片段offsetof程序及原始解码输出位于 `local/nomount-kernel-survey-20261014-01/`，脚本和fixture哈希写入逐目标数据。

## 复核决定（Decision）

**修改（Modify）**：保留逐级扩展方向，把共用片段失效与实际回调语义作为独立适配任务。

### 有效性

已根据镜像/BTF确认权限、getattr、fillattr和actor差异；有界Developer反例挑战补充了6.12的file_operations前部变化。该目标仅换配置不可达成目标，未来实现必须按真实类型和行为分别选择接口。

### 简洁性

首选复用0.2.0静态基线和共同前部，低版本先补配置。高版本仍共用业务实现、kpm_utils.h及独立BTF／偏移文件。6.6只需要独立f_flags读取，不因相邻f_mode失效增加未使用字段。无需为每个内核生成一套业务源文件，也无需增加加载参数。

### 后果

新ABI桥接可能影响已有枚举、权限和属性路径，原0.1.0/0.2.0 Oracle应保留，追加新目标输入和对照用例；先取得独立Auditor结论，再由Tester验证各自身份。离线BTF通过仍不证明实际KP、CFI或真机并发兼容。常驻到重启的生命周期沿用，风险登记与新版本适用范围由维护者处理。

## 推进顺序

1. 小米4.4、4.9、4.14、4.19：逐目标取得完整配置；优先复用现有候选，通过静态表生成派生件。
2. 小米5.4与两份5.10：补准确原生permission选择，区分无BTF静态证据和有BTF查询。
3. 三份5.15：补命名空间getattr、fillattr与源权限上下文；Sony5.15有实机可提供下一轮验证。
4. 6.1：加入具有正确继续／停止语义的bool目录actor桥接。
5. 6.6：接入mnt_idmap和独立f_flags访问，保留已可共用的inode时间与目录片段。
6. 6.12：调整file、file_operations和拆分时间访问，确认分配入口。6.18继续暂缓。

本轮仅完成扩展盘点，没有生成13份新目标候选。按are-you-sure完成一个有界只读反例挑战；按respect-the-oracle保留原测试和结论边界；按no-negative-echo回读报告、逐目标数据与README，明确当前已验证版本和后续范围。

常规门禁13项：0失败、1项既有警告（zram_zstd历史派生清单缺handoff_by／handoff_at）。本轮README与报告相对链接另行逐项核对；只增报告数据和说明，既有测试脚本及冻结生产输入保持原字节。
