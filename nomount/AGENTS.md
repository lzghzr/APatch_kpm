# NoMount 开发约定

本目录由 Developer 维护，遵守仓库根目录和三方交付流程。

## 目标与输入

- 首轮目标为用户提供的 `boot_los23.2.img`，内核版本 `4.19.325-cip134-st18-perf-g7fc8455b2fa8`。
- 下一轮目标为 `B2N-416G_boot.img`（4.4.192-perf+）。参考 Nokia SDM660 提交 `67c3e103decafc3ff8a361c39f079a0dfce2a23c` 的声明与目标配置；参考源码为4.4.196，不能声明为镜像的准确构建源码。变化字段另以目标机器码交叉核对。
- 以 `UPSTREAM.md` 指定的 Git 提交为原版源码基线。上游 Git 子模块位于 `nomount/upstream/nomount`；移植代码在本目录单独维护。
- 首轮内核源码参考为 `LineageOS/android_kernel_sony_sm8250` 的 `7fc8455b2fa84be76364c2457e6503b867ceb12a`，与镜像版本标记一致。源码用于核对字段语义，运行时偏移仍取自目标。
- 普通文件、目录枚举、APK 资源和映射访问共用一致的规则。PackageManager 的扫描成功不代表应用进程读取成功。
- 模块成功初始化后驻留到重启，与 zram_zstd 保持一致；不实现热卸载和已发布回调的撤销。exit 只作诊断，不能把其返回值当成 KP 卸载保护。

## 本地静态适配数据

用户静态适配以本次提供的 boot 镜像重新取证，绑定镜像身份生成结果；不按机型或内核版本套用旧表。
目标配置与回归输入放在仓库根目录的 `local/nomount/configs/`，由已有 `/local/` 规则忽略，不进入源码或默认构建。
该目录目前保留22份历史配置，其中12份v4用于既有回归；文件内容不因移动而改变。
依赖这些输入的自检须先备齐原目标证据，缺文件应报未就绪，不能把空配置矩阵算作通过。

新检出若需重放历史回归，可从迁移前提交恢复本地输入（仅在目标目录不存在时执行）：

```sh
mkdir -p local
# <迁移前提交> 可取本次迁移提交的父提交；恢复的是历史回归输入，不是新设备适配结果。
git archive <迁移前提交> nomount/configs | tar -x -C local
```

历史报告保留原路径；本文件下列 `local/` 路径均相对仓库根目录。

## 文件职责

- `nomount.c`：KPM 元信息、完整初始化、状态查询和驻留诊断入口。
- `Makefile`：dynamic / static 两种产物，静态版附带布局 JSON。
- `local/nomount/configs/boot_los23.2.json`：首轮目标的38项配置及镜像、源码和证据绑定。
- `local/nomount/configs/B2N-416G.json`／`local/nomount/configs/boot_los23.2-v2.json`：0.2.0 的42项静态配置。原0.1.0配置与候选保持原样。
- `nm_layout.c`：布局获取层的编译入口；当前只构建对象文件。
- `nm_native_entry.c`：布局、操作表尺寸和原生封装的联合编译入口。
- `nm_rules_entry.c`：规则核心的独立编译入口；与其他临时入口分别编译。
- `nm_file_entry.c`：只读文件引擎的独立编译入口，准备后返回尚未发布的完整操作表。
- `nm_inode_entry.c`：普通文件物化引擎的独立编译入口；与其他临时入口分别编译。
- `nm_directory_entry.c`：原生父目录视图的联合编译入口，当前仍只构建对象。
- `nm_structs.h`：有目标证据的共同内核结构片段与协议定义。
- `nm_offsets.c`：偏移表、访问器、短函数推导和调度。
- `nm_btf.c`：原生 BTF 查询。
- `nm_native.c`：原生 RCU、控制载荷传输和 backing 目录枚举封装。
- `nm_protocol.h`：与原版用户态工具一致的控制载荷。
- `nm_operations.c`：按目标完整尺寸分配/复制操作表，及发布前失败清理。
- `nm_rules.h` / `nm_rules.c`：模块私有规则、UID 筛选和子项索引；原生结构访问通过布局层。
- `nm_file.c`：文件 open/release、同步 read_iter/write_iter、seek、只读 mmap 和 splice_read 回调。
- `nm_inode.c`：普通文件 inode 物化、getattr 与完整 super_operations 代理。
- `nm_current.c`：复用 KP current/cred 布局取得 fsuid 与 compat 状态。
- `nm_directory_nodes.c`：私有目录视图、子项规则选择及虚拟枚举 cookie。
- `nm_directory.c`：原生父目录 lookup/iterate、dentry 重验证与完整操作表快照。
- `nm_virtual_directory.c`：纯虚拟／backing 目录共用的 inode 缓存、属性、枚举和 seek 分派。
- `nm_topology.c`：按路径建立／裁剪目录树、原生目录 anchor 与批次退役；管理索引只在锁内访问。
- `nm_topology_entry.c`：目录拓扑的联合对象编译入口；控制层随后调用持锁的增删／清空接口。
- `nm_backing_directory.c`：backing 子路径查询、合并枚举与 seek 封装。
- `nm_backing_inode.c`：完整 backing 引擎准备、源读取权限、私有子规则与递归物化。
- `nm_backing_subtree.c`：自动父目录按当前父视图继承 backing 来源，以及源目录搜索权限。
- `nm_backing_entry.c`：准备完整 backing 引擎并提供查询与枚举接口；控制注册由 nm_control_entry.c 接入。
- `nm_control_lock.c`：原生管理 mutex 的准备和未发布失败清理。
- `nm_control.c`：控制命令、批次游标、规则与 UID 管理以及规则列表分页。
- `nm_control_key.c`：keyring 预解析载荷与 key_type 注册；成功后驻留。
- `nm_control_entry.c`：实际 KPM 包含的完整 backing 与控制层入口，先准备引擎和锁，最后注册 key type。
- `module/`：配套ZIP自有安装与启动脚本；上游用户态、WebUI、metainstall及路径处理仍从冻结子模块读取。
- `tools/build_zip.py`：从干净冻结提交打包ZIP，直接用NDK编译上游nm；记录独立ZIP实例、工具／输入及产物哈希，不重建KPM。
- `tools/test_zip_module.py`：临时目录执行安装与启动脚本，以CLI／安装器夹具验证控制流，不能代替实机。
- VFS、规则管理和控制接口按业务拆分，避免把目标布局混进规则实现。

## 配套元模块

- 安装以包内nm的版本及隔离UID状态查询确认控制接口；2.1.1的CLI已传播列表查询错误；安装继续使用版本和隔离UID状态查询作兼容判据。不按uname或驱动版本字符串分支，不加载／卸载内核驱动。
- APatch元模块metamount先于普通post-fs-data执行，metamount自行检查接口、停用标记和开机回执；清空旧规则并恢复UID／isolated设置后再发布文件规则。后续每个写入操作核对退出状态，失败清规则。
- 路径以NUL分隔；find和xargs分步核对。保留原版分区映射、.replace与opaque路径处理，跳过disable/remove/skip_mount模块。
- .booting保存boot_id，收到boot-completed后删除。上次回执未完成时暂停注入，不能把它定性为NoMount导致崩溃；同次开机重入不判为旧启动。
- ZIP卸载清当前文件规则、配套数据及属于本模块的nm快捷入口；KPM保持原生命周期。原版WebUI安全模式在下次开机生效。
- ZIP候选用源码完整commit、独立Build ID#实例号与ZIP SHA-256交接。打包从Git对象读取输入，固定ZIP时间及权限，使用新实例目录；用户态源码和GPL-3许可证随包附带。KPM与ZIP分别绑定身份与实机覆盖。

先核对共同结构和 SDK 已确认的字段，再取得不能覆盖的偏移。生产代码统一使用根目录 `kpm_utils.h` 的指令解码和 BTF 查询。BTF 查询与短函数推导分开；仅数据或接口不可用时回退，有效 BTF 的错误保留。必要布局无法确认时停止初始化。

有布局依赖时提供 static / dynamic 两种模式，共用业务实现。源码与 Makefile 面向最新 KP SDK；旧 KP 派生件在已构建的二进制上生成。跨目标的函数 ABI 依据实际接口证据选择。

## 控制与生命周期

- 保留上游 keyring 协议作为首选接入方式，核对 `key_type`、预解析载荷、权限和用户页访问的实际契约后实现。
- KPM 参数不承担规则传递；规则由配套用户态工具管理。
- 嵌入允许默认 `pre-kernel-init` 和 `post-kernel-init`，分别绑定实机证据；文件规则等到数据分区可读后建立，并在 Android 系统应用扫描前完成。
- 初始化拒绝非空参数，加载事件不决定是否执行准备；全部可能失败的准备在 key type 注册前完成，注册成功后直接返回成功。失败只清理未发布对象。
- 目标启用 CFI 时，Tester 在加载前绑定实际 KP／boot 身份并确认目标 `__cfi_slowpath` 挂接成功。当前 KP 不导出可靠的 CFI 就绪状态；到达 KPM init 或单独的 `bypass_kcfi done:0` 日志均不能证明挂接完成。KPM 回调位于 KP 可执行分配区域，CFI 处理复用 KP；保持 `-ffixed-x18`。
- 原生 inode、dentry、superblock、文件及映射的引用和锁不能由模块私有锁代替。
- 规则替换/删除使用原生 `synchronize_rcu` 和 `call_rcu`；不经过 SDK 的 `synchronize_rcu`/`kfree_rcu` 包装。
- 规则数组、子项数组和 UID 数组为不可变快照。修改者持有管理锁，读者持有原生 RCU 读锁；带出读侧范围的规则先增加引用。
- 替换/删除将旧规则收进 `nm_rule_updates`，管理层解锁后调用 `nm_finish_rule_updates`，统一等宽限期再释放路径引用。纯私有数组的 RCU 回调只释放模块私有内存；路径及 dentry 引用在进程上下文释放。
- `nm_set_leaf_rule` 只接收尚未发布的新规则，成功时接收调用者的一份引用，失败保持旧数组及引用。规则曾发布后不再次进入任意叶节点，避免在退役链表中重复入链；`nm_remove_leaf_rule` 只负责数组，包含子目录的叶节点由拓扑层先处理虚拟目录保留。
- 子项数组仅持有叶节点指针，引用和父目录关系由拓扑层管理。摘下叶节点后等宽限期再调用 `nm_free_leaf`；已发布表的失败清理不能直接释放仍可被访问的对象。
- backing 目录使用原生 `iterate_dir`，由其锁住 backing inode；同一 inode 的接管回调使用外层已有锁，直接转发保存的原回调。
- backing 子项通过原生 `vfs_path_lookup` 取得完整 path；传入 backing mount 以保留目标 Android permission2 和挂载点遍历。名称限单个分量，flags=0 保留末尾 symlink 的类型，成功引用转交调用者，取得后被模块拒绝的路径在进程上下文 path_put。调用者先退出模块 RCU，不持管理锁或 backing inode 锁。
- 合并枚举共用现有规则过滤器，先读 backing，再输出虚拟子项；点项显示 outer 目录和父目录编号。blocked UID 保留 backing 内容并跳过规则子项。枚举／seek 同时核对 backing inode 操作表和已打开 file 的 f_op，拒绝再次进入模块目录表，覆盖 i_fop 先发布而 i_op 尚未发布的窗口。
- 纯虚拟／backing 目录共用完整操作表和 iget5_locked 缓存，依 rule 类型分派。backing 目录复制既有字段覆盖的属性，保留自己的 i_data；getattr 转交源路径，再替换 ino/dev。新inode候选先取得独立path/node引用，缓存命中释放本次候选的引用及info。
- 完整 backing 引擎必须在实际 KPM 初始化时经 nm_prepare_backing_queries 准备，源原生权限接口和其 ABI 不可用就失败。准备成功后安装 open 的源读取权限检查，普通文件和 backing 目录均执行 MAY_OPEN | MAY_READ，以补足 dentry_open 不做 DAC 的边界。完整入口随后经 nm_prepare_backing_subtrees 接入来源继承和 MAY_EXEC：backing 父目录的显式 lookup 与 ref-walk revalidate 都经权限分派器调用源 mount/inode 的搜索权限；LOOKUP_RCU 仍返回 ECHILD。各独立对象准备入口用于分段开发，实际 KPM 初始化须走完整入口。
- backing fallback取得完整源path后转交临时规则，物化取得独立path再释放规则，不进管理索引；标记 published 以阻止误入管理树。普通文件复用文件物化，子目录新建空节点并递归走相同目录引擎。显式规则优先，blocked UID 在 fallback 前产生负项；无显式 leaf 的 owned 普通文件／目录正项按下述严格回源判据复用；负项和链接仍失效重查。
- 继承正项复用仅接普通文件／目录：每次ref-walk用源父path与有界名字快照执行原生查询，核对mount+dentry、类型、普通文件mapping、mode/uid/gid、SID及已复制的size/times/blocks（目录另核对nlink）。源标签仍经getsecctx验证，命中不再notifysecctx；atime变化也保守失效，净收益待真机。
- inherited_child为私有来源标记，区分无显式规则的临时子项与显式／自动父；不增加缓存引用，info/rule的ARM64尺寸保持64/56字节。可睡眠查询前后分别用短RCU选择当前UID规则、核对父视图与名字；变更则失效重建，不在存活inode上换源/刷新标签。不跨睡眠持有规则裸指针，不持d_lock或管理锁回源，不用TTL/generation跳过源检查。既有path/node生命周期及原生shrinker回收保持。
- Developer入口为tools/test_cache_reuse.py：读取1545条int/bool冻结夹具，仅按7c4e160授权迁移M1-O1/O2的稳定正项返回值，类型检查、负项与clear_rules后失效保持；其余表达式和顺序不变，追加源／规则／绑定变化和回源交错。工具手动调用，未接共享门禁；宿主桩不证明原生dcache命中、shrinker或真实并发，迁移独立复核待Auditor。
- 完整引擎依赖全齐后才开放拓扑中的 backing 目录规则。准备失败只清理尚未发布的私有表，并清空拓扑准备状态和权限入口；已有引擎拒绝重复完整准备。fallback普通链接按下述现代接口契约物化，特殊文件仍拒绝。
- 在已有管理目录下新增深层规则时，建立私有自动父链，管理阶段不解析这些前缀的当前 UID 视图。自动／保留目录的 inherit_backing 只属于模块私有规则；查找时从实际父inode的独立path取得来源，使用原生 vfs_path_lookup 查询相应子目录，并持独立 path/rule/node 引用。ENOENT 保留纯目录，其他原生错误保留，源为非目录时返回 ENOTDIR。自动／保留目录的 inherit_backing 分支仍强制重查，以覆盖源出现／变化；显式来源撤销后有子规则的目录恢复父来源。
- 在建管理父链前已打开的 fallback 目录持有原节点及源 path；新路径查找进入新管理节点。现有 FD 的目录视图保持到引用结束。删除最后子规则会裁剪自动父链，已打开的 inode 持有空节点直到 evict；撤销有子项的显式目录仍保留该管理节点。
- keyring 载荷先经过 `CAP_SYS_ADMIN` 检查，再通过原生 `memdup_user` 取得内核快照；响应核对用户拷贝长度。控制协议保持 4096 字节及 32/64 位地址传递。
- v22 保持4096字节外层；ADD／列表记录头24字节、DEL头18字节。`version` 回复为 `22 (KPM <发布版本>)`，KPM元信息仍使用发布版本。配套CLI在非version操作前探测且精确要求协议22；安装器同样核对线协议号，不按内核版本选择布局。用户必须成组更新KPM与ZIP后重启。
- UID默认作用域为(0,0)，单UID为(uid,uid)，范围包含两端；默认规则可带排除范围，显式范围拒绝重叠，相同范围不同排除集合返回EEXIST。删除精确匹配范围和排除集合，旧单UID内部入口仍可用。范围条数不按UID个数展开。
- opaque的backing目录只提供属性/安全标签，子项来自显式规则；禁止backing查找、自动父目录来源继承和backing枚举。inode绑定中的flags包含opaque位，切换opaque/合并视图必须重新匹配缓存。带内容的`.replace`先建opaque目录再加文件，空`.replace`与`.remove`白化；启动每步核对错误，失败清规则。
- 控制层使用原生 `__mutex_init`／`mutex_lock`／`mutex_unlock`，按目标完整 mutex 尺寸分配。当前明确要求无 `dep_map`，含 lockdep 的布局返回 EOPNOTSUPP；原生动态 class key 注册未接入。首轮配置已确认 DEBUG_LOCK_ALLOC／DEBUG_MUTEXES／DEBUG_SPINLOCK／LOCKDEP 未启用，mutex_size=32，初始化 class key 为 NULL。动态尺寸与 ABI 从 BTF 取得，静态值来自对应源码／配置证据，验证放在布局层。
- key_type 只共用 name／def_datalen 前16字节和连续的 preparse／free_preparse／instantiate 回调；key_preparsed_payload 只共用连续 data／datalen。其起点由 nm_offsets.c 配置、nm_btf.c 查询。BTF 核对回调 ABI、完整尺寸和连续位置；key type 优先按已证完整尺寸分配；BTF明确不可用且完整尺寸未知时，可使用独立512字节清零容量，覆盖已核对声明及内部注册写入。容量不写入key_type_size，不参与原表复制。成功注册为初始化最后一步，此后表、锁和模块均驻留到重启。接口版本由 nm_protocol.h 的 NM_CONTROL_VERSION 提供，NM_KPM_VERSION 单独标识发布版本。
- 动态自建表对已取得的 inode_operations／dentry_operations／key_type 尺寸执行512字节上界门控：超界在完整准备／控制校验时返回E2BIG，自建分配在分配前拒绝；不截断，不影响按精确尺寸复制原表。注册锚点已识别的link及其16字节链表写入也须在容量内，超界错误不得进入尾部未覆盖的降级。完整尾部未覆盖且已知尺寸在界内时沿用原处理；尺寸仍为-1时保留既有512字节回退，这不证明未知厂商尾部在界内，AUD-001保持OPEN。静态编译分支不增加该门控。
- 无 BTF 的 key_type 尺寸取自已核对的注册／注销与声明契约：`register_key_type` 前18～23条由原始type的name与链表容器关系取得link，`unregister_key_type` 前16～20条核对同一节点的next／prev及两个自指针写回；两者须一致。注册入口可见class初始化时，要求实际memset目标、零值、零长度及`class_offset == link + sizeof(nm_key_type_tail)`；初始化已被编译器消除的形态沿用对应完整声明契约。管理mutex仅证明其自身布局，不用来推断key_type的LOCKDEP。完整尾部为link加空lock_class_key，自然对齐8；未知入口保留独立容量，已识别形态内部冲突报错。不能识别任意厂商未使用的追加尾部，AUD-001仍须独立复核。
- 控制布局新增GCC、无SCS、SCS和PAC入口，三个key回调由原生56字节前缀与调用者交叉确认，调用者最多30条，载荷检查最多13条；CFI跳板只接受一条直接B，可带BTI C前缀并核对4／8字节边界。mutex完整初始化最多10条，覆盖count、owner和已核对的owner加两个OEM槽声明，不按版本号分派。`tools/test_key_control_shapes.py`对8份无BTF语料执行逐指令NOP／原子状态写回、调用身份、class冲突与保护页；矩阵还执行8份实际BTF尺寸读取。此处覆盖控制布局和尺寸，不等于其它VFS字段或完整模块已适配。
- 批次 ADD 逐项在锁外解析 backing，再持管理锁发布；DEL 在管理锁内处理。完整记录操作失败后仍继续，status 保留第一错误，arg1 为已遍历字节末端；截断记录停在该记录起点。载荷非事务，已成功的前后记录保留。统一在管理锁外 finish 退役对象。
- GET_LIST 对管理索引持同一 mutex，列出用户可重提交的显式规则，跳过 automatic 与仅供子项保留的 inherit_backing 目录。单页在锁内取得一致内容；跨页修改仍为尽力分页。无法容纳单条记录时返回 EOVERFLOW。自动父目录统一设置 inherit_backing，在实际父视图以后由 pure 变为 backing 时也能取得源子目录；纯父没有来源时保持纯目录。
- 操作表的大小、每个回调位置、调用 ABI 和 CFI 必须得到目标证据，不能把整份上游头文件视为通用布局。
- 使用新字段前先比较需要支持的上游声明及目标厂商声明，并核对 SDK 是否已有可用结构。共同前部直接放进 `nm_structs.h`，不为其中每个成员新增偏移。当前 SDK 对 file/kiocb/file_operations 仅有前向声明；共同片段已比较 4.4、4.9、4.14、4.19、5.15、6.6 和首轮目标。
- CFI 窗口识别同时接受回调减锚点、锚点减回调；仍核对旋转、比较及分支。`super_cache_count` 的 slowpath 形态限定前27条，核对64位 type ID 构造、`__cfi_slowpath` 调用目标及后续 sb/回调实参。keyring 的 SUB/CMN 载荷检查限定前10条，回调槽读取的寄存器与栈写入重排限定前22条；同源入口夹具见 `tools/test_cfi_layout_shapes.py`，不能外推为其他编译形态的支持。
- 首轮文件表只填写读取相关回调；当前写打开与截断准入见下述M1/M2契约。首轮open拒绝写打开和O_TRUNC；read_iter 在转交前拒绝异步请求；mmap 使用原生 `generic_file_readonly_mmap`，保持 outer VMA 文件引用和 backing 页缓存映射，拒绝共享可写映射。
- 文件表另接入ioctl／compat_ioctl／fsync，沿用open持有的backing引用转发，保持原生参数与errno；compat缺回调不得回退native。`nm_file_control_ops`和`nm_file_sync_ops`只描述已核对的连续片段，以已有mmap／release锚点定位；BTF存在时独立验证新增槽位与参数原型。所有新旧file槽位显式拒绝负数。`test_file_control.py`、`test_file_control_layout.py`和`test_file_control_replay.py`由Developer在该功能候选冻结前手动执行，未接共享门禁；行为等价与目标性能推进记录见`Developer/proposals/2026-10-22-nomount-functional-parity/README.md`。
- 物化层须将 inode 的 i_mapping 转接到 backing，并在 inode 生命周期内持有规则引用。mmap 成功后按原版处理 S_PRIVATE；不能把 vma->vm_file 替换成 backing 而省略 VMA 引用记账。
- 普通文件通过原生 new_inode 取得文件系统分配的对象；保留原生锁、链表、引用及嵌入 i_data。规则由物化函数另取一份引用，d_splice_alias 接收 inode 引用，原生失败路径也可能消耗它。
- super_operations 复制完整目标尺寸，原生 alloc/destroy/free 与尾部均保留，只替换 drop/evict。发布前完成私有头部和表初始化，以 CAS 防止覆盖发生变化的原表；公开后的代理表驻留。调用方持管理锁及 sb 路径引用。
- 虚拟 inode 的 evict 清除私有指针、结束 i_mapping 借用，truncate 本 inode 的 i_data，再调用 clear_inode。进程上下文释放规则路径，RCU 回调只释放私有元数据；原生 VFS 完成后续 inode destroy/free。
- 原生父目录安装视图时，调用者持管理锁与 inode 引用，先完成空视图的 i_op/i_fop 发布，再发布 children。inode evict 先恢复原生表，再让原生 evict 继续；目录节点及代理仅在 RCU 宽限期后释放，节点不持原生路径引用。
- 目录按 fsuid 选择规则，使用 kpm_utils.h 的 task_fsuid 和已初始化 KP cred 偏移。compat cookie 复用 SDK 取得的当前 thread_info 及 TIF_32BIT，不新增 task/cred 偏移。
- 重验证在 ref-walk 中运行，LOOKUP_RCU 返回 ECHILD。使用原生 dget_parent/dput 稳定父目录引用，规则替换／删除和 UID 排除使已有注入缓存失效。
- 原生 dentry 操作表按完整字节与 NULL 形态共享不可变快照，CAS 发布后驻留。只替换 revalidate/weak，原生 release 及其他回调、d_fsdata 均保留。快照不保存可悬空的原表地址，不为每个条目分配回收对象。
- dentry 发布在调用者持有 d_lock 时计算最终 flags，先 release 写 d_op，再以一次 release 写 d_flags 发布调用标志；不得在操作表发布前写入新标志。`tools/test_dentry_publication.py` 检查生产 helper 的两处存储边界、原有 flags 语义及未插桩 ARM64 STLR 顺序；宿主检查不证明 VFS 并发。
- injected dentry 当前仅接新建、无原生私有数据且无需原生 d_init/d_release 的对象；其余返回 EOPNOTSUPP 并保持原表。普通 lookup 包装失败时摘哈希，释放原生 alias 返回引用，再传播错误。
- 枚举在 RCU 内复制名称与元数据，在解锁后调用原生 actor。保留原版 32/64 位 cookie；32 位索引超过表示范围返回 EOVERFLOW，缓冲区满时保持当前项的位置。普通父目录转发保存的原 iterate 回调，不再次取得同一 inode 的锁。
- inode 初始化器中的局部操作表可能带有不可预知的编译器后缀。查不到表名时，从入口固定窗口跟踪地址，先核对 i_fop 与 i_data 的共同几何，再用已确认的 open 槽和原生 no_open 回调核对表身份。读取须在已取得的核心镜像边界内；CFI 只跟随一条核心代码区内的直接 B。不得为了宿主夹具合成运行端不存在的查询别名。
- 完整表尺寸由静态配置、BTF或已核对的末端声明契约取得。动态模式无BTF时先探测同表回调几何，再计算尾部与最终对齐；未匹配契约时停止准备。回调字段和ABI核验完成后才能发布表。
- 纯虚拟目录复用原生 iget5_locked。预分配 info 的 rule/node 用于匹配；set 只设置私有信息和模块操作表。以返回 inode 的 i_private 是否等于本次 info 判断新建，完成初始化后 unlock_new_inode；命中旧对象时只释放本次未发布 info，不读取额外 i_state 偏移。
- iget 的 test 在原生 inode_hash_lock 内运行，也必须另持原生 RCU 读锁读取模块 info：原生 find_inode 会先调用 test 再检查 I_FREEING。回调内不分配、不等待宽限期。
- lookup 在 RCU 内取得规则与 this_dir 节点引用，再交给物化层。inode 新建时各取一份独立引用，evict 释放；d_splice_alias 消耗 iget 返回的 inode 引用。目录缓存匹配和重验证同时检查 rule/node 身份。
- 拓扑层发布 leaf.this_dir 前持有节点引用，摘除或替换后保留该引用至原生 RCU 宽限期结束，再释放。叶节点摘下后同样等待读者退出；这些引用归拓扑层管理。
- file 的 f_path/f_inode/f_op 是已比较七组声明的连续 32 字节片段，以现有 f_inode 偏移向前取得 f_path。虚拟目录枚举在 actor 调用前退出 RCU，点项的父目录用 dget_parent/dput 保有引用。
- 拓扑管理的 add/remove/clear 接口由控制层在进程上下文持原生管理 mutex 调用；nm_finish_topology_updates 在解锁后执行。实际 KPM 初始化包含完整控制入口；宿主夹具不证明原生锁竞争、keyring 或 VFS 并发。
- 新增规则先建立私有缺失目录链，并预分配最高边界的子项数组，再安装原生父目录操作表。安装成功后只做无需分配的发布。自动父目录总是新建私有节点；不能在缺失前缀探测后再次解析并采用原生节点，破坏未公开子树的边界。
- 原生 anchor 持有 path 和节点引用。再次添加时从 inode 已安装的操作表复用节点，不假定 path_put 会使 inode evict。节点还有子项或仍归目录记录拥有时保留 anchor；其余在管理锁内摘下，宽限期后释放路径。
- 删除最后规则时先确定可裁剪的自动虚拟父目录链，预分配最高边界替换数组；提交后清空所有摘下节点的 children，清除只供管理锁内使用的 owner。存活 inode 可继续持有空节点，历史读者退出后才释放叶节点和规则。
- 规则数组和子项数组的 build / publish 分开，拓扑层备齐全部输入后再发布；原有 set/insert/remove 接口继续共用同一构造器。失败保持旧数组，输入规则引用保留给调用者。
- 规范路径允许裁掉尾部斜线；拒绝根目录规则、空分量、点分量和超长名称。只有 ENOENT 被当作缺失父目录；其他原生解析错误保留。原生 d_hash_and_lookup 的错误在发布前处理，成功后对缓存目标 d_drop/dput，并调用 shrink_dcache_parent。

## 验证

v22 候选冻结前，Developer 显式运行 `tools/test_v22_sync.py --oracle-output <冻结 contracts 目录> --output <新目录>` 与 `tools/test_v22_module.py --output <新目录>`。前者重放双 ABI 业务夹具并贯通实际 CLI 字节与控制处理，后者重放安装/启动及 WebUI Node VM 用例。生成副本的协议迁移见 `Developer/proposals/2026-10-22-nomount-v22/README.md`；原 Oracle 文件保持不变，迁移待独立复核。这两项未接共享门禁，宿主自检不覆盖浏览器渲染或真实内核并发。

`tools/inspect_target.py` 生成单个目标的镜像、配置、符号和短函数入口清单。这是开发输入，不是运行时加载或安全结论。

`tools/test_layout.py` 执行生产偏移代码，输入指定镜像、符号表及有独立依据的参考值；检查实际偏移存储与访问器，并用合成 BTF 检查分派边界。仅缺查询接口或返回空数据时回退；内核返回的错误指针保留 errno，即使它也使用 `ENODATA`。

`tools/test_rules.py` 执行生产规则代码，覆盖 UID 回退、哈希碰撞、替换/删除、失败后旧状态保持、路径引用和 UID 分页。其原生接口夹具只检查调用契约；不证明并发、目录接管或应用扫描。

`tools/test_rule_layout.py` 用合成 BTF 执行规则层的共同前部核对。静态版的共同前部需要目标源码/访存证据；动态版先核对 BTF，缺必要类型或布局不一致时停止该层准备。

`tools/compare_structs.py` 对保存的上游 fs.h 和目标 fs.h 编译核对共同片段；范围限于片段及未重排配置，不证明完整类型或所有厂商布局。

`tools/test_file_layout.py` 执行真实目标的 simple_open/noop_llseek/nonseekable_open/file_ns_capable 小窗口，并检查生产 BTF/回调 ABI 分派。函数入口只证明对象字段；完整表大小和后续回调槽必须另有目标证据。

`tools/test_file.py` 执行实际只读文件回调，检查原生接口、写/异步请求拒绝、位置同步、错误返回、映射契约及完整表构造。其夹具不证明 native VMA、页缓存或冻结行为。

`tools/test_inode_layout.py` 比较 inode 操作表／映射、size／时间和 superblock 前部的共同声明；执行 BTF 必要字段和回调 ABI 拒绝边界。只有片段匹配才直接访问，后续回调 ABI 不匹配时停止准备。

`tools/test_inode.py` 执行实际普通文件物化、完整 super_operations 复制、发布竞争和回收路径，核对 backing 生命周期及失败清理。原生接口夹具不证明文件系统私有析构或 RCU 并发；这些还需独立审计和真机事实。

`tools/test_directory_layout.py` 比较七组 dcache 共同片段，核对目录回调 ABI、可选 iterate/d_init、release 槽和必要字段拒绝边界。4.4 的 dentry_operations 没有 d_init，release 槽不能放进共同片段。

`tools/test_directory.py` 完整运行已有 inode Oracle，并追加原生父目录查找、UID 缓存重验证、快照复用、原生 release 保存、枚举过滤与 cookie 恢复检查。其合成 SDK 输入只检查生产宏的调用契约，不代表目标上的 task/cred 偏移值；不证明原生文件系统、并发或 Android 扫描。

`tools/test_virtual_directory.py` 完整运行目录及 inode Oracle，再追加纯虚拟目录的新建／命中、创建与 splice 失败、别名返回、子项查找、点项续读、UID 筛选和引用回收。原生 inode 缓存由接口夹具代替，不能据此给出原生并发结论。

`tools/test_virtual_directory_layout.py` 比较七组 f_path 共同片段，编译匹配目标的五个函数声明，并执行生产 BTF 的外层及 iget test/set 嵌套回调 ABI 拒绝边界。动态 ABI 不匹配时停止准备。

`tools/test_topology.py` 完整执行虚拟目录／目录／inode Oracle，再检查自动建树、首次接管和缓存复用时的分配失败、规则升级与多 UID 删除、空目录裁剪、原生 anchor 保留、存活 inode 的空视图及路径引用平衡。路径和原生 inode 缓存使用接口夹具，不证明真实挂载命名空间或管理并发。

`tools/test_topology_layout.py` 保留既有虚拟目录布局 Oracle，编译核对匹配目标的缓存接口声明，并执行生产 BTF 的函数原型拒绝边界。

`tools/test_backing_directory.py` 完整执行既有拓扑 Oracle，再检查 backing 子路径引用、原生错误、名称边界、递归拒绝、点项编号、规则过滤、UID、缓冲区续读和 cookie／seek。另覆盖 file 已保存模块表而 inode 表仍为原生的发布窗口。接口夹具不证明目标权限、原生锁或并发。

`tools/test_backing_directory_layout.py` 保留既有拓扑布局 Oracle，编译核对目标 namei.h 的 vfs_path_lookup 声明，并执行生产 BTF 的参数数量、宽度、返回类型和缺符号拒绝边界。

`tools/test_backing_inode.py` 完整执行 backing Oracle，再检查真实共用目录回调的物化／缓存命中、alias、源读取权限、递归查找、显式覆盖、源替换／删除／新增后的重查、分配失败、普通文件 read_iter 转交及路径退役。初始化失败清理函数也执行检查。接口夹具不证明原生 ACL、CFI 或并发。

`tools/test_backing_inode_layout.py` 保留既有 backing 布局 Oracle，编译核对目标 inode_permission2 声明，并执行生产 BTF 的参数数量、宽度、返回类型和缺符号拒绝边界。

`tools/test_backing_subtree.py` 读取同一源码状态下 test_backing_inode.py 已生成的 Oracle 输出，先校验其工具与源码回执，再完整执行已有 Oracle，并接入子目录阶段。覆盖多个 UID 的来源继承、显式规则／缓存搜索权限拒绝、源暂缺／类型错误／原生错误、规则替换、自动父链分配失败、裁剪与引用释放、显式目录撤销后恢复来源。使用新的空输出目录；已有测试脚本保持原样。原生接口仍由宿主夹具代替，结果不证明真实 ACL、VFS 并发或实机。

`tools/test_control.py` 复用并完整执行匹配源码的子目录 Oracle，追加原生管理锁和 key_type 注册调用契约、权限／快照／短拷贝拒绝、32/64 位载荷、批次第一错误与截断游标、UID 命令、规则分页及导出清空后恢复。成功注册对象仅在宿主夹具结束时释放；生产成功路径驻留。此工具不编译联合入口的初始化函数，实际包含顺序由 ARM64 联合对象编译检查。

`tools/test_control_layout.py` 编译核对 4.4／首轮目标／5.15／6.6 的 keyring 连续片段，并从目标 mutex／spinlock／osq 声明与配置取得完整尺寸。ARM64 编译确认尺寸与位置；生产 BTF 检查字段连续性、数据类型、回调／函数 ABI、尺寸与 lockdep 拒绝边界。这些声明比较不是对应版本已完成适配的结论。

`tools/test_kpm.py` 校验并完整执行匹配源码的控制 Oracle，再执行实际 KPM 入口与控制构造器的加载阶段、注册冲突、七个分配失败点、状态拷贝和驻留退出。原生依赖准备及动态 BTF 在宿主中由接口夹具代替；真实 ARM64 ELF 的元信息、导入和寄存器另行检查。静态 JSON／blob 往返必须只修改76字节配置段并能还原原字节。

`tools/test_load_events.py` 复用冻结0.3.0的挂载上下文Oracle并保留621条断言，追加实际KPM入口在pre、post及手动加载下的成功、依赖／BTF错误、注册冲突、分配失败、状态查询与驻留行为。旧test_kpm.py的pre拒绝断言对应历史要求，保持原脚本；本轮加载契约另由新工具验证，须独立审计。宿主夹具不证明实际开机时原生依赖、CFI或BTF已就绪。

0.2.0 静态基线42项均为待填写值；表长84字节。新增 getattr_callback_args、getattr_function_args、kstat_inode_first、name_hash_args 四项独立选择，分别绑定回调原型、原生函数原型、共同属性片段及哈希函数原型；不按内核版本选择。必要值未取得或不受支持时停止初始化。BTF 按真实字段及函数原型填入，查询代码仍与短函数推导分开。

`tools/test_call_abis.py` 从冻结0.1.0控制 Oracle 的已登记输出取得完整断言，更新受影响的生产片段，显式补齐已核对的4.19夹具 ABI 输入，再追加两参函数／三参回调、属性字段字节边界及未知选择拒绝。原 assert 表达式逐项保持；原测试脚本保持原样。此夹具迁移不证明真实原生调用或动态 BTF 成功。

`tools/check_target_calls.py` 在 B2N 镜像的指定有界片段中核对字段与调用寄存器。其窗口和寄存器模式只覆盖已核对的目标；完整表尺寸另需目标配置／声明证据，不能把脚本通过当作通用布局保证。

目标配置通过根目录 `patch_offsets.py` 修改已构建二进制。配置值须绑定目标证据，基础实例与派生哈希一起交接。构建使用新输出，禁止覆盖已有 KPM；候选布局 JSON 使用单独的 `LAYOUT_DIR`，再附到相应归档目录。

新派生件统一生成到 `artifacts/binary-port/nomount/<派生 SHA-256>/<派生件名>`，目标身份写入元数据和回执。历史生成命令和交接记录保留原样；当前位置由维护者登记记录取得。

Android boot 输入按 boot 头的 kernel 段长度截取后解压。arm64 头的 `image_size` 表示有效内存范围，不能用它越过 kernel 段读取后续 ramdisk。原始 boot 和提取内核分别记录哈希。

候选从冻结提交构建，绑定完整提交、实例号和产物哈希。Developer 自检、Auditor 独立审计与 Tester 真机事实分别记录；不更改已有 Oracle 或借宿主 Mock 改变内核语义。

## 0.3.0 原生挂载上下文

- 以固定 NoMount LKM 的 `IDMAP_PATH`／`nm_getattr` 为语义参考：源读取／搜索权限取源path的挂载上下文；纯虚拟目录的fillattr取getattr回调参数；真实backing属性仍由vfs_getattr_nosec处理源路径。
- 配置表45项、90字节；新增permission_abi（0=Android mount三参，1=inode两参，2=user_namespace三参，3=mnt_idmap三参）、fillattr_abi（2/3/4参）、getattr_context_kind（0=path，1=user_namespace，2=mnt_idmap）。新增值默认未知，按实际类型和签名取得；数目相同不等于类型相同。
- 挂载上下文前部仅在目标BTF/声明核对后使用。带namespace/idmap的getter只读取相应成员；两参permission与旧Android接口不读取它。禁止以init_user_ns替代源mount上下文。
- 属性回调分别采用准确的三参、四参及两种五参类型；generic_fillattr保留准确的两参、namespace三参和idmap/request_mask四参类型。新接口的BTF查询仍在nm_btf.c，配置与验证在nm_offsets.c。
- 首批新增配置为Sony5.15、Android13/14的5.15及Android13的5.10；旧B2N和Sony4.19新增v3配置，旧JSON保持冻结。6.1的bool actor、6.6的file字段分离和6.12重排仍按未适配边界保留，不据新接口分派宣称这些目标已支持。
- test_mount_abis.py读取冻结0.2.0宿主Oracle，保留602条assert表达式及顺序，仅补旧目标新增配置输入，再追加权限／挂载上下文用例。test_target_layout.py对真实BTF运行生产查询，校验新接口的指向类型及错误拒绝；原生查询由宿主API夹具提供，不代替运行端证据。

## 0.3.1 候选

- 默认加载事件、配套ZIP与署名／许可改动登记为0.3.1，原0.3.0第一组候选和独立结论保留。Makefile、控制协议版本与ZIP module.prop同步，ZIP versionCode为301。
- 版本调整不改变45项偏移表、目标配置或加载实现。重新构建四基础件、14条目标派生记录及配套ZIP；审计和测试按新commit、实例及产物哈希绑定。
- 既有Oracle及历史报告保持冻结，版本／身份变更通过新记录交接，不改写旧结论。

## 0.4.0 目录回调

- 本轮扩展上限为 kernel_android14-6.1（6.1.176）；5.15保留已有离线适配，实机待设备恢复。
- 配置表46项、92字节，末项dir_actor_abi（0=int，0继续；1=bool，true继续），默认-1拒绝初始化。新配置使用-v4后缀；原45项配置、历史候选保持冻结。
- nm_dir_context共用16字节布局，匿名union分别声明准确int／bool函数指针。BTF核对返回类型INT的SIGNED／BOOL编码、宽度和参数，再选择接口；unsigned char不能代替bool。BTF查询仍在nm_btf.c，配置与调用归一化在nm_offsets.c。
- int转发保留原始停止值；bool停止转换为内部非零值，虚拟枚举仍返回0，让原生actor所属对象提供getdents错误。代理过滤器分别以准确返回类型入口转交共用逻辑。
- 缓冲区满时保留当前cookie，点项成功后才推进；隐藏项继续枚举，转发尝试后标记emitted，避免提前进入虚拟子项。实际CFI和VFS并发继续由独立审计／真机验证。
- test_directory_abis.py使用冻结的0.3.1加载事件Oracle生成物，保留640条assert表达式和顺序，分别执行int与bool契约。三个原生枚举夹具和输出actor按真实bool语义迁移，生产逻辑直接取当前文件；test_directory_btf.py在真实BTF夹具上追加编码、参数和pos位置反例。既有测试脚本保持原字节。

## 0.4.1 上游更新

- NoMount子模块冻结到7046c7ad3ee0bf4ae66e80f6b93b1e30db0cb4e3（master 2.1.1），用户态工具、WebUI、元模块路径脚本和源码包从该提交构建。固定SDK及46项配置表不变。
- KPM保持原有独立规则／inode引用及进程上下文退役实现；上游LKM的规则对象内联、path持有和call_rcu重构需要另作内核生命周期适配。已有发布前分配／安装、actor UID缓存及原生RCU边界按现有实现保留。
- 版本号0.4.1，ZIP versionCode=401。6.1仅有离线自检，缺实机；5.15设备暂时不可用。已有0.3.1真机结论不覆盖新字节。
- test_upstream_cli.py只替换上游架构入口及syscall接口，执行原版解析和JSON输出代码，覆盖列表错误、分页末页错误、转义／跨缓冲区输出和安装探测；Oracle脚本保持原字节。

## 0.4.2 主线查找优化

- 接入043ea665953e133c0306ffd7f4095a73b1b0254c的小目录筛选、27d4f0e16e581f2c9ad16321ee3a9891c503ebf2的UID预筛选及63193900c1b8c5a0a3efebd953cd4f1a1a18fd84的直接UID位选择；同用主线nm_qhash和名称比较。
- 子项<=2不分配Bloom，快速哈希筛选后精确比较。3及以上沿用完整名称哈希／排序表；重建函数在bloom_words=0时返回，2/3转换重新构造不可变快照。
- UID私有数组增加256位mask。ADD复制旧mask并置位，DEL从剩余UID重建，mask命中后仍检查完整UID。数组为空时可直接返回；非空对象只在原生RCU保护内重新取得并访问。隔离UID和多用户语义保留。
- 变化仅限模块私有数据，46项偏移配置及目标JSON不变。版本0.4.2，ZIP versionCode=402；SDK、上游gitlink、运行接口及规则引用／退役机制保留。
- test_hotpath_rules.py读取0.4.0冻结的int/bool目录Oracle生成物，替换受影响的生产函数和私有结构，保留每种645条assert表达式及顺序。新增碰撞、旧快照、删除重建、分配失败、UID边界和2/3转换检查；以夹具计数确认小目录查找不调用完整名称哈希，不将它写成实机性能提升。

## 0.4.3 私有内存

- nm_memory.c统一私有分配。1～1024字节先以GFP=0调用原生__kmalloc，按至少64字节的二次幂请求并清零；失败或大对象调用原生vzalloc。包装器仍要求可睡眠上下文，零大小返回NULL。
- 进程上下文由原生kvfree配对；RCU回调按原生is_vmalloc_addr区分，slab对象kfree，vmalloc对象vfree_atomic。原生memdup_user载荷继续kfree，路径及节点引用仍按原有生命周期释放。
- 7个已有目标核对新增原生符号。绑定缺失拒绝准备，不使用KP私有固定池；46项配置表保持不变。
- test_memory.py保留冻结0.4.2完整int/bool Oracle的所有断言。旧夹具采用slab未命中、vmalloc承担分配的合法后端；独立新增用例验证slab清零／对齐、阈值、回退成功、总失败及两种释放上下文。原有测试脚本保持原字节，结果不代表实机性能。

## 0.5.0 inode绑定

- nm_inode_info保存独立r_path、dir_node、类型flags、来源／初始化及链接清理状态，不保留管理rule引用。物化时原生path_get，目录候选另取node引用；新inode接收，iget失败／命中缓存释放候选引用。普通文件在new_inode成功后取得path，避免失败多取引用。
- evict在进程上下文释放path/node，RCU只释放info内存。管理规则引用及批次退役保留；inode不增加规则refs，规则撤销后可直接释放，已打开文件继续使用其独立path。
- 目录iget按node散列，同path/mount、node、flags才可能命中；initialized前由原生iget等待初始化，完成后核对共同nm_inode_owner_prefix的mode/uid/gid。此状态属私有结构，避免新增原生i_state偏移。属性核对从调用者保活的path读取，RCU退役的info只比较指针与私有字段。
- dentry重验证核对相同绑定与虚拟ino，来源或属性改变失效；自动父目录与不满足正项复用判据的继承对象仍重查。open／getattr／fallback／源搜索权限均改用独立path。
- test_inode_binding.py从0.4.3冻结Oracle迁移全部693条原断言，673条保持表达式及顺序，20条改变仅涉及私有字段、inode不再增加rule引用、独立path释放和node散列；原文／新文逐项记录回执，需Auditor复核。旧脚本保持冻结。/new替换夹具补不同dentry，保留来源变更失效的原断言。
- 新用例检查规则真正释放后的open/read、同来源缓存复用、mount/node/flags不匹配、mode/uid/gid变化、新inode初始化等待及路径／节点引用平衡。46项配置与原有七目标范围保持不变；宿主自检不替代实机VFS、ACL及CFI结论。

## 0.5.1 安全标签

- nm_security.c经原生security_inode_getsecctx/notifysecctx/release_secctx复制每个新inode的独立安全上下文；模式先初始化，再由LSM确定对象类。普通文件／backing目录取源inode，纯虚拟目录取实际父inode。保留原生security分配／释放生命周期。
- 获取上下文在进程上下文、iget/hash锁及模块RCU范围外；新inode由初始化者独占，目录I_NEW阻挡使用者。notify返回成功后仍检查security_inode_getsecid，拒绝实际SID不一致。接口缺失、标签不可取或复制失败均传播错误。
- 私有info保存来源SID及初始化错误。缓存test只读非分配的getsecid快照；新候选SID不同即不复用。ref-walk dentry重验证比较当前源／父SID，源重新标记后旧视图失效。
- 目录初始化失败记录init_error、release发布initialized并unlock_new_inode；已在test命中的等待者唤醒后检查错误，iput其引用并传播错误。失败inode保持模块evict回调，独立path/node在进程上下文释放；新查找拒绝失败缓存。
- test_security_context.py使用冻结0.5.0的735条int/bool Oracle，733条保持原表达式和顺序，2条仅增加来源SID参数并逐项登记。旧测试脚本保持原字节。新增真实SID不同、源／父改标签、复制无效成功、分配失败及I_NEW等待者错误清理；原mmap的S_PRIVATE契约保留。
- 46项布局表及七目标配置保持原样。版本0.5.1，ZIP versionCode=501；WebUI仅在生成副本中把四处空列表表情替换为_(._.)_，上游gitlink保持冻结。
- root或UID变化后的magisk域读取不能证明普通应用/ART域可读。修复验收须覆盖目标虚拟路径标签、artd读取以及真实应用进程的APK/DEX加载；PackageManager登记与启动分别记录。

## ZIP 0.5.1 计数修订

- 启动根目录读取APatch的MODULE_DIR后去掉末尾斜杠，再拼接模块目录。rule-paths和上游gitlink保持冻结；内核规则仍按原生路径语义工作。
- WebUI生成副本的parseRuleList仅归一化来源路径的重复斜杠；首页、模块列表和卡片刷新共用此入口，保留原版按规则来源计数的逻辑。已在内核中的双斜杠规则也能显示。
- ZIP沿用0.5.1版本，按新源码指纹登记新的独立Build ID/实例；KPM沿用cfb971d195d997808b68567b8ffc61a4dcd32b90构建的已冻结字节，正在进行的实机记录继续绑定原KPM/ZIP身份。ZIP界面修订另行核验。

## 0.5.2 名称与构建

- KPM登记名与产物前缀使用NoMount；项目目录、ZIP内部id和keyring类型保留nomount。API探测经keyring，管理命令按NoMount名称操作。
- Makefile仅提供dynamic/static两种产物，all生成两件；普通日志均经nm_log.h的nm_log_info/nm_log_error输出，保留INFO/ERR等级和初始化偏移诊断。既有debug归档与独立记录保持原样。
- 上游Git子模块仍为配套ZIP的实际源码输入：nm、WebUI、路径及安装脚本、源码包与许可证从冻结Git对象取得；KPM编译器不包含上游LKM源码，用户安装二进制无Git依赖。

## 2.1.1-20261014 发布约定

- 版本采用上游元模块版本加本轮日期，与 rek/rekx 格式一致。KPM Makefile、NM_KPM_VERSION 和 ZIP version 同步；ZIP versionCode 使用 YYYYMMDD，保持普通整数范围。
- ZIP 文件及显示名为 NoMount-kpm，内部 id/keyring 类型仍为 nomount；用户可覆盖更新已有安装。KPM 管理名称保持 NoMount。
- Actions 分别构建 KPM 和配套 ZIP，再由统一发布任务收集。ZIP 使用固定 NDK 26.3.11579264，在 Linux runner 显式指定 linux-x86_64；build_zip 从同次干净提交和冻结 gitlink 读取实际输入。
- release_zip.py 负责发布目录的 ZIP 副本、独立清单及哈希；合并发布前核对 KPM/ZIP 的完整 source_commit 和 NoMount 版本。最终 SHA256SUMS 包括两类发布文件，BUILD_MANIFEST 保留 KPM 信息并追加 companion 引用。
- 用户侧安装／VFS业务保持现状；本轮只更改版本字符串、配套显示名、打包文件名和发布流程。已有审计／实机结论绑定旧实例，新实例需经轻量差异复核后由维护者验收。

- ZIP 文件名为 NoMount-kpm_<版本>.zip；module.prop 的 updateJson 指向正式 Releases/latest/download/NoMount-kpm.json。发布时读取包内 version/versionCode/CHANGELOG，生成更新 JSON 和更新说明，下载 URL 绑定实际发布标签和版本化文件名。未发布的工作树不维护在线更新 JSON。
- 更新信息遵循 KernelSU module.prop 的 updateJson 入口及通用四字段格式（version、整数 versionCode、zipUrl、changelog）；id 不变。规范来源：https://kernelsu.org/zh_CN/guide/module.html 与 https://topjohnwu.github.io/Magisk/guides.html。
- 正式发布每轮使用新标签：release-action 开启 immutableCreate 和 artifactErrorsFailBuild，来源 commit 使用 github.sha；已公开标签不做资产覆盖更新，避免更新 JSON 与 ZIP 分批替换形成失效入口。

## 非 BTF 共同布局

- 共同定义可覆盖的片段直接复用。短入口验证只确认定义能用于运行目标，不为片段内每个字段重建偏移。
- `path`、`dentry` 前部仍使用 nm_structs.h；规则入口核对实际 path.mnt、path.dentry 与 dentry.d_inode 基址链。
- 两目标的 i_fop／i_flctx 连续，用 nm_inode_file_locks 表达；inode_init_always 取得 i_fop 起点，并核对 i_data 紧随这段。完整 address_space 尺寸从 address_space_init_once 的首个 memset 长度取得。
- kstat 使用两个已核对的前部与时间／blocks 片段。generic_fillattr 的 mode／uid／gid 读写确定格式，未匹配或两组同时匹配时失败；不按版本号选择。
- 整对象复制／清零长度共用有界识别，tty_default_fops 为7条，address_space_init_once 为8条。源对象语义、调用目标和参数状态分别绑定；未知指令失败。
- 原生 inode／super／dentry 操作表的完整复制范围继续需要目标证据。共同前部、最高已访问成员或相邻静态符号间隔不能替代完整尺寸。
- `ext4_drop_inode` 前12条核对已取得的 nlink 与后续 hlist.pprev 检查；hlist 的连续定义用于取得 i_hash 起点。窄加载及 inode 保存不得覆盖仍需使用的基址或待测值。
- `vfs_getattr_nosec` 的 mount/dentry/stat 入口限12条，path/stat/mask/flags 入口限29条；同时用 `simple_getattr` 首9条核对参数及首个 generic_fillattr 调用。只支持实际匹配的回调／原生 ABI；回调槽取得后仍需完整 inode／super 操作表校验。
- mutex 使用两份已核对的完整无调试定义，`__mutex_init` 的7／10条初始化与返回逐条匹配后使用对应 sizeof；匹配结果缓存到布局表。此证据只用于 mutex 与4字节spinlock形态，不能推出整个内核的LOCKDEP配置或key_type尾部。
- `user_preparse` 前11条核对长度范围、data非空及data／datalen连续关系；分支必须向前跳至同一拒绝块。有效BTF错误继续保留，完整控制校验仍要求key_type尺寸及回调。
- lockref的lock／count与d_op连续，确认4字节spinlock后直接以已有d_op起点复用片段。目录枚举槽从完整file_operations范围内的唯一dcache_readdir取得，并与iterate_dir首12条共同核对iterate／shared形态；完整dentry表、回调与actor ABI另行取得。
- 条件分支的方向和目标距离使用kpm_utils.h的有符号字节位移，不以原始imm19的非零值代替向前分支。
- `__dentry_kill` 前23／17条核对DCACHE_OP_PRUNE、原生调用及参数链；release／prune连续片段共用，init是否存在由实际槽与共同前部的间隔取得。`empty_dir_readdir` 前30／20条核对actor的6个实参及int返回约定，保留未覆盖ABI的拒绝。
- `generic_shutdown_super` 前35／25条先锚定sb和s_op，callee-saved x19／x20跨原生BL保持；只接受明确白名单和security释放的小型前向分支。取得put_super后共用连续drop／evict／put片段，完整super操作表尺寸仍独立确认。
- `inode_permission` 首7条和`inode_permission2` 首8／4条核对mount／inode／mask ABI，原生调用目标与表回调共用有界单B跳板识别。CFI拒绝分支必须跳过当前调用，跨度由各调用点提供。
- key_type的name／def_datalen、三个必备回调及link合计至少56字节；只在key_type_user的这段可读前缀内匹配唯一连续回调组。register_key_type前18／19条核对name@0，key_instantiate_and_link前22／26条核对def_datalen@8及preparse槽；三项代码指针复用单B跳板核对。这个下界只约束扫描，完整尺寸另取，未匹配形态拒绝。

## 自建操作表容量

- 精确尺寸由nm_operation_size读取；nm_owned_operation_size仅服务原表为NULL的新建清零表。BTF明确不可用时，inode／dentry／key可使用512字节容量，已知尺寸优先；有效BTF错误仍失败。
- 512来自已核对ARM64声明的保守预算：inode不超过256、dentry不超过192、key含lockdep预算不超过200字节。它不是原生sizeof，也不是未来任意厂商扩展的保证；增加支持范围时重新核对声明。
- 原生inode／super／dentry代理的复制、比较及完整范围校验继续使用精确尺寸。容量只扩大目标存储，不扩大源读取；发布前按已核对字段与ABI填写回调，驻留生命周期保持。
- virtual-directory、topology、backing-path三个准备阶段在BTF不可用时使用已核对的共同原生声明；变化的fillattr、permission、actor ABI仍须取得，符号绑定仍逐项检查。

## 操作表末端尺寸

- `nm_structs.h` 的inode尾部从getattr起，super从drop_inode起，dentry从release起；片段保留自然对齐，完整inode／dentry表的64字节对齐另算。支持范围为前述Sony声明与Nokia语义参考，不代表任意厂商追加尾部均已确认。
- BTF明确不可用时，`nm_prepare_operation_sizes`先执行所需字段探测，再从set_posix_acl首13条、super_cache_count旧形态最坏27条（13／17／21为特定成功分支），VFS形态含可选PAC前缀最多27条，取得set_acl与nr_cached_objects。后者与free_cached_objects连续，避免扫描较长的super_cache_scan。
- sdcardfs两符号齐全时保持112字节前缀主路径；单符号残缺直接失败，主路径解析失败不穿透。仅两符号皆缺时，从d_set_d_op最长47条取得d_real，使用独立的无umount_end／独立canonical加四预留槽联合契约；锚点来源写入状态与日志。d_real可得不证明未知尾部，AUD-001仍open。
- 尾部选择同时核对iop.getattr→set_acl、sop.drop→nr_cached及drop→evict、dop.init／release→canonical关系；使用片段的sizeof／offsetof计算完整尺寸。三项范围全部有效后写回，原表复制／比较继续使用所得完整尺寸。
- 已知声明几何不能证明隐蔽的未使用厂商尾部不存在；`AUD-001`仍开放，候选发布前由独立审计评估这一支持契约及key新建容量边界。
- `tools/test_operation_extents.py`在原动态准备夹具生成后追加新窗口和用例，原工具及原断言保持；验证两目标三项尺寸、后续全部布局准备、BTF路由、冲突拒绝及112字节保护页边界。宿主准备通过不等于原生注册或完整初始化通过。

`tools/test_inode_storage_lookup.py` 在已执行原断言的操作表尺寸夹具上，追加真实局部符号名称用例。核对两个目标的 inode 存储字段、缺符号／边界／回调时拒绝、初始化器未知指令与保护页边界；它只执行布局准备，不证明原生注册、CFI 调用或真机加载。

## 代码区间符号

- 初始化局部表识别先核对代码末端位于已取得的镜像区间。`_etext` 保留链接地址而不在该区间时，改查已重定位的 `__start_rodata` 作为代码读取上界；起点、末端和表边界仍须有序，缺证据停止准备。
- `test_inode_code_bounds.py` 在 B2N 真实表名夹具的全部原断言之后，追加链接地址与重定位地址分离、缺边界、倒置及越界用例。实际符号值来自目标镜像及 Tester 记录，不把宿主统一平移模型当成所有符号都会重定位的保证。

## 新增镜像适配

- `local/nomount/configs/kernel_mi6-4.4-v4.json` 绑定米6镜像；其三类操作表符合已有4.4尾部契约。厂商声明用于解释共同片段；不同于目标指令的字段逐项记录，不能把参考源码称为准确构建源码。`tty_default_fops` 的完整复制／清零长度优先于参考声明的大小。完整复制范围仍待核对的目标只保留本地草稿，不能按版本号或build-id填值后交接。
- 米6的两种新增GCC形态分别读取register_key_type前19条、super_cache_count前13条。原始type、链表容器、shrinker→sb→s_op及回调实参链均须确认；`test_gcc_layout_shapes.py` 使用真实窗口及保护页核对。
- 原生is_vmalloc_addr不存在时，`nm_offsets.c` 从kvfree首14条核对保留x0的入口、两次无符号地址比较、完整范围常量和原生vfree／kfree分派。范围同时用于两种模式的私有分配释放，不写入结构体偏移表；未知形态仍拒绝。RCU回调继续把vmalloc对象交给vfree_atomic，slab对象交给kfree。`test_vmalloc_range.py` 覆盖独立函数、内联范围、缺依赖和保护页。
- 新增目标的静态配置和动态准备覆盖分别记录在开发报告；静态件可用不代表动态解析已经覆盖同一编译形态。

## 目标末端锚点与参考尾部

- 成员位置、整对象复制／清零长度优先取自目标机器码；厂商公布的源码用于解释字段和连续尾部，不能作为整份布局的准确副本。源码提交标识只记录参考来源。
- 离线工具 `tools/derive_operation_tails.py` 分别从 `set_posix_acl`、`super_cache_count`、`d_set_d_op` 和 `unregister_key_type` 取得 set_acl、nr_cached_objects、d_real、link。d_real 以 DCACHE_OP_REAL 标志链确认，link 以同一节点 next／prev 的自指写回确认。
- 完整尺寸按“目标锚点偏移 + 含锚点的连续尾部宽度，再按类型要求向上对齐”计算。源码只提供锚点之后的指针、预留槽、空 lock_class_key 和最终对齐；条件宏必须与目标 IKCONFIG 核对。未知尾部声明停止分析。最高已访问成员自身仍只给出下界。
- 米8、米9的参考 cache 宏链为128字节，米10、米11和Android12-5.10为64字节，并核对目标原生表地址。米8／米9的 inode_operations 因此为256字节；不能沿用统一64字节对齐模型得到的192。原生地址对齐只能交叉核对要求，不能单独证明完整尺寸。
- `nm_directory_proxy`／`nm_dentry_proxy` 的表头按128字节对齐。第二份快照的位移仍按目标完整表尺寸取整；128字节要求的目标，其表尺寸也为128的倍数。分配、反查私有头部和完整快照由 `test_proxy_alignment.py` 追加验证；历史断言保留。
- 米8、米9、米10、米11、Android12-5.10 的 `local/nomount/configs/*-v4.json` 是离线静态适配；动态模式尚未覆盖这些目标的完整无BTF编译形态。其余八份目标的动态覆盖边界沿用本轮之前的记录。
- `test_tail_derivation.py` 用真实短窗口及断链、错标志、未知尾部反例检查解析；参考尾部仍是支持契约，隐藏厂商追加字段不能仅凭这些窗口排除，独立审计与实机验证继续分别记录。


## 文档分工与加载接入

README 仅写普通用户的文件选择、界面操作和可见状态；加载差异、偏移、路径、时序、排查与发布配方放本文件及 [配套工程约定](module/AGENTS.md)。README 的更新记录保留原文与原顺序。

- 动态 `NoMount.kpm` 在加载时获取目标布局；静态 `NoMount_baselines.kpm` 是移植模板，须按目标镜像适配后加载，同名 `.kpm.json` 与基线绑定。实际 KPM 文件名带版本号，管理名称均为 `NoMount`，每次只用一份。
- 目标为 Android ARM64，适配范围 4.4～6.1；6.1 只有离线适配。同一内核版本的其他设备仍须独立确认，没有 BTF 的设备可能需要静态移植。
- 嵌入件随 boot 管理；安装方式由运行端 KP 从 `/data/adb/ap/kpm/nomount/nomount.kpm` 读取，在 `post-fs-data` / `before` 阶段加载，先于配套规则发布。运行端须支持该目录机制。
- 安装方式的技术判定共同核对 `load_source=file`、`load_event=post-fs-data` 与对应目录加载日志 `rc=0`；只有文件来源字段不能单独证明本次开机自动加载。
- `/data/adb/ap/kpm/nomount/disable` 仅阻止下次目录加载，不卸载当前 KPM，不影响 boot 中的嵌入件；替换安装文件需重启，嵌入方式更新须替换 boot 中的模块。成功初始化后驻留到重启，不执行热卸载。
- OTA 保留 userdata 时通常保留已安装文件，但内核、KP 与布局契约须重新确认，不能据文件仍在认定兼容。
- 本轮 Sony Xperia 1 II / Linux 4.19 / KP d09 / 指纹 `508d47da` 验证了安装、无 BTF 动态准备与配套发布；5.15 未测，文件添加夹具与隐藏已有文件的覆盖分别记录。身份与证据见 `Developer/reports/2026-10-17-nomount-install-path-docs.md` 的身份表与引用。


## 2026-10-20 VFS入口扩展（阶段实现）

- 当前新增范围为米8 4.9、米9 4.14、米10 4.19、米11 5.4、Android12 5.10。每次取得字段、完整表尺寸和原生ABI分别核对，组件准备不等于完整初始化。
- 基础字段识别支持准确PAC前缀；GCC的kstat字段按实际序列在前20／23条内取得，旧Clang窗口不扩大。哈希函数区分GCC长度检查和Clang清零／重排，旧path_open包装同时核对path复制及dentry→inode来源。
- 新inode初始化器的固定前20条（有PAC时多1条）追踪参数保存、ADRP／ADD及no_open表身份。已核对五目标的fop／flctx／i_data连续声明，按共同片段取得相对位置；旧入口仍要求原有显式mapping交叉检查。FP及SCS改写清除相关地址来源，未知调用／原子指令拒绝。
- address_space的完整memset仍优先读原生长度参数；新增GCC 24条和PAC 27条内联整对象清零形态，验证零覆盖、缺口补齐和后续原生锁调用，不能按最高单成员写入猜尺寸。两形态分别覆盖160／224字节，支持范围绑定已核对的初始化语义和声明。
- 目录迭代槽由实际调用者及simple_dir_operations回调双向确认；共同片段分别覆盖无iopoll及插入iopoll的形态，iterate与iterate_shared连续。权限入口按NULL mount包装／原生inode两参的数据流区分，核对inode_permission2／__inode_permission2／generic_permission实际目标，不按版本号选ABI。
- `Developer/tools/verify_nomount_vfs_matrix.py`对明确选择的镜像执行生产代码、参考比较、逐指令反例和保护页；它同时记录所有未覆盖阶段。当前米8／米9／米10验证40项，米11／Android12验证34项，五目标的hash另作直接验证。
- super生命周期新增25／27／35／45条入口，核对原始sb、s_op及put_super实参；仅支持不改写保存对象的前缀，条件分支必须越过回调，未知指令拒绝。CFI只接已观察到的2／3位旋转，LDAR识别统一放公共工具头并区分LDXR／LDAXR／STLR。
- 五目标的dentry生命周期／actor及完整inode／super／dentry表准备仍未覆盖；米11和Android12的getattr入口也未覆盖。缺少必需尺寸时继续拒绝完整准备，不能发布为五目标动态兼容件；既有静态配置保持原样。

## 2026-10-20 VFS回调补充与尺寸证据

- 五目标的dentry init／release／actor均已接通。GCC入口只读前13条与DCACHE_OP_PRUNE前向分支的6条块；分支位移限制384字节，目标在已确认代码范围，且回跳到原flags检查。其它形态分别为17／24／27条，Android的lockref置dead为内联原子读取及count=-128写回。
- empty_dir_readdir按已确认的pos==0路径核对actor、名称长度、DT_DIR、inode编号及32位返回检查，包含CFI旋转2／3位；保留旧形态及其错误语义。
- 米11的getattr固定47条核对memset、保留的path／stat／mask／flags及交错CFI；Android12固定42条核对内联清零和属性标志、原始path／stat／mask及CFI。其simple_getattr前11条与generic_fillattr的两参字段复制交叉确认。前三份原getattr路径不变。
- 新尺寸证据读取器独立核对set_acl、nr_cached_objects、d_real及list_lru_node数组步长。最后一项来自list_lru_count_node的5／7条完整短函数：原生node数组索引、末端nr_items和RET，取得64／128字节对齐；不是相邻全局符号距离。memcg node的已核对自然片段48字节，最终对齐另由数组步长给出。
- 尺寸读取器目前只供明确选定目标的离线证据执行，不接入完整尺寸接受调度。原native字段位置与相同对齐，仍可能对应含／不含KABI预留槽的不同sizeof；五份的inode／super／dentry完整尺寸仍保留未知哨兵，完整准备拒绝。
- 新矩阵入口为`Developer/tools/verify_nomount_vfs_completion.py`：先原样运行上一轮矩阵，再追加43项参考比较、回调／末端锚点反例、保护页与未知尺寸拒绝。旧Oracle及断言不改；静态v4尺寸依赖目标IKCONFIG和已核对尾部声明，不能据此声称动态尺寸已经获得。


## backing符号链接接口

- 现代get_link使用vfs_get_link；vfs_readlink不存在时以generic_readlink接readlink槽。旧follow_link/put_link以generic_readlink进入模块回调，再传backing dentry/inode；两种都保留原生用户复制、errno及清理语义。
- 源readlink槽按已核对前部及permission ABI/getattr联合几何取得：Android mount型readlink@40，getattr@128或follow型@144；原生inode/namespace/idmap型readlink@32/getattr@112。不扫描表取偏移；有效BTF独立核对槽/原型，缺API/数据才用声明。静态46项/92字节配置保持。
- 源readlink只接受已知generic_readlink，或现代原生vfs_readlink可处理的NULL默认槽；未知自定义readlink即使get_link已知也拒绝。资格检查在物化及跟随前执行，不调用未知回调。
- 现代正向身份为simple_get_link、page_get_link、f2fs_get_link、ext4_encrypted_get_link、f2fs_encrypted_get_link及其具名入口；CFI仅核对有效核心区间内至已知函数体的单B（可带BTI C）。未知回调/跳板在调用前拒绝。
- 旧接口整对核对simple_follow_link+NULL、page_follow_link_light+page_put_link、ext4_encrypted_follow_link+kfree_put_link；清理配对在可能睡眠的分配/安全入口前校验并捕获，指针在inode info中固定。源安全检查在follow前执行，错误由原生回调自行清理，错误cookie不再交给调用者。成功cookie在外层path_put前用源inode和捕获的put清理。
- 链接独立表纳入virtual识别/getattr/evict与失败清理。清除IOP_NOFOLLOW，保留原生空i_link及自己的i_data；RCU回调先返回ECHILD。相对/绝对字符串、解密或缺钥匙编码结果原样交给VFS，不自行解密。
- backing枚举保留原生DT_LNK/DT_UNKNOWN，受管理子项的d_ino与lookup相同按父编号/名字计算；blocked UID及点项语义保持。actor仍在模块RCU之外调用。
- Developer依次手动运行test_link_interfaces.py、test_link_consistency.py：后者保留前者963处断言及顺序后追加源readlink资格、路径/FD属性、枚举编号及cookie退役用例。test_link_prefix.py与test_link_readlink_layout.py核对6份声明前部及真实/合成BTF源readlink槽。既有8份BTF/80项负例与12份静态配置回归继续执行。测试未接共享门禁；宿主直接回调不证明原生syscall、CFI、实际解密、O_PATH建立或并发。


## xattr读取入口

- `nm_xattr.c`接原生vfs_getxattr/vfs_listxattr，以及经BTF确认存在的独立do_get_acl；对三类自建inode，将dentry及get的userns/idmap改为info持有的源path；普通inode和纯虚拟目录直通。原生函数继续执行权限、LSM（含security.*捷径）、handler分派与errno；模块不自行解释/调用未知文件系统回调，链接的正向资格核验不变。
- get支持已核对的plain四参、userns/idmap五参，list为三参。有效BTF逐项核对参数数目/宽度、具名dentry/context与返回值；BTF不可用仅沿已核对的plain/userns共同契约。静态仍46项/92字节；idmap新接入要求BTF，未知形态拒绝ADD。
- 控制key成功注册后才标记驻留。首次ADD在管理锁内完成所需接入（普通get/list及存在时的独立ACL），全部成功后才调用拓扑发布；版本查询与DEL不触发。部分成功保留且ready为false、回调直通；后续ADD只重试未成功的一处。当前SDK没有在途撤钩同步，不以失败回滚释放这些已发布代码；它们与控制key同样驻留到重启。
- 原生调用者持有外层dentry/inode，info的独立源path覆盖可睡眠调用。源为自建inode/循环、绑定损坏或源上下文为空时，在原生调用前拒绝；不查当下规则代替已打开FD的绑定。每次读取不分配、不调用管理锁、不取额外path引用。
- `tools/test_xattr_read.py`保留链接轮989处宿主断言及顺序再追加路径/FD、原生错误、注册失败/部分成功与阻断发布夹具；SDK参数帧直接读取当前hook.h声明。`tools/test_xattr_read_btf.py`保留8份真实BTF的原断言后追加读取ABI负例。Developer候选自检手动调用，未接共享门禁；不把原生桩称为真实LSM/syscall/CFI或性能证据。
- 独立ACL入口存在性同时核对BTF与原生符号；原型/上下文未知、同址别名或证据冲突时拒绝。独立入口无静态契约时拒绝；旧共享契约中的无入口形态沿get处理ACL。`test_xattr_acl.py`在1021处断言后追加第三入口失败/重试和access/default路径/FD实参；`test_xattr_acl_btf.py`追加真实入口及签名反例。
- 当前完成get/list及已证独立ACL读取侧；setattr与setxattr接入下述A档契约。ATTR_SIZE由M2单独处理，普通文件M1写入见下述句柄契约。AUD-001仍OPEN。

## 属性修改的 A 档权限契约

- 属性与安全标签仍沿维护者 `docs/records/2026-10-23-setattr-permission-semantics-ruling.md` 第五节A档保持快照：模块不主动刷新全存活别名。动态版在下述 DAC 委托能力具备时，新的 permission 决策读取绑定源的 DAC，而不是虚拟 inode 的旧 mode/uid/gid；能力未启用的目标和静态版保留既有行为。源安全标签仍没有全别名刷新协议。`DEV-055` 的剩余直接字段读者与真机验证另行交接。
- 快照指虚拟 inode 缓存的 mode/uid/gid 与安全标签，不是所有系统调用结果的快照。getattr 仍读取绑定源属性，可能返回新 mode；路径重验证可以丢弃旧 dentry、后续物化可取得新属性，已持有 FD 则继续引用旧 inode。源文件系统及安全回调的原生返回值仍须保留，不能承诺源撤权后每一次操作都会成功。
- 成功setattr会回写发起修改的那个虚拟inode的mode/uid/gid/size/times；所有引用该同一inode的FD自然共享更新。其它别名inode，以及直接在源侧发生的属性变化，不主动同步；LSM标签没有刷新协议。上面的快照语义不表示发起修改的inode永久保持旧mode/uid/gid。
- A档锁序为VFS调用者已持有的外层inode锁→源inode锁。源锁使用已核验的可失败原生接口；获取失败原样返回且不解锁，成功获取后所有返回路径配对释放。源是外层自身或模块自建inode时拒绝递归。只调用目标ABI已确认的notify_change/notify_change2，不自行调用未知文件系统私有回调。
- **跨mount弱语义**：回调不取得源mnt_want_write/drop_write，只依赖VFS调用者已持有的外层写引用；同sb重取会与freezer互等。跨mount时并没有源侧writer/freeze屏障，只能保留源notify_change与文件系统自身实际提供的检查。notify_change没有通用只读/freeze保护；模块在源锁内另用已确认的__mnt_is_readonly检查当前MNT_READONLY/SB_RDONLY状态，先拒绝EROFS再进入修改，不能隔离随后remount-ro的竞态，也不能宣称完成完整源写事务。
- nm_setattr.c接普通文件、符号链接及有源目录的setattr槽。动态版仅在目标BTF确认源锁位置/类型、ia_valid、回调与原生helper原型后启用；有效BTF冲突保留错误，缺失数据/符号时属性修改拒绝。静态46项表尚未提供源锁证据，setattr返回EOPNOTSUPP，已有读取能力保持。未知/负布局在调用前拒绝，不按版本猜偏移。
- namespace/idmap回调使用绑定源mount的上下文，但要求与调用者上下文相同；不同映射下iattr已转换的UID/GID尚无重解释契约，返回EXDEV。ATTR_SIZE按下述M2契约转交；MODE/UID/GID与SIZE复合在源锁前拒绝。普通文件M1写入不通过该属性支路。纯虚拟目录无源时返回EOPNOTSUPP。

## setxattr 的 A 档入口契约

- 按同一裁定第六节，`nm_xattr_write.c`在完整vfs_setxattr取锁、权限与LSM检查之前换绑源dentry；原生函数自行取得源inode锁、执行trusted.*的CAP_SYS_ADMIN与security.*的LSM检查、handler分派及CREATE/REPLACE，不调用noperm或私有handler。路径/lpath与FD使用相同入口及inode绑定，不查询当前规则替换held-FD来源。
- **跨mount弱语义**：回调不取得源mnt_want_write/drop_write，只依赖VFS调用者已持有的外层写引用；同sb重取会与freezer互等。没有源侧writer/freeze屏障，也不隔离随后remount-ro竞态。转交前用已确认的__mnt_is_readonly查询当前源MNT_READONLY/SB_RDONLY状态，先拒绝EROFS再进入修改；不能宣称完成完整源写事务。此限制独立记DEV-056，OPEN；DEV-055的held-FD快照限制仍OPEN。
- 新写入口由BTF核对plain五参、userns/idmap六参及具名dentry/context、参数/返回宽度与只读helper原型；mapped要求调用上下文与源mount相同，否则EXDEV。源绑定损坏、未初始化、负布局或循环在原生调用前拒绝。原生源path引用覆盖整个可睡眠调用，不额外取得锁/分配；不刷新虚拟inode权限或安全标签快照。
- managed security.capability到达转交入口时EOPNOTSUPP，避免写入可能已按外层对象转换的载荷。旧形态可能在hook前已返回原生EPERM/EINVAL，不承诺syscall一律EOPNOTSUPP。该名字在取得转换层证据前仍属未完成项，其它security.*保留原生LSM。
- 独立do_set_acl写支路单独核对具名原型/符号存在性，存在时在ACL解析与原生锁/权限/LSM之前同源换绑；不从普通入口推断全名空间覆盖。缺失或不一致证据时拒绝ADD，不按版本猜原型。
- 控制key驻留后的首次ADD先激活读族、再激活写族，全部安装成功才发布规则。部分写hook保留、ready=false且managed修改拒绝；下次只补未成功hook。静态表没有新转交证据，已核对的plain/userns入口只用于EOPNOTSUPP拒绝；未知形态/独立ACL无证据则拒绝ADD。旧静态46项表不变。无BTF动态目标仅在源锁已准备、context=0、无do_set_acl且nm_xattr_signature.c的36/24/11/8条真实形态全部一致时启用plain5：同一entry dentry的锁链、locked权限/安全调用链及readonly完整短函数交叉核对；未知或冲突保留拒绝。context=1/2无BTF路径未覆盖。
- Developer手动运行`tools/test_xattr_write.py`、`tools/test_xattr_write_btf.py`、`tools/test_xattr_plain5.py`及12份静态配置回归；旧业务断言只追加，工具未接共享门禁。宿主权限/LSM模型不能代替原生syscall、SELinux、CFI或并发freeze/remount的实机验证。


## xattr 删除与 syscall 列表入口

- 动态版首次ADD在读取族、写入族之后准备`nm_xattr_extra.c`，有完整证据时两个新hook全部安装并发布ready后才发布规则；部分安装保留供重试，managed请求在ready前拒绝。BTF明确不可用、无独立删除ACL且旧follow共同几何已确认时，若源锁原始推导结果仅为不支持／缺来源，可关闭extra而继续建立只读规则：ready保持false，set沿既有拒绝hook，remove由已核对的原生空槽前置拒绝；handler型删除不沿用此降级。源锁冲突／无效数据／未准备、有效BTF错误及hook失败仍中止，不把汇总的setter关闭状态当作全部原因。静态版不接此层，配置及既有行为不变。
- `vfs_removexattr`独立核对plain二参、mapped三参及具名dentry/context，不从setxattr的参数数目推断；无BTF仅接受真实目标29/16/9条前缀，同一dentry的源锁与独立permission/security链必须一致。源不存在属性的ENODATA由原生删除透传。存在独立`vfs_remove_acl`时另核对具名mapped三参BTF并在其取inode/锁/权限/LSM之前换源；非BTF缺该符号可继续，存在但无签名证据则拒绝，不从do_set_acl推测删除支路。删除没有nscap值转换，security.capability删除仍交原生权限/LSM，设置限制保持。
- 目标syscall内部`listxattr(dentry,user_buffer,size)`可能内联导出VFS实现。额外入口只换dentry，保留原生分配/用户拷贝/零长度探测/总字节数；不清S_PRIVATE、不填猜测的i_op槽、不在模块中拼接或过滤属性列表。有BTF核对其三参具名原型；无BTF核对25条helper与9条独立security前缀，未知形态或有效BTF错误拒绝接线。
- Developer手动运行`tools/test_xattr_remove_list.py`与`tools/test_xattr_remove_list_btf.py`。宿主测试保留1666条Oracle，原生list函数体以字段访问器及FS/LSM/拷贝桩承接，并使用宿主临时文件的真实xattr；不替代Android原生路径/FD/LSM三态复验。DEV-059/060由发现方复核关闭。

## 普通文件 M1：backing 句柄转发

- 依据写入链裁定第四节（ab392d7），受管理路径所在挂载必须可写；不绕过外层VFS只读检查。数据直写绑定backing，不做copy-up，源原生权限或打开失败原样透传；O_TRUNC与ATTR_SIZE沿下述M2自然边界，复合拒绝仍保留。
- 完整backing引擎在源权限接口和write_iter共同槽/签名核验成功后，将write_iter填入尚未发布的普通文件表并启用写打开。独立文件/物化入口仍是只读能力，未具备源写权限委托时保持EROFS；纯虚拟目录也不开放写打开。BTF有效时拒绝槽位/原型/具名参数冲突，不可用才沿已核对共同IO声明；静态表不新增字段。
- 源DAC按实际访问模式检查MAY_OPEN|MAY_WRITE，RDWR另含MAY_READ；不能用读权限替代写权限，也不能把dentry_open称作完整DAC入口。源file沿open→同步write/read/fsync→release保持同一对象，release先清private_data再fput。源安全回调及held-FD/别名快照沿既有句柄模型，不增加逐次权限委托/别名刷新协议。
- write_iter与read_iter一样只临时换ki_filp、保留ki_pos/请求标志/迭代器和原生返回值；短写不补写，出错恢复外层指针。ki_complete非NULL在源回调前EOPNOTSUPP；源写回调缺失EINVAL。不新增逐次mnt_want_write/file_start_write，不重开来源，不按sb或版本号分派。
- open的原生写句柄责任与每次VFS的freeze责任不同；本M1不新增独立源freeze取得协议，不将句柄模型表述为所有并发freeze情形已获真机证明。freeze/remount和真实源LSM/持久性仍需Tester验证。
- fsync沿已接通的源回调，完整保留range/datasync与errno；同步完成不等于断电持久性证明。写入之前的拒绝/零进展错误应保持数据不变；原生写后或fsync错误可能发生在数据已修改后，不做内存字节伪回滚。
- 后段初始化失败同时清读/写准入，释放未发布表。test_file_write.py追加完整prepare与后段失败重准备、六类M1用例；test_file_write_btf.py在8份BTF旧断言后追加write_iter反例。Developer手动触发，未接共享门禁。宿主pwrite/fsync/重开证据不代替目标设备文件系统、CFI/LSM或断电测试。


## M2：自然边界的大小修改

- 依据`docs/records/2026-10-23-truncate-oracle-migration-auth.md`，nm_open保留O_TRUNC，并把该位计入源写权限意图；O_RDONLY|O_TRUNC也检查MAY_WRITE及原有读取权限。只剔除CREAT/EXCL/NOCTTY，不复制VFS检查链、不增加内部truncate hook。
- 源dentry_open完成打开，外层VFS随后通过handle_truncate→setattr处理O_TRUNC。不能把传入flag或源open成功当作截断完成。truncate/ftruncate同样转交既有源inode锁→notify_change(2)→成功后同步发起虚拟inode的size/times等属性。
- SIZE与MODE/UID/GID复合在源锁前整体EOPNOTSUPP；包括外层notify内生的MODE。保留KILL原始标记，不清位制造可接受请求。该复合形态被拒绝，真机未做panic测试。
- 源只读、锁失败、未知/负布局、无源、跨映射沿属性A档拒绝；静态表仍缺源锁证据，保持EOPNOTSUPP。没有新增源writer/freeze屏障，也不隔离remount-ro竞态；A档已记录的跨mount弱语义及DEV-055快照边界继续适用。
- 成功只同步发起inode，其它别名缓存不主动刷新；借用的源mapping保留，页缓存/映射协调由源文件系统承担。源在报错前可能已部分修改，不伪回滚磁盘/缓存，也不把源错误后的虚拟缓存旧值说成所有路径都原子失败。
- 当前完整宿主入口为`tools/test_truncate.py`，以冻结1379条Oracle逐条登记4处已授权期望迁移，追加path/FD/O_TRUNC及拒绝路径；其它断言表达式不变。先前分阶段工具的输入绑定旧里程碑，不能将旧冻结输出当作当前生产已执行。另手动执行8份BTF、原负例及12份静态配置回归；未接共享门禁。宿主IO/mmap/fsync不代替目标LSM/CFI、页缓存并发、断电或性能证据。


## 无 BTF 的源 inode 锁

- `nm_offsets.c`在`vfs_setxattr`／`vfs_removexattr`／`do_truncate2`的固定36／29／43条前缀内，追踪入口dentry→共同d_inode→锁入参。来源只经64位MOV保留；BL清caller-saved，访存写回清基址，未知指令拒绝。前向分支合流取来源交集并检查锁阶段，不接回边。
- 紧邻BL的`ADD x0, xN, #imm`必须来自已确认inode。调用目标按核心代码区内单跳CFI／BTI归一化，与具名`down_write/up_write`或`mutex_lock/mutex_unlock`匹配，不能凭两个地址不同判断锁类型。同函数的lock/unlock先一致，再要求至少两个不同函数体的偏移与锁类型一致；存在的第三来源冲突或不能确认时也拒绝，不投票。
- `nm_prepare_setattr`仅在BTF返回`-ENODATA && unavailable`时调用该推导；有效BTF错误原样保留。新锚点限plain／Android接口，mapped接口继续要求BTF。新锁证据缺失只保留可选写回调的EOPNOTSUPP，读入口不因它失败；成功仍要求killable／interruptible锁、unlock、readonly及notify符号齐全。
- 静态46项表和MODE／UID／GID与SIZE复合拒绝保持原样。`setxattr`由原生VFS自己取锁，不依赖`nm_setattr_layout`；其独立写入ABI的BTF门保持原契约，补源锁不等于开放无BTF的xattr写入。
- 1505条基础宿主入口为`tools/test_inode_lock.py`，读取1433条int／bool Oracle并逐条保留，更新实际prepare及宿主命名副本，再追加真实目标窗口回放、合成mutex／其它合法偏移、冲突／别名／来源破坏／分支／保护页／BTF路由及非BTF准备后的setter调用。测试只在给定本地Image上执行生产推导，不执行目标机器码；原生ABI、LSM／CFI和并发安全须独立审计与真机确认。
- 设备真实`cip135-st19`的`vfs_removexattr`解锁位于索引28；29条固定窗口完整包含该调用，原28条仅覆盖其前置ADD。`tools/test_inode_lock_device.py`保留1505条Oracle，追加真实设备的截短／完整窗口对照与新增尾字的正反夹具；追踪器来源、控制流、阶段及多源接受条件不变。

## DEV-055：按能力启用的动态 DAC 委托

- 完整 backing 引擎准备时，在控制注册与 inode 发布前为普通文件和目录装 permission；Android 接口同时装 permission2。符号链接表与静态版保持原样。BTF 独立核对回调与 generic_permission 原型，源表字段边界使用 BTF 类型尺寸，不用 owned 表容量替代。
- BTF 不可用时，permission ABI 与 getattr 几何共同限定已核对声明前部；generic 的调用参数另取具名入口证据。Sony Android 入口使用 13 条前缀，Nokia 分离入口使用 39 条范围内的 FASTPERM 直达路径；非 Android 二参复用既有 inode/mask 到 generic 的前缀。未知形态不调用新接口，记录具体错误并保留原核心能力，该目标的 DEV-055 DAC 限制仍存在。
- 每次 permission 先对 MAY_NOT_BLOCK 返回 ECHILD，再读已初始化 inode info 的独立源 path。源绑定断链、初始化失败或递归虚拟来源拒绝；没有来源的纯虚拟目录使用自身 generic DAC。有源时只接受 NULL 或正向确认的 generic_permission 槽，Android permission2 必须为空；未知文件系统自定义授权返回 EOPNOTSUPP，不用 generic 替代它。
- generic 使用源 inode 和源 mount 的 userns/idmap，保留原生 DAC、ACL、capability fallback 和错误值。模块不复制 ACL 算法，不取管理锁、外层或源 inode 锁，不改凭据或 S_PRIVATE。既有 setattr 的外层 inode → 源 inode 锁序不变。普通已打开 read/write 不增加逐次撤权重检。
- 此次 permission 决策只保留外层 security_inode_permission 一次调用；实际 inode LSM hook 随原生 S_PRIVATE 门控为 0 或 1。mmap 成功后清位的既有动作和断言不变，回调不采样该位，因此并发清位不会添加第二次 inode LSM。原 open 阶段既有完整源权限检查与 capability 的原生安全检查仍按各自契约执行。
- 自检入口为 tools/test_dev055_permission.py 和 tools/test_dev055_permission_btf.py：1837 条旧宿主断言逐条保留，追加源 DAC、拒绝、完整动态 prepare 与 mmap 清位交错；8 份真实 BTF 追加回调/helper 的独立签名反例。宿主 ACL/capability 依赖桩和确定性交错不代替原生 syscall、CFI、SELinux 或真实并发证据。
- O_NOATIME 封口尚未实现：仅在 security_file_fcntl 前按当前 f_flags 判断“新增”存在并发清位后重新添加的窗口。阶段性封口范围需维护者取得用户选择后再实现；不要把 DAC 委托概括成 DEV-055 全部闭环。
