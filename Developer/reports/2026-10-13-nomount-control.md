# NoMount：管理锁与 keyring 控制

本轮接通原版 keyring 控制协议，支持规则增删、UID 管理、隔离 UID 筛选、版本与列表查询、清空规则和 UID。新增规则先在管理锁外解析来源，持原生 mutex 发布，解锁后统一退役旧对象。规则列表可导出并重新提交。

角色为 Developer。联合对象源码检查点为 `5372c6c35ca19f1c9a88deb9f52f985f30c9da37`。宿主命令及布局自检绑定 `d946214a841f89fefd0db73cba32e03a1bb96468`；随后只有 nm_control_entry.c 的 include 顺序修复，业务代码与自检工具逐字节相同，修复由实际 ARM64 联合编译确认。宿主夹具不编译该入口初始化函数，因此未重复运行不受影响的宿主用例。

当前仍是探索对象，没有可加载 KPM、Build ID 或 instance_id。以下为开发自检，不是独立审计或真机结论。

## 输入与布局

首轮目标仍为 `kernel_img/boot_los23.2.img`，内核 `4.19.325-cip134-st18-perf-g7fc8455b2fa8`。沿用已核对的 boot SHA-256 `199658639f7389153ee8a7efe00154f0892e272ddc872728ea326e3e1ce2383b`、有界内核 SHA-256 `299f7e2580c54684c3b825bea57f1b16c53055f485ebd2b937593ac57ff9b0d2` 和配置 SHA-256 `5a03d694a8a1fb015c1e977ada538e8eb7b259dc119a7a771e577481e1d9d450`。

匹配源码为 `LineageOS/android_kernel_sony_sm8250` 的 `7fc8455b2fa84be76364c2457e6503b867ceb12a`；NoMount 上游为 `1ded61dc908c511072162fa0bee44e6ccdb7b4c7`；KP 编译输入为 `b51197aaba8f2272dd8a3e30c85698a29aa928c9`。本轮只读获取目标 mutex、lockdep、keyring 源码及上游 keyring 声明，保存在 local 中，未改子模块。

SDK 没有可复用的 mutex 定义。使用原生完整尺寸内存，模块不访问其内部字段；目标配置未启用 DEBUG_LOCK_ALLOC、DEBUG_MUTEXES、DEBUG_SPINLOCK 或 LOCKDEP，MUTEX_SPIN_ON_OWNER 与 SMP 已启用。按目标 mutex、spinlock、osq 声明编译核对尺寸为32、wait_list 为16；class key 为零尺寸。目标 [__mutex_init](https://github.com/LineageOS/android_kernel_sony_sm8250/blob/7fc8455b2fa84be76364c2457e6503b867ceb12a/kernel/locking/mutex.c#L39) 初始化原生对象，所用非调试 helper 不使用 class key，传 NULL。动态 BTF 若发现 dep_map 则停止；支持 lockdep 还需要原生动态 class key 注册，留待相应目标接入。

key_type 共同 name／def_datalen 前部为16字节，连续 preparse／free_preparse／instantiate 为24字节；key_preparsed_payload 的 data／datalen 连续16字节。4.19 的回调起点为24、预解析 data 为40；5.15／6.6 的这两个起点变化为32和48。共同片段放 nm_structs.h，其起点与 mutex 尺寸放 nm_offsets.c，BTF 查询和 ABI 检查放 nm_btf.c。没有新增函数扫描或版本号分支。

key type 仍按已有完整136字节尺寸分配，目标 [register_key_type](https://github.com/LineageOS/android_kernel_sony_sm8250/blob/7fc8455b2fa84be76364c2457e6503b867ceb12a/security/keys/key.c#L1115) 写入内部尾部。注册前填齐回调，注册为最后一步；失败释放未发布表，成功后保留表与 mutex，驻留到重启。KPM 入口将在下一段调用完整准备函数。接口版本为0.1.0。

## 命令行为

保留4096字节协议及32／64位地址载荷。预解析先检查 CAP_SYS_ADMIN，再复用已有 nm_exchange_payload 取得独立内核快照；执行结果写 status，完整响应复制后返回 ECANCELED。未知命令和超界载荷返回错误，短拷贝返回 EFAULT。free_preparse 在错误返回后仍可被原生调用，保持有效。

批次遇到完整记录的操作错误仍继续，status 保留第一错误，arg1 返回已遍历字节位置；截断记录停止在该记录起点。已成功的记录保留，批次不是事务。ADD 在锁外解析 backing path，在锁内调用拓扑接口；DEL、UID 修改及清空由同一原生 mutex 串行；需要等待 RCU 或释放路径的退役动作在解锁后执行。

GET_LIST 持 mutex 遍历管理索引，只输出可由用户重新提交的显式规则。自动父目录和撤销来源后保留的继承目录由子规则重建。分页游标只保证单页安全，跨页修改可能改变列表。容不下单条记录时返回 EOVERFLOW。

导出恢复可能先提交深层规则，再提交来源父目录。自动父链因此统一设置 inherit_backing：纯父没有来源时继续纯目录，父视图以后成为 backing 时从当前父 inode 查询来源。自检验证清空并按导出顺序恢复122条规则后，源 sub／deep 和原有文件仍能访问。

## 方案复核

**保留（Retain）**：采用原生 mutex、锁外来源解析与最后 keyring 注册。

### 有效性

已有规则、拓扑与退役接口已接到全部控制命令。载荷权限及快照沿用原生封装；批次和分页使用核对过的上游协议。ASan／UBSan 用例覆盖操作错误继续处理、截断游标、规则列表恢复及来源继承；完整注册表和权限回调的调用契约也已执行。

### 简洁性

原生可睡眠 mutex 串行管理接口；既有 RCU 保留读侧语义。只为 SDK 和共同片段未覆盖的完整尺寸、回调起点取得布局，复用已有 key_type 完整尺寸。用户工具继续使用原版线协议。

### 后果

注册成功后内核可持有回调，模块及注册表驻留。锁和注册失败只清理未发布对象。含 lockdep 的目标明确停止；跨页查询采用尽力分页，批次保留部分成功。一次有界 Developer 辅助只读复核未发现本段新的实质缺陷；该辅助不构成 Auditor 结论。

建议下一段接 KPM 入口、Makefile、静态 JSON 与完整候选构建，并核对目标 CFI 回调要求。

## 自检与探索对象

证据在 `local/nomount-control-20261013/` 的新输出目录内。

- prior-inode-03／prior-subtree-02：完整保留并执行既有 backing、拓扑、目录、inode 与子目录 Oracle，均通过。
- prior-layout-01：既有虚拟目录、拓扑、backing 及权限接口布局 Oracle 通过。
- selfcheck-02：ASan／UBSan 通过。覆盖 mutex 准备失败、重复准备、注册缺符号／分配失败／冲突清理、完整注册表、CAP 拒绝、载荷长度／魔数／拷贝错误、32／64位地址、未知命令、批次范围与游标、UID 命令、两页122条规则、清空与列表恢复、来源子目录和文件查询、退役引用平衡。原生 mutex 由调用契约夹具代替，不证明实际争用。
- layout-06：编译核对4.4、首轮目标、5.15、6.6的 keyring 片段，ARM64编译确认尺寸与偏移；生产 BTF 覆盖连续位置、类型、回调与函数原型、完整尺寸、缺符号、lockdep 拒绝，以及另一组已核对的32／48起点。ASan／UBSan 通过。这些头文件比较不是高版本适配结论。
- 初次 layout-01～04 的新增声明夹具缺前向声明、__user 或指针类型转换，已补齐；layout-05 通过，补充 ARM64 数值断言及输入回执后 layout-06 通过。selfcheck-01 缺宿主 __user 定义，修正新增夹具后 selfcheck-02 通过。已有 Oracle 未改。
- compile-01：联合入口的 include 被格式工具重排，编译失败。独立注释分开依赖层后，compile-02 的 dynamic／static 联合对象从修复检查点编译通过；其余业务及自检输入未变。
- compile-02：每份对象有两条 SDK 既有 READ_ONCE／WRITE_ONCE 重定义警告，其余按 Wall／Werror 检查。全部 ELF 导入匹配当前 KP 导出；动态14694条、静态8822条指令操作数中未发现 FP／SIMD／SVE 或 x18。
- freeze-binding-01：宿主及布局回执匹配其冻结提交，联合对象匹配修复提交；已有20个测试脚本与前一文档检查点逐字节相同。
- 本轮9个 C／头文件通过项目 clang-format 检查。
- 常规仓库门禁13项：0失败，1项既有 zram_zstd 交接字段警告（handoff_by／handoff_at）。

| 证据 | SHA-256 |
| --- | --- |
| prior-subtree-02/receipt.json | `24a750d6ff1fbf3354811086fbc3c5698629689749369d1daded05a2fafebf40` |
| selfcheck-02/receipt.json | `bb3b7b1b2a464ffa73357db6573dc804852d46e9180ff1cd3bc12f40798c83f7` |
| layout-06/receipt.json | `1bdd791dea6cf8a99ec44f875ffe1b2373ff64e3c4a58a273def779ac8e2fde2` |
| freeze-binding-01/receipt.json | `aa87ebbe67780b95bed708f78a208ab1983a26b9ae142d997cf082d56e2eef5c` |
| compile-02/receipt.json | `d7468fb50ebdca16e25c141c328006af475cb3e22b41bc9211e9d658af6b2994` |
| compile-02/dynamic.o | `d78350149b2228ba4e453294be62fc25ab5db56d2024a3c5a1cddde90e198fcf` |
| compile-02/static.o | `cf8f2dae97a8254d442a8a13f65e2b5e30a6bfb13327cfca78daf7ad1a36074e` |

按 are-you-sure 完成本段挑战；按 no-negative-echo 回读实现与说明；按 respect-the-oracle 保留原有基准。尚未执行真实 keyring、VFS／mutex 并发、目标 CFI 或 Android 应用扫描。可加载 KPM、完整加载失败路径和冻结候选仍待下一段；真机操作由 Tester 进行。
