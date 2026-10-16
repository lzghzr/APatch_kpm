# NoMount：backing 查找与合并枚举

本轮完成 backing 子路径查询、目录合并枚举和 seek 封装。枚举先显示 backing 原有条目，过滤被规则覆盖的名字，再输出规则子项；点项显示外层目录编号。封装尚未接到 backing 目录 inode，拓扑仍拒绝这类规则。下一步接目录物化和缓存重验证，再接控制层。

角色为 Developer。源码检查点为 `3914a57a0b59e9656d18c9f829fc80520a224d70`，ARM64 探索对象从该提交编译；本轮没有 KPM、Build ID 或 instance_id。以下是实现方自检，不是独立审计或真机结论。

## 输入与实现

目标继续为 `kernel_img/boot_los23.2.img`，内核 `4.19.325-cip134-st18-perf-g7fc8455b2fa8`。

- boot SHA-256：`199658639f7389153ee8a7efe00154f0892e272ddc872728ea326e3e1ce2383b`。
- 有界提取内核 SHA-256：`299f7e2580c54684c3b825bea57f1b16c53055f485ebd2b937593ac57ff9b0d2`。
- 匹配内核源码：`LineageOS/android_kernel_sony_sm8250`，`7fc8455b2fa84be76364c2457e6503b867ceb12a`。
- 配置 SHA-256：`5a03d694a8a1fb015c1e977ada538e8eb7b259dc119a7a771e577481e1d9d450`。
- NoMount 上游保持 `1ded61dc908c511072162fa0bee44e6ccdb7b4c7`。
- KP 编译输入为 `b51197aaba8f2272dd8a3e30c85698a29aa928c9`。

新增 nm_backing_directory.c 和 nm_backing_entry.c。沿用现有 path、file、inode、qstr 片段和访问器，没有新增结构体偏移。BTF 的函数 ABI 核对独立放在 nm_btf.c；缺符号或 ABI 不匹配停止该层准备。

查询使用原生 vfs_path_lookup，传入 backing dentry 和 mount，取得一份独立完整 path 引用。匹配目标的 [namei.c](https://github.com/LineageOS/android_kernel_sony_sm8250/blob/7fc8455b2fa84be76364c2457e6503b867ceb12a/fs/namei.c#L2542) 及 namei.h 已核对，目标符号表含函数和 CFI 跳板。保存的 namei.c SHA-256 为 `d7abb03d9eae5d860f80969f2ade52fd9758134e0f4adc207db9552985db5cbb`，读取日期为 2026-10-13。

名字限定为单个分量，拒绝空名字、点分量、斜线、内嵌 NUL 和超过 255 字节的名字。flags=0 保留末尾符号链接的类型；物化层的类型支持随后接入。查询不借用 outer dentry；调用前退出模块 RCU，且不持管理锁或 backing inode 锁。成功路径引用转交调用者；模块在原生成功后拒绝结果时负责 path_put，原生错误不改写。

合并枚举复用 nm_directory_filter、nm_emit_children 和原生 iterate_dir 封装。native actor 在模块 RCU 外执行，点项编号使用 outer 目录与父目录的编号。缓冲区满保留当前位置；过滤后无实际输出才进入规则枚举阶段。blocked UID 保留 backing 内容并跳过规则子项。seek 保留现有 32/64 位虚拟 cookie，普通位置转交 backing 的原生 llseek。

## 方案复核

**修改（Modify）**，本段修正已完成。

### 有效性

最初考虑的 lookup_one_len_unlocked 固定传 NULL mount。本目标的 do_inode_permission 仅在 mount 非 NULL 时调用 Android permission2；该 helper 也不完成挂载点遍历。选用已有 vfs_path_lookup 保留完整原生路径处理，宿主用不同的输入／返回 mount 检查结果引用不会被父 mount 覆盖。目标上的权限效果仍待独立审计及真机验证。

### 简洁性

复用原生路径解析和既有目录过滤、UID、cookie、seek 实现，无需新增锁布局或逐字段偏移。当前仅提供对象入口；目录物化、子规则持有和重验证接好后再开放 backing 目录规则。

### 后果

只读 Developer 辅助挑战发现，i_fop 先于 i_op 发布时，open 可能已让 file 保存模块目录表。枚举／seek 因此同时核对 inode 的 i_op 和 file 保存的 f_op，拒绝递归进入模块目录回调。新增用例模拟此窗口，两条路径都返回 ELOOP。它不能证明并发安装过程中不存在其他窗口，后续接入仍需处理规则循环和缓存刷新。

按 are-you-sure 完成这次有界方案挑战；按 no-negative-echo 回读源码、README 与本报告；按 respect-the-oracle 核对已有 15 个测试脚本与上一检查点逐字节一致。本轮新增两个测试脚本，保留并完整执行旧拓扑及布局 Oracle。

## 验证与证据

证据保存在新的 `local/nomount-backing-directory-20261013/` 子目录。

- selfcheck-02：路径引用转交／拒绝释放、原生错误、名字边界、递归拒绝、合并过滤、点项编号、UID、满缓冲区续读、32/64 位 cookie、seek 和 file 操作表发布窗口通过 ASan/UBSan。其调用夹具不证明原生权限、锁或挂载点行为。
- layout-01：保留既有拓扑布局 Oracle，编译核对匹配目标的 vfs_path_lookup 声明，执行生产 BTF 的参数数量、宽度、返回类型及缺符号拒绝边界，通过 ASan/UBSan。
- compile-03：从上述源码检查点编译 dynamic / static ARM64 对象通过。每份对象有两条 SDK 既有 READ_ONCE/WRITE_ONCE 重定义警告，其他按 Wall/Werror 检查。所有未解析导入均与当前 KP 导出对应；动态 11932 条、静态 6721 条指令的操作数检查未发现 FP/SIMD/SVE 或 x18。
- freeze-binding-01：自检源码及工具哈希与冻结 Git blob 一致；15 个已有 Oracle 未变。compile-03 自身记录源码提交，并在编译前后核对源输入。
- 初次 compile-01 记录了联合入口被格式化排序打乱 include 依赖的编译失败，已修正。compile-02 的指令检查正则跨行把下一条指令地址当作寄存器；改为逐行匹配后在 compile-03 重新检查，寄存器禁止范围保持。
- 常规仓库门禁 13 项：0 失败、1 项既有 zram_zstd 交接字段警告（handoff_by／handoff_at）。初次系统 Python 3.9 无法执行偏移工具的较新类型语法，换已安装 Python 3.14 后通过，未修改门禁或 Oracle。

| 证据 | SHA-256 |
| --- | --- |
| selfcheck-02/receipt.json | `3899816ca2216ffad03aa9580599ec04fb44b58b5c72deaeedd13f826061edbe` |
| layout-01/receipt.json | `3821043820731705f7619d6566b4c2403abcfc019621e4ff1abc3483be935f66` |
| freeze-binding-01/receipt.json | `33739e4d29ff881b3513055cbd5cb8e40d0d2598d93953020d6fbce3d1d233f4` |
| compile-03/receipt.json | `e8275c77cbe9a146300261591209105a50e07cfef6e714a32da941c691752233` |
| compile-03/dynamic.o | `74350d99af19e7eb02acdcb055c59bf1de33a67f34c426aba39231a2615b7f67` |
| compile-03/static.o | `c0a41a716202258514b5062e7952ec0c98d012e6e1a4babc143550534a780f77` |

仍未覆盖 backing inode 物化、派生子规则与缓存重验证、符号链接／特殊文件、规则并发修改、实际管理锁、keyring、KPM 初始化和 Android 应用扫描。真实文件系统、CFI、设备存活与应用启动交由 Auditor／Tester 分别验证。
