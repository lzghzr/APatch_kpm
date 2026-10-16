# NoMount：共同结构与只读文件回调

本轮完成只读文件回调和完整操作表构造，并比较了需要使用的跨版本结构。目录查找、inode 物化与 keyring 注册仍待接入，目前没有可加载的 KPM。

角色为 Developer，源码检查点 `a85b881a05de25fe5354882d075cb234f39f78df`。本轮产物为自检证据与 ARM64 对象，不是 KPM 候选，尚无 Build ID / instance_id。对象哈希只绑定本轮编译结果，不作为独立审计、实机或交付结论。

## 输入与结构取舍

目标仍为 `kernel_img/boot_los23.2.img`，版本 `4.19.325-cip134-st18-perf-g7fc8455b2fa8`。

- boot SHA-256：`199658639f7389153ee8a7efe00154f0892e272ddc872728ea326e3e1ce2383b`。
- 有界提取内核 SHA-256：`299f7e2580c54684c3b825bea57f1b16c53055f485ebd2b937593ac57ff9b0d2`。
- 原版 NoMount：`nomount/nomount` 子模块的 `1ded61dc908c511072162fa0bee44e6ccdb7b4c7`，kernel 部分 GPL-2。
- 厂商参考：`LineageOS/android_kernel_sony_sm8250` 的 `7fc8455b2fa84be76364c2457e6503b867ceb12a`，与目标版本标记一致。
- 上游比较：Linux `v4.4`、`v4.9`、`v4.14`、`v4.19`、`v5.15`、`v6.6` 的 fs.h。公开文件取自官方内核源码镜像，逐份哈希记在本轮 local 证据；它们只是声明参考，不是模块构建依赖。

先核对 SDK：当前 KP 的 file、kiocb、file_operations 只有前向声明，没有可直接使用的完整类型。因此在 `nm_structs.h` 定义已确认的共同片段，直接访问片段内成员：

| 片段 | 结果与用途 |
| --- | --- |
| file_operations 前六个成员 | 七组声明均为 owner / llseek / read / write / read_iter / write_iter，ARM64 位置为 0 / 8 / 16 / 24 / 32 / 40，前部尺寸 48 |
| kiocb 到完成指针 | 七组声明的位置均为 ki_filp=0、ki_pos=8、ki_complete=16，前部尺寸 24 |
| f_flags / f_mode | 保留连续 32 位片段，只取得其起点 |

ki_complete 在 6.6 的回调签名有变化，本模块只用该成员检查 NULL，不调用完成回调。共同片段编译核对的条件是未启用结构重排；当前目标未启用 RANDSTRUCT。动态 BTF 会拒绝与片段不一致的布局。上述比较不等于已适配或验证七种内核。

完整 file 中间有锁和配置相关成员：4.4 mutex 使用 count 与可选 owner，5.15 已使用 atomic-long owner，不能把完整 file 当成通用定义。file_operations 后续成员也会变化：4.4 没有 iterate_shared，5.15 在 iter 回调后有 iopoll，6.6 取消 iterate。因此只给本轮真正需要、且共同片段无法覆盖的位置保留偏移。

## 实现与目标证据

`nm_file.c` 实现 open/release、同步 read_iter、llseek、readonly mmap、splice_read。open 取得 backing 文件并保存在外层 file 的 private_data；release 先摘下该指针，再调用原生 fput。读取临时使用 backing 文件，返回时恢复原 ki_filp，保留原生结果和 ki_pos。

完整操作表按目标尺寸分配并清零，只填读取相关回调。`nm_file_entry.c` 的准备函数完成依赖与布局准备后返回尚未发布的表，后续物化层负责绑定 inode；失败保持输出为空。

文件访问所需的新偏移继续放在 `nm_offsets.c`，BTF 与回调 ABI 查询放在 `nm_btf.c`，指令解码和 BTF 遍历使用根目录 `kpm_utils.h`。

| 对象字段 | 目标值 | 依据 |
| --- | ---: | --- |
| inode.i_private | 704 | simple_open 前四条中的 inode 读取与 file 写入 |
| file.private_data | 200 | simple_open，同步核对目标声明编译结果 |
| file.f_pos | 104 | noop_llseek 两条入口，同步核对目标声明 |
| file.f_flags | 64 | nonseekable_open 五条入口取得 f_mode，再按共同片段取得 flags 起点 |
| file.f_cred | 144 | file_ns_capable 八条入口，在调用和 x0 改写前取得 |

目标完整 file 尺寸为 256，mutex 为 32。完整 file_operations 仍为前轮已核对的 296；本轮使用 open=104、release=120、mmap=88、splice_read=192。完整表与这些后续槽位由匹配目标声明提供，函数入口不会猜测它们。

动态版先用 BTF；查询不可用时尝试上述固定窗口。真实 BTF 错误保留，不回退覆盖它。入口只取得五个对象字段，缺完整表或回调槽证据时仍停止准备。BTF 同时核对共同片段、回调参数数量、整数/指针类别及宽度；完整类型准确不代替 CFI 与实机调用验证。

## 只读边界与方案复核

**保留（Retain）**：使用原版同步读取与 outer-file 页缓存映射，首轮限于既定的 APK／只读文件场景。

有效性：普通读取、seek、私有 mmap 与 splice_read 的生产回调已有宿主执行证据。物化层仍需把虚拟 inode 的 i_mapping 转接到 backing，并在 inode 生命周期内持有规则引用；完成这些步骤后才可让文件被系统发现。

简洁性：优先用共同结构片段，避免为 read_iter、write_iter 或 kiocb 三个前部字段分别计算偏移。mmap 调用原生 generic_file_readonly_mmap，无需计算 VMA 字段，也不替换 vma->vm_file。

后果：异步读取在提交 backing 前返回 EOPNOTSUPP；立即恢复原 ki_filp 不能覆盖已排队请求的生命周期。共享可写映射使用的 superblock 冻结记账不同于 backing 页缓存，原生 readonly helper 在提交前拒绝它。open 在虚拟目录分支前拒绝写打开与 O_TRUNC，包含 O_RDONLY|O_TRUNC。

同步写需要 backing superblock 的冻结保护，其他修改接口也不属于首轮读取契约。因此本轮只读表未填写入、ioctl、fsync、splice_write 槽，也不取得其偏移；后续支持写入须另核对原生冻结与锁顺序。前轮已入库的 Oracle、断言与夹具未改变，本轮夹具验证实际只读契约。

内部只读挑战回看确认最小只读范围成立，没有操作设备或代替 Auditor 写结论。按 no-negative-echo 回读源文件、README 与记录；按 respect-the-oracle 核对生产路径和既有测试，未为宿主夹具改变内核锁或 VMA 引用机制。

## 自检与证据

本轮目录 `local/nomount-file-20261012/` 全部为新输出，旧报告与归档保持原记录。

- 共同片段：六个上游版本与匹配目标，共七组声明的 ARM64 编译核对通过；不是完整结构的跨厂商保证。
- test_file_layout：真实入口执行、字段存储、分支与参数改写边界、BTF 共同片段、回调 ABI 错误及查询分派，ASan/UBSan 通过。
- test_file：执行实际读取回调与表构造，覆盖写/截断拒绝、open 失败、release、位置同步、读错误与异步拒绝、mapping 一致性及 readonly helper 契约、分配失败和偏移重叠拒绝，ASan/UBSan 通过。
- 原有布局、规则、BTF 前部和原生封装四组自检回归通过；它们没有改变。
- NDK 26.3.11579264 编译动态、静态对象通过，均包含六个实际文件回调。每份对象有两条 SDK 既有 READ_ONCE/WRITE_ONCE 重定义警告，其余使用 Wall/Werror。C 文件格式与 diff 检查通过。
- 对象未解析导入为当前 KP 的 kallsyms_lookup_name、kallsyms_lookup_name_by_suffix、kf_strncmp、printk（静态对象仅用其中两项），没有新增裸 memset。当前 KP 对 KPM 代码区域有 CFI 处理路径；实际目标的该路径是否生效仍需 Tester 记录。
- 常规门禁 13 项检查：0 失败、1 既有警告，来自旧 zram_zstd 交接清单缺少 handoff_by / handoff_at。

| 本轮证据 | SHA-256 |
| --- | --- |
| common-reference-02/receipt.json | `dfb973d0f45021e155ec21af66ce3c6f87915504a36bb854719c8c30b42dadf3` |
| native-reference-02/reference.json | `51d1850e1a7fe7d3fefa6f5cff7aaf9e523678223c24bda84774bb381a61a8b2` |
| file-layout-03/receipt.json | `d8b14f77dfff7db3e51892c6fe1547a5fad0775b49c89f0aba451ecdfbe2fa15` |
| file-selfcheck-05/receipt.json | `682aa037c0cc3d49b8369dca8c55385297c93f3b1b2681133f2807249b8faf66` |
| compile-03/receipt.json | `616f580acb995b372a0cb597bd42cdf890eb547e564da6e727d35fae5df9dbcf` |
| compile-03/dynamic.o | `3daa58cb4502aa3678bd24d9e53e4908a4dc9d5373aa82aaa970edd6cadf2239` |
| compile-03/static.o | `e4412bfacedb0983f84579cf75cebf8c0e6e73a0cb039ed8ead9a13486cc0829` |

上述宿主夹具只检查接口调用契约，不证明 native VMA 引用、页缓存、并发、冻结、SELinux、CFI 或应用启动。完成可加载候选后，实机测试仍由 Tester 进行。
