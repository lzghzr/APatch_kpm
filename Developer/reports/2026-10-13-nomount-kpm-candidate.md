# NoMount 0.1.0：KPM 候选与首轮静态测试件

已接入完整 KPM 入口并从冻结源码构建四份候选，同时生成 `boot_los23.2.img` 对应的静态普通／debug 测试件。只读文件、目录合并和 keyring 规则管理进入同一初始化路径。本记录为 Developer 自检；候选等待 Auditor 独立审计及 Tester 真机验证。

## 冻结身份与输入

源码提交：`c35ecd34ecb6a06c1d54ebda6e6a0e900065f16a`。源码指纹：`5dd2d5ca48b76cfa44941793212d69df40be1898eb391710e2f287e2edc8f2a8`。所有基础实例均由统一 `tools/build_candidate.py nomount` 入口从该干净提交构建，目标为 `all debug`，工具链 `ndk26.3.11579264`，构建前后输入一致。

KP 编译输入为 `b51197aaba8f2272dd8a3e30c85698a29aa928c9`，NoMount 子模块为 `1ded61dc908c511072162fa0bee44e6ccdb7b4c7`；两者未改。本记录的 SDK 提交标识构建输入，实际加载所用 KP 由 Tester 另行绑定和核对。

首轮目标为 `kernel_img/boot_los23.2.img`，内核 `4.19.325-cip134-st18-perf-g7fc8455b2fa8`。boot SHA-256 为 `199658639f7389153ee8a7efe00154f0892e272ddc872728ea326e3e1ce2383b`；有界内核 SHA-256 为 `299f7e2580c54684c3b825bea57f1b16c53055f485ebd2b937593ac57ff9b0d2`；配置 SHA-256 为 `5a03d694a8a1fb015c1e977ada538e8eb7b259dc119a7a771e577481e1d9d450`。匹配源码为 LineageOS/android_kernel_sony_sm8250 的 `7fc8455b2fa84be76364c2457e6503b867ceb12a`。

目标没有 BTF，启用 CFI／CFI_CLANG 与 SHADOW_CALL_STACK，CFI_PERMISSIVE 未启用。首轮使用已配置的静态测试件。动态版需要完整必要 BTF，不能据其构建成功认定该 4.19 镜像可用。

## 基础候选

每行的提交均为上述完整源码提交，instance_id 已包含 Build ID 和实例号。

| 模式 | instance_id | KPM SHA-256 |
| --- | --- | --- |
| dynamic / 普通 | `nomount-0.1.0+g5dd2d5ca48b7.rb8a05ff9.kpb51197a.ndk26.3.11579264#1` | `73be1356fcee0ad135ed11bab89318be1147ebc3faf395d83ccc2fff4da49bc2` |
| static / 普通 | `nomount-0.1.0_baselines+g5dd2d5ca48b7.rde831ef7.kpb51197a.ndk26.3.11579264#1` | `54e7c570694c19429b873000424bca89d3a3089b4b9abd78c92748aef05119f4` |
| static / debug | `nomount-0.1.0_baselines_debug+g5dd2d5ca48b7.rba92ba97.kpb51197a.ndk26.3.11579264#1` | `0d0bbb985aec1026d25efe5c9866cc4448a073a5eb17d6137f523df29782c1ae` |
| dynamic / debug | `nomount-0.1.0_debug+g5dd2d5ca48b7.r1ab551ec.kpb51197a.ndk26.3.11579264#1` | `5fff59b80b7660aaaa67db16e8b0857886d0319a15bf0ee19e20b67cfa5fd28a` |

[基础交接清单](handoffs/2026-10-13-nomount-0.1.0.json) 保存配方、92项冻结输入、完整身份和归档路径。使用 `--handoff` 产清单，尚未写入维护者 metadata；维护者导入后同步当前版本字段。已归档 KPM 和 MANIFEST 保持原字节。

静态基础配置38项均为待填写值，附有对应 `.kpm.json`。普通与 debug 的嵌入版本分别为0.1.0和0.1.0_d，管理名称统一为 nomount；元信息记录 offset_mode 和 lifetime=reboot。

## 4.19 静态测试件

[目标配置](../../nomount/configs/boot_los23.2.json) 汇总此前已核对的38项布局，不按版本号选择偏移。配置 SHA-256 为 `f9ef23f3892d65d8b149c80e699035af8d4e2386ef06d7a4e3eb0c127348825e`。根目录 patch_offsets.py 的 SHA-256 为 `97a51b293af447b3cd6608c953cec95cdfc62f985346463f2285b28ab3c86033`。

| 测试件 | base instance_id | 派生 KPM SHA-256 |
| --- | --- | --- |
| 普通 | `nomount-0.1.0_baselines+g5dd2d5ca48b7.rde831ef7.kpb51197a.ndk26.3.11579264#1` | `a3694526cac5c4cef05fd6b5326790101513f42c31094203c648618898ba7dcb` |
| debug | `nomount-0.1.0_baselines_debug+g5dd2d5ca48b7.rba92ba97.kpb51197a.ndk26.3.11579264#1` | `606ebed60723b116eb31f4cd3557b905fb76763e03d30422c2d030bab4d6e7f7` |

[目标交接清单](handoffs/2026-10-13-nomount-0.1.0-target.json) 绑定基础实例、基础哈希、工具／配置哈希、实际命令、派生 KPM 和伴随 JSON。标准 binary_ports 记录在原有目标记录后追加，既有记录保持不变。两份派生件只修改文件偏移35812处的76字节配置段，其他字节与各自基础产物一致。

## 初始化与加载约定

nomount.c 包含完整 nm_control_entry.c。初始化拒绝非空加载参数，嵌入加载使用 `post-kernel-init`。引擎、原生管理锁和控制表全部准备完成后才注册 key type；注册失败释放未发布对象，成功后直接返回成功。状态查询支持空命令或 status，检查用户缓冲区长度和拷贝结果。

模块、注册表和已发布 VFS 回调驻留到重启。exit 只作诊断；当前 KP 的卸载路径会继续释放模块，不能依赖 exit 的返回值保护回调。因此测试及使用均不得卸载。

## 方案复核（Decision）

**修改（Modify）**：保留完整入口及静态目标配置，将 CFI 生效确认列为 Tester 加载前条件。

### 有效性

目标具有 `__cfi_slowpath`，未发现 `__cfi_slowpath_diag`。KP 的 `kernel/patch/common/secpass.c` 中 should_cfi_pass 覆盖 KPM 可执行分配范围；`kernel/patch/module/module.c` 的 move_module 使用该可执行区域。该路径可以处理模块回调的 CFI 检查，但实际挂接是否成功必须有目标证据。cfi_bypass 不导出，两个 slowpath 均缺失时 bypass_kcfi 仍可能返回0；到达 KPM init 和单独的 `bypass_kcfi done:0` 均不能证明目标挂接已生效。事件 hook 的安装顺序也不能提供这个保证。

### 简洁性

可信基线是复用 KP 对其模块代码区域的处理，并在加载前核对实际 KP／boot 身份和目标 slowpath 挂接记录。它比模块内新增 CFI 处理或查找 KP 私有状态更少耦合，且直接对应原生回调的执行路径。保持 `-ffixed-x18` 与通用寄存器编译约束；模块只承担已有业务初始化。

### 后果

注册成功后内核可调用模块代码，驻留是本实现的生命周期契约。所有失败点放在注册之前，避免成功注册后又返回加载错误而释放回调代码。宿主夹具可以检查此顺序及失败清理，不能证明真实 CFI、锁竞争或 VFS 引用安全。本轮一次有界 Developer 辅助只读挑战支持上述修订，不构成 Auditor 结论。

### 修订建议

Auditor 先独立复核完整入口、原生回调 ABI、CFI 路径和派生配置字节。Tester 再绑定实际 KP／boot 身份，确认目标 `__cfi_slowpath` 挂接成功后使用首轮静态测试件；参数留空，规则在数据分区可读后、系统应用扫描前建立。测试结束通过重启结束模块生命周期。

## Developer 自检

证据位于 `local/nomount-kpm-20261013/` 的独立输出目录。

- prior-inode-01／prior-subtree-01／prior-control-01：完整执行既有 inode、目录、拓扑、backing、子目录和控制 Oracle，通过。
- selfcheck-01：ASan／UBSan 通过。完整执行控制 Oracle，再执行真实 KPM 入口和控制构造器；原生依赖准备及 BTF 查询由宿主接口夹具代替。覆盖加载阶段／参数拒绝、构造失败、动态 BTF 失败、key type 注册冲突、七个分配失败点、失败后状态／指针清理、状态缓冲区及短拷贝、驻留退出。成功注册对象只在夹具结束时清理。
- selfcheck-01：静态普通／debug 两种基线均完成 JSON／blob 配置替换及还原；字段38项、范围76字节，配置以外字节保持不变，恢复后与基础二进制相同。
- build-02：四种探索构建通过；全部导入与 KP 导出匹配，artifact_gate 四份 KPM 通过。build-01 因新增 author 元信息超过 SDK 长度上限编译失败，缩短字段后通过；既有 Oracle 未改。
- freeze-binding-01：已有22个测试脚本与上一检查点逐字节相同；自检源码回执匹配冻结提交，四种探索 KPM 与冻结候选逐字节相同。
- binary-check-01：四份候选和两份派生件的全部 ELF 导入均匹配 SDK 导出。动态每份14791条、静态每份8919条指令操作数未发现 FP／SIMD／SVE 或 x18。
- candidate-verify-01：对交接清单四条 build 调用 identity.verify_build 的 candidate 档位，均为0问题；每条重算92项提交输入并核对归档产物。此项是 Developer 身份自检，维护者尚未导入登记。
- nomount.c 通过项目 clang-format 检查。

| 证据 | SHA-256 |
| --- | --- |
| prior-control-01/receipt.json | `223985768c7baee98952ed602cb10cd7a2baf96cf4a907d5ef1207c8662f7d5a` |
| selfcheck-01/receipt.json | `c344633754030113e04e4843ea1b0dc6caeae5edfa544e0caf18d7dd477a3652` |
| freeze-binding-01/receipt.json | `baaa87be380a98e52371b60a99da7cc77ab80a824a7c9f4de322e1ce51d1c99f` |
| binary-check-01/receipt.json | `6402e7ba117d06cfe9cd35ddd9c7c2438330089bd41c4da4f0156c50e701600c` |
| candidate-verify-01/receipt.json | `d66c911edcff852fa0821870ea22ef99439285b5cbcacea5da300fb78c6ebd33` |

常规仓库门禁13项：1项失败、1项警告。失败为 nomount 的 Makefile 版本0.1.0与 metadata 空版本不一致；版本声明由维护者维护，已提供 [登记补丁建议](../proposals/2026-10-13-nomount-version/README.md)。警告为既有 zram_zstd 交接缺 handoff_by／handoff_at，其文件未改。其余检查通过。

本轮按 are-you-sure 完成挑战并修订加载条件，按 no-negative-echo 回读实现、清单和公开说明，按 respect-the-oracle 保持已有基准及断言。上述检查属于 Developer 自检；真实 keyring、CFI、VFS／RCU／mutex 并发、SELinux、应用发现与启动仍由独立审计及真机测试确认。4.4／5.15 尚未适配；fallback symlink／特殊文件物化和 lockdep 目标接入沿用已记录的未覆盖范围。
