# run_cmd_demo 开发约定

## 编译模式

本模块共用命令执行逻辑，定义 `CONFIG_KPM_BASELINES` 编译静态基线，未定义时为动态版。两版管理名称都是 `run_cmd_demo`；文件分别为 `<模块>_<版本>_baselines.kpm` 和 `<模块>_<版本>.kpm`。模式记录在 `offset_mode` 中。

`run_cmd.c` 保存执行和控制逻辑，`run_cmd.h` 保存模块定义及核对过的工作项前缀，`rc_utils.h` 保存 KP 风格封装。偏移表、实例与计算集中于 `rc_offsets.c`，公共指令与 BTF 查询使用根目录 `kpm_utils.h`。

## 偏移取得

动态版先查询目标 BTF，缺少数据或查询接口时走已有固定窗口推导。Android 4.4～5.10 是函数推导的默认适配范围；5.15～6.6 优先通过 BTF 适配。失败返回错误，不按版本号猜偏移。

静态版不查询 BTF 或扫描指令。以下四个 int16 字段保存于独立的 `.data.re_offsets`；模板全为 `-1`，移植后才能加载。

| 字段 | 静态配置含义 |
| --- | --- |
| `subprocess_info_path_offset` | `subprocess_info.path` 的字节偏移 |
| `cred_security_offset` | `cred.security` 指针的字节偏移 |
| `cred_sid_offset` | `task_security_struct.sid` 的结构内字节偏移 |
| `legacy_worker_size` | 旧 `kthread_worker` 的完整大小；现代 creator 路径可保持 `-1` |

## 执行环境

DEV-122 将域判断放在提交期。模块加载只准备执行通道；普通加载不判断域，`post-fs-data` 时 Magisk 域尚未就绪也可加载。通过加载参数提交的命令是一次显式提交。

每次提交只检查设备已有的 Magisk 执行域。不可用时不排队，CTL0 返回 `-EOPNOTSUPP` 并写出 `unavailable\n`；不影响模块、worker 或上一次结果。域就绪后可重新提交，无需重装。模块不新增策略，不缓存失败，也不自动重试。加载参数里的命令若提交失败，查看内核日志后重新提交。

日志按阶段区分：`init: exec channel ready` 表示通道已准备；`exec context lookup:` 记录本次提交的域查询；`exec: ctx=` 表示进入执行准备。拒绝的命令不会进入执行准备。

`cmd_capable` 只表示执行通道已准备，不代表目标域可用。两个调用点都在 worker 建立后才进入 `submit_cmd`；入口仍以 `-EAGAIN` 保护未就绪的 worker（AUD-050 / AUD-053）。

## 控制入口与输出

单次命令最长 4095 字节。模块一次只执行一条命令；前一条未结束时，新提交返回 `-EBUSY`。执行没有超时，长时间不退出的命令会一直占用通道。

`result` 查询执行状态：首次提交前为 `idle`，执行中为 `pending`。结束后的 `ret` 是 Linux 原始等待状态：正常退出时等于退出码乘以 256（如退出码 1 对应 `ret=256`）；被信号终止时按信号状态解码。负值表示执行接口出错。

标准输入、输出和错误默认连接到 `/dev/null`。需要保留文字输出时，可以在控制入口提交 `date > /data/local/tmp/run_cmd_demo.out 2>&1`，执行结束后用有读取权限的终端查看该文件。文件访问仍受设备权限和 SELinux 策略限制。

## 路径与偏移约束

`subprocess_info->path` 偏移来源：动态版优先 BTF（`kpm_btf_offset(... "subprocess_info", "path", 8)`），缺失时走
`call_usermodehelper_exec` 入口的 `LDR [x0, #imm]` + 同寄存器 `CBZ` 指令链；静态版读 `.data.re_offsets` 的边车配置。
两道判据、**主次分明**：BTF 先用**类型内断言**（`成员偏移 + sizeof(void*) <= subprocess_info 的 BTF size`）——
这是结构性判据，越界即作废该候选；`path_offset_in_range()`（`0 <= off <= 0x100`）是**最后一道统一兜底**，
只用于挡住指令链 `imm12<<3` 能取到的 32760 这类离谱值，不能替代类型内断言。**不要把它们写成一个口径**：
BTF 候选要过两道，指令链与静态边车只过上界那一档（它们拿不到类型大小）。
BTF 与指令链都是**候选来源**：BTF 候选越界只作废该候选、回退指令链，全部来源都失败才 fail-closed（`-ENOENT`）；
两条日志把原因分开——BTF 越界记 `BTF subprocess_info.path out of type: off=… size=…` 再记
`path offset=0x… via=insn (btf candidate rejected)`，BTF 压根没有则只记 `path offset=0x… via=insn`。

写入后 `run_cmd_path_matches()` 回读，判据是**指针身份**（`*slot == sh`，写入进去的就是模块自己 `.data` 里的 `sh`
地址），不是内容比较：偏移落在 `0x100` 内却指向无效地址时，`strncmp` 会 deref 野指针（8 字节写变成缺页/panic），
比指针只读回同宽的值。不一致即打 `exec: helper path write-back mismatch at 0x…`、回收 `info`、返回 `-EIO` 且不 exec。

**槽位必须 `volatile`**：`*p = X; if (*p != X)` 是 GCC 眼里的死存储消除对象，非 volatile 写法会被折叠成
`str` + `csel`、**不产生任何 `ldr`**，失配分支直接变成不可达死代码（`aud050b` 实例即此坑，源码看着完全正确）。
所以判据只能看产物：`tools/check_path_guard.py` 反汇编 `run_cmd_work`（判据见「自检与生命周期」一节），
base 与 baselines 两个变体都查。

**真值 0x38 的独立来源只有设备侧**：`su_probe 0.1.2` 在 XQ-DQ72 上报 `path offset=0x38 via=btf`。主机夹具两条路径
（指令链 `test_run_cmd.c` 的 `entry[2] = 0xf9401c09` 用例、BTF 的 `btf_fixture()` 用例）都只是「能取到夹具给定的
0x38」——BTF 那条的值由夹具 `btf_records[1].members[0].offset` 写死，属 roundtrip，不是独立证据。

SID 的静态配置不包含 `selinux_blob_sizes.lbs_cred`。这个值由内核启动后形成，加载时从实际符号取得，再加到结构内偏移上；没有该符号时使用结构内偏移。动态路径保存的 SID 偏移已包含运行时加量。不得把裸镜像中初始化前的 blob 大小写成最终偏移。

移植时核对工作项共同前缀：node=0、func=16、worker=24，现代 canceling=32，模块存储为 40 字节。静态版将这项核对留在离线分析阶段；不兼容时需修改结构定义或执行方案，不能通过四字段补丁修正。新旧 worker API 依据实际符号选择，函数地址、执行域 SID 以及 KP 提供的凭据布局继续在运行时取得。

## 构建与替换

各模块保留独立 Makefile。新的空输出目录中，`all` 生成动态和静态两份普通版，`baselines` 只生成静态版。

```sh
make -C run_cmd_demo all OUT_DIR=../local/run-cmd-round1
```

静态版从 `rc_offsets.c` 生成内嵌布局（schema 3），同名 `.kpm.json` 从产物导出。新基线可直接配合目标配置改表；旧件继续使用原配套 JSON。使用目标分析结果填写完整 `offsets` 后，执行：

```sh
python3 patch_offsets.py patch run_cmd_demo_baselines.kpm --offsets target-offsets.json --output target.kpm
```

已有基线只需 Python 标准库，用户侧无需 NDK。修改源码后的候选构建使用仓库统一入口，并通过 `--extra-input patch_offsets.py` 捕获共享工具；未冻结构建记为 exploration。原产物和清单不可覆盖。

统一候选构建使用 `--target all`，保留默认 `LAYOUT_DIR=$(OUT_DIR)`，让静态 JSON 与 KPM 同目录并一起归档。生成的 `.kpm.json` 不计入源码输入；统一入口会在重建前将旧 KPM 与 JSON 一起移走。手工构建可以另设 `LAYOUT_DIR`，但交接前必须将配套 JSON 放回 KPM 同目录，并核对其产物哈希与清单登记。

## 自检与生命周期

`tools/test_run_cmd.py` 使用既有 C Oracle 验证动态控制、执行凭据和偏移逻辑；`tools/test_baselines.py` 验证模式元信息、静态偏移补丁的字节范围及运行时 SID 加量。宿主适配只处理元信息宏与 ELF section 属性。执行域契约收窄后，原回退成功断言改为「只查询目标域且拒绝排队」，分别验证查询报错和零 SID；保留同实例重新提交、原结果不变、回读失配及凭据缺失的检查，并新增早期加载参数被拒后仍处于 `idle` 的用例。其余依赖、长度、worker、控制回包、文件描述符和锁语境断言保持。该契约迁移由 Auditor 独立复核。

`tools/check_path_guard.py` 对 base 和 baselines 分别检查产物中的 path 回读守卫（AUD-050 S2、AUD-056）：
写入、同址回读及比较只能形成一组守卫；比较必须使用回读和写入的 `sh` 指针对应的不同寄存器，且比较前不得重写。
`b.eq` 必须跳到 exec 窗口的首条槽位 `ldr`，不能是空分支；失配块以越过该窗口的 `b` 或 `ret` 终止，块内不得有条件分支跳进窗口。
exec 使用 `ldr <槽>` → `mov w1,#2`（`UMH_WAIT_PROC`）→ `blr`，槽位加载与间接调用使用同一寄存器。

| 常规检查结果 | 退出码 | 判定与处理 |
| --- | --- | --- |
| `PASS` | `0` | 已识别守卫，产物断言全部通过。 |
| `FAIL` | `1` | 守卫断言不成立，例如缺少同址回读或失配路径仍可进入 exec；按脚本打印的原因复核。 |
| `UNKNOWN` | `2` | 找不到待查函数，或前置守卫检查通过后仍无法识别 exec 窗口；交维护者裁定，不计为失败或通过。 |

一次检查多份产物时，任一 `FAIL` 返回 `1`；没有 `FAIL` 但有 `UNKNOWN` 返回 `2`。结论只对本次检查的 `instance_id` 与 SHA-256 对应字节成立，不接入发布门禁。

`--negative <kpm>` 要求负向件明确为 `FAIL`；`--negative-control <kpm>` 用通过件的反汇编做回归，要求 **gap0 PASS、gap1–gap11 全 FAIL**。

`path_guard_cases()` 覆盖源码级的三条拒载路径：BTF 成员越界（回退指令链；指令链也失败时整体 `-ENOENT`）、偏移超 `0x100`（`0x110` 拒、`0x100` 收）、写后回读不一致（`-EIO` 且 setup 之后不再 exec）；另有一条「指针不等但内容完全相同」的用例必须返回 `-EIO`（防止退回内容比较），并直测生产判据 `run_cmd_path_matches()`（同指针收、异指针拒、空槽拒）。

ctl0 只提交或查询命令，worker 等待 UMH 完成。KP 的 exit 调用上下文和 worker 回调生命周期限制仍存在，当前版本通过重启移除或更换。宿主与离线结果不能替代实际 SELinux、CFI、线程和设备测试。

独立debug目标不再生成：当前模块未使用CONFIG_DEBUG；既有debug归档和独立记录保留。
