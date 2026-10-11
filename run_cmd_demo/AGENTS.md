# run_cmd_demo 开发约定

## 编译模式

本模块共用命令执行逻辑，定义 `CONFIG_KPM_BASELINES` 编译静态基线，未定义时为动态版。两版管理名称都是 `run_cmd_demo`；文件分别为 `<模块>_<版本>_baselines.kpm` 和 `<模块>_<版本>.kpm`，debug 在末尾增加 `_debug`。模式记录在 `offset_mode` 中。

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

SID 的静态配置不包含 `selinux_blob_sizes.lbs_cred`。这个值由内核启动后形成，加载时从实际符号取得，再加到结构内偏移上；没有该符号时使用结构内偏移。动态路径保存的 SID 偏移已包含运行时加量。不得把裸镜像中初始化前的 blob 大小写成最终偏移。

移植时核对工作项共同前缀：node=0、func=16、worker=24，现代 canceling=32，模块存储为 40 字节。静态版将这项核对留在离线分析阶段；不兼容时需修改结构定义或执行方案，不能通过四字段补丁修正。新旧 worker API 依据实际符号选择，函数地址、执行域 SID 以及 KP 提供的凭据布局继续在运行时取得。

## 构建与替换

各模块保留独立 Makefile。新的空输出目录中，`all` 生成两份普通版，`debug` 生成两份 debug，`baselines` 只生成静态普通/debug 两份。

```sh
make -C run_cmd_demo all debug OUT_DIR=../local/run-cmd-round1
```

根目录 `patch_offsets.py` 的 schema 3 适用于普通偏移表；schema 1/2 保留原有 Binder ABI 契约。静态 KPM 附带同名 `.kpm.json`，生成布局时使用 `--source run_cmd_demo/rc_offsets.c`。使用目标分析结果填写完整 `offsets` 后，执行：

```sh
python3 patch_offsets.py patch run_cmd_demo_baselines.kpm --offsets target-offsets.json --output target.kpm
```

已有基线只需 Python 标准库，用户侧无需 NDK。修改源码后的候选构建使用仓库统一入口，并通过 `--extra-input patch_offsets.py` 捕获共享工具；未冻结构建记为 exploration。原产物和清单不可覆盖。

统一构建入口当前会把模块内的 JSON 计入源码输入，候选构建须用 `LAYOUT_DIR` 将生成的布局放在新的输出目录中，避免生成文件改变输入清单。例如目标参数为 `all debug LAYOUT_DIR=../local/run-cmd-round1/layouts`；布局与其 KPM 的 SHA-256 对应，交接时一同保存。

## 自检与生命周期

`tools/test_run_cmd.py` 使用既有 C Oracle 验证动态控制、执行凭据和偏移逻辑；`tools/test_baselines.py` 验证模式元信息、静态偏移补丁的字节范围及运行时 SID 加量。已有 C 断言保持原样，宿主适配只处理元信息宏和 ELF section 属性。

ctl0 只提交或查询命令，worker 等待 UMH 完成。KP 的 exit 调用上下文和 worker 回调生命周期限制仍存在，当前版本通过重启移除或更换。宿主与离线结果不能替代实际 SELinux、CFI、线程和设备测试。
