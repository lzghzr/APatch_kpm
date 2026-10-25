# re_kernel 工程约定

本目录由 Developer 维护，遵循仓库根目录及 docs/ 的角色与身份规则。README 面向普通用户；加载机制、协议、移植和排查细节在本文件维护。更新记录在 README 保留原文。

## 接入、排查与静态移植

基于 Re:Kernel 的 KernelPatch 移植，向配套墓碑应用发送 Binder、信号和网络事件通知，由应用决定是否解冻；模块同时清理冗余异步 Binder 消息。

模块管理名称为 `re_kernel`，使用 Re:Kernel 的消息协议。需要配套墓碑应用支持该协议。

## 选择版本

| 版本 | 文件 | 使用方式 |
| --- | --- | --- |
| 动态版 | `re_kernel.kpm` | 加载时自动获取目标内核偏移 |
| 静态基线 | `re_kernel_baselines.kpm` | 根据目标内核修改偏移后加载 |

两种版本在 APatch 中都叫 `re_kernel`，选择一种加载即可。文件名带 `_debug` 的版本用于排查问题。

适配目标为 Android ARM64，内核 4.4～6.6。动态版优先使用 BTF；缺少必要数据或查询接口时，尝试从内核函数推导。获取失败时停止加载，具体原因见内核日志。

## 加载

在 APatch 的内核模块页面加载动态版或已移植的静态版，再由配套墓碑应用连接。网络监控 UID 由墓碑应用配置。

### 安装方式

需要 APatch/KP 支持目录自动加载。在内核模块页选择“安装”（不是“立即加载”），安装器按管理名称将文件保存为 `/data/adb/ap/kpm/re_kernel/re_kernel.kpm`，即 `/data/adb/ap/kpm/<id>/<id>.kpm`；输入文件的版本后缀不影响此路径。启用时应无该目录下的 `disable` 标记。

重启后，KP 在 `post-fs-data` 的 `before` 事件处理期间读取目录加载，无需设置嵌入用的 `-V`。核对模块版本、`load_source=file`、`load_event=post-fs-data` 及对应目录加载日志 `rc=0`；仅有 `load_source=file` 也可能是手动加载，不能单独作自动加载判据。再确认 `rekernel` family，由配套应用连接、订阅并配置网络 UID。模块不会补发加载或订阅前的通知。

**已实机验证自动加载及 family 建立**：结论仅来自 4.19 / XQ-AT52 / KP d09 单机，5.15 未测，不能外推；墓碑应用业务链路未验证。候选身份与实测记录见 [Tester 报告]。该实验以手动复制文件完成，不代表管理器“安装”按钮全流程已实测。

### 嵌入方式

嵌入启动镜像时，**建议**选择 `post-kernel-init`，让原生 Generic Netlink 先完成初始化。符号与偏移检查通过后，若 `init_net->genl_sock` 仍为空，初始化直接返回 `-107`（`-ENOTCONN`）。`pre-kernel-init` 仅在 Genl socket 已建立且其余依赖满足时可行；事件名本身不保证可用。事后 family 存在不能反推加载瞬间已可通信。

使用 kptools 时，在该模块的 `-M <kpm>` 或 `-E <已嵌入名称>` 后指定 `-V post-kernel-init`。加载事件属于嵌入配置，修改后需要更新该配置。

### 更新、停用与边界

- 同管理名 `re_kernel` 冲突返回 `-EEXIST`（-17），不会替换旧实例。嵌入/安装及静态/动态均只选一份，改文件名不能避开冲突。
- `/data/adb/ap/kpm/re_kernel/disable` **只阻止目录加载**，不卸载当前实例，也不禁用嵌入副本。停用已安装文件时设置标记；嵌入件需取消嵌入，再重启并确认实际来源。
- 不要热卸载或热换版；本模块卸载生命周期尚未验证，更换或移除须重启。替换已安装文件后当前仍运行旧版，必须重启才生效；嵌入件更新须更新启动镜像。
- 保留 userdata 通常会保留已安装文件，但**不保证 OTA 后兼容**。新 boot 仍须带支持目录加载的 KP，并满足用户态 `before` 上报、内核导出及布局/ABI 条件；静态偏移须重新核对，重启后再确认 family 和应用连接。

## 静态移植

准备目标设备的 `boot.img`、静态基线及同一构建的 `.kpm.json`，分析目标偏移后填写到 JSON 的 `offsets` 中。基线是移植模板，须先完成目标适配。

在仓库根目录运行：

```sh
python3 patch_offsets.py patch re_kernel_baselines.kpm --offsets target-offsets.json --output target.kpm
```

配套布局文件应放在基线旁，命名为 `re_kernel_baselines.kpm.json`。替换工具只依赖 Python 标准库，用户侧无需 NDK。
