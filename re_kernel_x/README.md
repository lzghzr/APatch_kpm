# ReKernel-X

基于 [ReKernel-X](https://github.com/myflavor/ReKernel-X) 的 KernelPatch 模块移植。向配套墓碑应用发送 Binder、信号和网络事件通知，由墓碑应用决定是否解冻。模块同时按规则清理冗余的异步 Binder 消息。

模块管理名称为 `re_kernel_x`，使用 ReKernel-X 的消息协议。需要配套墓碑应用支持该协议。

## 选择版本

| 版本 | 文件 | 使用方式 |
| --- | --- | --- |
| 动态版 | `re_kernel_x.kpm` | 加载时自动获取目标内核偏移 |
| 静态基线 | `re_kernel_x_baselines.kpm` | 根据目标内核修改偏移后加载 |

两种版本在 APatch 中都叫 `re_kernel_x`，选择一种加载即可。文件名带 `_debug` 的版本用于排查问题。

适配目标为 Android ARM64，内核 4.4～6.6。动态版优先使用 BTF；缺少必要数据或查询接口时，尝试从内核函数推导。获取失败时停止加载，具体原因见内核日志。

## 加载

在 APatch 的内核模块页面加载动态版或已移植的静态版，再由配套墓碑应用连接。网络监控 UID 和异步清理规则由墓碑应用配置。

嵌入内核开机加载时，选择 `post-kernel-init`。默认的 `pre-kernel-init` 可能早于 Generic Netlink 初始化，出现 `-107`。

使用 kptools 时，在该模块的 `-M <kpm>` 或 `-E <已嵌入名称>` 后指定 `-V post-kernel-init`。加载事件属于嵌入配置，修改后需要更新该配置。

卸载与热重载的生命周期处理仍待验证，移除或更换模块时建议重启设备。

## 静态移植

准备目标设备的 `boot.img`、静态基线及同一构建的 `.kpm.json`，分析目标偏移后填写到 JSON 的 `offsets` 中。基线是移植模板，须先完成目标适配。

在仓库根目录运行：

```sh
python3 patch_offsets.py patch re_kernel_x_baselines.kpm --offsets target-offsets.json --output target.kpm
```

配套布局文件应放在基线旁，命名为 `re_kernel_x_baselines.kpm.json`。替换工具只依赖 Python 标准库，用户侧无需 NDK。

构建与移植细节见 [AGENTS.md](AGENTS.md)。

## 更新记录

### 1.6-20261010

新增 BTF 获取偏移，动态版加载时优先查询目标内核 BTF<br />
缺少 BTF 数据或查询接口时，继续尝试内核函数推导<br />
提供动态版和静态基线两种产物

### 1.6-20261008

沿用上游 ReKernel-X 1.6，日期后缀标识本轮 KPM 移植<br />
Genl 收发、网络 UID 增删、异步清理规则及统一 Binder 释放调用配置

### 1.6

版本号与 [ReKernel-X 1.6](https://github.com/myflavor/ReKernel-X/releases/tag/1.6) 对齐<br />
模块改名为 `re_kernel_x`，加入作者 `myflavor`<br />
模块描述改为 `every bit belongs to you.` 看似浪漫实则没招了<br />
Genl 控制请求仅允许 UID 1000
