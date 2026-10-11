# re_kernel

基于 [Re:Kernel](https://github.com/Sakion-Team/Re-Kernel/tree/main/LKM-Source) 的 KernelPatch 模块移植。向配套墓碑应用发送 Binder、信号和网络事件通知，由墓碑应用决定是否解冻。模块同时清理冗余的异步 Binder 消息。

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

嵌入内核开机加载时，选择 `post-kernel-init`。默认的 `pre-kernel-init` 可能早于 Generic Netlink 初始化，出现 `-107`。

使用 kptools 时，在该模块的 `-M <kpm>` 或 `-E <已嵌入名称>` 后指定 `-V post-kernel-init`。加载事件属于嵌入配置，修改后需要更新该配置。

## 静态移植

准备目标设备的 `boot.img`、静态基线及同一构建的 `.kpm.json`，分析目标偏移后填写到 JSON 的 `offsets` 中。基线是移植模板，须先完成目标适配。

在仓库根目录运行：

```sh
python3 patch_offsets.py patch re_kernel_baselines.kpm --offsets target-offsets.json --output target.kpm
```

配套布局文件应放在基线旁，命名为 `re_kernel_baselines.kpm.json`。替换工具只依赖 Python 标准库，用户侧无需 NDK。

## 更新记录

### 11.7-20261010

新增 BTF 获取偏移，动态版加载时优先查询目标内核 BTF<br />
缺少 BTF 数据或查询接口时，继续尝试内核函数推导<br />
提供动态版和静态基线两种产物

### 11.7

对齐 Sakion Re:Kernel 11.7 的 Generic Netlink 协议，支持网络 UID 增删和版本查询<br />
保留异步消息 code 29～32 上报过滤及本地冻结判断<br />
异步清理与本项目 rekx 的基础去重一致：保留一条匹配旧消息，跳过带对象或额外缓冲区的消息，锁内复核后同步释放

### 8.0.0

同步LKM<br />
适配新的 `rekernel_cmd`<br />
为网络解冻增加 uid 过滤

### 7.6.0

过滤更多网络包

### 7.5.1

更加严谨的处理netlink消息

### 7.5.0

增加netlink消息处理，支持通过消息移除/proc/rekernel

### 7.0.1

适配更多内核

### 7.0.0

PACKET_SIZE 从 128 增加到 256<br />
异步 netlink_kmsg 新增 `rpc_name` 和 `code` 字段

### 6.0.14

新增 netlink hello<br />

### 6.0.13

修复 6.0.12 引入的错误

### 6.0.12

修复 binder_stats_deleted(BINDER_STAT_TRANSACTION) 地址错误<br />
理论上支持 6.6

### 6.0.11

修复 lineage-22.1-4.19 内核崩溃问题

### 6.0.10

支持 `Harmony` 内核

### 6.0.9

同步LKM<br />
保留最早的异步消息

### 6.0.8

由于 4.x 和 5.x 版本差异过大, 去除 /proc/rekernel/ 的读写权限<br />
更加小心的清理过时消息<br />
支持 6.1

### 6.0.7

为了兼容5.4内核, 不再增加 TF_UPDATE_TXN

### 6.0.6

优化 binder 被冻结时的体验

### 6.0.5

变更 binder_proc->context 的搜索条件<br />
变更 task_struct->jobctl 获取方式<br />
移除 frozen()<br />
binder 被冻结时不再有动作

### 6.0.4

再次扩大 binder_proc->alloc 的搜索范围

### 6.0.3

修复 4.4 内核清理过时消息时卡死

### 6.0.2

修复某些内核函数过长导致的加载失败

### 6.0.1

将网络解冻 hook 点从 ip 层变更为 tcp 层

### 6.0.0

新增网络解冻, 同步版本号

### 1.4.0.4

函数版本判断条件由内核版本判断改为分析函数参数

### 1.4.0.3

解决应用长时间冻结后, 唤醒重载的问题

### 1.4.0.2

变更 hook 函数, 使其适配更多内核

### 1.4.0.1

修复偏移计算错误, 增加 README

### 1.4.0.0

同步官方 kpm 仓库，尝试更换编译器

### 1.3.6.5

CGRP_FREEZE 支持改为可选项，因为 4.14 及以下内核不支持此功能

### 1.3.6.4

修复对 5.4 的支持<br />
模块依然支持 4.4，但加载时会判断是否支持 `freeze`，如果内核不支持此功能则无法加载

### 1.3.6.3

将线程休眠判断逻辑从 `hans` 改为 `millet`<br />
增加 `quiet` 版，大幅减少唤醒次数

### 1.3.6.2

修复 `f_p` 重启失效

### 1.3.6.1

变更休眠线程判断条件

### 1.3.6.0

同步 Kernel.Modifier.v3.6，版本号也同步一下
