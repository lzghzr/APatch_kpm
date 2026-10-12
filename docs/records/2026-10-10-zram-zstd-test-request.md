# 真机测试请求：zram_zstd 0.1.0（重跑轮，2026-10-10）

角色：维护者。本文是**测试请求与授权记录**，不含测试结论。测试对象、判据与回执由 Tester 给出。
授权依据：用户 2026-10-10 明确「可以授权嵌入模块」；授权边界见下，已同步进
[metadata/identity.json](../../metadata/identity.json) 的 `tester_authorization` 与
`tester_criteria_unload_unsafe`。

## 一、测试对象（只测可交付集合）

模块名（`kpatch` 侧）：`zram_zstd`；加载事件：`post-kernel-init`（必须开机嵌入，运行时手动加载仅用于检查注册）。

| 变体 | instance_id | 产物 SHA-256 | 字节 |
| --- | --- | --- | --- |
| `base` | `zram_zstd-0.1.0+gd464ad07ccb0.r21df036f.kpb51197a.ndk26.3.11579264#1` | `f48f3155f6ada61803ace3cd627772ea595681489f3be6305ac192557f0ab7d2` | 229312 |
| `baselines` | `zram_zstd-0.1.0_baselines+gd464ad07ccb0.rf876d2a6.kpb51197a.ndk26.3.11579264#1` | `d0c28ea484c38ecd7b13e39e13f2566a5719e9feceb99dd7fb425f733241ca7f` | 222536 |
| `baselines_debug` | `zram_zstd-0.1.0_baselines_debug+gd464ad07ccb0.r8985a06f.kpb51197a.ndk26.3.11579264#1` | `455426a2352a95586fdc05ff360d689377fd1061c9547d79a38d8b25435ae98d` | 222536 |
| `debug` | `zram_zstd-0.1.0_debug+gd464ad07ccb0.rf04090a6.kpb51197a.ndk26.3.11579264#1` | `2490abcfc0ed4497c3f2e4462c4608de57d46f41e1c5eede349f2b35805d18ad` | 229312 |

**初始候选 4 份（`+gc330fe19c6d2`）不在本次测试范围**：其产物缺必需节 `.kpm.ctl0`，`artifact_audit` 阻断、
控制入口探测不可用，审计已判定不可交付。

## 二、授权范围

| 允许 | 限制 |
| --- | --- |
| **嵌入开机加载**：把上表指定实例的 `.kpm` 写入开机加载配置/模块目录，使其在 `post-kernel-init` 自动加载；为此可重启设备 | 一次只嵌入**一个**实例；逐实例记录 `instance_id` + 产物 SHA-256；不得用其它字节替代 |
| `adb shell/pull/push/getprop/dmesg`、`adb reboot`、`adb reboot bootloader`、`fastboot devices/getvar/reboot` | 仍禁止：`fastboot flash/erase/-w`、清 pstore、改 superkey、重装 APatch、刷机、recovery 清数据 |
| 记录与采样：`/proc/crypto`、`/sys/block/zram0/comp_algorithm`、`module list`、`dmesg` | superkey 只经环境变量传入，不落盘；报告用设备指纹哈希代替序列号 |

**禁止卸载**：本模块的卸载路径是已书面接受的高风险（`RA-001`，定级高，见
[模块登记](../../metadata/modules/zram_zstd.json)）。任何 `module unload` 试验都视为违反该风险接受，
必须先重新评估 `RA-001`。移除嵌入只能通过「撤销嵌入配置 + 重启」完成。

## 三、两个阻塞项（执行前必须解决）

1. **测试工具必须支持不卸载流程**：`Tester/tools/run_test.sh` 当前无条件执行
   `module unload`（第 347/411 行）并以「卸载干净」为判据（第 439 行），对本模块**不可直接使用**。
   请先增加 `--no-unload`（或等价的模块专用流程），并在 `selftest_scripts.sh` 中补正反用例
   （无卸载模式下不得出现 unload 命令、不得据此判定失败），再执行真机测试。
2. **必须先证明回退路径可用且已授权**：模块在开机时加载，若注册失败或引发异常，设备可能进入反复重启，
   而移除嵌入若需要恢复出厂/线刷（黑名单操作），则**不得嵌入**。请先确认并记录一条在**现有授权内**可用的回退路径
   （例如：APatch/KP 的安全模式或跳过模块的启动方式；或在不加载模块的情况下可移除嵌入配置），
   写明操作步骤与验证方式。若回退需要新增授权操作，请回报维护者，由维护者另行书面授权后再嵌入。

## 四、判据

**强判据（观测窗口内）**：

- `boot_id` 不变（同一启动内）；
- `uptime` 单调递增；
- `adb` 持续响应（每次轮询有返回）；
- 观测窗口结束时模块**仍在** `module list` 中（本模块终态是"保持加载"，不是"卸载干净"）。

**功能判据（逐条记录命令与输出）**：

- `/proc/crypto` 出现 `name: zstd` 且 `driver: zstd-kpm`；
- `cat /sys/block/zram0/comp_algorithm` 能看到 `zstd`，切换为 `[zstd]` 后 zram 读写（写满 + 读回校验）不失败；
- 手动加载路径下 `kpatch su kpm ctl0 zram_zstd ping` 返回 `pong`（嵌入加载的实例以 `/proc/crypto` 为准）；
- 换页压力（在当前可用手段内）下无崩溃、无 RCU stall。

**弱证据**：`dmesg` 无崩溃特征只能写「未观察到」，不得写成"验证通过"；结论不得外推机型/内核。

## 五、前置与留证

- 加载/嵌入前必录四项基线：`boot_id`、`uptime`、`pstore` 残留、当前模块清单；
- 每次运行使用唯一 `run_id`；同一天同产物重跑必须指定新的 `RUNDIR`/`ESCDIR`，不得覆盖旧证据；
- 退出码语义：1 判据失败、2 用法/环境、3 前置条件不满足、90 设备无响应/崩溃 → **立即停止重试**、采证并通知维护者
  （[升级流程](../../docs/process/07-escalation-device.md)）；崩溃特征出现时保持现场，不得自动卸载、不得反复加载；
- 报告需含：实例身份三要素、仪器冻结状态（工具 commit + 逐文件哈希）、命令与输出、判据计数、环境事实、未覆盖清单。

## 六、回执落点

`Tester/reports/runs/<唯一 run_id>.md`（升级单落 `Tester/reports/escalations/`）；完成后由维护者登记
`device_tests[]`，并按结果更新覆盖矩阵与验收范围。
