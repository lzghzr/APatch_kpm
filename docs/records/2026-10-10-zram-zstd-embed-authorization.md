# 维护者裁决：zram_zstd 开机嵌入授权与回滚授权（2026-10-11）

角色：维护者。本文回应 Tester 的[物理动作与高危测试申请单](../../Tester/reports/escalations/2026-10-11-zram_zstd-boot-embed-action-request.md)
（设备指纹 `b754dad7`，Nokia 7 plus / Android 10 / 内核 4.4.192），并记录授权范围与前置条件。
授权来源：用户 2026-10-10 明确「可以授权嵌入模块」；授权边界同步进
[metadata/identity.json](../../metadata/identity.json) 的 `tester_authorization`。

## 一、裁决

- **批准**对指定实例执行开机嵌入（事件 `post-kernel-init`）与引导验证。
- **同时授权回滚刷写**：`fastboot flash boot_b local/tester-raw/boot_b_backup.img && fastboot reboot`
  （备份 SHA-256 `b71d23c9a39589f822ec98a0c77b69df3440d808c83126d63053d02688ef3312`，已与设备端 sha256sum 比对一致）。
  该操作属 Tester 黑名单，**只能由维护者执行**。
- **禁止卸载**：任何时候不得执行 `module unload`（`AUD-009`/`RA-001`，定级高）；移除嵌入只能"撤销嵌入 + 重启"。

## 二、授权对象（逐个执行，一次一个）

| 项 | 值 |
| --- | --- |
| 实例 | `zram_zstd-0.1.0+gd464ad07ccb0.r21df036f.kpb51197a.ndk26.3.11579264#1` |
| 产物 | `artifacts/zram_zstd-0.1.0+gd464ad07ccb0.r21df036f.kpb51197a.ndk26.3.11579264/zram_zstd_0.1.0.kpm` |
| SHA-256 | `f48f3155f6ada61803ace3cd627772ea595681489f3be6305ac192557f0ab7d2` |
| 事件 | `post-kernel-init`（必须；`pre-kernel-init` 会被模块自身拒绝） |

其余 3 个修复候选需**另行逐次授权**（每次一个实例、一次重启）；初始 4 份不在授权范围（缺 `.kpm.ctl0`，不可交付）。

## 三、三项前置条件（满足前不得刷入）

1. **不卸载流程就绪**：不得使用 `Tester/tools/run_test.sh` 默认流程（第 347/411 行 `module unload`、第 439 行
   "卸载干净"判据）。须先提供 `--no-unload`（或等价的观察式流程）并在 `selftest_scripts.sh` 补正反用例；
   终态判据改为"模块仍在 `module list` + `boot_id` 未变 + `uptime` 单调 + `adb` 持续响应"。
2. **嵌入机制在设备上确认可用**：请先以只读方式确认实际可用的嵌入通道（APatch 管理器的模块嵌入/开机自启，
   或 KernelPatch boot 镜像补丁工具），并记录所采用的方式与版本；不得凭假设直接刷写。
3. **回滚通道可用**：设备能进入 fastboot 且 `fastboot devices` 可见（否则备份无意义，不得刷入）。

## 四、留证要求

- 刷入前后 `boot_b` 分区 sha256（`adb shell sha256sum /dev/block/bootdevice/by-name/boot_b` / fastboot 侧核对）；
- 嵌入命令、镜像路径与输出；刷写命令与 `fastboot` 回显；
- 重启后：`boot_id`、`uptime`、`module list`、`/proc/crypto`（`name: zstd`、`driver: zstd-kpm`）、
  `/sys/block/zram0/comp_algorithm`、`dmesg` 摘要（弱证据，只能写"未观察到"）；
- 任何异常按 [07 升级流程](../../docs/process/07-escalation-device.md)：立即停止重试、保持现场、通知维护者，
  并在申请单第 6 节「动作回执」回填时间、实际动作、结果、设备状态、pstore 变化与回执人。

## 五、未覆盖（授权不覆盖）

- 卸载路径（禁止）、其它候选实例、其它机型与内核版本、静态基线版（四项偏移仍为 `-1`）；
- 授权不构成"设备可用"结论：真机结果仍需按判据留证并由维护者登记 `device_tests[]`。

## 六、授权修订（2026-10-11，用户指示）

用户明确两点，据此修订执行分工（原文保留，仅追加）：

1. **嵌入由 Tester 完成**：设备内已有嵌入工具（APatch 管理器的模块嵌入能力），Tester 有权在设备侧完成嵌入，
   无需维护者代刷。此授权**覆盖该工具内部对 boot 分区的写入**（属原黑名单「刷机」范畴，故在此显式授权），
   但严格限定为第二节所列**单一实例与产物哈希**，一次一个，逐次重启。
2. **回滚由维护者本人手动执行**：若出现 bootloop / 无响应，由维护者用 fastboot 手动恢复
   （备份 `local/tester-raw/boot_b_backup.img`，SHA-256 `b71d23c9…ef3312`）。
   因此原第一节「同时授权回滚刷写（由维护者/代理执行）」**废止**：Tester 与任何代理均不得执行 `fastboot flash`；
   Tester 的职责是**立即停止、保持现场、发升级单**并把「需要维护者执行的物理动作」写清楚。

### 修订后的前置条件

| 前置 | 状态 |
| --- | --- |
| ① 禁用卸载 | 生效：任何流程（含 `run_test.sh` 默认流程）**不得出现 `module unload`**；观察式流程优先；若复用 `run_test.sh` 必须先提供 `--no-unload` |
| ② 嵌入工具 | **已具备**：Tester 用设备内工具完成；须记录工具名称/版本、实际步骤、生效方式（是否重启后生效） |
| ③ 维护者在线 | **必须**：嵌入与首次重启期间维护者在线待命（可执行 fastboot 回滚）；Tester 开始前确认 |

### 修订后 Tester 须留的证据

- 嵌入前：`module list`（确认 `zram_zstd` 尚未加载）、`boot_id`、`uptime`、pstore 状态；
- 嵌入动作：工具名称/版本、选择的对象（instance_id + 产物 SHA-256）、输出与提示、是否需要重启；
- 嵌入后重启：`boot_id`（应变化，属预期）、`module list`（应含 `zram_zstd`）、`/proc/crypto`、
  `/sys/block/zram0/comp_algorithm`、`dmesg` 摘要；
- 任何 bootloop/无响应：按 [07 升级流程](../../docs/process/07-escalation-device.md) 停止并升级，**不得自行清除或刷写**。
