# 复测请求：zram_zstd 0.2.0 legacy 候选（按在册哈希，2026-10-11）

角色：维护者。本文是**复测请求**，不含测试结论。目的：关闭
[`MNT-015`](../../metadata/modules/zram_zstd.json)（上一轮实机推送的是**未登记**的 legacy 派生字节，
设备结论无法绑定在册身份）。关闭条件即本请求的执行目标：**按在册 `instance_id` + 产物哈希复测**。

## 一、复测对象（只测这两份，逐个执行）

| 变体 | instance_id | 产物 | SHA-256 | 字节 |
| --- | --- | --- | --- | --- |
| `legacy` | `zram_zstd-0.2.0_legacy+g7385c17eb83a.r9c2631dc.kpb51197a.ndk26.3.11579264#1` | `zram_zstd_0.2.0_legacy.kpm` | `dc4d7f7cd2c2c48cb8afa31e9f1748243a927de2fd0a7544e8bcc593b8f7e4f0` | 246832 |
| `legacy_debug` | `zram_zstd-0.2.0_legacy_debug+g7385c17eb83a.r544cec1c.kpb51197a.ndk26.3.11579264#1` | `zram_zstd_0.2.0_legacy_debug.kpm` | `238d291f8cdfeba10b5ed679568b26f048fc838d60d544c597ede2d9ba76f901` | 246832 |

- 源码提交 `4f2a50487f9f06a8cbbd41108974ed440facb1a6`；`kp_compat=legacy`；工具链 `ndk26.3.11579264`。
- **不测** modern 形态：4.4 上只能跑旧 KP，modern 加载会报 `unknown symbol`——这是环境事实，不是缺陷，
  记录在未覆盖清单即可（其设备证据仍缺，验收范围会写明）。
- 上一轮实测的 0.1.0 派生字节结论（[报告](../../Tester/reports/runs/2026-10-11-zram_zstd-0.1.0-4.4-boot-live#1.md)）**不继承**：
  0.2.0 是不同字节、不同源码提交。

## 二、本轮重点（与上轮的唯一差别）

**推送/嵌入前先核对在册哈希**：`sha256sum` 实测值必须等于上表对应值，且报告身份表里要写
「在册 instance_id / 在册 SHA-256 / 实测 SHA-256 = 一致」。不一致就停下来问维护者，不得沿用近似件。

## 三、授权（沿用，含边界）

| 允许 | 限制 |
| --- | --- |
| 用**设备内工具**完成开机嵌入（一次一个实例），为此可重启 | 严格限定上表字节；不得用其它字节替代；不得同时嵌入两个实例 |
| `adb shell/pull/push/getprop/dmesg`、`adb reboot`、`adb reboot bootloader`、`fastboot devices/getvar/reboot` | 仍禁止：`fastboot flash/erase/-w`、清 pstore、改 superkey、重装 APatch、刷机、recovery 清数据 |
| 记录 `/proc/crypto`、`/sys/block/zram0/comp_algorithm`、`module list`、`dmesg` | superkey 只经环境变量；报告用设备指纹哈希 `b754dad7` 代替序列号 |

- **禁止 `module unload`**（`AUD-009`/`RA-001`，高）；移除嵌入只能「撤销嵌入 + 重启」。
- **回滚由维护者本人手动执行**（`fastboot flash boot_b local/tester-raw/boot_b_backup.img`，备份
  `b71d23c9…ef3312`，已与设备端比过）；Tester 与任何代理不得执行 `fastboot flash`。
- 嵌入与首次重启期间**维护者在线待命**（开始前确认）。

## 四、判据（沿用上轮 9 项强判据，逐条给命令与输出）

1. 强判据（观测窗口内）：`boot_id` 不变（同一次启动内）、`uptime` 单调、`adb` 持续响应、
   窗口结束时模块**仍在** `module list`（本模块终态是常驻，不是「卸载干净」）；
2. `/proc/crypto` 出现 `name: zstd`、`driver: zstd-kpm`；
3. `cat /sys/block/zram0/comp_algorithm` 可见 `zstd`，切为 `[zstd]` 后 zram 写满 + 读回校验通过；
4. `swapon /dev/block/zram0` 后 `/sys/block/zram0/mm_stat` 出现有效压缩计数；
5. 若走运行时热加载路径：`kpatch su kpm ctl0 zram_zstd ping` 返回 `pong`（嵌入路径以 `/proc/crypto` 为准）；
6. 弱证据：`dmesg` 无崩溃特征只能写「未观察到」；结论不得外推机型/内核。

## 五、前置与留证

- **不卸载流程**：不得使用 `Tester/tools/run_test.sh` 默认流程（其 `module unload` 与「卸载干净」判据对本模块禁用）；
  必须先提供 `--no-unload`（或观察式流程）并在 `selftest_scripts.sh` 补正反用例；
- 嵌入前四项基线：`boot_id`、`uptime`、pstore 残留、当前 `module list`；
- 唯一 `run_id`；同日重跑用新的 `RUNDIR`/`ESCDIR`，不得覆盖旧证据；
- 退出码语义：1 判据失败、2 用法/环境、3 前置不满足、90 设备无响应/崩溃 → **立即停止重试**、采证、通知维护者
  （[07 升级流程](../process/07-escalation-device.md)）；崩溃时不得自动重启反复尝试、不得卸载；
- 报告需含：实例身份三要素（在册/实测哈希对照）、嵌入工具与步骤、仪器冻结（工具 commit + 逐文件哈希）、
  命令与输出、判据计数、环境事实、未覆盖清单。

## 六、落点与后续

`Tester/reports/runs/<唯一 run_id>.md`（异常走 `Tester/reports/escalations/`），按 R8 自行检查点提交；
维护者接收后登记 `device_tests[]`，再由独立于 owner=Developer 的角色关闭 `MNT-015`，之后进入验收与签名交付。
