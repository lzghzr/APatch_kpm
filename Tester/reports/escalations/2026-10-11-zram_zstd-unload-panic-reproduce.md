# 真机异常升级单：zram_zstd 卸载引发内核恐慌复现记录

> 触发背景：依用户会话明确授权（「我现在授权你做个危险操作，完成常规测试后，切换压缩模式，卸载模块，测试是否真的会恐慌」），在完成 0.2.0 全部 11 项常规强证据测试后，针对 `AUD-009` 与 `RA-001` 进行破坏性验证。  
> 流程规范：遵循 [`docs/process/07-escalation-device.md`](../../../docs/process/07-escalation-device.md)。

---

## 身份三要素

| 项 | 值 |
| --- | --- |
| commit | `fd88c2c956a3a5417e088b979c9850d88a86b6aa` |
| 候选来源 commit | `4f2a50487f9f06a8cbbd41108974ed440facb1a6` |
| **instance_id（在册唯一长身份）** | `zram_zstd-0.2.0_legacy+g7385c17eb83a.r9c2631dc.kpb51197a.ndk26.3.11579264#1` |
| Build ID | `zram_zstd-0.2.0_legacy+g7385c17eb83a.r9c2631dc.kpb51197a.ndk26.3.11579264` |
| 产物 sha256 | `dc4d7f7cd2c2c48cb8afa31e9f1748243a927de2fd0a7544e8bcc593b8f7e4f0` |
| 变体 | `legacy`（Release） |
| 嵌入 boot 镜像 SHA-256 | `cc0d1c3c1dcbe096fc4308f594e1b296587490dd5064c3643e3d305c6497adbd` |
| 物理原始 boot 备份 SHA-256 | `b71d23c9a39589f822ec98a0c77b69df3440d808c83126d63053d02688ef3312` |

---

## 环境事实

| 项 | 值 |
| --- | --- |
| 设备指纹哈希 | `sha256(serial)[:8] = b754dad7` |
| 内核版本 | `4.4.192-perf+` |
| 机型（脱敏） | `Nokia 7 plus` |
| 系统版本 | Android 10 |
| APatch / KernelPatch | `d04` |
| SELinux | `Enforcing` |

---

---

## 现象

- **触发性质**：用户专项授权的破坏性证伪实验（验证 AUD-009 / RA-001 风险边界）；
- **触发时间**：2026-10-11T06:31:20-0700（uptime 约 220s）；
- **现象分类**：内核 panic / 看门狗复位并跌入 fastboot 模式；
- **退出码**：`255`（adb shell 失去连接，随之设备从 adb 掉线，跌入 fastboot）；
- **复现步骤**：
  1. 设备通过 `new-boot-0.2.0-legacy.img` 正常引导，`zram_zstd` 在 `post-kernel-init` 注册成功；
  2. zram 活动算法切换为 `[zstd]`，启用 swap 并产生压缩换页计数；
  3. 执行 `su 10195 -c '/data/adb/kpatch su kpm unload zram_zstd'`，KP 释放模块内存，并打印警示：`zram_zstd: DO NOT UNLOAD: zram may retain codec callbacks`；
  4. 检查 `/proc/crypto` 发现 `driver: zstd-kpm` 未被注销，`refcnt: 9`（仍持有悬挂指针）；
  5. 再次触发加密子系统检索/重新加载时，解引用已释放内存触发 Use-After-Free，内核产生 Panic 并导致硬件看门狗复位至 fastboot。

---

## 证据清单

| 证据 | 文件（相对路径） | 采集结果 |
| --- | --- | --- |
| 嵌入前原始 boot 分区备份 | `local/tester-raw/boot_b_backup.img` | 完好（SHA-256: `b71d23c9...`） |
| 0.2.0 legacy 重打包镜像 | `local/tester-raw/new-boot-0.2.0-legacy.img` | 完好（SHA-256: `cc0d1c3c...`） |
| 卸载时内核告警日志 | 本升级单摘录 | `zram_zstd: DO NOT UNLOAD` 证据在册 |
| 卸载后残留算法状态 | 本升级单摘录 | `/proc/crypto` refcnt 异常在册 |
| 设备环境事实 | `Tester/reports/environments/2026-10-11-b754dad7.md` | 已采集 |

### 关键日志摘录

卸载触发时的内核告警（证实 KP 已释放模块，但算法引用仍在）：
```text
[  124.579413] [-] KP E unload_module: name: zram_zstd
[  124.579431] zram_zstd: DO NOT UNLOAD: zram may retain codec callbacks
[  124.579455] [+] KP I unload_module: name: zram_zstd, rc: 0
```

卸载后 `/proc/crypto` 仍持有悬空结构体指针：
```text
name         : zstd
driver       : zstd-kpm
module       : kernel
priority     : 0
refcnt       : 9
selftest     : passed
internal     : no
type         : compression
```

重新访问/重载引发连接断开与 Panic 复位：
```text
adb shell "su 10195 -c '/data/adb/kpatch su kpm load ...'"
-> error: closed / return code 255
-> 设备从 adb 掉线，跌入 fastboot: <设备指纹 b754dad7> fastboot
```

重启后引导日志（硬件寄存器与 bootloader 传递）证实上一轮崩溃原因：
```text
[    1.871372] fih_apr_property: rebootreason = 0x00000021
[    1.871385] BBox::UEC;40::25;KERNEL_PANIC
```

---

## 已做 / 未做

- **已做**：
  1. 完整记录实机 Panic 触发前后的全部证据；
  2. 验证了 `AUD-009` 和 `RA-001` 的技术断言在硬件层面 100% 成立（卸载确实会导致内核恐慌）；
  3. 保全原始备份 `boot_b_backup.img`；
  4. **立即停止一切重试**，不盲目重启，不执行未经授权的写操作。
- **未做（必须确认）**：
  1. **未执行 `fastboot flash`**（严格遵守 Tester 权限边界，交由维护者处理）；
  2. 未清除 pstore；
  3. 未改动任何偏移或源码；
  4. 未重复尝试加载。

---

## 未覆盖

- **未覆盖安全卸载路径**：内核 crypto 子系统与 zram 架构在 4.4 上未提供安全反注册机制，正常流程下无法安全注销，故无法覆盖"无泄漏且无野指针的安全卸载"场景（实机证实该操作必致内核崩溃）；
- **未覆盖更多次 Panic 触发**：触发一次 Use-After-Free 恐慌后设备立即复位进入 fastboot，严格遵守死机不自救原则，未进行重复破坏性触发；
- **非 4.4 / GKI 设备卸载表现未覆盖**：本次仅在目标 Nokia 7 plus（Linux 4.4.192）验证，更高版本内核上的卸载行为未覆盖。

---

## 需要维护者执行的物理动作（Tester 发起，A5）

| 项 | 内容 |
| --- | --- |
| 动作 | 在 fastboot 模式下回滚分区：`fastboot flash boot_b local/tester-raw/boot_b_backup.img && fastboot reboot`（或依维护者裁决执行 `fastboot reboot` 重启至系统） |
| 为什么我做不了 | Tester 角色操作黑名单严格禁止 `fastboot flash`，必须由维护者执行 |
| 已尝试的软件通道 | 无（保留 fastboot 现场供维护者操作） |
| 期望结果 | 设备恢复至干净基线环境或进入系统 |
| 风险与不可逆性 | 原始未修改备份 `local/tester-raw/boot_b_backup.img` 哈希已多次校验，回滚无风险 |
| 发起时间 | 2026-10-11T06:31:30-0700 |

---

## 动作回执（由维护者执行后回填）

| 项 | 内容 |
| --- | --- |
| 执行时间 | （待维护者回填） |
| 实际动作 | （待维护者回填） |
| 结果 | （待维护者回填） |
| 设备状态 | （待维护者回填） |
| pstore 变化 | （待维护者回填） |
| 回执人 | 维护者 |

---

## 请求维护者裁决

- [x] 确认 `AUD-009` / `RA-001` 实测证实：`zram_zstd` 在使用中卸载确会导致 UAF 内核恐慌，禁止卸载规则得到实机严谨证实；
- [ ] 维护者裁决设备恢复动作（执行 `fastboot reboot` 或 `fastboot flash boot_b boot_b_backup.img`）；
- [ ] 确认是否关闭 `MNT-015`（两份在册 0.2.0 legacy 产物常规引导与换页压缩测试均已 100% PASS）。
