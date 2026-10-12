# 真机异常升级单：zram_zstd 静止态卸载与二次加载 Panic 验证

> 触发背景：应用户补充测试要求（「你已经测试了 在 comp_algorithm=[zstd] 且 swap 处于活动状态下，是否补测一个 comp_algorithm 非 zstd模式，并且暂时关闭 swap？」），在确认物理备份完好的前提下，执行静止态（非 zstd 算法 + swapoff）卸载及边界探测实验。  
> 流程规范：遵循 [`docs/process/07-escalation-device.md`](../../../docs/process/07-escalation-device.md)。

---

## 身份三要素

| 项 | 值 |
| --- | --- |
| commit | `56128f735640a3dd90dca440938ff5d140e7041e` |
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

## 现象与对照实验全过程

### 阶段 1：静止态基线确认
- 确认算法配置：`comp_algorithm=[lzo] lz4 deflate`（zstd 未激活）；
- 执行 `swapoff /dev/block/zram0`，`/proc/swaps` 确认无活动 swap 分区。

### 阶段 2：静止态卸载（证实无同步崩溃）
- 执行 `/data/adb/kpatch su kpm unload zram_zstd`；
- 命令返回：`UNLOAD_RC=0`；
- 内核日志输出：
  ```text
  [-] KP E unload_module: name: zram_zstd
  zram_zstd: DO NOT UNLOAD: zram may retain codec callbacks
  [+] KP I unload_module: name: zram_zstd, rc: 0
  ```
- 系统状态：`uptime 12 min` 保持单调递增，`boot_id` 未变，`kpm list` 确认模块已移出列表；
- **现象事实 1**：在静止态（非 zstd + swap 关闭）下卸载模块，**不会立即引发同步内核崩溃**。

### 阶段 3：非 zstd 业务可用性验证
- 重新启用 swap：`swapon /dev/block/zram0`；
- 算法维持 `[lzo]`，`mm_stat` 显示正常压缩换页（4096 -> 81 字节），系统读写正常；
- **现象事实 2**：模块卸载后，内核内置的 `lzo` 压缩机制可独立正常运转。

### 阶段 4：算法注销缺陷与残留野指针确认
- 读取 `/proc/crypto`：发现 `driver: zstd-kpm` **仍然驻留且 refcnt=1**；
- 证实：KernelPatch 卸载仅释放了 KPM 模块内存，但**未向 Linux 加密子系统注销该算法**，全局链表保留了悬挂条目。

### 阶段 5：二次加载触发 Use-After-Free 内核恐慌
- 尝试通过 `/data/adb/kpatch su kpm load /data/local/tmp/zram_zstd_test.kpm` 重新加载该模块；
- 加载调用 `crypto_register_alg(zstd_alg)` 时，在内核全局算法链表遍历/查重阶段解引用已破坏的内存节点；
- **立即触发内核 Panic**；
- adb shell 连接瞬间断开（退出码 `255`），硬件看门狗复位，设备跌入 fastboot 模式（`<设备指纹 b754dad7> fastboot`）。

---

## 证据清单

| 证据 | 文件（相对路径） | 采集结果 |
| --- | --- | --- |
| 嵌入前原始 boot 分区备份 | `local/tester-raw/boot_b_backup.img` | 完好（SHA-256: `b71d23c9...`） |
| 0.2.0 legacy 重打包镜像 | `local/tester-raw/new-boot-0.2.0-legacy.img` | 完好（SHA-256: `cc0d1c3c...`） |
| 静止态卸载日志 | 本单摘录 | `UNLOAD_RC=0`，系统存活在册 |
| 残留算法验证 | 本单摘录 | `/proc/crypto` refcnt=1 悬挂条目在册 |
| 二次加载崩溃日志 | 本单摘录 | 退出码 255，设备跌入 fastboot 在册 |
| 设备环境事实 | `Tester/reports/environments/2026-10-11-b754dad7.md` | 已采集 |

---

## 已做 / 未做

- **已做**：
  1. 完整执行「静止态卸载 -> lzo 业务复核 -> 残留野指针探测 -> 二次加载触发崩溃」的全链条验证；
  2. 证实卸载后系统全局链表已被毒化；
  3. 保全原始备份 `boot_b_backup.img`；
  4. 遇到掉线后**立即停止一切重试**，不盲目操作硬件。
- **未做（必须确认）**：
  1. **未执行 `fastboot flash`**（严格遵守 Tester 权限边界，交由维护者处理）；
  2. 未清除 pstore；
  3. 未改动任何偏移或源码；
  4. 未重复尝试加载。

---

## 未覆盖

- **未覆盖安全反注册支持**：Linux 4.4 架构缺少 KPM 级别的安全 crypto 注销支持，无法覆盖"无泄漏且无野指针的安全反注册"路径；
- **未覆盖更高内核版本表现**：本次仅在目标 4.4 设备完成，更高版本（如 5.10 / 5.15）的表现未覆盖。

---

## 需要维护者执行的物理动作（Tester 发起，A5）

| 项 | 内容 |
| --- | --- |
| 动作 | 在 fastboot 模式下执行重启：`fastboot reboot`（或回滚：`fastboot flash boot_b local/tester-raw/boot_b_backup.img && fastboot reboot`） |
| 为什么我做不了 | 设备处于 fastboot 模式，Tester 权限严格受限，禁止自行执行恢复性刷写/重启 |
| 已尝试的软件通道 | 无（保留 fastboot 现场供维护者操作） |
| 期望结果 | 设备重启后引导进入 Android 系统恢复 ADB 连通 |
| 风险与不可逆性 | `boot_b` 镜像已预置 0.2.0 legacy 正常引导版本，直接 `fastboot reboot` 无风险 |
| 发起时间 | 2026-10-11T06:45:40-0700 |

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

- [x] 确认静止态对比实验结果：
  1. 静止态（`[lzo]` + `swapoff`）下卸载瞬间**不会引发同步崩溃**，且 `lzo` 正常业务仍可运作；
  2. 但卸载后内核全局 `crypto_alg_list` 残留野指针，**二次加载必然触发 Use-After-Free 内核恐慌**；
  3. 彻底印证 `AUD-009` 与 `RA-001`：**该模块不可卸载、不可动态重载，必须作为 boot 嵌入常驻模块使用**。
- [ ] 维护者执行 `fastboot reboot` 恢复设备进入系统；
- [ ] 维护者确认关闭 `MNT-015` 并进行最终验收。
