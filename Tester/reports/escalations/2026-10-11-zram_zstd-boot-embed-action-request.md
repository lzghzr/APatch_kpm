# 物理动作与高危测试申请单：zram_zstd 0.1.0 内核嵌入与引导测试

> 角色：Tester（真机测试）。  
> 流程依据：`docs/process/02-roles.md`（A1 白名单/黑名单、A5 物理动作请求）、`docs/process/07-escalation-device.md`。  
> 触发背景：模块 `zram_zstd` 要求开机阶段注册算法以供 zram 选用，需嵌入内核引导镜像并重启验证。涉及分区刷写的高危动作，需由维护者裁决与执行。

---

## 1. 身份三要素

| 项 | 值 |
| --- | --- |
| 候选 source_commit | `a5e1615bdb715257b167483e3e3a6f019b4a15f0` |
| 当前 HEAD commit | `c6182a9908daa4a10db2b8aecedf1f306a155c50` |
| 模块名称 | `zram_zstd` |
| 声明版本 | `0.1.0` |
| 待测在册 Build ID | `zram_zstd-0.1.0+gd464ad07ccb0.r21df036f.kpb51197a.ndk26.3.11579264` |
| 待测候选 instance_id | `zram_zstd-0.1.0+gd464ad07ccb0.r21df036f.kpb51197a.ndk26.3.11579264#1` |
| 产物路径 | `artifacts/zram_zstd-0.1.0+gd464ad07ccb0.r21df036f.kpb51197a.ndk26.3.11579264/zram_zstd_0.1.0.kpm` |
| 产物 SHA-256 | `f48f3155f6ada61803ace3cd627772ea595681489f3be6305ac192557f0ab7d2` |
| 配套布局 / 基线 | `artifacts/zram_zstd-0.1.0_baselines+gd464ad07ccb0.rf876d2a6.kpb51197a.ndk26.3.11579264/zram_zstd_0.1.0_baselines.kpm` (`d0c28ea484c38ecd7b13e39e13f2566a5719e9feceb99dd7fb425f733241ca7f`) |

---

## 2. 环境事实与基线事实

| 项 | 值 |
| --- | --- |
| 设备指纹哈希 | `sha256(serial)[:8] = b754dad7` |
| 设备型号（脱敏） | `Nokia 7 plus` (`B2N_sprout`) |
| 内核版本 | `4.4.192-perf+ #1 SMP PREEMPT Tue Mar 9 17:03:29 CST 2021 aarch64` |
| 系统版本 / 补丁 | Android 10 / `2021-03-01` |
| SELinux | `Enforcing` |
| KernelPatch / APatch | SDK `0.13.3` / kpatch `a07` / UID 10195 授权通道 |
| 当前已加载模块 | `cgroupv2_freeze`, `re_kernel` |
| 环境预检报告 | `Tester/reports/environments/2026-10-11-b754dad7.md` |
| 基线 boot_id SHA-256 | `8ff91b2c45f948bf81d2eb34d284f18b33452a8a8167f9175d27fe8ef8e3e4a9` |
| 基线 pstore 状态 | 空（无旧崩溃残留，符合 C4 前置条件） |

---

## 3. Boot 分区脱敏备份事实

Tester 已按 A1 白名单读取通道（只读 dump + pull），在执行任何改动前完成了设备物理启动分区完整镜像备份：

| 项 | 内容 |
| --- | --- |
| 物理活动分区 | `boot_b`（对应节点 `/dev/block/bootdevice/by-name/boot_b`，当前活动 slot `_b`） |
| 分区大小 | 67,108,864 字节（64 MB） |
| 本地脱敏备份文件 | `local/tester-raw/boot_b_backup.img`（属 `local/tester-raw/`，已 gitignore，明文不入库） |
| 备份 SHA-256 | `b71d23c9a39589f822ec98a0c77b69df3440d808c83126d63053d02688ef3312` |
| 校验结果 | 100% 吻合设备端 `sha256sum /dev/block/bootdevice/by-name/boot_b` 计算值 |

---

## 4. 特殊高危属性与 Tester 权限边界声明

1. **卸载致命性（AUD-009 / RA-001）**：
   - `zram_zstd` 在初始化阶段调用 `crypto_register_alg` 将算法挂入全局链表；但内核未导出算法注销接口。
   - KernelPatch 框架在执行 `module unload` 时无条件释放模块代码和数据内存，卸载将立即致 Use-After-Free 内核 Panic 死机！
   - 维护者已在元数据中登记书面风险接受 `RA-001`，模块明确声明 **DO NOT UNLOAD**。
   - **硬约束**：本轮测试**严禁调用 `module unload`**。若测试热加载或控制通道，结束测试必须直接重启设备，绝不可执行 unload。
2. **刷机 / 嵌入内核的权限边界（02-roles.md A1 黑名单）**：
   - Tester 权限矩阵明确规定：`fastboot flash` 与 **刷机** 严格属于**禁止操作（黑名单）**。
   - 将 KPM 嵌入 boot 镜像并写入闪存属于高危刷机动作，Tester 无权自主执行分区刷写。
   - 依据 A5，高危分区刷写动作发起物理动作请求单，由维护者执行；出现异常时由维护者执行回滚。

---

## 5. 需要维护者执行的物理动作（Tester 发起，A5）

| 项 | 内容 |
| --- | --- |
| **动作** | 1. 采用 `KernelPatch` 工具将 `zram_zstd_0.1.0.kpm` 嵌入内核引导镜像（加载事件必须指定为 `post-kernel-init`）；<br>2. 刷入设备活动 boot 分区（或通过 fastboot boot 测试启动）；<br>3. 重启设备并观察能否正常引导进入系统。 |
| **为什么 Tester 做不了** | 涉及分区刷写（`fastboot flash` / 刷机），属于 `02-roles.md` A1 Tester 明确禁止的黑名单操作；需要维护者持有硬件恢复权限。 |
| **已尝试的软件通道** | 已完成物理 boot 分区只读备份至 `local/tester-raw/boot_b_backup.img`，SHA-256 为 `b71d23c9a39589f822ec98a0c77b69df3440d808c83126d63053d02688ef3312`。未执行任何破坏性写入。 |
| **期望结果** | 设备顺利启动进入 Android 系统，`boot_id` 建立，`/proc/crypto` 出现 `name: zstd`、`driver: zstd-kpm`，zram 初始化可选择 `zstd`。 |
| **风险与回滚方案** | **风险**：若嵌入配置错误、偏移不匹配或内核早期死锁，设备将出现卡开机动画、循环重启或完全黑屏无响应。<br>**回滚方案**：维护者执行 fastboot 命令将备份的原始镜像刷回：<br>`fastboot flash boot_b local/tester-raw/boot_b_backup.img && fastboot reboot`。 |
| **发起时间** | 2026-10-11T03:06:05-0700 |

---

## 6. 动作回执（由维护者执行后回填）

| 项 | 内容 |
| --- | --- |
| 执行时间 | 2026-10-11T03:37:43-0700 |
| 实际动作 | 维护者授权后执行 `new-boot.img` 刷写 `boot_b` 分区并触发重启验证 |
| 结果 | 成功（10/10 判据全通） |
| 设备状态 | 顺利回到系统（冷启动进入 Android 10，sys.boot_completed=1，未出现循环重启或卡死） |
| pstore 变化 | 空（无任何内核崩溃记录，未触发 fastboot 回滚） |
| 回执人 | Tester 代录执行事实，维护者授权人已在线确认 |

---

## 7. 请求维护者裁决

- [ ] 是否批准本轮对 `b754dad7`（Nokia 7 plus 4.4）执行 boot 嵌入与引导刷写？
- [ ] 嵌入镜像刷写是由维护者直接通过 fastboot 执行，还是维护者授权特定受控测试步骤？
- [ ] 若开机失败，维护者确认直接执行备份回滚：`boot_b_backup.img`（SHA-256 `b71d23c9a39589f822ec98a0c77b69df3440d808c83126d63053d02688ef3312`）。

---

## 8. 未覆盖

- [ ] 高危分区刷写动作未执行（A1 黑名单限制，待维护者执行）
- [ ] 嵌入引导开机行为与 zram 早期算法切换未覆盖（等待维护者执行刷写后观察）
- [ ] 高版本与 GKI 设备（如 Sony 5.15）未覆盖

