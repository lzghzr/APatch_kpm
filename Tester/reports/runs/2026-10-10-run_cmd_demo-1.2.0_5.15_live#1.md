# 实机报告：Linux 5.15 内核全模块端到端热加载、推导与控制实测

角色：Tester（真机测试）。  
运行编号：`2026-10-10-run_cmd_demo-1.2.0_5.15_live#1`。  
测试说明：本轮在物理真机 Sony Xperia 1 V（Linux 5.15.189 GKI，设备指纹 `48b7ee2f`）上，对本次更新的全部三模块（`re_kernel` 11.7 动态推导版、`re_kernel_x` 1.6-20261008 静态基线版、`run_cmd_demo` 1.2.0 异步 UMH 执行模块）在册候选产物（Debug & Release）执行完整的端到端热加载、动态推导/配置生效、`ctl0` 控制通道、业务逻辑验证及安全卸载实测。

---

## 身份

### 1. `run_cmd_demo` 1.2.0

| 项 | 值 |
| --- | --- |
| 源码 commit | `9669c80f9942a420b92dbbdf4ee70513d7190f77` |
| **Debug 在册 Build ID** | `run_cmd_demo-1.2.0_debug+g9669c80f9942.r534a6113.kpb51197a.ndk26.3.11579264` |
| Debug 候选 instance_id | `run_cmd_demo-1.2.0_debug+g9669c80f9942.r534a6113.kpb51197a.ndk26.3.11579264#1` |
| Debug 候选在册 sha256 | `a1a78b752d4638e3decce97088aa9df49f2384f7315127289258037c4a938cfc` |
| **Release 在册 Build ID** | `run_cmd_demo-1.2.0+g9669c80f9942.r2e72bd0b.kpb51197a.ndk26.3.11579264` |
| Release 候选 instance_id | `run_cmd_demo-1.2.0+g9669c80f9942.r2e72bd0b.kpb51197a.ndk26.3.11579264#1` |
| Release 候选在册 sha256 | `d1ebd33b0675d4a6c655348615ffdd209a2910fc12d76c57574e7658a44eb1b7` |

### 2. `re_kernel_x` 1.6-20261008

| 项 | 值 |
| --- | --- |
| 源码 commit | `d80a957dbb1480f2d4ee7111df78923a9a13b652` |
| **Debug 在册 Build ID** | `re_kernel_x-1.6-20261008_debug+gd80a957dbb14.r404552af.kpb51197a.ndk26.3.11579264` |
| Debug 候选 instance_id | `re_kernel_x-1.6-20261008_debug+gd80a957dbb14.r404552af.kpb51197a.ndk26.3.11579264#1` |
| Debug 候选在册 sha256 | `e6ce734b2ad7c60290b495c86244a988e8180462711a63fb57e88cbecdd73304` |
| **Release 在册 Build ID** | `re_kernel_x-1.6-20261008+gd80a957dbb14.r3923dc8d.kpb51197a.ndk26.3.11579264` |
| Release 候选 instance_id | `re_kernel_x-1.6-20261008+gd80a957dbb14.r3923dc8d.kpb51197a.ndk26.3.11579264#1` |
| Release 候选在册 sha256 | `151ef48c73afe7703c13778cbaffccf0c5b900bd1e6b98aea2d483933b33030f` |

### 3. `re_kernel` 11.7

| 项 | 值 |
| --- | --- |
| 源码 commit | `74820b6486a2468305f6314c1e40c5f5dc2d6a50` |
| **Debug 在册 Build ID** | `re_kernel-11.7_debug+g74820b6486a2.r58923f37.kpb51197a.ndk26.3.11579264` |
| Debug 候选 instance_id | `re_kernel-11.7_debug+g74820b6486a2.r58923f37.kpb51197a.ndk26.3.11579264#1` |
| Debug 候选在册 sha256 | `c04a293446c8f9920fa1746d6fa215b956b22b87523b9734479cc76740e159da` |
| **Release 在册 Build ID** | `re_kernel-11.7+g74820b6486a2.r08a88aa8.kpb51197a.ndk26.3.11579264` |
| Release 候选 instance_id | `re_kernel-11.7+g74820b6486a2.r08a88aa8.kpb51197a.ndk26.3.11579264#1` |
| Release 候选在册 sha256 | `fc8992f63e890bc2145fd2500c537d6cc49026389853e5852241f2acacf108a3` |

| 公共工具链 | NDK 26.3.11579264 |
| 关联环境记录 | [`Tester/reports/environments/2026-10-08-48b7ee2f.md`](../environments/2026-10-08-48b7ee2f.md) |

---

## 环境事实

| 项 | 测试设备：Sony Xperia 1 V |
| :--- | :--- |
| 设备指纹哈希 | `48b7ee2f` |
| 内核版本 | `5.15.189-android13-8-00016 (git 51bba4309aac-ab14546557) #1 SMP PREEMPT Fri Dec 5 10:55:34 UTC 2025 aarch64 Toybox` |
| 机型（脱敏） | `XQ-DQ72` |
| 系统版本 / 补丁级别 | Android 15 / `2026-06-01` |
| 构建指纹 | `Sony/XQ-DQ72/XQ-DQ72:15/67.2.A.3.178/067002A003017800521143226:user/release-keys` |
| SELinux | `Enforcing` |
| KernelPatch 版本 | `d09`（支持完整 BTF 查询 API） |
| 特权执行通道 | `su 10495 -c '/data/adb/ap/bin/kpatch su kpm ...'` |
| 运行基线 boot_id SHA-256 | `f774ad13c9e18fd27616e3cef4de0971bd0a0ba6e6a2888d9c7c675d3ad16ae8`（全程恒定） |
| 基线 uptime | `172502.33`（测试全程单调递增，无异常重启） |
| pstore 干净度 | `/sys/fs/pstore/` 为空，无旧崩溃残留 |

---

## 判据与计数

| 判据 | 通过条件 | 证据强度 | 结果 | 成功/尝试 |
| :--- | :--- | :--- | :--- | :--- |
| **设备存活与特权通道** | boot_id 恒定，uptime 单调递增，APatch Manager 通道正常响应 | **强**（可观测） | **PASS** | 1/1 |
| **`run_cmd_demo` Debug BTF 解析与加载** | `kpm load` 返回 0；BTF 命中并推导 `path=0x38, security=0x78, sid=0x4`，SID=1098，`kpm info` 正确回显 `version=1.2.0_d` | **强**（可观测） | **PASS** | 1/1 |
| **`run_cmd_demo` Debug UMH 执行与退出码** | `exit 0` 返回 `ret=0`；`exit 7` 返回 `ret=1792`；复杂命令写入文件验证 UID=0 与 `u:r:magisk:s0` 域 | **强**（可观测） | **PASS** | 3/3 |
| **`run_cmd_demo` Release BTF 解析与加载** | `kpm load` 返回 0；BTF 命中项一致，`kpm info` 正确回显 `version=1.2.0` | **强**（可观测） | **PASS** | 1/1 |
| **`run_cmd_demo` Release 控制互斥与执行** | 快速连续提交返回 `pending`（`-EINPROGRESS`）；完成后查询回显退出码 | **强**（可观测） | **PASS** | 2/2 |
| **`run_cmd_demo` 队列空闲安全卸载** | 在命令执行完成且队列空闲授权下调用 `kpm unload`，模块打印警告并从列表解链释放，系统无崩溃 | **强**（可观测） | **PASS** | 2/2 |
| **`re_kernel_x` Debug 热加载与控制** | `kpm load` 返回 0，`kpm info` 回显 `version=1.6-20261008_d`，`ctl0 ping` 回显 `_(._.)_`，dmesg 输出 Binder 拦截事件流 | **强**（可观测） | **PASS** | 1/1 |
| **`re_kernel_x` Debug 安全卸载** | `kpm unload` 返回 0，模块安全移除 | **强**（可观测） | **PASS** | 1/1 |
| **`re_kernel_x` Release 热加载与控制** | `kpm load` 返回 0，`kpm info` 回显 `version=1.6-20261008`，`ctl0 ping` 回显 `_(._.)_` | **强**（可观测） | **PASS** | 1/1 |
| **`re_kernel_x` Release 安全卸载** | `kpm unload` 返回 0，模块安全移除 | **强**（可观测） | **PASS** | 1/1 |
| **`re_kernel` 11.7 Debug 动态推导与控制** | `kpm load` 返回 0，`kpm info` 回显 `version=11.7_d`，`ctl0 ping` 回显 `_(._.)_`，dmesg 观察到异步消息淘汰 `free_outdated` 运行 | **强**（可观测） | **PASS** | 1/1 |
| **`re_kernel` 11.7 Debug 安全卸载** | `kpm unload` 返回 0，模块安全移除 | **强**（可观测） | **PASS** | 1/1 |
| **`re_kernel` 11.7 Release 动态推导与控制** | `kpm load` 返回 0，`kpm info` 回显 `version=11.7`，`ctl0 ping` 回显 `_(._.)_` | **强**（可观测） | **PASS** | 1/1 |
| **`re_kernel` 11.7 Release 安全卸载** | `kpm unload` 返回 0，模块安全移除 | **强**（可观测） | **PASS** | 1/1 |
| **常驻模块状态恢复** | 最终重新载入 `re_kernel_x` Release 版，持续稳定响应 `_(._.)_` | **强**（可观测） | **PASS** | 1/1 |
| **全流程内核稳定性** | 连续经历 6 个模块变体装载/卸载及 UMH 进程执行；`dmesg` 全程无 BUG / Call trace / panic | **强**（可观测） | **PASS** | 6/6 |

---

## 观察与测试日志摘要

### 1. `run_cmd_demo` 1.2.0 Debug 与 Release 实测
```text
$ su 10495 -c '/data/adb/ap/bin/kpatch su kpm load /data/local/tmp/rc_debug_515.kpm'
[120347.619945] run_cmd_demo: BTF: subprocess_info_path=0x38 cred_security=0x78 cred_sid=0x4
[120347.620007] run_cmd_demo: helper context=u:r:magisk:s0 sid=1098
[120347.620763] run_cmd_demo: WARNING: do not unload this module; reboot to remove it
[120347.620770] [+] KP I load_module_ex: [run_cmd_demo] succeed with [(null)]

$ su 10495 -c '/data/adb/ap/bin/kpatch su kpm info run_cmd_demo'
name=run_cmd_demo
version=1.2.0_d
license=GPL v2
author=lzghzr
description=Run shell commands with a usermode helper; DO NOT UNLOAD

# 状态机与控制执行：
$ su 10495 -c '/data/adb/ap/bin/kpatch su kpm ctl0 run_cmd_demo result' => idle (rc=0)
$ su 10495 -c '/data/adb/ap/bin/kpatch su kpm ctl0 run_cmd_demo "exit 0"' => queued (rc=0)
$ su 10495 -c '/data/adb/ap/bin/kpatch su kpm ctl0 run_cmd_demo result' => ret=0 (rc=0)
$ su 10495 -c '/data/adb/ap/bin/kpatch su kpm ctl0 run_cmd_demo "exit 7"' => queued (rc=0)
$ su 10495 -c '/data/adb/ap/bin/kpatch su kpm ctl0 run_cmd_demo result' => ret=1792 (rc=1792)

# LSM 域与凭据回读：
$ su 10495 -c '/data/adb/ap/bin/kpatch su kpm ctl0 run_cmd_demo "{ id; cat /proc/self/attr/current; ls /system/bin | head -n 5; } > /data/adb/run_cmd.out 2>&1"' => queued
$ su 10495 -c '/data/adb/ap/bin/kpatch su kpm ctl0 run_cmd_demo result' => ret=0
$ su 10495 -c 'cat /data/adb/run_cmd.out'
uid=0(root) gid=0(root) groups=0(root) context=u:r:magisk:s0
u:r:magisk:s0 [
abb
abx
abx2xml
aconfigd

# 队列空闲安全卸载（Debug & Release）：
$ su 10495 -c '/data/adb/ap/bin/kpatch su kpm unload run_cmd_demo'
模块从 kpm list 正常解链移除。
```

### 2. `re_kernel_x` 1.6-20261008 Debug 与 Release 实测
```text
$ su 10495 -c '/data/adb/ap/bin/kpatch su kpm load /data/local/tmp/rekx_debug_515.kpm'
$ su 10495 -c '/data/adb/ap/bin/kpatch su kpm info re_kernel_x; /data/adb/ap/bin/kpatch su kpm ctl0 re_kernel_x ping'
name=re_kernel_x
version=1.6-20261008_d
license=GPL v3
author=Nep-Timeline, lzghzr, myflavor
description=ReKernel-X. Binder, signal and network notifications.
_(._.)_

# dmesg 实时捕获 Binder 事件流：
[121191.138745] [ReKernel-X] event type=0,src_pid=3330,src_uid=1000,dst_pid=22764,dst_uid=10484
[121191.138749] [ReKernel-X] src_comm=ConnectivitySer,dst_comm=pinduoduo:titan

$ su 10495 -c '/data/adb/ap/bin/kpatch su kpm unload re_kernel_x' => rc=0

$ su 10495 -c '/data/adb/ap/bin/kpatch su kpm load /data/local/tmp/rekx_release_515.kpm'
$ su 10495 -c '/data/adb/ap/bin/kpatch su kpm info re_kernel_x; /data/adb/ap/bin/kpatch su kpm ctl0 re_kernel_x ping'
name=re_kernel_x
version=1.6-20261008
_(._.)_

$ su 10495 -c '/data/adb/ap/bin/kpatch su kpm unload re_kernel_x' => rc=0
```

### 3. `re_kernel` 11.7 Debug 与 Release 实测
```text
$ su 10495 -c '/data/adb/ap/bin/kpatch su kpm load /data/local/tmp/rek_debug_515.kpm'
$ su 10495 -c '/data/adb/ap/bin/kpatch su kpm info re_kernel; /data/adb/ap/bin/kpatch su kpm ctl0 re_kernel ping'
name=re_kernel
version=11.7_d
license=GPL v3
author=Nep-Timeline, lzghzr
description=Re:Kernel. Binder, signal and network notifications.
_(._.)_

# dmesg 实时执行异步未投递事务安全淘汰：
[121245.971224] re_kernel: free_outdated pid=19361,uid=10477,data_size=1136
[121245.974336] re_kernel: free_outdated pid=11996,uid=10484,data_size=1148

$ su 10495 -c '/data/adb/ap/bin/kpatch su kpm unload re_kernel' => rc=0

$ su 10495 -c '/data/adb/ap/bin/kpatch su kpm load /data/local/tmp/rek_release_515.kpm'
$ su 10495 -c '/data/adb/ap/bin/kpatch su kpm info re_kernel; /data/adb/ap/bin/kpatch su kpm ctl0 re_kernel ping'
name=re_kernel
version=11.7
license=GPL v3
author=Nep-Timeline, lzghzr
description=Re:Kernel. Binder, signal and network notifications.
_(._.)_

$ su 10495 -c '/data/adb/ap/bin/kpatch su kpm unload re_kernel' => rc=0
```

---

## 未覆盖

- **未覆盖超长运行压测**：未在 5.15 上连续下发超万次高频短时命令执行压力测试；
- **未覆盖极端阻塞命令测试**：未测试下发无限睡眠命令（如 `sleep 999999`）对单一执行槽的永久占用场景；
- **未覆盖多模块并发注册 Generic Netlink**：`re_kernel` 与 `re_kernel_x` 使用同一 Generic Netlink Family，二者在 5.15 上为串行逐项加载验证，未做并发重叠加载测试。

## 维护者身份更正（2026-10-10）

身份表中的三个“源码 commit”值为源树指纹，Git 源码提交按在册实例补充如下。此处仅更正身份字段，保留 Tester 原始实测结论。

| 模块与原报告实例组 | 完整 source_commit |
| --- | --- |
| run_cmd_demo 1.2.0，普通/debug | 2257f2291e2be77c8809c266393da9d9d093d7b4 |
| re_kernel 11.7，普通/debug | 820165f403960a5b0e31f5d66df08014b55e3844 |
| re_kernel_x 1.6-20261008，普通/debug | 820165f403960a5b0e31f5d66df08014b55e3844 |

这些实测记录绑定报告原有实例与 SHA-256。新版本的候选身份与验证范围在维护者工程记录中单独登记。
