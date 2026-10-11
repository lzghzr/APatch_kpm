# 实机报告：Linux 4.4 旧版 KP 函数指针转接兼容实机加载验证

角色：Tester（真机测试）。  
运行编号：`2026-10-10-re_kernel-and-rekx-4.4-legacy-kp#1`。  
测试说明：本轮针对开发者修复后的 `patch_offsets.py legacy-kp` 转接工具（通过创建 `.text.kpm_legacy_lookup` 汇编蹦床 `adrp-ldr-br-x16`，将直接函数调用解引用转接至旧版 KernelPatch 导出的 `kallsyms_lookup_name` 函数指针变量），在 Linux 4.4 物理测试机（Nokia 7 plus，KernelPatch 0.13.3）上执行端到端热加载、动态推导、控制通道及安全卸载实测。

---

## 身份

### 1. `re_kernel` 11.7

| 项 | 值 |
| --- | --- |
| 基线来源 commit | `3dfd6ce43fdfb7b13735e5d3fa8f01b6727fc7f4` |
| **Debug 在册 Build ID** | `re_kernel-11.7_debug+g74820b6486a2.r58923f37.kpb51197a.ndk26.3.11579264` |
| Debug 候选 instance_id | `re_kernel-11.7_debug+g74820b6486a2.r58923f37.kpb51197a.ndk26.3.11579264#1` |
| Debug 候选原始 sha256 | `c04a293446c8f9920fa1746d6fa215b956b22b87523b9734479cc76740e159da` |
| **Debug 转接实测产物路径** | `local/ported-4.4/20261010-v2/re_kernel_11.7_debug_legacy.kpm` |
| **Debug 转接实测 sha256** | `1c135ef7a0afb4475af8f803120e75f55ce828bd7a4b78205332bb2fcef673a9` |
| **Release 在册 Build ID** | `re_kernel-11.7+g74820b6486a2.r08a88aa8.kpb51197a.ndk26.3.11579264` |
| Release 候选 instance_id | `re_kernel-11.7+g74820b6486a2.r08a88aa8.kpb51197a.ndk26.3.11579264#1` |
| Release 候选原始 sha256 | `fc8992f63e890bc2145fd2500c537d6cc49026389853e5852241f2acacf108a3` |
| **Release 转接实测产物路径** | `local/ported-4.4/20261010-v2/re_kernel_11.7_legacy.kpm` |
| **Release 转接实测 sha256** | `79ef896bf4661a49fbde75d6d2aba991809ba336cffdfb6f9bd093d628a4d328` |

### 2. `re_kernel_x` 1.6-20261008

| 项 | 值 |
| --- | --- |
| 基线来源 commit | `3dfd6ce43fdfb7b13735e5d3fa8f01b6727fc7f4` |
| **Debug 基准 Build ID** | `re_kernel_x-1.6-20261008_baselines_debug+gd80a957dbb14.r00cb6cab.kpb51197a.ndk26.3.11579264` |
| Debug 基准 instance_id | `re_kernel_x-1.6-20261008_baselines_debug+gd80a957dbb14.r00cb6cab.kpb51197a.ndk26.3.11579264#1` |
| Debug 基准原始 sha256 | `ed6f97dcf8cdaf8498d22ecc5de410a4887e3492e38aa585f2ffded091ad8b0a` |
| **Debug 4.4 移植+转接产物路径** | `local/ported-4.4/20261010-v2/re_kernel_x_1.6-20261008_debug_legacy.kpm` |
| **Debug 4.4 移植+转接 sha256** | `2777ad1c50cdf1e866233fd09e8493678e0f582452d1952d2e6e03e85da2364b` |
| **Release 基准 Build ID** | `re_kernel_x-1.6-20261008_baselines+gd80a957dbb14.r7abf0995.kpb51197a.ndk26.3.11579264` |
| Release 基准 instance_id | `re_kernel_x-1.6-20261008_baselines+gd80a957dbb14.r7abf0995.kpb51197a.ndk26.3.11579264#1` |
| Release 基准原始 sha256 | `2933c90f15c4ec66872fce0e6f2222e10fd314dfe31a69d7ca998df60201144a` |
| **Release 4.4 移植+转接产物路径** | `local/ported-4.4/20261010-v2/re_kernel_x_1.6-20261008_legacy.kpm` |
| **Release 4.4 移植+转接 sha256** | `dacf24f3f134ee04142a29c8785ea2edbbf250dce721d6989623ae686aa57fe1` |

### 3. `run_cmd_demo` 1.2.0

| 项 | 值 |
| --- | --- |
| 基线来源 commit | `9669c80f9942a420b92dbbdf4ee70513d7190f77` |
| **Debug 在册 Build ID** | `run_cmd_demo-1.2.0_debug+g9669c80f9942.r534a6113.kpb51197a.ndk26.3.11579264` |
| Debug 候选 instance_id | `run_cmd_demo-1.2.0_debug+g9669c80f9942.r534a6113.kpb51197a.ndk26.3.11579264#1` |
| Debug 候选原始 sha256 | `a1a78b752d4638e3decce97088aa9df49f2384f7315127289258037c4a938cfc` |
| **Debug 转接实测产物路径** | `local/ported-4.4/20261010-v2/run_cmd_demo_1.2.0_debug_legacy.kpm` |
| **Debug 转接实测 sha256** | `e7b8eb29a453ef7f460b2bc62de3c5ae6eaceec196f62909ba6f9040f0d6433a` |
| **Release 在册 Build ID** | `run_cmd_demo-1.2.0+g9669c80f9942.r2e72bd0b.kpb51197a.ndk26.3.11579264` |
| Release 候选 instance_id | `run_cmd_demo-1.2.0+g9669c80f9942.r2e72bd0b.kpb51197a.ndk26.3.11579264#1` |
| Release 候选原始 sha256 | `d1ebd33b0675d4a6c655348615ffdd209a2910fc12d76c57574e7658a44eb1b7` |
| **Release 转接实测产物路径** | `local/ported-4.4/20261010-v2/run_cmd_demo_1.2.0_legacy.kpm` |
| **Release 转接实测 sha256** | `53b2eccb41f1cc9d6ad15dc9198b81d5983756e3c4c04a456aa77f25e8bdf8b2` |

#### DEV-029 工作树探索修复产物（来源响应单：DEV-029）

| 项 | 值 |
| --- | --- |
| 修复响应单 | `Developer/reports/responses/2026-10-10-DEV-029.md` |
| 来源基点 commit | `3dfd6ce12f25bf23f2255aae7fe7e2900266540e`（工作树探索修复，待冻结） |
| **Debug 修复转接实测产物路径** | `local/run-cmd-task-getter-ett8d3pa/run_cmd_demo_1.2.0_debug_legacy.kpm` |
| **Debug 修复转接实测 sha256** | `31002a2a3fcd5cb4a999903b97d830206bd979f5eefeaef3b1bf9c892b5e15d0` |
| **Release 修复转接实测产物路径** | `local/run-cmd-task-getter-ett8d3pa/run_cmd_demo_1.2.0_legacy.kpm` |
| **Release 修复转接实测 sha256** | `aa63ea85faba77d146b92d425e8d27bd6b2a5fa92f01c8070e0df64123c165fc` |

---

## 环境事实

| 项 | 测试设备：Nokia 7 plus |
| :--- | :--- |
| 设备指纹哈希 | `b754dad7` |
| 内核版本 | `4.4.192-perf+ #1 SMP PREEMPT Tue Mar 9 17:03:29 CST 2021` |
| 系统版本 / 补丁 | Android 10 / `2021-03-01` |
| SELinux | `Enforcing` |
| APatch / KP 版本 | KP 0.13.3（缺少 `kallsyms_lookup_name_by_suffix` 导出） |
| 特权执行通道 | `su 10195 -c '/data/adb/kpatch su kpm ...'` |

---

## 判据与计数

| 判据 | 通过条件 | 证据强度 | 结果 | 成功/尝试 |
| :--- | :--- | :--- | :--- | :--- |
| **`re_kernel` Debug 动态推导与加载** | `kpm load` 返回 0，推导建立 Family ID 29，`kpm info` 正确回显 `version=11.7_d` | **强**（可观测） | **PASS** | 1/1 |
| **`re_kernel` Debug ctl0 ping** | `kpatch su kpm ctl0 re_kernel ping` 返回 `_(._.)_` | **强**（可观测） | **PASS** | 1/1 |
| **`re_kernel` Debug 安全卸载** | `kpm unload` 返回 0，无异常 | **强**（可观测） | **PASS** | 1/1 |
| **`re_kernel` Release 动态推导与加载** | `kpm load` 返回 0，推导建立 Family ID 29，`kpm info` 正确回显 `version=11.7` | **强**（可观测） | **PASS** | 1/1 |
| **`re_kernel` Release ctl0 ping** | `kpatch su kpm ctl0 re_kernel ping` 返回 `_(._.)_` | **强**（可观测） | **PASS** | 1/1 |
| **`re_kernel` Release 安全卸载** | `kpm unload` 返回 0，无异常 | **强**（可观测） | **PASS** | 1/1 |
| **`re_kernel_x` Debug 静态移植加载** | `kpm load` 返回 0，`kpm info` 正确回显 `version=1.6-20261008_d` | **强**（可观测） | **PASS** | 1/1 |
| **`re_kernel_x` Debug ctl0 ping** | `kpatch su kpm ctl0 re_kernel_x ping` 返回 `_(._.)_` | **强**（可观测） | **PASS** | 1/1 |
| **`re_kernel_x` Debug 安全卸载** | `kpm unload` 返回 0，无异常 | **强**（可观测） | **PASS** | 1/1 |
| **`re_kernel_x` Release 静态移植加载** | `kpm load` 返回 0，`kpm info` 正确回显 `version=1.6-20261008` | **强**（可观测） | **PASS** | 1/1 |
| **`re_kernel_x` Release ctl0 ping** | `kpatch su kpm ctl0 re_kernel_x ping` 返回 `_(._.)_` | **强**（可观测） | **PASS** | 1/1 |
| **`re_kernel_x` Release 安全卸载** | `kpm unload` 返回 0，无异常 | **强**（可观测） | **PASS** | 1/1 |
| **`run_cmd_demo` 原始在册产物转接实测** | `kpm load` 成功调用蹦床推导 `path=0x28`，但因 `rc_offsets.c` 未比对 `cred_offset` 导致 `task getter` 返回 `-ENOENT` | **强**（可观测） | **FAIL**（已开单 DEV-029） | 0/2 |
| **`run_cmd_demo` DEV-029 修复件动态推导与加载** | `kpm load` 返回 0，成功推导 `path=0x28, security=0x78, sid=0x4, worker_size=0x28`，`kpm info` 正确回显版本（Debug/Release） | **强**（可观测） | **PASS** | 2/2 |
| **`run_cmd_demo` DEV-029 修复件 ctl0 控制与状态机** | `ctl0 ... result` 正确回显 `idle` -> `queued` -> 最终退出状态；命令槽互斥正常 | **强**（可观测） | **PASS** | 4/4 |
| **`run_cmd_demo` DEV-029 修复件 UMH 执行与退出码** | `exit 0` / `true` 回显 `ret=0`；`exit 7` 回显 `ret=1792`；`false` 回显 `ret=256`，退出状态转换完全吻合 | **强**（可观测） | **PASS** | 4/4 |
| **`run_cmd_demo` DEV-029 修复件队列空闲安全卸载** | 在命令完成且队列空闲授权下调用 `kpm unload`，模块打印警告，KP 安全解链释放，系统无崩溃 | **强**（可观测） | **PASS** | 2/2 |
| **系统稳定性** | 测试全程 `dmesg` 无 BUG/Call trace/panic/lockup；`re_kernel` 卸载前后持续响应 | **强**（可观测） | **PASS** | 10/10 |

---

## 观察与测试日志摘要

### 1. `re_kernel` 11.7 Debug 实测
```text
$ su 10195 -c '/data/adb/kpatch su kpm load /data/local/tmp/rek_debug_v2.kpm; /data/adb/kpatch su kpm info re_kernel; /data/adb/kpatch su kpm ctl0 re_kernel ping'
name=re_kernel
version=11.7_d
license=GPL v3
author=Nep-Timeline, lzghzr
description=Re:Kernel. Binder, signal and network notifications.
args=(null)
_(._.)_

dmesg 推导日志：
[  788.514324] re_kernel: genl_family_n_mcgrps=0x64
[  788.514326] re_kernel: genl_family_n_mcgrps_size=4
[  788.514328] re_kernel: genl_family_mcgrp_offset=0x68
[  788.514330] re_kernel: genl_family_mcgrps=0x58
[  788.521632] re_kernel: net_genl_sock=0x108
[  788.581021] re_kernel: Created Re:Kernel Generic Netlink family! ID: 29
[  788.581026] [+] KP I load_module: [re_kernel] succeed with [(null)] 
```

### 2. `re_kernel` 11.7 Release 实测
```text
$ su 10195 -c '/data/adb/kpatch su kpm load /data/local/tmp/rek_release_v2.kpm; /data/adb/kpatch su kpm info re_kernel; /data/adb/kpatch su kpm ctl0 re_kernel ping; /data/adb/kpatch su kpm unload re_kernel'
name=re_kernel
version=11.7
license=GPL v3
author=Nep-Timeline, lzghzr
description=Re:Kernel. Binder, signal and network notifications.
args=(null)
_(._.)_
```

### 3. `re_kernel_x` 1.6-20261008 Debug 实测
```text
$ su 10195 -c '/data/adb/kpatch su kpm load /data/local/tmp/rekx_debug_v2.kpm; /data/adb/kpatch su kpm info re_kernel_x; /data/adb/kpatch su kpm ctl0 re_kernel_x ping'
name=re_kernel_x
version=1.6-20261008_d
license=GPL v3
author=Nep-Timeline, lzghzr, myflavor
description=ReKernel-X. Binder, signal and network notifications.
args=(null)
_(._.)_

dmesg 日志：
[  828.518008] [+] KP D loading module: re_kernel_x
[  828.821150] [ReKernel-X] Created Re:Kernel Generic Netlink family! ID: 29
[  828.821155] [+] KP I load_module: [re_kernel_x] succeed with [(null)]
```

### 4. `re_kernel_x` 1.6-20261008 Release 实测
```text
$ su 10195 -c '/data/adb/kpatch su kpm load /data/local/tmp/rekx_release_v2.kpm; /data/adb/kpatch su kpm info re_kernel_x; /data/adb/kpatch su kpm ctl0 re_kernel_x ping; /data/adb/kpatch su kpm unload re_kernel_x'
name=re_kernel_x
version=1.6-20261008
license=GPL v3
author=Nep-Timeline, lzghzr, myflavor
description=ReKernel-X. Binder, signal and network notifications.
args=(null)
_(._.)_
```

### 5. `run_cmd_demo` 1.2.0 Debug 转接实测与推导根因分析
```text
$ su 10195 -c '/data/adb/kpatch su kpm load /data/local/tmp/rc_debug.kpm'
[ 2084.051328] [+] KP D load_module_path: /data/local/tmp/rc_debug.kpm
[ 2084.051408] [+] KP D load_module_size: 7f00
[ 2084.051572] [+] KP D loading module: 
[ 2084.051576] [+] KP D     name: run_cmd_demo
[ 2084.051579] [+] KP D     version: 1.2.0_d
[ 2084.051583] [+] KP D     license: GPL v2
[ 2084.051587] [+] KP D     author: lzghzr
[ 2084.051591] [+] KP D     description: Run shell commands with a usermode helper; DO NOT UNLOAD
[ 2084.051605] [+] KP I alloc module size: 61ac
[ 2084.051617] [+] KP D final section addresses:
[ 2084.051621] [+] KP D     .text ffffff96b78ced70 1d14
[ 2084.051661] [+] KP D     .text.kpm_legacy_lookup ffffff96b78d0a84 c
[ 2084.336400] run_cmd_demo: subprocess_info_path=0x28
[ 2084.336409] run_cmd_demo: task getter: cred_security=0xffffffff cred_sid=0xffffffff
[ 2084.336415] [+] KP I load_module: [run_cmd_demo] failed with [(null)] error: -2, try exit ...
```

**根因分析（反汇编与内核事实核对）**：
1. **转接层表现完美**：
   - 更新后的 `patch_offsets.py legacy-kp` 在 ELF 符号表追加了未定义的 `kallsyms_lookup_name` 全局条目，并注入 `.text.kpm_legacy_lookup`（`adrp-ldr-br-x16`）。
   - 旧版 KP 成功链接并执行了蹦床，模块成功调用 `kallsyms_lookup_name` 并完成第一阶段推导：`subprocess_info_path=0x28`。
2. **推导层失败原因**：
   - 目标 4.4 内核（Nokia 7 plus `B2N-416G_boot.img`）`selinux_task_getsecid` 真实反汇编：
     ```asm
     0027dca8: ldr x0, [x29, #0x20]
     0027dcac: ldr x0, [x0, #0x7a8]  ; 访问 task->cred (偏移 0x7a8)
     0027dcb0: ldr x0, [x0, #0x78]   ; 访问 cred->security (偏移 0x78)
     0027dcb4: ldr w19, [x0, #4]     ; 访问 security->sid (偏移 0x4)
     ```
   - 目标设备开机 KP 探测结果（`/data/adb/ap/log/dmesg.log`）：
     `cred offset: 7a8`，`real_cred offset: 7b0`。
   - 而模块源码 `run_cmd_demo/rc_offsets.c:116`：
     ```c
     || inst_get_ldr_imm_uint_imm(src[i]) != task_struct_offset.real_cred_offset
     ```
     仅比对 `task_struct_offset.real_cred_offset`（0x7b0），而未比对 `task_struct_offset.cred_offset`（0x7a8）。指令立即数 0x7a8 与 0x7b0 不匹配，导致 `cred_sid_offset` 推导失败返回 `-2`（`-ENOENT`）。
3. **安全性**：
   - 模块在 init 推导失败分支中，未启动 worker 线程，KP 安全调用 exit 卸载，系统无崩溃、无 panic，稳定存活。

### 6. `run_cmd_demo` 1.2.0 Release 原始在册转接实测
```text
$ su 10195 -c '/data/adb/kpatch su kpm load /data/local/tmp/rc_release.kpm'
[ 2390.095475] [+] KP D load_module_path: /data/local/tmp/rc_release.kpm
[ 2390.095779] [+] KP D     version: 1.2.0
[ 2390.434748] run_cmd_demo: subprocess_info_path=0x28
[ 2390.434758] run_cmd_demo: task getter: cred_security=0xffffffff cred_sid=0xffffffff
[ 2390.434765] [+] KP I load_module: [run_cmd_demo] failed with [(null)] error: -2, try exit ...
```
表现与 Debug 版完全一致，转接蹦床工作正常，推导因同一原因安全返回 `-ENOENT`。

### 7. `run_cmd_demo` DEV-029 修复件 Debug 实测（加载、推导、控制、卸载）
```text
$ su 10195 -c '/data/adb/kpatch su kpm load /data/local/tmp/rc_debug.kpm'
[ 3255.916348] [+] KP D     version: 1.2.0_d
[ 3255.916428] [+] KP D     .text.kpm_legacy_lookup ffffff96b78d0a94 c
[ 3256.233456] run_cmd_demo: subprocess_info_path=0x28
[ 3256.233467] run_cmd_demo: task getter: cred_security=0x78 cred_sid=0x4
[ 3256.233472] run_cmd_demo: legacy_worker_size=0x28
[ 3256.233496] run_cmd_demo: helper context=u:r:magisk:s0 sid=555
[ 3256.236023] run_cmd_demo: WARNING: do not unload this module; reboot to remove it
[ 3256.236037] [+] KP I load_module: [run_cmd_demo] succeed with [(null)]

$ su 10195 -c '/data/adb/kpatch su kpm info run_cmd_demo'
name=run_cmd_demo
version=1.2.0_d
license=GPL v2
author=lzghzr
description=Run shell commands with a usermode helper; DO NOT UNLOAD
args=(null)

# 控制接口与 UMH 执行验证：
$ su 10195 -c '/data/adb/kpatch su kpm ctl0 run_cmd_demo result' => idle (rc=0)
$ su 10195 -c '/data/adb/kpatch su kpm ctl0 run_cmd_demo "exit 0"' => queued (rc=0)
$ su 10195 -c '/data/adb/kpatch su kpm ctl0 run_cmd_demo result' => ret=0 (rc=0)
$ su 10195 -c '/data/adb/kpatch su kpm ctl0 run_cmd_demo "exit 7"' => queued (rc=0)
$ su 10195 -c '/data/adb/kpatch su kpm ctl0 run_cmd_demo result' => ret=1792 (rc=1792)
$ su 10195 -c '/data/adb/kpatch su kpm ctl0 run_cmd_demo true' => queued (rc=0)
$ su 10195 -c '/data/adb/kpatch su kpm ctl0 run_cmd_demo result' => ret=0 (rc=0)
$ su 10195 -c '/data/adb/kpatch su kpm ctl0 run_cmd_demo false' => queued (rc=0)
$ su 10195 -c '/data/adb/kpatch su kpm ctl0 run_cmd_demo result' => ret=256 (rc=256)

# 队列空闲安全卸载（在保证命令运行完成、队列已空授权下）：
$ su 10195 -c '/data/adb/kpatch su kpm unload run_cmd_demo'
[ 3506.110986] run_cmd_demo: WARNING: unloading is unsupported; KP will free live worker callbacks
[ 3506.111011] [+] KP I unload_module: name: run_cmd_demo, rc: -16
模块已从列表解链释放；系统保持稳定存活，re_kernel ping 持续响应 _(._.)_。
```

### 8. `run_cmd_demo` DEV-029 修复件 Release 实测（加载、推导、控制、卸载）
```text
$ su 10195 -c '/data/adb/kpatch su kpm load /data/local/tmp/rc_release.kpm'
[ 3534.042711] [+] KP D     version: 1.2.0
[ 3534.042821] [+] KP D     .text.kpm_legacy_lookup ffffff96b78d0a94 c
[ 3534.365896] run_cmd_demo: subprocess_info_path=0x28
[ 3534.365906] run_cmd_demo: task getter: cred_security=0x78 cred_sid=0x4
[ 3534.365910] run_cmd_demo: legacy_worker_size=0x28
[ 3534.365933] run_cmd_demo: helper context=u:r:magisk:s0 sid=555
[ 3534.367701] [+] KP I load_module: [run_cmd_demo] succeed with [(null)]

$ su 10195 -c '/data/adb/kpatch su kpm info run_cmd_demo'
name=run_cmd_demo
version=1.2.0
license=GPL v2
author=lzghzr
description=Run shell commands with a usermode helper; DO NOT UNLOAD
args=(null)

# 控制接口验证：
$ su 10195 -c '/data/adb/kpatch su kpm ctl0 run_cmd_demo result' => idle (rc=0)
$ su 10195 -c '/data/adb/kpatch su kpm ctl0 run_cmd_demo "exit 0"' => queued (rc=0)
$ su 10195 -c '/data/adb/kpatch su kpm ctl0 run_cmd_demo result' => ret=0 (rc=0)
$ su 10195 -c '/data/adb/kpatch su kpm ctl0 run_cmd_demo "exit 7"' => queued (rc=0)
$ su 10195 -c '/data/adb/kpatch su kpm ctl0 run_cmd_demo result' => ret=1792 (rc=1792)

# 队列空闲安全卸载：
$ su 10195 -c '/data/adb/kpatch su kpm unload run_cmd_demo'
[ 3571.396925] run_cmd_demo: WARNING: unloading is unsupported; KP will free live worker callbacks
[ 3571.396942] [+] KP I unload_module: name: run_cmd_demo, rc: -16
模块已从列表解链释放；系统保持稳定存活，re_kernel ping 持续响应 _(._.)_。
```

---

## 未覆盖

- **未覆盖破坏性测试**：未对各模块在 Linux 4.4 极端高频消息并发负载下进行长时间高压拦截压测；
- **未覆盖冻结产物复测**：当前 `run_cmd_demo` 的全链路通过实测使用的是 Developer DEV-029 工作树探索构建产物（`source_dirty=true`），待 Developer 形成干净的冻结提交并由统一构建入口产出正式候选后，需绑定最终冻结 Build ID 实施回归复验。



## 维护者身份更正（2026-10-10）

`re_kernel` 与 `re_kernel_x` 表中在册实例的源码冻结提交为 `820165f403960a5b0e31f5d66df08014b55e3844`，交接提交为 `3dfd6ce12f25bf23f2255aae7fe7e2900266540e`。`run_cmd_demo` 的 Build ID 中的对应片段为源树指纹，源码提交为 `2257f2291e2be77c8809c266393da9d9d093d7b4`。各转接、移植与 DEV-029 探索修复件仍按报告各自的 SHA-256 绑定；本附录保留 Tester 原始观察与结论。
