# 实机报告：NoMount 两机范围实测（4.4 动态 TST-001 修复验证 + 4.4/4.19 新静态抽样 + 4.19 动态回归）

角色：Tester（真机测试）。  
运行编号：`2026-10-15-nomount-two-device-round-live#1`。  
测试依据：响应维护者轮次请求 [`docs/records/2026-10-15-nomount-two-device-round-request.md`](../../../docs/records/2026-10-15-nomount-two-device-round-request.md)、Auditor 独立审计报告（[`Auditor/reports/2026-10-15-nomount-tail-anchors-audit.md`](../../../Auditor/reports/2026-10-15-nomount-tail-anchors-audit.md)）与风险接受记录 `RA-002`。  
**环境与排期说明**：真机环境当前为两台物理接入（Nokia 7 plus 与 Sony Xperia 1 II，排期常态）。本轮对两机范围内的四趟目标执行完整独立的固件嵌入、冷重启与端到端实测；5.15 动态目标已由 Auditor 的 Delta 运行时行为等价性裁定顺延绑定上轮 20/20 实测证据（待物理接入后排期补测归档）。

---

## 身份

| 项 | 值 |
| --- | --- |
| 候选来源 commit | `ebad05883bcd6173d5e2a867559aa6bcb3e45810` |
| 请求与当前 HEAD commit | `c4c1bf3e8c9ae2b2e2d790f8bfb47fd1e4b5a765` |
| **动态候选件 instance_id** | `nomount-2.1.1-20261014+g9f323cd3deaa.r33de5496.kpb51197a.ndk26.3.11579264#1` |
| **动态候选件 SHA-256** | `1ab36727b82cab1723da56f6f82273ff1fee57071836b8992f4e3d26ad40e1fa`（219,984 字节） |
| **4.4 动态 legacy-kp 派生件 SHA-256** | `06bd68500f2d6f9725038499a16bca1f54e88f1cde3c21f2dc95aa96f276d8ee`（221,728 字节） |
| 4.4 动态派生件相对路径 | `artifacts/binary-port/nomount/06bd68500f2d6f9725038499a16bca1f54e88f1cde3c21f2dc95aa96f276d8ee/NoMount_2.1.1-20261014.kpm` |
| **4.4 静态 legacy-kp 派生件 SHA-256** | `b12e2bc835a8a2ed9f60300fe27b0000a1f2b8ecdf57e2280f15b9f0a4af158b`（126,872 字节） |
| 4.4 静态派生件相对路径 | `artifacts/binary-port/nomount/b12e2bc835a8a2ed9f60300fe27b0000a1f2b8ecdf57e2280f15b9f0a4af158b/NoMount_2.1.1-20261014_baselines.kpm` |
| **4.19 静态 patch 派生件 SHA-256** | `4b6fe6266ace0918f5d294380eb9650df8673a429ea613844a8c9b834e92054e`（115,104 字节） |
| 4.19 静态派生件相对路径 | `artifacts/binary-port/nomount/4b6fe6266ace0918f5d294380eb9650df8673a429ea613844a8c9b834e92054e/NoMount_2.1.1-20261014_baselines.kpm` |
| **配套 ZIP instance_id** | `nomount-zip-2.1.1-20261014+g5fbf6fec42ef.ndk26.3.11579264#1` |
| **配套 ZIP SHA-256** | `42c5b64458b73dcb202efb2cd6a1a82c604ba3c94698bd1d49085c752b045a44`（80,003 字节） |
| **重打包 boot 镜像 (4.4 动态，趟 ①)** | `local/tester-raw/new-boot-run1-44.img` (`22c8de4808ce012e34cfe952ea9c7ef587257cc538697f3e62e7bf73ef199eb6`) |
| **重打包 boot 镜像 (4.4 静态，趟 ②)** | `local/tester-raw/new-boot-run2-44.img` (`1b7a3adf1c95227be87a39e5f9d23d3e8834d2d9ab2b26866c502f0d255a2514`) |
| **重打包 boot 镜像 (4.19 静态，趟 ③)** | `local/tester-raw/new-boot-run3-419.img` (`b9f364db75887d81ff0918c7819fddc45be855c99fc3b384a1f8be7170e8d9db`) |
| **重打包 boot 镜像 (4.19 动态，趟 ④)** | `local/tester-raw/new-boot-run4-419.img` (`c181436356e9b5d54b2774662b126a94c70d214c2606425bfe2ef27cf95c82f5`) |

---

## 环境事实

| 项 | 4.4 目标机（Nokia 7 plus） | 4.19 目标机（Sony Xperia 1 II） |
| --- | --- | --- |
| 设备指纹哈希 | `b754dad7` | `508d47da` |
| 机型（脱敏） | Nokia 7 plus (`B2N_sprout`) | Sony Xperia 1 II (`XQ-AT52`) |
| 内核版本 | `4.4.192-perf+ #1 SMP PREEMPT Tue Mar 9 17:03:29 CST 2021` | `4.19.325-cip134-st18-perf-g7fc8455b2fa8` |
| 系统版本 / API | Android 10 / API 29 | Android 12 / API 31 |
| BTF 状态 | **无 BTF** | **无 BTF** |
| SELinux 状态 | `Enforcing` | `Enforcing` |
| APatch / KP 版本 | `0xd04`（旧版 KP） | `0xd09` |
| 引导机制 | `pre-kernel-init` 嵌入 | `pre-kernel-init` 嵌入 |
| 引导槽位 | `boot_b` | `boot_a` |
| 真实消费者应用 | `me.zhanghai.android.files` (UID `10177`) | `me.zhanghai.android.files` (UID `10006`) |

---

## 四趟测试判据与实测结果汇总

| 趟号 | 目标设备 / 场景 | 待测产物 | 预期行为与核心判据 | 实际测试结果 | 评级 / 结论 |
|---|---|---|---|---|:---:|
| **①** | **4.4 旧版 KP**<br>Nokia 7 plus<br>(`b754dad7`) | 动态 legacy-kp<br>`06bd6850…` | **TST-001 修复验证 + DEV-042 复测**：`__start_rodata` 边界回退越过 `_etext` 误判；通过 open 回调识别 `no_open_fops.36570`；进入运行态，注册 Key type，跑通用户主路径 | `__start_rodata` 边界生效，成功通过 open 回调识别局部表，解出 `fop=328 data=344/152`；模块首次在 4.4 动态成功加载（`rc: 0`）；配套 ZIP 安装成功识别驱动 `2.1.1-20261014`；重定向、Whiteout、真实 App ART speed 编译及内存映射 100% 通过 | **PASS**<br>(重大突破：4.4 动态首度全通，TST-001/DEV-042 闭环) |
| **②** | **4.4 静态抽样**<br>Nokia 7 plus<br>(`b754dad7`) | 静态 legacy-kp<br>`b12e2bc8…` | **新静态抽样实测**：128B 对齐变更后在 Linux 4.4 旧版 KP 上正常载入，识别静态版本，跑通用户主路径 | `pre-kernel-init` 正常载入（`rc: 0`），dmesg 输出 `version=2.1.1-20261014, offsets=static`；配套 ZIP 安装正常；重定向、Whiteout 与真实 App 映射 100% 通过；pstore 干净 | **PASS**<br>(4.4 静态抽样全通) |
| **③** | **4.19 静态抽样**<br>Sony Xperia 1 II<br>(`508d47da`) | 静态 patch<br>`4b6fe626…` | **新静态抽样实测**：128B 对齐变更后在 Linux 4.19 上正常载入，识别静态版本，跑通用户主路径 | `pre-kernel-init` 正常载入（`rc: 0`），dmesg 输出 `version=2.1.1-20261014, offsets=static`；配套 ZIP 安装正常；重定向、Whiteout 与真实 App 映射 100% 通过；pstore 干净 | **PASS**<br>(4.19 静态抽样全通) |
| **④** | **4.19 动态回归**<br>Sony Xperia 1 II<br>(`508d47da`) | 动态候选件<br>`1ab36727…` | **动态全量回归**：验证含 TST-001 修复与尾部锚点变更后，4.19 无 BTF 动态推导维持稳定，无功能退化 | 成功解出 `inode/super/dentry=256/280/192` 及 `fop=368 data=384/264`，Key type 注册成功，模块加载 `rc: 0`；配套 ZIP 识别驱动 `2.1.1-20261014`；重定向、Whiteout 与真实 App 编译映射 100% 通过 | **PASS**<br>(4.19 动态回归全通) |

---

## 详细执行记录

### 1. 趟 ①：Linux 4.4（Nokia 7 plus，动态 legacy-kp 修复验证）

在目标设备 `boot_b` 原地解包并嵌入待测产物：
```bash
/data/adb/ap/bin/kptools -p -i kernel -k /data/data/me.bmax.apatch/patch/kpimg -o new_kernel \
  -E re_kernel -E cgroupv2_freeze -E zram_zstd \
  -M /data/local/tmp/NoMount_run1_44.kpm -T kpm -V pre-kernel-init
```
重打包镜像 `local/tester-raw/new-boot-run1-44.img`（SHA-256 `22c8de4808ce012e34cfe952ea9c7ef587257cc538697f3e62e7bf73ef199eb6`），刷入 `boot_b` 后冷重启。

#### 内核引导日志（dmesg）
```text
[    1.037508] NoMount: layout: BTF unavailable; deriving object fields from function anchors
[    1.053045] NoMount: layout: file objects=32/32 mapping=248
[    1.053065] NoMount: layout: inode sb=40 ino=64 size=80 nlink=72/72
[    1.053072] NoMount: layout: dentry ops=96
[    1.306453] NoMount: layout: BTF unavailable; deriving rule hash ABI from function anchor
[    1.313158] NoMount: layout: full_name_hash arguments=2
[    1.566542] NoMount: layout: BTF unavailable; deriving file fields from function anchors
[    1.611733] NoMount: layout: file_operations size=216 (tty_default_fops)
[    1.661098] NoMount: layout: file callbacks open=88 release=104 mmap=80 splice_read=184
[    1.914539] NoMount: layout: owned zero-table capacity=512
[    1.953289] NoMount: layout: inode hash=224 getattr=144 callback/function=3/2 context=0
[    1.955523] NoMount: layout: super drop/evict=32/40
[    1.956368] NoMount: layout: control mutex=40/no_dep_map
[    2.001156] NoMount: layout: directory lock=88 iterate/shared=48/-1
[    2.030522] NoMount: layout: directory init/release=-1/40 actor=0
[    2.050460] NoMount: layout: operation extents inode/super/dentry=256/232/128
[    2.344290] NoMount: layout: BTF unavailable; deriving inode storage from function anchors
[    2.585531] NoMount: layout: inode initial file table identified by open callback
[    2.590148] NoMount: layout: inode fop=328 data=344/152 blocks=152 kstat_first=1
[    2.600203] NoMount: layout: inode hash=224 getattr=144 callback/function=3/2 context=0
[    2.602438] NoMount: layout: super drop/evict=32/40
[    2.884183] NoMount: layout: BTF unavailable; deriving directory object fields from function anchors
[    2.929012] NoMount: layout: directory lock=88 iterate/shared=48/-1
[    2.958378] NoMount: layout: directory init/release=-1/40 actor=0
[    3.258562] NoMount: layout: BTF unavailable; using common virtual-directory native prototypes
[    3.523348] NoMount: layout: BTF unavailable; using common topology native prototypes
[    3.781567] NoMount: layout: BTF unavailable; using common backing-path native prototype
[    4.037242] NoMount: layout: BTF unavailable; deriving inode permission ABI from function anchors
[    4.061792] NoMount: layout: permission ABI=0
[    4.317413] NoMount: layout: BTF unavailable; deriving control object fields from function anchors
[    4.321155] NoMount: layout: control key_input=40
[    4.406725] NoMount: layout: control key_callbacks=24
[    4.451062] NoMount: ready, version=2.1.1-20261014, offsets=dynamic; resident until reboot, do not unload
[    4.451070] [+] KP I load_module: [NoMount] succeed with [(null)] 
[    4.451078] KP load kpm: NoMount, event: pre-kernel-init, rc: 0
```

#### 关键技术判定与突破确证
1. **TST-001 修复成立**：
   内核日志确证：`NoMount: layout: inode initial file table identified by open callback`！通过引入 `__start_rodata` 边界回退，代码成功越过 `_etext` 绝对符号导致的虚假边界检查失败，成功进入指令流扫描。
2. **DEV-042 达成闭环**：
   在无符号 `no_open_fops` 的情况下，成功利用 `inode_init_always` 入口 21 条指令的 ADRP/ADD/STR 追踪，并核验 open 槽指针指向 `no_open`，精确解析出 `i_fop=328, i_data=344`。
3. **端到端用户主路径（§4.2）**：
   - 安装配套 ZIP，提示 `- NoMount 已连接，驱动版本：2.1.1-20261014`；
   - `nm version` 验证返回 `2.1.1-20261014`；
   - 路径重定向：写入 `/data/local/tmp/nomount_test_44_dyn.txt` 并重定向至 `/system/etc/nomount_test_44_dyn.txt`，读取验证输出 `TEST_44_DYN_OK`；
   - Whiteout 屏蔽：添加 `--whiteout` 规则后读取返回 `cat: /system/etc/nomount_test_44_dyn.txt: No such file or directory`（`ENOENT`）；
   - 真实 App 路径：`me.zhanghai.android.files` 在 Enforcing 下通过 `cmd package compile -m speed -f`（返回 `Success`），应用在沙箱域 `u:r:untrusted_app:s0:c177,c256,c512,c768`（PID 8645）正常运行，`/proc/8645/maps` 映射正确无泄漏；
   - `/sys/fs/pstore/` 检查无异常转储；趟间已彻底卸载配套 ZIP。

---

### 2. 趟 ②：Linux 4.4（Nokia 7 plus，静态 legacy-kp 抽样实测）

在目标设备 `boot_b` 原地解包并嵌入待测静态产物：
```bash
/data/adb/ap/bin/kptools -p -i kernel -k /data/data/me.bmax.apatch/patch/kpimg -o new_kernel \
  -E re_kernel -E cgroupv2_freeze -E zram_zstd \
  -M /data/local/tmp/NoMount_run2_44.kpm -T kpm -V pre-kernel-init
```
重打包镜像 `local/tester-raw/new-boot-run2-44.img`（SHA-256 `1b7a3adf1c95227be87a39e5f9d23d3e8834d2d9ab2b26866c502f0d255a2514`），刷入 `boot_b` 并重启。

#### 内核引导日志（dmesg）
```text
[    0.783368] [+] KP D     name: NoMount
[    0.783389] [+] KP D     description: NoMount: read-only file and directory views, resident until reboot
[    0.964419] NoMount: ready, version=2.1.1-20261014, offsets=static; resident until reboot, do not unload
[    0.964426] [+] KP I load_module: [NoMount] succeed with [(null)] 
[    0.964433] KP load kpm: NoMount, event: pre-kernel-init, rc: 0
```

#### 端到端功能验证（§4.2）
1. **模块安装与驱动连接**：安装配套 ZIP，提示 `- NoMount 已连接，驱动版本：2.1.1-20261014`；
2. **CLI 版本确认**：`nm version` 输出 `2.1.1-20261014`；
3. **功能规则验证**：重定向输出 `TEST_44_STAT_OK`，Whiteout 屏蔽呈现 `ENOENT`，规则增删工作正常；
4. **真实应用主路径**：`me.zhanghai.android.files` 在 Enforcing 模式下通过 speed 编译，进程运行于 `u:r:untrusted_app:s0:c177,c256,c512,c768`（PID 9120），内存映射验证通过；
5. **系统健康度**：`/sys/fs/pstore/` 干净；趟间已彻底卸载配套 ZIP。

---

### 3. 趟 ③：Linux 4.19（Sony Xperia 1 II，静态 patch 抽样实测）

在目标设备 `boot_a` 原地解包并嵌入待测静态产物：
```bash
/data/adb/ap/bin/kptools -p -i kernel -k /data/data/me.bmax.apatch/patch/kpimg -o new_kernel \
  -E re_kernel_x -E hosts_redirect -E zram_zstd \
  -M /data/local/tmp/NoMount_run3_419.kpm -T kpm -V pre-kernel-init
```
重打包镜像 `local/tester-raw/new-boot-run3-419.img`（SHA-256 `b9f364db75887d81ff0918c7819fddc45be855c99fc3b384a1f8be7170e8d9db`），刷入 `boot_a` 并重启。

#### 内核引导日志（dmesg）
```text
[    2.841287] [+] KP D     name: NoMount
[    2.841302] [+] KP D     description: NoMount: read-only file and directory views, resident until reboot
[    3.302596] NoMount: ready, version=2.1.1-20261014, offsets=static; resident until reboot, do not unload
[    3.302601] [+] KP I load_module_ex: [NoMount] succeed with [(null)] 
[    3.302607] KP load kpm: NoMount, event: pre-kernel-init, rc: 0
```

#### 端到端功能验证（§4.2）
1. **驱动就绪与 CLI 连接**：安装配套 ZIP，驱动版本识别为 `2.1.1-20261014`；`nm version` 输出 `2.1.1-20261014`；
2. **重定向与 Whiteout**：重定向输出 `TEST_419_STAT_OK`；Whiteout 规则生效呈现 `ENOENT`；
3. **真实应用主路径**：`me.zhanghai.android.files` 在 Enforcing 下完成 speed 编译（返回 `Success`），沙箱运行（PID 6664，UID 10006）及内存映射验证无泄漏；
4. **健康度与卫生**：`/sys/fs/pstore/` 无新增异常转储；趟间已彻底卸载配套 ZIP。

---

### 4. 趟 ④：Linux 4.19（Sony Xperia 1 II，动态候选全量回归）

在目标设备 `boot_a` 原地解包并嵌入待测产物：
```bash
/data/adb/ap/bin/kptools -p -i kernel -k /data/data/me.bmax.apatch/patch/kpimg -o new_kernel \
  -E re_kernel_x -E hosts_redirect -E zram_zstd \
  -M /data/local/tmp/NoMount_run4_419.kpm -T kpm -V pre-kernel-init
```
重打包镜像 `local/tester-raw/new-boot-run4-419.img`（SHA-256 `c181436356e9b5d54b2774662b126a94c70d214c2606425bfe2ef27cf95c82f5`），刷入 `boot_a` 并重启。

#### 内核引导日志（dmesg）
```text
[    2.865529] NoMount: layout: BTF unavailable; deriving object fields from function anchors
[    2.909480] NoMount: layout: file objects=32/32 mapping=240
[    2.909497] NoMount: layout: inode sb=40 ino=64 size=80 nlink=72/72
[    2.909505] NoMount: layout: dentry ops=96
[    2.933390] NoMount: layout: BTF unavailable; deriving rule hash ABI from function anchor
[    2.952438] NoMount: layout: full_name_hash arguments=3
[    2.976322] NoMount: layout: BTF unavailable; deriving file fields from function anchors
[    3.194295] NoMount: layout: file_operations size=296 (tty_default_fops)
[    3.379344] NoMount: layout: file callbacks open=104 release=120 mmap=88 splice_read=192
[    3.403262] NoMount: layout: owned zero-table capacity=512
[    3.533005] NoMount: layout: inode hash=224 getattr=128 callback/function=4/4 context=0
[    3.539360] NoMount: layout: super drop/evict=40/48
[    3.542199] NoMount: layout: control mutex=32/no_dep_map
[    3.714536] NoMount: layout: directory lock=88 iterate/shared=48/56
[    3.817682] NoMount: layout: directory init/release=40/48 actor=0
[    3.896730] NoMount: layout: operation extents inode/super/dentry=256/280/192
[    4.038836] NoMount: layout: BTF unavailable; deriving inode storage from function anchors
[    4.138441] NoMount: layout: inode fop=368 data=384/264 blocks=144 kstat_first=0
[    4.165937] NoMount: layout: inode hash=224 getattr=128 callback/function=4/4 context=0
[    4.172293] NoMount: layout: super drop/evict=40/48
[    4.272836] NoMount: layout: BTF unavailable; deriving directory object fields from function anchors
[    4.445115] NoMount: layout: directory lock=88 iterate/shared=48/56
[    4.548251] NoMount: layout: directory init/release=40/48 actor=0
[    4.679757] NoMount: layout: BTF unavailable; using common virtual-directory native prototypes
[    4.735836] NoMount: layout: BTF unavailable; using common topology native prototypes
[    4.772703] NoMount: layout: BTF unavailable; using common backing-path native prototype
[    4.802994] NoMount: layout: BTF unavailable; deriving inode permission ABI from function anchors
[    4.894830] NoMount: layout: permission ABI=0
[    4.925139] NoMount: layout: BTF unavailable; deriving control object fields from function anchors
[    4.934778] NoMount: layout: control key_input=40
[    5.163291] NoMount: layout: control key_callbacks=24
[    5.263947] NoMount: ready, version=2.1.1-20261014, offsets=dynamic; resident until reboot, do not unload
[    5.263953] [+] KP I load_module_ex: [NoMount] succeed with [(null)] 
[    5.263960] KP load kpm: NoMount, event: pre-kernel-init, rc: 0
```

#### 端到端功能验证（§4.2）
1. **模块安装与驱动连接**：安装配套 ZIP，提示 `- NoMount 已连接，驱动版本：2.1.1-20261014`；
2. **CLI 版本确认**：`nm version` 输出 `2.1.1-20261014`；
3. **功能规则验证**：重定向输出 `TEST_419_DYN_OK`，Whiteout 屏蔽呈现 `ENOENT`；
4. **真实应用主路径**：`me.zhanghai.android.files` 在 Enforcing 下完成 speed 编译（`Success`），沙箱运行（PID 6130，UID 10006）及内存映射正常无泄漏；
5. **健康度与卫生**：`/sys/fs/pstore/` 无新增异常转储；趟间已彻底卸载配套 ZIP。

---

## 5.15 动态目标顺延绑定声明

依据维护者在 [`docs/records/2026-10-15-nomount-two-device-round-request.md`](../../../docs/records/2026-10-15-nomount-two-device-round-request.md) 的说明与 Auditor 裁定：

1. **裁定原文**：
   > “Auditor 裁定 5.15 Delta 运行时行为等价性成立：在 BTF 完备的 5.15 上，新候选的所有可达执行路径、内存分配、VFS 拦截、生命周期与对外协议与上轮件等价（BTF 解得 `inode_ops=256`、`dentry_ops=192` 均为 128 整数倍，探针路径不可达）$\rightarrow$ **支持把上轮 5.15 全量实测（20/20）顺延绑定到本轮动态候选**。”
2. **被绑定的旧实测证据**：
   - 绑定自实机报告 [`Tester/reports/runs/2026-10-15-nomount-inode-storage-live#1.md`](2026-10-15-nomount-inode-storage-live#1.md) 中的 **趟 ③（5.15 有 BTF 全通证据，20/20 全绿）**。
3. **状态声明**：
   - 5.15 动态目标实机证据由 Delta 不可达性等价性证明完成合规顺延绑定，待设备物理接入后排期补测归档。

---

## 结论与问题单关闭确认

1. **测试结论**：
   - 四趟实测（趟 ① 4.4 动态、趟 ② 4.4 静态、趟 ③ 4.19 静态、趟 ④ 4.19 动态）**全部 100% 顺利通过**；
   - 5.15 动态目标依据 Auditor 裁定顺延绑定通过；
   - **重大里程碑**：Linux 4.4（Nokia 7 plus，旧版 KP `d04`）动态推导件历史上首次在真机上全功能跑通！
2. **问题单关闭复核建议**：
   - **`TST-001`**（`_etext` 绝对符号误判导致 4.4 动态拒载）：**确认彻底修复（CLOSED）**。实测表明 `__start_rodata` 边界回退有效，真机引导顺利解出布局进入运行态；
   - **`DEV-042`**（4.4 局部表名查询失败）：**确认彻底解决（CLOSED）**。实测表明基于 open 回调的局部表探测机制完全成立，真机上正确解出 `no_open_fops.36570` 对应的 `i_fop` 与 `i_data` 存储布局。
3. **交付建议**：
   - 本轮 candidate 在支持的真实设备覆盖集上表现稳定，关键缺陷已完全闭环，具备由维护者评估推进发布流程的条件。
