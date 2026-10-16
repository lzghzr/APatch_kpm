# 实机报告：NoMount inode storage 修复候选真机实测（三趟物理实机 + 两趟静态证据绑定）

角色：Tester（真机测试）。  
运行编号：`2026-10-15-nomount-inode-storage-live#1`。  
测试依据：响应维护者轮次请求 [`docs/records/2026-10-15-nomount-inode-storage-request.md`](../../../docs/records/2026-10-15-nomount-inode-storage-request.md)、Auditor 独立审计报告（[`Auditor/reports/2026-10-15-nomount-inode-storage-audit.md`](../../../Auditor/reports/2026-10-15-nomount-inode-storage-audit.md)）、[Tester 手册 §4.2 / §4.4](../../../docs/process/tester-handbook.md) 与风险接受记录 `RA-002`。  
**特别声明**：本轮测试对象为 Developer 提交的 **candidate（候选档）** 构建。根据维护者依据 Auditor 独立审计裁定（`EQUIVALENT`，100% 行为等价）发布的调整规则，本轮对 3 个硬件目标执行物理真机实测（趟 ① 4.4 修复目标、趟 ② 4.19 动态回归、趟 ③ 5.15 BTF 回归），静态派生件（趟 ④ 与 ⑤）按 Tester 手册 §4.4 规范严格绑定已验收的静态真机证据。

---

## 身份

| 项 | 值 |
| --- | --- |
| 候选来源 commit | `846f3d1bce5f7aa9c9f8d180e3c1b2f02b6d3e34` |
| 请求与当前 HEAD commit | `50600204762c290d135f5f3f57de9e06b6c39762` |
| **动态候选件 instance_id** | `nomount-2.1.1-20261014+g526802555793.r3ac93780.kpb51197a.ndk26.3.11579264#1` |
| **动态候选件 SHA-256** | `7e21475004c69deafa8d32d3607ca5359b0df0907a212ba0bbc37772ea5200ae`（213,528 字节） |
| **4.4 动态 legacy-kp 派生件 SHA-256** | `971b9e28135bcdfd45c8e223f20d5092ff53e719faaa00f2b08e36f53f5a497b`（213,520 字节） |
| 4.4 派生件相对路径 | `artifacts/binary-port/nomount/971b9e28135bcdfd45c8e223f20d5092ff53e719faaa00f2b08e36f53f5a497b/NoMount_2.1.1-20261014.kpm` |
| **配套 ZIP instance_id** | `nomount-zip-2.1.1-20261014+g5fbf6fec42ef.ndk26.3.11579264#1` |
| **配套 ZIP SHA-256** | `42c5b64458b73dcb202efb2cd6a1a82c604ba3c94698bd1d49085c752b045a44`（80,003 字节） |
| **重打包 boot 镜像 (4.4)** | `local/tester-raw/new-boot-nomount-candidate-44.img` (`3c9e4c473e86675cbef5c7b3448c5b0433747dade8f9e9f53eeaffe82ab29ae1`) |
| **重打包 boot 镜像 (4.19)** | `local/tester-raw/new-boot-nomount-candidate-419.img` (`30f53a933f9e6c83bca97f66966e3d78439f1744c7c74a1239b149dfacd5858c`) |
| **重打包 boot 镜像 (5.15)** | `local/tester-raw/new-boot-nomount-candidate-515.img` (`4ba93487c09272d1bc4ee9acd515d15f7c6123b1d1bc036e487f3904462b35db`) |

---

## 环境事实

| 项 | 4.4 目标机 | 4.19 目标机 | 5.15 目标机 |
| --- | --- | --- | --- |
| 设备指纹哈希 | `b754dad7` | `508d47da` | `48b7ee2f` |
| 机型（脱敏） | Nokia 7 plus (`B2N_sprout`) | Sony Xperia 1 II (`XQ-AT52`) | Sony Xperia 1 V (`XQ-DQ72`) |
| 内核版本 | `4.4.192-perf+ #1 SMP PREEMPT Tue Mar 9 17:03:29 CST 2021` | `4.19.325-cip134-st18-perf-g7fc8455b2fa8` | `5.15.189-android13-8-00016-g51bba4309aac-ab14546557` |
| 系统版本 / API | Android 10 / API 29 | Android 12 / API 31 | Android 15 / API 35 |
| BTF 状态 | **无 BTF** | **无 BTF** | **有 BTF** |
| SELinux 状态 | `Enforcing` | `Enforcing` | `Enforcing` |
| APatch / KP 版本 | `0xd04`（旧版 KP） | `0xd09` | `0xd09` |
| 引导机制 | `pre-kernel-init` 嵌入 | `pre-kernel-init` 嵌入 | `pre-kernel-init` 嵌入 |
| 引导槽位 | `boot_b` | `boot_a` | `boot_b` |
| 真实消费者应用 | N/A（模块拒载未进入用户态） | `me.zhanghai.android.files` (UID `10006`) | `com.cxinventor.file.explorer` (UID `10409`) |

---

## 测试矩阵判据与实测结果汇总

| 趟号 | 目标设备 / 场景 | 待测产物 | 预期行为与核心判据 | 实际测试结果 | 评级 / 结论 |
|---|---|---|---|---|:---:|
| **①** | **4.4 旧版 KP**<br>Nokia 7 plus<br>(`b754dad7`) | 动态 legacy-kp 派生件<br>`971b9e28...` | **本轮核心修复目标**：验证基于 `inode_init_always` 的 inode storage 探针是否突破旧版 `-ENOENT` 失败；能否顺利注册 Key type 并跑通用户主路径 | 操作表尺寸解出 `256/232/128`；但在执行探针有效性检查时，因 Nokia 4.4 内核中 `_etext` 为绝对符号导致地址数值小于已重定位的 `_stext`，误判触发 `inode initial file table evidence unavailable`，返回 `-2` 安全拒载 | **FAIL**<br>(安全 Fail-Closed，确证为探针符号断言缺陷，DEV-042 未闭环) |
| **②** | **4.19 无 BTF**<br>Sony Xperia 1 II<br>(`508d47da`) | 动态候选件<br>`7e214750...` | **全量回归验证**：验证无 BTF 下末端推导与 inode storage 维持稳定，不发生功能退化，跑通 §4.2 用户主路径与沙箱映射 | 成功解出 `inode/super/dentry=256/280/192` 及 `fop=368 data=384/264`，Key type 注册成功，模块加载 `rc: 0`；配套 ZIP 识别驱动 `2.1.1-20261014`；重定向、Whiteout、真实 App ART 编译及内存映射 100% 通过 | **PASS**<br>(4.19 动态回归完全通过) |
| **③** | **5.15 有 BTF**<br>Sony Xperia 1 V<br>(`48b7ee2f`) | 动态候选件<br>`7e214750...` | **BTF 回归验证**：确认有 BTF 时函数探针路径不被触发，BTF 5 项结构尺寸与关键字段解析无退化，全功能正常运行 | BTF 正常解析 5 类结构体尺寸；模块正常加载（`rc: 0`）；配套 ZIP 安装正常；重定向、Whiteout 与真实应用（CX 文件管理器）编译及映射 100% 通过 | **PASS**<br>(5.15 BTF 回归完全闭环) |
| **④** | **4.19 静态**<br>Sony Xperia 1 II | 静态 patch 派生件<br>`56fcfd9a...` | **静态发布口径实测 / 证据绑定**：依据 Tester 手册 §4.4 与 Auditor 报告 100% 行为等价裁定进行证据绑定 | **免测绑定**：绑定自 `2026-10-14-nomount-2.1.1-20261014-live#1` 趟 ② 验收证据。Auditor 反汇编证明控制流、生命周期与行为完全等价 | **BOUND (PASS)**<br>(依据 §4.4 绑定) |
| **⑤** | **4.4 静态**<br>Nokia 7 plus | 静态 legacy-kp 派生件<br>`9e392933...` | **静态发布口径实测 / 证据绑定**：依据 Tester 手册 §4.4 与 Auditor 报告 100% 行为等价裁定进行证据绑定 | **免测绑定**：绑定自 `2026-10-14-nomount-2.1.1-20261014-live#1` 趟 ④ 验收证据。Auditor 反汇编证明控制流、生命周期与行为完全等价 | **BOUND (PASS)**<br>(依据 §4.4 绑定) |

---

## 详细执行记录

### 1. 趟 ①：Linux 4.4（Nokia 7 plus，动态 legacy-kp 修复目标实测）

在目标设备 `boot_b` 原地解包并嵌入待测产物：
```bash
/data/adb/ap/bin/kptools -p -i kernel -k /data/data/me.bmax.apatch/patch/kpimg -o new_kernel \
  -E re_kernel -E cgroupv2_freeze -E zram_zstd \
  -M /data/local/tmp/NoMount_candidate_44.kpm -T kpm -V pre-kernel-init
```
重打包镜像 `local/tester-raw/new-boot-nomount-candidate-44.img`（SHA-256 `3c9e4c473e86675cbef5c7b3448c5b0433747dade8f9e9f53eeaffe82ab29ae1`），刷入 `boot_b` 后冷重启。

#### 内核引导日志（dmesg）
```text
[    1.037354] NoMount: layout: BTF unavailable; deriving object fields from function anchors
[    1.052885] NoMount: layout: file objects=32/32 mapping=248
[    1.052904] NoMount: layout: inode sb=40 ino=64 size=80 nlink=72/72
[    1.052911] NoMount: layout: dentry ops=96
[    1.306164] NoMount: layout: BTF unavailable; deriving rule hash ABI from function anchor
[    1.312870] NoMount: layout: full_name_hash arguments=2
[    1.566305] NoMount: layout: BTF unavailable; deriving file fields from function anchors
[    1.611550] NoMount: layout: file_operations size=216 (tty_default_fops)
[    1.660958] NoMount: layout: file callbacks open=88 release=104 mmap=80 splice_read=184
[    1.914318] NoMount: layout: owned zero-table capacity=512
[    1.953100] NoMount: layout: inode hash=224 getattr=144 callback/function=3/2 context=0
[    1.955337] NoMount: layout: super drop/evict=32/40
[    1.956187] NoMount: layout: control mutex=40/no_dep_map
[    2.001031] NoMount: layout: directory lock=88 iterate/shared=48/-1
[    2.030404] NoMount: layout: directory init/release=-1/40 actor=0
[    2.050364] NoMount: layout: operation extents inode/super/dentry=256/232/128
[    2.344143] NoMount: layout: BTF unavailable; deriving inode storage from function anchors
[    2.565460] NoMount: layout: inode initial file table evidence unavailable
[    2.565476] NoMount: layout: inode field derivation failed (-2)
[    2.565487] NoMount: initialization failed: -2
[    2.565496] [+] KP I load_module: [NoMount] failed with [(null)] error: -2, try exit ...
[    2.565521] KP load kpm: NoMount, event: pre-kernel-init, rc: -2
```

#### 根因技术诊断分析（Live Environment Fact）
本次测试出现的新报错日志：
`NoMount: layout: inode initial file table evidence unavailable`
经深入比对真机内核符号事实与源码实现：
1. 源码实现位置：[`nomount/nm_offsets.c:1087-1097`](../../../nomount/nm_offsets.c#L1087-L1097)：
   ```c
   struct nm_initial_fops_probe probe = {
       kallsyms_lookup_name_by_suffix("no_open"), 
       kallsyms_lookup_name("_stext"),
       kallsyms_lookup_name("_etext"), 
       kallsyms_lookup_name("_end")
   };
   if (!probe.end)
       probe.end = kallsyms_lookup_name("__end_rodata");
   if (!probe.open || !probe.start || probe.code_end <= probe.start || probe.end < probe.code_end) {
       nm_log_error("layout: inode initial file table evidence unavailable\n");
       return -ENOENT;
   }
   ```
2. Nokia 7 plus 4.4 真机 `/proc/kallsyms` 符号实测输出：
   ```text
   ffffff8aad680800 T _stext
   ffffff8009000000 A _etext
   ffffff8aaeded000 R __end_rodata
   ffffff8aad7e62dc t no_open
   ffffff8aae619ef0 r no_open_fops.36570
   ```
3. **断言失效原因**：
   - `_stext` 是代码段起始符号（类型为 `T`），在启动装载时完成了基地址重定位，值为 `0xffffff8aad680800`；
   - `_etext` 在该 4.4 内核中为绝对链接符号（类型为 `A`），保持编译链接期的绝对虚拟地址 `0xffffff8009000000`，未参与重定位；
   - 在数值大小上：`0xffffff8009000000` 显著小于 `0xffffff8aad680800`；
   - 导致断言中的 `probe.code_end <= probe.start` 在真机上无条件触发为真，探针逻辑在尚未开始扫描 `inode_init_always` 指令流之前便误判为“边界不可用”直接返回 `-ENOENT (-2)`。
4. **安全评价**：
   - 模块严格遵守 Fail-Closed 原则，检测异常即刻退出，KP 干净卸载，未引发内核崩溃或系统软重启。
   - **问题单状态**：`DEV-042`（4.4 局部表查询失败）在真机上尚未闭环，需交回 Developer 修正符号边界断言。

---

### 2. 趟 ②：Linux 4.19（Sony Xperia 1 II，动态候选件全量回归）

在目标设备 `boot_a` 原地解包并嵌入待测产物：
```bash
/data/adb/ap/bin/kptools -p -i kernel -k /data/data/me.bmax.apatch/patch/kpimg -o new_kernel \
  -E re_kernel_x -E hosts_redirect -E zram_zstd \
  -M /data/local/tmp/NoMount_candidate_419.kpm -T kpm -V pre-kernel-init
```
重打包镜像 `local/tester-raw/new-boot-nomount-candidate-419.img`（SHA-256 `30f53a933f9e6c83bca97f66966e3d78439f1744c7c74a1239b149dfacd5858c`），刷入 `boot_a` 并重启。

#### 内核引导日志（dmesg）
```text
[    2.865298] NoMount: layout: BTF unavailable; deriving object fields from function anchors
[    2.909238] NoMount: layout: file objects=32/32 mapping=240
[    2.909252] NoMount: layout: inode sb=40 ino=64 size=80 nlink=72/72
[    2.909257] NoMount: layout: dentry ops=96
[    2.933127] NoMount: layout: BTF unavailable; deriving rule hash ABI from function anchor
[    2.952201] NoMount: layout: full_name_hash arguments=3
[    2.976079] NoMount: layout: BTF unavailable; deriving file fields from function anchors
[    3.194091] NoMount: layout: file_operations size=296 (tty_default_fops)
[    3.379148] NoMount: layout: file callbacks open=104 release=120 mmap=88 splice_read=192
[    3.403076] NoMount: layout: owned zero-table capacity=512
[    3.532836] NoMount: layout: inode hash=224 getattr=128 callback/function=4/4 context=0
[    3.539197] NoMount: layout: super drop/evict=40/48
[    3.542034] NoMount: layout: control mutex=32/no_dep_map
[    3.714377] NoMount: layout: directory lock=88 iterate/shared=48/56
[    3.817546] NoMount: layout: directory init/release=40/48 actor=0
[    3.896597] NoMount: layout: operation extents inode/super/dentry=256/280/192
[    4.038698] NoMount: layout: BTF unavailable; deriving inode storage from function anchors
[    4.138253] NoMount: layout: inode fop=368 data=384/264 blocks=144 kstat_first=0
[    4.165755] NoMount: layout: inode hash=224 getattr=128 callback/function=4/4 context=0
[    4.172113] NoMount: layout: super drop/evict=40/48
[    4.272645] NoMount: layout: BTF unavailable; deriving directory object fields from function anchors
[    4.444958] NoMount: layout: directory lock=88 iterate/shared=48/56
[    4.548101] NoMount: layout: directory init/release=40/48 actor=0
[    4.679572] NoMount: layout: BTF unavailable; using common virtual-directory native prototypes
[    4.735634] NoMount: layout: BTF unavailable; using common topology native prototypes
[    4.772493] NoMount: layout: BTF unavailable; using common backing-path native prototype
[    4.802776] NoMount: layout: BTF unavailable; deriving inode permission ABI from function anchors
[    4.894606] NoMount: layout: permission ABI=0
[    4.924923] NoMount: layout: BTF unavailable; deriving control object fields from function anchors
[    4.934567] NoMount: layout: control key_input=40
[    5.163123] NoMount: layout: control key_callbacks=24
[    5.263788] NoMount: ready, version=2.1.1-20261014, offsets=dynamic; resident until reboot, do not unload
[    5.263795] [+] KP I load_module_ex: [NoMount] succeed with [(null)] 
[    5.263803] KP load kpm: NoMount, event: pre-kernel-init, rc: 0
```

#### 端到端功能验证（§4.2）
1. **模块安装与驱动连接**：安装配套 ZIP `NoMount-kpm_2.1.1-20261014.zip`，提示 `- NoMount 已连接，驱动版本：2.1.1-20261014`；
2. **CLI 版本确认**：`/data/local/tmp/nm version` 输出 `2.1.1-20261014`；
3. **重定向规则**：添加 `/system/etc/nomount_test_419.txt` 重定向规则，读取内容验证为 `CANDIDATE_419_DYNAMIC_OK`；
4. **Whiteout 屏蔽**：添加 `--whiteout` 规则后读取返回 `cat: /system/etc/nomount_test_419.txt: No such file or directory`（`ENOENT`）；删除规则后列表恢复干净；
5. **真实应用主路径**：
   - 目标应用：`me.zhanghai.android.files`（Material Files，UID `10006`）；
   - 执行 `cmd package compile -m speed -f me.zhanghai.android.files`，返回 `Success`；
   - 启动应用，进程运行于受限域 `u:r:untrusted_app:s0:c6,c256,c512,c768`（PID 6756）；
   - 内存映射 `/proc/6756/maps` 验证通过，Dalvik / ART / oat 映射正常，无非法泄漏；
6. **健康度与卫生**：`/sys/fs/pstore/` 无新增转储；趟间已彻底卸载配套 ZIP 并清除临时测试文件。

---

### 3. 趟 ③：Linux 5.15（Sony Xperia 1 V，动态候选件 BTF 回归实测）

在目标设备 `boot_b` 原地解包并嵌入待测产物：
```bash
/data/adb/ap/bin/kptools -p -i kernel -k /data/data/me.bmax.apatch/patch/kpimg -o new_kernel \
  -E re_kernel_x -E zram_zstd -E hosts_redirect \
  -M /data/local/tmp/NoMount_candidate_515.kpm -T kpm -V pre-kernel-init
```
重打包镜像 `local/tester-raw/new-boot-nomount-candidate-515.img`（SHA-256 `4ba93487c09272d1bc4ee9acd515d15f7c6123b1d1bc036e487f3904462b35db`），刷入 `boot_b` 并重启。

#### 内核引导日志（`/data/adb/ap/log/dmesg.log`）
```text
[    0.258043] [+] KP D     name: NoMount
[    0.258059] [+] KP D     description: NoMount: read-only file and directory views, resident until reboot
[    0.301448] NoMount: layout: BTF objects=32 mapping=232 sb=40 ino=64 nlink=72 size=80 d_op=96
[    0.331736] NoMount: file_operations size=288
[    0.331744] NoMount: inode_operations size=256
[    0.331766] NoMount: super_operations size=232
[    0.331771] NoMount: dentry_operations size=192
[    0.331934] NoMount: key_type size=184
[    0.629362] NoMount: ready, version=2.1.1-20261014, offsets=dynamic; resident until reboot, do not unload
[    0.629366] [+] KP I load_module_ex: [NoMount] succeed with [(null)] 
[    0.629376] KP load kpm: NoMount, event: pre-kernel-init, rc: 0
```

#### 端到端功能验证（§4.2）
1. **模块安装与驱动连接**：安装配套 ZIP，正确建立符号链接并识别驱动版本 `2.1.1-20261014`；
2. **CLI 版本确认**：`nm version` 输出 `2.1.1-20261014`；
3. **功能规则验证**：重定向输出 `CANDIDATE_515_DYNAMIC_OK`，Whiteout 屏蔽呈现 `ENOENT`，规则增删与已有模块共存无冲突；
4. **真实应用主路径**：
   - 目标应用：`com.cxinventor.file.explorer`（CX 文件管理器，UID `10409`）；
   - 执行 `cmd package compile -m speed -f com.cxinventor.file.explorer`，返回 `Success`；
   - 启动应用，进程运行于受限域 `u:r:untrusted_app:s0:c153,c257,c512,c768`（PID 11067）；
   - 内存映射 `/proc/11067/maps` 验证通过，ART 编译码加载正常；
5. **健康度与卫生**：`/sys/fs/pstore/` 无新增崩溃记录；趟间已彻底卸载配套 ZIP。

---

### 4. 趟 ④ & 趟 ⑤：静态派生件证据绑定声明（依据 Tester 手册 §4.4）

依据维护者在 [`docs/records/2026-10-15-nomount-inode-storage-request.md`](../../../docs/records/2026-10-15-nomount-inode-storage-request.md) 的最终裁定与 Auditor 独立审计报告（[`Auditor/reports/2026-10-15-nomount-inode-storage-audit.md`](../../../Auditor/reports/2026-10-15-nomount-inode-storage-audit.md) §3.4）：

1. **绑定依据（Auditor 裁定原文）**：
   > “Auditor 裁定：`77a5baa3…` 相对已验收发布件 `76e220cd…` 在语义、控制流、执行路径、生命周期、安全模型与对外行为上 **100% 行为等价**。Auditor 确认：该行为等价结论在技术与法理上支持将已验收的静态真机测试证据直接绑定至新静态字节 `77a5baa3…`。”
2. **被绑定的旧真机证据**：
   - **4.19 静态派生件**（`56fcfd9a7f3490df58a0e3b60d292cad1083ac852375e9cb3ad5dbdd95f42186`）：绑定自已验收实机报告 [`Tester/reports/runs/2026-10-14-nomount-2.1.1-20261014-live#1.md`](2026-10-14-nomount-2.1.1-20261014-live#1.md) 中的 **趟 ②（4.19 静态版全通证据，20/20 项全绿）**；
   - **4.4 静态 legacy-kp 派生件**（`9e39293341f225e24bce9384faf531b9a23532d5fc773f38c327c258661f4248`）：绑定自已验收实机报告 [`Tester/reports/runs/2026-10-14-nomount-2.1.1-20261014-live#1.md`](2026-10-14-nomount-2.1.1-20261014-live#1.md) 中的 **趟 ④（4.4 静态 legacy-kp 版全通证据，20/20 项全绿）**。
3. **未重复上机目标**：
   - 4.19 静态派生目标（Sony Xperia 1 II）；
   - 4.4 静态 legacy-kp 目标（Nokia 7 plus）。

---

## 结论与问题单跟踪

1. **测试结果**：
   - 趟 ①（4.4 动态修复目标）：**FAIL（安全拒载，未进入用户态）**；
   - 趟 ②（4.19 动态回归）：**PASS（完全通过）**；
   - 趟 ③（5.15 BTF 回归）：**PASS（完全通过）**；
   - 趟 ④ & ⑤（静态目标）：**BOUND（依据 §4.4 合规绑定已验收结论）**。
2. **问题单跟踪**：
   - **`DEV-042`**：由于 4.4 动态真机测试触发探针符号边界断言缺陷未能加载，判据要求之真机全通条件未达成，**维持未闭环状态，不予关闭**；
   - **`AUD-001`**：无 BTF 目标仍使用自建容量，维持 OPEN。
3. **交付建议**：
   - 鉴于核心修复目标（4.4 动态）仍处于 Fail-Closed 状态，本轮候选**不具备发布口径准入条件**，待 Developer 针对绝对符号断言修复后再次提交复核。
