# 实机报告：NoMount 自建操作表容量（无 BTF 动态路径）探索构建定向实测

角色：Tester（真机测试）。  
运行编号：`2026-10-15-nomount-owned-operation-capacity-live#1`。  
测试依据：响应维护者轮次请求 [`docs/records/2026-10-15-nomount-owned-operation-capacity-request.md`](../../../docs/records/2026-10-15-nomount-owned-operation-capacity-request.md)、Auditor 独立审计报告（[`Auditor/reports/2026-10-15-nomount-owned-operation-capacity-audit.md`](../../../Auditor/reports/2026-10-15-nomount-owned-operation-capacity-audit.md)）与风险接受记录 `RA-002`。  
**特别声明**：本轮测试对象为 Developer 提交的 **exploration（探索档）** 构建，**本轮不出具正式验收结论**，实测结果专用于为开发者定位非 BTF 降级路径上的剩余缺口。

---

## 身份

| 项 | 值 |
| --- | --- |
| 探索来源 commit | `7e668af2213d78a4e7cbb0c72bc9f5660678403d` |
| 请求与当前 HEAD commit | `d7132a1e9205b9f2f2f18d5d805d81834fd63aaa` |
| **待测动态探索件 instance_id** | `nomount-2.1.1-20261014+g875b16f95083.r130c2158.kpb51197a.ndk26.3.11579264#1` |
| **待测动态探索件 SHA-256** | `24efeb02dd0b89283aca40f768d59203cada3aaaf3d4fe0811e3b35e7f7c9f63`（202,728 字节） |
| **重打包 boot 镜像 (4.19 诊断)** | `local/tester-raw/new-boot-nomount-capacity-419-dynamic.img` (`f05344f4829bc866805768f3c8f0559ca19bcfdbcb15e54f03f411bc5a8e34cd`) |
| **重打包 boot 镜像 (5.15 回归)** | `local/tester-raw/new-boot-nomount-capacity-515-dynamic.img` (`c3c0e6e0dcfcd7808c529a6017988432bd2aae4e703183c1a6aa3de09b9d08c4`) |
| **配套 ZIP instance_id** | `nomount-zip-2.1.1-20261014+g5fbf6fec42ef.ndk26.3.11579264#1` |
| **配套 ZIP SHA-256** | `42c5b64458b73dcb202efb2cd6a1a82c604ba3c94698bd1d49085c752b045a44` |

---

## 环境事实

| 项 | 4.19 诊断目标 | 5.15 回归目标 |
| --- | --- | --- |
| 设备指纹哈希 | `508d47da` | `48b7ee2f` |
| 机型（脱敏） | Sony Xperia 1 II (`XQ-AT52`) | Sony Xperia 1 V (`XQ-DQ72`) |
| 内核版本 | `4.19.325-cip134-st18-perf-g7fc8455b2fa8` | `5.15.189-android13-8-00016-g51bba4309aac-ab14546557` |
| 系统版本 / API | Android 12 / API 31 | Android 15 / API 35 |
| BTF 支持状态 | **无 BTF** | **有 BTF** |
| SELinux 状态 | `Enforcing` | `Enforcing` |
| APatch / KernelPatch | `0xd09` | `0xd09` |
| 引导机制 | APatch `pre-kernel-init` 极早期内核嵌入 | APatch `pre-kernel-init` 极早期内核嵌入 |
| 真实消费者应用 | N/A（未进入运行态） | `com.cxinventor.file.explorer` (UID `10409`) |

---

## 两趟测试判据与实测结果汇总

| 趟号 | 目标设备 / 场景 | 待测产物 | 预期行为与核心判据 | 实际测试结果 | 评级 / 结论 |
|---|---|---|---|---|:---:|
| **①** | **4.19 无 BTF**<br>Sony Xperia 1 II<br>(`508d47da`) | `NoMount_2.1.1-20261014.kpm`<br>(`24efeb02dd0b...`) | **诊断缺口**：相比上轮 `-ENODATA(-61)` 阻塞，验证 512B 容量策略能否放行 key 分配与控制布局校验，确认停在原表尺寸缺失缺口，验证 Fail-Closed 安全拒载 | 突破前轮 `-61` 限制，日志确认 `owned zero-table capacity=512` 激活；随后停在三类原表复制尺寸缺失处，精准返回 `-ENOENT (-2)`，KP 干净拒载，系统正常启动无崩溃 | **诊断成功**<br>(Fail-Closed 确证) |
| **②** | **5.15 有 BTF**<br>Sony Xperia 1 V<br>(`48b7ee2f`) | `NoMount_2.1.1-20261014.kpm`<br>(`24efeb02dd0b...`) | **回归验证**：确认在具备 BTF 内核上容量策略不被触发，既有 BTF 5 项表尺寸正常查询，模块正常加载并在 Enforcing 下主路径可用 | BTF 正常识别并查询到所有 5 类结构体精确尺寸（容量策略未触发）；模块成功加载（`rc: 0`）；配套 ZIP 安装成功识别驱动 `2.1.1-20261014`；重定向、白名单透传与真实应用 ART/mmap 全量通过 | **PASS**<br>(无回归破坏) |

---

## 详细执行记录

### 1. 趟 ①：Linux 4.19（无 BTF 诊断）

在 `boot_a` 原地解包并嵌入待测探索件：
```bash
/data/adb/ap/bin/kptools -p -i kernel -k /data/data/me.bmax.apatch/patch/kpimg -o new_kernel \
  -E re_kernel_x -E zram_zstd -E hosts_redirect \
  -M /data/local/tmp/NoMount_exploration_dynamic_419.kpm -T kpm -V pre-kernel-init
```

刷入分区冷启动后，抓取内核 `dmesg` 日志：
```text
[    2.865600] NoMount: layout: BTF unavailable; deriving object fields from function anchors
[    2.909552] NoMount: layout: file objects=32/32 mapping=240
[    2.909568] NoMount: layout: inode sb=40 ino=64 size=80 nlink=72/72
[    2.909573] NoMount: layout: dentry ops=96
[    2.933455] NoMount: layout: BTF unavailable; deriving rule hash ABI from function anchor
[    2.952528] NoMount: layout: full_name_hash arguments=3
[    2.976407] NoMount: layout: BTF unavailable; deriving file fields from function anchors
[    3.194472] NoMount: layout: file_operations size=296 (tty_default_fops)
[    3.379550] NoMount: layout: file callbacks open=104 release=120 mmap=88 splice_read=192
[    3.403465] NoMount: layout: owned zero-table capacity=512
[    3.403480] NoMount: initialization failed: -2
[    3.403490] [+] KP I load_module_ex: [NoMount] failed with [(null)] error: -2, try exit ...
[    3.403520] KP load kpm: NoMount, event: pre-kernel-init, rc: -2
```

**诊断分析**：
1. **控制布局校验通过**：上轮卡在 `calculate_btf_control_layout` 返回 `-61`；本轮 Key 对象的分配与控制布局校验顺利通过；
2. **容量策略正常触发**：在 BTF 不可用（`-ENODATA` 且 `unavailable == true`）时，成功切换为 `nm_owned_operation_fallback = true`，输出 `layout: owned zero-table capacity=512`；
3. **精准定位于未完成面**：进入 `nm_prepare_operation_sizes()` 后，`file_operations size=296` 已由锚点解出，但 `inode_ops_size`、`super_ops_size`、`dentry_ops_size` 仍为 `-1`，函数安全触发 Fail-Closed 并返回 `-ENOENT (-2)`；
4. **资源安全退回**：KernelPatch 识别 `-2` 后安全释放已分配资源，系统正常启动，`/sys/fs/pstore/` 干净无崩溃记录。

---

### 2. 趟 ②：Linux 5.15（有 BTF 回归）

在 `boot_b` 原地解包并嵌入待测探索件：
```bash
/data/adb/ap/bin/kptools -p -i kernel -k /data/data/me.bmax.apatch/patch/kpimg -o new_kernel \
  -E re_kernel_x -E zram_zstd -E hosts_redirect \
  -M /data/local/tmp/NoMount_exploration_dynamic_515.kpm -T kpm -V pre-kernel-init
```

刷入分区冷启动后，检查内核引导日志（`/data/adb/ap/log/dmesg.log`）：
```text
[    0.257428] NoMount: layout: BTF objects=32 mapping=232 sb=40 ino=64 nlink=72 size=80 d_op=96
[    0.287693] NoMount: file_operations size=288
[    0.287700] NoMount: inode_operations size=256
[    0.287721] NoMount: super_operations size=232
[    0.287727] NoMount: dentry_operations size=192
[    0.287891] NoMount: key_type size=184
[    0.585265] Key type nomount registered
[    0.585277] NoMount: ready, version=2.1.1-20261014, offsets=dynamic; resident until reboot, do not unload
[    0.585280] [+] KP I load_module_ex: [NoMount] succeed with [(null)] 
[    0.585289] KP load kpm: NoMount, event: pre-kernel-init, rc: 0
```

**功能与回归核验**：
1. **容量策略未触发**：内核 BTF 存在且有效，`calculate_btf_operation_sizes` 返回 0，未打印 `owned zero-table capacity`，严格按 BTF 解析出全部五类精确尺寸；
2. **模块注册成功**：Key type 注册成功，模块常驻内核；
3. **配套工具通信**：安装 companion ZIP，安装脚本正确探测到驱动 `2.1.1-20261014`；调用 `nm version` 准确输出 `2.1.1-20261014`；
4. **功能验证**：
   - 重定向规则测试：创建测试文件重定向，读取内容一致；
   - Whiteout 测试：白名单屏蔽后目标呈现 `ENOENT`；
   - 真实应用测试：执行 `cmd package compile -m speed -f com.cxinventor.file.explorer` 成功返回 `Success`；启动应用后进程运行在受限域 `u:r:untrusted_app:s0:c153,c257,c512,c768`（UID `10409`），`/proc/<pid>/maps` 正确加载；
   - pstore 检查：`/sys/fs/pstore/` 无新增异常转储，测试结束前卸载 companion ZIP。

---

## 结论与对开发者的反馈

1. **探索目标达成**：
   - **512 字节自建表容量策略在 4.19 实机上工作符合设计**：成功化解了上轮 Key 控制面因无 BTF 而被 `-61` 直接拒载的问题，并如预期在 `owned zero-table capacity=512` 后因缺少 3 类原表复制尺寸而精准截流在 `-2 (-ENOENT)`；
   - **对既有 BTF 体系零破坏**：5.15 GKI 内核完整验证了 BTF 正常路径完全未受容量降级分支干扰，所有尺寸精确解析且功能端到端全绿。
2. **剩余缺口定位**：
   无 BTF 内核如果要真正完成动态全量加载，仍需解决原表复制尺寸的获取问题（`inode_ops_size`、`super_ops_size`、`dentry_ops_size`）。
3. **性质声明**：
   本报告为探索诊断报告，不构成正式候选验收。
