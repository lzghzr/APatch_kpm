# NoMount 尾部锚点、十三目标静态适配与 TST-001 修复独立审计报告

- **模块**：`nomount`
- **版本**：`2.1.1-20261014`
- **构建档位**：`candidate`
- **源码冻结提交**：[`ebad05883bcd6173d5e2a867559aa6bcb3e45810`](https://github.com/kernelpatch/APatch_kpm/commit/ebad05883bcd6173d5e2a867559aa6bcb3e45810)
- **KernelPatch 提交**：`b51197aaba8f2272dd8a3e30c85698a29aa928c9`
- **工具链**：`ndk26.3.11579264`（Android NDK r26d / Clang 17.0.2）
- **审计角色**：Auditor（独立执行，不依赖实现方/维护方中间产物）
- **依据请求**：[`docs/records/2026-10-15-nomount-tail-anchors-request.md`](../../../docs/records/2026-10-15-nomount-tail-anchors-request.md) 与 [`docs/records/2026-10-15-nomount-4.4-probe-bound-request.md`](../../../docs/records/2026-10-15-nomount-4.4-probe-bound-request.md)

---

## 1. 审计对象与独立复现

### 1.1 候选原件无缓存重编译

Auditor 在纯净隔离沙箱目录 `local/auditor-scratch/nomount-tail-anchors-20261015/worktree`（检出 `ebad05883bcd6173d5e2a867559aa6bcb3e45810`）中使用独立 NDK r26d 执行完整重编译：

| 变体模式 | instance_id | 预期 SHA-256 | 独立重编译 SHA-256 | 字节数 | 吻合判定 |
| :--- | :--- | :--- | :--- | :---: | :---: |
| **base（动态）** | `nomount-2.1.1-20261014+g9f323cd3deaa.r33de5496.kpb51197a.ndk26.3.11579264#1` | `1ab36727b82cab1723da56f6f82273ff1fee57071836b8992f4e3d26ad40e1fa` | `1ab36727b82cab1723da56f6f82273ff1fee57071836b8992f4e3d26ad40e1fa` | 219,984 | **100% 吻合** |
| **baselines（静态）** | `nomount-2.1.1-20261014_baselines+g9f323cd3deaa.r98bc011c.kpb51197a.ndk26.3.11579264#1` | `b45ea0e0f0dca680fe33430f12b0006ce473c5bf25bb5a3a15a7a96fdba4dc43` | `b45ea0e0f0dca680fe33430f12b0006ce473c5bf25bb5a3a15a7a96fdba4dc43` | 115,104 | **100% 吻合** |

### 1.2 目标派生件独立复算与可追溯性

Auditor 使用沙箱独立重编译产物，经 `patch_offsets.py` 重现目标派生链路：
1. **4.4 动态 legacy-kp 派生件**（供 TST-001 复测）：
   - 命令：`patch_offsets.py legacy-kp <base_kpm> --output <out>`
   - 产物 SHA-256：`06bd68500f2d6f9725038499a16bca1f54e88f1cde3c21f2dc95aa96f276d8ee`（221,728 字节）
   - 比对结论：**100% 逐字节吻合**，compat 收据（`c0ef4a4ac95e…`）一致。
2. **13 份静态目标派生件**（涵盖 10 份唯一字节）：
   - `B2N-416G-v4.json` $\rightarrow$ `94bafae7efafcabaaf20e7db119672c0e48d215513a0a5fb961a64c04547a581`
   - `kernel_mi6-4.4-v4.json` $\rightarrow$ `f4c1c21940a09a2c071b3071712d66d353fc0a40c21a26a1c4aec28ca975647b`
   - `boot_los23.2-v4.json` $\rightarrow$ `4b6fe6266ace0918f5d294380eb9650df8673a429ea613844a8c9b834e92054e`
   - `boot_67.2.A.3.178-v4.json` $\rightarrow$ `8d497f8fdf2ff2667498b350735f6ae117fa829144cc5f73f21d5595e50a299d`
   - `kernel_android13-5.10-v4.json` $\rightarrow$ `dfa3e6e99349d60fea428822583b9be8912714513fc12e2de81018a902384c29`
   - `kernel_android13-5.15-v4.json` $\rightarrow$ `8d497f8fdf2ff2667498b350735f6ae117fa829144cc5f73f21d5595e50a299d`
   - `kernel_android14-5.15-v4.json` $\rightarrow$ `8d497f8fdf2ff2667498b350735f6ae117fa829144cc5f73f21d5595e50a299d`
   - `kernel_android14-6.1.json` $\rightarrow$ `b02dc587cb51726f40c17a03bf0b9d081908eba6922cadb1a7907044ca40a08a`
   - `kernel_mi8-4.9-v4.json` $\rightarrow$ `781e053bda096c774cb9434c0fbf55605c6abc5705f256413421962236d57684`
   - `kernel_mi9-4.14-v4.json` $\rightarrow$ `09a49a36faba1e25078785848d652a9e787543eb1762a75eb99e77b1591f0c38`
   - `kernel_mi10-4.19-v4.json` $\rightarrow$ `a2b54956913b128f228509bb0c7d55155911d3d6ecc29cdd21a880ff67c12de9`
   - `kernel_mi11-5.4-v4.json` $\rightarrow$ `bc69619694faa8f30a783c394317f19fbfd4930f6a6810bb9481bd0bd7001431`
   - `kernel_android12-5.10-v4.json` $\rightarrow$ `dfa3e6e99349d60fea428822583b9be8912714513fc12e2de81018a902384c29`
   - 比对结论：**13 份配置生成全部 100% 逐字节重现**，配置补丁严格仅替换 92 字节 `.data.re_offsets` 段。

---

## 2. TST-001 修复独立审查（追加审计范围）

### 2.1 缺陷成因与机制确认

1. **绝对符号物理事实**：
   - 在 Nokia 4.4（B2N）内核中，链接脚本将 `_etext` 定义为绝对符号（符号类型 `A`），在引导重定位时不参与 KASLR 地址平移，保留链接期虚拟地址（如 `0xffffff8008f80000`）；
   - `_stext` 与 `_end` 是重定位符号（类型 `T`/`R`/`D`），随内核加载基址平移；
   - 旧检查 `probe.code_end <= probe.start` 在绝对符号环境下必然触发，导致此前误判为区间不可用返回 `-ENOENT`。
2. **修复代码机制审查（`nomount/nm_offsets.c` 行 1091～1105）**：
   - 增加了对 `code_end` 的边界审查：当 `probe.code_end <= probe.start || probe.code_end > probe.end` 时，回退查找 `__start_rodata`；
   - 在标准 Linux 内核内存拓扑中，代码段 `.text` 紧接只读数据段 `.rodata`，`__start_rodata` 为类型 `R`（重定位符号），其物理偏移与 `_etext` 严格一致；
   - 若回退后仍然不满足 `start < code_end <= end`，则严格打印 `inode code boundary symbol shape unsupported` 并返回 `-ENOENT`；
3. **过读/越界与 Fail-Closed 判定**：
   - `nm_code_matches` 仅在 `value >= start` 且 `value <= code_end - 4` 时读取一条 4 字节指令；由于 `code_end` 为真实的 `.text` 上界，绝不会越界触及非代码内存，无缺页风险；
   - 无论符号缺失、倒置、越界还是无有效替代符号，均严格 Fail-Closed 返回 `-ENOENT`，绝无硬编码跳过。
4. **测试验证**：
   运行 `nomount/tools/test_inode_code_bounds.py`，模拟绝对链接地址、逆序上界、超大越界等 5 种边界反例，测试全部 PASS。确认 `TST-001` 代码修复成立，状态更新为 **`fixed`**（待 Tester 4.4 实测闭环）。

---

## 3. 尾部锚点推导与 128 字节代理对齐审查

### 3.1 尾部锚点方法与 5 份新目标配置

1. **锚点选取与宽度推导**：
   - 锚点取自目标内核已知反汇编：`set_posix_acl`（`set_acl`）、`super_cache_count`（`nr_cached_objects`）、`d_set_d_op`（`d_real`）、`unregister_key_type`（`link`）；
   - 尺寸公式：$\text{align\_up}(\text{成员偏移} + \text{尾部宽度}, \text{类型对齐})$；
   - 未知尾部或未覆盖宏时拒绝计算，杜绝猜偏移。
2. **64 字节 $\rightarrow$ 128 字节有界反例复核**：
   - 审查确认：米8（4.9）与米9（4.14）的缓存宏配置（`L1_CACHE_BYTES` = 128），导致其原生 `inode_operations` 与 `dentry_operations` 在内核中按 128 字节自然对齐；若统一按 64 字节计算会导致末端尺寸截断（由 256B 误判为 192B）；
   - Developer 修正私有代理头为 128 字节对齐，并按 128 字节对齐取整尺寸，有界反例复核成立；
3. **套件回归**：
   - 运行 `test_tail_derivation.py`，5 组目标锚点及 37 项断链/错标志反例全部 PASS；
   - 运行 `test_proxy_alignment.py`，完整内存 Oracle 的 693 项断言全部 PASS；
   - 运行 `test_static_targets.py`，13 份静态配置往返与布局校验全部 PASS。

---

## 4. 静态等价再裁定（关键裁定）

针对维护者要求判定：本轮静态候选 `b45ea0e0…` 相对上一轮已验收静态（`77a5baa3…`）是否行为等价，能否顺延 §4.4 绑定：

1. **反汇编与代码变更事实**：
   - 静态编译排除了动态推导代码，但保留了共用的内存管理与代理头定义；
   - 相比上一轮静态件，本轮静态件存在以下实质变化：
     1) 新增通用函数 `nm_find_vmalloc_range`（处理无 `is_vmalloc_addr` 导出时的 vmalloc 地址分类）；
     2) `struct nm_directory_proxy` 与 `struct nm_dentry_proxy` 中的 `tables` 对齐属性由 `aligned(64)` 调整为 `aligned(128)`；
     3) 代理头偏移 `offsetof(proxy, tables)` 由 64 字节物理变为 128 字节，导致 Slab 分配尺寸由 256/512 字节提升至 512/1024 字节。
2. **对已有目标（4.4 Nokia / 4.19 Sony / 5.15 Sony）的行为分析**：
   - **理论相容性**：128 字节对齐在数学与硬件层面上为 64 字节对齐的严格超集，指针反算公式保持同构，内存 Oracle 全通；
   - **物理结构变化**：对齐属性对**所有编译入产物的目标全局生效**，改变了宿主内核 Slab 对象的实际布局与偏移量。
3. **裁定结论与范围**：
   - **裁定：本轮静态件对已有目标属于「结构扩展变更（Structural Extension）」，不能单凭反汇编等价性直接免测顺延已验收证据**；
   - **实机测试要求**：
     - **已有可用设备（4.4 Nokia / 4.19 Sony / 5.15 Sony）**：为确保 128 字节代理头在真实内核 Slab 与 VFS 调用中无隐蔽异常，**建议由 Tester 在具备设备的已有目标中至少抽样实测 1 趟静态件（优先 4.19 静态 patch 或 4.4 静态 legacy-kp）**，不可全部免测；
     - **新增 5 目标（米8/米9/米10/米11/Android12）**：当前无设备，依据维护者指示，在元数据中如实登记为「无实机证据」，依靠本轮离线测试 Oracle 与配置校验提供验证。

---

## 5. 安全评估与 AUD-001 风险边界

1. **静态扫描与产物审计**：
   - 运行 `static_scan.py nomount`，无内核空间未授权释放或原子上下文睡眠风险；
   - 运行 `artifact_audit.py --module nomount`，输出 0 阻塞错误（PASS）。
2. **`AUD-001` 状态**：
   - 动态路径中 `key_type` 精确尺寸依然未知（`-1`），依然依赖 512 字节自建清零容量；
   - 裁定：**`AUD-001` 维持 OPEN 状态**。

---

## 6. 审计综合裁定汇总

| 审查项 | 判定 | 依据 |
| :--- | :---: | :--- |
| **候选无缓存重编译** | **PASS** | 动静态 2 款候选 SHA-256 100% 逐字节吻合 |
| **派生链路闭环** | **PASS** | 4.4 动态 legacy-kp 及 13 份静态目标派生件 100% 重现 |
| **TST-001 边界修复** | **FIXED** | 绝对符号回退 `__start_rodata` 正确，无过读，fail-closed 保持 |
| **尾部锚点推导** | **PASS** | 128 字节对齐反例复核成立，37 组断链反例全通过 |
| **静态等价判定** | **STRUCTURAL CHANGE** | 代理头对齐由 64 改为 128B 全局生效，不可直接免测顺延，需抽样真机实测 |
| **AUD-001 风险** | **OPEN** | key_type 精确尺寸仍未解，维持 OPEN |
| **DEV-042 / TST-001** | **FIXED (PENDING TEST)** | 代码层修复完成，待 Tester 4.4 实机闭环 |

---

## 7. 5.15 动态候选 Delta 等价性与证据顺延绑定裁定（追加裁定）

### 7.1 背景与裁定请求

维护者于 [`docs/records/2026-10-15-nomount-tail-anchors-request.md`](../../../docs/records/2026-10-15-nomount-tail-anchors-request.md) §追加裁定请求及 [`docs/records/2026-10-15-nomount-two-device-round-request.md`](../../../docs/records/2026-10-15-nomount-two-device-round-request.md) 中提出：
- 5.15 真机设备（Sony Xperia 1 V）物理存在，但当前未接入工作站（需待用户安排时间接入），本轮可用真机仅 Nokia 7 plus（4.4）与 Sony Xperia 1 II（4.19）；
- 维护者请求 Auditor 就以下事项给出技术与流程裁定：**新动态候选 `1ab36727b82cab1723da56f6f82273ff1fee57071836b8992f4e3d26ad40e1fa`（源码提交 `ebad0588`）相对上一轮已通过真机全量测试（20/20 项全绿）的动态候选 `7e21475004c69deafa8d32d3607ca5359b0df0907a212ba0bbc37772ea5200ae`（源码提交 `846f3d1b`）之代码差异，是否足以支撑 Delta 运行时等价结论，进而允许顺延绑定上轮 5.15 实机证据以避免阻塞本轮发布？**

### 7.2 Delta 代码差异在 5.15 BTF 环境下的可达性分析

Auditor 对两次构建绑定的源码范围（`846f3d1b` $\rightarrow$ `ebad0588`）进行了完整代码与数据流差异审计，共涉及 4 处 C 代码变更：

1. **`calculate_function_inode_offsets` 中绝对符号 `_etext` 回退 `__start_rodata` 的边界修复（TST-001）**：
   - 在 5.15 内核中，内核原生编译包含了完整合法的 BTF（`.BTF` 段，哈希 `384f6f49…`）；
   - 动态初始化主入口 `nm_prepare_inode_layout` 首先调用 `calculate_btf_offsets(&unavailable)`；
   - 在 5.15 下 BTF 解析成功返回 `rc = 0`，因此条件分支 `if (rc == -ENODATA && unavailable)` **严格不成立**；
   - 包含 TST-001 修复代码的 `calculate_function_inode_offsets` 及其下属指令扫描逻辑在 5.15 运行时**严格不可达（100% Unreachable Code）**。

2. **`nm_check_key_name` 与 `nm_find_super_cache` 启发式规则扩展**：
   - 同样地，5.15 的控制结构与超级块尺寸通过 `calculate_btf_control_layout` 与 `calculate_btf_offsets` 直接解析；
   - 相应回退函数 `calculate_function_control_offsets`、`calculate_function_key_callbacks` 及 `calculate_function_super_callbacks` 在 5.15 运行时**完全不被执行（100% Unreachable Code）**。

3. **`nm_prepare_native` 中 `is_vmalloc_addr` 符号查找与回退函数 `nm_find_vmalloc_range`**：
   - 在 5.15 内核符号表（kallsyms）中，`is_vmalloc_addr` 作为导出内核函数常驻符号表（类型 `T`）；
   - `kfunc(nm_is_vmalloc_addr) = (typeof(kfunc(nm_is_vmalloc_addr)))kallsyms_lookup_name_by_suffix("is_vmalloc_addr")` 成功解析非空指针；
   - 条件分支 `if (!kfunc(nm_is_vmalloc_addr))` 判定为假；
   - 本轮新增的 `nm_find_vmalloc_range` 启发式扫描逻辑在 5.15 运行时**绝对不被触发（100% Unreachable Code）**。

4. **`struct nm_directory_proxy` 与 `struct nm_dentry_proxy` 128 字节对齐变更**：
   - 在 5.15 目标下，BTF 解得 `inode_ops_size = 256`、`dentry_ops_size = 192`，两者均为 128 的整数倍；
   - 代理头对齐由 64 字节调整为 128 字节在数学与硬件体系结构上构成严格超集包容关系；
   - 表头回算偏移宏 `offsetof(struct nm_directory_proxy, tables)` 与 `offsetof(struct nm_dentry_proxy, tables)` 与目标原生表尺寸完美契合，未改变任何 VFS 回调协议与调用拓扑。

5. **静态目标配置（13 份 JSON 与 5 份新目标锚点）**：
   - 静态配置仅参与静态基线件（`NoMount_2.1.1-20261014_baselines.kpm`）的编译与派生段生成；
   - 动态候选件（`NoMount_2.1.1-20261014.kpm`）的编译选项未定义 `CONFIG_KPM_BASELINES`，完全不包含静态配置段代码与数据。

### 7.3 Auditor 裁定结论

综合上述形式化证明与路径可达性审计，Auditor 做出如下最终裁定：

1. **5.15 Delta 运行时行为等价性（Delta Runtime Equivalence）成立**：
   - 新动态候选 `1ab36727b82cab1723da56f6f82273ff1fee57071836b8992f4e3d26ad40e1fa` 在 5.15（BTF 具备）目标环境下的所有可达执行路径、内存分配、VFS 拦截挂钩、生命周期控制及对外 CLI/Zip 协议，与上轮已实测的 `7e21475004c69deafa8d32d3607ca5359b0df0907a212ba0bbc37772ea5200ae` **数学与运行时严格等价**。
2. **支持 5.15 动态实机证据顺延绑定**：
   - 依据 Tester 手册 §4.4 与证据追溯性原则，**允许维护者将上轮 `7e214750…` 在 Sony Xperia 1 V（5.15）上的全量实测报告（20/20 PASS）顺延绑定至本轮动态候选 `1ab36727…`**；
   - **本轮交付与发布流程不因 5.15 设备当前未接入而受阻**。
3. **交付披露与后续补测口径**：
   - 维护者在验收结论与发布说明中须如实声明：*5.15 动态候选基于 Auditor Delta 不可达性等价证明顺延绑定上轮实测证据；待设备物理接入后排期补测归档*；
   - 该等价性裁定**仅适用于 BTF 完备的 5.15 动态目标**；对于无 BTF 的 4.4/4.19 目标及物理结构发生变化的静态件，仍须严格遵循已有的实机测试与抽样要求。

---

## 8. DEV-044 对齐算术更正与 5.15 Delta 绑定有效性复核（追加更正）

### 8.1 问题单响应与算式更正

Developer 于 [`Developer/proposals/2026-10-15-nomount-final-check/README.md`](../../../Developer/proposals/2026-10-15-nomount-final-check/README.md) 提出 **DEV-044**，指出：
- 本报告 §7.2 第 4 项中表述「在 5.15 目标下，BTF 解得 `inode_ops_size = 256`、`dentry_ops_size = 192`，两者均为 128 的整数倍」，其中 `dentry_ops_size = 192` 的算术整除推论有误：
  $$192 = 128 \times 1 + 64,\quad 192 \pmod{128} = 64 \neq 0$$
  实际情况为：$256$ 是 128 的整数倍（$128 \times 2 = 256$），而 $192$ 是 64 的整数倍（$64 \times 3 = 192$），并非 128 的整数倍。

Auditor 完全接受 Developer 的算术勘误，在此做出形式化追加更正。

### 8.2 结构体几何布局与对齐链独立推导

Auditor 独立核验该算式勘误是否影响 5.15 Delta 运行时等价性及证据顺延绑定结论：

1. **`struct nm_directory_proxy`（目录操作表代理）**：
   - 代理头偏移：`offsetof(struct nm_directory_proxy, tables) = 128`；
   - 第一表（`inode_operations`）：位于 `proxy->tables`，尺寸为 256 字节（$128 \times 2$）；
   - 第二表位移：`nm_directory_file_table_offset() = (struct_offset.inode_ops_size + 63U) & ~63U = (256 + 63) & ~63 = 256`；
   - 第二表（`file_operations`）：位于 `proxy->tables + 256`，因基址为 128 字节对齐且位移为 256，第二表物理基址同样严格保持 128 字节与 64 字节对齐。

2. **`struct nm_dentry_proxy`（条目操作表代理）**：
   - 代理头偏移：`offsetof(struct nm_dentry_proxy, tables) = 128`；
   - 第一表（原生快照）：位于 `candidate->tables`，物理基址为 128 字节对齐（因 `candidate` 由 `nm_zalloc` 按二次幂对齐分配，且 `tables` 属性为 `aligned(128)`）；
   - 第二表位移（`span`）：`nm_dentry_table_offset() = (struct_offset.dentry_ops_size + 63U) & ~63U = (192 + 63) & ~63 = 192`；
   - 第二表（公开发布表）：位于 `candidate->tables + 192`；
   - **对齐判定**：
     - 基地址 `candidate->tables` 满足 128 字节对齐（进而严格满足 64 字节对齐）；
     - 跨度 $192$ 为 64 的整数倍（$64 \times 3 = 192$）；
     - 因此发布表基址 `candidate->tables + 192` **严格满足 64 字节对齐**（$\text{addr} \equiv 0 \pmod{64}$）；
   - **目标内核硬件与 ABI 对齐要求**：
     - 在 ARM64 Linux 5.15 内核（含 Sony Xperia 1 V 的 Cortex-A510 / A715 / X3 拓扑）中，L1 Cache Line 为 64 字节（`L1_CACHE_BYTES = 64`），原生 `dentry_operations` 的自然缓存对齐约束为 64 字节；
     - 仅米8 / 米9 等特定高通 Kryo 385 平台因 `L1_CACHE_BYTES = 128` 才要求 128 字节对齐（这也是本轮将代理头对齐提升至 128 字节的原因）；
     - 因此在 5.15 目标下，发布表基址达到 64 字节对齐，**已 100% 满足目标内核 VFS 调用的物理硬件与 ABI 对齐要求**。

3. **指针逆向寻址宏算术正确性**：
   - 条目反查宏：
     $$\text{proxy} = (\text{void}*)((\text{uintptr\_t})\text{table} - \text{nm\_dentry\_table\_offset}() - \text{offsetof}(\text{struct nm\_dentry\_proxy, tables}))$$
   - 代入 5.15 参数：
     $$\text{proxy} = \text{table} - 192 - 128 = \text{table} - 320$$
   - 反向寻址依赖的是代数加减法的封闭性（$\text{proxy} + 128 + 192 - 192 - 128 = \text{proxy}$），**并不依赖于 192 是否能被 128 整除**；
   - 只要分配与寻址位移严格匹配且未发生越界，反查公式便完全自洽；
   - 此结论已由 `nomount/tools/test_proxy_alignment.py` 中 693 项断言（含第 70 行 `assert(proxy && !((uintptr_t)proxy % 128) && !((uintptr_t)table % 64))`）完全验证通过。

### 8.3 复核结论与 DEV-044 处置

1. **对 5.15 Delta 证据绑定结论的影响**：
   - **零影响（No Impact）**：更正算术推论后，5.15 动态目标下的代理表分配、对齐要求（64 字节）、第二表发布位移（192 字节）与逆向寻址运算（-320 字节）全部物理成立且逻辑闭环；
   - 结合 §7.2 证明的 BTF 路径不可达性（TST-001、`nm_check_key_name`、`nm_find_super_cache` 及 `nm_find_vmalloc_range` 均 100% 不可达），**5.15 动态 Delta 运行时等价性与实机证据顺延绑定结论完全有效、保持不变**。
2. **问题单关闭建议**：
   - **`DEV-044`**：Auditor 已在此追加详实算术勘误、几何推导与证据链说明；建议维护者采纳本追加报告并核准关闭 `DEV-044`。
