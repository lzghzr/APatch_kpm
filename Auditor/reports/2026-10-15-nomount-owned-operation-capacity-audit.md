# NoMount 自建操作表容量（无 BTF 动态路径）探索构建独立审计报告：容量契约、越界最坏情形与降级边界

- 角色：Auditor（独立审计）
- 模块：`nomount`（内嵌注册名 `NoMount`）
- 审计对象：`nomount` 自建操作表容量探索版本（两件均为 `exploration`，尚不是完整测试候选）
- 源码冻结提交：`7e668af2213d78a4e7cbb0c72bc9f5660678403d`
- 依据任务与请求：[`docs/records/2026-10-15-nomount-owned-operation-capacity-request.md`](../../docs/records/2026-10-15-nomount-owned-operation-capacity-request.md)
- 审计工具链：LLVM / Clang 17.0.2 (NDK r26d / `26.3.11579264`)，Python 3.11
- 平台符号快照：[`Auditor/snapshots/kp_runtime_symbols-b51197aaba8f.json`](../snapshots/kp_runtime_symbols-b51197aaba8f.json)（KernelPatch `b51197a`）
- 审计结论：**通过（PASS）—— 容量与复制长度严格分离，无过读风险；降级门控与未完成面严格 Fail-Closed；确认为合格的探索构建，同意 Tester 开展 4.19 诊断与 5.15 回归实测**

---

## 1. 探索构建身份与沙箱无缓存重编译

### 1.1 构建实例绑定
本轮 Developer 提交 2 款探索构建件，已由维护者导入 `metadata/modules/nomount.json`（exploration 档）：

| 模式 | 实例 ID | 产物文件名 | 产物 SHA-256 | 偏移模式 | 状态 |
| --- | --- | --- | --- | --- | --- |
| 动态 | `nomount-2.1.1-20261014+g875b16f95083.r130c2158.kpb51197a.ndk26.3.11579264#1` | `NoMount_2.1.1-20261014.kpm` | `24efeb02dd0b89283aca40f768d59203cada3aaaf3d4fe0811e3b35e7f7c9f63` | dynamic | **PASS** |
| 静态 | `nomount-2.1.1-20261014_baselines+g875b16f95083.r471c373b.kpb51197a.ndk26.3.11579264#1` | `NoMount_2.1.1-20261014_baselines.kpm` | `77a5baa38d3072c4fb63da4cb70b286d83d93cf06fa06179b8c4125f9c2bc15a` | static | **PASS** |

### 1.2 独立沙箱无缓存重编译验证
Auditor 在独立沙箱 `local/auditor-scratch/nomount-capacity-20261015/worktree`（基于提交 `7e668af2` 且完整拉取子模块）中，使用 NDK r26d 执行独立构建：
```bash
ANDROID_NDK=/path/to/ndk/26.3.11579264 make -C nomount all
```
实测重编译产物 SHA-256 如下：
- `NoMount_2.1.1-20261014.kpm`: `24efeb02dd0b89283aca40f768d59203cada3aaaf3d4fe0811e3b35e7f7c9f63`（100% 逐字节吻合）
- `NoMount_2.1.1-20261014_baselines.kpm`: `77a5baa38d3072c4fb63da4cb70b286d83d93cf06fa06179b8c4125f9c2bc15a`（100% 逐字节吻合）
- `NoMount_2.1.1-20261014_baselines.kpm.json`: 表偏移 43176，表大小 92 字节（100% 逐字节吻合）

---

## 2. 核心审计判定：容量契约、越界最坏情形与安全边界

### 2.1 容量契约独立核实
Auditor 逐一校验了 `Developer/reports/data/2026-10-15-nomount-owned-operation-capacity.json` 引用的 8 份原生内核头文件声明，文件哈希 100% 吻合：
1. **`struct inode_operations`**：
   - 4.4（Nokia B2N，`include/linux/fs.h`）：28 个函数指针（224 字节），按 64 字节对齐（`____cacheline_aligned`）上界为 **256 字节**；
   - 4.19（Sony Xperia 1 II，`include/linux/fs.h`）：23 个函数指针 + 4 项 Android KABI 保留槽（共 27 槽，216 字节），64 字节对齐上界为 **256 字节**。
2. **`struct dentry_operations`**：
   - 4.4（Nokia B2N，`include/linux/dcache.h`）：14 个函数指针（112 字节），64 字节对齐上界为 **128 字节**；
   - 4.19（Sony Xperia 1 II，`include/linux/dcache.h`）：13 个函数指针 + 1 项 KABI USE + 3 项 KABI 保留（共 17 槽，136 字节），64 字节对齐上界为 **192 字节**。
3. **`struct key_type`**：
   - 4.4（约 160 字节）、4.19（约 168 字节）、5.15（BTF 确定值为 184 字节）、6.6（约 200 字节）；
   - `lock_class` 预算分析：在关闭 lockdep 的 Android 生产内核上（`mutex_no_lockdep == 1`），`struct lock_class_key` 为空结构体（0 字节）；即便在开启 lockdep 的内核上（`struct hlist_node` 16B + `subclass_key` 8B），32 字节预算亦完全充裕；且 NoMount 本身在 `nm_validate_control_layout` 中明确要求 `mutex_no_lockdep == 1`，遇到 lockdep 开启内核直接返回 `-EOPNOTSUPP` 拒绝加载。
4. **结论**：512 字节（`NM_OWNED_OPERATIONS_CAPACITY = 512`）对于已审查的 4.4～6.6 声明具备充足裕量（均 <= 256 字节，裕量超过 2x）。

### 2.2 厂商内核结构体超出 512B 的最坏情形分析（Worst-Case Analysis）
若某些厂商定制内核在上述结构体中添加了大量私有扩展字段，导致结构体实际 `sizeof > 512` 字节，Auditor 给出的确切行为推演与最坏情形如下：
1. **最坏情形 1：堆越界读取致内核 Panic 或 CFI 违规崩溃（Heap OOB Read）**：
   - 若内核在调用 VFS 虚目录/虚文件操作时，尝试解引用位于偏移 >= 512 字节处的函数指针；
   - 由于 `nm_zalloc(512)` 仅向内核堆申请了 512 字节，访问越界偏移将读取相邻堆块的数据；
   - 若相邻堆块为非法地址或垃圾指针，直接触发指令异常（Instruction Abort / Bad PC / Page Fault Oops）；
   - 在开启 CFI（Control Flow Integrity）的环境（如 4.19 Sony 真实目标）下，间接跳转违规将立即触发 `BRK` 崩溃。
2. **最坏情形 2：堆越界写入致 Slab 内存破坏（Heap Corruption）**：
   - 特别针对 `struct key_type`：内核 `register_key_type` 会在结构体末尾写入内部 `link`（`struct list_head`，16 字节）和 `lock_class`；
   - 若厂商定制导致 `link` 偏移跨越到 >= 512 字节，`register_key_type` 将直接向分配块之后的内存执行链表插入写入，污染相邻 Slab 对象的元数据或业务数据，造成不可预料的系统不稳定甚至安全风险。
3. **Auditor 评估结论**：
   - 512 字节是**特定于已核对声明的经验契约**，正如 Developer 在报告中所申明，**绝不是对任意后续厂商扩展的普遍保证**；
   - 未来若有新厂商内核接入，必须通过目标 BTF 或函数反汇编独立复核该上界。

### 2.3 分配与复制长度分离（防过读审计）
Auditor 逐行复核了 `nm_operations.c`、`nm_inode.c`、`nm_directory.c` 中的所有内存分配与内存复制逻辑：
1. `nm_new_operations(kind, original)`：
   - **`original != NULL`（原生表克隆代理）**：`size` 严格取 `nm_operation_size(kind)`。若该类型的精确尺寸未知（`-1`），函数在分配前直接返回 `ERR_PTR(-EINVAL)`，绝不调用 `nm_zalloc`，更绝不调用 `memcpy`；
   - **`original == NULL`（自建清零表）**：`size` 允许取 `nm_owned_operation_size(kind)`（512 字节），但因 `original == NULL`，`memcpy` 分支直接被条件判断跳过；
2. 真实原表复制点（如 `nm_inode.c` 的 `super_ops_size`、`nm_directory.c` 的 `dentry_ops_size` 和 `inode_ops_size`）全部只读取 `struct_offset` 中的精确尺寸，没有任何一处将 512 字节作为复制源的长度。
3. **结论**：**过读风险完全消除（Zero Over-Read Risk）**。

### 2.4 降级门控严密性核查
审查 `nm_prepare_operation_sizes` 与 `nm_get_btf` 的错误处理逻辑：
- 仅当 `calculate_btf_operation_sizes(&unavailable)` 返回 `rc == -ENODATA` 且 `unavailable == true`（即明确确认 BTF 函数符号缺失或 BTF 对象为 NULL）时，才激活 `nm_owned_operation_fallback = true`；
- 若内核存在 BTF，但在解析某个具体类型尺寸时出错（如类型损坏或缺失），返回 `-ENOENT` 或相应错误，`unavailable` 保持 `false`，门控直接返回错误码，**绝不吞没有效 BTF 错误**；
- 若静态基准版（`CONFIG_KPM_BASELINES`），该降级分支在编译期完全剥离，不被触发。

### 2.5 `key_type_size` 未知不阻塞的安全性
在 `nm_validate_control_layout` 中：
- `key_type_size` 在 BTF 缺失时保持为 `-1`（未被伪造填充）；
- 控制布局校验使用 `key_capacity`（512 字节）检验回调区间：`key_callbacks + sizeof(struct nm_key_callbacks) <= key_capacity`；
- 因 NoMount 仅通过 `nm_new_operations(NM_KEY_TYPE, NULL)` 新建私有 Key 对象，不克隆原生 Key 表，只要分配容量能安全容纳回调头部与注册字段，该放行完全合法，未削弱任何控制面安全检查。

### 2.6 未完成面与 Fail-Closed 保证
核查 `copy_size_gaps`：
- 当前版本无 BTF 时，三类原生复制尺寸（`inode_ops_size`、`super_ops_size`、`dentry_ops_size`）仍无法确定（取值为 `-1`）；
- 在 `nm_prepare_operation_sizes()` 循环中，`NM_INODE_OPS`、`NM_SUPER_OPS`、`NM_DENTRY_OPS` 依然严格调用 `nm_operation_size()` 检查；当遇到 `-1` 时，函数必定直接返回 `-ENOENT` 失败退出；
- **结论**：模块在缺少这三项尺寸时，必定在加载初始化早期 **Fail-Closed 退出**，绝不会进入半初始化运行状态。

---

## 3. 测试套件与 Oracle 纪律复核

1. **46 个已有测试工具未变**：核对 `git diff 7e668af2^..7e668af2 -- nomount/tools/`，确认 46 个既有测试工具文件逐字节完全未改动。
2. **新增测试套件有效性**：
   - `test_operation_capacity.py`：包含 ASan/UBSan、mmap 真实保护页越界防护测试、BTF 门控及控制边界测试，本地运行通过（`PASS: owned capacity, exact-copy guard page...`）；
3. **`test_native.py` 历史夹具状态独立核实**：
   - 审查 `nomount/tools/test_native.py` 源码确认，其在编译前拼接代码时未提供 `nm_zalloc`/`nm_free` 声明，导致在 clang 编译阶段即报错退出，未执行断言；
   - 开发者如实披露该历史状态，未为了迁就该旧单测而修改内核生产架构，亦未篡改已有断言，完全符合 [.agents/skills/respect-the-oracle/SKILL.md](../../.agents/skills/respect-the-oracle/SKILL.md) 纪律。

---

## 4. 静态扫描与产物独立审计

- **边界与安全静态扫描（`Auditor/tools/static_scan.py`）**：
  - 数据文件：[`Auditor/reports/data/2026-10-15-nomount-owned-operation-capacity-static-scan.json`](data/2026-10-15-nomount-owned-operation-capacity-static-scan.json)
  - 扫描无新增阻断性缺陷，未发现原子性破坏或越界读写风险。
- **产物独立审计（`Auditor/tools/artifact_audit.py`）**：
  - 数据文件：[`Auditor/reports/data/2026-10-15-nomount-owned-operation-capacity-artifact-audit.json`](data/2026-10-15-nomount-owned-operation-capacity-artifact-audit.json)
  - 0 个 error；未定义符号在平台快照及 kallsyms 规范中闭环。

---

## 5. 移交 Tester 定向测试建议（非验收轮）

依据维护者请求，本轮为**探索诊断轮**（非验收轮），测试结果用于协助 Developer 定位剩余缺口：
1. **趟 ①：4.19（无 BTF）动态件 `24efeb02dd0b…`（诊断趟）**：
   - 目的：验证 512 字节容量策略与共同原型在无 BTF 下能否推进加载流程（重点观察是否顺利通过 key 分配与控制布局校验，并确认最终是否按预期停留在三类原表复制尺寸缺失的 `-ENOENT` 保护上）；
   - 记录精确返回码与内核 dmesg。
2. **趟 ②：5.15（有 BTF）动态件（回归趟）**：
   - 目的：确认在有 BTF 环境下，容量降级策略未被误触发，BTF 路径与既有 46 项查询逻辑未受任何破坏；
3. **安全红线**：严格遵循 RA-002（独立嵌入 + 重启）；若遇卡死或无响应立即停止并走设备升级流程，严禁反复重试。

---

## 6. 最终审计意见与移交

1. **构建可复现性**：两款探索件在独立沙箱中 100% 逐字节重现；
2. **安全边界成立**：容量与复制长度彻底解耦，无过读漏洞；降级门控与缺失尺寸 Fail-Closed 保证完整；
3. **探索性质确认**：明确记录这是 exploration 构建，不可直接发布；
4. **同意移交**：同意 Tester 开展 4.19 诊断与 5.15 回归实测。
