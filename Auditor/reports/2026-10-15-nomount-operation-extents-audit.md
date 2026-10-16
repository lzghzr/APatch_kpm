# NoMount 操作表尺寸补齐（无 BTF 动态路径）探索构建独立审计报告：末端推导、几何推理与支持范围界定

- 角色：Auditor（独立审计）
- 模块：`nomount`（内嵌注册名 `NoMount`）
- 审计对象：`nomount` 操作表尺寸补齐探索版本（包含动态件、静态基准件与 4.4 动态 legacy-kp 派生件）
- 源码冻结提交：`b4cf78daff053dea0b5ca987b33782f6bbfda552`
- 依据任务与请求：[`docs/records/2026-10-15-nomount-operation-extents-request.md`](../../docs/records/2026-10-15-nomount-operation-extents-request.md)
- 审计工具链：LLVM / Clang 17.0.2 (NDK r26d / `26.3.11579264`)，Python 3.11
- 平台符号快照：[`Auditor/snapshots/kp_runtime_symbols-b51197aaba8f.json`](../snapshots/kp_runtime_symbols-b51197aaba8f.json)（KernelPatch `b51197a`）
- 审计结论：**通过（PASS）—— 三类操作表末端推导数学与几何逻辑成立，前缀与指令边界安全无过读；AUD-001 风险收窄（维持 open）；同意移交 Tester 开展三趟定向实测**

---

## 1. 探索构建身份、沙箱重编译与 4.4 派生件验证

### 1.1 构建实例绑定
本轮 Developer 提交 2 款探索构建件及 1 款 4.4 动态兼容派生件，已由维护者导入 `metadata/modules/nomount.json`（exploration 档）：

| 形态 | 实例 ID / 派生路径 | 产物文件名 | 产物 SHA-256 | 偏移模式 | 状态 |
| --- | --- | --- | --- | --- | --- |
| 动态件 | `nomount-2.1.1-20261014+g4b49827eb674.ra2d2c48f.kpb51197a.ndk26.3.11579264#1` | `NoMount_2.1.1-20261014.kpm` | `1db32ea9a394164a6d3fde01d94875c516eafff953a30bd9ced6ea1c8b7e66ea` | dynamic | **PASS** |
| 静态件 | `nomount-2.1.1-20261014_baselines+g4b49827eb674.rdaba8f18.kpb51197a.ndk26.3.11579264#1` | `NoMount_2.1.1-20261014_baselines.kpm` | `77a5baa38d3072c4fb63da4cb70b286d83d93cf06fa06179b8c4125f9c2bc15a` | static | **PASS** |
| 4.4 动态派生件 | `artifacts/binary-port/nomount/d9d7d29785961e15f7db03bf1cc589ef48b0a5ecdf3afe621b9545958949ddc6/` | `NoMount_2.1.1-20261014.kpm` | `d9d7d29785961e15f7db03bf1cc589ef48b0a5ecdf3afe621b9545958949ddc6` | legacy-kp | **PASS** |

*注：静态件 SHA-256 与上一探索轮完全相同，确认新增的无 BTF 操作表尺寸推导代码被 `#ifndef CONFIG_KPM_BASELINES` 隔离，未污染静态基准件。*

### 1.2 独立沙箱无缓存重编译验证
Auditor 在独立沙箱 `local/auditor-scratch/nomount-extents-20261015/worktree`（检出提交 `b4cf78da` 且包含完整子模块）中，使用 NDK r26d 执行独立构建与派生：
```bash
ANDROID_NDK=/path/to/ndk/26.3.11579264 make -C nomount all
python3 patch_offsets.py legacy-kp nomount/NoMount_2.1.1-20261014.kpm --output NoMount_2.1.1-20261014_legacy.kpm
```
实测重编译与重派生产物 SHA-256 如下：
- `NoMount_2.1.1-20261014.kpm`: `1db32ea9a394164a6d3fde01d94875c516eafff953a30bd9ced6ea1c8b7e66ea`（100% 逐字节吻合）
- `NoMount_2.1.1-20261014_baselines.kpm`: `77a5baa38d3072c4fb63da4cb70b286d83d93cf06fa06179b8c4125f9c2bc15a`（100% 逐字节吻合）
- `NoMount_2.1.1-20261014_legacy.kpm`: `d9d7d29785961e15f7db03bf1cc589ef48b0a5ecdf3afe621b9545958949ddc6`（100% 逐字节吻合）

### 1.3 4.4 派生件可追溯性与契约核验
Auditor 逐项核对了派生件及同目录收据 `NoMount_2.1.1-20261014.kpm.compat.json`：
1. **基础实例与父哈希**：严格绑定 `base_instance_id` `nomount-2.1.1-20261014+g4b49827eb674.ra2d2c48f.kpb51197a.ndk26.3.11579264#1` 与 `parent_sha256` `1db32ea9...`；
2. **工具链一致性**：所用工具 `patch_offsets.py` SHA-256 为 `97a51b293af447b3cd6608c953cec95cdfc62f985346463f2285b28ab3c86033`，命令行为标准 `legacy-kp` 字节变换；
3. **源码整洁度**：审查 `nomount/Makefile` 及 C 源码，确认未引入任何针对 4.4 的代码分支或兼容宏，低版本兼容完全在二进制层闭环。

---

## 2. 末端成员推导成立性与几何推理复算

本轮 Developer 核心变更在于：在无 BTF 时，通过目标内核导出的末端函数反汇编及静态表前缀，定位末端成员并结合声明尾部片段计算操作表尺寸。Auditor 独立复核其数学与几何严密性：

### 2.1 尾部几何片段独立计算
在 64 位 ARM64 自然对齐下，Auditor 实测编译核算各尾部片段的 `sizeof` 与内部关键成员 `offsetof`：
- `struct nm_inode_acl_tail`: `size = 88`, `offsetof(set_acl) = 48`
- `struct nm_inode_xattr_acl_tail`: `size = 80`, `offsetof(set_acl) = 72`
- `struct nm_super_context_tail`: `size = 240`, `offsetof(reporting.cache) = 192`
- `struct nm_super_mount_tail`: `size = 200`, `offsetof(reporting.cache) = 184`
- `struct nm_dentry_canonical_tail`: `size = 88`, `offsetof(canonical_path) = 56`
- `struct nm_dentry_select_tail`: `size = 72`, `offsetof(canonical_path) = 64`

### 2.2 目标尺寸几何推理复算
在 `nm_set_operation_extents` 中，通过比对提取的末端偏移与已知锚点偏移的相对距离，严格分支匹配两套几何契约：

#### Case 1：Sony 4.19 内核几何契约
1. **`inode_operations`**：
   - 提取锚点 `iop_getattr = 112`，末端 `last_acl = 160`；
   - 几何校验：`last_acl - iop_getattr = 160 - 112 = 48`，恰好等于 `offsetof(nm_inode_acl_tail, set_acl)`；
   - 尺寸计算：`nm_tail_extent(112, 88, 64) = (112 + 88 + 63) & ~63 = 256` 字节。
2. **`super_operations`**：
   - 提取锚点 `sop_drop_inode = 40`，末端 `last_cache = 232`；
   - 几何校验：`last_cache - sop_drop_inode = 232 - 40 = 192`，恰好等于 `offsetof(nm_super_context_tail, reporting.cache)`；
   - 尺寸计算：`nm_tail_extent(40, 240, 8) = (40 + 240 + 7) & ~7 = 280` 字节。
3. **`dentry_operations`**：
   - 提取锚点 `dop_release = 48`（`dop_init = 40` 在场），末端 `last_canonical = 104`；
   - 几何校验：`last_canonical - dop_release = 104 - 48 = 56`，恰好等于 `offsetof(nm_dentry_canonical_tail, canonical_path)`；
   - 尺寸计算：`nm_tail_extent(48, 88, 64) = (48 + 88 + 63) & ~63 = 192` 字节。
- **复算结果**：`inode=256, super=280, dentry=192`，与 Sony 4.19 参考事实完全一致。

#### Case 2：Nokia B2N 4.4 内核几何契约
1. **`inode_operations`**：
   - 提取锚点 `iop_getattr = 144`，末端 `last_acl = 216`；
   - 几何校验：`last_acl - iop_getattr = 216 - 144 = 72`，恰好等于 `offsetof(nm_inode_xattr_acl_tail, set_acl)`；
   - 尺寸计算：`nm_tail_extent(144, 80, 64) = (144 + 80 + 63) & ~63 = 256` 字节。
2. **`super_operations`**：
   - 提取锚点 `sop_drop_inode = 32`，末端 `last_cache = 216`；
   - 几何校验：`last_cache - sop_drop_inode = 216 - 32 = 184`，恰好等于 `offsetof(nm_super_mount_tail, reporting.cache)`；
   - 尺寸计算：`nm_tail_extent(32, 200, 8) = (32 + 200 + 7) & ~7 = 232` 字节。
3. **`dentry_operations`**：
   - 提取锚点 `dop_release = 40`（`dop_init = -1` 缺失），末端 `last_canonical = 104`；
   - 几何校验：`last_canonical - dop_release = 104 - 40 = 64`，恰好等于 `offsetof(nm_dentry_select_tail, canonical_path)`；
   - 尺寸计算：`nm_tail_extent(40, 72, 64) = (40 + 72 + 63) & ~63 = 128` 字节。
- **复算结果**：`inode=256, super=232, dentry=128`，与 B2N 4.4 参考事实完全一致。

若任意一项成员距离与已知声明不符，`nm_set_operation_extents` 直接返回 `-EOPNOTSUPP` 拒绝，杜绝几何错误。

---

## 3. 前缀下界与读取边界安全分析（防过读）

1. **`sdcardfs_ci_dops` 探测前缀下界**：
   - `NM_DENTRY_TAIL_PROBE_SIZE = 14 * sizeof(void*) = 112` 字节；
   - 在 4.4 与 4.19 两套声明中，`dentry_operations` 的有效槽数分别为 14（112B）与 17（136B）；
   - `sdcardfs_canonical_path` 在两目标中均位于 slot 13（偏移 104 字节），严格小于 112 字节；
   - 探测循环 `slot < 14` 绝不读取 slot 14（偏移 112 字节及之后）；Auditor 验证了测试夹具在 byte 112 紧邻 `PROT_NONE` 保护页时的执行情况，未触发任何 SIGSEGV。
2. **函数入口指令上限**：
   - `set_posix_acl` 限制在 13 条指令以内（`nm_ret(src[12])` 校验）；
   - `super_cache_count` 限制在 21 条指令以内（`nm_ret(src[20])` 校验）；
   - 避免了解析异常函数时可能引发的指令扫描越界。

---

## 4. 分配上界、原表复制契约与 AUD-001 支持范围界定

### 4.1 分配上界与原表复制契约
- 在补齐三项尺寸后，`nm_prepare_operation_sizes()` 中的循环检查全部通过；
- 真实原表复制点（如 `nm_inode.c` 中的 `super_ops_size`、`nm_directory.c` 中的 `dentry_ops_size` 和 `inode_ops_size`）均使用推导出的精确尺寸进行分配、克隆与比较；
- 512 字节容量不再用于上述三类操作表。

### 4.2 AUD-001 风险定级与支持范围界定
针对维护者关于 `AUD-001`（厂商扩展越界）在本轮的状态与支持范围的提问：
1. **风险范围显著收窄**：
   - 上一轮中 `inode`、`super`、`dentry`、`key_type` 四类表均面临容量与尺寸不确定性；
   - 本轮中 `inode`、`super`、`dentry` 三类表已通过末端成员反汇编与几何校验确立了精确尺寸与边界，若厂商定制修改了相对几何直接返回 `-EOPNOTSUPP`；
   - 唯独 `struct key_type` 在无 BTF 下精确尺寸依然未知（保持 `-1`），继续使用 512 字节清零容量分配。
2. **问题单状态：维持 OPEN**：
   - 依据所有权规则，`AUD-001` 本轮**维持 OPEN 状态**。在未取得 `key_type` 精确尺寸或确立白名单之前，不予关闭；
3. **本轮支持范围（Supported Boundaries）**：
   - **严格限定于**：符合 Case 1（Sony 4.19 几何契约，如 Sony Xperia 1 II）与 Case 2（Nokia 4.4 几何契约，如 Nokia 7 plus）两套参考声明的内核；
   - **不支持声明**：任何具有非标准成员重排、移除了 QUOTA 槽、或追加了不可观测尾部字段的未知厂商定制内核，均不在本轮支持范围内（会被 `-EOPNOTSUPP` fail-closed 拦截）。

---

## 5. 静态扫描与产物独立审计

- **边界与安全静态扫描（`Auditor/tools/static_scan.py`）**：
  - 数据文件：[`Auditor/reports/data/2026-10-15-nomount-operation-extents-static-scan.json`](data/2026-10-15-nomount-operation-extents-static-scan.json)
  - 扫描结果：PASS。无并发原子性破坏或越界读写风险。
- **产物独立审计（`Auditor/tools/artifact_audit.py`）**：
  - 数据文件：[`Auditor/reports/data/2026-10-15-nomount-operation-extents-artifact-audit.json`](data/2026-10-15-nomount-operation-extents-artifact-audit.json)
  - 结果：PASS（0 个 error）。未定义符号全部在平台快照及 kallsyms 规范中闭环。

---

## 6. 移交 Tester 三趟测试建议（探索阶段）

本轮是决定探索件"能否升为候选"的关键实测证据：

| 趟次 | 待测目标 | 待测产物 | 重点验证项 |
| --- | --- | --- | --- |
| **①** | **4.19**（Sony Xperia 1 II，无 BTF） | 动态件 `1db32ea9...` | 验证尺寸补齐后能否顺利越过 `-ENOENT` 完成加载与注册；按 §4.2 跑通 Enforcing 下用户主路径（标签继承、真实消费者读取/映射，无 `EACCES`） |
| **②** | **4.4**（Nokia 7 plus，旧 KP） | 动态 legacy-kp 派生件 `d9d7d297...` | 验证旧 KP 符号变换后的动态件能否在 4.4 上加载并跑通主路径 |
| **③** | **5.15**（Sony Xperia 1 V，有 BTF） | 动态件 `1db32ea9...` | 回归验证：确认有 BTF 时不触发函数推导分支，既有 46 项查询功能完好 |

*规程要求：每趟独立嵌入 + 重启（严格遵守 RA-002 禁止卸载/动态重载）；遇卡死立即停止走设备升级流程。*

---

## 7. 最终审计意见与移交

1. **构建与派生**：2 款探索 KPM 与 1 款 4.4 派生件 100% 独立重现并吻合；
2. **末端几何成立**：推导与对齐逻辑严谨，Sony（256/280/192）与 B2N（256/232/128）复算完全闭环；
3. **支持范围明确**：AUD-001 风险收窄但维持 OPEN，支持范围限定于两套已核验几何；
4. **同意移交**：同意 Tester 开展 4.19 动态、4.4 动态派生件及 5.15 回归三趟实测。
