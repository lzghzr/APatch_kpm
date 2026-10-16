# NoMount 操作表尺寸补齐探索独立审计结论与元数据入库提案

依据维护者轮次请求 [`docs/records/2026-10-15-nomount-operation-extents-request.md`](../../../docs/records/2026-10-15-nomount-operation-extents-request.md)。

Auditor 已完成 NoMount 操作表尺寸补齐探索版本（源码冻结 `b4cf78da`）的独立无缓存重编译、4.4 legacy-kp 派生件追溯核验、操作表末端几何数学证明、探针读取边界与防过读安全性审计、AUD-001 风险边界判定，以及测试套件复核工作：

1. **探索构建无缓存重编译与 4.4 派生件可追溯性**：
   - 2 款探索变体（Dynamic 与 Static Baselines）在独立沙箱下使用 NDK r26d 重编译，SHA-256 100% 逐字节吻合；
   - 4.4 动态派生件（`d9d7d2978596…`）经 `patch_offsets.py legacy-kp` 独立变换复现，输入哈希、工具哈希与 receipt 完全闭合；源码与 Makefile 保持最新 KP 契约，未引入任何旧版本兼容分支；
2. **末端成员推导与几何数学证明**：
   - 独立从 Linux 源码树推导末端成员尾部片段与完整类型自然对齐：
     - Sony 4.19（Case 1）：`inode_ops_size` = 256 字节、`super_ops_size` = 280 字节、`dentry_ops_size` = 192 字节；
     - Nokia B2N 4.4（Case 2）：`inode_ops_size` = 256 字节、`super_ops_size` = 232 字节、`dentry_ops_size` = 128 字节；
   - 经测试工具 `nomount/tools/test_operation_extents.py` 在 `boot_los23.2.img` 与 `B2N-416G_boot.img` 上均通过，计算结果与内核静态/动态事实完全一致；
3. **前缀下界与读取边界安全（防过读）**：
   - `dentry_operations` 在未探测前缀长度前，仅读取所有候选声明共有的 112 字节（14 个指针）最小前缀；经保护页（Guard Page）隔离测试，确认绝不越界触发缺页异常；
   - `set_posix_acl` 指令窗口严格限制为 13 条 ARM64 指令且在 `ret` 处提前终止；`super_cache_count` 指令窗口严格限制为 21 条 ARM64 指令且在 `ret` 处提前终止，无越界读取只读代码段风险；
4. **AUD-001 风险范围判定与本轮支持边界**：
   - `inode_operations`、`super_operations`、`dentry_operations` 三类原表不再依赖 512 字节估计容量，尺寸未知直接拒绝；
   - `key_type` 精确尺寸在无 BTF 目标下仍未知（`-1`），继续沿用 512 字节清零自建容量；
   - **判定结论**：`AUD-001`（厂商扩展操作表越界破坏内核）风险范围由 4 类操作表**收窄至仅针对 `key_type`**；**`AUD-001` 维持 OPEN 状态**；
   - **本轮支持边界**：严格限定为声明结构与相对位移完全符合 **Case 1（Sony 4.19 / 5.4 风格）** 与 **Case 2（Nokia B2N 4.4 风格）** 的已知内核几何，不支持任意未知厂商私有扩展内核；
5. **同意移交 Tester 开展三趟探索实测**：
   - 明确本轮构建仍为探索性质（`kind: exploration`），非正式交付轮；
   - 同意 Tester 依据计划开展三趟真机测试：
     - ① **4.19（Sony LOS 23.2）**：动态件 `1db32ea9a394…`，验证尺寸补齐后越过 `-ENOENT` 成功加载并跑通挂载拦截；
     - ② **4.4（Nokia B2N）**：动态派生件 `d9d7d2978596…`，验证 legacy-kp 符号兼容并跑通挂载拦截；
     - ③ **5.15（Pixel 7）**：动态件 `1db32ea9a394…`，验证 BTF 原生路径不受尺寸推导影响且功能完全正常。

完整审计报告见 [`Auditor/reports/2026-10-15-nomount-operation-extents-audit.md`](../../reports/2026-10-15-nomount-operation-extents-audit.md)。

---

## 提案清单

本目录提供结构化数据文件，供维护者在核对 Auditor 检查点提交后，同步合入 `metadata/modules/nomount.json`：

1. [report_versions.json](report_versions.json): 包含 3 份报告与数据文件的首次入库基线与版本记录：
   - `Auditor/reports/2026-10-15-nomount-operation-extents-audit.md`: `b1fde3312db045b59260b11b1b0038488a8a9daf0f5bc6347d584ff026ef8fa5` (12,199 字节)
   - `Auditor/reports/data/2026-10-15-nomount-operation-extents-artifact-audit.json`: `ff9bbf8c48069da2cb345d72181588de0a024e4292d03ed62db1f8bd2b84ca5a` (355,969 字节)
   - `Auditor/reports/data/2026-10-15-nomount-operation-extents-static-scan.json`: `61aa2629acdf4642ed1bf262e8b807ad77103a40cc56c0d29a77ac30af3a25ce` (9,550 字节)

2. [audits.json](audits.json): 包含 2 个探索构建实例（`base`, `baselines`）的审计记录条目，绑定 `source_commit` `b4cf78daff053dea0b5ca987b33782f6bbfda552` 及对应的产物 SHA-256。

Auditor 严格遵循所有权规则，不直接修改他人拥有的元数据结论或直接提交 `metadata/` 文件。
