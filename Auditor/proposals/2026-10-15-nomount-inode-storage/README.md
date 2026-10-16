# NoMount inode storage 修复候选独立审计结论与元数据入库提案

依据维护者轮次请求 [`docs/records/2026-10-15-nomount-inode-storage-request.md`](../../../docs/records/2026-10-15-nomount-inode-storage-request.md)。

Auditor 已完成 NoMount inode storage 修复候选版本（源码冻结 `846f3d1b`）的独立无缓存重编译、4 件目标派生件链路复现核验、局部表推导几何与边界安全审查、静态版行为等价深度裁定，以及 DEV-042 复核工作：

1. **候选构建独立重编译与派生件可追溯性**：
   - 2 款候选变体（Dynamic 与 Static Baselines）在独立沙箱下使用 NDK r26d 重编译，SHA-256 100% 逐字节吻合；
   - 4 件派生件（4.4 动态 legacy-kp、4.19 静态 patch、4.4 静态 patch、4.4 静态 legacy-kp）经 `patch_offsets.py` 独立重跑比对 100% 吻合，父链与 compat 收据完整；源码与 Makefile 保持最新 KP 规范；
2. **Inode Storage 识别机制与防过读安全性**：
   - 确证 4.4 局部符号修饰（`no_open_fops.36570`）致使旧版精确名称查找失败属实；
   - 独立审查 `nm_probe_inode_storage` 与 `nm_initial_fops_matches`：21 条指令窗口严格跟踪 ADRP/ADD/STR，断言 `mapping == file_ops + 16` 硬几何，指针解引用严格限定于已校验的 rodata/代码边界内，无盲猜偏移，无过读越界风险；
3. **静态差异深度裁定（本轮关键裁定）**：
   - 动态推导代码在宏 `#ifndef CONFIG_KPM_BASELINES` 门控下预处理 100% 剥离；
   - 反汇编 106 个函数证明：104 个函数指令完全同构，仅 `nm_validate_control_layout`（寄存器缓存）与 `nm_prepare_control_engine`（增补纯幂等校验）存在共计 4 字节微调；
   - **裁定：新静态字节 `77a5baa3…` 与已验收发布集 `76e220cd…` 100% 行为等价，技术上支持将已验收的静态真机证据直接绑定至新静态字节**；
4. **AUD-001 风险状态与支持边界**：
   - `key_type` 精确尺寸依然未知（`-1`），沿用 512 字节自建容量，`AUD-001` 维持 OPEN；支持范围限定于 Case 1（Sony 4.19）与 Case 2（Nokia 4.4）几何；
5. **DEV-042 问题单复核**：
   - 代码层修复已验证（`fixed`），待 Tester 完成 4.4 真机测试后正式复核关闭；
6. **同意移交 Tester 开展实测验证**：
   - 同意 Tester 依据计划开展真机测试：重点测试 ① 4.4 动态兼容件（本轮修复目标）、② 4.19 动态回归、③ 5.15 BTF 回归；
   - ④ 与 ⑤ 两趟静态测试可依据 Auditor 静态等价裁定免测绑定，若条件具备亦可执行以求经验层面双重闭环。

完整审计报告见 [`Auditor/reports/2026-10-15-nomount-inode-storage-audit.md`](../../reports/2026-10-15-nomount-inode-storage-audit.md)。

---

## 提案清单

本目录提供结构化数据文件，供维护者在核对 Auditor 检查点提交后，同步合入 `metadata/modules/nomount.json`：

1. [report_versions.json](report_versions.json): 包含 3 份报告与数据文件的首次入库基线与版本记录：
   - `Auditor/reports/2026-10-15-nomount-inode-storage-audit.md`: `88f092d2cdd59459accf9096109a6549a77c5019ee6c51bb743dfb56cb4e2ef4` (11,094 字节)
   - `Auditor/reports/data/2026-10-15-nomount-inode-storage-artifact-audit.json`: `d0a17155ff4c579a71e84af826cc3c57a8fd6ac8b6cb652b7938a414e6fb3fa9` (2,486,826 字节)
   - `Auditor/reports/data/2026-10-15-nomount-inode-storage-static-scan.json`: `24929a2e9138556351b6ff7926c6bde38e4ecae77a32dc5125c18b139b124d84` (9,550 字节)

2. [audits.json](audits.json): 包含 2 个候选构建实例（`base`, `baselines`）的审计记录条目，绑定 `source_commit` `846f3d1bce5f7aa9c9f8d180e3c1b2f02b6d3e34` 及对应的产物 SHA-256。

Auditor 严格遵循所有权规则，不直接修改他人拥有的元数据结论或直接提交 `metadata/` 文件。
