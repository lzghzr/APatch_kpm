# NoMount 自建操作表容量探索独立审计结论与元数据入库提案

依据维护者轮次请求 [`docs/records/2026-10-15-nomount-owned-operation-capacity-request.md`](../../../docs/records/2026-10-15-nomount-owned-operation-capacity-request.md)。

Auditor 已完成 NoMount 自建操作表容量探索版本（源码冻结 `7e668af2`）的无缓存独立重编译、容量契约与越界最坏情形推演、防过读与降级门控审查，以及测试套件与 Oracle 纪律复核工作：

1. **探索构建无缓存重编译**：
   - 2 款探索变体（Dynamic 与 Static Baselines）在独立沙箱下使用 NDK r26d 重编译，SHA-256 100% 逐字节吻合；
2. **容量契约与越界最坏情形（Worst-Case Analysis）**：
   - 核对 4.4～6.6 原生声明，512 字节容量对受限清零表具备充裕裕量（上界 <= 256 字节）；
   - 推演若厂商定制内核结构体超出 512 字节的最坏情形：堆越界读取致指令异常/CFI违规崩溃（Heap OOB Read），以及 `key_type` 尾部 `link` 写入致 Slab 堆破坏（Heap OOB Write）；明确确认该容量是**特定经验契约**，非对任意未知厂商内核的普遍保证；
3. **分配容量与复制长度彻底分离（防过读）**：
   - 原表代理克隆路径严格要求精确尺寸，尺寸未知直接 `-EINVAL` 拒绝，绝不分配亦绝不复制；
   - 512 字节仅用于 `original == NULL` 的全零表内存分配，完全消除过读风险；
4. **降级门控与未完成面 Fail-Closed**：
   - 仅在 BTF 明确不可用（`-ENODATA` 且 `unavailable == true`）时启用容量策略，有效 BTF 错误严格向上传播；
   - 缺失三类原表复制尺寸（`inode_ops_size`、`super_ops_size`、`dentry_ops_size`）时必定在准备阶段返回 `-ENOENT` 失败退出，绝不进入半初始化运行状态；
5. **Oracle 纪律与测试披露**：
   - 46 个既有测试文件逐字节未变；新增容量与保护页测试通过；独立核实历史 `test_native.py` 编译期失败披露属实，未弱化断言；
6. **定向测试移交**：
   - 明确本轮为探索诊断轮（非验收轮）；同意 Tester 在 4.19 执行诊断实测（验证容量推进与 `-ENOENT` 边界）及在 5.15 执行 BTF 回归实测。

完整审计报告见 [`Auditor/reports/2026-10-15-nomount-owned-operation-capacity-audit.md`](../../reports/2026-10-15-nomount-owned-operation-capacity-audit.md)。

---

## 提案清单

本目录提供结构化数据文件，供维护者在核对 Auditor 检查点提交后，同步合入 `metadata/modules/nomount.json`：

1. [report_versions.json](report_versions.json): 包含 3 份报告与数据文件的首次入库基线与版本记录：
   - `Auditor/reports/2026-10-15-nomount-owned-operation-capacity-audit.md`: `7ca0625509475dd04088257d0808d5aea6e4a21f06eb6ec4afecdf38a6da6c23` (11,903 字节)
   - `Auditor/reports/data/2026-10-15-nomount-owned-operation-capacity-artifact-audit.json`: `d48aa85ffa73a18fe206dc2a50a21fa5ad491cc019d443ee098d34f47c6b9455` (351,575 字节)
   - `Auditor/reports/data/2026-10-15-nomount-owned-operation-capacity-static-scan.json`: `54475cca1de0dbb6b15bde9aca74d5f682d1ef742b5332eadc2ca930966e7f9a` (9,550 字节)

2. [audits.json](audits.json): 包含 2 个探索构建实例（`base`, `baselines`）的审计记录条目，绑定 `source_commit` `7e668af2213d78a4e7cbb0c72bc9f5660678403d` 及对应的产物 SHA-256。

Auditor 严格遵循所有权规则，不直接修改他人拥有的元数据结论或直接提交 `metadata/` 文件。
