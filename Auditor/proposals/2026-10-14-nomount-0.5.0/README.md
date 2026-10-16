# NoMount 0.5.0 独立审计结论与元数据入库提案

依据维护者轮次请求 [`docs/records/2026-10-14-nomount-0.5.0-round-request.md`](../../../docs/records/2026-10-14-nomount-0.5.0-round-request.md)。

Auditor 已完成 NoMount 0.5.0（及 0.4.2/0.4.3）的全量独立审计工作：
1. **变体差异逐目标独立判定（支撑单变体真机测试判据）**：实证全部 8 组目标派生件及 2 组候选产物的 `debug` 与 `release` 变体在执行指令段 `.text`（100% 逐字节相同）、`.data.re_offsets`（100% 相同）、`.rodata`（100% 相同）、`.rela.text`（100% 相同）均无任何差异，差异严格局限于 `.kpm.info` 模块信息段内版本串字面量（`0.5.0` vs `0.5.0_d`，多 2 字节）及符号表偏移；**正式确认单变体测试判据成立，Tester 每个目标仅需测 release 变体**；
2. **候选产物重编译**：0.5.0（4 份）、0.4.3（4 份）与 0.4.2（4 份）共 12 份候选产物沙箱无缓存重编译 100% 逐字节吻合；
3. **目标派生件重跑**：36 条目标派生记录（24 份唯一二进制）两段式链路重跑 100% 逐字节吻合；
4. **架构升级审查**：
   - 私有小对象分配（0.4.3）：`nm_zalloc` 结合 `__kmalloc(span, 0)` 原子 slab 分配与 `vzalloc` 回退，RCU 释放经 `is_vmalloc_addr` 分流 `vfree_atomic`，逻辑严密无睡眠与悬挂指针风险；
   - Inode 绑定解耦（0.5.0）：`nm_inode_info` 彻底解耦 `struct nomount_rule*`，独立持有 `r_path` 并在物化与驱逐时成对调用 `path_get`/`path_put`；散列迁移至 `dir_node`；独立复核 20 处 Oracle 测试断言迁移有效；
5. **配套 ZIP 闭环**：`nomount-kpm.zip` 哈希一致；随包脚本 `sources/build-nm.sh` 重编译 `nm` 产物 100% 逐字节吻合；开源许可证与署名完备；
6. **安全与常驻**：RA-002 依然成立，维持常驻不卸载约束。

完整审计报告见 [`Auditor/reports/2026-10-14-nomount-0.5.0-module-audit.md`](../../reports/2026-10-14-nomount-0.5.0-module-audit.md)。

## 提案清单

本目录提供结构化数据文件，供维护者在核对 Auditor 检查点提交后，同步追加至 `metadata/modules/nomount.json`：

1. [report_versions.json](report_versions.json): 包含 3 份报告与数据文件的首次入库基线与版本记录：
   - `Auditor/reports/2026-10-14-nomount-0.5.0-module-audit.md`: `84b10db1db866921d555b7facf8e90418e82cc3051bc7a9d4aca24f23aa2f12c` (18,606 字节)
   - `Auditor/reports/data/2026-10-14-nomount-0.5.0-artifact-audit.json`: `e2b33dc4ea5e4e22f0d2e710ec31465d8d66400a80414e4d6b278a21345e5a21` (392,328 字节)
   - `Auditor/reports/data/2026-10-14-nomount-0.5.0-static-scan.json`: `b6c022cc7978b718e10e9e3ebb087df15089b144223ce31ab1c017a5936d37ed` (9,497 字节)

2. [audits.json](audits.json): 包含 4 个候选构建实例（`base`, `baselines`, `baselines_debug`, `debug`）的审计记录条目，绑定 `source_commit` `773385757fcaaa6588e7946862e6784842c1901c` 及对应的产物 SHA-256。

Auditor 严格遵循所有权规则，不直接修改他人拥有的元数据结论或直接提交 `metadata/` 文件。
