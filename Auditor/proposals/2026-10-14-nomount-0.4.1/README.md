# NoMount 0.4.1 独立审计结论与元数据入库提案

依据维护者轮次请求 [`docs/records/2026-10-14-nomount-0.4.0-0.4.1-round-request.md`](../../../docs/records/2026-10-14-nomount-0.4.0-0.4.1-round-request.md)。

Auditor 已完成 NoMount 0.4.1 及 0.4.0 的全量独立审计工作：
1. **候选产物重编译**：0.4.1（4 份）与 0.4.0（4 份）共 8 份候选产物沙箱无缓存重编译 100% 逐字节吻合；
2. **目标派生件重跑**：32 条目标派生记录（24 份唯一二进制，含新增 `kernel_android14-6.1` 目标）两段式链路重跑 100% 逐字节吻合；
3. **上游刷新边界证实**：对比证实 0.4.1 与 0.4.0 的执行代码段 `.text`（66,052 字节）与偏移表 `.data.re_offsets`（92 字节）100% 逐字节相同，差异严格局限于版本字符串字面量与注释更新；
4. **6.1 定向目录 Actor ABI 审查**：确认 46 项偏移表末项 `dir_actor_abi`（0=int，1=bool）与 `nm_directory_filter_bool` 分流机制严密，符合 Linux 6.1 布尔迭代契约；
5. **未移植上游重构评估**：独立评估 upstream v2.1.1 的规则内联、inode/rule 解耦、RCU 退役与 UID Bloom 等未移植改动，证实均不包含关键安全性或正确性 Bugfix，现行架构安全稳固；
6. **配套 ZIP 闭环**：`nomount-kpm.zip` 哈希一致；随包脚本 `sources/build-nm.sh` 重编译 `nm` 产物 100% 逐字节吻合；独立核实分页错误非零退出与 JSON 特殊字符转义；开源许可证与署名完备；
7. **安全与常驻**：RA-002 依然成立，维持常驻不卸载约束。

完整审计报告见 [`Auditor/reports/2026-10-14-nomount-0.4.1-module-audit.md`](../../reports/2026-10-14-nomount-0.4.1-module-audit.md)。

## 提案清单

本目录提供结构化数据文件，供维护者在核对 Auditor 检查点提交后，同步追加至 `metadata/modules/nomount.json`：

1. [report_versions.json](report_versions.json): 包含 3 份报告与数据文件的首次入库基线与版本记录：
   - `Auditor/reports/2026-10-14-nomount-0.4.1-module-audit.md`: `d580d5ec912288868db80d0ce6b80194e86f273edbadec75b53d450c56ebd848` (22,698 字节)
   - `Auditor/reports/data/2026-10-14-nomount-0.4.1-artifact-audit.json`: `dae68d8e5a27a80463d308f8b5f957bcfc443d0e13dc689c5817df1389b738d3` (358,130 字节)
   - `Auditor/reports/data/2026-10-14-nomount-0.4.1-static-scan.json`: `d3b6b87b0994f26a02f7ad4e24f1165f0ea75872b292fa42df2ea75df78b7136` (9,470 字节)

2. [audits.json](audits.json): 包含 4 个候选构建实例（`base`, `baselines`, `baselines_debug`, `debug`）的审计记录条目，绑定 `source_commit` `17b4c622988eee61af2d029bf95ea594fb8da790` 及对应的产物 SHA-256。

Auditor 严格遵循所有权规则，不直接修改他人拥有的元数据结论或直接提交 `metadata/` 文件。
