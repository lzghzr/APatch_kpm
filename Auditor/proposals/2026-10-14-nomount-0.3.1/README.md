# NoMount 0.3.1 独立审计结论与元数据入库提案

依据维护者轮次请求 [`docs/records/2026-10-14-nomount-0.3.1-round-request.md`](../../../docs/records/2026-10-14-nomount-0.3.1-round-request.md)。

Auditor 已完成 NoMount 0.3.1 的全量独立审计与 DEV-035 复核工作：
1. **候选产物重编译**：4 份 0.3.1 候选产物沙箱无缓存重编译 100% 逐字节吻合；
2. **目标派生件重跑**：14 条目标派生记录（10 份唯一二进制）两段式链路重跑 100% 逐字节吻合；
3. **加载事件契约审查**：独立走查代码流，确认移除了 `pre-kernel-init` 的拒绝分支，默认嵌入时机与晚期加载均允许，准备流程与事件解耦，失败回滚只清理未发布对象，契约成立；
4. **DEV-035 许可与署名复核**：`NOTICE.md`、`LICENSE` 及随包源码完备，使用随包脚本 `build-nm.sh` 重编译 `nm` 产物与 0.3.0 ZIP 及 0.3.1 ZIP 内预置二进制 100% 逐字节吻合，达成闭环条件并出具响应报告；
5. **配套 ZIP 核验**：`nomount-kpm.zip` 哈希与结构核验一致；
6. **安全与常驻**：RA-002 依然成立，维持常驻不卸载约束。

完整审计报告见 [`Auditor/reports/2026-10-14-nomount-0.3.1-module-audit.md`](../../reports/2026-10-14-nomount-0.3.1-module-audit.md)。  
DEV-035 响应报告见 [`Auditor/reports/responses/2026-10-14-DEV-035.md`](../../reports/responses/2026-10-14-DEV-035.md)。

## 提案清单

本目录提供结构化数据文件，供维护者在核对 Auditor 检查点提交后，同步追加至 `metadata/modules/nomount.json`：

1. [report_versions.json](report_versions.json): 包含 4 份报告与数据文件的首次入库基线与版本记录：
   - `Auditor/reports/2026-10-14-nomount-0.3.1-module-audit.md`: `3bf3bdc3b0eb44170642b3cdfae2b2c2e045e68ed9ded00806ae2b02e9d6302c` (13,792 字节)
   - `Auditor/reports/responses/2026-10-14-DEV-035.md`: `4791f5446dbd0f3e48192431a34bc7b53fbc3781986d0c941cf1d01d9c73b129` (4,774 字节)
   - `Auditor/reports/data/2026-10-14-nomount-0.3.1-artifact-audit.json`: `0938a771a0be48f33a0db3d1c1cdf05c9946d48bfcbcf3eb94add88f08c3b0fa` (343,712 字节)
   - `Auditor/reports/data/2026-10-14-nomount-0.3.1-static-scan.json`: `13b182fcb30a6826aac988b03e74c20841cad9913bfb7fed80c359e71e0df545` (8,598 字节)

2. [audits.json](audits.json): 包含 4 个候选构建实例（`base`, `baselines`, `baselines_debug`, `debug`）的审计记录条目，绑定 `source_commit` `d33eaf8fa6f5376d1e84b82b3b7b8176b58ef561` 及对应的产物 SHA-256。

3. [issue_closure.json](issue_closure.json): 问题单 `DEV-035` 的独立复核与关闭建议条目。

Auditor 严格遵循所有权规则，不直接修改他人拥有的元数据结论或直接提交 `metadata/` 文件。
