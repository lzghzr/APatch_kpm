# NoMount 0.5.2 独立审计结论与元数据入库提案

依据维护者轮次请求 [`docs/records/2026-10-14-nomount-0.5.2-light-round-request.md`](../../../docs/records/2026-10-14-nomount-0.5.2-light-round-request.md)。

Auditor 已完成 NoMount 0.5.2 候选产物、8 条目标派生记录、产物 ELF 节段级 Delta 比对及 DEV-038 缺陷单的独立复核关闭工作：
1. **Delta 判定（核心支撑轻量回归判据 §4.3）**：
   - 实证 0.5.2 候选（Dynamic 70,368 字节、Static Baselines 42,996 字节）及全部 6 款派生目标二进制与 0.5.1 对应产物的执行指令段 `.text` 均 **100% 逐字节完全相同**；
   - 偏移表 `.data.re_offsets`（92 字节，46 个偏移与 ABI 标志）**100% 逐字节完全相同**；
   - 差异严格局限于注册名/文件名大小写收敛（`NoMount`）、版本号更新（`0.5.2`）、日志宏格式前缀（`nm_log_info` / `nm_log_error`）及重定位条目 addend 随字符串位置的自适应调整；
   - **正式确认《Tester 手册》§4.3 轻量回归判据成立**，建议 Tester 仅对 Sony Xperia 1 V（5.15，`Enforcing`）开展单目标冒烟实测覆盖安装与命名变更即可，免去三机全量回归。
2. **去 Debug 变体收敛**：Developer 响应维护者要求，彻底移除冗余的 `_debug` 变体，仅交付干净的 Dynamic 与 Static Baselines 两款候选。
3. **候选重编译与目标派生**：
   - 2 份候选产物沙箱无缓存重编译 100% 逐字节吻合；
   - 8 条目标派生记录（6 份唯一字节）重派生 100% 逐字节吻合。
4. **DEV-038 独立复核关闭**：
   - 审查维护者在 `tools/check_repository.py` 中的修复（`if '/' not in raw`），确认仅过滤真实顶层子模块，正确保留包含嵌套子模块的父项目；
   - 门禁 CI 选择摘要（15 个模块）与 `.github/workflows/build-kpm.yml` 实际构建目录完全一致；
   - `tools/selftest_tools.py` 新增夹具回归通过（34/34 PASS）；
   - Auditor 独立出具复核关闭报告，正式关闭 DEV-038（`status=closed`，`closed_by=Auditor`）。

完整审计报告见 [`Auditor/reports/2026-10-14-nomount-0.5.2-module-audit.md`](../../reports/2026-10-14-nomount-0.5.2-module-audit.md)，DEV-038 关闭响应见 [`Auditor/reports/responses/2026-10-14-DEV-038.md`](../../reports/responses/2026-10-14-DEV-038.md)。

## 提案清单

本目录提供结构化数据文件，供维护者在核对 Auditor 检查点提交后，同步合入 `metadata/modules/nomount.json`：

1. [report_versions.json](report_versions.json): 包含 4 份报告与数据文件的首次入库基线与版本记录：
   - `Auditor/reports/2026-10-14-nomount-0.5.2-module-audit.md`: `761bdbb037ee4d80638022c474bd8827a82425082307574334ba4b3e3fd65043` (10,514 字节)
   - `Auditor/reports/responses/2026-10-14-DEV-038.md`: `1c550e104ac568c69855242e181769a557f0a668c57e5198641bf071303a6ab0` (6,128 字节)
   - `Auditor/reports/data/2026-10-14-nomount-0.5.2-artifact-audit.json`: `76a48f4c3dba84dca195506eda9f2089560e8560a20146973665527c45d7f097` (334,009 字节)
   - `Auditor/reports/data/2026-10-14-nomount-0.5.2-static-scan.json`: `0604deb4c6c52a4b00da864761c45dee267e2b379b701462ddc3fee758670473` (9,550 字节)

2. [audits.json](audits.json): 包含 2 个候选构建实例（`base`, `baselines`）的审计记录条目，绑定 `source_commit` `6b870aa8bcfdc4523709bf7baa9d377fcb3744fa` 及对应的产物 SHA-256。

3. [issue_closure.json](issue_closure.json): 包含 `DEV-038` 的正式关闭记录（`closed_by=Auditor`，`status=closed`，复核证据与评注）。

Auditor 严格遵循所有权规则，不直接修改他人拥有的元数据结论或直接提交 `metadata/` 文件。
