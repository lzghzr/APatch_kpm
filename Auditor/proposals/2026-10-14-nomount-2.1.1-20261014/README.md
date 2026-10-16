# NoMount 2.1.1-20261014 发布前独立审计结论与元数据入库提案

依据维护者轮次请求 [`docs/records/2026-10-14-nomount-release-round-request.md`](../../../docs/records/2026-10-14-nomount-release-round-request.md)。

Auditor 已完成 NoMount 2.1.1-20261014 发布候选产物、8 条目标派生记录、产物 ELF 节段级 Delta 判定、配套发布 ZIP 及发布更新元数据的独立审计复核工作：

1. **候选无缓存重编译与目标派生复现**：
   - 2 款发布候选变体（Dynamic 与 Static Baselines）在干净沙箱下使用 NDK r26d 重编译，SHA-256 100% 逐字节吻合；
   - 8 条目标派生记录（6 份唯一二进制产物）独立重跑派生脚本，SHA-256 100% 吻合。
2. **Delta 判定（核心支撑轻量回归判据 §4.3）**：
   - 实证 2.1.1-20261014 候选及全部派生目标的偏移表段 `.data.re_offsets`（92 字节，46 项结构体偏移与 ABI 标志）与 0.5.2 **100% 逐字节完全相同**；
   - `.text` 执行代码段大小与 0.5.2 完全一致（Baselines 42,996 字节，Dynamic 70,368 字节），且 42,996 字节代码中**恰好只有 8 字节差异，分布于 5 条 ARM64 指令的立即数字段中**，其语义严格来自版本字符串长度变化（状态 Banner 缓冲区大小从 47 变为 56 字节，协议版本常量长度从 5 变为 14 字节）；
   - 无任何指令增删、无任何分支跳转目标修改、无任何寄存器分配变化、无任何函数调用或 ABI 协议变化；
   - **正式确认《Tester 手册》§4.3 轻量回归判据成立**，静态版产物在 5.15 / 4.19 / 4.4 上的逻辑与 0.5.2 严格等价，完全满足通过 Delta 判定与在册哈希绑定的条件。
3. **发布配套 ZIP 与更新元数据复核**：
   - 发布 ZIP `NoMount-kpm_2.1.1-20261014.zip`（80,003 字节，33 条目，SHA-256 `42c5b644...`）全部条目完整；
   - 内部 `module.prop`、`bin/` CLI 工具、WebUI 资源及开源许可证自洽；
   - 更新预览元数据 `Developer/reports/data/2026-10-14-nomount-update-preview.json` 的 `version` (`v2.1.1-20261014`)、`versionCode` (`20261014`) 与 `zipUrl` 完全闭环，`nomount/tools/test_update_json.py` 单元测试通过（3/3 OK）。
4. **文档与资产命名一致性（用户裁定贯彻）**：
   - 贯彻用户裁定（2026-10-14）「人类思维是会自动过滤版本号的，不用改」，确认 README 中 `NoMount-kpm.zip` 与实际资产名 `NoMount-kpm_<版本>.zip` 视为同一物，不改代码亦不改文档；
   - 独立核验确认 `update_json.zipUrl` 指向实际资产名 `NoMount-kpm_2.1.1-20261014.zip`，不存在资产名不匹配导致更新 404 风险。
5. **静态扫描与产物独立审计**：
   - 边界与安全静态扫描通过（PASS），无并发或内存安全风险；
   - 产物独立审计 0 个 error（PASS），未定义符号全部在平台快照及 kallsyms 规范中闭环。
6. **测试移交建议**：
   - 依据维护者与用户对发布前测试矩阵的最新指示，建议 Tester 重点在 4.19（Sony Xperia 1 II，CFI 开启）与 4.4（Nokia 7 plus）上实测**动态版** `NoMount_2.1.1-20261014.kpm`（补齐此前 13 条真机记录全为静态派生件的历史缺口）；
   - 静态版可依据本轮 Delta 判定结论与 0.5.2 在册实机证据绑定，亦可按需执行单目标冒烟。

完整审计报告见 [`Auditor/reports/2026-10-14-nomount-2.1.1-20261014-release-audit.md`](../../reports/2026-10-14-nomount-2.1.1-20261014-release-audit.md)。

---

## 提案清单

本目录提供结构化数据文件，供维护者在核对 Auditor 检查点提交后，同步合入 `metadata/modules/nomount.json`：

1. [report_versions.json](report_versions.json): 包含 3 份报告与数据文件的首次入库基线与版本记录：
   - `Auditor/reports/2026-10-14-nomount-2.1.1-20261014-release-audit.md`: `681954983396e63413a2062633a776923fa8e5cc6a43a1584dbfcbc73c2ed569` (14,836 字节)
   - `Auditor/reports/data/2026-10-14-nomount-2.1.1-20261014-artifact-audit.json`: `86c789d1c34dd00825063ea993304a58cd9540583cb3af76f6c134fb401546ed` (322,457 字节)
   - `Auditor/reports/data/2026-10-14-nomount-2.1.1-20261014-static-scan.json`: `d768b1ffa8b08765cca4c4702f5c52dee3f7e28bace897771242a34743b1b072` (9,550 字节)

2. [audits.json](audits.json): 包含 2 个候选构建实例（`base`, `baselines`）的审计记录条目，绑定 `source_commit` `e9ab619ea75e7fd611c28dcc0328dbb99ebf1dfb` 及对应的产物 SHA-256。

Auditor 严格遵循所有权规则，不直接修改他人拥有的元数据结论或直接提交 `metadata/` 文件。
