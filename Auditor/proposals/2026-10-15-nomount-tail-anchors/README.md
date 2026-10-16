# NoMount 尾部锚点与 TST-001 修复候选独立审计结论与元数据入库提案

依据维护者轮次请求 [`docs/records/2026-10-15-nomount-tail-anchors-request.md`](../../../docs/records/2026-10-15-nomount-tail-anchors-request.md) 与 [`docs/records/2026-10-15-nomount-4.4-probe-bound-request.md`](../../../docs/records/2026-10-15-nomount-4.4-probe-bound-request.md)。

Auditor 已完成 NoMount 尾部锚点、十三目标静态适配、TST-001 修复候选版本（源码冻结 `ebad0588`）的独立无缓存重编译、4.4 动态兼容派生件与 13 份静态派生件链路复算核验、TST-001 代码修复审查、尾部锚点推导反例复核、静态等价再裁定、5.15 动态 Delta 等价性裁定、DEV-044 对齐算术更正与安全审计工作：

1. **候选构建独立重编译与派生件可追溯性**：
   - 2 款候选变体（Dynamic 与 Static Baselines）在独立沙箱下使用 NDK r26d 重编译，SHA-256 100% 逐字节吻合；
   - 4.4 动态 legacy-kp 派生件（`06bd6850…`）及 13 份静态目标派生件经 `patch_offsets.py` 独立重现 100% 吻合，父链与 compat 收据完整；
2. **TST-001 代码修复独立审查（追加范围）**：
   - 确证 Nokia 4.4 内核中 `_etext` 为绝对符号导致旧版误判边界属实；
   - 审查确认当 `code_end` 异常时回退至重定位符号 `__start_rodata` 正确无误；读取严格受限于 `[_stext, __start_rodata - 4]`，无过读越界风险；回退失效时严格 Fail-Closed 返回 `-ENOENT`；
   - 独立运行 `nomount/tools/test_inode_code_bounds.py` 5 组边界反例全部通过，确认 `TST-001` 代码修复成立，标记为 **`fixed`**（已由 Tester 4.4 实机全通闭环关闭）；
3. **尾部锚点推导与 128 字节代理对齐审查**：
   - 5 份新目标（米8 4.9、米9 4.14、米10 4.19、米11 5.4、Android 12 5.10）锚点选取与尾部宽度推导严密；
   - 有界反例复核成立：米8 / 米9 原生操作表地址及缓存行要求 128 字节对齐，将私有代理表头纠正为 128 字节对齐，避免末端尺寸截断；
   - 独立运行 `test_tail_derivation.py`（37 项反例全通）、`test_proxy_alignment.py`（Oracle 693 项断言全通）、`test_static_targets.py`（13 份配置往返校验全通）；
4. **静态等价再裁定（关键裁定）**：
   - 理论上 128 字节对齐完全包容 64 字节对齐，指针反算公式保持同构；
   - 但物理结构层面，私有代理头偏移由 64 字节扩展为 128 字节，Slab 分配阶数改变，且该变更**对已有目标全局生效**；
   - **裁定：本轮静态件对已有目标属于结构扩展变更，不能单凭反汇编等价性直接免测顺延已验收证据**；
   - **实机测试要求**：已有设备目标抽样实测静态件（Tester 已实测 4.4 与 4.19 静态件，各 20/20 项全绿通过）；新增 5 目标目前无设备，如实登记为「无实机证据」；
5. **5.15 动态候选 Delta 等价性与证据顺延绑定裁定（追加裁定）**：
   - 证明：在 5.15 BTF 完备内核下，TST-001 修复代码、`nm_check_key_name` / `nm_find_super_cache` 启发式规则、以及 `nm_find_vmalloc_range` 回退代码在运行时**100% 严格不可达**；
   - **裁定：新动态候选 `1ab36727…` 相对上轮已实测的 `7e214750…` 在 5.15 下满足严格的 Delta 运行时等价；支持顺延绑定上轮 Sony Xperia 1 V 的 20/20 PASS 实测证据**；发布不因 5.15 未接入而受阻；
6. **DEV-044 对齐算术更正与有效性复核（追加更正）**：
   - 响应 Developer DEV-044，更正 §7.2 第 4 项关于 192 能被 128 整除的笔误，明确 $192 = 64 \times 3$；
   - 独立几何证明：发布表基址满足 64 字节对齐，完全满足 5.15 内核 L1 Cache Line（64 字节）对齐要求；逆向寻址运算（`-320` 字节）完全封闭自洽；
   - 结论：**DEV-044 勘误对 5.15 Delta 证据绑定结论零影响，等价性裁定保持完全有效**；建议维护者核准关闭 DEV-044；
7. **AUD-001 风险状态与支持边界**：
   - `key_type` 精确尺寸依然未解，512 字节自建容量保留，`AUD-001` 维持 OPEN；
8. **结论与验收支持**：
   - Tester 4.4 动态首度全通确证 TST-001/DEV-042 闭环，静态抽样与 4.19 动态回归全绿，同意发布口径验收。

完整审计报告见 [`Auditor/reports/2026-10-15-nomount-tail-anchors-audit.md`](../../reports/2026-10-15-nomount-tail-anchors-audit.md)。

---

## 提案清单

本目录提供结构化数据文件，供维护者在核对 Auditor 检查点提交后，同步合入 `metadata/modules/nomount.json`：

1. [report_versions.json](report_versions.json): 包含 3 份报告与数据文件的入库基线与版本记录：
   - `Auditor/reports/2026-10-15-nomount-tail-anchors-audit.md`: `4340bdfd87c509c468304cbacd8f72a37cc15f8ab6e10134f3e9669161059f46` (20,496 字节；基线 `7034cff5…` 10,534 字节；v2 `9ede5143…` 15,833 字节)
   - `Auditor/reports/data/2026-10-15-nomount-tail-anchors-artifact-audit.json`: `e0ef7eab770d45e8df48fd2e0db44bfaf226e19c891beff63ce2286fffb60045` (2,615,059 字节)
   - `Auditor/reports/data/2026-10-15-nomount-tail-anchors-static-scan.json`: `e961dd762bd82c158a590923d46210566d8a8bbf4146179fe3b3f5c4b7331f35` (9,552 字节)

2. [audits.json](audits.json): 包含 2 个候选构建实例（`base`, `baselines`）的审计记录条目，绑定 `source_commit` `ebad05883bcd6173d5e2a867559aa6bcb3e45810` 及对应的产物 SHA-256、5.15 Delta 绑定范围与 DEV-044 处置建议。

Auditor 严格遵循所有权规则，不直接修改他人拥有的元数据结论或直接提交 `metadata/` 文件。
