# NoMount 0.5.1 独立审计结论与元数据入库提案

依据维护者轮次请求 [`docs/records/2026-10-14-nomount-0.5.1-round-request.md`](../../../docs/records/2026-10-14-nomount-0.5.1-round-request.md) 与关闭请求 [`docs/records/2026-10-14-DEV-036-closure-request.md`](../../../docs/records/2026-10-14-DEV-036-closure-request.md)。

Auditor 已完成 NoMount 0.5.1 候选产物、16 条目标派生记录、配套 ZIP 及 DEV-036 缺陷单的全量独立审计与复核关闭工作：
1. **变体差异逐目标独立判定（支撑单变体真机测试判据 §4.1）**：实证全部 8 组目标派生件及 2 组候选产物的 `debug` 与 `release` 变体在执行指令段 `.text`（100% 逐字节相同）、`.data.re_offsets`（100% 相同）、`.rodata`（100% 相同）、`.rela.text`（100% 相同）均无任何差异，差异严格局限于 `.kpm.info` 模块信息段内版本串字面量（`0.5.1` vs `0.5.1_d`，多 2 字节）及符号表索引；**正式确认单变体测试判据成立，Tester 每个目标仅需测 release 变体**；
2. **候选产物重编译**：4 份候选产物沙箱无缓存重编译 100% 逐字节吻合；
3. **目标派生件重跑**：16 条目标派生记录（12 份唯一字节）重跑 100% 逐字节吻合；
4. **DEV-036 架构安全审查与 LSM 原生继承**：
   - 原生 LSM 接口调用时机严谨：`security_inode_getsecctx` 在锁外睡眠获取，`security_inode_notifysecctx` 在 `i_mode` 类别设定后执行；
   - 错误闭环与并发控制：普通文件失败经 `iput` 原生 evict 回收，目录 Inode 在 `I_NEW` 保护下初始化，唤醒等待者无条件检查 `init_error` 并安全释放，绝不发布错误 alias；
   - 动态标签感知：`secid` 比较接入目录缓存 test 与 dentry 校验，源对象 relabel 时缓存即刻失效；
   - 独立复核 2 处 Oracle 测试断言迁移有效，51 处安全生命周期新断言覆盖完整；
5. **配套 ZIP 闭环**：`nomount-kpm.zip` 哈希一致；随包脚本 `sources/build-nm.sh` 重编译 `nm` 产物 100% 逐字节吻合；WebUI 补齐空列表表情 `_(._.)_`；
6. **安全与常驻**：RA-002 依然成立，维持常驻不卸载约束；
7. **DEV-036 复核关闭**：Auditor 独立复核代码与架构成立，Tester 侧已在 Sony 5.15（Enforcing）覆盖真实消费者（`artd` 编译返回 0 无 `EACCES`、`u:r:priv_app:s0` 正常加载执行与内存映射），并全量通过 4.19 与 4.4 回归（各 20/20 项强证据判据通过）。**DEV-036 闭环条件全部达成，Auditor 正式复核关闭（`status=closed`，`closed_by=Auditor`）**。

完整审计报告见 [`Auditor/reports/2026-10-14-nomount-0.5.1-module-audit.md`](../../reports/2026-10-14-nomount-0.5.1-module-audit.md)，DEV-036 关闭响应见 [`Auditor/reports/responses/2026-10-14-DEV-036.md`](../../reports/responses/2026-10-14-DEV-036.md)。

## 提案清单

本目录提供结构化数据文件，供维护者在核对 Auditor 检查点提交后，同步追加至 `metadata/modules/nomount.json`：

1. [report_versions.json](report_versions.json): 包含 4 份报告与数据文件的首次入库基线与版本记录：
   - `Auditor/reports/2026-10-14-nomount-0.5.1-module-audit.md`: `1a76fe526e00d49ceda87ec8082ebee62b7786431519300172aa68a2ecf6aa1a` (20,315 字节)
   - `Auditor/reports/responses/2026-10-14-DEV-036.md`: `fe0d19b725ef85b6d74b3b9c9afcff989088a26c7a73c936535b6997aa3fd55b` (8,584 字节)
   - `Auditor/reports/data/2026-10-14-nomount-0.5.1-artifact-audit.json`: `3e7310384e0d23d79cd459b98432b559c825605833e751f13f785c503121a172` (1,848,974 字节)
   - `Auditor/reports/data/2026-10-14-nomount-0.5.1-static-scan.json`: `a105bb27f64de12132572e955bc8000af5c3419fddaf1a8804b82d5ed70aa0d4` (9,526 字节)

2. [audits.json](audits.json): 包含 4 个候选构建实例（`base`, `baselines`, `baselines_debug`, `debug`）的审计记录条目，绑定 `source_commit` `cfb971d195d997808b68567b8ffc61a4dcd32b90` 及对应的产物 SHA-256。

3. [issue_closure.json](issue_closure.json): 包含 `DEV-036` 的正式关闭记录（`closed_by=Auditor`，`status=closed`，复核证据与评注）。

Auditor 严格遵循所有权规则，不直接修改他人拥有的元数据结论或直接提交 `metadata/` 文件。
