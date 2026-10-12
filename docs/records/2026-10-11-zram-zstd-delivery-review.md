# zram_zstd 0.3.0 签名交付复核（2026-10-11）

角色：维护者。复核对象为签名提交 `0b1bafa4b113aed85e208caa65d5a0d89f55e512`，候选源码提交为 `d39961d051605dc1d0432ed88f063cb5d1ff4f0f`。本记录追加复核事实，角色报告保持原结论。状态：交付待完成。

## 对象与核验

| instance_id | 产物 SHA-256 |
| --- | --- |
| `zram_zstd-0.3.0+gad3822546cc3.r07e12989.kpb51197a.ndk26.3.11579264#1` | `063f1cf8c665023c526cdda997c5584cfa11839c7cfa61df3089553e2f3c6eee` |
| `zram_zstd-0.3.0_baselines+gad3822546cc3.r145225af.kpb51197a.ndk26.3.11579264#1` | `529653ec03ea13b305e8b36dea8047185d64eba811856aee626416a97293cd50` |
| `zram_zstd-0.3.0_baselines_debug+gad3822546cc3.rc293f246.kpb51197a.ndk26.3.11579264#1` | `47de1be3c93e33e5451a696f40fc94087cca995e09044d3b49f7adb0baca79ad` |
| `zram_zstd-0.3.0_debug+gad3822546cc3.rea498d28.kpb51197a.ndk26.3.11579264#1` | `77708ff1021dc3ac74705490c7b4aed34467040262e87126864818e59ddc022d` |

- 三笔提交 `336c217514cf0406019290da1bb7e5e80a1600d5`、`1c2503a295919b06b4dea3353843cae758137c4e`、`0b1bafa4b113aed85e208caa65d5a0d89f55e512` 均通过 `git verify-commit`；工具、模块、记录顺序及模块标题前缀符合约定。
- 四个指定实例逐一执行 `identity.verify_build(entry, profile="candidate")`，均为零问题；两份派生件和转换回执的实际 SHA-256 均与登记一致。
- 对被复核签名提交运行 `python3 tools/check_repository.py --strict`：13 项，零失败、零警告。该检查将空交付集合记为 `delivery_pending`，不证明已完成交付。
- 四个指定实例逐一执行 `identity.verify_build(entry, profile="delivery", deliveries=record["deliveries"])`，均因缺少交付绑定失败。`deliveries[]` 为空。
- 对上述签名提交构造字段完整的临时绑定，仅在内存调用 `identity.delivery_problems(entry, binding)`，四个实例均报告模块树不同及下列五项构建输入不同。该诊断未写入交付绑定。
- 独立审计与实机结果引用现有角色报告，本次未重跑编译或操作设备；实机证据只覆盖两份派生件、该台 4.4.192 设备及各自 11/11 已执行判据。

## MNT-017（高，归属维护者）签名内容与冻结候选不同，交付闭环缺失

- 类别：product；状态：open；frequency：未知；confidence：已确认。
- 身份与证据：上表四实例；候选模块树 `957af2c4a9572ecf40858b2a4f74f47cdd5ad7f1`，交付模块树 `846b26b5edbf5243d69b1640806eb1f9c2164246`。复现：`git diff d39961d051605dc1d0432ed88f063cb5d1ff4f0f 0b1bafa4b113aed85e208caa65d5a0d89f55e512 -- zram_zstd tools/identity.py`，并逐实例运行 `python3 tools/identity.py verify --module zram_zstd --instance-id '<上表实例>' --profile delivery`。
- 构建输入差异：`tools/identity.py`、`zram_zstd/Makefile`、`zram_zstd/SOURCES.json`（删除）、`zram_zstd/tools/prepare_codec.py`、`zram_zstd/tools/selfcheck.py`。另有模块文档差异。
- 影响：签名提交中的构建输入无法绑定本轮已审计、已测试候选。原交付记录关于“全部构建输入逐字节一致”的陈述与复算不符。
- 闭环缺口：无交付绑定，无保存绑定及核验回执的后续签名记录；SMB 副本 HEAD 为 `459ceef810f4315b1de77f90141626fc3d20c55e`，与本轮签名提交不同。只读比对 501 个当前普通跟踪文件：359 一致、114 缺失、28 内容不同；子模块未展开，目录读取受限项不宣称已核验。
- 建议：维护者使交付输入与冻结候选一致；若保留新输入，交由 Developer 重新冻结、构建新实例，并按变化范围补独立审计和测试。随后追加明确 D 的交付绑定，完成指定实例 delivery 核验，保存回执并在取得签名授权后形成记录提交 E，按既定范围同步 Git 跟踪文件及删除/改名。
- 关闭条件：由 Auditor 或 Developer 独立复核新交付 D 与具体候选的输入一致性、实际可信签名、逐实例 delivery 成功、D/E 回执顺序和接收副本一致性；维护者同步状态。不得通过缩小判据消除差异。

## MNT-018（高，归属维护者）风险接受范围与 0.3.0 验收引用不一致

- 类别：product；状态：open；frequency：未知；confidence：已确认。
- 身份与证据：上表四实例与登记的两份派生件；`risk_acceptances[RA-001].approval_scope` 明确仅覆盖 0.1.0 八个在册候选、指定 KP，不覆盖未来版本；其修订仍标 `scope_unchanged=true`。0.3.0 的验收却引用同一 RA-001。
- 影响：已确认的卸载/重载 Panic 风险在 0.3.0 验收中缺少与具体版本、实例及派生形态对应的风险接受范围记录。本次未判断其它会话中是否已有授权。
- 建议：核对已有用户授权；存在明确授权时追加对应的新范围记录及证据引用，否则先取得用户对具体范围的决定。保留既有 RA-001 原文与历史批准边界。
- 关闭条件：Auditor 或 Developer 独立确认追加记录覆盖本轮具体实例和派生哈希、KP/设备与常驻使用限制，批准来源可追溯，验收引用一致；维护者同步状态。

复核记录通过无签名检查点归档，问题单保持 open；未产生交付级签名或执行推送、同步。
