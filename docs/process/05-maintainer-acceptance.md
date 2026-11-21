# 维护者验收与签名交付

验收针对具体构建实例。维护者复算关键证据，确认其强度与覆盖范围，再决定接受、拒绝或带明确范围的风险接受。

## 验收清单

```text
[ ] 对象为完整 source_commit + instance_id + 每个产物 SHA-256
[ ] 指定实例通过 candidate 核验；源码、工具链、参数、构建事务可复核
[ ] 独立审计报告包含重编译/字节解析、边界、安全、同源风险与未覆盖项
[ ] Tester 报告区分真机结果、mock 自检、未执行；判据和脚本身份完整
[ ] 变体覆盖符合 Tester 手册 §4.1：只测一个变体时，另有审计结论证明 debug 与 release 差异仅限日志/断言；
    验收记录写明实测变体与被绑定变体的依据（未确认差异时两个变体都要测）
[ ] 用户主要操作覆盖符合 Tester 手册 §4.2：报告列出用户主路径并给出逐条结论；注入内容由**真实消费者**
    （应用/ART/系统服务）在 Enforcing 下验证可用，而非仅「PackageManager 已登记」或仅探针可读
[ ] 走轻量回归档（Tester 手册 §4.3）时：审计已证明差异仅限命名/版本/日志，且冒烟覆盖了用户主路径与命名/安装流程；
    未重复上机的目标写明由哪份 delta 结论与哈希绑定
[ ] 静态件按 Tester 手册 §4.4 绑定时：审计给出了预处理剥离证据 + 全函数反汇编语义比对，且写明等价范围；
    验收记录引用该结论与被绑定的旧证据
[ ] 关键主张由维护者复现；引用报告的部分标明来源和未独立复现原因
[ ] 当前版本声明自洽；历史产物按其所属构建版本核对
[ ] 阻塞问题已独立复核关闭，或由维护者书面批准风险范围及恢复触发条件
[ ] 未因过门禁缩小断言、用例或检查范围；判据变更有理由与复核记录
[ ] 新验收条目追加到 acceptances[]，与实例的 commit、指纹、产物哈希一致
[ ] 交付提交签名有效且交付源码与候选构建输入一致（不使用交付标签）
[ ] deliveries[] 绑定已追加，指定实例通过 delivery 核验
[ ] 绑定与回执索引保存在后续签名提交；主副本的提交与对象一致
```

## 候选核验

```bash
python3 tools/selftest_tools.py
bash Tester/tools/selftest_scripts.sh
python3 tools/identity.py verify --module <module> --instance-id '<build_id>#<n>' --profile candidate
python3 tools/check_repository.py --strict
shasum -a 256 <登记的 artifacts.path>     # Linux 使用 sha256sum
```

自检是工具逻辑证据。常规门禁、strict 门禁都不替代角色结论或发布决定。
历史 exploration 记录与未执行设备报告保持历史状态；验收对象必须单独通过严格核验。
参数复验需在对应冻结工作树和环境运行 `verify --check-build-args`，不能拿当前工作树解释旧构建。

## 结论与问题单

审计报告与实机报告都要绑定同一个实例的字节。报告生成时的工具 commit/hash 与产物 source_commit 分开记录。
报告格式检查仅证明字段存在；审计独立性、真实运行和关闭证据由维护者逐项审阅。

问题单的 `owner` 是修复归属，`closed_by` 是独立复核者。维护者只同步已有复核证据，不能替修复归属方关闭问题。
`wontfix` 需说明批准人、影响范围、风险与重新评估触发条件。未执行项不能变成通过。

## 验收记录

追加到模块元数据的 `acceptances[]`：

```json
{
  "instance_id": "<build_id>#<n>",
  "source_commit": "<40 位 SHA>",
  "fingerprint_sha256": "<64 位 SHA-256>",
  "artifacts": { "<产物名>": "<64 位 SHA-256>" },
  "accepted_by": "维护者",
  "accepted_at": "<UTC 时间>",
  "report": "docs/records/<验收记录>.md",
  "scope": "<可交付范围、限制和已批准风险>"
}
```

已有单项 `acceptance` 保持原样，后续验收只追加数组。新候选要有新的验收；历史验收只适用于原实例。

## 交付自足性（克隆即可开工）

`main` 的用途是让别人克隆后直接读交付文件就能改代码或照它新建项目，所以交付树必须**自己站得住**：

- 交付文档里的相对链接必须指向**交付集合内**的文件；指向角色报告、`docs/records/`、`local/` 这类不随仓库发布的内容，一律改成纯文本标注（保留文件名便于检索），不要留链接语法。
- 子模块路径（`KernelPatch/`、`nomount/upstream/nomount/`、`zram_zstd/upstream/zstd/`）可以作为链接存在，但需在一处说明「子模块需 `--recursive` 克隆」。
- 门禁的 `deliverable_links` 检查逐条解析这些链接并给出「存在但不随仓库发布」与「不存在」两类原因；它把「工作树里有、但交付时会被排除」也算失败，所以在 `dev` 上就能提前拦住，不必等到压平。
- 判据不改动角色报告的写作方式：报告照旧不入库，只是文档不得再链接它们。
- **发布件里的版本记录按已交付口吻写**：`CHANGELOG` 的当前版本条目描述本版本实际交付的行为，上游同步能覆盖的改动合并成一句，只单列本仓库特有的契约（CLI 迁移、修复、保留策略）。门禁在 `version_consistency` 里检查首条条目的措辞，技术文档中的同名用词不受影响。

## 发布资产的字节身份

Release 上的配套 ZIP 必须与**已验收实例**逐字节一致：出件工具链与构建参数要和审计时相同，换工具链就等于换了一个未经验证的产物。

- 发版后用下载到的资产跑 `python3 tools/check_release_zip.py <zip>`：内层可执行哈希须命中已登记的 `device-tested` 实例，`module.prop` 版本与条目数须与登记一致。
- 同一检查也进了门禁（`companion_zip_binary`）：本地登记的每个配套 ZIP 都会核对内层哈希与 ELF 可加载性。
- 该约束只针对**用户态可执行**：`.kpm` 是 ELF64 可重定位目标（ET_REL），由 KernelPatch 的内核侧加载器装入，不经 Bionic，因此 NDK 编的 KPM 不受影响；用户态静态链 Bionic 的 `bin/nm` 才受 TLS 对齐约束。
- **Bionic 链接的可执行要求 PT_TLS 段对齐 ≥ 64**；低于该值的二进制在 Android 上会以 `TLS segment is underaligned` 直接 abort（DEV-117：NDK 出的 arm64 件对齐 8，在 Android 17 上装不上；Zig/musl 件不受该检查约束）。

## 交付核验

按 [一轮完整流程](03-round-flow.md) 的 D/E 顺序签名、绑定、保存回执。

```bash
git verify-commit <D>
python3 tools/identity.py verify --module <module> --instance-id '<build_id>#<n>' --profile delivery
python3 tools/check_repository.py --strict
git status --short
```

签名记录字段与实际签名复验都须通过；信任配置不可用时保留记录并停止交付。
回执使用独立的新路径，不能改写构建时封存的 `MANIFEST.json`。

## 验收结论模板

```text
验收对象：完整 commit + instance_id + 产物 SHA-256
复算：命令、输出与工具身份
独立证据：审计报告、实机报告、关键主张复现
问题处置：已关闭项、已批准风险、未决项与触发条件
范围：机型/内核/功能/验证层级与未覆盖原因
结论：接受 / 有条件接受 / 拒绝（附理由）
签名：交付 D、记录 E 与验证结果
```
