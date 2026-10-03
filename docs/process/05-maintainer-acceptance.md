# 维护者验收与签名交付

验收针对具体构建实例。维护者复算关键证据，确认其强度与覆盖范围，再决定接受、拒绝或带明确范围的风险接受。

## 验收清单

```text
[ ] 对象为完整 source_commit + instance_id + 每个产物 SHA-256
[ ] 指定实例通过 candidate 核验；源码、工具链、参数、构建事务可复核
[ ] 独立审计报告包含重编译/字节解析、边界、安全、同源风险与未覆盖项
[ ] Tester 报告区分真机结果、mock 自检、未执行；判据和脚本身份完整
[ ] 关键主张由维护者复现；引用报告的部分标明来源和未独立复现原因
[ ] 当前版本声明自洽；历史产物按其所属构建版本核对
[ ] 阻塞问题已独立复核关闭，或由维护者书面批准风险范围及恢复触发条件
[ ] 未因过门禁缩小断言、用例或检查范围；判据变更有理由与复核记录
[ ] 新验收条目追加到 acceptances[]，与实例的 commit、指纹、产物哈希一致
[ ] 交付提交与标签签名有效，交付源码与候选构建输入一致
[ ] deliveries[] 绑定已追加，指定实例通过 delivery 核验
[ ] 绑定与回执索引保存在后续签名提交；主副本的提交、标签、对象一致
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

## 交付核验

按 [一轮完整流程](03-round-flow.md) 的 D/E 顺序签名、绑定、保存回执。

```bash
git verify-commit <D>
git verify-tag <module>-<版本>
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
签名：交付 D、记录 E、标签与验证结果
```
