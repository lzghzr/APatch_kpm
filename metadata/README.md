# 元数据（维护者所有）

本目录登记身份、归属与结论索引。每个实例由完整 source_commit、instance_id 和产物 SHA-256 定位。

| 文件 | 内容 |
| --- | --- |
| `identity.json` | 流程、路径所有权、平台依赖、判据与约定 |
| `modules/<module>.json` | 当前版本声明、只追加的构建/验收/交付、独立报告索引与问题状态 |

## 模块记录结构

维护者在首次受控登记或导入前建档；版本声明随当前源码更新，旧构建记录保持原样。

```json
{
  "module": "<module>",
  "status": "candidate",
  "version_declared": "<version>",
  "version_sources": { "makefile": "<version>", "readme_heading": "<version>" },
  "builds": [],
  "audits": [],
  "device_tests": [],
  "issues": [],
  "acceptances": [],
  "deliveries": []
}
```

## 构建条目

`builds[]` 通过受控工具追加，同时更新登记人和时间。条目包含：

- `build_id`、`instance_id`、`fingerprint_sha256`：配方与具体实例。
- `source_commit`、`source_dirty`、`kind`：构建源码、干净状态、candidate 或 exploration。
- `sources`、`source_tree_sha256`、`source_tree_blob_sha256`：输入文件与两种字节表示。
- `kernelpatch_commit`、`toolchain`、`recipe`：平台、编译器字节 SHA-256、有效参数与返回码。
- `build_transaction`：统一构建入口的提交/源树/平台/配方绑定、构建成功和输入未变证据。
- `artifacts`：文件名、归档相对路径、SHA-256、大小与内嵌元信息。

工具核验按记录绑定的提交执行。候选必须走统一构建入口，直接 `record --kind exploration` 用于探索。
探索记录保留其边界，不能被候选核验、验收或交付采用。

## 报告与问题索引

`audits[]`、`device_tests[]` 指向角色报告，注明 instance_id、完整 commit、产物哈希、验证范围和结论。
继承的历史索引保持历史形态；新增索引使用规范实例名。
`issues[]` 使用仓库同前缀唯一编号，severity 按影响，frequency/confidence 分别记。
关闭证据须来自独立于 owner 的角色，由维护者同步状态；流程工具问题也要注明所验证工具的 commit/hash。

`issues[].class` 决定关闭成本（规则见 [复核经济学](../docs/process/08-review-economics.md)）：

- `product`：代码/产物/安全/身份/构建事务，走完整独立复核链（不变）。
- `record`：报告措辞、计数、索引、元数据文字；owner 一次更正 + 一次独立确认即关闭，同轮批量处理。
  已关闭的 `record` 单必须带 `reviews[]` 一次确认记录（门禁校验）；`closed_by != owner` 依旧强制。
- 两个类别都必须留痕（更正前后文字与哈希）。低风险不等于静默消失，只是轮数为 1。

## 验收与交付

- `acceptances[]` 只追加，绑定 instance_id、source_commit、fingerprint_sha256、产物哈希、验收人/时间与范围。
  已有单项 `acceptance` 保留并一起核验。
- `deliveries[]` 只追加，保存同一实例的源码、指纹、产物、签名交付提交 D、标签与绑定人/时间。
  核验复算签名并核对交付源码与候选一致。
- `status`、当前版本声明与角色结论索引由维护者维护，登记器不会提升状态或更新版本声明。

完整规则见 [身份与可追溯性](../docs/process/01-identity.md)，签名与回执顺序见
[一轮完整流程](../docs/process/03-round-flow.md)。人工更正结论字段需同步 updated_at/updated_by，并追加维护者记录。
公开文件使用仓库相对路径与脱敏摘要。

## 报告版本索引

`report_versions[]` 只追加，记录每个被引用报告（审计报告、复核报告、回执）的字节身份：

- `append_only_baseline`：原文基线——`sha256`/`size` 与入库 `commit`；该前缀**不可改写**。
- `versions[]`：每次追加登记新整份 `sha256`、`size`、追加段 `added_sha256`/`added_size`，以及入库后的 `commit`
  （尚未提交时留 `commit: null` 并在交付前补登）。
- 判据：现行字节必须以基线为**完整前缀**、每段追加哈希吻合、最新版本等于工作树字节；索引字段引用的报告哈希
  必须是版本表中的已知版本。
- 除「当前工作树这一版」（须标 `pending_commit`，提交后补登 `commit`）外，**每个版本都必须引用提交**；
  字节确实不可恢复的历史状态登记在 `unarchived_versions[]` 并写明 `note`。门禁 `report_version_commits`
  常规模式提示、验收/交付模式失败（规则见 [复核经济学](../docs/process/08-review-economics.md) R8）。
- 与「整份哈希恒定」的区别见 [复核经济学](../docs/process/08-review-economics.md)：后者与授权追加更正自相矛盾。

引用报告必须**先进提交再被引用**；`referenced_reports_archived` 在常规模式提示、验收/交付模式判失败。

## 风险接受

`risk_acceptances[]` 只追加，登记维护者**书面批准**的风险接受，使「已知但不能（或暂不）通过代码消除」的风险
不静默消失（见 [问题单规则](../docs/process/04-issue-ticket.md)）。每条包含：

- `id`（`RA-<三位序号>`，仓库范围内单调递增）、`module`、`risk`：风险事实与可触发路径。
- `severity` 与 `severity_basis`：**按影响定级**，不因缓解手段有限或频率未知而降级。
- `approved_by`、`approved_at`、`approval_scope`：批准人、时间与适用范围（模块/版本/候选集/平台框架 commit）；
  超出范围即不再适用。
- `rationale`、`mitigation`：为何无法消除、现有哪些缓解与使用约束。
- `recovery_triggers[]`：重新评估或撤销该接受的触发条件。
- `evidence`、`recorded_by`：风险来源报告（含哈希与章节）与登记人。

风险接受**不降低**定级，也不等于问题关闭；若来源报告对同一事项另有相反定性，仍需相应角色统一后由独立角色复核。
本条不替代问题单：需要跟踪修复的问题仍开 `issues[]`。

## 维护者记录

`maintainer_records[]` 只追加，记录不属于 `builds[]`/`acceptances[]`/`deliveries[]` 的维护者事实与索引，
例如本轮登记范围、报告索引、归档位置与未决项。每条含 `at`、`by`、`scope`；涉及的实例身份照原值引用，
不改写构建条目。

- `baseline_layouts[]`：`baselines` 变体的布局 `.kpm.json` 归档索引，逐条记 `instance_id`、`path`、`sha256`/`size`
  与布局内嵌的 `kpm_sha256`。布局随 `.kpm` 放进 `artifacts/<instance_id>/`，不覆盖封存的 `MANIFEST.json`。

## 已迁移模块的历史登记

源码目录迁移后，旧记录设置 `status: archived` 与 `superseded_by`，指向已登记且有源码的现行模块。历史 `builds[]`、实例、提交与产物哈希保留原值。历史名称门禁从每条构建绑定的冻结源码读取唯一 `KPM_NAME`；提交不可读取、注册名不符、旧目录仍在场或替代模块无效时均拒绝。当前模块继续要求产物注册名与模块名一致。全部历史产物仍参与身份与哈希核验。
