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

## 验收与交付

- `acceptances[]` 只追加，绑定 instance_id、source_commit、fingerprint_sha256、产物哈希、验收人/时间与范围。
  已有单项 `acceptance` 保留并一起核验。
- `deliveries[]` 只追加，保存同一实例的源码、指纹、产物、签名交付提交 D、标签与绑定人/时间。
  核验复算签名并核对交付源码与候选一致。
- `status`、当前版本声明与角色结论索引由维护者维护，登记器不会提升状态或更新版本声明。

完整规则见 [身份与可追溯性](../docs/process/01-identity.md)，签名与回执顺序见
[一轮完整流程](../docs/process/03-round-flow.md)。人工更正结论字段需同步 updated_at/updated_by，并追加维护者记录。
公开文件使用仓库相对路径与脱敏摘要。

## 已迁移模块的历史登记

源码目录迁移后，旧记录设置 `status: archived` 与 `superseded_by`，指向已登记且有源码的现行模块。历史 `builds[]`、实例、提交与产物哈希保留原值。历史名称门禁从每条构建绑定的冻结源码读取唯一 `KPM_NAME`；提交不可读取、注册名不符、旧目录仍在场或替代模块无效时均拒绝。当前模块继续要求产物注册名与模块名一致。全部历史产物仍参与身份与哈希核验。
