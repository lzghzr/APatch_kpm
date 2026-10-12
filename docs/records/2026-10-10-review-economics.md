# 复核经济学落地记录（门禁三条新判据 + 问题分类 + 报告版本索引）

维护者；2026-10-10。本记录保存本轮流程优化的**理由、变更内容、正反回归与覆盖范围**。
规则正文见 [docs/process/08-review-economics.md](../process/08-review-economics.md)。

## 起因与成本证据（zram_zstd 0.1.0 一轮）

| 维度 | 数量 |
| --- | --- |
| 自研代码 | 567 行 |
| 流程往返文本 | 1035 行（审计报告 239、复核报告 132、登记记录 392、请求 164、回执 108） |
| 元数据/文档改动 | 22 个文件、8829 行插入 |
| 提交 | 6 个，其中代码提交 2 个 |
| 问题单 | 4 张，其中记录类 3 张（引用标识笔误、报告字节改写、回执计数） |

真实事故链：维护者把 KernelPatch 写成 `b51197aba`（不可解析）→ 开 `MNT-014` → 一轮复核；
报告在登记后被原位改写 → 开 `MNT-013` → 三轮判据调整；Auditor 回执计数错误 → 开 `DEV-030`。
三张记录类问题串行占用了一整轮迭代预算，而模块代码本身只有一次修复。

**一处更正**：本记录初稿曾把「三角色由同一主体扮演」列为根因，**该判断有误并已撤回**。
三角色由三个独立智能体承担，角色隔离成立；被优化的是往返耦合，不是独立性。

## 变更内容

### 1. 门禁三条新判据（`tools/check_repository.py`）

| 判据 | 规则 | 模式 | 本轮若已有此判据 |
| --- | --- | --- | --- |
| `identity_tokens` | 结构化提交字段（`*_commit`、`commit`）必须可解析；KernelPatch 字段在子模块对象库核验 | 失败即失败 | `b51197aba` 当场被拦，`MNT-014` 不会发生 |
| `report_versions` | 报告字节身份：现行字节须以入库原文为完整前缀、逐段追加哈希吻合、最新版本等于工作树、索引哈希须是已知版本（含 `unarchived_versions[]`） | 失败即失败 | 登记后改写当场被发现，`MNT-013` 的一半消失 |
| `report_versions_coverage` | 未纳入版本索引的历史模块记录 | 提示 | — |
| `report_version_commits` | 版本索引中除当前版（须标 `pending_commit`）外，每个版本必须引用提交；字节确失者登记 `unarchived_versions[]` 并写 note | 常规提示，验收/交付失败 | 未落盘的历史版本（本轮 v1/v2/v3）在制度上无法登记 |
| `referenced_reports_archived` | 被引用报告须已入库且与工作树一致（先入库再引用） | 常规提示，验收/交付失败 | 引用未归档字节的行为被显式标注 |

### 2. 问题分类（`class`）与关闭成本分级

- `product`：完整独立复核链（不变）。
- `record`：owner 一次更正 + 一次独立确认即关闭，同轮批量；已关闭的 `record` 单必须带 `reviews[]`（门禁校验）；
  `closed_by != owner` 依旧强制。
- 已登记字段约定：`metadata/identity.json` 的 `conventions.issue_classes`/`issue_class_rule`/`record_issue_closure`；
  模板与规则同步在 [04-issue-ticket.md](../process/04-issue-ticket.md)、
  [templates/issue-ticket.md](../templates/issue-ticket.md)、[metadata/README.md](../../metadata/README.md)。

### 3. 报告版本索引取代「整份哈希恒定」

`report_versions[]`：`append_only_baseline`（入库提交 blob）+ `versions[]`（只追加版本、追加段哈希、入库后提交）
+ `unarchived_versions[]`（已知但字节未保留的历史版本，如实登记，使历史引用可校验）。
本仓库首个使用者为 `metadata/modules/zram_zstd.json`（2 份报告：模块审计报告 5 版、AUD-008 回执 2 版，
其中 3 版字节已不可恢复）。

### 4. 交接即提交（R8）与角色检查点提交

三角色可在**自己拥有的路径**内创建无签名检查点提交（`git commit --no-gpg-sign -m "checkpoint(<角色>): <产物>"`），
产出即提交；边界为不 `tag`/`push`、不 `checkout/restore/reset/stash/clean`、不提交他人文件，
交付级签名提交 D 与标签仍只由维护者产出。改动落在
[02-roles.md](../process/02-roles.md) 的「角色检查点提交」「Auditor 版本控制」两行、
[03-round-flow.md](../process/03-round-flow.md) 第 0.5 节，规则正文见
[08-review-economics.md](../process/08-review-economics.md) R8。

配套判据 `report_version_commits` 使「未落盘的版本」在制度上无法登记——本轮的 v1/v2/v3 若在规则生效后发生，
只能登记为 `unarchived_versions[]` 并写明丢失原因。

### 5. 增量复核档位与批量更正窗口

`incremental` 档写进 [01-identity.md](../process/01-identity.md) 档位表：复核范围可限定为修复 diff +
受影响节区/判据 + 受影响实例，其余显式声明「未重做」。批量窗口与「先入库再引用」写进
[03-round-flow.md](../process/03-round-flow.md) 第 3 步。

## 正反回归（`tools/selftest_tools.py`）

新增四组夹具，共 25 项全部通过：

```text
[PASS] identity_tokens      {'真实提交通过': True, '本仓不存在提交被拒': True, '子模块不存在提交被拒': True, '非十六进制被拒': True}
[PASS] report_versions      {'纯追加版本通过': True, '未登记的追加被拒': True, '改写原文前缀被拒': True, '索引哈希非已知版本被拒': True}
[PASS] referenced_reports_archived {'已入库引用通过': True, '未入库引用在严格模式失败': True, '常规模式仅提示': True}
[PASS] report_version_commits {'基线有提交+当前待提交通过': True, '历史版本缺提交被拒': True, '当前版未标待提交被拒': True, '常规模式仅提示': True, 'unarchived 缺说明被拒': True}
```

实现过程中夹具先暴露了三个自身缺陷（判据按工作目录取路径、遍历器不产出标量叶子、版本哈希收集过宽），
均已修正——这正是"判据必须先有反例"的价值。

## 覆盖范围与已知限制

- 三条新判据**只施加于纳入 `report_versions[]` 的记录**；7 个历史模块记录保持原形态，门禁以提示列出。
- `identity_tokens` 只检查结构化字段，不检查散文里引用的标识（如报告正文中的 SHA）；散文引用仍靠人核。
- `referenced_reports_archived` 在常规模式为提示：本仓库当前允许"先改后提交"的工作方式，
  验收/交付时升级为失败。
- 未改动任何高风险项判据：独立复核、身份绑定、"未覆盖不得写成通过"、产物不可覆盖、断言不得因过门禁放宽。

## 未决与下一步

- 门禁变更需随本轮元数据一并入库（当前工作树含 Auditor 追加段、Developer 第二轮回执与本记录）。
- 下一步按 [08-review-economics.md](../process/08-review-economics.md) 的 R3/R4 执行：
  报告入库后再引用、更正批量处理；本轮剩余待办为 `MNT-013` 的一次确认与真机/交付推进。
