# 问题单模板

> 复制到对应角色的报告中（Auditor 报告 / 实机报告）并在 `metadata/modules/<module>.json` 的 `issues` 里登记。

```text
<角色前缀>-<序号>（严重度，归属角色）一句话结论
- 证据：可复现命令与实测输出（哈希、计数、异常文本、代码位置 file:line）
- 影响：对用户/交付的实际后果
- 建议：可执行的最小修正
- 关闭条件：由谁、在哪个提交、用什么证据关闭
- 状态：open | fixing | fixed(待复核) | closed | wontfix(需维护者批准)
```

## 字段说明

| 字段 | 要求 |
| --- | --- |
| 编号 | `<前缀>-<三位序号>`，前缀 `DEV`/`AUD`/`TST`/`MNT`，仓库同前缀内不复用 |
| 严重度 | 高 / 中 / 中低 / 低，判据见 [../process/04-issue-ticket.md](../process/04-issue-ticket.md) |
| 归属 | Developer / Auditor / Tester / 维护者 / 环境事实（无归属） |
| 证据 | 必须能被人复跑；代码位置写到 `file:line` |
| 关闭条件 | 写清「谁 + 哪个 commit + 什么证据」 |
| 状态 | 修复者最多置 `fixed(待复核)`；`closed` 由独立复核者给出证据，维护者同步元数据 |

## 元数据登记格式

```json
{
  "id": "AUD-001",
  "severity": "高",
  "owner": "Developer",
  "status": "open",
  "title": "一句话结论",
  "evidence": "复现命令与输出摘要",
  "impact": "实际后果",
  "suggestion": "最小修正",
  "closure": "由 Auditor 在新 Build ID/instance 上重跑 artifact_audit.py 通过后关闭",
  "frequency": "未知",
  "confidence": "推断",
  "found_in_build": "<build_id>#<n>",
  "fixed_in_commit": null,
  "closed_by": null
}
```
