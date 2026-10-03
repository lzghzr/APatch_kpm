# Developer 修复响应

问题单由发现方复核关闭。Developer 修复后在这里留一份**修复响应**，不动发现方的报告，也不改 `metadata/` 里的状态字段。

- 命名：`<日期>-<问题编号>.md`，例如 `2026-10-03-AUD-002.md`
- 模板：[docs/templates/developer-response.md](../../../docs/templates/developer-response.md)
- 必填：问题编号、修复 commit、Build ID、证据（命令与输出）
- 流转：Developer 写响应并把问题单置 `fixed(待复核)`（由维护者同步到 `metadata/`）→ **发现方**（Auditor/Tester）
  用新 Build ID 复核后写「复核记录」并关闭 → 维护者更新元数据状态。

规则：

1. 一个响应只对应一个问题单；一条问题单可以有多个响应（修复后又回归）。
2. 响应只追加，不覆盖历史；更正写在新的响应里，注明「后续状态」。
3. 不要在这里写验收结论或审计结论——那是发现方与维护者的事。
