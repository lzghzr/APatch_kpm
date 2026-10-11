# run_cmd 基线的维护者接入建议

模块版本为 1.3.0。Developer 已提供独立 Makefile 的 static/dynamic 普通与 debug 产物、schema 3 静态 JSON、模块 AGENTS 与自检。维护者补丁更新模块版本声明和两份项目技能的接入清单，不改旧构建记录或角色结论。

现有 Actions 的 `all debug` 目标可生成四份 KPM 和两份静态 JSON。完整的双模式发布、模式门禁、布局文件校验与身份 CLI 变体支持继续按 [双模式构建建议](../2026-10-10-kpm-modes/README.md) 接入，并将 run_cmd 纳入相同规则；其布局校验需支持不含 Binder ABI 的 schema 3。当前仓库通用门禁仍只对 ReKernel-X 专门核对布局，不能将其通过视为 run_cmd 静态 JSON 已获独立验证。

共享替换工具的 schema 3、旧 schema 1/2 回归和本轮产物身份见 [开发报告](../../reports/2026-10-10-run-cmd-baselines.md)。README 写法是用户习惯，已落在用户记忆区域；项目开发标准保存在 Developer/README.md 与 run_cmd_demo/AGENTS.md。
