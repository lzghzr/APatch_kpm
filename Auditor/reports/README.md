# Auditor 报告目录

| 路径 | 内容 |
| --- | --- |
| `reports/<日期>-<模块>-<版本>.md` | 审计报告（人读），用 `docs/templates/auditor-report.md` |
| `reports/data/<日期>-<模块>-<版本>.json` | `artifact_audit.py` 的机器可读结果 |
| `reports/data/<日期>-<模块>-static_scan.json` | `static_scan.py` 的机器可读结果 |
| `snapshots/kp_runtime_symbols-<commit12>.json` | 平台符号快照（由 `kp_symbols_extract.py` 生成，固定后可复算） |

规则：

1. 报告必须绑定身份三要素，并**分节**区分「独立复现」与「按报告采信」。
2. 每条结论给出可复现命令与实测输出；审查点要写明是「已确认为缺陷」还是「需人工确认」。
3. 报告只追加：修复后的复核结论追加到「复核记录」，不改写原结论。
4. 不要把本机绝对路径、设备序列号、superkey、抓包原文写进报告（门禁会机检）。
5. 审计结论绑定当次审计对象；对象被改写（重签名、重构建）时用 build_id 与 tree 比对说明旧结论是否仍然成立。
