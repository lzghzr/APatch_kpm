# Tester 报告目录

| 子目录 | 放什么 | 命名 |
| --- | --- | --- |
| `environments/` | 预检采集的环境事实 | `<日期>-<设备指纹8位>.md` |
| `runs/` | 一轮实机测试报告 | `<run_id>.md`（自动骨架使用 `<日期>-<模块>-<产物基名>#<n>`） |
| `escalations/` | 死机/卡死升级单 | `<run_id>.md`（`run_test.sh` 生成骨架，冲突时保留旧证据并记录实际路径） |
| `responses/` | Tester 自有工具或流程缺陷的修复响应 | `<日期>-<问题编号>-<轮次>.md` |

规则：

1. 报告用 `docs/templates/tester-report.md`；升级单用 `docs/templates/escalation.md`。
2. 每份报告必须绑定身份三要素（commit + Build ID + 产物 SHA-256）与设备指纹哈希；不得写入明文序列号、superkey、抓包原文。
3. 报告只追加，不覆盖旧结论；更正写在「后续状态」小节里。
4. 「真机未执行」也必须留一份记录（说明原因、未覆盖清单、何时补测），不允许用沉默代替结论。
5. 报告模板的固定小节（身份 / 环境事实 / 判据与计数 / 未覆盖）由门禁 `tools/check_repository.py` 机检。

## 维护者流程记录：修复响应

修复响应使用 [tester-response.md](../../docs/templates/tester-response.md)，目录约定见 [responses/README.md](responses/README.md)。响应由 Tester 追加，维护者同步问题状态；独立复核与关闭遵循问题单条件。实机报告沿用以上身份与设备判据，工具修复响应单独检查工具身份、自检层级与复核请求。
