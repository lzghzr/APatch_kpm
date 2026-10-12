# 独立复核请求：维护者工具与判据改动（2026-10-11）

角色：维护者 → Developer。依据 respect-the-oracle 第 3 条（断言变更受控协议），判据与夹具改动须由独立角色复核。

## 复核对象

`git diff origin/main main -- tools/ .agents/ AGENTS.md docs/process/`：

| # | 改动 | 位置 |
| --- | --- | --- |
| ① | 交付判据：模块树与全部构建输入按内容同一性核验；模块目录缺失或查询失败即判失败 | `tools/identity.py` |
| ② | 门禁删除 5 条报告文风/关键词类检查，条目 17 → 13 | `tools/check_repository.py` |
| ③ | `version_consistency`：元数据滞后于源码改为待办提示 | 同上 |
| ④ | 报告类判据合并为 `report_integrity`，区分硬判据与软判据 | 同上 |
| ⑤ | 自检夹具期望值调整与新增（`delivery_missing_module`、`delivery_flattened_history`、报告追加链分档等） | `tools/selftest_tools.py`、`tools/selftest_artifact_gate.py` |

## 需要独立回答

1. 内容同一性是否足以证明「交付的源码＝被审计的源码」；
2. 被删的检查是否有机检能力（可用既有记录验证）；
3. 版本滞后降级是否会掩盖真实矛盾（请构造反例）；
4. 软/硬划分是否把应有硬判据降级；
5. 夹具期望值改动是否存在隐蔽削弱；
6. 是否还有未登记的判据放宽。

## 结果

`DEV-031`（模块树查询失败被当成相等）、`DEV-032`（历史缺提交被当前字节顶替）由 Developer 独立复核关闭；
反例与结论见 `Developer/reports/responses/2026-10-11-DEV-031-032.md` 与 `…-DEV-032-06a371bc.md`。
