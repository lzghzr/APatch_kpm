# Auditor（独立审计）

Auditor 用自己的工具重解析产物字节、重构造夹具，产出**绑定身份的结论**与带严重度、归属的问题单。
独立性不等于另写一份代码，而在于**不共享结论来源**。

- 手册：`docs/process/auditor-handbook.md`
- 问题单格式：`docs/process/04-issue-ticket.md`、模板 `docs/templates/issue-ticket.md`
- 审计报告模板：`docs/templates/auditor-report.md`

## 目录

```text
Auditor/tools/kp_symbols_extract.py   从 KernelPatch submodule 提取平台可解析符号快照
Auditor/tools/artifact_audit.py       自带 ELF64 解析器：身份复算 + 结构 + 符号可解析性 + 跨版本依赖
Auditor/tools/static_scan.py          边界扫描 + 安全评估（启发式，产出审查点）
Auditor/snapshots/                    平台符号快照（含 KernelPatch commit，生成后固定）
Auditor/reports/                      审计报告与机器可读结果
```

## 常用命令

```bash
python3 Auditor/tools/kp_symbols_extract.py                 # 平台符号快照
python3 Auditor/tools/artifact_audit.py --module re_kernel  # 产物独立审计（非 0 退出 = 有阻塞项）
python3 Auditor/tools/static_scan.py re_kernel --strict     # 边界/安全审查点
python3 Auditor/tools/kallsyms_extract.py --scan-local      # 独立 kallsyms 提取（判定镜像含/不含符号表）
```

`artifact_audit.py` 的审计对象**不只来自维护方登记表**：默认同时独立扫描 `artifacts/**/*.kpm`，
报出「未登记产物」「与已登记产物字节相同的副本」「登记了但不在场」。用 `--artifacts-dir` 改/加扫描目录，
`--strict-unregistered` 让「存在未登记字节」直接返回非零（见 `AUD-010`）。

`kallsyms_extract.py` 是 **O2/AUD-018** 的独立实现：**不调用 `kernel_img/offset_harness`**、不导入 `tools/*`，
自解析裸 arm64 Image 的 token 表 / markers / names 三段，并要求 markers 逐项吻合才判定「含 kallsyms」。
输出每镜像的「符号数 / 提取模式 / 失败原因」，供覆盖矩阵从 `SKIP（未覆盖）` 改成确定取值。
注意：**签名法的负结果不等于"内核不含 kallsyms"**，报告必须写明方法范围（见 AUD-018）。

## 禁止事项（门禁会机检）

- 导入或调用 `tools/identity.py`、`kernel_img/offset_harness` 作为结论来源；
- 用 Developer 的构建断言、模块日志、自检输出充当审计结论；
- 直接修改模块源码（发现问题只提问题单，交回 Developer）。

## 必须声明

1. **同源风险**：哪些结论依赖了与实现方同源的来源（语料、镜像、同一份源码）。
2. **未验证清单**：哪些结论需要真机或目标内核源码才能判定。
3. **限制结论的环境事实**：语料缺失、SELinux 策略、设备接收率等。

## 问题单归属

`AUD-xxx` 由 Auditor 复核关闭：Developer 修复并置 `fixed(待复核)` 后，Auditor 在新 Build ID 上重跑相关检查并写明关闭证据。
