# NoMount 容量探索：审计与测试后的开发跟进

本轮审计和定向实测已完成。5.15 的 BTF 动态路径加载及功能回归通过；4.19 验证了容量策略启用后因复制尺寸缺失而拒绝加载，尚未进入运行态。本轮仍是探索构建。

## 绑定身份

- 源码提交：`7e668af2213d78a4e7cbb0c72bc9f5660678403d`。
- 动态实例：`nomount-2.1.1-20261014+g875b16f95083.r130c2158.kpb51197a.ndk26.3.11579264#1`。
- KPM SHA-256：`24efeb02dd0b89283aca40f768d59203cada3aaaf3d4fe0811e3b35e7f7c9f63`；本次重新读取归档文件核对一致。
- 报告复核基点：`267faae96b20f14ece4c986703abcd7eb233f1aa`。

输入报告及本次读取的 SHA-256：

| 报告 | SHA-256 |
| --- | --- |
| [独立审计](../../Auditor/reports/2026-10-15-nomount-owned-operation-capacity-audit.md) | `7ca0625509475dd04088257d0808d5aea6e4a21f06eb6ec4afecdf38a6da6c23` |
| [定向实测](../../Tester/reports/runs/2026-10-15-nomount-owned-operation-capacity-live%231.md) | `b04d3b6f46b368c64888cefa4eaa78dab5cee803b8f1687806332d3239952dc1` |

## 4.19 的执行范围

实测日志中的 `owned zero-table capacity=512` 证明容量策略已启用。随后返回 `-ENOENT (-2)`。冻结源码的调用顺序为：

`nm_prepare_control_engine → nm_prepare_backing_queries → nm_prepare_path_rules → nm_prepare_directory_view → nm_prepare_materialization → nm_prepare_operation_sizes`。

`nm_operations.c:14-18` 依次检查操作表尺寸；file 已得到 296，遇到未知的 inode 尺寸即返回。super、dentry 尺寸也尚未取得，但本次循环首先停在 inode。该检查没有分配操作表。

`nm_control_entry.c:16-22` 要求 backing 准备成功，才执行控制布局校验、管理锁准备和 key 注册。因此本次 4.19 没有执行控制布局校验及 key 对象分配。测试报告第 79 行的“Key 对象的分配与控制布局校验顺利通过”和第 124 行相应归因超出了执行范围，已提出 [DEV-041](../proposals/2026-10-15-nomount-capacity-followup/issues.json)，请 Tester 追加更正；原日志和诊断结果继续保留。

本次核对了上述六个入口及操作表文件，均与绑定源码提交逐字节一致。没有重新构建或操作设备。

## 后续开发边界

独立审计认可本轮作为探索件，但维护者登记的 `AUD-001` 仍未修复：已核对声明小于 512 字节，不能证明未知厂商扩展也受此上界约束。5.15 使用 BTF 精确尺寸，其通过结果也不能覆盖无 BTF 的容量分支。

完整无 BTF 候选仍需取得 inode、super、dentry 原表的可信复制范围，处理未知布局的容量上界风险，再提供 4.4 所需的二进制兼容派生件。之后重新冻结并交独立审计及 4.19、4.4 实测。本次只跟进报告事实，不改变实现或问题关闭状态。

## 复核决定（Decision）

**修改（Modify）**：修正测试覆盖范围的表述，保留本轮实测证据。

### 有效性

绑定源码和日志足以确认 4.19 的拒绝阶段；5.15 的加载、通信及功能结果由 Tester 报告支持。当前证据不支持完整无 BTF 动态加载成功。

### 简洁性

采用一次报告追加更正及一次独立确认即可。无需为修正文案重建 KPM 或重复设备测试。

### 后果

更正后可避免把尚未执行的控制路径当成通过项。`AUD-001` 和三类复制范围仍作为后续候选的开发约束。

本次 respect-the-oracle 核对没有改动测试或断言；no-negative-echo 回读本报告与提案，保留事实判定必需的引用和限制。
