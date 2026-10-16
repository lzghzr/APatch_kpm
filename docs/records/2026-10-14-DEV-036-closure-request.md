# 请求：DEV-036 独立复核关闭

角色：维护者 → Auditor。依据 DEV-036 的 `closure` 条件：「Auditor 独立复核 LSM ABI/生命周期/初始化独占/缓存及 2 条 Oracle 迁移，Tester 绑定 0.5.1 新身份覆盖 Sony 5.15 真实应用和 artd 读取/DEX 加载并回归 4.4、4.19 后，由独立于 Developer 的角色复核关闭。」

## 两部分条件的完成情况

| 条件 | 状态 | 证据 |
| --- | --- | --- |
| Auditor 侧：LSM ABI／生命周期／初始化独占／缓存／2 条 Oracle 迁移 | **已达成** | `Auditor/reports/2026-10-14-nomount-0.5.1-module-audit.md` §3（含 `secid` 校验防静默 unlabeled） |
| Tester 侧：Sony 5.15 真实应用与 artd 读取/DEX 加载 + 4.4/4.19 回归 | **已达成** | 三份 0.5.1 真机报告，各 **20/20**：见下 |

## Tester 侧证据摘要（0.5.1 release 变体，`nomount-0.5.1_baselines+g17d96f6cff64.rf55be15b…#1`）

| 目标 | 派生件 | 关键证据 |
| --- | --- | --- |
| Sony 5.15（Enforcing） | `abe50c72…` | 虚拟 APK 标签与源**严格一致** `u:object_r:system_file:s0`；`cmd package compile -m speed -f` → **`dex2oat returned code 0`、无 `EACCES`**；真实应用域 `u:r:priv_app:s0` 加载执行；`/proc/<pid>/maps` 映射 APK 与编译 DEX 且虚拟路径无泄漏 |
| Sony 4.19 | `eeae3cec…` | ART 编译 + `u:r:untrusted_app:s0` 加载与映射；Enforcing 标签对照；常规回归全量 |
| Nokia 4.4 | `8c50c2cd…` | 同上 |

报告路径：`Tester/reports/runs/2026-10-14-nomount-0.5.1-{5.15,4.19,4.4}-boot-live#1.md`。

## 请求

请 Auditor 独立复核上述设备证据是否满足 DEV-036 的关闭条件；满足则登记 `status=closed`、`closed_by=Auditor`（独立于 owner=Developer），并说明复核依据。**维护者不自行关闭。**

## 边界

- 6.1 仍无实机；dynamic 形态无真机证据；
- 关闭范围仅限 DEV-036 记录的行为结论，不外推到其它机型/内核。
