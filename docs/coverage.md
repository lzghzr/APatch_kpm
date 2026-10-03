# 覆盖矩阵

每项覆盖绑定完整源码提交、构建实例与产物 SHA-256；角色报告只适用于所列字节与环境。维护者本轮整理报告索引，实际结论来自所引用角色。

## re_kernel_x 1.6

冻结源码：`52b303df659616012077bc95ed7899655295d925`。完整实例及产物哈希见 [模块登记](../metadata/modules/re_kernel_x.json)，八份 ABI3/4/5/6 release/debug 基准见 [候选登记](records/2026-10-02-re-kernel-x-1.6-registration.md)。

| 范围 | 验证层级 | 覆盖与证据 |
| --- | --- | --- |
| 八份基准产物重编译、ELF 结构与导入符号 | 独立静态审计 | [Auditor 1.6 报告](../Auditor/reports/2026-10-02-re-kernel-x-auth-audit.md)记录八份哈希一致；平台 SDK 0.13.9 |
| 命名与控制入口 UID 鉴权 | 源码审计、主机测试 | 同一审计报告记录 AUD-001/AUD-002 复核关闭；实现方套件的测试具有同源性 |
| 代码风格修复 AUD-004 | 历史独立复核 | [风格复核](../Auditor/reports/2026-10-02-re-kernel-static-style-verification.md)绑定历史提交 `5c779c9b6cc7de1308d884906c4ddda3f7152c13`，覆盖该次修复 |
| abi5 release/debug 在线存活、UID 矩阵、组播、加载与卸载 | 角色实机报告 | [Tester 1.6 报告](../Tester/reports/runs/2026-10-02-re_kernel_x-1.6_abi5_live-run-1.md)记录 12/12 强判据；单台 Linux 5.15 设备，环境和个人运行信息已脱敏 |
| 本机基准身份 | 已登记基准与实机报告对应 | 用户确认基准偏移对应本轮测试机；ABI5 release/debug 使用在册基准字节。其它目标内核继续按 AUD-003 的偏移核对和适配登记前提执行 |
| ABI3/4/6 实机、长期休眠唤醒、极端压力 | 未覆盖 | 本轮 Tester 报告未覆盖这些范围 |

报告存活与功能判据的结果不能外推到其它内核或设备。基准身份与本机对应关系已由用户确认，维护者验收和签名交付字段按实际状态登记。

## 历史身份

`re_kernel_static` 已迁移为 `re_kernel_x`。其 [历史登记](../metadata/modules/re_kernel_static.json)保留原始构建与问题记录；历史产物继续按各自冻结提交和哈希核验。当前报告清理与验证范围见 [工程整理记录](records/2026-10-03-git-reorganization.md)。

## 其它模块

`re_kernel`、`hosts_redirect`、`cgroupv2_freeze`、`dont_kill_freeze`、`lmkd_dont_kill`、`qti_battery_charger`、`xperia_ii_battery_age`、`xperia_led_brightness_test` 尚未在当前元数据中建立完整候选身份；本表将其标为未验证。

## 更新规则

维护者在每轮交付后更新范围、验证层级与具体身份。静态与实机结论引用对应角色报告；缺少材料的项目逐项说明原因。历史结论保持原有身份边界。
