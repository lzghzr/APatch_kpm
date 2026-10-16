# NoMount 0.1.0 首轮审计与测试跟进

角色：Developer。本轮只核对已入库的审计／测试及维护者登记，更新模块说明并提出记录问题。未重编译、未改变候选代码、未操作设备；以下复核不替代 Auditor 或 Tester 的结论。

## 已收到的记录

源码为 `c35ecd34ecb6a06c1d54ebda6e6a0e900065f16a`。Auditor 报告 `Auditor/reports/2026-10-13-nomount-0.1.0-module-audit.md` 的 SHA-256 为 `1725db60c9fd363d0421f0f4500ed1d6cd93d1c344c5f2f6111ecebb1f3268a1`，记录四份候选重编译与两份目标派生件字节一致，未发现阻塞性代码缺陷。审计登记引用该报告，读取后复算哈希一致。

| 4.19 实测变体 | base instance_id | 实测派生 SHA-256 |
| --- | --- | --- |
| 普通 | `nomount-0.1.0_baselines+g5dd2d5ca48b7.rde831ef7.kpb51197a.ndk26.3.11579264#1` | `a3694526cac5c4cef05fd6b5326790101513f42c31094203c648618898ba7dcb` |
| debug | `nomount-0.1.0_baselines_debug+g5dd2d5ca48b7.rba92ba97.kpb51197a.ndk26.3.11579264#1` | `606ebed60723b116eb31f4cd3557b905fb76763e03d30422c2d030bab4d6e7f7` |

Tester 报告：

- `Tester/reports/runs/2026-10-13-nomount-0.1.0-4.19-boot-live#1.md`（debug）：SHA-256 `db2e02b077302caef00cac0b9fe4249f862285c9b024751b12c99b9eed5dbc4c`。
- `Tester/reports/runs/2026-10-13-nomount-0.1.0-4.19-boot-live#2.md`（普通）：SHA-256 `0b8f5d4b2de5dc36621713cd7d73a306ae8fdc281e7abeff7c1161d445d1b71b`。

报告和当前归档派生件复算哈希均与维护者登记一致。两次报告各记12/12，观察期超过240秒，覆盖开机加载、版本／状态查询、root 视角文件读取、目录枚举、规则撤销和常驻。设备为 Sony Xperia 1 II，目标内核 `4.19.325-cip134-st18-perf-g7fc8455b2fa8`，SELinux Enforcing。维护者已登记验收，deliveries 仍为空；版本声明已同步0.1.0，上一轮版本登记补丁已落实。

## 复核决定（Decision）

**修改（Modify）**：模块说明更新为已有基础 VFS 实测；CFI 的记录判据交回原角色补证或更正。

### 有效性

测试里的 `test_app.apk` 和 `app.apk` 分别读出26字节和9字节文本内容。它们证明文件视图可以枚举和读取，不能证明 PackageManager 接受真实 APK、扫描后注册包或应用进程成功启动。两份报告也未覆盖非 root／UID 隔离访问，README 保留这些未验证项。

CFI 的两份实测摘录只有 `KP bypass_kcfi done: 0`。在编译 SDK `b51197aaba8f2272dd8a3e30c85698a29aa928c9` 的 `KernelPatch/kernel/patch/common/secpass.c:49-105` 中，目标 slowpath 地址为空时仍可返回0；此汇总行单独不能证明实际挂接。审计要求的 `hook __cfi_slowpath_diag: ..., error: 0` 也不由该 SDK 的成功分支输出：第90行的日志在 `if (err)` 内。实际运行 KP 仅记作 d09，尚需可核对的构建身份或对应源码。当前已读报告没有提供足以消除该差异的直接证据；不据此断言实际 hook 失败。

### 简洁性

保留冻结候选和基础 VFS 实测记录。补证优先使用已有运行日志及实际 KP 的地址／分支证据；由报告作者追加说明，并经独立复核。无需为记录缺口修改生产代码或重新构建候选。

### 后果

将文本占位文件读通外推为应用安装成功，会掩盖系统扫描、SELinux 与应用进程读取的边界；把汇总返回值当作 CFI 挂接证据，会使其他目标加载前检查失效。记录问题不会抹去已有 VFS 实测，也不构成对其存活事实的否定。模块继续按 RA-002 常驻，设备现场保持原样。

## 正式记录问题

### DEV-033（中，归属 Tester）CFI 成功判据缺少直接证据

- 类别：record；状态：open；frequency：两份报告各出现一次；confidence：已确认记录证据不足，实际 CFI 状态待补证。
- 证据：上述两份实机报告的 CFI 判据和日志摘要仅列 `bypass_kcfi done: 0`；对照冻结 SDK secpass.c 的无地址返回0路径。
- 影响：无法据当前摘要核对加载前已满足 slowpath 挂接前提；相关12/12计数中的CFI项目需要作者解释。
- 建议：绑定实际 KP 的构建身份，补充该次运行已有的目标地址解析／挂接结果证据；若无法取得，追加更正为未验证并同步计数。普通和debug的运行证据分别绑定，不自动互相继承。
- 关闭条件：Tester 追加更正并提交后，由 Developer 或 Auditor 独立核对运行身份、日志及计数，维护者登记关闭。不得只用汇总返回值或另一轮日志关闭。

### DEV-034（中，归属 Auditor）CFI 日志要求与引用 SDK 的输出分支不符

- 类别：record；状态：open；frequency：审计报告3.5节一处；confidence：已确认冻结 SDK 的分支行为，实际运行 KP 版本待核对。
- 证据：审计3.5节要求 `hook __cfi_slowpath_diag: ..., error: 0`；冻结 SDK secpass.c:87-93 的日志只在 err 非零时输出。__cfi_slowpath 和 diag 共用该日志标签，标签本身也不能确定选中的符号。
- 影响：按该 SDK 成功路径执行也无法产生所要求的日志，判据无法复现。
- 建议：追加与实际 KP 相符、可以取得的挂接证据要求；分别说明源码分析、地址解析、挂接成功和真实 VFS 调用的证明范围。
- 关闭条件：Auditor 提交追加更正，由 Developer 独立核对冻结 SDK／实际 KP 的分支与修订判据，再由维护者同步关闭；既有原文保留。

[问题登记提案](../proposals/2026-10-13-nomount-cfi-records/README.md) 提供结构化条目，供维护者追加到 issues。Developer 不直接改 metadata 或他人报告，也不自行关闭以上问题。

## 后续安排与检查

先补齐本轮 CFI 记录，并由 Tester 验证真实 APK 的扫描、启动和非 root／UID 访问。随后按既定顺序推进4.4，再做5.15；新目标仍由该目标的布局和接口证据取得配置。签名交付由维护者处理。

按 are-you-sure 完成上述有界挑战，按 no-negative-echo 回读最终说明，按 respect-the-oracle 保留已有报告、候选与断言。本轮仅进行身份哈希、源码分支和文档核对，不产生新的真机结论。

常规仓库门禁13项：0失败、1项既有警告（zram_zstd 历史派生清单缺 handoff_by／handoff_at）。新文档的相对链接与公开文件内容另行回读；冻结生产输入保持原字节。

## 后续状态：2026-10-13 独立复核关闭

Developer 已复核 Tester 的 `2eb1f31cc948c70b2318aa006d0c89063224f172` 与 Auditor 的 `c5d10800aeff4cbca3ba204936580289cbfd1ae5`，报告只追加关系、目标预设和计数核对通过。**DEV-033、DEV-034 均为 closed，closed_by=Developer**；维护者同步元数据。详见 [关闭记录](responses/2026-10-13-DEV-033-034-close.md)。

普通静态派生件的非 root／UID 应用侧补测已由 Tester 记录12/12；PackageManager 扫包及新应用启动仍按未覆盖保留。原问题及当时状态原文保持不变。
