# KPM 构建整理与 NoMount 0.5.2

NoMount、zram_zstd、run_cmd_demo 当前代码均未使用 CONFIG_DEBUG。三者的 Makefile 现在只生成动态、静态两种产物。NoMount 的 KPM 管理名和文件前缀统一为 `NoMount`，初始化、偏移及错误信息由 `nm_log_info` / `nm_log_error` 输出，保留 INFO / ERR 等级与诊断内容。NoMount 版本为 0.5.2；zram_zstd 和 run_cmd_demo 的普通版行为及版本保持原样。

ZIP 的内部 ID 和 keyring 控制接口仍为 `nomount`。上游子模块是 ZIP 的实际构建输入：用户态 nm、WebUI、路径脚本与许可证均取自冻结 Git 提交。KPM C 编译不包含上游 LKM，用户安装成品也无需 Git。当前保留子模块以复现配套 ZIP。

## 冻结候选

共同 source_commit：`6b870aa8bcfdc4523709bf7baa9d377fcb3744fa`。

KernelPatch：`b51197aaba8f2272dd8a3e30c85698a29aa928c9`；工具链标签 `ndk26.3.11579264`。三者均通过 `tools/build_candidate.py`，目标为 `all`，捕获 `patch_offsets.py` 额外输入；从干净冻结提交生成并归档新实例。

| instance_id | KPM SHA-256 |
| --- | --- |
| `nomount-0.5.2+g67d57610fbb3.r82344ba9.kpb51197a.ndk26.3.11579264#1` | `3ee86ab682f1c8ce55ffc6bbdd6fe03eb05c056b79228a0a165c5129cccf4997` |
| `nomount-0.5.2_baselines+g67d57610fbb3.rdcd5f4e5.kpb51197a.ndk26.3.11579264#1` | `3f42d66a0da0eadf8d13c029594744505f9572e850a7c3d4648e01df825c5d40` |
| `zram_zstd-1.0.0+g1a0ddbecc272.r8522990d.kpb51197a.ndk26.3.11579264#1` | `3a91f9631c2dba8dde5616512333ce17ca262f934ed6f76cfafb2b6ff7f25e10` |
| `zram_zstd-1.0.0_baselines+g1a0ddbecc272.r79955c1f.kpb51197a.ndk26.3.11579264#1` | `f90d2e1713e6aa1f8c6329571ee6df9f8c5970899382b1a7a76f132677646f88` |
| `run_cmd_demo-1.3.0+g43485f3f6b9d.r12d3dc50.kpb51197a.ndk26.3.11579264#1` | `caf3ada14a6e2fbaabb9c8b439f7e7c9613c12ffabc54b6f5fdb3a144ca1d178` |
| `run_cmd_demo-1.3.0_baselines+g43485f3f6b9d.rc619670d.kpb51197a.ndk26.3.11579264#1` | `e2daa67ebb34a423c3e8f62c4aa947ae2cc1a602c34249ff741b014941ec18e1` |

完整构建参数及产物位置见 [NoMount](handoffs/2026-10-14-nomount-0.5.2.json)、[zram_zstd](handoffs/2026-10-14-zram-zstd-1.0.0-two-variants.json)、[run_cmd_demo](handoffs/2026-10-14-run-cmd-1.3.0-two-variants.json) 交接清单。

NoMount 配套 ZIP：`nomount-zip-0.5.2+gdc96b1300cc7.ndk26.3.11579264#1`，SHA-256 `5b470b905cde09f1509feefd20657f646067e52febfd5dc7c24ccb821c72fd70`。与上一轮模块计数修复 ZIP 对比，仅 module.prop 的版本字段变化；nm、WebUI 和脚本字节相同。完整身份见 [ZIP 清单](data/2026-10-14-nomount-0.5.2-zip.json)。

NoMount 复用已有七份目标布局配置，生成 8 条适配记录、6 份唯一 KPM 字节，包括 B2N 可选的旧 KP 二进制转换。JSON/blob 两种输入一致，恢复基线一致；布局仅改 92 字节，旧 KP 转换限于回执登记的区间。见 [目标件交接](handoffs/2026-10-14-nomount-0.5.2-target.json)。静态模板仍不能直接加载。

## 开发者自检

- 六个实例 `candidate` 档均通过源码指纹和产物哈希核验。
- 候选及 NoMount 目标件通过实际 ELF、静态布局和 SDK 导入核对；指令扫描未见 FP/SIMD/SVE 或 x18 操作数。
- zram_zstd 和 run_cmd_demo 各两份普通 KPM 与上一轮同版本、同模式、同 KP 的对应产物逐字节相同。
- 本轮涉及的 43 份既有自检脚本保持原样，无断言调整。现行工具自检 33/33 通过；机制适配只追加六个文件发现正反例。
- 修改的 NoMount C/H 通过 clang-format 检查；diff 无空白错误。NoMount 仅有 SDK 既有 READ_ONCE / WRITE_ONCE 宏重定义警告，没有日志宏重定义；zram_zstd 有两处上游未使用函数警告，run_cmd_demo 无警告。完整分类和编译日志哈希见验证数据。
- 常规仓库门禁 14 项，0 项失败、2 项警告；警告为历史交接字段及未登记交接实例，本轮候选仍待维护者导入。

证据及旧实例比较见 [验证数据](data/2026-10-14-kpm-cleanup-checks.json)。这是 Developer 自检，不是独立审计或本轮实机结论；本轮未操作设备。

## 复核决定（Decision）

**保留（Retain）**。

### 有效性

去掉未参与代码行为的 debug 目标达成用户要求，普通版仍保留错误和偏移日志。四份已有普通产物字节一致，六份当前候选通过编译与身份核验。

### 简洁性

两种必要偏移模式直接复用已有构建规则。统一日志仅用两个宏；无需增加新的调试开关或日志框架。rek/rekx 的 CONFIG_DEBUG 实际产生诊断内容，保留其已有目标。

### 后果

旧 debug 产物、身份、审计和测试证据保持原样。新候选通过维护者配套规则后才可接入远程 CI 和登记验收；NoMount 改名需用户通过重启更换已嵌入模块，控制协议不变。

## 维护者交接

[配套提案](../proposals/2026-10-14-kpm-cleanup/README.md) 区分已经标准授权落地的 identity 文件发现机制与维护者所有的命名判据、CI、规则/技能及两个当前版本字段补丁。机制适配须维护者同轮逐字节复核。维护者补丁在临时副本通过原有 33 组自检和 10 个正反例，现行门禁尚未采纳这些判据变化；因此不能把副本结果称为线上 CI 已通过。当前 CI 的 zram_zstd/run_cmd_demo `all debug` 调用必须配套更新后才能构建本轮源码。

新模块默认不提供 debug 件；已有模块只有实际调试用途时保留。需要审计绑定本轮 NoMount 的名称、日志和变体范围；实机安排归 Tester，既有普通版字节相同的证据供独立角色决定是否复用。

另外发现现行 CI 选择摘要排除了包含嵌套子模块的 NoMount 与 zram_zstd，而实际工作流会构建它们。已提交 [DEV-038 提案](../proposals/2026-10-14-kpm-cleanup/issues.json)，由维护者修复；常规门禁的选择摘要不能作为实际 CI 成功证据。
