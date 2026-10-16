# NoMount 最终既有实机证据整理

角色：Tester。按 S01 整理当前动态、静态候选与已绑定派生字节；完整源码提交、instance_id、产物 SHA-256 集中保存在[来源索引](data/2026-10-16-nomount-final-evidence-index.json)的 `identities`。本次只复算文件与 Git blob 身份，新增设备运行 **0 趟**、构建 **0 次**；以下 PASS 均引用历史报告，不构成新测试或交付验收。

两机四趟在 S02 中均为 PASS；每趟 **20/20** 为 S05 `device_tests` 的原登记。5.15 动态为 Auditor 更正后 Delta 裁定绑定 S03 的旧实测，不与四趟合并为新的测试运行。索引逐件复算当前两个基础候选、三件实测派生件、4.4 静态中间父件、旧 5.15 动态件及共用 ZIP 的实际归档字节。

| 历史趟次 | 目标与实际字节索引 | 原结果与计数 | 关键覆盖与来源 |
| --- | --- | --- | --- |
| S02 ① | Nokia 4.4，`dynamic_44` → `dynamic` | PASS，20/20（S05） | `rc=0`；越过绝对符号边界误判，经 open 回调识别局部表，`fop=328 data=344/152`；ZIP连接、重定向、Whiteout、真实 App 编译与映射（S02/S05） |
| S02 ② | Nokia 4.4，`static_44` → `static_44_parent` → `static` | PASS，20/20（S05） | 新静态抽样，`rc=0`、`offsets=static`、版本识别与用户主路径（S02/S05/S15） |
| S02 ③ | Sony II 4.19，`static_419` → `static` | PASS，20/20（S05） | 新静态抽样，加载、ZIP连接、重定向、Whiteout、真实 App 编译与映射（S02/S05/S15） |
| S02 ④ | Sony II 4.19，`dynamic` 基础件原字节 | PASS，20/20（S05） | `rc=0`，操作表尺寸 `256/280/192`、`fop=368 data=384/264`，用户主路径回归（S02/S05） |
| S03 ③ → 本轮绑定 | Sony V 5.15，`old_dynamic_515` → `dynamic` | 旧实测 PASS 20/20；本轮 BOUND | 旧件 BTF 五类结构、加载、ZIP、重定向/Whiteout、CX 文件管理器编译与映射；当前字节依据 S04 §7/§8 绑定（S02/S03/S05） |

四趟各有一次独立嵌入、重启与主路径记录；原件没有逐项20条输出、每项尝试次数或重试统计，本次不补造。S04 认定静态 64→128 字节代理头为结构变化，须真机抽样；S02 的两趟新静态实测满足该抽样来源要求，不能将此写成全部静态目标均已上机。

环境按运行报告保留（S02/S03），设备标识均为既有脱敏指纹：

| 设备 | 内核 / 系统 / KP / BTF | 消费者与共存环境 |
| --- | --- | --- |
| Nokia 7 plus / `b754dad7` | `4.4.192-perf+`，Android 10 / API29，KP `d04`，无 BTF | Enforcing；Material Files UID10177，`untrusted_app`；`pre-kernel-init`；共存 `re_kernel/cgroupv2_freeze/zram_zstd` |
| Sony Xperia 1 II / `508d47da` | `4.19.325-cip134-st18-perf-g7fc8455b2fa8`，S02记 Android 12 / API31，KP `d09`，无 BTF | Enforcing；Material Files UID10006，`untrusted_app`；`pre-kernel-init`；共存 `re_kernel_x/hosts_redirect/zram_zstd` |
| Sony Xperia 1 V / `48b7ee2f` | `5.15.189-android13-8-00016-g51bba4309aac-ab14546557`，Android 15 / API35，KP `d09`，有 BTF | S03旧实测：Enforcing；CX 文件管理器 UID10409，`untrusted_app`；`pre-kernel-init`；共存 `re_kernel_x/hosts_redirect/zram_zstd` |

环境快照 S09/S10/S11 的采集时间分别为 2026-10-15 19:00:31、19:00:32、06:30:55（均 -0700）。S10 的系统属性为 **16 / 补丁2026-09-01**，构建指纹仍标 Android 12；S02 摘要写 **Android 12 / API31**，现有材料不足以统一这些口径。S10 记录 **pstore有旧残留且NoMount已加载**，S02 各趟写 pstore干净/无新增转储；缺少逐趟时间及处置链，不能把该快照视作四趟全部通过 C4 的证明，也不能由此判定残留来自这四趟。S09/S11记pstore空。上述差异保留，未重新采集。

脚本身份：S09/S10/S11 自述 `preflight.sh` 哈希，本次与 S13 字节核对一致。S12/S13/S14 在本轮冻结提交与 S02/S03 各自所列参考 HEAD 中逐字节相同，完整提交与工具 SHA-256 见索引。**这仅是辅助字节参考**：S02/S03 没有当次 `run_test.sh` 路径/哈希与执行回执，S05 的 `mode=run_test.sh --no-unload` 是登记；当次实际判据脚本身份、调用与完整冻结检查结果仍未能从现有材料确认。

TST-001 / DEV-042 的历史关闭证据为 S02 ①：4.4 动态加载成功、局部表识别、布局与用户主路径通过；S05记录 `closed_by=Tester`，修复归属为 Developer。旧 S03 的4.4拒载事实保持。5.15引用 S04 **§8更正后**裁定：`192 % 128 = 64`、`192 % 64 = 0`，更正后绑定结论保持；S07采纳、S08独立响应。本次未重新证明 Delta，也未重新关闭问题。

结论只覆盖原件记录的具体字节、设备、内核与判据。加载成功、实际读取与消费者编译/映射是直接行为记录；dmesg无异常或pstore无新增仅表述为“未观察到”，不能替代存活主判据。原件未给出逐趟 `boot_id` 不变、`uptime` 单调对照及精确观察秒数，不能声称存活N秒；标签逐项对照、UID隔离与目录合并的逐项原输出也未在四趟摘要中列全，保留请求范围与证据可见度差异。

未覆盖与风险：5.15当前动态件没有新增上机记录（两机轮次未接入，待轮换补测）；当前静态5.15没有新抽样；6.1与新增五目标（米8/米9/米10/米11/Android12）无实机证据。长期稳定性、卸载/动态重载及未列出的功能/机型不在此次证据范围。RA-002要求常驻至重启、嵌入参数留空、禁止卸载与动态重载，移除需撤销嵌入配置后重启；卸载配套ZIP不等于移除KPM。AUD-001未知厂商尾部风险保持 OPEN（S04/S05/S07）。

本次文件复算结果与所有来源的路径、完整提交、SHA-256、长度、Git blob OID见索引 `sources`；全体来源当前字节与冻结提交blob一致。历史原件、判据和原计数保持原样，报告采用三方交付流程、respect-the-oracle、are-you-sure及no-negative-echo做边界复核。
