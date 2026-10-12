# zram_zstd 0.1.0 候选身份登记（流程验证重跑轮）

维护者；2026-10-10。本记录保存**重跑轮**的建档与登记结果。上一轮的记录已按用户要求撤销，
全部内容保留在本地分支 `test/process-restart-backup`（`dba224f`），需要时
`git reset --hard test/process-restart-backup` 可取回。

重跑目的：验证新落地的复核规则（`identity_tokens`/`report_versions`/`report_version_commits`/
`referenced_reports_archived`、`class` 分类、`incremental` 档位、批量更正窗口、R8 交接即提交）。规则见
[复核经济学](../process/08-review-economics.md)，落地记录见 [本轮流程变更](2026-10-10-review-economics.md)。

## 起点

| 项 | 值 |
| --- | --- |
| 开审起点提交 | `4f11c43bc2a4`（`checkpoint(维护者): 清理悬空的 MNT 阶段日志，形成干净开审状态`） |
| 模块源码 | 冻结于 `a5e1615bdb715257b167483e3e3a6f019b4a15f0`（AUD-008 修复后） |
| 初始候选源码 | `e6ca482ecd40f4415d17acd349bd9875c6b64356` |
| KernelPatch commit | `b51197aaba8f2272dd8a3e30c85698a29aa928c9`（0.13.9） |
| 工具链 | `ndk26.3.11579264` |
| 保留的开发者材料 | 模块源码与自检脚本、开发自检报告、AUD-008 修复响应、两轮交接清单与两套静态布局、两份冻结回执数据 |
| 撤销的材料 | 旧模块记录、两份旧 Auditor 报告、旧维护者请求/登记记录（均在备份分支） |

## 登记动作

1. 维护者建档 `metadata/modules/zram_zstd.json`（`version_declared=0.1.0` 取自 `Makefile` 的
   `MYKPM_VERSION`，`readme_heading` 取自 README 更新记录；`builds/audits/device_tests/issues/`
   `acceptances/deliveries/report_versions` 均为空数组，等待审计与结论）。
2. 两次 `import-manifest` 导入交接清单，保留原 `instance_id` 与归档路径，未重新编号：

   | 轮次 | 交接清单 | 清单 SHA-256 | 实例数 |
   | --- | --- | --- | --- |
   | 初始候选 | `Developer/reports/handoffs/2026-10-10-zram-zstd-candidate.json` | `f37142b5\u20260d93b0` | 4 |
   | AUD-008 修复候选 | `Developer/reports/handoffs/2026-10-10-AUD-008-zram-zstd-candidate.json` | `a087c909\u2026a1d00a` | 4 |

3. 静态基线布局按规则归档进 `artifacts/<instance_id>/`（与 `.kpm` 同目录，未覆盖 `MANIFEST.json`），
   并在 `maintainer_records[].baseline_layouts` 登记路径、哈希与内嵌 `kpm_sha256`（初始 2 份 + 修复 2 份）。

## 在册实例（8）

| 轮次 / 变体 | instance_id | 产物 SHA-256 |
| --- | --- | --- |
| 初始 `base` | `zram_zstd-0.1.0+gc330fe19c6d2.r4f8aafd2.kpb51197a.ndk26.3.11579264#1` | `e77e43f1194020a625b1895fa9699e078b96c2593c844a21638b8c291e9614ac` |
| 初始 `baselines` | `zram_zstd-0.1.0_baselines+gc330fe19c6d2.r96a59ed2.kpb51197a.ndk26.3.11579264#1` | `64b5a23163a4f0283b409647fe1303b3b911c2d889b3db2f4dc9f63ee696df10` |
| 初始 `baselines_debug` | `zram_zstd-0.1.0_baselines_debug+gc330fe19c6d2.r4fa063b1.kpb51197a.ndk26.3.11579264#1` | `4ce9a938c695eb92ba9753c75374d3c93fe8ac52f90f6df824eedcfbb0a888e7` |
| 初始 `debug` | `zram_zstd-0.1.0_debug+gc330fe19c6d2.r627503cf.kpb51197a.ndk26.3.11579264#1` | `7a7d18b9f7c9bfff89f0b2e7a440b4f4a79afbb273efb6fe3e3c5d6e83a7a279` |
| 修复 `base` | `zram_zstd-0.1.0+gd464ad07ccb0.r21df036f.kpb51197a.ndk26.3.11579264#1` | `f48f3155f6ada61803ace3cd627772ea595681489f3be6305ac192557f0ab7d2` |
| 修复 `baselines` | `zram_zstd-0.1.0_baselines+gd464ad07ccb0.rf876d2a6.kpb51197a.ndk26.3.11579264#1` | `d0c28ea484c38ecd7b13e39e13f2566a5719e9feceb99dd7fb425f733241ca7f` |
| 修复 `baselines_debug` | `zram_zstd-0.1.0_baselines_debug+gd464ad07ccb0.r8985a06f.kpb51197a.ndk26.3.11579264#1` | `455426a2352a95586fdc05ff360d689377fd1061c9547d79a38d8b25435ae98d` |
| 修复 `debug` | `zram_zstd-0.1.0_debug+gd464ad07ccb0.rf04090a6.kpb51197a.ndk26.3.11579264#1` | `2490abcfc0ed4497c3f2e4462c4608de57d46f41e1c5eede349f2b35805d18ad` |

## 维护者复算

```bash
for iid in <上表 8 个 instance_id>; do
  python3 tools/identity.py verify --module zram_zstd --instance-id "$iid" --profile candidate
done
```

结果：8 条 `verify[candidate]` 均为「复算 1 份产物，1 条构建记录，0 处问题」，源码按绑定提交核验通过（36 项 blob）；
归档产物哈希与登记逐字节一致。布局内嵌 `kpm_sha256` 与对应静态产物哈希逐份对应。

## 未决项

- **独立审计未执行**：本模块尚无 Auditor 报告（`audits[]` 为空）；审计对象应为上表 8 个在册实例，
  建议按 `incremental` 档聚焦修复差异（`a5e1615` 相对 `e6ca482` 的改动）并声明其余部分「未重做」。
- **真机未执行**：`device_tests[]` 为空；原生注册结果、`post-kernel-init` 加载次序、zram 切换到 `zstd`、
  控制命令、并发与交换空间压力、收益均无实测证据。
- **静态基线版**：布局已登记，但五项偏移仍为模板值 `-1`，填写前不具备可加载的静态移植能力。
- **风险与验收**：卸载路径的可致 Panic 风险在本轮尚无书面处置（上一轮的 `RA-001` 随备份分支保留）；
  未追加 `acceptances[]`/`deliveries[]`，模块 `status` 保持 `candidate`。
- **覆盖矩阵**：待审计与真机结论到位后更新 [覆盖矩阵](../coverage.md)。

## 审计接收（2026-10-10）

Auditor 已完成重跑轮首次完整审计，并按 R8 在自己的路径内做了检查点提交
`8388b95 checkpoint(Auditor): zram_zstd 0.1.0 全量产物独立审计报告与复核回执`（报告 19973 字节 +
三份逐项数据）。维护者接收动作：

| 动作 | 结果 |
| --- | --- |
| `report_versions[]` | 登记报告与主数据文件的**入库原文基线**（含提交 `8388b95`）；两份均引用提交，无 `pending_commit` |
| `audits[]` | 追加 8 条，逐实例绑定 `report_sha256`/`data_sha256` 与产物哈希 |
| 问题单 | `AUD-008`（中低，`product`）→ **closed**，`closed_by=Auditor`；`AUD-009`（**高**，`product`）→ **open** |
| 维护者记录 | 记录接收范围、报告/数据 blob 哈希与问题单同步 |

审计结论要点（引自报告，非维护者结论）：8/8 独立重编译逐字节吻合；修复候选 4 份含 8 字节 `.kpm.ctl0`
与合法 `R_AARCH64_ABS64` 重定位；`clang-format` 零告警；Oracle 原 21 项断言逐字保留、共 32 项通过，
ASan/UBSan 零告警；初始候选 4 份仍缺 `.kpm.ctl0`（故**只有修复候选可进入后续交付**）。

未决：`AUD-009` 需维护者书面风险接受（定级高、范围限 `zram_zstd 0.1.0` 在 KP `b51197aaba…` 框架下的卸载路径、
含恢复触发条件），或由框架层修复后复核关闭；真机与静态偏移仍未覆盖。

## AUD-009 处置：书面风险接受（2026-10-10）

`AUD-009`（高）在报告中的关闭条件是"由维护者出具书面风险接受并在元数据登记关闭，或框架层/模块层实现安全卸载防护"。
维护者按用户批准采用前者：

| 字段 | 值 |
| --- | --- |
| 风险 | 卸载后内核 UAF：KP `module.c:541` 忽略退出回调返回值并无条件释放模块内存，算法链悬挂指针可致 Panic |
| 定级 | **高**（按影响；不因缓解手段有限或触发频率低而降级——报告 frequency=低频、confidence=已确认） |
| 批准人 / 范围 | 维护者（用户批准）／模块 0.1.0 在册 8 实例在 KP `b51197aaba8f2272dd8a3e30c85698a29aa928c9` 框架下的卸载路径；可交付集合只含修复候选 4 份 |
| 理由 / 缓解 | KP 无阻断卸载接口，模块无法在不注销算法的前提下安全释放内存；缓解为 README、`KPM_DESCRIPTION`、退出日志警示 + 常驻设计 + 只读控制入口 |
| 恢复触发条件 | ① KP 检查退出返回值或提供注销/引用计数 ② 模块可安全注销或无活跃引用 ③ 真机观察到不同失败模式 ④ 任何卸载试验、批量部署或对外发布前重新确认 |

登记结果：`risk_acceptances[]` 新增 `RA-001`；`AUD-009` 状态 `open → closed`，`closed_by=维护者`
（独立于 `owner=Developer`），`risk_acceptance=RA-001`。**关闭依据是风险接受而不是缺陷修复**，模块代码未改动。

未决：真机 `device_tests[]` 仍为空；4 份静态布局的五项偏移仍为模板值 `-1`；未追加 `acceptances[]`/`deliveries[]`。

## 真机测试接收（2026-10-11）

Tester 在授权下完成实机测试并按 R8 入库（`5afb485 checkpoint(Tester): zram_zstd 实机引导与交换空间测试报告及动作回执`）。
维护者接收结论与**一处身份差异**：

| 项 | 结果 |
| --- | --- |
| 测试设备 | Nokia 7 plus（`b754dad7`）/ Android 10 / 内核 `4.4.192-perf+` / KP 0.13.3 |
| 判据 | 9 项强判据全通：热加载与动态推导、`ctl0 ping` → `pong`、`/proc/crypto` `name: zstd`/`driver: zstd-kpm`、boot 重打包、刷写 `boot_b` 后一次冷启动成功、`post-kernel-init` 于 2.57s（`init` 前）自动加载 `rc=0`、`comp_algorithm` 切为 `[zstd]`、`swapon` 后 `mm_stat` 压缩计数有效（4096→58 字节）；弱证据「未观察到崩溃特征」（pstore 持续为空） |
| 协议遵守 | 未执行 `module unload`（遵守 `RA-001`），以整机重启替代 |
| 备份 | `local/tester-raw/boot_b_backup.img`（`b71d23c9…ef3312`）与重打包镜像 `new-boot.img`（`127e3fbd…`）在场且哈希复算一致 |
| **身份差异** | 实机推送/嵌入的是 `local/tester-raw/zram_zstd_0.1.0_debug_legacy.kpm`（`f6d25190…`，245056 B），**不是**在册产物 `2490abcf…`（229312 B）；派生字节未登记（原因：测试机 KP 0.13.3 未导出 `kallsyms_lookup_name_by_suffix`） |

处置：`device_tests[]` 按「在册实例 + 派生字节」双身份登记并写明范围限制（设备结论只覆盖派生字节）；
新开 `MNT-015`（中，`open`）跟踪该身份缺口。**用户澄清后已重新定性**：KP 0.13.9 与 4.4 内核不兼容，4.4 上只能跑旧 KP（实测 `d04`）而旧 KP 未导出 `kallsyms_lookup_name_by_suffix`，**legacy-kp 转接是 4.4 的必经部署路径**；因此缺口是「4.4 形态没有在册候选 + 转接工具仍是工作树探索状态（且有历史 Oops 记录）」，归属由 Tester 改为 **Developer**，Tester 推送派生字节不据此追责。**在册修复候选 4 份产物目前没有设备证据**，
因此验收与交付的范围必须据此限定，或先补一轮绑定在册字节的复测。

## 0.2.0 审计接收（2026-10-11）

Auditor 按 R8 自行检查点提交（`22bcfc7 checkpoint(Auditor): 优化审计工具性能（kallsyms 10x+ / static_scan 7x+）
并产出 zram_zstd 0.2.0 独立审计报告与复核结论`）。维护者接收动作：`report_versions[]` 登记报告与两份数据
（均引用该提交）；`audits[]` 追加 6 条（逐实例绑定产物哈希）；新登记 `DEV-030`。审计结论要点：

- 6 份在册产物独立重编译 **100% 逐字节吻合**（含 2 份布局 JSON），必需节区齐备、入口重定位合法；
- zstd 子模块按冻结 gitlink 核对，18 份源文件与 3 处地址运算修补无未授权改动；
- legacy 13 处直接 `CALL26` 全部安全重定向至本地跳板，历史 Oops 隐患根除；`test_legacy_kp.py:82` 的 FAIL
  被独立裁定为**历史断言过时**（非实现缺陷，Developer 未弱化断言）；
- `DEV-030`（高，寄存器别名覆盖）修复有效，**Auditor 独立复核关闭**；风格零警告、静态扫描无新增阻塞项。

问题单同步：`AUD-008`/`AUD-009` 状态不变（0.2.0 未复现 `AUD-008`）；`MNT-015` 定级 中 → **高**
（0.2.0 legacy 已在册且经审计，但 4.4 可交付形态仍无设备证据，阻塞交付），保持 `open` 待复测；
`MNT-016` 仍待 Developer 一次确认。

## 0.2.0 legacy 复测与授权破坏性验证（2026-10-11）

Tester 按 R8 分两次检查点提交（`56128f7`、`c6da195`）。维护者接收：

| 项 | 结果 |
| --- | --- |
| 复测 #1（`legacy_debug`） | 在册 = 实测 `238d291f…`；11/11 强判据 PASS；`run_test.sh --no-unload` |
| 复测 #2（`legacy`） | 在册 = 实测 `dc4d7f7c…`；11/11 强判据 PASS；同上 |
| 工具改动 | `run_test.sh` 新增 `--no-unload`（跳过卸载阶段并改判「常驻存活」）；维护者逐行核对该分支**未放宽任何判据** |
| `MNT-015` | **closed**（关闭者＝维护者，独立于 owner=Developer）：身份缺口消除 |

**授权破坏性验证（用户会话内明确授权）**：

1. `comp_algorithm=[zstd]` + swap 活动下卸载 → KP 释放模块而算法引用仍在 → 再访问即 UAF，内核 Panic，看门狗复位进 fastboot；
2. 静止态（非 zstd + swapoff）卸载 → **无同步崩溃**（uptime 单调、boot_id 未变、模块已移出列表），但 `crypto_alg_list`
   残留野指针 → **二次加载立即 UAF Panic**。结论：该模块**不可卸载、不可动态重载**，只能作为 boot 嵌入常驻模块。

`RA-001` 已据此修订：新增两条实机证据、触发概率由「低频」改为「条件触发即必然」、约束扩展为
「不可卸载、不可重载，移除只能撤销嵌入 + 重启」、恢复触发条件追加「内核/KP 提供安全反注册路径时重评」。

待办：两次升级单的「动作回执」尚待维护者回填（设备当时在 fastboot）；pstore 中的崩溃证据**不得清除**。
