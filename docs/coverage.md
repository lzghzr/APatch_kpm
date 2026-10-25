# 覆盖矩阵

每项覆盖绑定完整源码提交、构建实例与产物 SHA-256；角色报告只适用于所列字节与环境。维护者本轮整理报告索引，实际结论来自所引用角色。

## re_kernel_x 1.6

冻结源码：`52b303df659616012077bc95ed7899655295d925`。完整实例及产物哈希见 [模块登记](../metadata/modules/re_kernel_x.json)，八份 ABI3/4/5/6 release/debug 基准见 [候选登记](records/2026-10-02-re-kernel-x-1.6-registration.md)。

| 范围 | 验证层级 | 覆盖与证据 |
| --- | --- | --- |
| 八份基准产物重编译、ELF 结构与导入符号 | 独立静态审计 | [Auditor 1.6 报告]记录八份哈希一致；平台 SDK 0.13.9 |
| 命名与控制入口 UID 鉴权 | 源码审计、主机测试 | 同一审计报告记录 AUD-001/AUD-002 复核关闭；实现方套件的测试具有同源性 |
| 代码风格修复 AUD-004 | 历史独立复核 | [风格复核]绑定历史提交 `5c779c9b6cc7de1308d884906c4ddda3f7152c13`，覆盖该次修复 |
| abi5 release/debug 在线存活、UID 矩阵、组播、加载与卸载 | 角色实机报告 | [Tester 1.6 报告]记录 12/12 强判据；单台 Linux 5.15 设备，环境和个人运行信息已脱敏 |
| 本机基准身份 | 已登记基准与实机报告对应 | 用户确认基准偏移对应本轮测试机；ABI5 release/debug 使用在册基准字节。其它目标内核继续按 AUD-003 的偏移核对和适配登记前提执行 |
| ABI3/4/6 实机、长期休眠唤醒、极端压力 | 未覆盖 | 本轮 Tester 报告未覆盖这些范围 |

报告存活与功能判据的结果不能外推到其它内核或设备。基准身份与本机对应关系已由用户确认，维护者验收和签名交付字段按实际状态登记。

## 2026-10-10 冻结候选（re_kernel 11.7 / re_kernel_x 1.6-20261008 / run_cmd_demo 1.2.0 / hosts_redirect 2.0.0 / dont_kill_freeze 1.0.2 / cgroupv2_freeze 1.0.12）

冻结源码：`2257f2291e2be77c8809c266393da9d9d093d7b4`。13 份候选的完整实例、产物哈希与复算命令见
[候选登记](records/2026-10-10-candidate-registration.md)及各模块登记（[re_kernel](../metadata/modules/re_kernel.json)、
[re_kernel_x](../metadata/modules/re_kernel_x.json)、[run_cmd_demo](../metadata/modules/run_cmd_demo.json)、
[hosts_redirect](../metadata/modules/hosts_redirect.json)、[dont_kill_freeze](../metadata/modules/dont_kill_freeze.json)、
[cgroupv2_freeze](../metadata/modules/cgroupv2_freeze.json)）。

| 范围 | 验证层级 | 覆盖与证据 |
| --- | --- | --- |
| 13 份候选身份、源码 blob 绑定、配方指纹与产物哈希 | 维护者复算 | [候选登记](records/2026-10-10-candidate-registration.md)记录逐条 candidate 核验 0 处问题；`import-manifest` 落盘前另行核验归档产物哈希 |
| 构建事务、宿主自检、ELF 导入与 SDK 导出检查、离线语料回归 | 实现方自检（同源，非独立结论） | [Developer 冻结候选构建报告]，含未执行语料清单 |
| 独立审计：重编译、字节解析、边界与安全评估 | 未覆盖 | 本轮没有 Auditor 报告 |
| 真机：存活判据、功能与生命周期 | 未覆盖 | 本轮未执行设备测试，未接触 superkey |

覆盖只适用于所列字节。实现方自检与维护者复算都不替代独立审计和实机结论；13 份实例保持 `candidate`，未追加验收或交付。

## 历史身份

`re_kernel_static` 已迁移为 `re_kernel_x`。其 [历史登记](../metadata/modules/re_kernel_static.json)保留原始构建与问题记录；历史产物继续按各自冻结提交和哈希核验。当前报告清理与验证范围见 [工程整理记录](records/2026-10-03-git-reorganization.md)。

## zram_zstd 0.1.0（重跑轮）

冻结源码：初始候选 `e6ca482ecd40f4415d17acd349bd9875c6b64356`、修复候选
`a5e1615bdb715257b167483e3e3a6f019b4a15f0`。8 个在册实例、产物哈希、布局索引与问题单见
[候选登记](records/2026-10-10-zram-zstd-registration.md)与 [模块登记](../metadata/modules/zram_zstd.json)；
审计请求见 [审计请求](records/2026-10-10-zram-zstd-audit-request.md)。

| 范围 | 验证层级 | 覆盖与证据 |
| --- | --- | --- |
| 8 个在册实例身份、源码 blob、配方指纹、产物哈希与布局对应 | 维护者复算 | 8 条 candidate 核验 0 处问题；布局内嵌 `kpm_sha256` 与静态产物逐份对应 |
| 8 份产物独立重编译（8/8 逐字节吻合）、ELF 节区与 ABS64 重定位自解析、格式检查、Oracle 32 项断言与 ASan/UBSan | 独立审计 | [Auditor 报告]：`report_versions` 已按入库原文登记；含语料同源声明 |
| 初始候选缺 `.kpm.ctl0` 与释放未置空（`AUD-008`，中低） | 已独立复核关闭 | 修复候选 4 份含 8 字节 `.kpm.ctl0` 与合法重定位；`closed_by=Auditor` |
| 卸载路径 Use-After-Free 可致 Panic（`AUD-009`，**高**） | 维护者书面风险接受 | 登记 `RA-001`（批准人、范围限模块 0.1.0 + KP `b51197aaba…` 卸载路径、理由与四条恢复触发条件齐备）；**风险不因接受而降级**，使用前提为常驻、不卸载；`AUD-009` 据此关闭但模块代码未变 |
| 真机：热加载、`ctl0 ping`、`post-kernel-init` 开机自动加载、zram 切 `[zstd]`、交换空间压缩 | 已执行（**限于派生字节**） | [实机报告]：Nokia 7 plus / 4.4.192 上 9 项强判据全通（含 2.57s 于 init 前自动加载、`mm_stat` 4096→58 字节），未执行 unload（遵守 RA-001）；推送的是未登记的 `legacy-kp` 派生字节 `f6d25190…`，与在册产物 `2490abcf…` 不同——**4.4 上 KP 0.13.9 不兼容，降级为必经路径**，缺的是「在册的 legacy 候选」而非测试执行，见 `MNT-015`（owner=Developer） |
| 在册修复候选 4 份产物的设备证据；4.4 形态的 legacy-kp 候选 | **未覆盖** | 4.4 需 legacy-kp 转接，而该形态未登记；`MNT-015` 待 Developer 产出在册 legacy 候选后由 Tester 复测 |
| 静态基线可加载性 | 未覆盖 | 4 份布局五项偏移仍为模板值 `-1`，未派生目标偏移 |
| 高版本/GKI 内核（5.10/5.15/6.1/6.6）与 BTF 路径 | 未覆盖 | 仅在 Android 4.4（B2N）语料上验证推导窗口 |

### zram_zstd 0.2.0（当前版本）

| 范围 | 验证层级 | 覆盖与证据 |
| --- | --- | --- |
| 0.2.0 六个在册实例（base/baselines/baselines_debug/debug/legacy/legacy_debug）的独立重编译、节区与重定位、命名与自识别契约 | 独立审计 | [审计报告]：6/6 逐字节吻合；`kp_compat`/`offset_mode` 与命名一致 |
| zstd 子模块冻结（v1.3.1 `aecf3b47…`）、18 份源文件与 3 处地址运算修补 | 独立审计 | 按冻结 gitlink 核对，无未授权改动 |
| legacy 转接契约（13 处直接 `CALL26` → 本地跳板 ADRP+LDR+BR） | 独立审计 | 独立解析确认安全；历史"直接跳入数据指针"隐患已根除 |
| `DEV-030`（高，寄存器别名覆盖） | **已关闭** | 修复有效（`zs_functions.c:29-43` 保守失效），Auditor 独立复核关闭 |
| `test_legacy_kp.py:82` 的 FAIL | **独立裁定为断言过时** | 非实现缺陷；Developer 未改断言（遵守 Oracle），新用例覆盖正确契约 |
| 代码风格 / 静态扫描 | 独立审计 | 风格零警告；启发式扫描无新增阻塞项 |
| 0.2.0 legacy / legacy_debug 两份产物的真机证据 | **已覆盖（在册身份）** | [复测 #1]／[#2]：实测 SHA-256 与在册值逐位一致（`dc4d7f7c…`／`238d291f…`），各 11/11 强判据通过，`--no-unload` 模式；`MNT-015` 已关闭 |
| 卸载/重载风险的实证（授权破坏性验证） | **已实证** | [卸载复现]、[静止态卸载+二次加载]：zstd 活动下卸载立即 UAF Panic；静止态卸载无同步崩溃但遗留野指针、二次加载立即 Panic → `RA-001` 已修订为「不可卸载、不可动态重载」|
| 0.2.0 modern 形态的设备证据、静态基线可加载性、5.15+ GKI | 未覆盖 | 4.4 只能跑旧 KP，modern 加载报 `unknown symbol` 属环境事实；静态表五项偏移仍为模板 `-1` |

覆盖只适用于所列字节。审计结论不替代真机结论；模块 `status=candidate`，未追加验收或交付。

### zram_zstd 0.3.0（当前版本：纯净构建 + 二进制派生件）

| 范围 | 验证层级 | 覆盖与证据 |
| --- | --- | --- |
| 4 份普通候选（base/baselines/baselines_debug/debug）独立重编译、静态布局、命名与自识别契约 | 独立审计 | [审计报告]：4/4 逐字节吻合（含 2 份布局 JSON） |
| ZSTD `1.5.7-kernel` 子模块冻结（`5d9fb478…`）与 95 份上游源 | 独立审计 | 按冻结 gitlink 核对，`SOURCES.json` 零漂移 |
| 2 份二进制派生件（`2cd50444…` release / `20af1b9b…` debug） | 独立审计 + 真机 | 审计：Auditor **独立重跑变换逐字节复现**并核对回执、13 处 `CALL26` → 本地跳板；真机：各 **11/11 强判据 PASS**、派生哈希=实测哈希、绑定基准实例 |
| 代码风格 / 静态扫描 | 独立审计 | 0 报错；无阻塞性缺陷 |
| 现代形态在 4.4 的设备证据 | 未覆盖 | 4.4 只能跑旧 KP（KP 0.13.9 不兼容、旧 KP 缺 suffix 导出）——环境事实；其设备证据由登记的派生件承载 |
| 静态基线可加载性、5.15+ GKI | 未覆盖 | 静态表五项偏移仍为模板 `-1`；GKI 不在本轮范围 |

**形态规则**：源码/Makefile 只面向当前 KP；旧 KP 兼容只在**构建后的 KPM 字节**上做（见
[纯净构建 + 二进制适配](records/2026-10-11-clean-build-binary-adaptation.md)），派生件不登记为编译变体、不进 Releases。
验收：4 份候选按静态/主机/独立审计层，2 份派生件含真机证据（见 `acceptances[]` 与 `binary_ports[].acceptance`）。

## 其它模块

`cherish_oplus_thermal_killer_test`、`cherish_peekaboo_test`、`lmkd_dont_kill`、`proc_boot_config_init_test`、
`qti_battery_charger`、`shamiko_helper_test`、`xperia_ii_battery_age`、`xperia_led_brightness_test` 尚未在当前元数据中
建立候选身份；本表将其标为未验证。已登记的 `re_kernel`、`re_kernel_x`、`run_cmd_demo`、`hosts_redirect`、
`dont_kill_freeze`、`cgroupv2_freeze`、`zram_zstd` 见上方各自章节。

## 更新规则

维护者在每轮交付后更新范围、验证层级与具体身份。静态与实机结论引用对应角色报告；缺少材料的项目逐项说明原因。历史结论保持原有身份边界。

## 2026-10-10 最终工程候选

本轮六模块冻结身份、15 份产物与宿主/发布筛选核验见 [维护者工程记录](records/2026-10-10-round-finalization.md)。run_cmd_demo 1.3.0 保持验证型 demo。AUD-007 按 Auditor 原八实例复核同步关闭；历史 Linux 4.4/5.15 实机范围按原报告与各自字节保留。本轮新实例处于 candidate，等待对应独立审计与实机复验。

## 2026-10-17 APatch「安装」路径（落盘加载）

「安装」＝KPM 落盘到 `/data/adb/ap/kpm/<id>/<id>.kpm`，由 KernelPatch 在 `post-fs-data`/"before" 同步加载（`load_source=file`、`load_event=post-fs-data`）。

| 项 | 结果 | 证据 |
| --- | --- | --- |
| 机制（Linux 4.19 / XQ-AT52 / KP `d09`） | **实机成立**：`load_source=file`、`load_event=post-fs-data`、`rc=0` | [re_kernel 实验]、[zram_zstd 实验] |
| `re_kernel` 11.7-20261010 | 安装路径加载成功并建立 family `rekernel`；业务未验（墓碑应用未运行） | 同上 |
| `zram_zstd` 1.0.0 | 撤嵌入后安装路径加载成功，`preferredZram.sh` 选中 `[zstd-kpm]`，8 GiB swap 正常 | 同上 |
| `re_kernel_x` 1.6-20261008 | **未做安装路径实测**（仍为嵌入）；机制同源但**不据此宣称可用** | — |
| 时序 | 落盘加载约 24s，厂商首次设 zram `disksize` 约 41s，早约 17s | [只读时序勘查] |

范围：以上均为**该单机**结论；**5.15 未测**；4.4（KP `0.13.4`）无目录自动加载实现，不可验证。
设备侧变更：该机 `boot_a` 已撤销 `zram_zstd` 嵌入，回滚镜像哈希与现状见 [模块登记](../metadata/modules/zram_zstd.json) 的 `maintainer_records`。
