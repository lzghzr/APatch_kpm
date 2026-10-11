# 旧 KP 查找转接的调用契约修正

Developer；2026-10-10。用户授权连接 B2N 验证加载异常，本轮唯一一次诊断加载捕获了内核 Oops。**需要修复的是临时 `legacy-kp` 转换工具：只改导入名称会把直接函数调用转向函数指针变量的数据地址。** 当前证据不支持把此次异常归因于动态偏移推导。

本记录追加到 [此前排查](2026-10-10-rek-4.4-panic-investigation.md) 和 [原工具自检](2026-10-10-legacy-kp-import.md) 之后，更正原工具自检对“签名相同即可替换”的判断。旧报告、冻结产物、清单、原自检断言均保留。脱敏身份与原始证据哈希见 [诊断收据](data/2026-10-10-legacy-kp-call-abi.json)。

## 身份与设备事件

- 来源 commit：`820165f403960a5b0e31f5d66df08014b55e3844`。
- parent instance_id：`re_kernel-11.7_debug+g74820b6486a2.r58923f37.kpb51197a.ndk26.3.11579264#1`。
- 原始 SHA-256：`c04a293446c8f9920fa1746d6fa215b956b22b87523b9734479cc76740e159da`。
- 本次实测临时件 SHA-256：`25dbdf61103247f83f14209400e3d1d7f52dae4eb84e641974e27e7502f01342`。
- 设备指纹哈希：`b754dad7`；Linux `4.4.192-perf+`，KP 实际返回 `d04`，按版本编码为 0.13.4；不能据此确定运行端源码 tag。
- 加载命令时间：2026-10-10 16:04:58 UTC。加载次数 1，超时 20 秒，自动重试 0，重启操作 0，崩溃后的设备操作 0。

加载前核对 boot_id、uptime、模块清单与 pstore：uptime 1373 秒，pstore 只有此前已检查的 48 字节 pmsg，没有 console/dmesg 崩溃记录。先启动实时日志采集，推送并核对实测字节哈希；旧 re_kernel 卸载返回 0，三秒后 boot_id 保持、模块清单仅有 cgroupv2_freeze。随后只加载一次临时件。加载超时后立即停止，保留日志并通知维护者；未查询崩溃后的设备状态，未卸载新模块、重启或换变体重试。此前一次采集器 UTF-8 解码失败发生于设备变更前，未执行推送、卸载或加载。

诊断脚本及原始日志保留于私有目录 `local/rek-authorized-test-dswhnh6f`；脚本 SHA-256 为 `c808ef7e6d90a557125c1a777a5d0d033c17b8a750b4b018f715cbc2e60eaaf4`。这些观察属于用户授权的 Developer 诊断，不能代替独立 Tester 验收。

## 根因证据

实时日志记录模块 `.text` 地址 `ffffff960b4c5228`，最后成功输出为 `cgroup_freezing` 地址。紧接着出现取指异常：PC=`ffffff960b18cda0`、LR=`ffffff960b4c5294`。PC 位于本次 KP data 范围 `ffffff960b18c000～ffffff960b1abce0`；LR 与模块 text 相差 `0x6c`。

对原始候选反汇编，`.text+0x68` 为 `R_AARCH64_CALL26 kallsyms_lookup_name_by_suffix`，下一条指令在 `0x6c`，对应 `__alloc_skb` 查找的返回位置。此前成功的原名查找使用 ADRP/LDR 读取函数指针，再 BLR 调用。

[KP start.c](../../KernelPatch/kernel/base/start.c) 中原名导出是 `unsigned long (*kallsyms_lookup_name)(const char*)` 变量，suffix 导出是函数。加载器把 undefined 符号解析为导出对象地址，再按原 CALL26 重定位；改名没有把调用改成解引用，因而跳入数据区。日志、精确返回地址与导出定义相互吻合。该调用发生在偏移推导前；不能由此次异常判断之后的模块初始化已正确或有误。

## 工作树修正与自检

`patch_offsets.py legacy-kp` 保留原调用符号索引及重定位，将 suffix 导入定义为模块内函数，并追加 12 字节 `ADRP x16; LDR x16; BR x16` 转接。两条 RELA 分别为 275/286，指向既有原名指针导入。转接读取指针后尾调用，保留参数、SP、LR；原全局绑定保留，不破坏 symtab 局部符号排序。新节表追加到文件末尾，原有代码、配置段、模块信息与调用重定位保留。

输入必须同时存在一个 undefined global suffix 函数导入与一个原名指针导入。当前 run_cmd_demo 缺少后者，明确拒绝；本轮临时方案覆盖 rek、rekx。使用只读父候选，输出至新的 `local/legacy-adapter-ukyhihlr`，派生身份见收据。修正工具尚未冻结，派生产物仅供离线检查，未发布、未交接实机测试。

- 新增 `Developer/tools/test_legacy_kp_adapter.py`：八份真实 KPM 检查通过，核对函数符号定义、指针导入、节和重定位、原字节保留、输出保护及重复转换拒绝。用 NDK 汇编器独立生成三条指令并逐字节比对；正负页距离及不同指针目标通过解码模型复算。模型不是 ARM64 真机执行。
- 四份静态布局校验及 dump 通过，原字段、ABI、表位置与表内容保留。原静态工具回归另见追加验证收据。
- 所有十份父候选与旧临时件复算哈希一致，冻结资产保留。工具判据自检 21/21 通过。
- 普通仓库门禁仍为 1 项失败、2 项警告：Tester 原始材料的公开卫生与身份引用问题，由对应角色处理。

## DEV-028（高，Developer）直接调用 KP 查找指针变量导致内核崩溃

状态：fixing，工作树修正完成，待冻结及独立复核。frequency：本轮一次加载一次复现；confidence：确认。影响：使用旧转换件加载可致内核崩溃。证据：上述 PC/LR、CALL26 与导出对象定义。维护者需登记正式问题并关联 Tester 已有升级事件，问题由独立角色复核关闭。

关闭条件：Auditor 对新冻结工具及派生实例独立解析转接、导入和重定位，复核既有断言失真；维护者确认设备恢复及下一轮范围后，由 Tester 验证新身份加载存活和初始化。修复者不关闭问题。

## 断言复核请求

`Developer/tools/test_legacy_kp.py` SHA-256 仍为 `cbe4e29e60fe010bfbe2dcbd988cdeffe7b6377dfa94c85caa2991aba2ea022a`，未修改。对修正工具运行，在第 82 行名称替换断言 FAIL：它要求 suffix 变成 undefined 原名导入，并进一步要求文件等长、只改字符串。这些要求没有表达 KP 的函数指针契约。此前通过只能证明补丁按指定范围完成，不能证明执行正确。

本轮只追加转接自检，完整保留失败记录。建议 Auditor 独立确认上述旧断言失真，再按 Oracle 变更协议单独处理；Developer 不自行弱化、删除或宣布旧测试通过。

## 自查决策（Decision）

**替换（Replace）**旧名称替换方案。有效性：实时 PC/LR 与源代码证明旧调用契约错误，正确转接已获离线反汇编和加载器契约支持。简洁性：复用既有调用重定位，仅追加三条指令，避免逐调用点重写或改模块业务源码。后果：仍只查原名、失去后缀兜底；要求既有指针导入，不能外推到 run_cmd_demo 或其它 KP 差异。一次限范围反例审查确认 ELF 与 ARM64 转接机制，但不充当独立审计。

按 no-negative-echo 回读工具、收据和公开报告，保留读者所需的崩溃事实与迁移边界；按 respect-the-oracle 保留旧断言及 FAIL。技能说明修正以 [补丁建议](responses/2026-10-10-legacy-kp-skill.patch) 交维护者。下一轮设备操作须按异常升级流程重新裁定。
