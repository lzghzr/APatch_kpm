# DEV-011：Sony 5.15 动态 Genl 推导失败修复与全量离线回归

角色：Developer。状态：实现修复待独立复核，尚未冻结候选。本报告是实现方自检，不是审计、真机复测或验收结论。

## 问题与身份

DEV-011（中，归属 Developer）：Genl 固定窗口与局部组播锚点未覆盖 Sony 5.15 的编译形态。

- 发现来源：Tester 的 [Sony 5.15 实机报告](../../../Tester/reports/runs/2026-10-08-re_kernel-8.0.0_5.15_live%231.md)。频率：未知；置信度：当前生产源码在目标镜像离线复现已确认。
- 基线实现 commit：`eed25b4367dbef2ac64502807b514410abb4c60b`；交接 commit：`e34ea88e2314ba04e354132dab4b061332998655`。
- 报告引用的 Debug instance：`re_kernel-8.0.0_debug+g5a7aa01549c3.r03b13379.kpb51197a.ndk26.3.11579264#1`；在册 SHA-256：`60721db1cf2881ba157b54291ac3ac922b0b9f24b6a803abf67876f412370df8`。实际加载文件身份有差异，见 DEV-013，不能直接把实机失败绑定到该在册字节。
- 影响：这类目标初始化返回 `-11`，模块功能不能启用。没有证据把此兼容性缺口定性为崩溃。
- 关闭条件：Auditor 核对新冻结提交及测试边界调整，Tester 对新登记实例复测 Sony 目标并绑定实际加载 SHA-256；Developer 不自行关闭。

## 根因与修复

从 `boot_67.2.A.3.178.img` 新提取的 Image 与旧提取结果字节相同，SHA-256 为 `ca82d6e899228f4de0cb65b1540dae6cfc6278fd8d52884d8f86e822529cafc0`。

1. `genlmsg_put` 第 7 条读取 `hdrsize`，第 24 条才读取 `id`。原算法只读取前 20 条，离线得到 `id=4, config=-1` 并返回 `-11`。因此报告所说函数体没有读取 id 不准确；实际是读取超出了原窗口。本报告只补充实现方证据，不改写 Tester 报告。
2. 把该固定窗口精确扩到 25 条，保持相邻字段、参数基址、首次调用/返回停止等匹配条件。
3. 随后发现 `mcgrps` 的旧注销局部模式也不匹配：目标保留独立的组播校验函数。增加 `genl_validate_assign_mc_groups` 前 24 条的补充锚点，要求同一入口中出现已识别组数字段的零值检查，以及从组指针读取首组 `name[0]` 的零值检查。缺符号或模式不成立时继续原注销窗口；原 u32 连续布局路径保留。
4. 新锚点不按内核版本分支；不扩扫整函数；字段无法识别仍拒绝初始化。

当前 Sony 七字段：`id=0, config=4, mcgrps=0x50, n_mcgrps=0x27, n_mcgrps_size=1, mcgrp_offset=0x20, net_sock=0x118`，与已有静态目标配置一致。离线整套生产 `calculate_offsets()` 返回 0。

## 测试边界调整范围与技术依据

`test_genl_offsets.py` 的四处 20 条取证/分配长度改为 25 条；`hdrsize_outside_prefix` 的诱饵从指令索引 20 移到 25。理由是目标真实字段位于索引 24，新的生产边界为 `[0,25)`。这是一项明确的边界规范变更，不宣称旧索引 20 负例仍被拒绝。

没有删除断言或用例；原 290 项负例全部保留，仍要求字段缺失、用途错误及新窗口之外的诱饵失败。新增 Sony 入口夹具核验七字段与 20 项拒绝情形，包括索引 25/24 的边界、缺失独立符号、错误组数、结果寄存器被覆盖、XZR 及跨调用匹配。

该边界调整需 Auditor 独立复核。后续冻结时，`test_genl_offsets.py` 的 Oracle 边界变更应单独提交，与生产修改分开；当前只保留工作树修改与独立补丁，没有创建提交。重复 network 测试轮次保留。

## 全量语料范围与结果

用户明确授权当前 `kernel_img/` 全量测试。逐文件列举实际输入，而不是依赖只发现 img 的默认列表。三个 img 经正常解包，九份裸内核直接作为输入。每份使用本轮独立输出目录。

| 输入 | 整套生产 C 推导结果 |
| --- | --- |
| `B2N-416G_boot.img` | 返回 0 |
| `boot-250514.img` | 未覆盖：符号提取失败 |
| `boot_67.2.A.3.178.img` | 返回 0 |
| `kernel_4.14` | 返回 0 |
| `kernel_4.14.186` | 未覆盖：符号提取失败 |
| `kernel_4.19` | 返回 0 |
| `kernel_4.4` | 返回 0 |
| `kernel_4.9` | 返回 0 |
| `kernel_4.9_miui` | 返回 0 |
| `kernel_5.15` | 返回 0 |
| `kernel_6.1` | 返回 -11：mcgrps |
| `kernel_6.6` | 未覆盖：符号提取失败 |

共 12 份：8 份返回 0，1 份识别失败，3 份符号提取未覆盖。返回 0 只证明当前生产推导走完；没有参考值的字段不能据此声明偏移正确，更不证明 hook 或业务兼容。已知参考核验：原五份语料的 35 个 Genl 字段与参考值一致、290 项负例通过；Sony 七字段匹配静态目标配置。

DEV-012（中，归属 Developer，状态 open）：`kernel_6.1` 的 `mcgrps` 未被当前锚点识别。频率未知，置信度离线复现已确认。此镜像未提取到精确名 `genl_validate_assign_mc_groups`，原注销局部模式亦未匹配，独立 Genl 段与整套加载时推导均返回 `-11`。其余 Genl 字段已取得。此轮不靠扩大窗口或猜偏移修复；需要独立确认其入口形态，后续另行适配并复核关闭。

三个符号提取未覆盖项不能定性为内核没有 kallsyms；困难镜像仍需现场分析。

## 构建与证据

在新的隔离目录使用 NDK 26.3.11579264、冻结 SDK `b51197aaba8f2272dd8a3e30c85698a29aa928c9` 构建 release/debug。当前为 dirty exploration，没有候选 instance_id，不用于真机交接。

- Release SHA-256：`0208e0d0b1557f338271da19834f2cc91de4474de142553dabcaa2adc77fc290`，46,120 字节。
- Debug SHA-256：`d2764ab41d730e5780699d14d6db67d7f4f5e389ddfe80de539056a64e02eab4`，54,904 字节。
- ARM64 ELF64 ET_REL，17 项未定义导入与旧候选一致。每变体 5 项现有 SDK 警告；没有为消除 SDK 警告改变 SDK。
- 主机 ASan/UBSan：原 Genl、上下文、指令宏、FIFO 用例及新增入口夹具通过。
- 本地证据：`local/rek-genl-515-mh1o2_9u/` 的 `old.log`、`window25.log`、`new.log`、`legacy-offsets.json`、`host-final/receipt.json`、`all-corpus/results.json`、`build-inputs.json`、`build-results.json`、`artifact-check.json` 和 `source-fingerprint.json`。

## DEV-013：Tester 实际加载文件与报告候选身份待核对

严重度中，归属 Tester，状态 open；频率未知，置信度文件尺寸/本地哈希差异已确认，实际设备文件身份未验证。

Tester 报告推送 Debug 为 54,096 字节，在册绑定产物为 54,056 字节。当前模块目录同名 Debug 为 54,096 字节、SHA-256 `d0c4c27c0230678717ce689f06d1a86ff4be2d58e25ea0e9811d03124dbf680c`，与在册 SHA 不同；相同大小不能证明设备加载的就是当前这份文件。4.4 报告同样推送 54,096 字节，并描述 SDK 0.13.4 重编译，同时引用旧实例；5.15 报告 SDK 表述也不一致。

请 Tester 补充实际推送/设备文件哈希与真实 SDK 来源，绑定新的构建身份或纠正引用。此处不改 Tester 原报告，不以当前源码复现代替设备字节核验。由独立角色复核后关闭，维护者登记 DEV-011/012/013。

## 未覆盖

未操作设备，未复测加载/卸载、Genl 收发、应用行为或并发；新修复未冻结、未登记候选。旧冻结源码和归档产物保留，其他角色报告与元数据不由本轮修改。

问题编号：DEV-011（本轮修复）；DEV-013（Tester 身份核对待处理）。实现修复等待独立复核，未自行关闭。

## 冻结身份补充（2026-10-08）
修复 commit：`f80c9a270c27d611b0147729e11c30d1f25577a1`。Oracle 边界独立提交：`fce5d75ef8e1a3c70921b5afa8e847dab751e707`；均为 Developer 无签名提交。
以下候选由干净冻结工作树经统一构建入口产生，产物字节与前述探索自检一致。Build ID / instance_id / SHA-256：

- base Build ID：`re_kernel-8.0.0+g9c1ce4ad97c0.r96eac7cd.kpb51197a.ndk26.3.11579264`。
- instance_id：`re_kernel-8.0.0+g9c1ce4ad97c0.r96eac7cd.kpb51197a.ndk26.3.11579264#1`。
- 产物 SHA-256：`931aca2529acfad4953ba62b024312b9e88fd6da037f891930a189f8d4485234`，47216 字节。

- debug Build ID：`re_kernel-8.0.0_debug+g9c1ce4ad97c0.r0a32e256.kpb51197a.ndk26.3.11579264`。
- instance_id：`re_kernel-8.0.0_debug+g9c1ce4ad97c0.r0a32e256.kpb51197a.ndk26.3.11579264#1`。
- 产物 SHA-256：`f9cb3b639e906f4f2053e508393bd682026ac3e752fc77c5a2d6d089f8b19322`，56472 字节。

证据：本地 `local/rek-freeze-20261008-tkmm64yd/candidate-verification.json` 的两项 candidate 核验均 `problems=[]`，源码按提交 blob 核验；新归档清单与产物在场且哈希一致。

[统一交接清单](../handoffs/re_kernel-8.0.0-20261008-genl.json) 已准备，维护者导入元数据后交 Auditor / Tester 独立复核。本轮结论来自实现方自检（构建 + 离线语料 + 代码走查），不是独立审计，也不是实机结论。
