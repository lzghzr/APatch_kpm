# 冻结提交候选构建（rek / rekx / run_cmd_demo / hosts_redirect / dont_kill_freeze / cgroupv2_freeze）

Developer；2026-10-10。以冻结提交 `2257f2291e2be77c8809c266393da9d9d093d7b4` 为唯一输入，用统一候选入口
`tools/build_candidate.py` 构建 6 个模块共 13 份 KPM。本轮不改动源码、测试与断言；冻结前的探索记录已按
「冻结后需重新构建候选」的约定重做身份绑定。这是 Developer 构建与 Tier-3 宿主自检，**不是独立审计，也不是实机结论**。

## 身份

| 项 | 值 |
| --- | --- |
| commit | `2257f2291e2be77c8809c266393da9d9d093d7b4` |
| KernelPatch commit | `b51197aaba8f2272dd8a3e30c85698a29aa928c9`（已初始化且干净） |
| 工作树 | 每个候选构建窗口内均为干净（修改 0 / 删除 0 / 未跟踪 0） |
| 工具链 | NDK 26.3.11579264（`ANDROID_NDK` 显式传入并进入配方记录） |
| 构建目标 | rek、rekx、run_cmd_demo `all debug`；hosts_redirect、dont_kill_freeze、cgroupv2_freeze `debug` |
| 构建事务 | 冻结输入 → 移走旧产物/中间产物 → `make -B` → 复核输入未变 → 归档 → 登记/交接 |
| 布局输出 | rek/rekx 静态基线的 `.kpm.json` 输出到 `LAYOUT_DIR=../local/post-freeze-candidate-20261010-09383f4c/<module>-layout` |
| 登记去向 | rek、rekx 各 4 份受控追加 `metadata/modules/*.json` 的 `builds[]`；run_cmd_demo 2 份、hosts_redirect / dont_kill_freeze / cgroupv2_freeze 各 1 份产出交接清单，待维护者建/补模块元数据后 `import-manifest` 导入 |

构建顺序说明：登记会立即修改 `metadata/`，使工作树对下一次候选构建变脏。因此先完成 rek 的登记并把该次追加
暂存到私有证据目录、复原冻结版元数据；随后在干净窗口内完成四份交接型构建与 rekx 登记；最后原样写回 rek 的追加
（写回文件 SHA-256 与登记产出逐字节一致：`d96dcf4981c4734e7219eb956a64ca7266c65dec17536710a410075b4556d456`）。
本次全部构建都发生在干净窗口内，`source_dirty=false`。

四个模块的交接清单为
[run_cmd_demo](../reports/handoffs/run_cmd_demo-20261010-frozen-candidate.json)、
[hosts_redirect](../reports/handoffs/hosts_redirect-20261010-frozen-candidate.json)、
[dont_kill_freeze](../reports/handoffs/dont_kill_freeze-20261010-frozen-candidate.json)、
[cgroupv2_freeze](../reports/handoffs/cgroupv2_freeze-20261010-frozen-candidate.json)；
归档产物在 `artifacts/<instance_id>/`（含各自 `MANIFEST.json`）。

## 产物身份（13 份）

配方指纹列只给前 16 位，完整值见 `metadata/modules/*.json` 与上述交接清单。

| 产物 | instance_id | 配方指纹 | SHA-256 | 字节 |
| --- | --- | --- | --- | --- |
| `cgroupv2_freeze_1.0.12_debug.kpm` | `cgroupv2_freeze-1.0.12_debug+gbb3cbdfdb1cd.rbfff8154.kpb51197a.ndk26.3.11579264#1` | `bfff81547cbf4321…` | `f570ae2d81ff2c2d7050e34098eaa2f9faae6de59fedf136d96627e33281f0c2` | 34336 |
| `dont_kill_freeze_1.0.2_debug.kpm` | `dont_kill_freeze-1.0.2_debug+g66d4b596b2ea.r26ef28f9.kpb51197a.ndk26.3.11579264#1` | `26ef28f9745513d6…` | `396ddf38cd0c98587a8d2903cb2d4f1618f652a440960dbf3a74859837d3bb68` | 11808 |
| `hosts_redirect_2.0.0_debug.kpm` | `hosts_redirect-2.0.0_debug+gc645a901ca7a.rb04db02f.kpb51197a.ndk26.3.11579264#1` | `b04db02fb0949a2e…` | `b5c8cb51e95e92168c639fe353da49311f9e3684a5be9bbce54a2f6ed1a23767` | 12328 |
| `re_kernel_11.7.kpm` | `re_kernel-11.7+g63a3af7d7034.r3efcc29a.kpb51197a.ndk26.3.11579264#1` | `3efcc29afe48ff76…` | `3ddb8fc9a69010bd87092f0d6b3d0af4e313585b1630d9c64f8a4517f2f86482` | 80600 |
| `re_kernel_11.7_baselines.kpm` | `re_kernel-11.7_baselines+g63a3af7d7034.ra3221655.kpb51197a.ndk26.3.11579264#1` | `a3221655d31c7c8e…` | `eb5d252c45603a23305ea6526d58339549ae92b861fc4ce92477b020c270d60b` | 34760 |
| `re_kernel_11.7_baselines_debug.kpm` | `re_kernel-11.7_baselines_debug+g63a3af7d7034.rdfb99af0.kpb51197a.ndk26.3.11579264#1` | `dfb99af0fbdaa6c0…` | `3f28328078a41807b1eb969d608b8c2621ef51e672a16355fc3bd85147c495c1` | 35552 |
| `re_kernel_11.7_debug.kpm` | `re_kernel-11.7_debug+g63a3af7d7034.rfd66d6af.kpb51197a.ndk26.3.11579264#1` | `fd66d6af0cd8f318…` | `3dba88b800871dac66e8a78ae84775213b0d967aa444d652fa6846065f6895c9` | 85440 |
| `re_kernel_x_1.6-20261008.kpm` | `re_kernel_x-1.6-20261008+gc98feee61782.r05be2926.kpb51197a.ndk26.3.11579264#1` | `05be2926f4f57a5d…` | `151ef48c73afe7703c13778cbaffccf0c5b900bd1e6b98aea2d483933b33030f` | 93744 |
| `re_kernel_x_1.6-20261008_baselines.kpm` | `re_kernel_x-1.6-20261008_baselines+gc98feee61782.rfed0f482.kpb51197a.ndk26.3.11579264#1` | `fed0f482417f5ec8…` | `2933c90f15c4ec66872fce0e6f2222e10fd314dfe31a69d7ca998df60201144a` | 42360 |
| `re_kernel_x_1.6-20261008_baselines_debug.kpm` | `re_kernel_x-1.6-20261008_baselines_debug+gc98feee61782.r70edd8bb.kpb51197a.ndk26.3.11579264#1` | `70edd8bbba83b1f9…` | `ed6f97dcf8cdaf8498d22ecc5de410a4887e3492e38aa585f2ffded091ad8b0a` | 41728 |
| `re_kernel_x_1.6-20261008_debug.kpm` | `re_kernel_x-1.6-20261008_debug+gc98feee61782.rafb02aeb.kpb51197a.ndk26.3.11579264#1` | `afb02aeb145bb32f…` | `e6ce734b2ad7c60290b495c86244a988e8180462711a63fb57e88cbecdd73304` | 98968 |
| `run_cmd_demo_1.2.0.kpm` | `run_cmd_demo-1.2.0+g9669c80f9942.r2e72bd0b.kpb51197a.ndk26.3.11579264#1` | `2e72bd0b1d3ac6a7…` | `d1ebd33b0675d4a6c655348615ffdd209a2910fc12d76c57574e7658a44eb1b7` | 27016 |
| `run_cmd_demo_1.2.0_debug.kpm` | `run_cmd_demo-1.2.0_debug+g9669c80f9942.r534a6113.kpb51197a.ndk26.3.11579264#1` | `534a6113262a678c…` | `a1a78b752d4638e3decce97088aa9df49f2384f7315127289258037c4a938cfc` | 27016 |

8 份在册实例（rek、rekx）逐条通过 `identity.py verify --profile candidate`：配方指纹可重算、有效编译参数已捕获、
`source_dirty=false`、源码按绑定提交 blob 逐文件核验（25 / 15 个文件）、产物哈希复算一致，0 处问题。
四份交接清单的 5 份候选条目用同一 `verify_build(profile="candidate")` 复核亦为 0 处问题，但**在维护者
`import-manifest` 之前它们不在 `metadata/` 中，不能作为已登记实例引用**。

## 变更点

- 本轮输入是冻结批次的四个提交：`4accb38`、`f05ca43`（rek、rekx 的 BTF 与双偏移模式）、`88f63c4`
  （run_cmd_demo 1.2.0）、`2257f22`（rek/rekx 与 hosts_redirect、dont_kill_freeze、cgroupv2_freeze 的偏移推导日志清理）。
- 本次构建不产生源码变更：本轮结束时工作树只多出两处预期的身份追加（`metadata/modules/re_kernel.json`、
  `re_kernel_x.json`）与四份新增交接清单；模块源码、测试源码与断言逐字节未变（未修改 Oracle）。
- 公共头 `kpm_utils.h` 在 `4accb38` 增加 BTF 记录与查询封装，因此复用它的模块重新编译；不影响控制流推导范围。

## 自检

```text
python3 tools/build_candidate.py <module> --toolchain ndk26.3.11579264 --target "<目标>" \
    --env ANDROID_NDK=<ndk26.3.11579264> [--env LAYOUT_DIR=../local/<本轮私有目录>/<module>-layout] [--handoff <清单>]
→ 13 份产物，构建事务与输入一致性检查通过，8 份登记 / 5 份交接
```

- 构建警告：rek、rekx 各 20 条，dont_kill_freeze、hosts_redirect 各 3 条，cgroupv2_freeze、run_cmd_demo 0 条。
  警告种类与冻结前同一模块完全相同，全部来自 KernelPatch 内核头（`cmpxchg.h` 末尾标签与 `ret` 可能未初始化、
  `rwonce.h`/`compiler.h` 的 `READ_ONCE`/`WRITE_ONCE` 重定义），模块自身源码无新增警告。
- 宿主自检（全部 rc=0）：
  - `re_kernel/tools/test_genl.py`：Genl/调用上下文、短锚点、Binder from / is_dead / alloc、异步清理与清理流程；
  - `re_kernel/tools/test_modes.py`：八份模式标签产物、静态导入与表补丁边界、动态零表；
  - `re_kernel/tools/test_btf.py`：合成 BTF 夹具（嵌套/匿名成员、共同布局、原生错误契约，rek、rekx 双模块）；
  - `re_kernel_x/tools/test_static.py --baselines <rekx 静态基线 + 布局>`：真实基线往返、四 ABI 释放参数、ASan/UBSan；
  - `re_kernel/tools/check_build.py`：rek 4 份 / rekx 4 份的未定义导入与 SDK 导出逐项匹配（19/15/15/19、21/18/18/21），
    实际指令无 FP/SIMD/SVE/x18 操作数；
  - `run_cmd_demo/tools/test_run_cmd.py`：异步/凭据/固定窗口偏移，另加 Sony 5.15 镜像的入口判据（path=0x38、sid=4、security=0x78、blob=0）。
- 离线语料回归（在冻结输入上重跑）：
  - 函数推导 11 份语料（android12-5.10、android13-5.10、android13-5.15、android14-5.15、android14-6.1、android15-6.6、
    mi10-4.19、mi11-5.4、mi6-4.4、mi8-4.9、mi9-4.14）全部 PASS；4.4～5.10 六份 `full_rc=0`，
    三份 5.15/6.1/6.6 按预期 `full_rc=-11`（这些版本默认走 BTF），socket 短链判据全部 PASS；
  - BTF 6 份语料（android13-5.10/5.15、android14-5.15、android14-6.1、android15-6.6、android16-6.12）PASS；
  - run_cmd_demo 偏移语料 9 份镜像（kernel_4.4、4.9、4.9_miui、4.14、4.19、5.15、6.1、6.6、B2N-416G_boot.img）
    与其 `reference.json` 逐项一致，另加 Sony 5.15 一份。
- 门禁：`python3 tools/selftest_tools.py` 21/21；`python3 tools/check_repository.py` 16 项检查 0 失败 0 警告。
  门禁通过不等于候选交接或验收。

## 与冻结前探索轮的字节一致性

- rek、rekx 共 8 份产物与 `offset-windows` 探索轮**逐字节一致**，并且该轮清单记录的全部构建输入哈希与冻结树
  **逐文件相同（0 处差异）**。因此那一轮的 13 份语料结论与 ELF 检查对本轮候选同样成立：不是"看起来相同"，
  而是输入与产物都相同。
- hosts_redirect、dont_kill_freeze 的 debug 产物与 `offset-logging` 探索轮逐字节一致（该轮公共头较旧，
  但两份模块不引用新增的 BTF 部分）。
- cgroupv2_freeze 本轮重新产出（公共头更新所致），字节与探索轮不同；该模块没有宿主测试。
- run_cmd_demo 本轮首次按冻结源码构建（探索轮与冻结内容在 `run_cmd.h`、`kpm_utils.h` 两处不同），
  因此它的镜像自检本轮全部重跑。

## 未解决项与降级行为

| 项 | 影响 | 当前行为 |
| --- | --- | --- |
| 6.12 / 6.18 的函数推导 | 该两份语料 `symbols.json` 缺 `binder_proc_transaction`，夹具的四个必需查询无法满足 | 记为未执行；两份语料由 BTF 路径覆盖（6.18 无 `reference.json`，仍为前瞻观察，未覆盖） |
| 6.18 目标 | 上轮观察 BTF 返回 -ENOENT、`binder_alloc` 无 `buffer`，KP 尚不支持 | 不新增按版本猜偏移的分支，保持降级/未适配 |
| kernel_4.14.186、boot-250514.img | 本轮语料目录缺 `symbols.json` | 未执行，按未覆盖记录 |
| cgroupv2_freeze | 模块无宿主测试，本轮仅有构建与候选核验 | 行为等价性留给独立审计 |
| 四份交接清单 | 尚未进入 `metadata/` | 由维护者 `import-manifest` 导入后方可 `verify` 引用 |

## 已知可疑点（请 Auditor 重点看）

- cgroupv2_freeze 的 debug 产物因公共头 `kpm_utils.h` 更新而重新产出，字节与上一轮不同；其引用公共头的实际路径与行为影响没有独立证据。
- `*.kpm.json` 布局文件属于通用构建器认定的构建输入扩展名（`.json`）：布局若写进模块目录，会在构建期间新增输入并触发
  「构建期间构建输入发生变化」拒绝登记。本轮沿用既有做法把布局输出到独立 `LAYOUT_DIR`，**未修改共享工具或检查范围**；
  该约定是否写入门禁/流程由维护者决定。
- 交接清单候选在 `metadata/` 之外，`identity.py verify` 只能核验已登记实例；导入前的引用需人工核对清单哈希。

## 边界声明

> 本轮结论来自实现方自检（冻结提交构建 + Tier-3 宿主测试 + 离线语料回归），**不是独立审计，也不是实机结论**。
> 跨版本正确性、权限与生命周期安全、真机可用性分别由 Auditor 与 Tester 出具；本轮未操作设备、未接触 superkey。

## 私有证据

`local/post-freeze-candidate-20261010-09383f4c/`：

- `verification.json`：13 份产物身份、字节一致性映射、自检与门禁结果、未覆盖清单；
- 四份交接清单副本 `handoffs/`，rek/rekx 的布局 JSON `re_kernel-layout/`、`re_kernel_x-layout/`；
- 各模块构建 stdout `*-build.log`，编译器日志在 `local/build_logs/20261010T0653*`、`T0655*`；
- `selfcheck/`：`genl`、`modes`、`btf`、`rekx-baselines`、`dynamic`（11 份语料）、`btf-corpus`（6 份）、
  `run-cmd`、`run-cmd-sony`、`run-cmd-compat/`（9 份镜像）及各自日志；
- `candidate-verify.txt`（8 份实例 candidate 核验）、`handoff-manifest-selfcheck.txt`、`selftest_tools.log`、
  `check_repository.log`；
- 保留的第一次失败尝试：`re_kernel-first-attempt-build.log` 与误落在模块目录的两份 `.kpm.json`
  （`re_kernel-first-attempt-module-json/`）——该次未登记任何身份。
