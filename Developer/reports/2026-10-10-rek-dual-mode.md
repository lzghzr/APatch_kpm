# rek / rekx 静态与动态双模式探索

角色：Developer；日期：2026-10-10。当前为未冻结探索，不是独立审计或实机结论。

## 实现

两模块各构建 static、dynamic、static_debug、dynamic_debug，编译时分别定义 `CONFIG_KPM_STATIC` 或 `CONFIG_KPM_DYNAMIC`，KPM 信息记录 `offset_mode`。同一模块管理名称保留，业务协议继续分别对应自身上游。共用入口 `Developer/templates/kpm-modes.mk`，`all` 生成两种普通版，`debug` 生成两种 debug 版；按模式也可单独构建。`baselines` 保留静态普通/debug 构建入口。

- rek 静态版复用现有 45 项偏移表与补丁工具，任务 UID、comm 和释放 ABI 都从表取得；普通/debug 均不导入 `task_struct_offset` 或 `cred_offset`。
- rek 动态版保留原有表，先使用 BTF，再沿用固定窗口函数推导。
- rekx 静态版的 45 项字段顺序、初值和二进制替换契约保持不变。
- rekx 动态版表初始化为零，仅 `binder_buffer_data=-1`。共用 rek 的 BTF 与函数推导；KP 已有 task/cred 结果填入既有表，skb 尾段由已确认的 ARM64 连续布局取得，socket 命名空间使用短 `sk_net_capable` 链。初始化失败时尚未安装业务 hook。

旧内核的 socket 链仍限定入口 16 条指令。五份实际语料中，4.4 直接读入 x1；其余先用临时寄存器读取 net->user_ns，再 MOV 到 x1。首个候选无法确认时失败，不继续找后面的替代值。函数推导适配范围继续为 4.4～5.10；5.15 及以上默认使用 BTF，没有增加按版本猜偏移的分支。

旧 Binder 缺少原生 `binder_alloc_copy_from_buffer` 时，动态版当前保留 `binder_buffer_data=-1`，添加依赖读取的规则返回 `-EOPNOTSUPP`，基础去重可继续。静态版可按实际证据填写内核 data 偏移。该降级不应被记录为旧内核已覆盖全部规则功能。

## 自检与范围

使用者确认五份旧内核以及四份 BTF 语料。缓存使用前复算实际源镜像和 Image 哈希；BTF 确认是 Image 中的实际字节片段。裸内核缓存只用于减小重复提取工作，用户入口仍可为 img。

| 输入 | 生产推导宿主结果 | 释放 ABI |
| --- | --- | --- |
| kernel_4.4 | 完整函数返回 0；socket 链通过 | 3 |
| kernel_4.9 | 完整函数返回 0；socket 链通过 | 4 |
| kernel_4.9_miui | 完整函数返回 0；socket 链通过 | 4 |
| kernel_4.14 | 完整函数返回 0；socket 链通过 | 4 |
| kernel_4.19 | 完整函数返回 0；socket 链通过 | 4 |
| boot_67.2.A.3.178.img | BTF：rek 38 项、rekx 45 项与参考一致 | 5 / off_end_offset |
| kernel_5.15 | BTF：rek 38 项、rekx 45 项与参考一致 | 5 / off_end_offset |
| kernel_6.1 | BTF：rek 38 项、rekx 45 项与参考一致 | 5 / off_end_offset |
| kernel_6.6 | BTF：rek 38 项、rekx 45 项与参考一致 | 5 / off_end_offset |

旧内核夹具运行实际完整 `calculate_offsets()`，只解释 ARM64 字节，不执行目标机器码。KP 的 cred/comm/uid 结果由宿主夹具输入提供，因此不证明目标 KP 的偏移计算；表中这些测试值不用于生成目标静态配置。另从同一实际入口运行新增片段，核对五份 socket 链均为 0x30。全流程返回成功仅证明该推导在这些机器码上完成，未逐字段独立证明全部旧内核布局。

最终自检包括：

- 两模块全部 8 份 KPM 构建及 ELF 导入检查，未定义导入均对应 KP 0.13.9 SDK 导出，未发现 FP/SIMD/SVE/x18 操作数。每次编译仍有既有 SDK 的 5 个头文件警告，新代码无编译警告。
- 四份实际 BTF × 两模块、完整合成 BTF 的 ASan/UBSan 自检通过。实际四份都是 ABI5；ABI3/4/6 的 BTF 分派通过合成验证，不能外推为实际 ABI6 设备覆盖。
- 原 rek 的 8 组消息、上下文、Genl、指令及清理 Oracle 通过；原 rekx 静态补丁与业务 Oracle 通过，保留四种 ABI 分派、数据读取、规则、UID、并发及清理判据。
- 新双模式自检覆盖元信息、动态表零初始化、静态导入、四种 ABI 配置补丁只改表、SDK 字段存储、socket 寄存器传递和固定窗口失败路径。
- 15 个既有测试文件（含两项维护者门禁测试）字节保持不变。上轮新建的 BTF 驱动只将模式宏 `CONFIG_REKERNEL_BTF` 改名为 `CONFIG_REKERNEL_X`，保留断言。本轮新建夹具修正不变更已有 Oracle。
- 项目 clang-format、`git diff --check` 与 regular 仓库门禁通过（16/16）。本轮开始时 282 个归档产物、MANIFEST 和既有清单保持原哈希。

私有证据：`local/rek-dual-20261010-zjknhsbg/` 下的 `legacy-production-final/receipt.json`、`btf-final-*/receipt.json`、`btf-synthetic-final/receipt.json`、`rek-host-final/receipt.json`、`rekx-static-final.log`、`modes-final/receipt.json`、两份 `*-elf-final.json`、`identity-final.json`、`oracle-preservation-all.json` 与 `preservation-final.json`。早期失败输出保留，最终结果用新目录记录。

## 全项目规范与维护者接入

默认规范写入 `Developer/README.md`，当前只接入 rek / rekx，其余有偏移依赖的模块随后逐个迁移；无偏移依赖的模块继续生成通用 KPM。

维护者路径的调整见 [补丁建议](../proposals/2026-10-10-kpm-modes/README.md)：根目录 AGENTS 固化规范、Actions 构建四变体、Releases 发布两模块各一份普通 static/dynamic 与静态 JSON、门禁区分静态布局与动态产物、身份 CLI 接受四种模式。Developer 未直接改写仓库的 AGENTS、Actions 或工具。

补丁副本通过原有 37 条产物门禁与 4 条发布 Oracle，并以实际八份产物确认发布 4 份普通 KPM + 2 份静态 JSON、debug 留在 artifacts；6 个缺项/错配/重复案例被拒绝。新增发布夹具曾暴露 `re_kernel_*` 会匹配 `re_kernel_x_*` 的筛选错误，已按项目数字版本前缀修正；失败副本保留。仓库当前发布行为待维护者落地该补丁。

## 自查决定

are-you-sure：Modify 后 Retain。动态表必须清零，不能继承静态模板；静态 rek debug 的 comm 也必须读取表；旧内核 socket 匹配必须覆盖短寄存器链。这三项已修正并验证。共用已有表、生产推导与原生 BTF API，没有运行时模式切换。一次有界 Developer 反例复核核对了新增字段和发布依赖，不作为独立 Auditor 结论。

no-negative-echo：最终命名使用 static / dynamic，文档说明实际入口与必要兼容行为。respect-the-oracle：原测试文件和断言保留，未为了宿主夹具新增生产专用行为。回读源码、产物信息、偏移表、配套 JSON 与清单。

## DEV-023（低，归属 Developer）：静态默认入口的 ABI 检查回归

- 证据：早期 `rekx-static-test.log` 中既有非法 ABI 初始化断言失败。双模式初始化曾使用 `CONFIG_KPM_STATIC` 的正向分支，导致未声明模式的旧静态编译入口走错分支。
- 影响：旧静态默认编译方式未保留入口行为；正式双模式构建均显式声明模式。频率：未指定模式的编译方式可复现；置信度：已有 Oracle 复现。
- 修复：rekx 延续默认静态行为，只有定义 `CONFIG_KPM_DYNAMIC` 才执行动态初始化；rekx 默认表与默认入口保持一致。旧 Oracle 无修改，最终输出 `rekx-static-final.log` 通过。
- 状态：fixed（待独立复核）；修复属于本轮脏树，身份见下。Developer 不关闭问题。
- 关闭条件：Auditor 在冻结后的源码和新实例上核对默认入口、两种显式模式以及非法 ABI 拒绝，再独立复核关闭。

## 身份与验证边界

统一入口 `tools/build_candidate.py`，工具链 `ndk26.3.11579264`，目标 `all debug`，显式 `--allow-dirty --handoff`。捕获共用模板、偏移推导、BTF 和补丁工具的额外输入；静态 JSON 输出到新的私有布局目录，避免计为构建期间新增源输入。

完整基础提交为 `7cb89e0c8c065443ac019f147c9bf4995f01db61`；KP SDK 为 `b51197aaba8f2272dd8a3e30c85698a29aa928c9`。以下每份均为 source_dirty=true：基础提交不包含本轮修改，按绑定提交的 verify 无法重算新增源码，不能作为冻结候选交接。已逐项复算当前构建输入和归档 KPM，均与清单一致；正式交接须冻结后重新构建。

### re_kernel

清单：[re_kernel](handoffs/re_kernel-20261010-dual-mode-final-exploration.json)。source_tree_sha256：`b67abd8fdefcfd989488aa8f52d3afbc8e1780bb6b88e40bc91bbc0f7b3f3213`。

- dynamic：`re_kernel-11.7_dynamic+gb67abd8fdefc.r1a5da94d.kpb51197a.ndk26.3.11579264#1`；KPM SHA-256：`fb00ca982319b7e7487085781a09aea4e41da9a3af05b10145149be8565d6fe9`。
- dynamic_debug：`re_kernel-11.7_dynamic_debug+gb67abd8fdefc.r0dfa74cb.kpb51197a.ndk26.3.11579264#1`；KPM SHA-256：`b1469dfd2f612f16189c337c103fbdd235aecf42a96acde783102790de38347c`。
- static：`re_kernel-11.7_static+gb67abd8fdefc.rc6075f08.kpb51197a.ndk26.3.11579264#1`；KPM SHA-256：`a54945f94f1fe7b8c11882204f15099681e2d8136f590e4394ef59a69a4b80ba`。
- static_debug：`re_kernel-11.7_static_debug+gb67abd8fdefc.rb5146fb4.kpb51197a.ndk26.3.11579264#1`；KPM SHA-256：`3f3e70d7b73cd68317e7d1457446cf6603a47cd147c2999361e1ab437dfbca1b`。

静态 JSON（未包含在统一构建器的 KPM-only 归档登记中，另行绑定）：

- `re_kernel_11.7_static.kpm.json`：`3cafa93a259119a36754c5521120e41a2c1a6ed01fdf7374d50d6e53df35ec60`；JSON 内的 KPM SHA 与上述静态实例一致。
- `re_kernel_11.7_static_debug.kpm.json`：`fd65d4037a40de705b81d4be59285867b99e18cbd9a94e724e9be415b1e7e636`；JSON 内的 KPM SHA 与上述静态实例一致。

### re_kernel_x

清单：[re_kernel_x](handoffs/re_kernel_x-20261010-dual-mode-final-exploration.json)。source_tree_sha256：`dcacf73849279c031873e72a0b68fbec04e946d08e495e6a851a3de0f1c9080f`。

- dynamic：`re_kernel_x-1.6-20261008_dynamic+gdcacf7384927.r4c2c1ab0.kpb51197a.ndk26.3.11579264#1`；KPM SHA-256：`1fc76b126c5d81f14c4edeeef3cb662cd60494211cfbb405a81b926af8d97a45`。
- dynamic_debug：`re_kernel_x-1.6-20261008_dynamic_debug+gdcacf7384927.r3879d7c9.kpb51197a.ndk26.3.11579264#1`；KPM SHA-256：`e92c9f496ce497991e72f1664a7d6ee144e6a69719c8f33ff91dd07e4955923c`。
- static：`re_kernel_x-1.6-20261008_static+gdcacf7384927.r7cfe2589.kpb51197a.ndk26.3.11579264#1`；KPM SHA-256：`87f62f34151d4bb38dc10fb2b287ff1f3e648f3e5eb043bc3881acf1aa177668`。
- static_debug：`re_kernel_x-1.6-20261008_static_debug+gdcacf7384927.r02ddc407.kpb51197a.ndk26.3.11579264#1`；KPM SHA-256：`94c61f455a2da621091f60804ae5ba731fe25ea98eb8c72dae9268e96df7b7dc`。

静态 JSON（未包含在统一构建器的 KPM-only 归档登记中，另行绑定）：

- `re_kernel_x_1.6-20261008_static.kpm.json`：`5de7d34bbc219bed0e38cc3e96b2ecccf8d85440ff5208caa6595be60bc05098`；JSON 内的 KPM SHA 与上述静态实例一致。
- `re_kernel_x_1.6-20261008_static_debug.kpm.json`：`e71b6b4df620c801f0a47e7b1c90afa11f5a3621304da480bdfd2123b0e91755`；JSON 内的 KPM SHA 与上述静态实例一致。

## 未覆盖

未在真机加载本轮双模式产物。原生 BTF API 执行、SDK 的真实任务偏移、CFI、锁/RCU、Genl 时序、跨厂商共同布局、规则降级和清理业务仍需 Auditor / Tester 绑定新产物验证。旧内核无原生读取入口时的 data 推导尚未实现。卸载生命周期沿用既有暂缓范围。

## 后续记录（2026-10-10）

当前构建入口与追加身份见 [项目构建入口](2026-10-10-rek-project-build.md)。本报告中的构建输入和实例保留为该轮实际记录。
