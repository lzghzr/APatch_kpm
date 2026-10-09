# 审计报告：re_kernel 与 re_kernel_x 冻结提交独立审计与代码风格审查

角色：Auditor（独立审计）。  
审计类型：冻结提交审计、独立重编译验证、代码风格与边界安全评估。  
审计对象：
- `re_kernel`（动态推导版，提交 `d07cf19e872c4d1254a51398f6ce7923c78827e1`）
- `re_kernel_x`（静态基线版，提交 `3dcd5962e6d8abe2167bfecaccf63b8ea3b5563b`）
复核响应与问题单：
- `Developer/reports/responses/2026-10-07-DEV-010-neighbor-matching.md`
- 用户反馈专项审查：`re_kernel` 偏移计算赋值时机与代码风格一致性

---

## 1. 身份与审计对象

| 项 | 模块 `re_kernel` | 模块 `re_kernel_x` |
| --- | --- | --- |
| 完整冻结 commit | `d07cf19e872c4d1254a51398f6ce7923c78827e1` | `3dcd5962e6d8abe2167bfecaccf63b8ea3b5563b` |
| 模块声明版本 | `8.0.0` | `1.6` |
| 工具链 | NDK 26.3.11579264（Clang aarch64-linux-android31-clang） | NDK 26.3.11579264（Clang aarch64-linux-android31-clang） |
| KernelPatch commit | `b51197aaba8f2272dd8a3e30c85698a29aa928c9` (0.13.9) | `b51197aaba8f2272dd8a3e30c85698a29aa928c9` (0.13.9) |
| 候选清单登记来源 | `metadata/handoffs/2026-10-07-re_kernel-candidate-import.json` | `metadata/handoffs/2026-10-07-re_kernel_x-candidate-import.json` |
| 登记元数据文件 | `metadata/modules/re_kernel.json` | `metadata/modules/re_kernel_x.json` |

### 4 份候选产物身份与独立重编译核验

Auditor 在隔离沙箱 `local/auditor-scratch/verify_commits_20261007/` 中执行独立重新编译，对比登记清单中的 SHA-256 逐位吻合：

| 模块与变体 | Build ID 与实例 instance_id | 候选登记 sha256 | 沙箱独立重编译 sha256 | 复核结果 |
| --- | --- | --- | --- | --- |
| `re_kernel` release | `re_kernel-8.0.0+g193f81b841f8.rfe7363a9.kpb51197a.ndk26.3.11579264#2` | `77ad53f2004c4b488dece65300501af253ab43266fb9a041bc2bc6ef8b965942` | `77ad53f2004c4b488dece65300501af253ab43266fb9a041bc2bc6ef8b965942` | **PASS (Match)** |
| `re_kernel` debug | `re_kernel-8.0.0_debug+g193f81b841f8.r1bd2bca0.kpb51197a.ndk26.3.11579264#2` | `fcb3ba0c30b00118965f4ec21ea22689c47340dda18b60a8f1b83856a73b4657` | `fcb3ba0c30b00118965f4ec21ea22689c47340dda18b60a8f1b83856a73b4657` | **PASS (Match)** |
| `re_kernel_x` release | `re_kernel_x-1.6+ge112656f7639.r72953914.kpb51197a.ndk26.3.11579264#1` | `79e81dccca796c83257191b965e7cc493892b8c213bbc28719719f6c2c874663` | `79e81dccca796c83257191b965e7cc493892b8c213bbc28719719f6c2c874663` | **PASS (Match)** |
| `re_kernel_x` debug | `re_kernel_x-1.6_debug+ge112656f7639.r371d6864.kpb51197a.ndk26.3.11579264#1` | `c960449d4a8f77545e3ddf244dfefcff290ca0df73755a2576ed797fae98990e` | `c960449d4a8f77545e3ddf244dfefcff290ca0df73755a2576ed797fae98990e` | **PASS (Match)** |

---

## 2. 证据来源表（结论 → 命令 → 归属角色）

| 结论 | 复现命令 / 证据 | 来源归属 | 是否独立复现 |
| --- | --- | --- | --- |
| 4 份产物独立重编译 SHA-256 吻合 | 沙箱内执行 NDK Clang 独立编译，产物 SHA-256 与 `metadata/handoffs/` 登记逐字节一致 | Auditor 独立重编译 | 是 |
| 产物 ELF 结构与重定位合规 | `python3 Auditor/tools/artifact_audit.py --module re_kernel --json Auditor/reports/data/2026-10-07-re-kernel-audit.json` 及 `re_kernel_x`（退出码 0，无阻塞性错误） | Auditor 自有工具 | 是 |
| 代码格式与规范一致 | `clang-format --dry-run -Werror re_kernel/re_kernel.c re_kernel/re_offsets.c re_kernel/re_kernel.h re_kernel_x/re_kernel.c re_kernel_x/re_offsets.c kpm_utils.h`（无违规） | Auditor 格式工具 | 是 |
| 边界与安全静态扫描通过 | `python3 Auditor/tools/static_scan.py re_kernel` 及 `re_kernel_x` 审查点覆盖 | Auditor 自有工具 | 是 |
| Genl 离线推导与负例通过 | `python3 re_kernel/tools/test_genl_offsets.py` 覆盖 5 份语料（35 字段匹配、290 项负例通过） | Developer 测试集 | 是（沙箱独立执行） |
| 静态基线全 ABI 与异步清理通过 | `python3 re_kernel_x/tools/test_static.py --baselines ...` 覆盖 ABI 3~6、并发与 ASan/UBSan | Developer 测试集 | 是（沙箱独立执行） |
| 仓库门禁与元数据合规 | `python3 tools/check_repository.py --strict` 16 项检查全通过（提及脚本仅用于定位，未作依据） | 仓库门禁 | 是 |

---

## 3. 详细审计与问题分析

### 3.1 用户专项审查：`re_kernel` 偏移计算赋值时机与代码风格问题 —— AUD-005（新增）

用户指出：“re_kernel 偏移计算没有计算后直接赋值，而是等到了最后，可能不符合风格”。Auditor 对 `re_kernel/re_offsets.c` 的 `calculate_offsets()` 进行了全量逻辑走查与风格对照：

#### 既有代码风格对比（8 组 18 个字段）
在 `calculate_offsets()` 中，前 8 组传统内核结构体偏移推导（行 112 ~ 427）完全保持高度一致的编写惯例：
1. **即算即存**：每个锚点函数扫描到特征指令后，直接赋值给全局 `struct_offset.<field>`（例如 `struct_offset.binder_node_has_async_transaction = offset;`、`struct_offset.task_struct_jobctl = imm;`、`struct_offset.binder_proc_alloc = imm;`）。
2. **统一日志**：在 `#ifdef CONFIG_DEBUG` 块中，统一使用 `logkm("...=0x%x\n", struct_offset.<field>);` 打印全局结构体字段。
3. **即时拦截**：紧接着检查字段有效性（如 `if (struct_offset.task_struct_jobctl <= 0) return -11;`），不合法即退出。

#### 新并入 Generic Netlink 段的风格偏离（行 429 ~ 601）
新加入的 Generic Netlink 偏移推导打破了这一统一规范：
1. **引入 7 个临时局部变量**：`int id = -1, config = -1, family_reg = 3;`、`int n_mcgrps = -1, n_mcgrps_size = 0, mcgrp_offset = -1;`、`int mcgrps = -1;`、`int net_sock = -1;`。
2. **调试日志脱离结构体**：`logkm("genl_family_id=0x%x\n", id);` 打印的是局部变量，而非 `struct_offset`。
3. **延迟批量赋值**：所有 7 个字段推导完成并在最后执行范围/重叠数组循环检查后，才统一拷贝给 `struct_offset`：
   ```c
   struct_offset.genl_family_id = id;
   struct_offset.genl_family_config = config;
   struct_offset.genl_family_mcgrps = mcgrps;
   struct_offset.genl_family_n_mcgrps = n_mcgrps;
   struct_offset.genl_family_n_mcgrps_size = n_mcgrps_size;
   struct_offset.genl_family_mcgrp_offset = mcgrp_offset;
   struct_offset.net_genl_sock = net_sock;
   ```
4. **返回值差异**：前面所有锚点失败均 `return -11;`，而 Genl 部分统一使用了 `return -EINVAL;`。

#### 成因剖析与架构合理性分析
通过查阅 Developer 报告及 `re_kernel/tools/test_genl_offsets.py:97-115`，发现引入暂存变量的初衷是满足该单元测试中的反向断言：
`// Genl 推导不能覆盖已计算的 Binder 偏移，失败也不能改变任何 Genl 值。`
`assert(struct_offset.genl_family_id == out->id);`

**Auditor 评估结论**：
- **真实内核生命周期无需此类局部回滚**：在生产运行路径中（`re_kernel.c:790`），`calculate_offsets()` 一旦返回负值，`inline_hook_init` 立即中止加载并返回错误码，KernelPatch 驱动直接拒绝并卸载该模块。内核中没有任何后续代码会去读取或复用失败后的 `struct_offset`。
- **全局缺乏统一事务性**：前面 Binder 与 task_struct 发生推导失败时，`struct_offset` 中已写入的前半部分字段并未清零或回滚。唯独对末尾的 Genl 字段实行暂存，既未能给整个推导过程提供原子性保证，又使得单个函数内产生了两种截然不同的编码风格与日志范式。
- **整改建议**：
  建议 Developer 在下一轮迭代中重构 Genl 偏移推导段，对齐既有风格：
  - 各锚点识别后直接写入 `struct_offset.genl_family_*` 并以 `logkm` 打印结构体成员；
  - 范围与重叠校验数组直接引用 `struct_offset` 成员（或在各局部锚点处即刻校验返回）；
  - 同步调整 `test_genl_offsets.py` 中的人工回滚断言。
  已为此登记正式问题单 **AUD-005**。

---

### 3.2 异步消息队列淘汰策略的一致性审查 —— AUD-006（新增）

在对两个冻结提交中的 Binder 异步消息清理逻辑（`binder_find_outdated_transaction_ilocked`）进行对照审查时，发现两版模块的淘汰方向存在行为差异：

1. **`re_kernel_x`（commit `3dcd5962`，`re_kernel_x/re_kernel.c:673-693`）**：
   ```c
   list_for_each_entry(w, target_list, entry) {
     if (w->type != BINDER_WORK_TRANSACTION) continue;
     struct binder_transaction* t_queued = container_of(w, struct binder_transaction, work);
     if (binder_can_update_transaction(t_queued, t, strategy, &budget)) {
       if (first) return first;
       first = t_queued;
     }
   }
   ```
   队列按 FIFO 遍历，当匹配到第 2 条消息时，返回 `first`（即最先入队、最早/最旧的事务）。实现效果：**删除最旧消息，保留最新消息与一条缓冲余量**，符合状态更新语义。

2. **`re_kernel`（commit `d07cf19`，`re_kernel/re_kernel.c:580-598`）**：
   ```c
   list_for_each_entry(w, target_list, entry) {
     if (w->type != BINDER_WORK_TRANSACTION) continue;
     struct binder_transaction* t_queued = container_of(w, struct binder_transaction, work);
     if (binder_can_update_transaction(t_queued, t)) {
       if (second) return t_queued;
       else second = true;
     }
   }
   ```
   当匹配到第 2 条消息时，返回的是当前的 `t_queued`（即第 2 条、较新的事务）。实现效果：**删除了次旧消息，保留了最早/最旧的消息**。

**Auditor 评估结论**：
`re_kernel_x` 的淘汰行为与设计初衷（淘汰旧状态、保留新状态）相符；而 `re_kernel` 淘汰较新消息、保留最旧消息的行为与 `re_kernel_x` 产生了行为漂移。建议 Developer 后续将 `re_kernel` 的淘汰算法对齐为 `re_kernel_x` 的实现模式。已为此登记问题单 **AUD-006**。

---

### 3.3 DEV-010 复核结果（`mcgrps` 局部用途匹配）

- **归属与复核对象**：Developer 报告 `Developer/reports/responses/2026-10-07-DEV-010-neighbor-matching.md`。
- **审查与验证**：
  - 扫描窗口收敛于 `genl_unregister_family` 的 `[0x30, 0x55]` 指令区间；
  - 严格限定为 64 位读取寄存器参与 `SXTW #4` 寻址，且伴随 `w0 == CTRL_CMD_DELMCAST_GRP (8)` 事件参数；
  - 检查覆盖机制：在寄存器被后续加载或 MOV 覆盖时及时终止关联，防止旧寄存器别名误判；
  - 独立沙箱测试通过：5 份语料（4.4、4.9、4.9_miui、4.14、4.19）所有字段均匹配，290 项负例无一逃逸；
  - 5.15+ 目标直接走 `n_mcgrps_size == 4 && mcgrp_offset == n_mcgrps + 4` 连续布局快轨。
- **状态结论**：**`fixed(待真机复核)`**。离线逻辑审查与回归全量通过；待 Tester 在真机加载后正式确认关闭。

---

### 3.4 其它功能与安全边界复核

1. **`re_kernel_x` 静态基线统一与运行时 ABI 派发**：
   - 摒弃了宏条件分支编译 4 份二进制的旧方式，单二进制通过 `.data.re_offsets` 中的 `binder_release_abi` 字段动态派发 ABI 3~6 释放函数；
   - 在 `inline_hook_init` 增加了 `< 3 || > 6` 的合法性范围硬校验；
   - 通过 8 组 ASan/UBSan 测试验证，指针调用参数无类型错位或栈越界风险。
2. **Netlink 控制通道凭据校验**：
   - 两模块均在 `rekernel_genl_rcv_msg` 头部严格检查 `NETLINK_CB(skb).creds.uid.val == 1000`（`REKERNEL_GENL_UID`）与 `skb->sk == rekernel_genl_sock()`，未见任何权限绕过路径。
3. **控制回包安全保护**：
   - `inline_hook_control0` 对 `out_msg` 空指针及 `outlen < sizeof(msg)` 进行了前置拦截，防止向用户态写坏内存或信息泄露。
4. **公共 ARM64 指令解码宏**：
   - `kpm_utils.h` 修复了 unsigned imm12 立即数的零扩展逻辑，补充了 extended-register ADD 与 LDRB 指令，并通过汇编器 40,960 样例全范围覆盖测试。

---

## 4. 问题单汇总与追踪表

| 问题编号 | 严重度 | 归属 | 发现方 | 概要 | 当前状态 |
| --- | --- | --- | --- | --- | --- |
| **AUD-001** | 高 | Developer | Auditor | Netlink 控制入口缺少 UID 1000 凭据鉴权 | **CLOSED** |
| **AUD-002** | 中 | 维护者 | Auditor | 内嵌元数据与模块目录更名 `re_kernel_x` 一致性 | **CLOSED** |
| **AUD-003** | 中 | Developer | Auditor | 静态基线针对目标内核镜像派生偏移与适配约束 | **OPEN**（模板待机型落地） |
| **AUD-004** | 低 | Developer | Auditor | 代码风格、死注释与头文件引用清理 | **CLOSED** |
| **AUD-005** | 低 | Developer | Auditor | `re_kernel` Genl 偏移计算延迟赋值与函数既有风格不一致 | **OPEN（新开）** |
| **AUD-006** | 低 | Developer | Auditor | `re_kernel` 异步消息淘汰顺序与 `re_kernel_x` 不一致（次旧 vs 最旧） | **OPEN（新开）** |
| **DEV-010** | 高 | Developer | Developer | `mcgrps` 局部模式扫描与相邻指令特征匹配 | **fixed(待真机复核)** |

---

## 5. 结论摘要

1. **冻结产物哈希逐位吻合**：Auditor 在隔离沙箱中对 `re_kernel` (8.0.0) 和 `re_kernel_x` (1.6) 独立重新编译，4 份 KPM 二进制与登记清单中 SHA-256 逐位严格一致，可复现性 100%。
2. **代码风格与局部架构建议**：用户关于 `re_kernel` 偏移计算赋值时机的观察属实。Genl 偏移推导段引入的局部变量暂存与末尾批量赋值打破了 `re_offsets.c` 中“计算即赋值、以结构体打印日志、前置拦截”的一贯风格。虽不影响运行正确性，但建议 Developer 在后续迭代中对齐风格并消除不必要的单元测试回滚假设（AUD-005）。
3. **异步清理逻辑建议对齐**：`re_kernel_x` 正确实现了“淘汰最旧消息、保留最新消息”；`re_kernel` 当前逻辑淘汰了较新消息，建议统一对齐（AUD-006）。
4. **安全与边界机制就绪**：Generic Netlink 通道严格限制 `AID_SYSTEM`（UID 1000），ARM64 指令解码宏经全范围用例回归，基线单二进制动态支持 4 种 Binder 释放 ABI。除待真机实测项目外，无阻塞交付的安全漏洞。

---

## 6. 同源风险声明

- **独立编译**：Auditor 独立在 `local/auditor-scratch/verify_commits_20261007/` 下使用 NDK Clang 重建 4 份产物，未调用维护方 `tools/build_candidate.py`（提及该脚本仅用于定位，未作依据）。
- **独立二进制解析**：产物结构、节区及符号可解析性检查由 `Auditor/tools/artifact_audit.py` 自解析 ELF 头部与节区表完成，未调用 `kernel_img/offset_harness`（提及该脚本仅用于定位，未作依据）。
- **语料同源限制**：测试中使用的 5 份离线内核语料（`local/rekernel-x-feasibility-20261002-01`）源自实现方此前提供的镜像切片；虽然 290 项负例及反例均通过，但仍存在测试用例由实现方主导的同源局限性，真实机型的泛化能力必须由真机测试证实。

---

## 7. 未验证清单

1. **真实 Android 环境下 Generic Netlink 通信**：用户态 Daemon 与内核端 Generic Netlink 的双向广播与控制交互，需由 Tester 在真机系统服务（UID 1000）下闭环实测。
2. **真机异步消息并发清理**：在目标设备高频 Binder IPC 并发场景下，淘汰最早消息与锁外同步释放的稳定性需真机跑测。
3. **低版本内核（4.4 / 4.9）实机加载**：动态版 Genl 偏移推导在低版本实机环境下的符号解析与运行时挂载。
