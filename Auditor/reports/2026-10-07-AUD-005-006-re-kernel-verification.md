# 审计复核报告：AUD-005 与 AUD-006 修复独立复核与状态关闭

角色：Auditor（独立审计）。  
审计类型：问题单复核、独立沙箱重编译、代码风格与异步队列逻辑审查。  
审计对象：`re_kernel`（修复提交 `eed25b4367dbef2ac64502807b514410abb4c60b`，交接提交 `e34ea88e2314ba04e354132dab4b061332998655`）  
响应来源：`Developer/reports/responses/2026-10-07-AUD-005-006-re_kernel.md`  
交接清单：`Developer/reports/handoffs/2026-10-07-re_kernel-AUD-005-006-candidate.json`  

---

## 1. 身份与审计对象

| 项 | 值 |
| --- | --- |
| 修复 commit | `eed25b4367dbef2ac64502807b514410abb4c60b` |
| 交接 commit | `e34ea88e2314ba04e354132dab4b061332998655` |
| 模块版本 | `8.0.0` |
| 工具链 | NDK 26.3.11579264（Clang aarch64-linux-android31-clang） |
| KernelPatch commit | `b51197aaba8f2272dd8a3e30c85698a29aa928c9`（SDK 0.13.9） |
| 候选登记来源 | `Developer/reports/handoffs/2026-10-07-re_kernel-AUD-005-006-candidate.json` |

### 产物身份与独立沙箱重编译核验

Auditor 在隔离沙箱 `local/auditor-scratch/verify_commits_20261007/re_kernel_aud_fix/` 中执行独立重新编译，产物 SHA-256 逐位吻合：

| 变体 | Build ID / instance_id | 清单登记 sha256 | 沙箱重编译 sha256 | 复核结果 |
| --- | --- | --- | --- | --- |
| release | `re_kernel-8.0.0+g5a7aa01549c3.r8451be48.kpb51197a.ndk26.3.11579264#1` | `8abf338c2e2425556c17ec6a56a0d803fd00e38ad4a84a433eca89129ecc7706` | `8abf338c2e2425556c17ec6a56a0d803fd00e38ad4a84a433eca89129ecc7706` | **PASS (Match)** |
| debug | `re_kernel-8.0.0_debug+g5a7aa01549c3.r03b13379.kpb51197a.ndk26.3.11579264#1` | `60721db1cf2881ba157b54291ac3ac922b0b9f24b6a803abf67876f412370df8` | `60721db1cf2881ba157b54291ac3ac922b0b9f24b6a803abf67876f412370df8` | **PASS (Match)** |

---

## 2. 证据来源表（结论 → 命令 → 归属角色）

| 结论 | 复现命令 / 证据 | 来源归属 | 是否独立复现 |
| --- | --- | --- | --- |
| 独立重编译哈希严格相符 | 沙箱执行 NDK Clang 独立编译，产物 SHA-256 与交接清单完全一致 | Auditor 独立重编译 | 是 |
| AUD-005 赋值风格完全对齐 | `git diff eed25b4^! re_kernel/re_offsets.c` 走查（直接写入结构体，日志统一） | Auditor 源码审查 | 是 |
| AUD-006 异步队列淘汰方向对齐 | `git diff eed25b4^! re_kernel/re_kernel.c` 走查（FIFO 命中第 2 条返回首条） | Auditor 源码审查 | 是 |
| 生产 FIFO 逻辑全用例通过 | 编译并运行 `re_kernel/tools/test_cleanup.c`（10 组用例 PASS） | Developer 测试集 | 是（沙箱独立执行） |
| 离线偏移推导与 290 负例通过 | 运行 `test_genl_offsets.py` 覆盖 5 份语料（35 字段匹配、290 项负例通过） | Developer 测试集 | 是（沙箱独立执行） |
| 格式规范与仓库严格门禁通过 | `clang-format --dry-run -Werror` 及 `check_repository.py --strict` 16 项全通过 | 格式与门禁工具 | 是 |

---

## 3. 详细复核与闭环分析（基于严格复核与客观评定）

### 3.1 AUD-005 复核：Generic Netlink 偏移计算与赋值风格 —— CLOSED
- **修复措施走查**：
  1. **彻底消除局部暂存变量**：Genl 推导逻辑全面移除 `int id, config, mcgrps, n_mcgrps, n_mcgrps_size, mcgrp_offset, net_sock` 7 个局部变量，各锚点函数（`genlmsg_put`、`genlmsg_multicast_allns`、`genl_unregister_family`、`genl_pernet_exit`）在指令特征匹配后直接写入 `struct_offset.<field>`；
  2. **统一结构体日志**：`#ifdef CONFIG_DEBUG` 块中统一使用 `logkm("...=0x%x\n", struct_offset.<field>);`，与前置 Binder 及 task_struct 推导段保持完全一致的日志范式；
  3. **统一失败错误码**：中间校验失败及末尾循环校验失败统一返回 `-11`，消除此前 `-EINVAL` 的不一致；
  4. **删除末尾批量赋值**：函数末尾的范围、对齐与重叠校验循环直接对 `struct_offset` 成员进行校验，全部通过即 `return 0;`；
  5. **单测断言合理调整**：[`re_kernel/tools/test_genl_offsets.py`](re_kernel/tools/test_genl_offsets.py) 删除了脱离内核运行事实的全字段回滚断言（`assert(struct_offset.genl_family_id == out->id)`），改为核验推导结果或前置字段保护，290 项负例拒绝逻辑保持完好。
- **Auditor 复核结论**：风格割裂问题已彻底解决，既有规范完全对齐。
- **状态变更**：`open` → **`CLOSED`**（Auditor 独立复核关闭）。

### 3.2 AUD-006 复核：异步 Binder 消息淘汰方向对齐 —— CLOSED
- **修复措施走查**：
  1. [`re_kernel/re_kernel.c:580-598`](re_kernel/re_kernel.c#L580-L598) 中的 `binder_find_outdated_transaction_ilocked` 重构为：
     ```c
     struct binder_transaction* first = NULL;
     list_for_each_entry(w, target_list, entry) {
       if (w->type != BINDER_WORK_TRANSACTION) continue;
       struct binder_transaction* t_queued = container_of(w, struct binder_transaction, work);
       if (binder_can_update_transaction(t_queued, t)) {
         if (first) return first;
         first = t_queued;
       }
     }
     return NULL;
     ```
  2. 队列按 FIFO 顺序遍历，命中第 1 条时记录为 `first`，命中第 2 条时立即返回 `first`（即最早入队、最旧的一条）；
  3. 从而与 `re_kernel_x` 达到完全一致的业务语义：**优先淘汰最早入队的过时状态，为最新消息保留一条缓冲余量**；零或一条匹配旧消息时均安全保留。
  4. 新增独立单元测试 [`re_kernel/tools/test_cleanup.c`](re_kernel/tools/test_cleanup.c)，覆盖 0/1/2/3/4 条匹配消息、冻结/非冻结状态、PID 字段存在与否及无关消息穿插等 10 组场景，全部断言通过。
- **Auditor 复核结论**：两版本模块的异步消息淘汰策略已完全统一，算法行为一致。
- **状态变更**：`open` → **`CLOSED`**（Auditor 独立复核关闭）。

### 3.3 技术细节澄清与核实
在 Developer 响应中提出的两处报告细节说明，Auditor 已进行核实澄清：
1. **连续布局快轨依据**：`re_offsets.c:508` 的判断条件为 `struct_offset.genl_family_n_mcgrps_size == 4 && struct_offset.genl_family_mcgrp_offset == struct_offset.genl_family_n_mcgrps + 4`，该分支是基于字段宽度及相邻特征计算的动态判断，并非根据静态内核版本号硬编码，此处表述已澄清。
2. **Netlink 接收方套接字校验**：动态版校验 `skb->sk == rekernel_genl_sock()`（精确匹配本模块套接字），静态版校验 `sock_net(skb->sk) == init_net`（初始网络命名空间），二者均结合内核凭据 `NETLINK_CB(skb).creds.uid.val == 1000` 实施了强鉴权保护。

---

## 4. 问题单状态汇总

| 问题编号 | 严重度 | 归属 | 发现方 | 概要 | 当前状态 |
| --- | --- | --- | --- | --- | --- |
| **AUD-001** | 高 | Developer | Auditor | Netlink 控制入口缺少 UID 1000 凭据鉴权 | **CLOSED** |
| **AUD-002** | 中 | 维护者 | Auditor | 内嵌元数据与模块目录更名 `re_kernel_x` 一致性 | **CLOSED** |
| **AUD-003** | 中 | Developer | Auditor | 静态基线针对目标内核镜像派生偏移与适配约束 | **OPEN**（模板待机型落地） |
| **AUD-004** | 低 | Developer | Auditor | 代码风格、死注释与头文件引用清理 | **CLOSED** |
| **AUD-005** | 低 | Developer | Auditor | `re_kernel` Genl 偏移计算延迟批量赋值风格偏离既有惯式 | **CLOSED（复核关闭）** |
| **AUD-006** | 低 | Developer | Auditor | `re_kernel` 异步消息淘汰顺序与 `re_kernel_x` 不一致（次旧 vs 最旧） | **CLOSED（复核关闭）** |
| **DEV-010** | 高 | Developer | Developer | `mcgrps` 局部模式扫描与相邻指令特征匹配 | **fixed(待真机复核)** |

---

## 5. 同源风险声明

- **独立编译**：Auditor 独立在沙箱 `local/auditor-scratch/verify_commits_20261007/re_kernel_aud_fix/` 构建，未调用维护方 `tools/build_candidate.py`（提及该脚本仅用于定位，未作依据）。
- **独立二进制解析**：产物结构、节区与符号解析由 `Auditor/tools/artifact_audit.py` 直接自解析 ELF 头部，未调用 `kernel_img/offset_harness`（提及该脚本仅用于定位，未作依据）。
- **语料同源限制**：离线推导测试使用的 5 份内核语料来自实现方提供的镜像切片，真实机型的泛化能力仍需由真机测试证实。

---

## 6. 未验证清单

1. **真实 Android 环境下 Generic Netlink 双向流通信**：用户态客户端订阅 `rekernel` 家族广播与控制交互（受限于 8.0.0 测试客户端名称未对齐，暂未跑实时组播流）。
2. **真机异步消息并发清理**：在目标设备高频 Binder IPC 极端并发场景下的长期稳定性。
3. [x] **低版本内核（4.4）实机加载与动态推导**：已由 Tester 在物理设备（Nokia 7 plus / 4.4.192）完成端到端闭环（见第 7 节）。

---

## 7. 后续实机测试追加复核记录（Linux 4.4 硬件动态推导与 DEV-010 闭环）

- **实机报告来源**：[`Tester/reports/runs/2026-10-08-re_kernel-8.0.0_4.4_live#1.md`](../../Tester/reports/runs/2026-10-08-re_kernel-8.0.0_4.4_live%231.md)
- **目标设备环境**：Nokia 7 plus（`B2N_sprout`，设备指纹哈希 `b754dad7`），Linux 4.4.192-perf+，Android 10，SELinux Enforcing，boot_id SHA-256 `491082c13a1c95fed2e83c1e85690f8a3f5379f1c178d3ae71aa8058db92b2cc`。
- **基线身份与产物核对**：
  - 来源 commit：`d07cf19e872c4d1254a51398f6ce7923c78827e1`（以及包含 AUD-005/006 修复的提交 `e34ea88`）
  - Debug 在册 instance_id：`re_kernel-8.0.0_debug+g193f81b841f8.r1bd2bca0.kpb51197a.ndk26.3.11579264#2`，sha256：`fcb3ba0c30b00118965f4ec21ea22689c47340dda18b60a8f1b83856a73b4657`
  - Release 在册 instance_id：`re_kernel-8.0.0+g193f81b841f8.rfe7363a9.kpb51197a.ndk26.3.11579264#2`，sha256：`77ad53f2004c4b488dece65300501af253ab43266fb9a041bc2bc6ef8b965942`
  - 目标测试镜像：`kernel_img/B2N-416G_boot.img`
- **判据与动态推导证据核验**：
  1. **模块加载与 ctl0**：物理加载成功（退出码 0），`ctl0 ping` 成功返回 `_(._.)_`；
  2. **Binder 与 Genl 运行时推导实证（DEV-010 闭环）**：
     真机内核 `dmesg` 明确输出：
     ```text
     re_kernel: genl_family_n_mcgrps=0x64
     re_kernel: genl_family_n_mcgrps_size=4
     re_kernel: genl_family_mcgrp_offset=0x68
     re_kernel: genl_family_mcgrps=0x58
     re_kernel: net_genl_sock=0x108
     re_kernel: Created Re:Kernel Generic Netlink family! ID: 29
     ```
     证实基于相邻指令模式匹配的 `mcgrps` 局部推导在 Linux 4.4 物理内核上成功命中有效字段，并成功创建 Generic Netlink family（ID 29）；
  3. **干净卸载与 pstore 干净度**：模块成功热卸载，`/sys/fs/pstore/` 检查无崩溃转储，内核运行平稳。
- **问题单状态更新**：
  - **DEV-010**（`mcgrps` 局部模式扫描与相邻指令特征匹配）：`fixed(待真机复核)` → **`CLOSED（实机复核关闭）`**。
- **同源风险声明**：Auditor 仅复核 Tester 报告中的量化判据与日志事实，未调用维护方工具或开发方 harness（提及 `kernel_img/offset_harness` 与 `tools/identity.py` 仅用于定位，未作依据）。

> 维护者公开整理（2026-10-08）：启动标识改为 SHA-256，保留相等关系；核验结论与候选身份保持原文。原文 SHA-256：`3065392c6722a78d32b153817847652685e9f1a0f683cf8d314862d690e53502`；原文保存在本地证据归档。
