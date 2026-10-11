# 独立审计复核报告：AUD-007 预处理与条件宏风格修复复核与问题单关闭

角色：Auditor（独立审计）。  
复核对象：
- Developer 修复响应：[`Developer/reports/responses/2026-10-10-AUD-007.md`](../../Developer/reports/responses/2026-10-10-AUD-007.md)
- 模块修复提交：
  - `re_kernel` 提交 `55c3b1c1f4515cb090c25a92e3ca030eaf43f79f`
  - `re_kernel_x` 提交 `820165f403960a5b0e31f5d66df08014b55e3844`
  - 共同源码冻结提交：`820165f403960a5b0e31f5d66df08014b55e3844`
  - 统一交接提交：`3dfd6ce12f25bf23f2255aae7fe7e2900266540e`
- 交接清单：
  - [`re_kernel-20261010-AUD-007.json`](../../Developer/reports/handoffs/re_kernel-20261010-AUD-007.json)
  - [`re_kernel_x-20261010-AUD-007.json`](../../Developer/reports/handoffs/re_kernel_x-20261010-AUD-007.json)

---

## 1. 身份与基线依据

| 项 | 值 |
| :--- | :--- |
| **问题单编号** | `AUD-007` |
| **共同源码冻结 commit** | `820165f403960a5b0e31f5d66df08014b55e3844` |
| **候选交接 commit** | `3dfd6ce12f25bf23f2255aae7fe7e2900266540e` |
| **对照审计基线 commit** | `2257f2291e2be77c8809c266393da9d9d093d7b4` |
| 编译工具链 | Android NDK 26.3.11579264（Clang `aarch64-linux-android31-clang`） |
| 平台 SDK | KernelPatch commit `b51197aaba8f2272dd8a3e30c85698a29aa928c9`（0.13.9） |

### 8 份新候选产物身份与独立沙箱重编译核验

Auditor 在隔离沙箱 `local/auditor-scratch/aud007_verify/` 中独立执行 NDK 编译，所有 8 份产物与交接清单的 SHA-256 逐位吻合：

| 模块 / 变体 | Build ID 与 instance_id | 交接清单 sha256 | 沙箱重编译 sha256 | 校验结果 |
| :--- | :--- | :--- | :--- | :--- |
| `re_kernel` / base | `re_kernel-11.7+g74820b6486a2.r08a88aa8.kpb51197a.ndk26.3.11579264#1` | `fc8992f63e890bc2145fd2500c537d6cc49026389853e5852241f2acacf108a3` | `fc8992f63e890bc2145fd2500c537d6cc49026389853e5852241f2acacf108a3` | **PASS (Match)** |
| `re_kernel` / baselines | `re_kernel-11.7_baselines+g74820b6486a2.r08ce5a98.kpb51197a.ndk26.3.11579264#1` | `3da1a47763da15853a9016c81e03215383c13d88d75bac04cd8519f85479eb13` | `3da1a47763da15853a9016c81e03215383c13d88d75bac04cd8519f85479eb13` | **PASS (Match)** |
| `re_kernel` / baselines_debug | `re_kernel-11.7_baselines_debug+g74820b6486a2.r127cc051.kpb51197a.ndk26.3.11579264#1` | `0bc6e3476f2892964b79f334e41f84fee67f141d9b3df1286a1e88421bc3acda` | `0bc6e3476f2892964b79f334e41f84fee67f141d9b3df1286a1e88421bc3acda` | **PASS (Match)** |
| `re_kernel` / debug | `re_kernel-11.7_debug+g74820b6486a2.r58923f37.kpb51197a.ndk26.3.11579264#1` | `c04a293446c8f9920fa1746d6fa215b956b22b87523b9734479cc76740e159da` | `c04a293446c8f9920fa1746d6fa215b956b22b87523b9734479cc76740e159da` | **PASS (Match)** |
| `re_kernel_x` / base | `re_kernel_x-1.6-20261008+gd80a957dbb14.r3923dc8d.kpb51197a.ndk26.3.11579264#1` | `151ef48c73afe7703c13778cbaffccf0c5b900bd1e6b98aea2d483933b33030f` | `151ef48c73afe7703c13778cbaffccf0c5b900bd1e6b98aea2d483933b33030f` | **PASS (Match)** |
| `re_kernel_x` / baselines | `re_kernel_x-1.6-20261008_baselines+gd80a957dbb14.r7abf0995.kpb51197a.ndk26.3.11579264#1` | `2933c90f15c4ec66872fce0e6f2222e10fd314dfe31a69d7ca998df60201144a` | `2933c90f15c4ec66872fce0e6f2222e10fd314dfe31a69d7ca998df60201144a` | **PASS (Match)** |
| `re_kernel_x` / baselines_debug | `re_kernel_x-1.6-20261008_baselines_debug+gd80a957dbb14.r00cb6cab.kpb51197a.ndk26.3.11579264#1` | `ed6f97dcf8cdaf8498d22ecc5de410a4887e3492e38aa585f2ffded091ad8b0a` | `ed6f97dcf8cdaf8498d22ecc5de410a4887e3492e38aa585f2ffded091ad8b0a` | **PASS (Match)** |
| `re_kernel_x` / debug | `re_kernel_x-1.6-20261008_debug+gd80a957dbb14.r404552af.kpb51197a.ndk26.3.11579264#1` | `e6ce734b2ad7c60290b495c86244a988e8180462711a63fb57e88cbecdd73304` | `e6ce734b2ad7c60290b495c86244a988e8180462711a63fb57e88cbecdd73304` | **PASS (Match)** |

---

## 2. 证据来源表（结论 → 命令 → 归属角色）

| 结论 | 独立复现命令 / 证据 | 来源归属 | 是否独立复现 |
| :--- | :--- | :--- | :--- |
| **8 份候选独立重编译哈希完全一致** | 沙箱 `local/auditor-scratch/aud007_verify/` 独立执行构建命令，SHA-256 逐位一致 | Auditor 独立重编译 | 是 |
| **源码差异与 AST 结构走查** | `git diff 2257f22..820165f` 行级审查预编译指令与符号声明顺序 | Auditor 独立审查 | 是 |
| **宿主 Genl / 锚点 / 清理单测** | 运行 `python3 re_kernel/tools/test_genl.py`，9 组用例通过（ASan/UBSan） | Developer 测试集 | 是（沙箱独立执行） |
| **BTF 布局与错误契约单测** | 运行 `python3 re_kernel/tools/test_btf.py`，全量断言通过 | Developer 测试集 | 是（沙箱独立执行） |
| **双模式构建与补丁工具单测** | 运行 `python3 re_kernel/tools/test_modes.py`，8 产物全通过 | Developer 测试集 | 是（沙箱独立执行） |
| **静态基线并发与规则单测** | 运行 `python3 re_kernel_x/tools/test_static.py`，全量断言通过 | Developer 测试集 | 是（沙箱独立执行） |

---

## 3. 详细审计与整改逐项复核

### 3.1 审查点 1：头文件包含位置归位（复核通过）
- **变更事实**：`re_kernel_x/re_kernel.c:26` 引入了 `#include "re_utils.h"`；彻底删除了 `re_kernel_x/re_offsets.c:269` 中的中段包含。
- **解耦机制**：在 `re_kernel_x/re_utils.h:13-19` 前置声明了 7 个访问器原型（`sk_buff_tail`、`sk_buff_transport_header`、`sk_buff_head`、`sk_buff_data`、`genl_family_n_mcgrps`、`genl_family_mcgrp_offset`、`net_genl_sock`），解决了 C 预处理器的符号声明先后依赖。
- **结论**：符合标准 C 工程范式，审查点 1 复核通过。

### 3.2 审查点 2：内核符号声明集中化（复核通过）
- **变更事实**：在 `re_kernel_x/re_kernel.c` 中，将散落在第 89～108 行的符号指针（`binder_free_txn_fixups`、`do_send_sig_info`、`memdup_user`、`sock_i_uid`、`tcp_v4_do_rcv`、`_raw_spin_lock`、`tracepoint_probe_register` 等）全部前提至 `#include "re_offsets.c"` 之前。
- **`binder_buffer_read` 排布**：紧随 `#include "re_offsets.c"` 之后放置，仅在其依赖的 `struct_offset` 就绪后立即定义。
- **结论**：两模块的符号声明区域完全对齐，不再在符号声明中途横切嵌入源文件，审查点 2 复核通过。

### 3.3 审查点 3：消除重复结构体定义（复核通过）
- **变更事实**：`re_kernel/re_offsets.c:1-47` 改为单一声明 45 项 `struct struct_offset`，彻底废弃了原先 `#else` 块中重复出现的 38 项冗余定义。
- **动态实例组织**：静态模式保留 `.data.re_offsets` volatile 数据段（90 字节）；动态模式实例直接清零声明 `struct struct_offset struct_offset = {};`，各字段访问保持原有命名契约。
- **结论**：彻底消除字段维护漂移隐患，审查点 3 复核通过。

### 3.4 审查点 4：入口 fail-fast 校验对齐（复核通过）
- **变更事实**：`re_kernel.c` 的 `inline_hook_init` 在函数开头置入静态 ABI 校验（`if (struct_offset.binder_release_abi < 3 || ... > 6) return -EINVAL;`），非法配置即刻阻断；下方由独立 `#ifndef CONFIG_KPM_BASELINES` 驱动 `calculate_offsets()`。
- **结论**：两模块初始化控制流逻辑完全一致，审查点 4 复核通过。

### 3.5 审查点 5：comm 日志访问器统一（复核通过）
- **定位复核**：经 Auditor 核对源码事实，原审计意见中提及的 comm 日志嵌套宏实际位于 `re_kernel.c` 的 `rekernel_report`（`src_comm/dst_comm` 日志区）。
- **整改落实**：`re_kernel` 统一封装了 `task_comm(task)` 访问器（静态模式读偏移表，动态模式调用 KP `get_task_comm`），彻底消除了事件上报路径中的脆弱嵌套 `#ifdef` 宏。
- **结论**：审查点 5 复核通过。

### 3.6 遵守测试 Oracle 与防反向过拟合复核（合规）
Auditor 专门走查了 `55c3b1c` 对宿主测试驱动（`test_genl.py`、`test_btf.py`、`test_genl_offsets.py`）的改动：
- 改动仅调整了提取器在面对唯一定义时的行级正则与符号切分规则；
- 明确固化了 `REK_BTF_FIELDS`（38 项动态查询字段清单），并断言其必为结构体子集；
- **全量业务断言无任何弱化、缩小或删除**，符合 `respect-the-oracle` 准则。

---

## 4. 问题单状态变更

依据本仓库治理规则（**问题单必须由发现方复核关闭，修复方无权自行关闭**）：

| 问题编号 | 严重度 | 归属 | 发现方 | 概要 | 当前状态 |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **AUD-007** | 低 | Developer | Auditor | `re_kernel` 与 `re_kernel_x` 头文件包含顺序（`#include`）与条件编译（`#ifdef`）风格漂移 | **CLOSED（独立复核关闭）** |

---

## 5. 同源风险声明

- **独立重编译**：Auditor 独立调用 NDK Clang 完成 8 项产物的沙箱重编译与 SHA-256 校验，未调用维护方构建脚本（提及 `tools/build_candidate.py` 仅用于定位，未作依据）；
- **独立语法走查**：Auditor 自行比对语法树与指令顺序，未依赖实现方 harness 作为依据（提及 `kernel_img/offset_harness` 仅用于定位，未作依据）。

---

## 6. 未验证清单

1. **新产物真实物理设备运行**：本轮 8 份新候选产物尚未在实体设备上加载（待 Tester 覆盖）；
2. **`run_cmd_demo` 真实设备执行验证**：命令执行与 root 提权仍待真机确认。
