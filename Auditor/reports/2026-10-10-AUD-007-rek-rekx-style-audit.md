# 独立审计报告：re_kernel 与 re_kernel_x 预处理包含与条件宏风格审查（AUD-007）

角色：Auditor（独立审计）。  
审计类型：专项代码风格走查、结构对称性审查与问题单发起。  
审计对象：
- `re_kernel` 11.7（来源 commit `2257f2291e2be77c8809c266393da9d9d093d7b4`，候选登记提交 `e855a3d515276acb8aefe58dc48a49e5d53ee312`）
- `re_kernel_x` 1.6-20261008（来源 commit `2257f2291e2be77c8809c266393da9d9d093d7b4`，候选登记提交 `e855a3d515276acb8aefe58dc48a49e5d53ee312`）

---

## 1. 身份与基线依据

| 项 | 模块 `re_kernel` | 模块 `re_kernel_x` |
| --- | --- | --- |
| 来源 commit | `2257f2291e2be77c8809c266393da9d9d093d7b4` | `2257f2291e2be77c8809c266393da9d9d093d7b4` |
| 候选登记 commit | `e855a3d515276acb8aefe58dc48a49e5d53ee312` | `e855a3d515276acb8aefe58dc48a49e5d53ee312` |
| 声明版本 | `11.7` | `1.6-20261008` |
| 编译工具链 | NDK 26.3.11579264（Clang aarch64-linux-android31-clang） | NDK 26.3.11579264（Clang aarch64-linux-android31-clang） |
| KernelPatch commit | `b51197aaba8f2272dd8a3e30c85698a29aa928c9` (0.13.9) | `b51197aaba8f2272dd8a3e30c85698a29aa928c9` (0.13.9) |

### 在册候选构建与产物身份

依据元数据登记（`metadata/modules/re_kernel.json` 与 `metadata/modules/re_kernel_x.json`），当前在册候选包含 8 份实例：

| 模块 | 模式与变体 | Build ID 与 instance_id | 产物 sha256 | 大小 |
| :--- | :--- | :--- | :--- | :--- |
| `re_kernel` | dynamic release | `re_kernel-11.7+g63a3af7d7034.r3efcc29a.kpb51197a.ndk26.3.11579264#1` | `fb00ca982319b7e7487085781a09aea4e41da9a3af05b10145149be8565d6fe9` | 80,600 B |
| `re_kernel` | dynamic debug | `re_kernel-11.7_debug+g63a3af7d7034.rfd66d6af.kpb51197a.ndk26.3.11579264#1` | `3dba88b800871dac66e8a78ae84775213b0d967aa444d652fa6846065f6895c9` | 85,440 B |
| `re_kernel` | static baselines | `re_kernel-11.7_baselines+g63a3af7d7034.ra3221655.kpb51197a.ndk26.3.11579264#1` | `a54945f94f1fe7b8c11882204f15099681e2d8136f590e4394ef59a69a4b80ba` | 34,760 B |
| `re_kernel` | static debug | `re_kernel-11.7_baselines_debug+g63a3af7d7034.rdfb99af0.kpb51197a.ndk26.3.11579264#1` | `3f3e70d7b73cd68317e7d1457446cf6603a47cd147c2999361e1ab437dfbca1b` | 35,552 B |
| `re_kernel_x` | dynamic release | `re_kernel_x-1.6-20261008+gc98feee61782.r05be2926.kpb51197a.ndk26.3.11579264#1` | `1fc76b126c5d81f14c4edeeef3cb662cd60494211cfbb405a81b926af8d97a45` | 93,744 B |
| `re_kernel_x` | dynamic debug | `re_kernel_x-1.6-20261008_debug+gc98feee61782.rafb02aeb.kpb51197a.ndk26.3.11579264#1` | `e6ce734b2ad7c60290b495c86244a988e8180462711a63fb57e88cbecdd73304` | 98,968 B |
| `re_kernel_x` | static baselines | `re_kernel_x-1.6-20261008_baselines+gc98feee61782.rfed0f482.kpb51197a.ndk26.3.11579264#1` | `87f62f34151d4bb38dc10fb2b287ff1f3e648f3e5eb043bc3881acf1aa177668` | 42,360 B |
| `re_kernel_x` | static debug | `re_kernel_x-1.6-20261008_baselines_debug+gc98feee61782.r70edd8bb.kpb51197a.ndk26.3.11579264#1` | `94c61f455a2da621091f60804ae5ba731fe25ea98eb8c72dae9268e96df7b7dc` | 41,728 B |

---

## 2. 证据来源表（结论 → 命令 → 归属角色）

| 结论 | 独立复现命令 / 证据 | 来源归属 | 是否独立复现 |
| :--- | :--- | :--- | :--- |
| **预处理与条件宏差异定位** | `diff -u` 与行级语法结构比对 `re_kernel/` 与 `re_kernel_x/` 源码 | Auditor 独立比对 | 是 |
| **头文件包含位置漂移确认** | 语法走查 `re_kernel/re_kernel.c`、`re_kernel_x/re_kernel.c` 及对应 `re_offsets.c` | Auditor 独立走查 | 是 |
| **门禁检查基线状态** | `python3 tools/check_repository.py --strict`（提及该脚本仅用于定位，未作依据） | 仓库门禁 | 是 |

---

## 3. 问题单：AUD-007

### 3.1 问题单基本信息
- **问题编号**：`AUD-007`
- **严重度**：低（Low - 代码风格、预处理组织与长期可维护性）
- **归属角色**：Developer
- **发现方**：Auditor（专项代码风格走查）
- **状态**：**OPEN**
- **概要**：`re_kernel` 与 `re_kernel_x` 头文件包含顺序（`#include`）与条件编译（`#ifdef`）位置存在不对称漂移

### 3.2 事实证据与缺陷分析

Auditor 对提交 `2257f2291e2be77c8809c266393da9d9d093d7b4` 中两模块的预处理指令与语法结构进行了专项审计，发现 5 处显著风格不一致：

1. **`re_utils.h` 包含位置不规范（严重违背 C 风格约定）**：
   - 在 `re_kernel/re_kernel.c:26` 中，`#include "re_utils.h"` 按正规惯例置于文件顶部包含区。
   - 在 `re_kernel_x` 中，`re_kernel.c` 顶部完全遗漏了 `re_utils.h`，反而将其埋在 `re_kernel_x/re_offsets.c:269`（实现文件正文中段）。
   - **成因**：`re_kernel_x/re_utils.h` 中的 `genlmsg_multicast_netns` 调用了 `genl_family_n_mcgrps` 等访问函数，开发者为迁就内联函数调用顺序，被动在 `re_offsets.c` 局部展开后才包含头文件。在 `.c` 实现文件中段包含 `.h` 头文件属于明显的代码异味。

2. **`re_offsets.c` 嵌入位置截断内核符号声明**：
   - 在 `re_kernel/re_kernel.c:115` 中，`#include "re_offsets.c"` 集中放在所有模块级内核符号指针（Binder、信号、网络、锁、tracepoint）和 forward declaration 之后，布局清晰。
   - 在 `re_kernel_x/re_kernel.c:69` 中，`#include "re_offsets.c"` 插入在 Binder 符号之后，其后（第 89～108 行）又重新声明 `do_send_sig_info`、`tcp_v4_do_rcv`、`_raw_spin_lock` 等，导致内核符号声明被强行截断为两段。

3. **`struct struct_offset` 条件宏重复声明**：
   - 在 `re_kernel/re_offsets.c` 中，结构体被重复定义了两次：第 1 行由 `#ifdef CONFIG_KPM_BASELINES` 包裹声明 45 项静态结构体，第 156 行由 `#ifndef CONFIG_KPM_BASELINES` 再次声明 38 项动态结构体。
   - 相比之下，`re_kernel_x/re_offsets.c:1-48` 无条件统一声明单份 45 项结构体，仅通过 `#ifndef CONFIG_KPM_BASELINES ... #else ... #endif` 控制实例初始值。`re_kernel` 的重复结构体定义显著增加了字段同步与维护风险。

4. **`inline_hook_init` 中静态 ABI 校验与推导入口的 `#ifdef` 位置不一**：
   - `re_kernel_x` 在 `inline_hook_init` 入口第一行（第 861 行）即对静态 ABI 进行 fail-fast 拦截（避免非法配置时冗余查找 20 多个内核符号），随后在下方独立调用 `calculate_offsets()`。
   - `re_kernel` 将静态 ABI 校验推迟到函数中后段（第 795 行），并与 `calculate_offsets()` 揉合在同一 `#ifdef ... #else ... #endif` 块内，风格不统一。

5. **`CONFIG_DEBUG` 下 `free_outdated` 日志中的 comm 提取存在嵌套宏**：
   - `re_kernel/re_kernel.c:486-493` 存在脆弱的嵌套宏：
     ```c
     #ifdef CONFIG_DEBUG
     #ifdef CONFIG_KPM_BASELINES
       const char* comm = (const char*)current + struct_offset.task_struct_comm;
       logkm("free_outdated pid=%d,uid=%d,data_size=%zu,comm=%s\n", pid, uid, buffer->data_size, comm);
     #else
       logkm("free_outdated pid=%d,uid=%d,data_size=%zu\n", pid, uid, buffer->data_size);
     #endif
     #endif
     ```
   - `re_kernel_x/re_kernel.c:545-548` 封装了安全访问函数 `task_struct_comm_ptr(current)`（无效偏移返回空串），直接消除嵌套宏，风格显著更优。

### 3.3 影响评估
- **严重度判定**：低（Low）。
- **影响范围**：当前不破坏模块编译与已有二进制测试，但降低了双模块的可维护性与架构对称性，且在实现文件中段包含头文件可能对代码阅读与静态分析工具造成混淆。

### 3.4 给 Developer 的整改建议

1. **头文件严格归位**：
   将 `re_kernel_x/re_offsets.c` 第 269 行的 `#include "re_utils.h"` 彻底移出，统一在 `re_kernel.c` 顶部按规范引入。
   若 `re_utils.h` 中的组播辅助内联函数依赖组播访问器，可在 `re_utils.h` 前置声明函数签名，或将纯工具宏与依赖偏移的业务内联函数做合理分层。
2. **符号声明集中化**：
   在 `re_kernel_x/re_kernel.c` 中，将散落在第 89～108 行的符号指针前移，与前序符号一并声明完毕后，再统一包含 `#include "re_offsets.c"`。
3. **消除重复结构体定义**：
   `re_kernel/re_offsets.c` 参考 `re_kernel_x` 做法，无条件统一声明单份 `struct struct_offset`，消除 45 项与 38 项的重复定义。
4. **统一 fail-fast 校验**：
   `re_kernel` 的 `inline_hook_init` 对齐 `re_kernel_x`，在入口处即时拦截非法静态 ABI。
5. **消除嵌套条件宏**：
   `re_kernel` 引入 `task_struct_comm_ptr` 安全访问器，消除 `free_outdated` 日志中的嵌套 `#ifdef`。

### 3.5 关闭条件
1. Developer 在新冻结提交中修复上述 5 项风格漂移；
2. 不弱化或修改既有测试 Oracle 断言（`test_genl.py`、`test_modes.py`、`test_static.py`、`test_btf.py` 等）；
3. 提交修复响应报告，附带变更 commit 与自检证据；
4. 由 Auditor 独立复核代码格式与预处理指令后关闭本问题单。**依据仓储规则，修复者不得自行关闭本问题单。**

---

## 4. 同源风险声明

- **独立审查**：Auditor 独立走查源码文本与语法树，未调用实现方 harness 脚本或维护方构建脚本作为定论依据（提及 `tools/check_repository.py` 仅用于定位，未作依据）。
- **同源风险范围**：本轮审查基于仓库当前提交源码，不涉及内核语料输入同源风险。

---

## 5. 未验证清单

1. **待 Developer 修复响应**：待 Developer 针对 AUD-007 提交修复提交并完成自检。
2. **修复后编译与 Oracle 回归**：待 Developer 交付新提交后，由 Auditor 独立复编译并验证 Oracle 断言未发生漂移。
