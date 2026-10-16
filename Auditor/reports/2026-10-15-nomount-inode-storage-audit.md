# NoMount inode storage 修复候选独立审计报告

- **模块**：`nomount`
- **版本**：`2.1.1-20261014`
- **构建档位**：`candidate`
- **源码冻结提交**：[`846f3d1bce5f7aa9c9f8d180e3c1b2f02b6d3e34`](https://github.com/kernelpatch/APatch_kpm/commit/846f3d1bce5f7aa9c9f8d180e3c1b2f02b6d3e34)
- **KernelPatch 提交**：`b51197aaba8f2272dd8a3e30c85698a29aa928c9`
- **工具链**：`ndk26.3.11579264`（Android NDK r26d / Clang 17.0.2）
- **审计角色**：Auditor（独立执行，不依赖开发者/维护者中间产物）
- **依据请求**：[`docs/records/2026-10-15-nomount-inode-storage-request.md`](../../../docs/records/2026-10-15-nomount-inode-storage-request.md)

---

## 1. 审计对象与独立复现

### 1.1 候选原件无缓存重编译

Auditor 在纯净隔离沙箱目录 `local/auditor-scratch/nomount-inode-storage-20261015/worktree`（检出 `846f3d1bce5f7aa9c9f8d180e3c1b2f02b6d3e34`）中使用独立 NDK r26d 执行重编译：

| 变体模式 | instance_id | 预期 SHA-256 | 独立重编译 SHA-256 | 字节数 | 比对结论 |
| :--- | :--- | :--- | :--- | :---: | :---: |
| **base（动态）** | `nomount-2.1.1-20261014+g526802555793.r3ac93780.kpb51197a.ndk26.3.11579264#1` | `7e21475004c69deafa8d32d3607ca5359b0df0907a212ba0bbc37772ea5200ae` | `7e21475004c69deafa8d32d3607ca5359b0df0907a212ba0bbc37772ea5200ae` | 213,528 | **100% 逐字节吻合** |
| **baselines（静态）** | `nomount-2.1.1-20261014_baselines+g526802555793.rec234bc2.kpb51197a.ndk26.3.11579264#1` | `77a5baa38d3072c4fb63da4cb70b286d83d93cf06fa06179b8c4125f9c2bc15a` | `77a5baa38d3072c4fb63da4cb70b286d83d93cf06fa06179b8c4125f9c2bc15a` | 111,864 | **100% 逐字节吻合** |

### 1.2 目标派生件（4 件）独立复现与可追溯性核验

Auditor 使用独立重编译的基准件，依据 Developer 登记的参数独立运行 `patch_offsets.py` 变换：

| 目标名称 | 变换链路 | 父输入件 SHA-256 | 派生产物 SHA-256 | 独立复现 SHA-256 | 吻合度 |
| :--- | :--- | :--- | :--- | :--- | :---: |
| **B2N-416G (4.4)** | 动态 + legacy-kp | `7e214750…`（动态 candidate） | `971b9e28135bcdfd45c8e223f20d5092ff53e719faaa00f2b08e36f53f5a497b` | `971b9e28135bcdfd45c8e223f20d5092ff53e719faaa00f2b08e36f53f5a497b` | **100% MATCH** |
| **boot_los23.2 (4.19)** | 静态 patch | `77a5baa3…`（静态 candidate） | `56fcfd9a7f3490df58a0e3b60d292cad1083ac852375e9cb3ad5dbdd95f42186` | `56fcfd9a7f3490df58a0e3b60d292cad1083ac852375e9cb3ad5dbdd95f42186` | **100% MATCH** |
| **B2N-416G (4.4)** | 静态 patch（中间父件） | `77a5baa3…`（静态 candidate） | `283ebfb447afd36709ba9464ac91aa3e07382099704c867d57fb649258fb2a5d` | `283ebfb447afd36709ba9464ac91aa3e07382099704c867d57fb649258fb2a5d` | **100% MATCH** |
| **B2N-416G (4.4)** | 静态 legacy-kp | `283ebfb4…`（静态 patch 中间件） | `9e39293341f225e24bce9384faf531b9a23532d5fc773f38c327c258661f4248` | `9e39293341f225e24bce9384faf531b9a23532d5fc773f38c327c258661f4248` | **100% MATCH** |

核验确认：4 件派生件的输入父件、工具指纹（`patch_offsets.py` SHA-256 `97a51b293af4…`）、命令行指令与 compat 收据（`13896399…` 与 `d3281f11…`）均形成完整密码学闭环，源码与构建配置保持最新 KP 规范，无旧版兼容污染。

---

## 2. Inode Storage 局部操作表识别方法独立审计

### 2.1 4.4 目标拒载成因与机制确认

1. **失败复现确证**：
   - 目标 Nokia B2N 4.4 内核镜像中，`no_open_fops` 为局部符号，编译器命名修饰为 `no_open_fops.36570`；
   - 旧代码依赖精确符号 `inode_init_always.no_open_fops` 或 `no_open_fops`，在 4.4 兼容派生件环境下精确查询均告缺失；原测试夹具因人为合成了 `no_open_fops` 别名导致宿主测试假绿；实机测试在 Inode Storage 阶段触发 `-ENOENT` 拒载属实。
2. **推导机制审查（`nm_probe_inode_storage` 与 `nm_initial_fops_matches`）**：
   - **指令窗口控制**：限制在 `inode_init_always` 入口 21 条 ARM64 指令之内，跟踪寄存器地址生成（ADRP/ADD/STR）；
   - **几何关系硬断言**：在 Linux 内核 `struct inode` 中，`i_fop` 与 `i_flctx` 连续（合计 16 字节，定义于 `struct nm_inode_file_locks`），其后紧随 `i_data`（`struct address_space`）；代码要求写入目标必须满足：
     $$\text{mapping} == \text{file\_ops} + \text{sizeof}(\text{struct nm\_inode\_file\_locks})$$
     在 B2N 4.4（`i_fop` = 328, `i_data` = 344）与 Sony 4.19（`i_fop` = 368, `i_data` = 384）上，两者差值均严格为 16 字节，杜绝偏移盲猜；
   - **表内容核对与内存边界安全**：
     - `table` 必须 8 字节对齐，且满足 $\text{start} \le \text{table} \le \text{end} - \text{file\_ops\_size}$；
     - 读取 `table + fop_open` 指针，通过 `nm_code_matches` 核对是否指向 `no_open`（或经过核心代码区内的直接分支 `b` 到达 `no_open`）；
     - 读取动作严格限定在已验证的内核 rodata/代码段内，保护页测试确认在末端截断或越界时安全返回 `false`，绝无 Page Fault 风险；
   - **Fail-Closed 终止门控**：若窗口内遇到未知 `call`、`branch`、`ret` 直接返回 `-EOPNOTSUPP`；窗口遍历完成未获匹配返回 `-ENOENT`。

---

## 3. 静态版差异深度裁定（本轮关键判定）

### 3.1 差异背景与现象

- **已验收发布集静态件**（`e9ab619e`）：SHA-256 `76e220cd0c7a6c2f5002d5f26148483baa06ccccad61f4838060159b7f2adac2`（111,968 字节，`.text` 42,996 字节）。
- **本轮候选静态件**（`846f3d1b`，与前两轮探索相同）：SHA-256 `77a5baa38d3072c4fb63da4cb70b286d83d93cf06fa06179b8c4125f9c2bc15a`（111,864 字节，`.text` 42,992 字节）。

### 3.2 源码层门控隔离核实

核对 `nomount/nm_offsets.c` 源码发现：
- 行 447 至行 1990（全部动态偏移推导与函数锚点分析逻辑，包括 `nm_btf.c`、`nm_probe_inode_storage`、`nm_find_inode_storage`、`calculate_function_inode_offsets`、`sdcardfs_ci_dops` 等）**被宏 `#ifndef CONFIG_KPM_BASELINES` 完整包裹**。
- 静态模式编译时，上述代码在预处理阶段被 100% 剥离，静态产物符号表中**不存在任何动态推导符号**。

### 3.3 反汇编与控制流逐指令比对

Auditor 使用 `llvm-objdump` 提取两版静态产物全部 106 个函数的汇编指令，进行语义反汇编比对：
1. **104 个函数指令集完全一致**：除因代码段收缩 4 字节导致的 PC 相对跳转标号微调外，指令序列与操作数 100% 等同；
2. **差异集中于仅有的 2 处微调**：
   - `nm_validate_control_layout`（60 条 → 56 条指令）：
     源码优化：引入 `int key_capacity = nm_owned_operation_size(NM_KEY_TYPE);` 局部缓存，消除对静态配置表的 4 次重复读取。逻辑判定上下界与对齐检查无任何变化；
   - `nm_prepare_control_engine`（232 条 → 235 条指令）：
     在调用 `nm_prepare_management_mutex()` 之前增加调用 `nm_prepare_control_layout()`。而静态编译下 `nm_prepare_control_layout()` 展开仅为直接执行纯函数 `nm_validate_control_layout()`。
3. **副作用与可达性审查**：
   - `nm_validate_control_layout()` 是纯粹的只读、无副作用校验函数（Pure Function），仅对已载入的静态常量表做范围比对；
   - 增加一次调用不仅无副作用，且在后续 `nm_prepare_management_mutex()` 中本就会再次执行该校验。

### 3.4 静态差异裁定结论

1. **行为完全等价（Behaviorally Equivalent）**：
   Auditor 裁定：`77a5baa3…` 相对已验收发布件 `76e220cd…` 在语义、控制流、执行路径、生命周期、安全模型与对外行为上 **100% 行为等价**。
2. **证据绑定裁定**：
   **Auditor 确认：该行为等价结论在技术与法理上支持将已验收的静态真机测试证据直接绑定至新静态字节 `77a5baa3…`**。
3. **发布审慎建议（致 Tester 与维护者）**：
   - 规则层：依据请求说明，若 Auditor 裁定等价，则 Tester 计划中的 ④（4.19 静态 patch）与 ⑤（4.4 静态 legacy-kp）两趟测试**在逻辑上可被省免**；
   - 实践层：鉴于当前处于正式发布前关键阶段，若真机环境充裕，Tester 执行 ④ 与 ⑤ 实测可提供物理层面的最终背书；若 Tester 决定精简测试轮次，**必须在测试报告中显式声明引用本审计报告之行为等价结论作为免测绑定依据**。

---

## 4. 安全评估与 AUD-001 风险边界

1. **静态扫描启发式结果**：
   - 运行 `static_scan.py nomount`，报告 3 处 `free_without_null`（均位于 userspace/未参与模块）、13 处分配点与 7 处 BTF 移位。核验确认内核模块热路径无原子上下文睡眠，无内存悬挂；
2. **产物独立审计**：
   - 运行 `artifact_audit.py --module nomount`，输出 0 项阻塞错误（PASS）；
3. **`AUD-001` 状态裁定**：
   - 本轮仅针对 Inode Storage 的 `i_fop` / `i_data` 局部表识别进行修复；
   - `key_type` 的精确结构尺寸在无 BTF 目标下仍无法推导（依然标记为 `-1`），继续沿用 512 字节自建清零容量；
   - **裁定：`AUD-001`（厂商扩展操作表越界风险）维持 OPEN 状态**；
   - **支持范围维持**：本轮 candidate 仍严格限定于满足 **Case 1（Sony 4.19 几何）** 与 **Case 2（Nokia 4.4 几何）** 的内核目标，不得外推至未知厂商内核。

---

## 5. DEV-042 复核状态

- **问题单**：`DEV-042`（局部操作表的精确名称查询失败，宿主合成别名遗漏 4.4 动态拒载条件）。
- **修复核查**：源码已修正，无缓存重编译通过，脱机双镜像（B2N 与 Sony）符号与测试工具执行通过。
- **复核结论**：Auditor 确认代码修复成立，标记为 **`fixed`（待闭环）**。依据问题单闭环判据，待 Tester 在 4.4 真机上完成实测全通后，由独立角色复核关闭。

---

## 6. Oracle 纪律复核

- 既有 46 个测试套件逐字节未动，测试用例未被删除或弱化；
- 新增 `nomount/tools/test_inode_storage_lookup.py` 单独建档，采用真实符号名称，并包含保护页内存边界断言，符合 Oracle 纪律要求。

---

## 7. 审计综合裁定

| 审计项 | 判定 | 依据 |
| :--- | :---: | :--- |
| **候选无缓存重编译** | **PASS** | 2 候选件 SHA-256 100% 逐字节吻合 |
| **派生链路闭环** | **PASS** | 4 件派生件链路与收据 100% 可复现 |
| **Inode Storage 识别** | **PASS** | 几何硬约束满足，保护页读取无过读风险，Fail-Closed 严密 |
| **静态版行为等价** | **EQUIVALENT** | 动态代码完全隔离，反汇编证明控制流与运算等价，支持证据绑定 |
| **AUD-001 风险状态** | **OPEN** | key_type 精确尺寸仍未解，范围收窄但维持 OPEN |
| **DEV-042 问题单** | **FIXED** | 代码级修复验证通过，待真机实测后正式关闭 |
| **移交真机测试** | **APPROVED** | 同意移交 Tester 开展实测验证 |
